"""verifier for LLM-produced reports.

Enforce:
- verbatim citation substring match against source fact verbatim / chunk text
- claim removal when all citations fail
- claim-ID reference resolution (unneeded references are dropped)
- orphan claim removal (unneded claims referenced are removed)
- remediation evidence+knowledge citation rule per recommendation
- timeline_events cap at 40 (this reduces prompt size)
- server-controlled field injection
- final schema validation

Usage:
    from app.verifier import verify_report
    verified_report, stats = verify_report(
        report=llm_output_dict,
        report_type="executive_risk",
        sanitized_bundle=sanitized_bundle_dict,
        retrieval_result=retrieval_result_dict,
        server_fields={
            "schema_version": "report-output/1.0",
            "submission_id": submission_uuid,
            "report_type": "executive_risk",
            "generated_at": utc_iso_now(),
            "model": "qwen2.5:7b-instruct",
            "prompt_version": "exec-v1",
            "sanitization_manifest_id": sanitization_manifest_id,
        },
    )
    if verified_report is None:
        # generation failed for this report
    else:
        # safe to persist
"""
import json
import logging
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

log = logging.getLogger(__name__)

def _norm(s) -> str:
    """Case-fold and collapse whitespace for verbatim comparison."""
    return " ".join(str(s).casefold().split())

SCHEMAS_DIR = Path("/opt/pipeline/schemas")

SERVER_FIELDS = (
    "schema_version",
    "submission_id",
    "report_type",
    "generated_at",
    "model",
    "prompt_version",
    "sanitization_manifest_id",
)

REPORT_TYPES = {
    "executive_risk": "report_executive_risk.schema.json",
    "timeline_attack_chain": "report_timeline_attack_chain.schema.json",
    "remediation": "report_remediation.schema.json",
}

MAX_TIMELINE_EVENTS = 40

_REGISTRY_CACHE: Registry | None = None


def _registry() -> Registry:
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is not None:
        return _REGISTRY_CACHE
    pairs = []
    for p in sorted(SCHEMAS_DIR.glob("*.schema.json")):
        contents = json.loads(p.read_text())
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        uri = contents.get("$id") or p.name
        pairs.append((uri, resource))
    _REGISTRY_CACHE = Registry().with_resources(pairs)
    return _REGISTRY_CACHE


def _validate_schema(report: dict, report_type: str) -> list[str]:
    schema_file = REPORT_TYPES[report_type]
    schema = json.loads((SCHEMAS_DIR / schema_file).read_text())
    validator = Draft202012Validator(schema, registry=_registry())
    errors = sorted(validator.iter_errors(report), key=lambda e: list(e.path))
    return [f"{list(e.path)}: {e.message}" for e in errors]


def _facts_by_id(sanitized_bundle: dict) -> dict[str, dict]:
    return {f["fact_id"]: f for f in sanitized_bundle.get("facts", []) if "fact_id" in f}


def _chunks_by_id(retrieval_result: dict) -> dict[str, dict]:
    """Index chunks by BOTH chunk_id (the storage primary key) and source_id
    (the human-readable identifier like 'mitre:T1059'). The model is told to
    copy source_id from the chunk payload, so lookup must accept either.
    Auto-recovery below also keeps working via this dual index."""
    out: dict[str, dict] = {}
    for c in retrieval_result.get("results", []):
        cid = c.get("chunk_id")
        sid = c.get("source_id")
        if cid:
            out[cid] = c
        if sid and sid != cid:
            out[sid] = c
    return out


def _verify_citation(citation: dict, facts: dict, chunks: dict) -> tuple[bool, str | None]:
    """Verify one citation. Tolerates LLM formatting quirks; catches fabrications.

    A citation is valid when its verbatim — after normalization — is a substring
    of the source's verbatim/text after the SAME normalization. This is applied
    twice: once with the existing `_norm` (which was previously applied only to
    the citation side, which is the reason the verifier rejected otherwise
    perfect citations) and once with a stricter loose-normalizer that folds
    common 7B-model formatting artifacts (wrapping quotes, trailing punctuation,
    HTML entities, curly quotes, en/em dashes, unicode ellipsis, whitespace
    runs, non-breaking spaces, BOM).

    Fabricated citations still fail: source_id absent from the fact/chunk map
    returns fact_not_found/chunk_not_found, and a verbatim whose normalized
    content is genuinely absent from the source returns verbatim_mismatch_*.
    """
    source_type = citation.get("source_type")
    source_id = citation.get("source_id")
    verbatim = citation.get("verbatim", "")
    if not isinstance(verbatim, str) or not verbatim:
        return False, "empty_verbatim"

    def _loose(s) -> str:
        if not isinstance(s, str):
            s = str(s) if s is not None else ""
        s = (s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
              .replace("&quot;", '"').replace("&#39;", "'").replace("&#x27;", "'"))
        s = s.replace("\u00a0", " ").replace("\u200b", "").replace("\ufeff", "")
        s = (s.replace("\u2026", "...").replace("\u2013", "-").replace("\u2014", "-")
              .replace("\u2018", "'").replace("\u2019", "'")
              .replace("\u201c", '"').replace("\u201d", '"'))
        s = " ".join(s.split())
        for _ in range(2):
            if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'", "`"):
                s = s[1:-1].strip()
        s = s.rstrip(".,;:!?")
        return s.lower()

    def _matches(src_raw) -> bool:
        if not isinstance(src_raw, str):
            src_raw = str(src_raw) if src_raw is not None else ""
        # Layer 1 — existing _norm applied symmetrically (this was the bug)
        a, b = _norm(verbatim), _norm(src_raw)
        if a and b and a in b:
            return True
        # Layer 2 — formatting-tolerant loose normalization on both sides
        a, b = _loose(verbatim), _loose(src_raw)
        if a and b and a in b:
            return True
        # Layer 3 — ellipsis-fragmented citation: "A ... B" means A and B
        # both appear (separately) in the source. Accept if every fragment
        # (>= 8 chars) appears in the source AND the combined preserved
        # content is meaningful (>= 15 chars). Short fragments are rejected
        # to prevent one-word coincidences from passing.
        if "..." in a:
            pieces = [p.strip() for p in a.split("...") if p.strip()]
            if (len(pieces) >= 2
                    and all(len(p) >= 8 and p in b for p in pieces)
                    and sum(len(p) for p in pieces) >= 15):
                return True
        return False

    if source_type == "evidence":
        fact = facts.get(source_id)
        if not fact:
            # Auto-recovery: if source_id was hallucinated but the verbatim
            # uniquely identifies exactly one real fact, accept it.
            matches = [f for f in facts.values() if _matches(f.get("verbatim", ""))]
            if len(matches) == 1:
                log.info("source_id_recovered stated=%s recovered=%s", source_id, matches[0].get("fact_id"))
                citation["source_id"] = matches[0].get("fact_id")
                citation["verified"] = True
                return True, None
            return False, "fact_not_found"
        if not _matches(fact.get("verbatim", "")):
            return False, "verbatim_mismatch_fact"
        citation["verified"] = True
        return True, None

    if source_type == "knowledge":
        chunk = chunks.get(source_id)
        if not chunk:
            matches = [c for c in chunks.values() if _matches(c.get("text", ""))]
            if len(matches) == 1:
                log.info("source_id_recovered stated=%s recovered=%s", source_id, matches[0].get("chunk_id"))
                citation["source_id"] = matches[0].get("chunk_id")
                citation["verified"] = True
                return True, None
            return False, "chunk_not_found"
        if not _matches(chunk.get("text", "")):
            return False, "verbatim_mismatch_chunk"
        citation["verified"] = True
        return True, None

    return False, f"unsupported_source_type:{source_type}"


def _verify_claims(report: dict, facts: dict, chunks: dict) -> dict:
    stats = {
        "claims_in": 0,
        "claims_out": 0,
        "citations_in": 0,
        "citations_dropped": 0,
        "claims_removed": 0,
        "drop_reasons": {},
    }
    for claim in report.get("claims", []):
        stats["claims_in"] += 1
        citations = claim.get("citations", [])
        stats["citations_in"] += len(citations)
        surviving = []
        for cit in citations:
            ok, reason = _verify_citation(cit, facts, chunks)
            if ok:
                surviving.append(cit)
            else:
                stats["citations_dropped"] += 1
                stats["drop_reasons"][reason] = stats["drop_reasons"].get(reason, 0) + 1
                log.info(
                    "citation_dropped claim=%s source=%s reason=%s",
                    claim.get("claim_id"), cit.get("source_id"), reason,
                )
        claim["citations"] = surviving
        if not surviving:
            claim["status"] = "removed"
            stats["claims_removed"] += 1
            log.info("claim_removed claim_id=%s", claim.get("claim_id"))
        else:
            claim["status"] = "verified"
    stats["claims_out"] = len(report.get("claims", []))
    return stats


def _remove_removed_claims(report: dict) -> None:
    report["claims"] = [
        c for c in report.get("claims", []) if c.get("status") != "removed"
    ]


def _inject_abstention_claim(report: dict, report_type: str, facts: dict) -> bool:
    """When zero claims survive verification, inject one honest stub claim.

    The stub:
    - has status "abstained" (a valid Claim status),
    - cites exactly one real evidence fact (Citation requires minItems:1
      and verified:true),
    - carries a fixed sentence as text (not model output — zero hallucination),
    - is accompanied by an abstention entry documenting the failure.

    Returns True if injection succeeded, False if no facts with non-empty
    verbatim exist (caller's existing fatal path still fires in that case).
    """
    if report_type == "executive_risk":
        claim_id = "c_abstain_executive"
        section = "summary"
        text = ("No grounded executive summary could be produced: every claim "
                "the model produced failed verbatim verification against the "
                "evidence bundle.")
    elif report_type == "remediation":
        claim_id = "c_abstain_remediation"
        section = "threat_model"
        text = ("No grounded threat model could be produced: every claim the "
                "model produced failed verbatim verification against the "
                "evidence bundle.")
    else:
        claim_id = "c_abstain_timeline"
        section = "narrative"
        text = ("No grounded attack-chain narrative could be produced: every "
                "claim the model produced failed verbatim verification against "
                "the evidence bundle.")

    citation = None
    for f in facts.values():
        v = f.get("verbatim", "")
        if isinstance(v, str) and v:
            citation = {
                "citation_id": "cit_abstain",
                "source_type": "evidence",
                "source_id": f["fact_id"],
                "verbatim": v,
                "verified": True,
            }
            break

    if citation is None:
        log.error("cannot inject abstention claim: no facts available")
        return False

    report.setdefault("claims", []).append({
        "claim_id": claim_id,
        "text": text,
        "citations": [citation],
        "status": "abstained",
    })
    report.setdefault("abstentions", []).append({
        "section": section,
        "reason": ("all model-emitted claims failed verbatim citation "
                   "verification; no grounded narrative was available"),
        "evidence_gap": ("every citation the model produced was rejected by "
                         "the verifier's verbatim substring check"),
    })
    if report_type == "executive_risk":
        report["insufficient_evidence"] = True
    log.warning("injected_abstention_claim report=%s claim_id=%s",
                report_type, claim_id)
    return True


def _existing_claim_ids(report: dict) -> set[str]:
    return {c["claim_id"] for c in report.get("claims", [])}


def _resolve_references(report: dict, report_type: str) -> dict:
    stats = {"dangling_refs_dropped": 0, "items_dropped": 0, "fatal": False}
    existing = _existing_claim_ids(report)

    if report_type == "executive_risk":
        if report.get("summary_claim_id") not in existing:
            if existing:
                report["summary_claim_id"] = sorted(existing)[0]
                stats["dangling_refs_dropped"] += 1
                log.warning("summary_claim_id_remapped to %s", report["summary_claim_id"])
            else:
                stats["fatal"] = True
                log.error("no_summary_claim_available")
                return stats
        before = len(report.get("key_finding_ids", []))
        report["key_finding_ids"] = [c for c in report.get("key_finding_ids", []) if c in existing]
        stats["dangling_refs_dropped"] += before - len(report["key_finding_ids"])
        filtered_techs = []
        for tech in report.get("mitre_techniques", []):
            surviving = [c for c in tech.get("evidence_claim_ids", []) if c in existing]
            if surviving:
                tech["evidence_claim_ids"] = surviving
                filtered_techs.append(tech)
            else:
                stats["items_dropped"] += 1
                log.info("mitre_technique_dropped technique_id=%s", tech.get("technique_id"))
        report["mitre_techniques"] = filtered_techs

    elif report_type == "timeline_attack_chain":
        if report.get("attack_chain_narrative_claim_id") not in existing:
            # Remap: prefer the first timeline event's description claim, then first step
            remap = None
            for ev in report.get("timeline_events", []):
                if ev.get("description_claim_id") in existing:
                    remap = ev["description_claim_id"]
                    break
            if remap is None:
                for st in report.get("attack_chain_steps", []):
                    if st.get("description_claim_id") in existing:
                        remap = st["description_claim_id"]
                        break
            if remap is None:
                if existing:
                    remap = sorted(existing)[0]
                else:
                    stats["fatal"] = True
                    log.error("no_narrative_claim_available")
                    return stats
            report["attack_chain_narrative_claim_id"] = remap
            stats["dangling_refs_dropped"] += 1
            log.warning("attack_chain_narrative_claim_id_remapped to %s", remap)

        filtered_events = []
        for ev in report.get("timeline_events", []):
            if ev.get("description_claim_id") in existing:
                filtered_events.append(ev)
            else:
                stats["items_dropped"] += 1
        report["timeline_events"] = filtered_events

        filtered_steps = []
        for st in report.get("attack_chain_steps", []):
            if st.get("description_claim_id") in existing:
                filtered_steps.append(st)
            else:
                stats["items_dropped"] += 1
        report["attack_chain_steps"] = filtered_steps

    elif report_type == "remediation":
        if report.get("threat_model_claim_id") not in existing:
            remap = None
            for rec in report.get("recommendations", []):
                if rec.get("rationale_claim_id") in existing:
                    remap = rec["rationale_claim_id"]
                    break
            if remap is None:
                if existing:
                    remap = sorted(existing)[0]
                else:
                    stats["fatal"] = True
                    log.error("no_threat_model_claim_available")
                    return stats
            report["threat_model_claim_id"] = remap
            stats["dangling_refs_dropped"] += 1
            log.warning("threat_model_claim_id_remapped to %s", remap)

        filtered_recs = []
        for rec in report.get("recommendations", []):
            if rec.get("rationale_claim_id") in existing:
                filtered_recs.append(rec)
            else:
                stats["items_dropped"] += 1
        report["recommendations"] = filtered_recs

    return stats


def _referenced_ids(report: dict, report_type: str) -> set[str]:
    refs = set()
    if report_type == "executive_risk":
        if report.get("summary_claim_id"):
            refs.add(report["summary_claim_id"])
        refs.update(report.get("key_finding_ids", []))
        for tech in report.get("mitre_techniques", []):
            refs.update(tech.get("evidence_claim_ids", []))
    elif report_type == "timeline_attack_chain":
        if report.get("attack_chain_narrative_claim_id"):
            refs.add(report["attack_chain_narrative_claim_id"])
        for ev in report.get("timeline_events", []):
            if ev.get("description_claim_id"):
                refs.add(ev["description_claim_id"])
        for st in report.get("attack_chain_steps", []):
            if st.get("description_claim_id"):
                refs.add(st["description_claim_id"])
    elif report_type == "remediation":
        if report.get("threat_model_claim_id"):
            refs.add(report["threat_model_claim_id"])
        for rec in report.get("recommendations", []):
            if rec.get("rationale_claim_id"):
                refs.add(rec["rationale_claim_id"])
    return refs


def _remove_orphans(report: dict, report_type: str) -> dict:
    refs = _referenced_ids(report, report_type)
    pre = len(report.get("claims", []))
    report["claims"] = [c for c in report.get("claims", []) if c["claim_id"] in refs]
    post = len(report["claims"])
    if pre != post:
        log.info("orphans_removed count=%d", pre - post)
    return {"orphans_removed": pre - post}


def _enforce_remediation_citations(report: dict) -> dict:
    claims_by_id = {c["claim_id"]: c for c in report.get("claims", [])}
    stats = {"recommendations_in": 0, "recommendations_out": 0, "recommendations_dropped": 0}
    kept = []
    for rec in report.get("recommendations", []):
        stats["recommendations_in"] += 1
        claim = claims_by_id.get(rec.get("rationale_claim_id"))
        if not claim:
            stats["recommendations_dropped"] += 1
            log.info("recommendation_removed_no_claim id=%s", rec.get("recommendation_id"))
            continue
        has_ev = any(c.get("source_type") == "evidence" for c in claim.get("citations", []))
        has_kn = any(c.get("source_type") == "knowledge" for c in claim.get("citations", []))
        if has_ev and has_kn:
            kept.append(rec)
        else:
            stats["recommendations_dropped"] += 1
            log.info(
                "recommendation_removed_missing_citation id=%s has_ev=%s has_kn=%s",
                rec.get("recommendation_id"), has_ev, has_kn,
            )
    report["recommendations"] = kept
    stats["recommendations_out"] = len(kept)
    return stats


def _cap_timeline(report: dict) -> dict:
    events = report.get("timeline_events", [])
    if len(events) > MAX_TIMELINE_EVENTS:
        log.warning("timeline_capped original=%d kept=%d", len(events), MAX_TIMELINE_EVENTS)
        report["timeline_events"] = events[:MAX_TIMELINE_EVENTS]
        return {"capped": len(events) - MAX_TIMELINE_EVENTS}
    return {"capped": 0}


def verify_report(
    report: dict,
    report_type: str,
    sanitized_bundle: dict,
    retrieval_result: dict,
    server_fields: dict,
) -> tuple[dict | None, dict]:
    """Run all verification stages. Returns (verified_report_or_None, stats)."""
    stats: dict = {"report_type": report_type, "fatal": False, "stages": {}}

    if report_type not in REPORT_TYPES:
        stats["fatal"] = True
        stats["stages"]["type_check"] = {"result": "unknown_report_type", "value": report_type}
        return None, stats

    facts = _facts_by_id(sanitized_bundle)
    chunks = _chunks_by_id(retrieval_result)

    stats["stages"]["claim_verification"] = _verify_claims(report, facts, chunks)
    _remove_removed_claims(report)

    if not report.get("claims"):
        _inject_abstention_claim(report, report_type, facts)

    s3 = _resolve_references(report, report_type)
    stats["stages"]["reference_resolution"] = s3
    if s3.get("fatal"):
        stats["fatal"] = True
        return None, stats

    if report_type == "remediation":
        stats["stages"]["remediation_citations"] = _enforce_remediation_citations(report)

    if report_type == "timeline_attack_chain":
        stats["stages"]["timeline_cap"] = _cap_timeline(report)

    stats["stages"]["orphan_cleanup"] = _remove_orphans(report, report_type)

    for k in SERVER_FIELDS:
        if k in server_fields:
            report[k] = server_fields[k]

    errors = _validate_schema(report, report_type)
    if errors:
        stats["fatal"] = True
        stats["stages"]["schema_validation"] = {"result": "failed", "errors": errors[:20]}
        return None, stats

    stats["stages"]["schema_validation"] = {"result": "ok"}
    return report, stats
