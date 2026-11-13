"""Worker pool: the pipeline itself.

Runs as one of as parallel systemd services (WORKER_ID env). 
Each worker atomically claims one submission per loop iteration via db.claim_one(). (there is some trade off during pollin)
If the worker dies mid-phase, another worker picks it up.
After CLAIM_TTL_SECONDS. Stuck tail states are reclaimed by _reclaim_zombies after ZOMBIE_TIMEOUT_S.

Model output is normalized deterministically before verification:
- source_type corrected from source_id prefix (f_* -> evidence, else knowledge)
- te_* source_ids dropped (not citable)
- duplicate claim_ids deduped, empty-text claims dropped
- phase / risk_level / timestamps canonicalized

JSON parsing tolerates unescaped control characters via strict=False.

Missing timeline issues result in guarantee fialures, timeline acts as extra sanatizer
"""
from __future__ import annotations

import os
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("CHROMA_TELEMETRY_ENABLED", "False")

import fcntl
import json
import logging
import re
import shutil
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app import cuckoo_client, db, extractor, knowledge, renderer, sanitizer, verifier

log = logging.getLogger("worker")

_WORKER_ID = os.environ.get("WORKER_ID", "0")

ROOT = Path("/opt/pipeline")
PROMPTS_DIR = ROOT / "prompts"
UPLOADS_ROOT = ROOT / "data" / "uploads"
ANALYSES_ROOT = ROOT / "data" / "analyses"
REPORTS_ROOT = ROOT / "data" / "reports"
LOCK_FILE = ROOT / "data" / f"worker-{_WORKER_ID}.lock"

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
EXTRACT_MODEL = "qwen2.5:7b-instruct"   # tiny MiniCPM model
REASON_MODEL  = "qwen3-reason"          # qwen 2.5:3b reasoning model
SCHEMAS_DIR = Path("/opt/pipeline/schemas")
_SCHEMA_MAP = {
    "executive_risk": "report_executive_risk.schema.json",
    "timeline_attack_chain": "report_timeline_attack_chain.schema.json",
    "remediation": "report_remediation.schema.json",
}
_SCHEMA_CACHE = {}
OLLAMA_NUM_PARALLEL = int(os.getenv("OLLAMA_NUM_PARALLEL", "4"))
LLM_TIMEOUT_S = 5400.0
MAX_CALLBACK_RETRIES = 5
POLL_INTERVAL_S = 3.0
ZOMBIE_TIMEOUT_S = 2600
ZOMBIE_SWEEP_INTERVAL_S = 15
PIPELINE_PURGE_AFTER_COMPLETION_S = 180 * 60
PIPELINE_PURGE_INTERVAL_S = 300
MAX_URL_BYTES = 200 * 1024 * 1024
URL_TIMEOUT_S = 60.0
MAX_REDIRECTS = 3

CATEGORY_PRIORITY = [
    "network", "dns", "http", "tls", "process", "command_line",
    "file", "registry", "service", "credential_access",
    "persistence", "mutex", "pipe", "user", "screenshot", "metadata", "other",
]
MAX_FACTS_FOR_LLM = 200
MAX_FACT_VERBATIM = 400
MAX_CHUNKS_FOR_LLM = 6
MAX_CHUNK_CHARS = 800

TIMESTAMP_RE = re.compile(r"@ (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z_]+)\}\}")
RFC3339_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)
SPACED_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?$")
SPACED_TS_MIN_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})$")
DEGENERATE_VERBATIM_RE = re.compile(r"\b(\w+)(?:\s+\1){4,}", re.IGNORECASE)

def _is_degenerate_fact(f: dict) -> bool:
    """Drop facts whose verbatim repeats one word 5+ times in a row.
    These trigger model degeneration loops (e.g. 'hardcoded hardcoded ...')."""
    v = f.get("verbatim", "")
    return bool(DEGENERATE_VERBATIM_RE.search(v))

EVENT_TYPE_MAP = {
    ("process", "image"): "process_start",
    ("process", "monitored_execution"): "process_start",
    ("network", "pcap_flow"): "network_connect",
    ("network", "sysmon_connect"): "network_connect",
    ("dns", "pcap_query"): "dns_query",
    ("dns", "query"): "dns_query",
    ("file", "created"): "file_write",
    ("file", "written"): "file_write",
}

PHASE_CANON = {
    "delivery": "delivery",
    "execution": "execution",
    "persistence": "persistence",
    "privilege_escalation": "privilege_escalation",
    "privilege escalation": "privilege_escalation",
    "privilege-escalation": "privilege_escalation",
    "defense_evasion": "defense_evasion",
    "defense evasion": "defense_evasion",
    "defense-evasion": "defense_evasion",
    "credential_access": "credential_access",
    "credential access": "credential_access",
    "credential-access": "credential_access",
    "discovery": "discovery",
    "lateral_movement": "lateral_movement",
    "lateral movement": "lateral_movement",
    "lateral-movement": "lateral_movement",
    "collection": "collection",
    "command_and_control": "command_and_control",
    "command and control": "command_and_control",
    "command-and-control": "command_and_control",
    "command & control": "command_and_control",
    "c2": "command_and_control",
    "c&c": "command_and_control",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "unknown": "unknown",
}

RISK_CANON = {"none", "low", "medium", "high", "critical", "unknown"}

_SHUTDOWN = False


def _sigterm(_signo, _frame):
    global _SHUTDOWN
    log.info("shutdown signal received; will exit after current task")
    _SHUTDOWN = True


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render_template(name: str, vars_dict: dict) -> str:
    text = (PROMPTS_DIR / f"{name}.txt").read_text(encoding="utf-8")
    def _sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in vars_dict:
            raise KeyError(f"missing template var {key} for {name}")
        val = vars_dict[key]
        if isinstance(val, (dict, list)):
            return json.dumps(val, ensure_ascii=False, separators=(",", ":"))
        return str(val)
    return PLACEHOLDER_RE.sub(_sub, text)


def _truncate_facts(facts: list[dict], max_verbatim: int = MAX_FACT_VERBATIM) -> list[dict]:
    # 1. Find the sample filename to use as a high-priority filter
    sample_name = ""
    for f in facts:
        if f.get("key") in ("primary_filename", "filename"):
            sample_name = str(f.get("value", ""))
            break

    # 2. Deduplicate: Keep only the first occurrence of each unique behavior
    seen = set()
    unique_facts = []
    for f in facts:
        sig = (f.get("category"), f.get("key"), str(f.get("value")))
        if sig not in seen:
            seen.add(sig)
            unique_facts.append(f)

    # 2b. Drop degenerate verbatims (repetition loops poison the LLM)
    before = len(unique_facts)
    unique_facts = [f for f in unique_facts if not _is_degenerate_fact(f)]
    dropped = before - len(unique_facts)
    if dropped:
        log.warning("dropped %d degenerate facts (repeated-word verbatims)", dropped)

    # 2c. Drop facts whose verbatim is too short to cite meaningfully.
    # A verbatim of "<local_IP>" (11 chars) gives the model nothing to anchor
    # on and reliably causes degeneration loops.
    unique_facts = [f for f in unique_facts
                    if len(str(f.get("verbatim", ""))) >= 25]

    # 3. Slim down & truncate
    out = []
    for f in unique_facts:
        v = f.get("verbatim", "")
        if len(v) > max_verbatim:
            v = v[:max_verbatim]

        slim_f = {
            "fact_id": f.get("fact_id"),
            "category": f.get("category"),
            "key": f.get("key"),
            "verbatim": v
        }
        out.append(slim_f)

    # 4. Score and Prioritize
    prio = {c: i for i, c in enumerate(CATEGORY_PRIORITY)}
    def score(f):
        s = 0
        val = str(f.get("value", ""))
        verb = f.get("verbatim", "")
        # Huge boost if the sample filename is in the fact
        if sample_name and (sample_name in val or sample_name in verb):
            s += 100
        # Standard category priority
        s -= prio.get(f.get("category", "other"), 999)
        return s

    out.sort(key=score, reverse=True)
    return out[:MAX_FACTS_FOR_LLM]

def _relevant_chunks_for_facts(facts: list[dict], chunks: list[dict], top_k: int = 6) -> list[dict]:
    """Return the top-k retrieval chunks by lexical overlap with the fact chunk.
    Falls back to the first top_k chunks if no chunk overlaps (preserves grounding)."""
    terms = set()
    for f in facts:
        for tok in str(f.get("verbatim", "")).lower().split():
            if len(tok) >= 6:
                terms.add(tok)
    if not terms:
        return chunks[:top_k]
    scored = []
    for c in chunks:
        text = (c.get("text", "") + " " + c.get("title", "")).lower()
        score = sum(1 for t in terms if t in text)
        scored.append((score, c))
    scored.sort(key=lambda pair: -pair[0])
    if scored and scored[0][0] == 0:
        return chunks[:top_k]
    return [c for _, c in scored[:top_k]]


def _truncate_chunks(chunks: list[dict]) -> list[dict]:
    out = []
    for c in chunks[:MAX_CHUNKS_FOR_LLM]:
        t = c.get("text", "")
        out.append({
            "chunk_id": c.get("chunk_id", ""),
            "source_id": c.get("source_id", c.get("chunk_id", "")),
            "source_type": c.get("source_type", "unknown"),
            "title": c.get("title", ""),
            "text": t[:MAX_CHUNK_CHARS],
        })
    return out


def _artifact_present(bundle: dict, name: str) -> bool:
    for a in bundle.get("artifacts", []):
        if a.get("artifact_name") == name:
            return bool(a.get("present"))
    return False


def _derive_timeline_candidates(bundle: dict) -> list[dict]:
    seen = set()
    out = []
    for fact in bundle.get("facts", []):
        key = (fact.get("category"), fact.get("key"))
        et = EVENT_TYPE_MAP.get(key)
        if not et:
            continue
        locator = fact.get("source", {}).get("locator", "")
        m = TIMESTAMP_RE.search(locator)
        if not m:
            continue
        ts = m.group(1)
        dedupe = (ts, et, str(fact.get("value", ""))[:100])
        if dedupe in seen:
            continue
        seen.add(dedupe)
        out.append({
            "event_id": f"te_{len(out) + 1:03d}",
            "timestamp": ts,
            "event_type": et,
            "source_artifact": fact.get("source", {}).get("artifact", ""),
            "source_fact_id": fact.get("fact_id"),
            "source_authoritative": bool(fact.get("authoritative")),
            "verbatim": str(fact.get("verbatim", ""))[:120],
        })
    # Prioritize timeline events that involve the sample
    sample_name = ""
    for f in bundle.get("facts", []):
        if f.get("key") in ("primary_filename", "filename"):
            sample_name = str(f.get("value", ""))
            break

    def score_tl(c):
        s = 0
        val = str(c.get("verbatim", ""))
        if sample_name and sample_name in val:
            s += 100
        return s

    out.sort(key=lambda c: (score_tl(c), c["timestamp"] or ""), reverse=True)
    return out[:300]


def _extract_json(content: str) -> dict:

    if len(content) > 60000:
        raise ValueError(f"response too large ({len(content)} chars); "
                         f"prompt cap not respected")

    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        if lines and lines[-1].strip().startswith("```"):
            content = "\n".join(lines[1:-1])
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"no JSON object in response: {content[:200]!r}")
    return json.loads(content[start:end + 1], strict=False)


def _normalize_timestamp(ts):
    if ts is None:
        return None
    if not isinstance(ts, str):
        ts = str(ts)
    ts = ts.strip()
    if not ts or ts.lower() in ("null", "none", "unknown"):
        return None
    m = RFC3339_RE.match(ts)
    if m:
        date, time_part, tz = m.groups()
        if tz is None:
            tz = "Z"
        if tz != "Z" and ":" not in tz and len(tz) == 5:
            tz = tz[:3] + ":" + tz[3:]
        return f"{date}T{time_part}{tz}"
    m = SPACED_TS_RE.match(ts)
    if m:
        return f"{m.group(1)}T{m.group(2)}Z"
    m = SPACED_TS_MIN_RE.match(ts)
    if m:
        return f"{m.group(1)}T{m.group(2)}:00Z"
    return ts


def _normalize_phase(phase) -> str:
    if not isinstance(phase, str):
        return "unknown"
    key = phase.strip().lower()
    return PHASE_CANON.get(key, "unknown")


def _normalize_risk(level) -> str:
    if not isinstance(level, str):
        return "unknown"
    v = level.strip().lower()
    return v if v in RISK_CANON else "unknown"


def _normalize_citation(cit):
    if not isinstance(cit, dict):
        return None
    sid = cit.get("source_id", "")
    if not isinstance(sid, str):
        sid = str(sid) if sid else ""
    if sid.startswith("te_"):
        return None
    source_type = "evidence" if sid.startswith("f_") else "knowledge"
    verbatim = cit.get("verbatim", "")
    if not isinstance(verbatim, str):
        verbatim = str(verbatim) if verbatim else ""
    cid = cit.get("citation_id", "")
    if not isinstance(cid, str):
        cid = str(cid) if cid else "cit"
    return {
        "citation_id": cid,
        "source_type": source_type,
        "source_id": sid,
        "verbatim": verbatim,
    }


def _normalize_claims(claims) -> list[dict]:
    if not isinstance(claims, list):
        return []
    seen = set()
    out = []
    for c in claims:
        if not isinstance(c, dict):
            continue
        cid = c.get("claim_id")
        if not isinstance(cid, str) or not cid.strip():
            continue
        if cid in seen:
            continue
        text = c.get("text", "")
        if not isinstance(text, str) or not text.strip():
            continue
        seen.add(cid)
        cits = c.get("citations", [])
        if not isinstance(cits, list):
            cits = []
        new_cits = [nc for nc in (_normalize_citation(x) for x in cits) if nc is not None]
        out.append({
            "claim_id": cid,
            "text": text,
            "citations": new_cits,
            "status": "verified",
        })
    return out


def _normalize_abstentions(items):
    out = []
    if not isinstance(items, list):
        return out
    for a in items:
        if not isinstance(a, dict):
            continue
        out.append({
            "section": str(a.get("section", "")),
            "reason": str(a.get("reason", "")),
            "evidence_gap": str(a.get("evidence_gap", "")),
        })
    return out


def _normalize_gaps(items):
    out = []
    if not isinstance(items, list):
        return out
    for g in items:
        if not isinstance(g, dict):
            continue
        out.append({
            "section": str(g.get("section", "")),
            "reason": str(g.get("reason", "")),
        })
    return out

_REQUIRED_ARRAYS = {
    "executive_risk": ("claims", "abstentions", "key_finding_ids", "mitre_techniques"),
    "timeline_attack_chain": ("claims", "abstentions", "gaps", "timeline_events", "attack_chain_steps"),
    "remediation": ("claims", "abstentions", "recommendations"),
}

def _normalize_report(report: dict, report_type: str) -> dict:
    if not isinstance(report, dict):
        return report
    for k in _REQUIRED_ARRAYS.get(report_type, ()):
        if k not in report or report[k] is None:
            report[k] = []


    if "claims" in report:
        report["claims"] = _normalize_claims(report["claims"])
    if "abstentions" in report:
        report["abstentions"] = _normalize_abstentions(report["abstentions"])

    if report_type == "executive_risk":
        report["risk_level"] = _normalize_risk(report.get("risk_level", "unknown"))
        techs = []
        for t in (report.get("mitre_techniques") or []):
            if not isinstance(t, dict):
                continue
            techs.append({
                "technique_id": str(t.get("technique_id", "")),
                "name": str(t.get("name", "")),
                "evidence_claim_ids": [
                    str(x) for x in (t.get("evidence_claim_ids") or []) if x
                ],
            })
        report["mitre_techniques"] = techs
        if "insufficient_evidence" not in report:
            report["insufficient_evidence"] = False

    elif report_type == "timeline_attack_chain":
        report["gaps"] = _normalize_gaps(report.get("gaps", []))
        evs = []
        for ev in (report.get("timeline_events") or []):
            if not isinstance(ev, dict):
                continue
            evs.append({
                "event_id": str(ev.get("event_id", "")),
                "timestamp": _normalize_timestamp(ev.get("timestamp")),
                "event_type": ev.get("event_type", "other"),
                "description_claim_id": str(ev.get("description_claim_id", "")),
                "ordering_basis": ev.get("ordering_basis", "unknown"),
                "source_authoritative": bool(ev.get("source_authoritative", False)),
            })
        report["timeline_events"] = evs
        steps = []
        for st in (report.get("attack_chain_steps") or []):
            if not isinstance(st, dict):
                continue
            steps.append({
                "step_id": str(st.get("step_id", "")),
                "phase": _normalize_phase(st.get("phase", "unknown")),
                "technique_id": st.get("technique_id"),
                "description_claim_id": str(st.get("description_claim_id", "")),
            })
        report["attack_chain_steps"] = steps

    elif report_type == "remediation":
        recs = []
        for r in (report.get("recommendations") or []):
            if not isinstance(r, dict):
                continue
            phases = [_normalize_phase(p) for p in (r.get("addresses_phases") or []) if p]
            if not phases:
                phases = ["unknown"]
            recs.append({
                "recommendation_id": str(r.get("recommendation_id", "")),
                "category": r.get("category", "general"),
                "priority": r.get("priority", "medium"),
                "action": str(r.get("action", "")),
                "rationale_claim_id": str(r.get("rationale_claim_id", "")),
                "playbook_id": str(r.get("playbook_id", "")),
                "verification": str(r.get("verification", "")),
                "applies_to": [str(x) for x in (r.get("applies_to") or []) if x],
                "addresses_phases": phases,
            })
        report["recommendations"] = recs

    return report

def _load_schema(report_type: str):
    if report_type in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[report_type]
    fname = _SCHEMA_MAP.get(report_type)
    if not fname:
        return None
    path = SCHEMAS_DIR / fname
    if not path.is_file():
        log.warning("schema file missing: %s", path)
        return None
    schema = json.loads(path.read_text(encoding="utf-8"))
    _SCHEMA_CACHE[report_type] = schema
    return schema

_COMMON_DEFS_CACHE = None

def _load_common_defs():
    global _COMMON_DEFS_CACHE
    if _COMMON_DEFS_CACHE is not None:
        return _COMMON_DEFS_CACHE
    path = SCHEMAS_DIR / "common.schema.json"
    if not path.is_file():
        _COMMON_DEFS_CACHE = {}
        return _COMMON_DEFS_CACHE
    data = json.loads(path.read_text(encoding="utf-8"))
    _COMMON_DEFS_CACHE = data.get("$defs", data.get("definitions", {}))
    return _COMMON_DEFS_CACHE


def _rewrite_external_refs(node, depth=0):
    """Recursively rewrite 'common.schema.json#/$defs/X' -> '#/$defs/X'."""
    if depth > 20:
        return node
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            ref = node["$ref"]
            if "common.schema.json#" in ref:
                return {"$ref": "#" + ref.split("#", 1)[1]}
        return {k: _rewrite_external_refs(v, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_rewrite_external_refs(v, depth + 1) for v in node]
    return node


_COMMON_DEFS_CACHE = None

def _load_common_defs():
    global _COMMON_DEFS_CACHE
    if _COMMON_DEFS_CACHE is not None:
        return _COMMON_DEFS_CACHE
    path = SCHEMAS_DIR / "common.schema.json"
    if not path.is_file():
        _COMMON_DEFS_CACHE = {}
        return _COMMON_DEFS_CACHE
    data = json.loads(path.read_text(encoding="utf-8"))
    _COMMON_DEFS_CACHE = data.get("$defs", data.get("definitions", {}))
    return _COMMON_DEFS_CACHE


def _rewrite_external_refs(node, depth=0):
    if depth > 20:
        return node
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            ref = node["$ref"]
            if "common.schema.json#" in ref:
                return {"$ref": "#" + ref.split("#", 1)[1]}
        return {k: _rewrite_external_refs(v, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_rewrite_external_refs(v, depth + 1) for v in node]
    return node


def _load_partial_schema(report_type: str, key):
    full = _load_schema(report_type)
    if not full:
        return None
    props = full.get("properties", {})
    keys = [key] if isinstance(key, str) else list(key)
    valid = [k for k in keys if k in props]
    if not valid:
        return None

    partial = {
        "type": "object",
        "properties": {k: props[k] for k in valid},
        "required": valid,
        "additionalProperties": False,
    }
    bundled = dict(_load_common_defs())
    if "$defs" in full:
        bundled.update(full["$defs"])
    if bundled:
        partial["$defs"] = bundled
    return _rewrite_external_refs(partial)

def _estimate_tokens(text: str) -> int:
    # ~3.6 chars/token for English + JSON on Qwen tokenizer; add 64 for
    # chat-template overhead.
    return max(1, len(text) // 3) + 64


def _ctx_for(system_text: str, user_text: str, num_predict: int) -> int:
    need = (_estimate_tokens(system_text) + _estimate_tokens(user_text)
            + num_predict + 256)
    for cap in (4096, 8192, 12288, 16384, 24576, 32768):
        if need <= cap:
            return cap
    return 32768


def _budget_for_call(report_type, key, vars_dict, model):
    """Return num_predict sized to the expected output for this call.

    Extract model outputs are short by design (claims, technique lists,
    timeline events). Reason model outputs are sized to input: the
    timeline_assembly call must fit one event_id per selected event, the
    remediation call fits one recommendation per ~4 claims. This prevents
    the fixed-2048 truncation cycle on verbose samples.
    """
    if model == EXTRACT_MODEL:
        keys = [key] if isinstance(key, str) else list(key)
        if "timeline_events" in keys or "attack_chain_steps" in keys:
            return 4096
        return 2048

    keys = [key] if isinstance(key, str) else list(key)

    if report_type == "timeline_attack_chain" and "timeline_event_ids" in keys:
        tl = vars_dict.get("TIMELINE_JSON") or {}
        n_events = len(tl.get("events", []))
        n_steps = len(tl.get("steps", []))
        # ~12 tokens per JSON event_id entry, ~14 per step_id, plus
        # narrative + gaps + structural overhead.
        return min(16384, max(4096, n_events * 20 + n_steps * 20 + 1500))

    if report_type == "remediation" and "recommendations" in keys:
        n_claims = len(vars_dict.get("CLAIMS_JSON") or [])
        # Worst case one rec per claim, ~140 tokens each, plus threat_model.
        return min(16384, max(2048, n_claims * 140 + 1500))

    if report_type == "executive_risk" and "summary_claim_text" in keys:
        # Summary is 200-400 words -> ~600 tokens, plus mitre + findings.
        return 3500

    return 2048



_SEED = 42   # baseline seed; retry path may vary it

def _call_ollama(system_text: str, user_text: str, num_predict: int = 4096, report_type: str = None, model: str = EXTRACT_MODEL, schema_override: dict = None, timeout: float = None) -> str:
    schema = _load_schema(report_type) if report_type else None
    body = {
        "model": model,
        "format": schema_override if schema_override else (_load_schema(report_type) if report_type else "json"),
        "stream": False,
        "think": False,
        "keep_alive": "24h",
        "options": {
            "temperature": 0, "seed": _SEED,
            "num_predict": num_predict,
            "num_ctx": _ctx_for(system_text, user_text, num_predict),
        },
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ],
    }
    effective_timeout = timeout if timeout else LLM_TIMEOUT_S
    r = httpx.post(OLLAMA_URL, json=body, timeout=effective_timeout)
    if r.status_code >= 500 and schema_override:
        log.warning("ollama 500 on schema-constrained call; falling back to format=json")
        body["format"] = "json"
        r = httpx.post(OLLAMA_URL, json=body, timeout=effective_timeout)
    r.raise_for_status()
    payload = r.json()
    content = payload["message"]["content"]
    done_reason = payload.get("done_reason", "")
    if done_reason == "length":
        retry_budget = int(num_predict * 2.0)
        if retry_budget > 16384:
            retry_budget = 16384
        log.warning(
            "llm truncation detected (num_predict=%d, will retry with %d)",
            num_predict, retry_budget,
        )
        body["options"]["num_predict"] = retry_budget
        body["options"]["seed"] = _SEED + 1
        r = httpx.post(OLLAMA_URL, json=body, timeout=effective_timeout)
        r.raise_for_status()
        payload = r.json()
        content = payload["message"]["content"]
        if payload.get("done_reason") == "length":
            log.error("llm truncated at retry ceiling (%d); giving up", retry_budget)
    return content


def _warm_up_llm() -> None:
    try:
        r = httpx.post(
            OLLAMA_URL,
            json={
                "model": "qwen2.5:7b-instruct",
                "stream": False,
                "keep_alive": "24h",
                "options": {"num_predict": 4, "num_ctx": 4096, "temperature": 0},
                "messages": [{"role": "user", "content": "ok"}],
            },
            timeout=300.0,
        )
        r.raise_for_status()
        log.info("llm warm-up ok worker=%s", _WORKER_ID)
        # warm the reasoning model
        try:
            r2 = httpx.post(
                OLLAMA_URL,
                json={
                    "model": REASON_MODEL,
                    "stream": False,
                    "keep_alive": "24h",
                    "options": {"num_predict": 4, "num_ctx": 8192, "temperature": 0},
                    "messages": [{"role": "user", "content": "ok"}],
                },
                timeout=300.0,
            )
            r2.raise_for_status()
            log.info("reason-model warm-up ok worker=%s", _WORKER_ID)
        except Exception as e:
            log.warning("reason-model warm-up failed worker=%s: %s", _WORKER_ID, e)
    except Exception as e:
        log.warning("llm warm-up failed worker=%s: %s", _WORKER_ID, e)


def _parse_and_verify(content, report_type, bundle, retrieval, manifest, sid):
    try:
        report_dict = _extract_json(content)
    except Exception as e:
        return None, [f"json_parse: {e}"]
    report_dict = _normalize_report(report_dict, report_type)
    server_fields = {
        "schema_version": "report-output/1.0",
        "submission_id": sid,
        "report_type": report_type,
        "generated_at": _now(),
        "model": "qwen2.5:7b-instruct",
        "prompt_version": f"{report_type}-v1",
        "sanitization_manifest_id": str(manifest.get("sanitization_manifest_id") or "unknown"),
    }
    verified, stats = verifier.verify_report(report_dict, report_type, bundle, retrieval, server_fields)
    if verified is not None:
        return verified, []
    stages = stats.get("stages", {})
    sv = stages.get("schema_validation", {})
    if sv.get("result") == "failed":
        return None, sv.get("errors", ["schema_validation_failed"])
    return None, [f"verify_fatal: stages={list(stages.keys())}"]

def _generate_subset(prompt_name, report_type, key, vars_dict, bundle, retrieval, manifest, sid, system_text, model, pipeline_dir=None):
    log.info("llm gen subset: report=%s key=%s model=%s sid=%s", report_type, key, model, sid)
    schema = _load_partial_schema(report_type, key)
    if not schema:
        log.error("No partial schema for %s.%s", report_type, key)
        return None

    try:
        content = _call_ollama(
            system_text,
            _render_template(prompt_name, vars_dict),
            report_type=report_type,
            model=model,
            schema_override=schema,
            num_predict=_budget_for_call(report_type, key, vars_dict, model),
            timeout=300.0,
        )
    except Exception as e:
        log.error("llm call failed subset=%s.%s: %s", report_type, key, e)
        return None

    # Save raw audit trail
    if pipeline_dir is not None:
        try:
            raw_dir = pipeline_dir / "llm_raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            (raw_dir / f"{report_type}_{key}.json").write_text(content, encoding="utf-8")
        except Exception:
            pass

    try:
        parsed = _extract_json(content)
    except Exception as e:
        log.error("json parse failed subset=%s.%s: %s", report_type, key, e)
        return None

    return parsed


def _generate_and_verify(prompt_name, report_type, vars_dict, bundle, retrieval, manifest, sid, system_text, pipeline_dir=None):
    log.info("llm gen: report=%s sid=%s", report_type, sid)
    try:
        content = _call_ollama(system_text, _render_template(prompt_name, vars_dict), report_type=report_type)
    except Exception as e:
        log.error("llm call failed report=%s: %s", report_type, e)
        return None

    # Audit trail: preserve raw LLM output before verification discards it
    if pipeline_dir is not None:
        try:
            raw_dir = pipeline_dir / "llm_raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            (raw_dir / f"{report_type}.json").write_text(content, encoding="utf-8")
        except Exception as e:
            log.warning("audit write failed report=%s: %s", report_type, e)

    report, errors = _parse_and_verify(content, report_type, bundle, retrieval, manifest, sid)
    if report is not None:
        log.info("llm gen ok: report=%s", report_type)
        return report
    repair_economical = not any(
        ("fact_not_found" in e) or ("chunk_not_found" in e) or ("verbatim_mismatch" in e)
        or ("verify_fatal" in e and "claim_verification" in e)
        for e in errors
    )
    if not repair_economical:
        log.warning("skip repair report=%s (unfixable error class) errors=%s",
                    report_type, errors[:3])
        return None
    log.warning("first attempt failed report=%s errors=%s", report_type, errors[:3])
    repair_vars = {
        "VALIDATION_ERRORS_JSON": errors[:20],
        "PRIOR_OUTPUT": content,
        "EVIDENCE_FACTS_JSON": vars_dict["EVIDENCE_FACTS_JSON"],
        "RETRIEVAL_CHUNKS_JSON": vars_dict["RETRIEVAL_CHUNKS_JSON"],
    }
    try:
        repaired = _call_ollama(system_text, _render_template("repair", repair_vars), report_type=report_type)
    except Exception as e:
        log.error("repair call failed report=%s: %s", report_type, e)
        return None
    if pipeline_dir is not None:
        try:
            (pipeline_dir / "llm_raw" / f"{report_type}_repair.json").write_text(repaired, encoding="utf-8")
        except Exception:
            pass
    report, errors = _parse_and_verify(repaired, report_type, bundle, retrieval, manifest, sid)
    if report is not None:
        log.info("repair succeeded report=%s", report_type)
        return report
    log.error("repair failed report=%s errors=%s", report_type, errors[:3])
    return None


def _check_url_safe(url: str) -> None:
    from urllib.parse import urlparse
    import ipaddress
    import socket
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"scheme {parsed.scheme!r} not allowed; only http/https")
    host = parsed.hostname
    if not host:
        raise ValueError("no hostname")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve hostname: {e}")
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(f"hostname resolves to private address {addr}")


def _download_url(url: str, target: Path) -> None:
    _check_url_safe(url)
    with httpx.stream("GET", url, timeout=URL_TIMEOUT_S, follow_redirects=True, max_redirects=MAX_REDIRECTS) as r:
        r.raise_for_status()
        total = 0
        with target.open("wb") as f:
            for chunk in r.iter_bytes(chunk_size=65536):
                total += len(chunk)
                if total > MAX_URL_BYTES:
                    raise ValueError(f"download exceeds {MAX_URL_BYTES} bytes")
                f.write(chunk)


def _notify_webapp(row: dict) -> None:
    url = row.get("callback_url")
    if not url:
        log.warning("no callback_url sid=%s", row["webapp_submission_id"])
        return
    manifest = row.get("report_manifest_json") or []
    payload = {
        "webapp_submission_id": row["webapp_submission_id"],
        "status": row["state"],
        "report_manifest": [
            {"type": m["type"], "sha256": m["sha256"],
             "generated_at": m["generated_at"], "relative_path": m["relative_path"]}
            for m in manifest
        ],
        "trace_id": row.get("trace_id"),
        "error_code": row.get("error_code"),
    }
    for attempt in range(MAX_CALLBACK_RETRIES):
        try:
            r = httpx.post(url, json=payload, timeout=10.0)
            if r.status_code < 500:
                log.info("callback ok sid=%s status=%s code=%d",
                         row["webapp_submission_id"], row["state"], r.status_code)
                return
        except Exception as e:
            log.warning("callback attempt %d failed sid=%s: %s",
                        attempt + 1, row["webapp_submission_id"], e)
        time.sleep(2 ** attempt)
    log.error("callback FAILED after retries sid=%s url=%s",
              row["webapp_submission_id"], url)


def _cleanup(row: dict) -> None:
    """Delete only the original uploaded file.

    analyses/<task_id>/ is kept for the 24h raw-export window; the webapp
    cleanup job (step 14c-6) calls pipeline DELETE /submissions/{id} to purge
    it when the window expires. reports/<sid>/ is likewise kept for the
    window and purged by the same DELETE call.
    """
    sid = row["webapp_submission_id"]
    up = UPLOADS_ROOT / sid
    if up.exists():
        shutil.rmtree(up, ignore_errors=True)


def _fail(row: dict, phase: str, error_code: str, message: str) -> None:
    sid = row["webapp_submission_id"]
    log.error("fail sid=%s phase=%s code=%s msg=%s", sid, phase, error_code, message[:300])
    try:
        row = db.set_state(sid, f"failed_{phase}", error_code=error_code)
    except Exception as e:
        log.error("cannot set failed state sid=%s: %s", sid, e)
        return
    _notify_webapp(row)
    _cleanup(row)


def _pipeline_dir(task_id: str) -> Path:
    d = ANALYSES_ROOT / task_id / "_pipeline"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _handle_received(row: dict) -> bool:
    sid = row["webapp_submission_id"]
    up = UPLOADS_ROOT / sid
    if not up.is_dir():
        _fail(row, "cuckoo_api", "upload_missing", f"no uploads dir {up}")
        return True

    url_file = up / "url.txt"
    if url_file.is_file():
        url = url_file.read_text().strip()
        target = up / "downloaded.bin"
        log.info("download url sid=%s url=%s", sid, url[:200])
        try:
            _download_url(url, target)
        except Exception as e:
            _fail(row, "extraction", "url_download_failed", str(e))
            return True
        file_path = target
    else:
        candidates = [f for f in up.iterdir() if f.is_file() and f.name != "url.txt"]
        if not candidates:
            _fail(row, "cuckoo_api", "upload_missing", "no staged file")
            return True
        file_path = candidates[0]

    try:
        task_id = cuckoo_client.submit_sample(file_path, platform=row.get("requested_platform") or cuckoo_client.detect_platform(file_path) or "windows")
    except Exception as e:
        _fail(row, "cuckoo_api", "cuckoo_submit_failed", str(e))
        return True

    date, short = task_id.split("-", 1)
    db.set_task_path(sid, task_id, date, f"{date}/{short}")
    db.set_state(sid, "submitted_to_cuckoo")
    log.info("submitted sid=%s task=%s", sid, task_id)
    return True


def _handle_poll(row: dict) -> bool:
    sid = row["webapp_submission_id"]
    task_id = row.get("cuckoo_task_id")
    if not task_id:
        _fail(row, "cuckoo_api", "no_task_id", "polling without task id")
        return True
    try:
        state, _ = cuckoo_client.get_task_state(task_id)
    except Exception as e:
        log.warning("poll ssh error sid=%s: %s", sid, e)
        return False
    log.info("poll sid=%s task=%s state=%s", sid, task_id, state)
    if state in cuckoo_client.TERMINAL_SUCCESS:
        try:
            db.set_state(sid, "sandbox_complete", sandbox_completed_at=_now())
            return True
        except ValueError as e:
            log.info("sid=%s terminal transition already done by another worker: %s", sid, e)
            return False
    if state in cuckoo_client.TERMINAL_FAILURE:
        try:
            _fail(row, "cuckoo_api", f"cuckoo_state_{state}", f"cuckoo reported {state}")
            return True
        except Exception as e:
            log.info("sid=%s failure already handled by another worker: %s", sid, e)
            return False
    if state == "NO_FILE":
        return False
    if row["state"] == "submitted_to_cuckoo":
        try:
            db.set_state(sid, "sandbox_running", sandbox_started_at=_now())
        except Exception:
            pass

    # Generic stuck-state timeout: any non-terminal cuckoo state that
    # persists past the threshold means cuckoo accepted but never processed.
    # Fail the submission and delete the orphaned cuckoo task.
    STUCK_TIMEOUT_HOURS = 8
    try:
        started = row.get("sandbox_started_at") or row.get("created_at")
        if started:
            from datetime import datetime as _dt, timezone as _tz
            dt = _dt.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_tz.utc)
            age_h = (_dt.now(_tz.utc) - dt).total_seconds() / 3600
            if age_h > STUCK_TIMEOUT_HOURS:
                log.warning(
                    "stuck sid=%s task=%s state=%s age=%.1fh — deleting cuckoo copy and failing",
                    sid, task_id, state, age_h,
                )
                try:
                    cuckoo_client.delete_task(task_id)
                except Exception as e:
                    log.warning("delete_task raised task=%s: %s", task_id, e)
                _fail(row, "cuckoo_api", f"stuck_{state}_{int(age_h)}h",
                      f"cuckoo state {state} persisted {age_h:.1f}h")
                return True
    except Exception as e:
        log.warning("stuck-timeout check failed sid=%s: %s", sid, e)


    return False


def _handle_sandbox_complete(row: dict) -> bool:
    sid = row["webapp_submission_id"]
    task_id = row["cuckoo_task_id"]
    log.info("fetch+extract sid=%s task=%s", sid, task_id)
    try:
        analysis_dir = cuckoo_client.fetch_task_artifacts(task_id)
        bundle = extractor.extract(analysis_dir, sid, task_id)
        # Override primary_filename with the actual uploaded name.
        # Cuckoo renames the file to its hash before analysis, so
        # orig_filename is often the hash. The user's original filename
        # is only available in uploads/<sid>/ until cleanup.
        up = UPLOADS_ROOT / sid
        if up.is_dir():
            uploaded_name = None
            for f in up.iterdir():
                if f.is_file() and f.name != "url.txt":
                    uploaded_name = f.name
                    break
            # URL submissions have no user-chosen filename; skip replacement
            # rather than showing "downloaded.bin" in the PDF.
            if uploaded_name == "downloaded.bin":
                uploaded_name = None
            if uploaded_name:
                hash_names: set[str] = set()
                for fact in bundle.get("facts", []):
                    if fact.get("key") in ("filename", "orig_filename"):
                        v = str(fact.get("value", ""))
                        if v:
                            hash_names.add(v)
                            if "." in v:
                                hash_names.add(v.rsplit(".", 1)[0])
                for fact in bundle.get("facts", []):
                    if fact.get("key") in ("primary_filename", "filename", "orig_filename"):
                        fact["value"] = uploaded_name
                        fact["verbatim"] = uploaded_name
                if hash_names:
                    for fact in bundle.get("facts", []):
                        for k in ("verbatim", "value"):
                            v = fact.get(k)
                            if not isinstance(v, str):
                                continue
                            new_v = v
                            for h in hash_names:
                                if h and h in new_v:
                                    new_v = new_v.replace(h, uploaded_name)
                            if new_v != v:
                                fact[k] = new_v
    except Exception as e:
        _fail(row, "extraction", "extract_failed", str(e))
        return True
    pipeline_dir = _pipeline_dir(task_id)
    _write_json(pipeline_dir / "evidence_bundle.json", bundle)
    # Pipeline owns the data now — delete cuckoo's copy to honor the privacy
    # policy that no analysis artifacts persist on the sandbox after extraction.
    try:
        cuckoo_client.delete_task(task_id)
    except Exception as e:
        log.warning("delete_task raised sid=%s task=%s: %s", sid, task_id, e)
    db.set_state(sid, "evidence_extracted")
    log.info("extracted sid=%s facts=%d", sid, len(bundle.get("facts", [])))
    return True


def _handle_evidence_extracted(row: dict) -> bool:
    sid = row["webapp_submission_id"]
    task_id = row["cuckoo_task_id"]
    pipeline_dir = _pipeline_dir(task_id)
    bundle = _read_json(pipeline_dir / "evidence_bundle.json")
    try:
        config = sanitizer.load_config(Path("/opt/pipeline/config/sanitizer.yaml"))
        sanitized, pre, preserve_ips = sanitizer.sanitize_bundle(bundle, config)
    except Exception as e:
        _fail(row, "sanitization", "sanitize_failed", str(e))
        return True
    manifest = sanitizer.build_manifest(sid, config, pre, pre)
    manifest["sanitization_manifest_id"] = f"{sid}-san-1"
    _write_json(pipeline_dir / "sanitized_bundle.json", sanitized)
    _write_json(pipeline_dir / "sanitization_manifest.json", manifest)
    import hashlib
    manifest_sha = hashlib.sha256((pipeline_dir / "sanitization_manifest.json").read_bytes()).hexdigest()
    db.set_aux_metadata(sid, sanitization_manifest_sha256=manifest_sha, llm_model="qwen2.5:7b-instruct")
    db.set_state(sid, "sanitized")
    log.info("sanitized sid=%s", sid)
    return True


def _handle_sanitized(row: dict) -> bool:
    sid = row["webapp_submission_id"]
    task_id = row["cuckoo_task_id"]
    pipeline_dir = _pipeline_dir(task_id)
    sanitized = _read_json(pipeline_dir / "sanitized_bundle.json")
    try:
        queries = knowledge.derive_queries(sanitized)
        col = knowledge.get_collection()
        result = knowledge.retrieve(queries, col)
    except Exception as e:
        _fail(row, "retrieval", "retrieve_failed", str(e))
        return True
    _write_json(pipeline_dir / "retrieval_result.json", result)
    import hashlib
    retrieval_sha = hashlib.sha256((pipeline_dir / "retrieval_result.json").read_bytes()).hexdigest()
    db.set_aux_metadata(sid, retrieval_result_sha256=retrieval_sha)
    db.set_state(sid, "retrieval_done")
    log.info("retrieved sid=%s chunks=%d sufficient=%s",
             sid, len(result.get("results", [])), result.get("confidence", {}).get("sufficient"))
    return True


FACTS_PER_CHUNK = 2
FACTS_CHUNK_THRESHOLD = 5

def _generate_claims_chunked(prompt_name, report_type, facts, extra_vars,
                             bundle, retrieval, manifest, sid, system_text,
                             model, pipeline_dir):
    """Extract claims from facts. Single call for small sets, chunked for large.

    Chunking preserves every fact. Each chunk produces a small claims array
    (5-15 claims typically), so no single call approaches the truncation
    ceiling. Claim IDs are renumbered after merging to guarantee uniqueness
    across chunks (chunk 2's c1 becomes c15, etc.).
    """
    if len(facts) <= FACTS_CHUNK_THRESHOLD:
        # Fast path: single call, current behavior
        vars_dict = dict(extra_vars)
        vars_dict["EVIDENCE_FACTS_JSON"] = facts
        return _generate_subset(prompt_name, report_type, "claims", vars_dict,
                                bundle, retrieval, manifest, sid, system_text,
                                model, pipeline_dir)

    facts = [dict(f, verbatim=f.get("verbatim", "")[:400]) for f in facts]
    chunks = [facts[i:i+FACTS_PER_CHUNK] for i in range(0, len(facts), FACTS_PER_CHUNK)]
    log.info("claims chunked: %d facts -> %d chunks of %d sid=%s",
             len(facts), len(chunks), FACTS_PER_CHUNK, sid)
    failed_chunks = 0
    all_claims: list[dict] = []
    for idx, chunk in enumerate(chunks):
        vars_dict = dict(extra_vars)
        vars_dict["EVIDENCE_FACTS_JSON"] = chunk
        vars_dict["CHUNK_INDEX"] = idx + 1
        vars_dict["CHUNK_TOTAL"] = len(chunks)
        try:
            result = _generate_subset(prompt_name, report_type, "claims", vars_dict,
                                     bundle, retrieval, manifest, sid, system_text,
                                     model, pipeline_dir)
        except Exception as e:
            log.warning("claims chunk %d/%d failed (retrying once): %s",
                        idx + 1, len(chunks), e)
            try:
                result = _generate_subset(prompt_name, report_type, "claims",
                                         vars_dict, bundle, retrieval, manifest,
                                         sid, system_text, model, pipeline_dir)
            except Exception as e2:
                log.error("claims chunk %d/%d failed after retry: %s",
                          idx + 1, len(chunks), e2)
                failed_chunks += 1
                continue
        if not result or "claims" not in result:
            # Do NOT retry — a deterministic generation retried with the same
            # prompt produces the same truncated output. Fail fast and let
            # generation_meta.degraded mark the report.
            log.warning("claims chunk %d/%d returned no claims; marking degraded",
                        idx + 1, len(chunks))
            failed_chunks += 1
            continue
        for claim in result["claims"]:
            # Renumber to guarantee global uniqueness
            all_claims.append(claim)
    # Deduplicate by (text[:80], first citation verbatim[:80]) to collapse
    # the same claim appearing in multiple chunks
    seen = set()
    deduped = []
    for c in all_claims:
        first_cit = (c.get("citations") or [{}])[0]
        sig = (c.get("text", "")[:80].lower(),
               (first_cit.get("verbatim") or "")[:80].lower())
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(c)
    for i, c in enumerate(deduped, 1):
        c["claim_id"] = f"c{i}"
    log.info("claims merged: %d raw -> %d deduped from %d chunks sid=%s",
             len(all_claims), len(deduped), len(chunks), sid)
    return {"claims": deduped, "_chunks_total": len(chunks),
            "_chunks_failed": failed_chunks}


def _generate_rem_claims_chunked(facts, chunks, bundle, retrieval, manifest,
                                 sid, system_text, pipeline_dir):
    """Chunk remediation claims by fact set. Keeps retrieval whole: remediation
    is where knowledge grounding matters most, so do not shrink the chunks
    list unless measurement shows truncation after this."""
    if len(facts) <= FACTS_CHUNK_THRESHOLD:
        vars_dict = {"EVIDENCE_FACTS_JSON": facts,
                     "RETRIEVAL_CHUNKS_JSON": chunks}
        res = _generate_subset("rem_claims", "remediation", "claims", vars_dict,
                               bundle, retrieval, manifest, sid, system_text,
                               EXTRACT_MODEL, pipeline_dir)
        claims = res.get("claims", []) if res else []
        failed = 0 if res else 1
        for i, c in enumerate(claims, 1):
            c["claim_id"] = f"c{i}"
        return {"claims": claims, "_chunks_total": 1, "_chunks_failed": failed}

    facts = [dict(f, verbatim=f.get("verbatim", "")[:400]) for f in facts]
    chunk_list = [facts[i:i+FACTS_PER_CHUNK]
                  for i in range(0, len(facts), FACTS_PER_CHUNK)]
    log.info("rem claims chunked: %d facts -> %d chunks sid=%s",
             len(facts), len(chunk_list), sid)

    all_claims = []
    failed_chunks = 0
    for idx, chunk in enumerate(chunk_list):
        vars_dict = {
            "EVIDENCE_FACTS_JSON": chunk,
            "RETRIEVAL_CHUNKS_JSON": _relevant_chunks_for_facts(chunk, chunks, top_k=2),
            "CHUNK_INDEX": idx + 1,
            "CHUNK_TOTAL": len(chunk_list),
        }
        try:
            res = _generate_subset("rem_claims", "remediation", "claims",
                                   vars_dict, bundle, retrieval, manifest,
                                   sid, system_text, EXTRACT_MODEL, pipeline_dir)
        except Exception as e:
            log.warning("rem claims chunk %d/%d failed (retrying once): %s",
                        idx + 1, len(chunk_list), e)
            try:
                res = _generate_subset("rem_claims", "remediation", "claims",
                                       vars_dict, bundle, retrieval, manifest,
                                       sid, system_text, EXTRACT_MODEL,
                                       pipeline_dir)
            except Exception as e2:
                log.error("rem claims chunk %d/%d failed after retry: %s",
                          idx + 1, len(chunk_list), e2)
                failed_chunks += 1
                continue
        if not res or "claims" not in res:
            # Do NOT retry — a deterministic generation retried with the same
            # prompt produces the same truncated output. Fail fast and let
            # generation_meta.degraded mark the report.
            log.warning("rem claims chunk %d/%d returned no claims; marking degraded",
                        idx + 1, len(chunk_list))
            failed_chunks += 1
            continue
        all_claims.extend(res["claims"])

    seen, deduped = set(), []
    for c in all_claims:
        first_cit = (c.get("citations") or [{}])[0]
        sig = (c.get("text", "")[:80].lower(),
               (first_cit.get("verbatim") or "")[:80].lower())
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(c)
    for i, c in enumerate(deduped, 1):
        c["claim_id"] = f"c{i}"
    log.info("rem claims merged: %d raw -> %d deduped from %d chunks sid=%s",
             len(all_claims), len(deduped), len(chunk_list), sid)
    return {"claims": deduped, "_chunks_total": len(chunk_list),
            "_chunks_failed": failed_chunks}


BEHAVIORAL_KEYS = {
    ("process", "image"), ("process", "command_line"),
    ("process", "parent_image"), ("process", "parent_command_line"),
    ("process", "loader_image"), ("process", "image_loaded"),
    ("process", "image_load"),
    ("process", "access_source_image"), ("process", "access_target_image"),
    ("process", "access_granted"), ("process", "process_access"),
    ("process", "terminated_image"), ("process", "registry_writer"),
    ("process", "dns_image"), ("process", "creator_image"),
    ("process", "deleter_image"), ("process", "network_image"),
    ("process", "monitored_execution"), ("process", "execution_stderr"),
    ("process", "execution_exit_code"), ("process", "payload_log"),
    ("process", "downloaded_was_executed_pid"),
    ("process", "tampered_image"), ("process", "tampering_type"),
    ("process", "remote_thread_source"), ("process", "remote_thread_target"),
    ("process", "remote_thread_start_address"), ("process", "remote_thread_start_module"),
    ("network", "sysmon_connect"), ("network", "pcap_flow"),
    ("network", "source_ip"),
    ("dns", "query"), ("dns", "pcap_query"), ("dns", "pcap_response"),
    ("dns", "query_results"),
    ("file", "created"), ("file", "deleted"),
    ("file", "created_by_sample"), ("file", "downloaded_by_sample"),
    ("file", "downloaded_sha256"),
    ("registry", "key_created"), ("registry", "value_set"),
    ("registry", "value_data"), ("registry", "key_renamed_from"),
    ("registry", "key_renamed_to"),
    ("event", "clipboard_changed_by"), ("event", "clipboard_content_hash"),
}


def _behavioral_facts(facts: list[dict]) -> list[dict]:
    """Facts that produce claims — drops static metadata, PE properties, etc."""
    return [f for f in facts if (f.get("category"), f.get("key")) in BEHAVIORAL_KEYS]


def _sample_features_for_llm(facts: list[dict]) -> dict:
    """Static features that map to knowledge DB entries (CVE / playbook / ATT&CK)."""
    feats: dict = {
        "versioninfo": {}, "pe_imports": [], "peid_signatures": [],
        "report_signatures": [], "report_ttps": [],
        "packed_sections": [],
    }
    for f in facts:
        key = f.get("key", "")
        val = f.get("verbatim") or f.get("value")
        if not val:
            continue
        if key.startswith("versioninfo_"):
            feats["versioninfo"][key[len("versioninfo_"):]] = str(val)
        elif key == "pe_import":
            feats["pe_imports"].append(str(val))
        elif key == "peid_signature":
            feats["peid_signatures"].append(str(val))
        elif key == "report_signature":
            feats["report_signatures"].append(str(val))
        elif key == "report_ttp":
            feats["report_ttps"].append(str(val))
        elif key == "pe_imphash":
            feats["pe_imphash"] = str(val)
        elif key == "pe_timestamp":
            feats["pe_timestamp"] = str(val)
        elif key == "filetype":
            feats["filetype"] = str(val)
        elif key == "media_type":
            feats["media_type"] = str(val)
        elif key == "tree_finger_magic":
            feats["magic"] = str(val)
        elif key == "tree_finger_mime":
            feats["mime"] = str(val)
        elif key == "pe_section":
            m = re.search(r"entropy=([\d.]+)", str(val))
            if m:
                try:
                    if float(m.group(1)) >= 7.0:
                        feats["packed_sections"].append(str(val))
                except ValueError:
                    pass
    return feats


def _produce_draft_bundle(sid, task_id, sanitized, retrieval, manifest,
                          system_text, pipeline_dir):
    """Phase 1: small model produces evidence.json, timeline.json, sample_features.json."""
    from concurrent.futures import ThreadPoolExecutor
    all_facts = sanitized.get("facts", [])
    behavioral = _behavioral_facts(all_facts)
    sample_features = _sample_features_for_llm(all_facts)

    exec_facts = _truncate_facts([f for f in behavioral
                                   if f.get("category") in ("process", "network", "dns")])
    rem_facts = _truncate_facts([f for f in behavioral
                                  if f.get("category") in ("network", "dns", "registry",
                                                           "persistence", "credential_access",
                                                           "process")])
    timeline_candidates = _derive_timeline_candidates({"facts": behavioral})
    chunks = _truncate_chunks(retrieval.get("results", []))

    draft = {
        "evidence": {"claims": [], "mitre_candidates": [],
                     "behavioral_summary": {}, "_chunks_total": 0,
                     "_chunks_failed": 0},
        "timeline": {"events": [], "steps": [], "candidate_claim_ids": [],
                     "_chunks_total": 0, "_chunks_failed": 0},
        "sample_features": sample_features,
    }

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_e = pool.submit(_generate_claims_chunked, "exec_claims", "executive_risk",
                          exec_facts, {}, sanitized, retrieval, manifest, sid,
                          system_text, EXTRACT_MODEL, pipeline_dir)
        f_r = pool.submit(_generate_rem_claims_chunked, rem_facts, chunks,
                          sanitized, retrieval, manifest, sid, system_text, pipeline_dir)
        exec_res = f_e.result()
        rem_res = f_r.result()

    if exec_res:
        for _c in exec_res.get("claims", []):
            _c["claim_id"] = f"e_{_c.get('claim_id', '')}"
        draft["evidence"]["claims"].extend(exec_res.get("claims", []))
        draft["evidence"]["_chunks_total"] += exec_res.get("_chunks_total", 0) or 0
        draft["evidence"]["_chunks_failed"] += exec_res.get("_chunks_failed", 0) or 0
    if rem_res:
        for _c in rem_res.get("claims", []):
            _c["claim_id"] = f"r_{_c.get('claim_id', '')}"
        draft["evidence"]["claims"].extend(rem_res.get("claims", []))
        draft["evidence"]["_chunks_total"] += rem_res.get("_chunks_total", 0) or 0
        draft["evidence"]["_chunks_failed"] += rem_res.get("_chunks_failed", 0) or 0

    draft["evidence"]["behavioral_summary"] = {
        "processes_spawned": sum(1 for f in behavioral
                                  if f.get("category") == "process"
                                  and f.get("key") == "image"),
        "network_connections": sum(1 for f in behavioral
                                    if f.get("category") == "network"
                                    and f.get("key") != "source_ip"),
        "files_written": sum(1 for f in behavioral
                              if f.get("category") == "file"
                              and f.get("key") in ("created", "created_by_sample")),
        "dns_queries": sum(1 for f in behavioral
                            if f.get("category") == "dns"),
        "registry_writes": sum(1 for f in behavioral
                                if f.get("category") == "registry"),
    }

    if draft["evidence"]["claims"]:
        _mitre_input = [{"claim_id": c.get("claim_id"),
                          "text": (c.get("text") or "")[:200]}
                         for c in draft["evidence"]["claims"][:20]]
        _mitre_facts = [{"fact_id": f.get("fact_id"),
                          "category": f.get("category"),
                          "key": f.get("key"),
                          "verbatim": (f.get("verbatim") or "")[:150]}
                         for f in exec_facts if f.get("key") != "pcap_flow"][:15]
        mitre_res = _generate_subset(
            "exec_mitre", "executive_risk", "mitre_techniques",
            {"CLAIMS_JSON": _mitre_input,
             "EVIDENCE_FACTS_JSON": _mitre_facts},
            sanitized, retrieval, manifest, sid, system_text,
            EXTRACT_MODEL, pipeline_dir)
        if mitre_res:
            draft["evidence"]["mitre_candidates"] = mitre_res.get("mitre_techniques", [])

    tl_chunks = [timeline_candidates[i:i+15]
                 for i in range(0, len(timeline_candidates), 15)]
    if not tl_chunks:
        tl_chunks = [[]]
    fact_by_id = {f["fact_id"]: f for f in _truncate_facts(behavioral)
                  if f.get("fact_id")}

    for chunk_idx, chunk_candidates in enumerate(tl_chunks):
        if not chunk_candidates:
            continue
        referenced = {c["source_fact_id"] for c in chunk_candidates
                      if c.get("source_fact_id")}
        chunk_facts = [fact_by_id[fid] for fid in referenced if fid in fact_by_id]
        if len(chunk_facts) < 20:
            seen = {f["fact_id"] for f in chunk_facts}
            for f in fact_by_id.values():
                if f["fact_id"] in seen:
                    continue
                chunk_facts.append(f)
                if len(chunk_facts) >= 20:
                    break

        events_res = _generate_subset(
            "timeline_events", "timeline_attack_chain",
            ["timeline_events", "claims"],
            {"TIMELINE_CANDIDATES_JSON": chunk_candidates,
             "EVIDENCE_FACTS_JSON": chunk_facts},
            sanitized, retrieval, manifest, sid, system_text,
            EXTRACT_MODEL, pipeline_dir)
        events = events_res.get("timeline_events", []) if events_res else []
        tl_claims = events_res.get("claims", []) if events_res else []
        if not tl_claims:
            draft["timeline"]["_chunks_failed"] += 1
            continue

        _id_map = {}
        for _i, _c in enumerate(tl_claims):
            _old_id = _c.get("claim_id", "")
            _new_id = f"tl_{chunk_idx}_{_i}"
            if _old_id:
                _id_map[_old_id] = _new_id
            _c["claim_id"] = _new_id
        for _ev in events:
            _ref = _ev.get("description_claim_id", "")
            if _ref in _id_map:
                _ev["description_claim_id"] = _id_map[_ref]
        draft["timeline"]["events"].extend(events)
        draft["evidence"]["claims"].extend(tl_claims)
        draft["timeline"]["candidate_claim_ids"].extend([c["claim_id"] for c in tl_claims])


    draft["timeline"]["events"].sort(key=lambda e: str(e.get("timestamp") or ""))
    draft["timeline"]["_chunks_total"] = len([c for c in tl_chunks if c])

    if draft["timeline"]["events"]:
        steps_events = draft["timeline"]["events"][:40]
        steps_claims = draft["evidence"]["claims"][:30]
        steps_res = _generate_subset(
            "timeline_steps", "timeline_attack_chain", "attack_chain_steps",
            {"TIMELINE_EVENTS_JSON": steps_events, "CLAIMS_JSON": steps_claims},
            sanitized, retrieval, manifest, sid, system_text,
            EXTRACT_MODEL, pipeline_dir)
        if steps_res:
            draft["timeline"]["steps"] = steps_res.get("attack_chain_steps", [])

    _write_json(pipeline_dir / "evidence.json", draft["evidence"])
    _write_json(pipeline_dir / "timeline.json", draft["timeline"])
    _write_json(pipeline_dir / "sample_features.json", draft["sample_features"])
    log.info("v2 phase 1 done sid=%s claims=%d events=%d",
             sid, len(draft["evidence"]["claims"]), len(draft["timeline"]["events"]))
    return draft


def _assemble_timeline_report(draft, sid, task_id, sanitized, retrieval,
                               manifest, system_text, pipeline_dir):
    """Call B: large model picks events + narrative."""
    evidence = draft["evidence"]
    timeline = draft["timeline"]
    if not timeline["events"]:
        log.warning("v2 timeline: no events; returning draft with abstention")
        report = {
            "timeline_events": [], "attack_chain_steps": [],
            "attack_chain_narrative_claim_id": (evidence["claims"][0]["claim_id"]
                                                 if evidence["claims"] else None),
            "claims": evidence["claims"] or [],
            "abstentions": [{
                "section": "timeline_events",
                "reason": "The sample produced no timestamped events within the analysis window.",
                "evidence_gap": "no process, network, or file events attributable to the sample",
            }],
            "gaps": [],
            "generation_meta": {
                "chunks_total": timeline.get("_chunks_total", 0),
                "chunks_failed": timeline.get("_chunks_failed", 0),
                "degraded": False,
            },
        }
        v, _ = _parse_and_verify(json.dumps(report), "timeline_attack_chain",
                                  sanitized, retrieval, manifest, sid)
        return v

    _all_events = timeline["events"][:30]
    _event_chunks = [_all_events[i:i+10] for i in range(0, len(_all_events), 10)]
    if not _event_chunks:
        _event_chunks = [[]]
    _merged_event_ids: list[str] = []
    _merged_step_ids: list[str] = []
    _merged_gaps: list = []
    _narrative_id = None
    _chunks_failed = 0
    for _chunk_events in _event_chunks:
        if not _chunk_events:
            continue
        _r = _generate_subset(
            "timeline_assembly", "timeline_attack_chain",
            ["attack_chain_narrative_claim_id", "timeline_event_ids",
             "attack_chain_step_ids", "gaps"],
            {"EVIDENCE_JSON": {
                "claims": evidence["claims"][:10],
                "mitre_candidates": evidence.get("mitre_candidates", []),
                "behavioral_summary": evidence.get("behavioral_summary", {}),
             },
             "TIMELINE_JSON": {"events": _chunk_events,
                               "steps": timeline["steps"][:15]}},
            sanitized, retrieval, manifest, sid, system_text,
            REASON_MODEL, pipeline_dir)
        if _r:
            _merged_event_ids.extend(_r.get("timeline_event_ids", []))
            _merged_step_ids.extend(_r.get("attack_chain_step_ids", []))
            _merged_gaps.extend(_r.get("gaps", []))
            if _narrative_id is None:
                _narrative_id = _r.get("attack_chain_narrative_claim_id")
        else:
            _chunks_failed += 1

    if not _merged_event_ids and not _merged_step_ids:
        log.error("v2 timeline assembly failed; using draft as-is")
        report = {
            "timeline_events": timeline["events"][:40],
            "attack_chain_steps": timeline["steps"][:8],
            "attack_chain_narrative_claim_id": (evidence["claims"][0]["claim_id"]
                                                 if evidence["claims"] else None),
            "claims": evidence["claims"] or [],
            "abstentions": [], "gaps": [],
            "generation_meta": {
                "chunks_total": timeline.get("_chunks_total", 0),
                "chunks_failed": timeline.get("_chunks_failed", 0),
                "degraded": True,
            },
        }
        v, _ = _parse_and_verify(json.dumps(report), "timeline_attack_chain",
                                  sanitized, retrieval, manifest, sid)
        return v

    res = {
        "timeline_event_ids": _merged_event_ids,
        "attack_chain_step_ids": _merged_step_ids,
        "attack_chain_narrative_claim_id": _narrative_id,
        "gaps": _merged_gaps,
    }

    event_map = {e["event_id"]: e for e in timeline["events"]}
    step_map = {s["step_id"]: s for s in timeline["steps"]}
    selected_events = [event_map[eid] for eid in res.get("timeline_event_ids", [])
                       if eid in event_map]
    selected_steps = [step_map[sid_] for sid_ in res.get("attack_chain_step_ids", [])
                      if sid_ in step_map]
    report = {
        "timeline_events": selected_events,
        "attack_chain_steps": selected_steps,
        "attack_chain_narrative_claim_id": res.get("attack_chain_narrative_claim_id"),
        "claims": evidence["claims"] or [],
        "abstentions": [],
        "gaps": res.get("gaps", []),
        "generation_meta": {
            "chunks_total": timeline.get("_chunks_total", 0),
            "chunks_failed": timeline.get("_chunks_failed", 0),
            "degraded": timeline.get("_chunks_failed", 0) > 0,
        },
    }
    v, _ = _parse_and_verify(json.dumps(report), "timeline_attack_chain",
                              sanitized, retrieval, manifest, sid)
    return v


def _assemble_rem_report(draft, sid, task_id, sanitized, retrieval,
                          manifest, system_text, pipeline_dir):
    """Call C: large model uses sample_features + retrieval to write recommendations."""
    evidence = draft["evidence"]
    sample_features = draft["sample_features"]
    chunks = _truncate_chunks(retrieval.get("results", []))

    _all_claims = evidence["claims"][:20]
    _claim_chunks = [_all_claims[i:i+10] for i in range(0, len(_all_claims), 10)]
    if not _claim_chunks:
        _claim_chunks = [[]]
    _chunk_groups = [chunks[i:i+3] for i in range(0, len(chunks), 3)]
    while len(_chunk_groups) < len(_claim_chunks):
        _chunk_groups.append(chunks[:3])

    _all_recs = []
    _threat_id = None
    _chunks_failed = 0
    for _claims_chunk, _chunks_chunk in zip(_claim_chunks, _chunk_groups):
        if not _claims_chunk:
            continue
        _r = _generate_subset(
            "rem_assembly", "remediation",
            ["threat_model_claim_id", "recommendations"],
            {"EVIDENCE_JSON": {
                "claims": _claims_chunk,
                "mitre_candidates": evidence.get("mitre_candidates", []),
                "behavioral_summary": evidence.get("behavioral_summary", {}),
             },
             "SAMPLE_FEATURES_JSON": sample_features,
             "RETRIEVAL_CHUNKS_JSON": _chunks_chunk},
            sanitized, retrieval, manifest, sid, system_text,
            REASON_MODEL, pipeline_dir)
        if _r:
            _all_recs.extend(_r.get("recommendations", []))
            if _threat_id is None:
                _threat_id = _r.get("threat_model_claim_id")
        else:
            _chunks_failed += 1

    for _i, _r in enumerate(_all_recs, 1):
        _r["recommendation_id"] = f"r{_i}"
    threat_id = _threat_id
    recs = _all_recs

   # threat_id = None
   # recs = []
   # if res:
   #     threat_id = res.get("threat_model_claim_id")
   #     recs = res.get("recommendations", [])

    report = {
        "threat_model_claim_id": threat_id,
        "recommendations": recs,
        "claims": evidence["claims"] or [],
        "abstentions": [] if recs else [{
            "section": "threat_model",
            "reason": "The sample produced no behavioral evidence warranting "
                      "specific remediation recommendations. Static properties "
                      "were reviewed against the knowledge base but no CVE or "
                      "playbook applies.",
            "evidence_gap": "no process, network, file, or registry behavior "
                            "was observed from the sample",
        }],
        "generation_meta": {
            "chunks_total": len(_claim_chunks),
            "chunks_failed": _chunks_failed,
            "degraded": _chunks_failed > 0,
        },
    }
    v, _ = _parse_and_verify(json.dumps(report), "remediation",
                              sanitized, retrieval, manifest, sid)
    return v


def _assemble_exec_report(draft, timeline_report, rem_report,
                           sid, task_id, sanitized, retrieval,
                           manifest, system_text, pipeline_dir):
    """Call A: large model writes the executive summary using timeline + remediation + sample_features."""
    evidence = draft["evidence"]
    sample_features = draft["sample_features"]

    # Build the set of claim IDs that survived verification in timeline and
    # rem reports. Exec must reason over exactly these claims; citing ones
    # that will be dropped by the verifier causes the whole exec report to
    # be rejected silently.
    _surviving_ids = set()
    for _r in (timeline_report, rem_report):
        if not _r:
            continue
        for _c in (_r.get("claims") or []):
            _cid = _c.get("claim_id")
            if _cid:
                _surviving_ids.add(_cid)
    exec_claims = [c for c in evidence["claims"] if c.get("claim_id") in _surviving_ids]
    if not exec_claims:
        log.warning("exec skipped: no claims survived timeline/rem; using raw draft claims")
        exec_claims = list(evidence["claims"])


    tl_events = timeline_report.get("timeline_events", []) if timeline_report else []
    tl_steps = timeline_report.get("attack_chain_steps", []) if timeline_report else []
    rem_recs = rem_report.get("recommendations", []) if rem_report else []

    timeline_summary = {
        "event_count": len(tl_events),
        "step_count": len(tl_steps),
        "phases_observed": sorted({s.get("phase") for s in tl_steps
                                    if s.get("phase")}),
    }
    rem_summary = {
        "recommendation_count": len(rem_recs),
        "top_categories": sorted({r.get("category") for r in rem_recs[:5]
                                   if r.get("category")}),
    }

    _chunks = _truncate_chunks(retrieval.get("results", []))
    _mitre = [c for c in _chunks if c.get("source_type") == "mitre-attack"][:2]
    if _mitre:
        _ids = {c["chunk_id"] for c in _mitre}
        _chunks = [c for c in _chunks if c["chunk_id"] not in _ids][:6 - len(_mitre)] + _mitre

    res = _generate_subset(
        "exec_assembly", "executive_risk",
        ["risk_level", "summary_claim_text", "summary_evidence_claim_ids",
         "key_finding_ids", "mitre_techniques"],
        {"EVIDENCE_JSON": {
            "claims": exec_claims[:20],
            "mitre_candidates": evidence.get("mitre_candidates", []),
            "behavioral_summary": evidence.get("behavioral_summary", {}),
         },
         "SAMPLE_FEATURES_JSON": sample_features,
         "TIMELINE_SUMMARY_JSON": timeline_summary,
         "REMEDIATION_SUMMARY_JSON": rem_summary,
         "RETRIEVAL_CHUNKS_JSON": _chunks},
        sanitized, retrieval, manifest, sid, system_text,
        REASON_MODEL, pipeline_dir)

    if not res:
        log.error("v2 exec assembly failed")
        report = {
            "claims": exec_claims or [],
            "mitre_techniques": evidence.get("mitre_candidates", []),
            "summary_claim_id": (exec_claims[0]["claim_id"]
                                  if exec_claims else None),
            "key_finding_ids": [], "risk_level": "unknown",
            "insufficient_evidence": True, "abstentions": [],
            "generation_meta": {
                "chunks_total": evidence.get("_chunks_total", 0),
                "chunks_failed": evidence.get("_chunks_failed", 0),
                "degraded": True,
            },
        }
        v, _exec_errs = _parse_and_verify(json.dumps(report), "executive_risk",
                                           sanitized, retrieval, manifest, sid)

        if v is None:
            log.error("exec report rejected by verifier: %s", _exec_errs[:5])

        return v

    claims_by_id = {c["claim_id"]: c for c in exec_claims}
    _raw_mitre = res.get("mitre_techniques", evidence.get("mitre_candidates", []))
    _valid_claim_ids = set(claims_by_id.keys())
    _clean_mitre = []
    for _t in _raw_mitre:
        if isinstance(_t, dict):
            _valid = [c for c in (_t.get("evidence_claim_ids") or []) if c in _valid_claim_ids]
            if _valid:
                _clean_mitre.append({**_t, "evidence_claim_ids": _valid})

    summary_text = res.get("summary_claim_text", "")
    summary_src_ids = res.get("summary_evidence_claim_ids", [])
    summary_citations = []
    for cid in summary_src_ids:
        src = claims_by_id.get(cid)
        if src:
            summary_citations.extend(src.get("citations", []))

    claims = list(exec_claims)
    if summary_text and summary_citations:
        claims.append({
            "claim_id": "c_summary",
            "text": summary_text,
            "citations": summary_citations[:5],
            "status": "verified",
        })
        summary_id = "c_summary"
    elif claims:
        summary_id = claims[0]["claim_id"]
    else:
        summary_id = None

    report = {
        "claims": claims,
        "mitre_techniques": _clean_mitre,
        "summary_claim_id": summary_id,
        "key_finding_ids": [c for c in res.get("key_finding_ids", []) if c in {x["claim_id"] for x in claims}],
        "risk_level": res.get("risk_level", "unknown"),
        "insufficient_evidence": False,
        "abstentions": [],
        "generation_meta": {
            "chunks_total": evidence.get("_chunks_total", 0),
            "chunks_failed": evidence.get("_chunks_failed", 0),
            "degraded": evidence.get("_chunks_failed", 0) > 0,
        },
    }
    v, _exec_errs = _parse_and_verify(json.dumps(report), "executive_risk",
                              sanitized, retrieval, manifest, sid)
    if v is None:
        log.error("exec report rejected by verifier (primary): %s", _exec_errs[:5])

    return v


def _filter_verified_claims(claims: list[dict], bundle: dict) -> list[dict]:
    """Drop claims whose citations reference non-existent fact_ids or
    whose verbatim does not exactly match the cited fact's stored verbatim.
    This prevents the orphan cascade in _assemble_timeline_report,
    _assemble_rem_report, and _assemble_exec_report — instead of dropping
    ~15 claims inside each report's verifier, we drop them once here
    and every report sees only valid claims from the start."""
    from app.verifier import _verify_citation, _facts_by_id
    facts = _facts_by_id(bundle)
    seen_ids: set[str] = set()
    valid = []

    for c in claims:
        _cid = c.get("claim_id")
        if _cid and _cid in seen_ids:
            continue
        cits = c.get("citations") or []
        if not cits:
            continue
        ok = True
        for cit in cits:
            if cit.get("source_type") != "evidence":
                continue
            vok, _reason = _verify_citation(cit, facts, {})
            if not vok:
                ok = False
                break
        if ok:
            if _cid:
                seen_ids.add(_cid)
            valid.append(c)
    return valid


def _generate_all_reports_v2(row: dict) -> dict:
    """Two-phase: small model draft, large model assembly. Exec reads timeline+rem."""

    import threading

    _stop_heartbeat = threading.Event()

    def _heartbeat():
        # Refresh updated_at every 5 min during long generation so
        # _reclaim_zombies does not treat a live-but-slow submission as
        # a dead worker. Same state, no phase change.
        while not _stop_heartbeat.wait(300):
            try:
                renewed = db.renew_claim(
                    row["webapp_submission_id"], _WORKER_ID
                )
                if not renewed:
                    log.warning(
                        "heartbeat lost claim sid=%s worker=%s",
                        row["webapp_submission_id"], _WORKER_ID,
                    )
            except Exception:
                pass

    _hb = threading.Thread(target=_heartbeat, daemon=True, name=f"hb-{row['webapp_submission_id']}")
    _hb.start()

    from concurrent.futures import ThreadPoolExecutor
    sid = row["webapp_submission_id"]
    task_id = row["cuckoo_task_id"]
    pipeline_dir = _pipeline_dir(task_id)
    sanitized = _read_json(pipeline_dir / "sanitized_bundle.json")
    manifest = _read_json(pipeline_dir / "sanitization_manifest.json")
    retrieval = _read_json(pipeline_dir / "retrieval_result.json")
    system_text = (PROMPTS_DIR / "system.txt").read_text(encoding="utf-8")

    draft = _produce_draft_bundle(sid, task_id, sanitized, retrieval, manifest,
                                   system_text, pipeline_dir)

    _pre_n = len(draft["evidence"]["claims"])
    draft["evidence"]["claims"] = _filter_verified_claims(
        draft["evidence"]["claims"], sanitized)
    _valid_ids = {c["claim_id"] for c in draft["evidence"]["claims"]}
    _ev_before = len(draft["timeline"]["events"])
    draft["timeline"]["events"] = [
        e for e in draft["timeline"]["events"]
        if e.get("description_claim_id") in _valid_ids
    ]
    log.info("claim_pre_verify: %d -> %d valid, events %d -> %d (sid=%s)",
             _pre_n, len(draft["evidence"]["claims"]),
             _ev_before, len(draft["timeline"]["events"]), sid)


    reports: dict = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_tl = pool.submit(_assemble_timeline_report, draft, sid, task_id,
                            sanitized, retrieval, manifest, system_text, pipeline_dir)
        f_rm = pool.submit(_assemble_rem_report, draft, sid, task_id,
                            sanitized, retrieval, manifest, system_text, pipeline_dir)
        timeline_report = f_tl.result()
        rem_report = f_rm.result()

    if timeline_report:
        reports["timeline_attack_chain"] = timeline_report
    if rem_report:
        reports["remediation"] = rem_report

    exec_report = _assemble_exec_report(draft, timeline_report, rem_report,
                                         sid, task_id, sanitized, retrieval,
                                         manifest, system_text, pipeline_dir)
    if exec_report:
        reports["executive_risk"] = exec_report

    log.info("v2 complete sid=%s reports=%d", sid, len(reports))

    _stop_heartbeat.set()
    return reports



def _generate_all_reports(row: dict) -> dict:
    from concurrent.futures import ThreadPoolExecutor

    sid = row["webapp_submission_id"]
    task_id = row["cuckoo_task_id"]
    pipeline_dir = _pipeline_dir(task_id)
    sanitized = _read_json(pipeline_dir / "sanitized_bundle.json")
    manifest = _read_json(pipeline_dir / "sanitization_manifest.json")
    retrieval = _read_json(pipeline_dir / "retrieval_result.json")

    all_facts = sanitized.get("facts", [])
    chunks = _truncate_chunks(retrieval.get("results", []))
    system_text = (PROMPTS_DIR / "system.txt").read_text(encoding="utf-8")
    reports = {}

    def _filter_facts(cats):
        return _truncate_facts([f for f in all_facts if f.get("category") in cats])

    # --- 1. EXECUTIVE RISK (Map-Reduce) ---
    log.info("exec_risk: start map-reduce sid=%s", sid)
    exec_facts = _filter_facts({"metadata", "process", "network", "screenshot"})

    # Map: Claims (Tiny Model)
    claims_res = _generate_claims_chunked("exec_claims", "executive_risk",
                                          exec_facts, {},
                                          sanitized, retrieval, manifest, sid,
                                          system_text, EXTRACT_MODEL, pipeline_dir)
    claims = claims_res.get("claims", []) if claims_res else []
    exec_chunks_failed = claims_res.get("_chunks_failed", 0) if claims_res else 0
    exec_chunks_total  = claims_res.get("_chunks_total", 1) if claims_res else 1
    # Verify claims immediately - no longer needed
    #if claims:
        #temp_report = {"claims": claims, "abstentions": [], "key_finding_ids": [], "mitre_techniques": []}
        #temp_verified, _ = _parse_and_verify(json.dumps(temp_report), "executive_risk", sanitized, retrieval, manifest, sid)
       # if temp_verified:
      #      claims = temp_verified.get("claims", [])

    # Map: MITRE (Tiny Model)
    if not claims:
        log.warning("exec_claims produced no claims sid=%s; skipping mitre/summary", sid)
        exec_report = {
            "claims": [],
            "mitre_techniques": [],
            "summary_claim_id": None,
            "key_finding_ids": [],
            "risk_level": "unknown",
            "insufficient_evidence": True,
            "abstentions": [],
        }
        exec_verified, _ = _parse_and_verify(json.dumps(exec_report), "executive_risk", sanitized, retrieval, manifest, sid)
        if exec_verified:
            reports["executive_risk"] = exec_verified
    else:
        mitre_res = _generate_subset("exec_mitre", "executive_risk", "mitre_techniques", {"CLAIMS_JSON": claims, "EVIDENCE_FACTS_JSON": exec_facts[:80]}, sanitized, retrieval, manifest, sid, system_text, EXTRACT_MODEL, pipeline_dir)
        mitre = mitre_res.get("mitre_techniques", []) if mitre_res else []

        summary_res = _generate_subset(
            "exec_summary", "executive_risk",
            ["summary_claim_id", "key_finding_ids", "risk_level"],
            {"CLAIMS_JSON": claims},
            sanitized, retrieval, manifest, sid, system_text, REASON_MODEL, pipeline_dir,
        )
        summary_id = summary_res.get("summary_claim_id") if summary_res else None
        key_findings = summary_res.get("key_finding_ids", []) if summary_res else []
        risk_level = summary_res.get("risk_level", "unknown") if summary_res else "unknown"

        exec_report = {
            "claims": claims,
            "mitre_techniques": mitre,
            "summary_claim_id": summary_id,
            "key_finding_ids": key_findings,
            "risk_level": risk_level,
            "insufficient_evidence": False,
            "abstentions": [],
            "generation_meta": {
                "chunks_total": exec_chunks_total,
                "chunks_failed": exec_chunks_failed,
                "degraded": exec_chunks_failed > 0,
            },
        }
        exec_verified, _ = _parse_and_verify(json.dumps(exec_report), "executive_risk", sanitized, retrieval, manifest, sid)
        if exec_verified:
            reports["executive_risk"] = exec_verified

    # --- 2. TIMELINE (Map-Reduce) ---
    log.info("timeline: start map-reduce sid=%s", sid)
    tl_facts = _filter_facts({"process", "network", "dns", "file", "metadata"})
    fact_by_id = {f["fact_id"]: f for f in tl_facts if f.get("fact_id")}
    candidates = _derive_timeline_candidates(sanitized)
    CHUNK_SIZE = 5
    tl_chunks = [candidates[i:i + CHUNK_SIZE] for i in range(0, len(candidates), CHUNK_SIZE)]
    if not tl_chunks: tl_chunks = [[]]
    tl_chunks_failed = 0

    for chunk_idx, chunk_candidates in enumerate(tl_chunks):
        if not chunk_candidates:
            continue # Skip empty chunks as before

        # Map: Events (Tiny Model and qwen model mapping)
        # tl_facts is already per-chunk (from _derive_timeline_candidates slicing)
        # truncates chunk tl_facts too.
        referenced_ids = {
            c["source_fact_id"] for c in chunk_candidates
            if c.get("source_fact_id")
        }
        chunk_tl_facts = [fact_by_id[fid] for fid in referenced_ids
                          if fid in fact_by_id]
        if len(chunk_tl_facts) < 20:
            seen_ids = {f["fact_id"] for f in chunk_tl_facts}
            for f in tl_facts:
                if f["fact_id"] in seen_ids:
                    continue
                chunk_tl_facts.append(f)
                if len(chunk_tl_facts) >= 20:
                    break

        tl_vars = {
            "TIMELINE_CANDIDATES_JSON": chunk_candidates,
            "EVIDENCE_FACTS_JSON": chunk_tl_facts,
        }
        events_res = _generate_subset(
            "timeline_events", "timeline_attack_chain",
            ["timeline_events", "claims"],
            tl_vars,
            sanitized, retrieval, manifest, sid, system_text, EXTRACT_MODEL, pipeline_dir,
        )
        events = events_res.get("timeline_events", []) if events_res else []
        tl_claims = events_res.get("claims", []) if events_res else []
        if not tl_claims:
            log.warning("timeline chunk %d returned no claims; marking degraded",
                        chunk_idx)
            tl_chunks_failed += 1
            continue
        if not events:
            log.info("timeline chunk %d: claims but no events; skipping steps",
                     chunk_idx)
            steps = []
        else:
            steps_res = _generate_subset(
                "timeline_steps", "timeline_attack_chain", "attack_chain_steps",
                {"TIMELINE_EVENTS_JSON": events, "CLAIMS_JSON": tl_claims},
                sanitized, retrieval, manifest, sid, system_text,
                EXTRACT_MODEL, pipeline_dir,
            )
            steps = steps_res.get("attack_chain_steps", []) if steps_res else []

        # Assemble Timeline Report
        tl_report = {
            "timeline_events": events,
            "attack_chain_steps": steps,
            "attack_chain_narrative_claim_id": None,
            "claims": tl_claims,
            "abstentions": [],
            "gaps": [],
            "generation_meta": {
                "chunks_total": len(tl_chunks),
                "chunks_failed": tl_chunks_failed,
                "degraded": tl_chunks_failed > 0,
            },
        }
        tl_verified, _ = _parse_and_verify(json.dumps(tl_report), "timeline_attack_chain", sanitized, retrieval, manifest, sid)
        if tl_verified:
            if "timeline_attack_chain" not in reports:
                reports["timeline_attack_chain"] = tl_verified
            else:
                # Merge chunks
                reports["timeline_attack_chain"]["timeline_events"].extend(tl_verified["timeline_events"])
                reports["timeline_attack_chain"]["attack_chain_steps"].extend(tl_verified["attack_chain_steps"])
                reports["timeline_attack_chain"]["claims"].extend(tl_verified.get("claims", []))

    if "timeline_attack_chain" in reports:
        reports["timeline_attack_chain"]["timeline_events"].sort(key=lambda x: str(x.get("timestamp") or ""))
    if "timeline_attack_chain" in reports:
        merged_events = reports["timeline_attack_chain"].get("timeline_events") or []
        merged_claims = reports["timeline_attack_chain"].get("claims") or []
        if merged_events and merged_claims:
            narrative_res = _generate_subset(
                "timeline_narrative", "timeline_attack_chain",
                "attack_chain_narrative_claim_id",
                {"TIMELINE_EVENTS_JSON": merged_events,
                 "CLAIMS_JSON": merged_claims},
                sanitized, retrieval, manifest, sid, system_text,
                REASON_MODEL, pipeline_dir,
            )
            narrative_id = (narrative_res.get("attack_chain_narrative_claim_id")
                            if narrative_res else None)
            if narrative_id:
                valid_ids = {c["claim_id"] for c in merged_claims}
                if narrative_id in valid_ids:
                    reports["timeline_attack_chain"]["attack_chain_narrative_claim_id"] = narrative_id
                else:
                    log.warning("post-merge narrative returned unknown claim_id %s; "
                                "leaving narrative null", narrative_id)

    # --- 3. REMEDIATION (Map-Reduce) ---
    log.info("remediation: start map-reduce sid=%s", sid)
    rem_facts = _filter_facts({"network", "dns", "registry", "persistence", "credential_access", "process"})

    # Map: Remediation Claims (Reasoning Model - links evidence + knowledge)
    rem_claims_res = _generate_rem_claims_chunked(
        rem_facts, chunks, sanitized, retrieval, manifest,
        sid, system_text, pipeline_dir,
    )
    rem_claims = rem_claims_res.get("claims", []) if rem_claims_res else []
    rem_chunks_failed = rem_claims_res.get("_chunks_failed", 0) if rem_claims_res else 0
    rem_chunks_total  = rem_claims_res.get("_chunks_total", 1) if rem_claims_res else 1
    if not rem_claims:
        log.warning("remediation claims empty sid=%s; skipping recommendations", sid)
        rem_report = {
            "threat_model_claim_id": None,
            "recommendations": [],
            "claims": [],
            "abstentions": [],
            "generation_meta": {
                "chunks_total": rem_chunks_total,
                "chunks_failed": rem_chunks_failed,
                "degraded": rem_chunks_failed > 0,
            },
        }
        rem_verified, _ = _parse_and_verify(json.dumps(rem_report), "remediation", sanitized, retrieval, manifest, sid)
        if rem_verified:
            reports["remediation"] = rem_verified
        return reports

    # Map: Threat Model + Recs (Reasoning Model)
    recs_res = _generate_subset(
        "rem_recs", "remediation", ["threat_model_claim_id", "recommendations"],
        {"CLAIMS_JSON": rem_claims},
        sanitized, retrieval, manifest, sid, system_text, REASON_MODEL, pipeline_dir,
    )
    threat_id = recs_res.get("threat_model_claim_id") if recs_res else None
    recs = recs_res.get("recommendations", []) if recs_res else []

    # Assemble Remediation
    rem_report = {
        "threat_model_claim_id": threat_id,
        "recommendations": recs,
        "claims": rem_claims,
        "abstentions": [],
        "generation_meta": {
            "chunks_total": rem_chunks_total,
            "chunks_failed": rem_chunks_failed,
            "degraded": rem_chunks_failed > 0,
        },
    }

    # Verify
    rem_verified, _ = _parse_and_verify(json.dumps(rem_report), "remediation", sanitized, retrieval, manifest, sid)
    if rem_verified:
        reports["remediation"] = rem_verified

    return reports




def _handle_retrieval_done(row: dict) -> bool:
    sid = row["webapp_submission_id"]
    task_id = row["cuckoo_task_id"]
    pipeline_dir = _pipeline_dir(task_id)
    _required = (pipeline_dir / "sanitized_bundle.json",
                 pipeline_dir / "sanitization_manifest.json",
                 pipeline_dir / "retrieval_result.json")
    _missing = [str(p) for p in _required if not p.is_file()]
    if _missing:
        _fail(row, "generation", "pipeline_artifacts_missing",
              f"required artifacts missing (likely purged externally): {_missing}")
        return True
    reports_file = pipeline_dir / "reports.json"

    if reports_file.is_file():
        log.info("reports cached, skipping llm sid=%s", sid)
        reports = _read_json(reports_file)
    else:
        db.set_state(sid, "generating_reports")
        reports = _generate_all_reports_v2(row)
        if not reports:
            _fail(row, "generation", "generation_failed", "all three reports failed generation")
            return True

        tl = reports.get("timeline_attack_chain")
        if tl is not None:
            events = tl.get("timeline_events") or []
            steps = tl.get("attack_chain_steps") or []
            abstentions = tl.get("abstentions") or []
            if not events and not steps and not abstentions:
                sanitized_for_count = _read_json(pipeline_dir / "sanitized_bundle.json")
                candidate_count = len(_derive_timeline_candidates(sanitized_for_count))
                if candidate_count > 0:
                    _fail(
                        row, "generation", "timeline_empty_after_verify",
                        f"timeline has 0 events, 0 steps, 0 abstentions, but "
                        f"evidence had {candidate_count} candidates; "
                        f"verifier must have dropped every event for bad citations",
                    )
                    return True
                log.warning(
                    "timeline empty and no candidates sid=%s; adding abstention",
                    sid,
                )
                tl.setdefault("abstentions", []).append({
                    "section": "timeline_events",
                    "reason": "the evidence bundle contained no extractable "
                              "timeline events (no sysmon process events, no "
                              "pcap flows, no file operations)",
                    "evidence_gap": "no timeline candidates were derivable "
                                    "from the sandbox artifacts",
                })

        _write_json(reports_file, reports)

    db.set_state(sid, "verifying")
    db.set_state(sid, "rendering")
    try:
        sanitized = _read_json(pipeline_dir / "sanitized_bundle.json")
        manifest = _read_json(pipeline_dir / "sanitization_manifest.json")
        # Inject absolute paths for screenshots so the renderer can read them
        shots = []
        for s in sanitized.get("screenshots", []):
            rel = s.get("relative_path", "")
            abs_p = (ANALYSES_ROOT / task_id / rel) if rel else None
            shots.append({
                **s,
                "absolute_path": str(abs_p) if abs_p else None,
            })

        result = renderer.render_all(
            reports=reports,
            evidence_bundle=sanitized,
            manifest=manifest,
            webapp_submission_id=sid,
            user_id=row["user_id"],
            out_dir=REPORTS_ROOT / sid,
            screenshots=shots,
        )
        manifest_entries = []
        for r in result["reports"]:
            manifest_entries.append({
                "type": r["type"],
                "sha256": r["sha256"],
                "generated_at": r["generated_at"],
                "relative_path": r["relative_path"],
            })
    except Exception as e:
        _fail(row, "rendering", "render_failed", str(e))
        return True

    db.set_report_manifest(sid, manifest_entries)
    row = db.set_state(sid, "complete", analysis_completed_at=_now())
    log.info("complete sid=%s reports=%d", sid, len(manifest_entries))
    _notify_webapp(row)
    _cleanup(row)
    return True


PHASES = {
    "received": _handle_received,
    "submitted_to_cuckoo": _handle_poll,
    "sandbox_running": _handle_poll,
    "sandbox_complete": _handle_sandbox_complete,
    "evidence_extracted": _handle_evidence_extracted,
    "sanitized": _handle_sanitized,
    "retrieval_done": _handle_retrieval_done,
}

def _worker_alive(worker_id) -> bool:
    """Kernel-level liveness probe via the worker's exclusive flock.

    main() holds LOCK_EX on data/worker-<id>.lock for the process lifetime.
    flock is released by the kernel when the process dies for ANY reason
    (crash, SIGKILL, OOM, container teardown). So: if we can acquire it,
    the owner is dead. If we can't, the owner is alive.
    """
    if not worker_id:
        return False
    lock_path = ROOT / "data" / f"worker-{worker_id}.lock"
    try:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False          # acquired → nobody holding → owner dead
        except BlockingIOError:
            return True           # held → owner alive
    finally:
        os.close(fd)


def _reclaim_zombies() -> int:
    from datetime import timedelta
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=ZOMBIE_TIMEOUT_S)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    reclaimed = 0
    for state in ("generating_reports", "verifying", "rendering"):
        try:
            rows = db.list_by_state(state, limit=50)
        except Exception as e:
            log.warning("reclaim query failed state=%s: %s", state, e)
            continue
        for row in rows:
            sid = row["webapp_submission_id"]
            worker_id = row.get("worker_claim")

            # PRIMARY: kernel-level liveness. Dead process → reclaim NOW.
            if worker_id and not _worker_alive(worker_id):
                try:
                    if db.reclaim_zombie(sid):
                        reclaimed += 1
                        log.warning(
                            "reclaimed_dead_worker sid=%s prior_state=%s worker=%s",
                            sid, state, worker_id,
                        )
                except Exception as e:
                    log.warning("reclaim_zombie failed sid=%s: %s", sid, e)
                continue

            # NULL claim in an in-progress state = crash between claim and
            # set_state. Nobody owns it, no future owner will appear → reclaim.
            if not worker_id:
                try:
                    if db.reclaim_zombie(sid):
                        reclaimed += 1
                        log.warning(
                            "reclaimed_orphan sid=%s prior_state=%s", sid, state,
                        )
                except Exception as e:
                    log.warning("reclaim_zombie failed sid=%s: %s", sid, e)
                continue

            # FALLBACK: worker is alive but the row has been idle past
            # ZOMBIE_TIMEOUT_S. This covers a wedged event loop (SIGSTOP,
            # deadlock inside httpx) that flock cannot see.
            if row.get("updated_at", "") > cutoff:
                continue
            try:
                if db.reclaim_zombie(sid):
                    reclaimed += 1
                    log.warning(
                        "reclaimed_zombie sid=%s prior_state=%s updated_at=%s",
                        sid, state, row.get("updated_at"),
                    )
            except Exception as e:
                log.warning("reclaim_zombie failed sid=%s: %s", sid, e)
    return reclaimed

def _purge_expired() -> int:
    """Delete terminal submissions past 90 min from completion, plus dirs.

    Runs on the worker sweep loop (every 5 min). The 90-min window gives
    the webapp's 60-min purchase window a 30-min safety buffer: pipeline
    always has the raw analysis available longer than the webapp will
    advertise it. Deletion order: analyses/ → reports/ → DB row. A crash
    between steps leaves orphans that _orphan_sweep will catch on restart
    (dir with no row) or cleanup timer (row with no dirs, handled by
    next run).
    """
    from datetime import timedelta
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=PIPELINE_PURGE_AFTER_COMPLETION_S)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        rows = db.list_terminal_past(cutoff)
    except Exception as e:
        log.warning("purge query failed: %s", e)
        return 0
    purged = 0
    for row in rows:
        sid = row["webapp_submission_id"]
        task_id = row.get("cuckoo_task_id")
        try:
            if task_id:
                shutil.rmtree(ANALYSES_ROOT / task_id, ignore_errors=True)
            shutil.rmtree(REPORTS_ROOT / sid, ignore_errors=True)
            if db.delete_submission(sid):
                purged += 1
                log.info(
                    "purged sid=%s task=%s prior_state=%s terminal_ts=%s",
                    sid, task_id, row.get("state"),
                    row.get("analysis_completed_at") or row.get("updated_at"),
                )
        except Exception as e:
            log.warning("purge failed sid=%s: %s", sid, e)
    return purged


def _orphan_sweep() -> None:
    """Delete analyses/ and uploads/ dirs with no corresponding DB row.

    A task dir is preserved if its cuckoo_task_id has any row in the
    submissions table, regardless of state. Completed submissions stay live
    for 24h for the raw-export window; webapp cleanup removes those rows
    explicitly. Orphan sweep handles the case where a DB row is gone but the
    directory remains (manual DB surgery, crash between DB delete and rmtree).
    """
    known_task_ids = set(db.list_all_task_ids())
    known_sids = set()
    for state in PHASES.keys():
        for row in db.list_by_state(state, limit=1000):
            known_sids.add(row["webapp_submission_id"])

    removed = 0
    for d in ANALYSES_ROOT.iterdir():
        if d.is_dir() and d.name not in known_task_ids:
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    for d in UPLOADS_ROOT.iterdir():
        if d.is_dir() and d.name not in known_sids:
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    if removed:
        log.info("orphan sweep: removed %d dirs", removed)


def _main_loop() -> None:
    log.info("worker %s loop starting", _WORKER_ID)
    last_sweep = 0.0
    _poll_debounce: dict[str, float] = {}
    _POLL_DEBOUNCE_S = 20.0
    while not _SHUTDOWN:
        now = time.time()
        if now - last_sweep >= ZOMBIE_SWEEP_INTERVAL_S:
            try:
                n = _reclaim_zombies()
                if n:
                    log.info("zombie sweep reclaimed %d rows", n)
            except Exception as e:
                log.warning("zombie sweep failed: %s", e)
            try:
                p = _purge_expired()
                if p:
                    log.info("purge sweep removed %d expired submissions", p)
            except Exception as e:
                log.warning("purge sweep failed: %s", e)
            last_sweep = now

        did_work = False
        for state, handler in PHASES.items():
            if _SHUTDOWN:
                break
            try:
                row = db.claim_one(state, _WORKER_ID)
            except Exception as e:
                log.exception("db.claim_one failed state=%s: %s", state, e)
                time.sleep(1.0)
                continue
            if row is None:
                continue
            sid = row["webapp_submission_id"]
            if state in ("submitted_to_cuckoo", "sandbox_running"):
                last_poll = _poll_debounce.get(sid, 0.0)
                if time.time() - last_poll < _POLL_DEBOUNCE_S:
                    try:
                        db.release_claim(sid, _WORKER_ID)
                    except Exception:
                        pass
                    continue
            log.info("pick sid=%s state=%s worker=%s", sid, state, _WORKER_ID)
            try:
                if handler(row):
                    did_work = True
            except Exception as e:
                log.exception("handler crashed sid=%s state=%s: %s", sid, state, e)
                try:
                    _fail(row, "unknown", "worker_crashed", str(e))
                except Exception:
                    pass
            finally:
                if state in ("submitted_to_cuckoo", "sandbox_running"):
                    _poll_debounce[sid] = time.time()
                try:
                    db.release_claim(sid, _WORKER_ID)
                except Exception as e:
                    log.warning("release_claim failed sid=%s: %s", sid, e)
        if not did_work:
            time.sleep(POLL_INTERVAL_S)
    log.info("worker %s loop exiting", _WORKER_ID)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)

    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.error("another worker holds %s; exiting", LOCK_FILE)
        return 1

    UPLOADS_ROOT.mkdir(parents=True, exist_ok=True)
    ANALYSES_ROOT.mkdir(parents=True, exist_ok=True)
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    from pathlib import Path as _P
    _probe = _P("/opt/pipeline/data/.write_probe")
    try:
        _probe.write_text("ok")
        _probe.unlink()
    except OSError as _e:
        log.error("FATAL: /opt/pipeline/data not writable by worker %s: %s. "
                  "systemd namespace issue, not a file issue. "
                  "Fix: systemctl stop pipeline-worker@*.service && sleep 10 && systemctl start pipeline-worker@*.service",
                  _WORKER_ID, _e)
        return 1

    db.init()

    _warm_up_llm()

    try:
        n = _reclaim_zombies()
        if n:
            log.info("startup reclaim: %d zombie rows", n)
    except Exception as e:
        log.warning("startup reclaim failed: %s", e)

    try:
        _orphan_sweep()
    except Exception as e:
        log.warning("orphan sweep failed: %s", e)

    try:
        _main_loop()
    finally:
        os.close(lock_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
