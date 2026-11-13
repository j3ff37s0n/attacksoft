"""PDF renderer for the three pipeline reports.

Aggregates network, DNS, file, and process indicators directly from the
sanitized evidence bundle so that the analyst sees every observed indicator
in tables, without relying on the LLM to enumerate them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import jinja2
from weasyprint import HTML

TEMPLATES_DIR = Path("/opt/pipeline/templates")
REPORT_TYPES = ("executive_risk", "timeline_attack_chain", "remediation")

EVENT_INDEX_RE = re.compile(r"event\[(\d+)\]")
PCAP_FLOW_RE = re.compile(r"(?P<src>[0-9a-fA-F:.]+):(?P<sport>\d+)\s+->\s+(?P<dst>[0-9a-fA-F:.]+):(?P<dport>\d+)/(?P<proto>\w+)")
SYSMON_CONN_RE = re.compile(r"(?P<dst>[0-9a-fA-F:.]+):(?P<dport>\d+)/(?P<proto>\w+)")

TABLE_CAP = 100


def _env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=jinja2.select_autoescape(["html"]),
        undefined=jinja2.StrictUndefined,
    )


def _user_hash(user_id: str) -> str:
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:12]


def _footer(webapp_submission_id: str, user_id: str, generated_at: str) -> str:
    return f"Submission: {webapp_submission_id} | User: {_user_hash(user_id)} | Generated: {generated_at}"


def _all_citations(claims: list[dict]) -> list[dict]:
    out = []
    for c in claims:
        for cit in c.get("citations", []):
            out.append({
                "claim_id": c["claim_id"],
                "source_type": cit.get("source_type", ""),
                "source_id": cit.get("source_id", ""),
                "verbatim": cit.get("verbatim", ""),
            })
    return out


def _load_screenshot(screenshot: dict) -> dict | None:
    p = Path(screenshot["relative_path"])
    if not p.is_file():
        return None
    data = base64.b64encode(p.read_bytes()).decode("ascii")
    ext = p.suffix.lower().lstrip(".") or "png"
    if ext == "jpg":
        ext = "jpeg"
    return {
        "relative_path": screenshot["relative_path"],
        "data_uri": f"data:image/{ext};base64,{data}",
    }


def _render_html(template_name: str, context: dict) -> str:
    return _env().get_template(template_name).render(**context)


def _write_pdf(html: str, out_path: Path) -> dict:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html).write_pdf(str(out_path))
    data = out_path.read_bytes()
    return {
        "path": str(out_path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


# ----------------------------- indicator aggregation -----------------------------

def _facts(bundle: dict, category: str, keys: set[str] | None = None) -> list[dict]:
    out = []
    for f in bundle.get("facts", []):
        if f.get("category") != category:
            continue
        if keys is not None and f.get("key") not in keys:
            continue
        out.append(f)
    return out


def _summarize_network(bundle: dict) -> dict:
    rows: dict[tuple, dict] = {}
    for f in _facts(bundle, "network", {"pcap_flow", "sysmon_connect"}):
        v = str(f.get("verbatim", ""))
        authoritative = bool(f.get("authoritative"))
        if f["key"] == "pcap_flow":
            m = PCAP_FLOW_RE.search(v)
            if not m:
                continue
            key = (m["dst"], m["dport"], m["proto"])
            direction = f"{m['src']}:{m['sport']} -> {m['dst']}:{m['dport']}/{m['proto']}"
        else:
            m = SYSMON_CONN_RE.search(v)
            if not m:
                continue
            key = (m["dst"], m["dport"], m["proto"])
            direction = f"{m['dst']}:{m['dport']}/{m['proto']}"
        row = rows.get(key)
        if row is None:
            rows[key] = {
                "dst": key[0],
                "port": key[1],
                "proto": key[2],
                "direction": direction,
                "authoritative": authoritative,
                "observed_count": 1,
            }
        else:
            row["observed_count"] += 1
            if authoritative:
                row["authoritative"] = True
                row["direction"] = direction
    ordered = sorted(rows.values(), key=lambda r: (not r["authoritative"], r["dst"], r["port"]))
    return {"rows": ordered[:TABLE_CAP], "total": len(ordered)}


def _summarize_dns(bundle: dict) -> dict:
    rows: dict[tuple, dict] = {}
    for f in _facts(bundle, "dns", {"pcap_query", "pcap_response", "query"}):
        v = str(f.get("verbatim", ""))
        authoritative = bool(f.get("authoritative"))
        key = (v,)
        if key in rows:
            rows[key]["count"] += 1
            if authoritative:
                rows[key]["authoritative"] = True
        else:
            rows[key] = {
                "value": v,
                "kind": f["key"],
                "authoritative": authoritative,
                "count": 1,
            }
    ordered = sorted(rows.values(), key=lambda r: (not r["authoritative"], r["value"]))
    return {"rows": ordered[:TABLE_CAP], "total": len(ordered)}


def _summarize_files(bundle: dict) -> dict:
    keys = {"created", "written", "deleted", "tree_filename"}
    # Cross-platform agent/OS noise patterns — must never appear in the file table.
    NOISE_PATTERNS = (
        # Windows
        "__PSScriptPolicyTest",
        "\\EBWebView\\",
        "\\appcompat\\Programs\\",
        "\\Windows\\Prefetch\\",
        "\\Microsoft\\Windows\\INetCache\\",
        "\\Windows\\SystemTemp\\Google",
        "\\ProgramData\\Microsoft\\Windows Defender",
        "\\Windows\\WinSxS\\",
        "\\Windows\\System32\\config\\",
        # Linux
        "/var/log/",
        "/var/cache/",
        "/var/lib/apt/",
        "/run/dbus/",
        "/run/systemd/",
        "/tmp/.X11-unix/",
        "/.cache/",
        "/home/sandbox/.local/",
        "/home/sandbox/.config/",
        "/opt/cuckoo3/",
        "/tmp/cuckoo_",
        "/var/lib/cuckoo/",
        "/proc/",
        "/sys/",
        "/dev/",
    )
    rows: dict[tuple, dict] = {}
    for f in _facts(bundle, "file", keys):
        v = str(f.get("verbatim", ""))
        if not v:
            continue
        if any(p in v for p in NOISE_PATTERNS):
            continue
        action = {
            "created": "created",
            "written": "written",
            "deleted": "deleted",
            "tree_filename": "submitted",
        }.get(f["key"], f["key"])
        key = (v, action)
        if key in rows:
            rows[key]["count"] += 1
        else:
            rows[key] = {"path": v, "action": action, "count": 1}
    ordered = sorted(rows.values(), key=lambda r: (r["action"], r["path"]))
    return {"rows": ordered[:TABLE_CAP], "total": len(ordered)}


def _summarize_processes(bundle: dict) -> dict:
    # Determine the sample marker (hash prefix) for filtering out agent noise
    sample_marker = ""
    for f in bundle.get("facts", []):
        if f.get("key") in ("primary_filename", "filename") and f.get("value"):
            v = str(f["value"]).lower()
            # Prefer the uuid-prefix form (Windows Cuckoo hash name)
            if "-" in v:
                sample_marker = v.split("-")[0][:8]
            # Otherwise use the filename stem without extension
            else:
                stem = v.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                sample_marker = stem[:8]
            # A marker shorter than 4 chars is too ambiguous to filter on
            if len(sample_marker) < 4:
                sample_marker = ""
            break

    grouped: dict[str, dict] = {}
    for f in _facts(bundle, "process"):
        locator = f.get("source", {}).get("locator", "")
        if not locator:
            continue
        m = EVENT_INDEX_RE.search(locator)
        if m:
            key = f"ev:{m.group(1)}"
        else:
            key = f"image:{f.get('value', f['fact_id'])}"
        g = grouped.setdefault(key, {})
        g.setdefault(f["key"], str(f.get("verbatim", "")))
        g.setdefault("_fact_ids", []).append(f["fact_id"])

    rows = []
    for key, g in grouped.items():
        image = g.get("image", "")
        cmdline = g.get("command_line", "") or g.get("monitored_execution", "")
        if not image and not cmdline:
            continue
        parent = g.get("parent_image", "")

        # FILTER: only processes that involve the sample (image, cmdline, or parent)
        if sample_marker:
            hay = f"{image} {cmdline} {parent}".lower()
            if sample_marker not in hay:
                continue

        rows.append({
            "image": image or "(unknown)",
            "command_line": cmdline or "",
            "parent_image": parent,
            "user": g.get("user", ""),
            "count": len(g.get("_fact_ids", [])),
        })
    rows.sort(key=lambda r: r["image"])
    return {"rows": rows[:TABLE_CAP], "total": len(rows)}


def _phase_coverage(timeline_report: dict) -> list[dict]:
    return [
        {"step_id": s["step_id"], "phase": s["phase"], "technique_id": s.get("technique_id") or "—"}
        for s in timeline_report.get("attack_chain_steps", [])
    ]


def _remediation_by_phase(remediation_report: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for rec in remediation_report.get("recommendations", []):
        for ph in rec.get("addresses_phases", []):
            grouped.setdefault(ph, []).append(rec)
    return grouped


def _common_context(
    report: dict,
    manifest: dict | None,
    webapp_submission_id: str,
    user_id: str,
    generated_at: str | None,
) -> dict:
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    claims = report.get("claims", [])
    return {
        "report": report,
        "manifest": manifest or {},
        "webapp_submission_id": webapp_submission_id,
        "user_hash": _user_hash(user_id),
        "generated_at": generated_at,
        "footer_text": _footer(webapp_submission_id, user_id, generated_at),
        "all_citations": _all_citations(claims),
        "claims_by_id": {c["claim_id"]: c for c in claims},
        "screenshots": [],
    }


def render_executive_risk(
    report: dict,
    evidence_bundle: dict,
    manifest: dict | None,
    webapp_submission_id: str,
    user_id: str,
    out_path: Path,
    screenshots: list[dict] | None = None,
    generated_at: str | None = None,
) -> dict:
    ctx = _common_context(report, manifest, webapp_submission_id, user_id, generated_at)
    ctx["report_title"] = "Executive Summary and Risk Report"
    ctx["summary_claim"] = ctx["claims_by_id"].get(report.get("summary_claim_id"))
    ctx["key_findings"] = [ctx["claims_by_id"][cid] for cid in report.get("key_finding_ids", []) if cid in ctx["claims_by_id"]]
    ctx["techniques"] = report.get("mitre_techniques", [])
    ctx["abstentions"] = report.get("abstentions", [])
    ctx["screenshots"] = [s for s in (_load_screenshot(x) for x in (screenshots or [])) if s]
    meta = {
        "orig_filename": "Unknown", "md5": "", "sha1": "", "sha256": "Unknown",
        "sha512": "", "filetype": "Unknown", "size_bytes": 0,
        "imphash": "", "pe_timestamp": "", "signature_status": "Unsigned",
        "version": {}, "sections": [], "imports_count": 0, "resources_count": 0,
    }
    for f in evidence_bundle.get("facts", []):
        k = f.get("key")
        v = f.get("value")
        if k == "primary_filename":
            meta["orig_filename"] = str(v)
        elif k == "md5":
            meta["md5"] = str(v)
        elif k == "sha1":
            meta["sha1"] = str(v)
        elif k == "sha256":
            meta["sha256"] = str(v)
        elif k == "sha512":
            meta["sha512"] = str(v)
        elif k == "filetype":
            meta["filetype"] = str(v)
        elif k == "file_size":
            try:
                meta["size_bytes"] = int(v)
            except (TypeError, ValueError):
                pass
        elif k == "pe_imphash":
            meta["imphash"] = str(v)
        elif k == "pe_timestamp":
            meta["pe_timestamp"] = str(v)
        elif k == "code_signatures":
            meta["signature_status"] = "None (unsigned)" if str(v) == "none" else str(v)
        elif k and k.startswith("versioninfo_"):
            meta["version"][k[len("versioninfo_"):]] = str(v)
        elif k == "pe_section":
            meta["sections"].append(str(v))
        elif k == "pe_import":
            meta["imports_count"] += 1
        elif k == "pe_resource":
            meta["resources_count"] += 1
    ctx["file_meta"] = meta
    return _write_pdf(_render_html("executive_risk.html", ctx), out_path)


def render_timeline_attack_chain(
    report: dict,
    evidence_bundle: dict,
    manifest: dict | None,
    webapp_submission_id: str,
    user_id: str,
    out_path: Path,
    screenshots: list[dict] | None = None,
    generated_at: str | None = None,
) -> dict:
    ctx = _common_context(report, manifest, webapp_submission_id, user_id, generated_at)
    ctx["report_title"] = "Timeline and Attack Chain"
    ctx["events"] = report.get("timeline_events", [])
    ctx["steps"] = report.get("attack_chain_steps", [])
    ctx["gaps"] = report.get("gaps", [])
    ctx["abstentions"] = report.get("abstentions", [])
    ctx["narrative_claim"] = ctx["claims_by_id"].get(report.get("attack_chain_narrative_claim_id"))
    ref_ids: set[str] = set()
    for ev in ctx["events"]:
        if ev.get("description_claim_id"):
            ref_ids.add(ev["description_claim_id"])
    for st in ctx["steps"]:
        if st.get("description_claim_id"):
            ref_ids.add(st["description_claim_id"])
    ctx["event_claims"] = [c for c in report.get("claims", []) if c["claim_id"] in ref_ids]
    ctx["network_summary"] = _summarize_network(evidence_bundle)
    ctx["dns_summary"] = _summarize_dns(evidence_bundle)
    ctx["file_summary"] = _summarize_files(evidence_bundle)
    ctx["process_summary"] = _summarize_processes(evidence_bundle)
    ctx["screenshots"] = [s for s in (_load_screenshot(x) for x in (screenshots or [])) if s]
    return _write_pdf(_render_html("timeline_attack_chain.html", ctx), out_path)


def render_remediation(
    report: dict,
    evidence_bundle: dict,
    manifest: dict | None,
    webapp_submission_id: str,
    user_id: str,
    out_path: Path,
    screenshots: list[dict] | None = None,
    generated_at: str | None = None,
    timeline_report: dict | None = None,
) -> dict:
    ctx = _common_context(report, manifest, webapp_submission_id, user_id, generated_at)
    ctx["report_title"] = "Remediation Recommendations"
    ctx["threat_model_claim"] = ctx["claims_by_id"].get(report.get("threat_model_claim_id"))
    ctx["recommendations"] = report.get("recommendations", [])
    ctx["abstentions"] = report.get("abstentions", [])
    ctx["phase_coverage"] = _phase_coverage(timeline_report or {})
    ctx["remediation_by_phase"] = _remediation_by_phase(report)
    ctx["network_summary"] = _summarize_network(evidence_bundle)
    ctx["dns_summary"] = _summarize_dns(evidence_bundle)
    ctx["file_summary"] = _summarize_files(evidence_bundle)
    ctx["screenshots"] = [s for s in (_load_screenshot(x) for x in (screenshots or [])) if s]
    return _write_pdf(_render_html("remediation.html", ctx), out_path)


def render_all(
    reports: dict[str, dict],
    evidence_bundle: dict,
    manifest: dict | None,
    webapp_submission_id: str,
    user_id: str,
    out_dir: Path,
    screenshots: list[dict] | None = None,
    generated_at: str | None = None,
) -> dict:
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    rendered = []
    timeline_report = reports.get("timeline_attack_chain")
    for rt in REPORT_TYPES:
        rpt = reports.get(rt)
        if rpt is None:
            continue
        out_path = out_dir / f"{rt}.pdf"
        if rt == "executive_risk":
            info = render_executive_risk(rpt, evidence_bundle, manifest, webapp_submission_id, user_id, out_path, screenshots, generated_at)
        elif rt == "timeline_attack_chain":
            info = render_timeline_attack_chain(rpt, evidence_bundle, manifest, webapp_submission_id, user_id, out_path, screenshots, generated_at)
        else:
            info = render_remediation(rpt, evidence_bundle, manifest, webapp_submission_id, user_id, out_path, screenshots, generated_at, timeline_report)
        info["type"] = rt
        info["generated_at"] = generated_at
        info["relative_path"] = f"{webapp_submission_id}/{rt}.pdf"
        rendered.append(info)
    return {"reports": rendered, "out_dir": str(out_dir)}


# ----------------------------- CLI -----------------------------

def _synthetic_bundle() -> dict:
    return {
        "schema_version": "evidence-bundle/1.0",
        "submission_id": "00000000-0000-4000-8000-000000000001",
        "cuckoo_task_id": "VERIFY",
        "analysis_date": "20261030",
        "extracted_at": "2026-10-30T00:00:00Z",
        "extractor_version": "verify",
        "sanitization_manifest_id": None,
        "task_selection": {"policy": "single_task", "selected_task_dir": "task_1", "reason": "verify", "additional_tasks": []},
        "artifacts": [],
        "binary": {"sha256": "0" * 64, "size_bytes": 0, "realpath_resolved": True, "file_type": "PE", "link_present": True},
        "facts": [
            {"fact_id": "f_process_001", "category": "process", "key": "image", "value": "/usr/bin/dash",
             "source": {"source_type": "artifact", "source_id": "sysmon", "locator": "event[0] EventID 1 Image", "sha256": "0"*64},
             "verbatim": "/usr/bin/dash", "authoritative": False},
            {"fact_id": "f_process_002", "category": "process", "key": "command_line", "value": "/bin/sh -c '/home/sandbox/cuckoo/write-test.exe'",
             "source": {"source_type": "artifact", "source_id": "sysmon", "locator": "event[0] EventID 1 CommandLine", "sha256": "0"*64},
             "verbatim": "/bin/sh -c '/home/sandbox/cuckoo/write-test.exe'", "authoritative": False},
            {"fact_id": "f_process_003", "category": "process", "key": "parent_image", "value": "/usr/bin/bash",
             "source": {"source_type": "artifact", "source_id": "sysmon", "locator": "event[0] EventID 1 ParentImage", "sha256": "0"*64},
             "verbatim": "/usr/bin/bash", "authoritative": False},
            {"fact_id": "f_network_001", "category": "network", "key": "sysmon_connect", "value": "203.0.113.42:443/tcp",
             "source": {"source_type": "artifact", "source_id": "sysmon", "locator": "event[3] EventID 3", "sha256": "0"*64},
             "verbatim": "203.0.113.42:443/tcp", "authoritative": False},
            {"fact_id": "f_network_002", "category": "network", "key": "sysmon_connect", "value": "203.0.113.42:443/tcp",
             "source": {"source_type": "artifact", "source_id": "sysmon", "locator": "event[4] EventID 3", "sha256": "0"*64},
             "verbatim": "203.0.113.42:443/tcp", "authoritative": False},
            {"fact_id": "f_file_001", "category": "file", "key": "created", "value": "/home/sandbox/cuckoo/write-test.exe",
             "source": {"source_type": "artifact", "source_id": "sysmon", "locator": "event[5] EventID 11", "sha256": "0"*64},
             "verbatim": "/home/sandbox/cuckoo/write-test.exe", "authoritative": False},
            {"fact_id": "f_dns_001", "category": "dns", "key": "query", "value": "evil-c2.example",
             "source": {"source_type": "artifact", "source_id": "sysmon", "locator": "event[6] EventID 22", "sha256": "0"*64},
             "verbatim": "evil-c2.example", "authoritative": False},
        ],
        "pcap_summary": {"present": False, "packet_count": 0, "flows": [], "dns_queries": [], "http_requests": [], "tls_sessions": [], "parse_error": None},
        "screenshots": [],
        "absent_artifacts": [],
        "insufficient_evidence": [],
        "extraction_warnings": [],
    }


def _synthetic_reports(submission_id: str, generated_at: str) -> dict:
    def claim(cid, text, src_id, src_type, verbatim):
        return {
            "claim_id": cid,
            "text": text,
            "citations": [{
                "citation_id": f"cit-{cid}",
                "source_type": src_type,
                "source_id": src_id,
                "verbatim": verbatim,
                "verified": True,
            }],
            "status": "verified",
        }

    base = {
        "schema_version": "report-output/1.0",
        "submission_id": submission_id,
        "generated_at": generated_at,
        "model": "qwen2.5:7b-instruct",
        "prompt_version": "verify-v2",
        "sanitization_manifest_id": "verify-manifest",
    }

    exec_r = {
        **base,
        "report_type": "executive_risk",
        "risk_level": "medium",
        "summary_claim_id": "c1",
        "key_finding_ids": ["c2", "c3"],
        "mitre_techniques": [
            {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "evidence_claim_ids": ["c2"]},
        ],
        "claims": [
            claim("c1", "The sample attempted to execute a Windows PE on a Linux host; the OS rejected the file format.",
                  "f_process_001", "evidence", "/usr/bin/dash"),
            claim("c2", "The agent attempted to run the file under /bin/sh, which failed with Exec format error.",
                  "f_process_002", "evidence", "/bin/sh -c '/home/sandbox/cuckoo/write-test.exe'"),
            claim("c3", "No behavioral telemetry was produced because the payload did not execute.",
                  "playbook:analysis.wrong-platform", "knowledge", "PE executable on Linux sandbox"),
        ],
        "abstentions": [
            {"section": "network_events", "reason": "no pcap activity", "evidence_gap": "task_1/dump.pcap empty"},
        ],
        "insufficient_evidence": False,
    }

    timeline_r = {
        **base,
        "report_type": "timeline_attack_chain",
        "attack_chain_narrative_claim_id": "c1",
        "timeline_events": [
            {"event_id": "e1", "timestamp": "2026-10-30T03:56:27Z", "event_type": "process_start",
             "description_claim_id": "c2", "ordering_basis": "artifact_timestamp", "source_authoritative": False},
            {"event_id": "e2", "timestamp": "2026-10-30T03:56:28Z", "event_type": "network_connect",
             "description_claim_id": "c4", "ordering_basis": "artifact_timestamp", "source_authoritative": False},
        ],
        "attack_chain_steps": [
            {"step_id": "s1", "phase": "execution", "technique_id": "T1059", "description_claim_id": "c2"},
            {"step_id": "s2", "phase": "command_and_control", "technique_id": "T1071", "description_claim_id": "c4"},
        ],
        "claims": [
            claim("c1", "The sample attempted to execute a Windows PE on Linux, received an Exec format error, "
                       "and no runtime behavior was observed; a subsequent outbound TCP connection to port 443 "
                       "was attempted from a peer process, which is not attributable to the sample itself.",
                  "f_process_002", "evidence", "/bin/sh -c '/home/sandbox/cuckoo/write-test.exe'"),
            claim("c2", "chmod marked the Windows PE executable on the Linux host.",
                  "f_process_001", "evidence", "/usr/bin/dash"),
            claim("c4", "An outbound TCP connection to port 443 was attempted.",
                  "f_network_001", "evidence", "203.0.113.42:443/tcp"),
        ],
        "abstentions": [],
        "gaps": [{"section": "network_events", "reason": "pcap contained no usable flows"}],
    }

    remed_r = {
        **base,
        "report_type": "remediation",
        "threat_model_claim_id": "c0",
        "recommendations": [
            {
                "recommendation_id": "r1",
                "category": "general",
                "priority": "low",
                "action": "No behavioral remediation required; the payload did not execute in the sandbox. Re-analyze on a Windows host before allowing this file.",
                "rationale_claim_id": "c1",
                "playbook_id": "playbook:analysis.wrong-platform",
                "verification": "Confirm the submitted file is a PE and was analyzed under a Linux platform profile.",
                "applies_to": ["write-test.exe"],
                "addresses_phases": ["execution"],
            },
            {
                "recommendation_id": "r2",
                "category": "general",
                "priority": "medium",
                "action": "Block outbound TCP/443 from the sandbox subnet except to the analysis C2 collector; the observed connection to 203.0.113.42:443/tcp was not attributable to the sample and should be investigated separately.",
                "rationale_claim_id": "c2",
                "playbook_id": "playbook:c2.http-beacon",
                "verification": "Query the egress firewall for other hosts on the same subnet that connected to 203.0.113.42:443 in the observation window.",
                "applies_to": ["203.0.113.42:443/tcp"],
                "addresses_phases": ["command_and_control"],
            },
        ],
        "claims": [
            claim("c0", "Given the sample did not execute, the threat model is unknown; if delivered to a "
                       "Windows endpoint the observed PE imports suggest a GUI application that would run "
                       "with logged-in user privileges.",
                  "playbook:analysis.wrong-platform", "knowledge", "PE executable on Linux sandbox"),
            claim("c1", "The sample is a Windows PE and cannot be exercised in the Linux sandbox.",
                  "playbook:analysis.wrong-platform", "knowledge", "PE executable on Linux sandbox"),
            claim("c2", "A separate outbound connection to 203.0.113.42:443/tcp was observed and is not attributable to the sample.",
                  "f_network_001", "evidence", "203.0.113.42:443/tcp"),
        ],
        "abstentions": [],
    }

    return {"executive_risk": exec_r, "timeline_attack_chain": timeline_r, "remediation": remed_r}


def _verify_mode() -> int:
    from pypdf import PdfReader

    submission_id = "00000000-0000-4000-8000-000000000001"
    user_id = "verify-user"
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "redaction_appendix": {
            "local_ips_redacted": 3,
            "passwords_secrets_redacted": 1,
            "sandbox_paths_redacted": 2,
            "sandbox_hostnames_users_redacted": 1,
            "remote_indicators_preserved": 5,
        }
    }
    out_dir = Path("/opt/pipeline/data/reports/_verify")
    bundle = _synthetic_bundle()
    reports = _synthetic_reports(submission_id, generated_at)
    result = render_all(reports, bundle, manifest, submission_id, user_id, out_dir, generated_at=generated_at)

    failures = 0
    footer_frag = f"Submission: {submission_id}"
    user_frag = f"User: {_user_hash(user_id)}"
    for info in result["reports"]:
        path = Path(info["path"])
        if not path.is_file() or info["size_bytes"] < 8000:
            print(f"FAIL {info['type']}: file missing or too small ({info['size_bytes']} bytes)")
            failures += 1
            continue
        try:
            text = "\n".join((page.extract_text() or "") for page in PdfReader(str(path)).pages)
        except Exception as exc:
            print(f"FAIL {info['type']}: text extraction failed: {exc}")
            failures += 1
            continue
        checks = {
            "footer": footer_frag in text,
            "user_hash": user_frag in text,
            "provenance": "Provenance" in text,
            "redaction": "Redaction Summary" in text,
        }
        if info["type"] == "executive_risk":
            checks["risk_badge"] = "MEDIUM" in text
            checks["summary"] = "attempted to execute" in text
        elif info["type"] == "timeline_attack_chain":
            checks["narrative"] = "Attack Chain Narrative" in text
            checks["network_table"] = "203.0.113.42" in text
            checks["process_table"] = "/usr/bin/dash" in text or "/bin/sh" in text
            _tl = text.lower()
            checks["phases"] = "execution" in _tl and ("command and control" in _tl or "command_and_control" in _tl)
        elif info["type"] == "remediation":
            checks["threat_model"] = "Threat Model" in text
            checks["coverage"] = "Attack Chain Coverage" in text
            _tl = text.lower()
            checks["phases"] = "execution" in _tl and ("command and control" in _tl or "command_and_control" in _tl)
            checks["recommendation"] = "r1" in text and "r2" in text
        bad = [k for k, v in checks.items() if not v]
        if bad:
            print(f"FAIL {info['type']}: missing {bad}, size={info['size_bytes']}")
            failures += 1
        else:
            print(f"PASS {info['type']}: {info['size_bytes']} bytes, sha={info['sha256'][:12]}")
    if failures:
        print(f"{failures} failure(s)")
        return 1
    print(f"all reports verified at {out_dir}")
    return 0


def _render_one(args: list[str]) -> int:
    if len(args) < 6:
        print("usage: renderer render <report_type> <report.json> <bundle.json> <submission_id> <user_id> <out_path> [manifest.json]", file=sys.stderr)
        return 2
    rt, report_path, bundle_path, sub_id, user_id, out_path = args[0], Path(args[1]), Path(args[2]), args[3], args[4], Path(args[5])
    manifest = json.loads(Path(args[6]).read_text()) if len(args) > 6 else None
    report = json.loads(report_path.read_text())
    bundle = json.loads(bundle_path.read_text())
    if rt == "executive_risk":
        info = render_executive_risk(report, bundle, manifest, sub_id, user_id, out_path)
    elif rt == "timeline_attack_chain":
        info = render_timeline_attack_chain(report, bundle, manifest, sub_id, user_id, out_path)
    elif rt == "remediation":
        info = render_remediation(report, bundle, manifest, sub_id, user_id, out_path)
    else:
        print(f"unknown report_type: {rt}", file=sys.stderr)
        return 2
    print(json.dumps(info, indent=2))
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python -m app.renderer verify | render <rt> <report.json> <bundle.json> <sub_id> <user_id> <out_path> [manifest.json]", file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    if cmd == "verify":
        return _verify_mode()
    if cmd == "render":
        return _render_one(sys.argv[2:])
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
