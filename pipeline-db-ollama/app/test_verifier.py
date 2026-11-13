"""Verifier test harness. Runs standalone; prints PASS/FAIL per case.

Run: python -m app.test_verifier
Exit 0 if all pass, 1 if any fail.
"""
import sys

from app.verifier import verify_report


def _sanitized_bundle():
    return {
        "facts": [
            {
                "fact_id": "f_proc_001",
                "verbatim": "powershell.exe -ExecutionPolicy Bypass -w hidden -c IEX",
                "category": "process",
            },
            {
                "fact_id": "f_reg_001",
                "verbatim": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "category": "registry",
            },
        ]
    }


def _retrieval():
    return {
        "results": [
            {
                "chunk_id": "chg_attack_T1547",
                "source_id": "attack:T1547",
                "text": "Adversaries may configure system settings to automatically execute during boot or logon.",
            },
            {
                "chunk_id": "chg_playbook_runkey",
                "source_id": "playbook:persistence.runkey",
                "text": "Enumerate HKCU and HKLM Software\\Microsoft\\Windows\\CurrentVersion\\Run entries.",
            },
        ]
    }


def _server_fields(report_type):
    return {
        "schema_version": "report-output/1.0",
        "submission_id": "01234567-89ab-4cde-8fab-0123456789ab",
        "report_type": report_type,
        "generated_at": "2026-10-29T00:00:00Z",
        "model": "qwen2.5:7b-instruct",
        "prompt_version": "test-v1",
        "sanitization_manifest_id": "san-0001",
    }


def _exec_report():
    return {
        "risk_level": "medium",
        "summary_claim_id": "c1",
        "key_finding_ids": ["c2", "c3", "c4"],
        "mitre_techniques": [
            {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "evidence_claim_ids": ["c1"]},
            {"technique_id": "T1547", "name": "Boot or Logon Autostart", "evidence_claim_ids": ["c3"]},
        ],
        "claims": [
            {
                "claim_id": "c1",
                "text": "Sample ran PowerShell with hidden window.",
                "citations": [{
                    "citation_id": "cit1",
                    "source_type": "evidence",
                    "source_id": "f_proc_001",
                    "verbatim": "powershell.exe -ExecutionPolicy Bypass -w hidden -c IEX",
                }],
                "status": "verified",
            },
            {
                "claim_id": "c2",
                "text": "Verbatim mismatch case.",
                "citations": [{
                    "citation_id": "cit2",
                    "source_type": "evidence",
                    "source_id": "f_proc_001",
                    "verbatim": "THIS STRING IS NOT IN THE FACT",
                }],
                "status": "verified",
            },
            {
                "claim_id": "c3",
                "text": "Sample wrote Run key.",
                "citations": [{
                    "citation_id": "cit3",
                    "source_type": "evidence",
                    "source_id": "f_reg_001",
                    "verbatim": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                }],
                "status": "verified",
            },
            {
                "claim_id": "c4",
                "text": "Source not found case.",
                "citations": [{
                    "citation_id": "cit4",
                    "source_type": "evidence",
                    "source_id": "f_does_not_exist",
                    "verbatim": "anything",
                }],
                "status": "verified",
            },
            {
                "claim_id": "c5",
                "text": "Orphan claim not referenced anywhere.",
                "citations": [{
                    "citation_id": "cit5",
                    "source_type": "evidence",
                    "source_id": "f_proc_001",
                    "verbatim": "powershell",
                }],
                "status": "verified",
            },
        ],
        "abstentions": [],
        "insufficient_evidence": False,
    }


def case_exec():
    report = _exec_report()
    out, stats = verify_report(
        report=report,
        report_type="executive_risk",
        sanitized_bundle=_sanitized_bundle(),
        retrieval_result=_retrieval(),
        server_fields=_server_fields("executive_risk"),
    )
    assert out is not None, f"exec report should have survived: {stats}"
    claim_ids = {c["claim_id"] for c in out["claims"]}
    assert "c1" in claim_ids, "c1 (good) should survive"
    assert "c2" not in claim_ids, "c2 (verbatim mismatch) should be removed"
    assert "c3" in claim_ids, "c3 (good) should survive"
    assert "c4" not in claim_ids, "c4 (source not found) should be removed"
    assert "c5" not in claim_ids, "c5 (orphan) should be removed"
    assert out["summary_claim_id"] == "c1"
    surviving_kf = set(out["key_finding_ids"])
    assert surviving_kf == {"c3"}, f"expected {{'c3'}}, got {surviving_kf}"
    # MITRE T1547 referenced c3 (survived), T1059 referenced c1 (survived)
    techs = {t["technique_id"] for t in out["mitre_techniques"]}
    assert techs == {"T1059", "T1547"}, f"unexpected techniques: {techs}"
    assert out["schema_version"] == "report-output/1.0"
    print("PASS case_exec")


def _remediation_report():
    return {
        "recommendations": [
            {
                "recommendation_id": "r1",
                "category": "persistence",
                "priority": "high",
                "action": "Remove the HKCU Run key value named Updater from the analyzed host.",
                "rationale_claim_id": "c1",
                "playbook_id": "playbook:persistence.runkey",
                "verification": "Reg query the Run key and confirm no Updater value remains.",
                "applies_to": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"],
            },
            {
                "recommendation_id": "r2",
                "category": "execution",
                "priority": "medium",
                "action": "Block PowerShell script block logging is already enabled; confirm.",
                "rationale_claim_id": "c2",
                "playbook_id": "playbook:execution.powershell",
                "verification": "Get-WinEvent Microsoft-Windows-PowerShell/Operational shows script block logging.",
                "applies_to": ["powershell.exe -ExecutionPolicy Bypass -w hidden -c IEX"],
            },
        ],
        "claims": [
            {
                "claim_id": "c1",
                "text": "Sample created HKCU Run key Updater pointing at its copy.",
                "citations": [
                    {
                        "citation_id": "cit1",
                        "source_type": "evidence",
                        "source_id": "f_reg_001",
                        "verbatim": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                    },
                    {
                        "citation_id": "cit2",
                        "source_type": "knowledge",
                        "source_id": "chg_playbook_runkey",
                        "verbatim": "Enumerate HKCU and HKLM Software\\Microsoft\\Windows\\CurrentVersion\\Run entries.",
                    },
                ],
                "status": "verified",
            },
            {
                "claim_id": "c2",
                "text": "Sample ran PowerShell with hidden window.",
                "citations": [
                    {
                        "citation_id": "cit3",
                        "source_type": "evidence",
                        "source_id": "f_proc_001",
                        "verbatim": "powershell.exe -ExecutionPolicy Bypass -w hidden -c IEX",
                    }
                ],
                "status": "verified",
            },
        ],
        "abstentions": [],
    }


def case_remediation():
    report = _remediation_report()
    out, stats = verify_report(
        report=report,
        report_type="remediation",
        sanitized_bundle=_sanitized_bundle(),
        retrieval_result=_retrieval(),
        server_fields=_server_fields("remediation"),
    )
    assert out is not None, f"remediation should have survived: {stats}"
    rec_ids = {r["recommendation_id"] for r in out["recommendations"]}
    assert "r1" in rec_ids, "r1 (evidence + knowledge) should survive"
    assert "r2" not in rec_ids, "r2 (evidence only, no knowledge) should be dropped"
    claim_ids = {c["claim_id"] for c in out["claims"]}
    assert "c1" in claim_ids
    assert "c2" not in claim_ids, "c2 was only referenced by r2, should be orphaned and removed"
    print("PASS case_remediation")


def _timeline_report(n_events):
    claims = []
    events = []
    for i in range(n_events):
        cid = f"c{i}"
        claims.append({
            "claim_id": cid,
            "text": f"event {i}",
            "citations": [{
                "citation_id": f"cit{i}",
                "source_type": "evidence",
                "source_id": "f_proc_001",
                "verbatim": "powershell",
            }],
            "status": "verified",
        })
        events.append({
            "event_id": f"e{i}",
            "timestamp": None,
            "event_type": "process_start",
            "description_claim_id": cid,
            "ordering_basis": "relative_sequence",
            "source_authoritative": False,
        })
    return {
        "timeline_events": events,
        "attack_chain_steps": [],
        "claims": claims,
        "abstentions": [],
        "gaps": [],
    }


def case_timeline_cap():
    report = _timeline_report(50)
    out, stats = verify_report(
        report=report,
        report_type="timeline_attack_chain",
        sanitized_bundle=_sanitized_bundle(),
        retrieval_result=_retrieval(),
        server_fields=_server_fields("timeline_attack_chain"),
    )
    assert out is not None, f"timeline should have survived: {stats}"
    assert len(out["timeline_events"]) == 40, f"expected 40 events, got {len(out['timeline_events'])}"
    assert stats["stages"]["timeline_cap"]["capped"] == 10
    print("PASS case_timeline_cap")


def case_all_claims_removed():
    report = _exec_report()
    # Break every claim's citations
    for c in report["claims"]:
        for cit in c["citations"]:
            cit["verbatim"] = "NOT IN ANY SOURCE"
    out, stats = verify_report(
        report=report,
        report_type="executive_risk",
        sanitized_bundle=_sanitized_bundle(),
        retrieval_result=_retrieval(),
        server_fields=_server_fields("executive_risk"),
    )
    assert out is None, "report should have been rejected when all claims fail"
    assert stats["fatal"] is True
    print("PASS case_all_claims_removed")


def main() -> int:
    failures = 0
    for name, fn in [
        ("case_exec", case_exec),
        ("case_remediation", case_remediation),
        ("case_timeline_cap", case_timeline_cap),
        ("case_all_claims_removed", case_all_claims_removed),
    ]:
        try:
            fn()
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            failures += 1
        except Exception as exc:
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
            failures += 1
    if failures:
        print(f"{failures} case(s) failed", file=sys.stderr)
        return 1
    print("all verifier cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
