"""Sanitizer test harness. Run: python -m app.test_sanitizer
Exit 0 if all pass, 1 on failure.
"""
import sys
from pathlib import Path

from app.sanitizer import (
    load_config,
    extract_preserve_ips,
    sanitize_bundle,
    sanitize_report,
    build_manifest,
)

CONFIG = load_config(Path("/opt/pipeline/config/sanitizer.yaml"))


def _bundle(facts):
    return {
        "schema_version": "evidence-bundle/1.0",
        "submission_id": "01234567-89ab-4cde-8fab-0123456789ab",
        "cuckoo_task_id": "RTW3E0",
        "analysis_date": "20261027",
        "extracted_at": "2026-10-29T00:00:00Z",
        "extractor_version": "0.1.0",
        "task_selection": {
            "policy": "single_task",
            "selected_task_dir": "task_1",
            "reason": "single",
            "additional_tasks": [],
        },
        "artifacts": [],
        "binary": {
            "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            "size_bytes": 4096,
            "realpath_resolved": True,
            "file_type": "PE32+",
            "link_present": True,
        },
        "facts": facts,
        "pcap_summary": {
            "present": True,
            "packet_count": 4,
            "flows": [],
            "dns_queries": [],
            "http_requests": [],
            "tls_sessions": [],
            "parse_error": None,
        },
        "screenshots": [],
        "absent_artifacts": [],
        "insufficient_evidence": [],
        "extraction_warnings": [],
    }


def _fact(fid, category, key, value, verbatim):
    return {
        "fact_id": fid,
        "category": category,
        "key": key,
        "value": value,
        "source": {
            "source_type": "artifact",
            "source_id": "analysis.json",
            "locator": "x",
            "sha256": "0" * 64,
        },
        "verbatim": verbatim,
        "authoritative": False,
    }


def case_internal_ip_redacted():
    b = _bundle([_fact("f1", "network", "tcp_connect", "192.168.0.100", "192.168.0.100:443")])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    assert "<local_IP>" in out["facts"][0]["verbatim"], out["facts"][0]["verbatim"]
    assert out["facts"][0]["value"] == "<local_IP>", out["facts"][0]["value"]
    assert stats["counts"]["local_ips"] >= 2
    assert stats["counts"]["remote_indicators_preserved"] == 0
    print("PASS case_internal_ip_redacted")


def case_public_ip_preserved():
    b = _bundle([_fact("f1", "network", "tcp_connect", "8.8.8.8", "connect to 8.8.8.8:53")])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    assert out["facts"][0]["verbatim"] == "connect to 8.8.8.8:53"
    assert out["facts"][0]["value"] == "8.8.8.8"
    assert stats["counts"]["local_ips"] == 0
    assert stats["counts"]["remote_indicators_preserved"] >= 2
    print("PASS case_public_ip_preserved")


def case_dns_preserved_ip():
    # A DNS A-record response returning 10.0.0.5 (attacker's C2 in private range)
    b = _bundle([
        _fact(
            "f1", "dns", "a_record_response", "10.0.0.5",
            "evil-c2.example A 10.0.0.5",
        ),
        _fact("f2", "network", "tcp_connect", "10.0.0.5", "10.0.0.5:443 tcp"),
    ])
    preserve = extract_preserve_ips(b)
    assert "10.0.0.5" in preserve, f"expected 10.0.0.5 in preserve, got {preserve}"
    out, stats, returned_preserve = sanitize_bundle(b, CONFIG, preserve)
    assert returned_preserve == preserve
    # Both facts should still contain 10.0.0.5 (preserved, not redacted)
    assert "10.0.0.5" in out["facts"][0]["verbatim"], out["facts"][0]["verbatim"]
    assert "10.0.0.5" in out["facts"][1]["verbatim"], out["facts"][1]["verbatim"]
    assert stats["counts"]["local_ips"] == 0
    assert stats["counts"]["remote_indicators_preserved"] >= 2
    print("PASS case_dns_preserved_ip")


def case_credentials_redacted():
    b = _bundle([
        _fact("f1", "credential_access", "password_field", "hunter2", "password=hunter2"),
        _fact("f2", "http", "post_body", "x", 'api_key="abc-123"'),
    ])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    assert "hunter2" not in out["facts"][0]["verbatim"], out["facts"][0]["verbatim"]
    assert "password=<redacted>" in out["facts"][0]["verbatim"]
    assert "abc-123" not in out["facts"][1]["verbatim"]
    assert "api_key=<redacted>" in out["facts"][1]["verbatim"]
    assert stats["counts"]["secrets"] >= 2
    print("PASS case_credentials_redacted")


def case_url_credentials_redacted():
    b = _bundle([
        _fact("f1", "http", "url", "https://admin:hunter2@internal.example.com/", "https://admin:hunter2@internal.example.com/"),
    ])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    text = out["facts"][0]["verbatim"]
    assert "hunter2" not in text, text
    assert "admin:hunter2" not in text, text
    assert "://<redacted>@" in text, text
    print("PASS case_url_credentials_redacted")


def case_sandbox_path_prefix():
    b = _bundle([
        _fact("f1", "file", "written", "/home/sandbox/Downloads/evil.exe", "/home/sandbox/Downloads/evil.exe"),
        _fact("f2", "file", "written", "C:\\cuckoo\\file.txt", "C:\\cuckoo\\file.txt"),
    ])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    t1 = out["facts"][0]["verbatim"]
    t2 = out["facts"][1]["verbatim"]
    assert t1.startswith("<sandbox_path>"), t1
    assert "/Downloads/evil.exe" in t1, t1  # filename preserved
    assert t2.startswith("<sandbox_path>"), t2
    assert "\\file.txt" in t2, t2
    assert stats["counts"]["sandbox_paths"] >= 2
    print("PASS case_sandbox_path_prefix")


def case_sandbox_path_lookalike_not_redacted():
    b = _bundle([
        _fact("f1", "file", "written", "/home/sandbox_test/config.json", "/home/sandbox_test/config.json"),
    ])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    assert out["facts"][0]["verbatim"] == "/home/sandbox_test/config.json", out["facts"][0]["verbatim"]
    assert stats["counts"]["sandbox_paths"] == 0
    print("PASS case_sandbox_path_lookalike_not_redacted")


def case_domain_hash_registry_preserved():
    b = _bundle([
        _fact("f1", "dns", "query_name", "evil.example.com", "evil.example.com A ?"),
        _fact("f2", "file", "hash", "abc123def", "sha256 abc123def"),
        _fact("f3", "registry", "created", "HKCU\\Software\\Updater", "HKCU\\Software\\Updater"),
    ])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    assert out["facts"][0]["verbatim"] == "evil.example.com A ?"
    assert out["facts"][1]["verbatim"] == "sha256 abc123def"
    assert out["facts"][2]["verbatim"] == "HKCU\\Software\\Updater"
    print("PASS case_domain_hash_registry_preserved")


def case_loopback_and_link_local():
    b = _bundle([
        _fact("f1", "network", "connect", "127.0.0.1", "127.0.0.1:8080"),
        _fact("f2", "network", "connect", "::1", "[::1]:8443"),
    ])
    out, stats, _ = sanitize_bundle(b, CONFIG)
    assert "127.0.0.1" not in out["facts"][0]["verbatim"]
    assert "<local_IP>" in out["facts"][0]["verbatim"]
    assert "::1" not in out["facts"][1]["verbatim"] or "<local_IP>" in out["facts"][1]["verbatim"]
    print("PASS case_loopback_and_link_local")


def case_manifest_counts():
    b = _bundle([
        _fact("f1", "network", "connect", "192.168.0.1", "192.168.0.1:443"),
        _fact("f2", "credential_access", "cred", "pass1", "password=pass1"),
        _fact("f3", "file", "written", "/home/sandbox/a.txt", "/home/sandbox/a.txt"),
        _fact("f4", "network", "connect", "8.8.8.8", "8.8.8.8:53"),
    ])
    sanitized, pre, preserve = sanitize_bundle(b, CONFIG)
    # Post-pass on a synthetic report that contains no new secrets
    report = {"claims": [{"claim_id": "c1", "text": "sample connected to 8.8.8.8", "citations": []}]}
    _, post = sanitize_report(report, CONFIG, preserve)
    manifest = build_manifest("01234567-89ab-4cde-8fab-0123456789ab", CONFIG, pre, post)
    assert manifest["schema_version"] == "sanitization-manifest/1.0"
    assert manifest["redaction_appendix"]["local_ips_redacted"] >= 1
    assert manifest["redaction_appendix"]["passwords_secrets_redacted"] >= 1
    assert manifest["redaction_appendix"]["sandbox_paths_redacted"] >= 1
    assert manifest["redaction_appendix"]["remote_indicators_preserved"] >= 1
    print("PASS case_manifest_counts")


def case_post_pass_warning():
    # Post-pass sees >=3 secrets injected by model that we must redact -> warning=True
    report = {
        "claims": [
            {
                "claim_id": "c1",
                "text": "password=a token=b pwd=c",
                "citations": [],
            }
        ]
    }
    _, post = sanitize_report(report, CONFIG, set())
    assert post["counts"]["secrets"] >= 3, post["counts"]
    assert post["warning"] is True, post
    print("PASS case_post_pass_warning")


def main() -> int:
    failures = 0
    for name, fn in [
        ("case_internal_ip_redacted", case_internal_ip_redacted),
        ("case_public_ip_preserved", case_public_ip_preserved),
        ("case_dns_preserved_ip", case_dns_preserved_ip),
        ("case_credentials_redacted", case_credentials_redacted),
        ("case_url_credentials_redacted", case_url_credentials_redacted),
        ("case_sandbox_path_prefix", case_sandbox_path_prefix),
        ("case_sandbox_path_lookalike_not_redacted", case_sandbox_path_lookalike_not_redacted),
        ("case_domain_hash_registry_preserved", case_domain_hash_registry_preserved),
        ("case_loopback_and_link_local", case_loopback_and_link_local),
        ("case_manifest_counts", case_manifest_counts),
        ("case_post_pass_warning", case_post_pass_warning),
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
    print("all sanitizer cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
