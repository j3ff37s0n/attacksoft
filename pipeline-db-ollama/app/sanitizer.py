"""Deterministic sanitizer for the evidence bundle and the LLM report.

Runs before the LLM ingestion.
cleans the cuckoo results so the model never sees local infrastructure
One move after the LLM runs 
Returns per-pass counts only; no redacted values are ever logged.

Test: python -m app.test_sanitizer
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SANITIZER_VERSION = "sanitizer/1.0"

# IPv4: standard pattern, validated with ipaddress.IPv4Address to reject
# out-of-range addresses like 256.1.1.1 which the regex would otherwise match.
IPV4_RE = re.compile(r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])')

# IPv6: canonical pattern from the RFC recommendations. Matches a wide variety
# of forms; every match is validated with ipaddress.IPv6Address before use.
IPV6_RE = re.compile(
    r'(?<![0-9a-fA-F:])('
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'
    r':(?::[0-9a-fA-F]{1,4}){1,7}|'
    r'::'
    r')(?![0-9a-fA-F:])'
)

# URL credentials: scheme://user:pass@host.  Match from :// up to the first @,
# stopping at / or whitespace so we do not eat path components.
URL_CRED_RE = re.compile(r'(?<=://)[^/@\s]+@')

# DNS response facts: any fact whose category is "dns" and whose key contains
# one of these tokens is treated as a DNS response. Any IP appearing in such a
# fact is preserved through internal-IP redaction (attacker C2 IP might be a
# private-range address, and that is legitimate evidence, not operator infra).
DNS_RESPONSE_KEY_RE = re.compile(
    r'(?i)(response|answer|a_record|aaaa_record|resolved|cname_response)'
)


@dataclass
class SanitizerConfig:
    internal_cidrs: list[str]
    sandbox_paths: list[str]
    sandbox_hostnames: list[str]
    sandbox_macs: list[str]
    secret_key_regex: str
    config_sha256: str
    _internal_networks: list = field(default_factory=list, init=False)
    _secret_re: re.Pattern = field(init=False)
    _secret_kv_re: re.Pattern = field(init=False)
    _path_patterns: list = field(default_factory=list, init=False)

    def __post_init__(self):
        self._internal_networks = [ipaddress.ip_network(c) for c in self.internal_cidrs]
        self._secret_re = re.compile(self.secret_key_regex)
        key_pat = self.secret_key_regex
        if key_pat.startswith("(?i)"):
            key_pat = key_pat[4:]
            flags = re.IGNORECASE
        else:
            flags = 0
        self._secret_kv_re = re.compile(
            r'(?P<key>' + key_pat + r')'
            r'(?P<sep>\s*[=:]\s*)'
            r'(?P<val>"[^"]*"|\'[^\']*\'|[^\s&;,}]+)',
            flags,
        )
        # Longest path first so /opt/cuckoo3 wins over /opt/cuckoo if both listed.
        sorted_paths = sorted(self.sandbox_paths, key=len, reverse=True)
        self._path_patterns = [
            re.compile(re.escape(p) + r'(?=[/\\\s]|$)') for p in sorted_paths
        ]


class _PassState:
    """Mutable accumulator for one sanitization pass."""

    def __init__(self):
        self.counts = {
            "local_ips": 0,
            "secrets": 0,
            "sandbox_paths": 0,
            "sandbox_hostnames": 0,
            "sandbox_macs": 0,
            "remote_indicators_preserved": 0,
        }
        self.rule_hits: dict[str, int] = {}

    def hit(self, rule_id: str, count: int = 1):
        self.rule_hits[rule_id] = self.rule_hits.get(rule_id, 0) + count

    def to_pass(self) -> dict:
        total_redactions = (
            self.counts["local_ips"]
            + self.counts["secrets"]
            + self.counts["sandbox_paths"]
            + self.counts["sandbox_hostnames"]
            + self.counts["sandbox_macs"]
        )
        return {
            "counts": dict(self.counts),
            "rule_hits": [
                {"rule_id": k, "count": v} for k, v in sorted(self.rule_hits.items())
            ],
            "warning": total_redactions > 2,
        }


def load_config(path: Path) -> SanitizerConfig:
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    data = yaml.safe_load(raw)
    return SanitizerConfig(
        internal_cidrs=data["internal_cidrs"],
        sandbox_paths=data.get("sandbox_paths", []),
        sandbox_hostnames=data.get("sandbox_hostnames", []),
        sandbox_macs=data.get("sandbox_macs", []),
        secret_key_regex=data["secret_key_regex"],
        config_sha256=sha,
    )


def _canonical_ip(ip_str: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        return None


def extract_preserve_ips(bundle: dict) -> set[str]:
    """Return canonical IP strings that must survive internal-IP redaction.

    An IP is preserved if it appears inside a fact whose category is "dns" and
    whose key names a response/answer. This captures the case where the attacker
    controls DNS and returns a private-range address for their C2 hostname.
    """
    preserve: set[str] = set()
    for fact in bundle.get("facts", []):
        if fact.get("category") != "dns":
            continue
        key = str(fact.get("key", ""))
        if not DNS_RESPONSE_KEY_RE.search(key):
            continue
        for field_name in ("value", "verbatim"):
            text = str(fact.get(field_name, "") or "")
            for m in IPV4_RE.finditer(text):
                canon = _canonical_ip(m.group())
                if canon:
                    preserve.add(canon)
            for m in IPV6_RE.finditer(text):
                canon = _canonical_ip(m.group())
                if canon:
                    preserve.add(canon)
    return preserve


def _sanitize_string(
    text: str,
    config: SanitizerConfig,
    preserve_ips: set[str],
    state: _PassState,
) -> str:
    if not text:
        return text

    # 1) URL credentials: scheme://user:pass@host -> scheme://<redacted>@host
    def _redact_url_cred(m: re.Match) -> str:
        state.counts["secrets"] += 1
        state.hit("credential_url")
        return "<redacted>@"

    text = URL_CRED_RE.sub(_redact_url_cred, text)

    # 2) key=value secrets. Preserve the key and separator, replace the value.
    def _redact_kv(m: re.Match) -> str:
        state.counts["secrets"] += 1
        state.hit("credential_kv")
        return f"{m.group('key')}{m.group('sep')}<redacted>"

    text = config._secret_kv_re.sub(_redact_kv, text)

    # 3) IPs. Order: check preserve, then internal, then leave alone (public).
    def _redact_ipv4(m: re.Match) -> str:
        matched = m.group()
        canon = _canonical_ip(matched)
        if canon is None:
            return matched
        if canon in preserve_ips:
            state.counts["remote_indicators_preserved"] += 1
            state.hit("dns_preserved_ip")
            return matched
        ip_obj = ipaddress.ip_address(canon)
        for net in config._internal_networks:
            if ip_obj.version == net.version and ip_obj in net:
                state.counts["local_ips"] += 1
                state.hit(f"internal_ipv{ip_obj.version}")
                return "<local_IP>"
        state.counts["remote_indicators_preserved"] += 1
        state.hit("public_ip_preserved")
        return matched

    text = IPV4_RE.sub(_redact_ipv4, text)

    def _redact_ipv6(m: re.Match) -> str:
        matched = m.group()
        canon = _canonical_ip(matched)
        if canon is None:
            return matched
        if canon in preserve_ips:
            state.counts["remote_indicators_preserved"] += 1
            state.hit("dns_preserved_ip")
            return matched
        ip_obj = ipaddress.ip_address(canon)
        for net in config._internal_networks:
            if ip_obj.version == net.version and ip_obj in net:
                state.counts["local_ips"] += 1
                state.hit(f"internal_ipv{ip_obj.version}")
                return "<local_IP>"
        state.counts["remote_indicators_preserved"] += 1
        state.hit("public_ip_preserved")
        return matched

    text = IPV6_RE.sub(_redact_ipv6, text)

    # 4) Sandbox path prefix. Replace the prefix only, keep the suffix so that
    # attacker filenames and subpaths survive.
    for pat in config._path_patterns:
        def _redact_path(m: re.Match) -> str:
            state.counts["sandbox_paths"] += 1
            state.hit("sandbox_path")
            return "<sandbox_path>"
        text = pat.sub(_redact_path, text)

    # 5) Sandbox hostnames (exact match, case-insensitive).
    for host in config.sandbox_hostnames:
        if not host:
            continue
        pattern = re.compile(r'(?<![A-Za-z0-9.\-])' + re.escape(host) + r'(?![A-Za-z0-9.\-])', re.IGNORECASE)
        def _redact_host(m: re.Match) -> str:
            state.counts["sandbox_hostnames"] += 1
            state.hit("sandbox_hostname")
            return "<sandbox_host>"
        text = pattern.sub(_redact_host, text)

    # 6) Sandbox MAC addresses (exact match, case-insensitive).
    for mac in config.sandbox_macs:
        if not mac:
            continue
        pattern = re.compile(re.escape(mac), re.IGNORECASE)
        def _redact_mac(m: re.Match) -> str:
            state.counts["sandbox_macs"] += 1
            state.hit("sandbox_mac")
            return "<sandbox_mac>"
        text = pattern.sub(_redact_mac, text)

    return text


def _sanitize_structure(obj: Any, config, preserve_ips, state) -> Any:
    if isinstance(obj, str):
        return _sanitize_string(obj, config, preserve_ips, state)
    if isinstance(obj, dict):
        return {k: _sanitize_structure(v, config, preserve_ips, state) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_structure(v, config, preserve_ips, state) for v in obj]
    return obj


def sanitize_bundle(
    bundle: dict, config: SanitizerConfig, preserve_ips: set[str] | None = None
) -> tuple[dict, dict, set[str]]:
    """Sanitize the evidence bundle. Returns (sanitized, pass_stats, preserve_ips).

    The returned preserve_ips must be passed to sanitize_report() so that the
    post-LLM pass uses the same DNS-derived allowlist.
    """
    if preserve_ips is None:
        preserve_ips = extract_preserve_ips(bundle)
    state = _PassState()
    sanitized = _sanitize_structure(bundle, config, preserve_ips, state)
    return sanitized, state.to_pass(), preserve_ips


def sanitize_report(
    report: dict, config: SanitizerConfig, preserve_ips: set[str]
) -> tuple[dict, dict]:
    """Sanitize the LLM report output. Returns (sanitized_report, post_pass_stats)."""
    state = _PassState()
    sanitized = _sanitize_structure(report, config, preserve_ips, state)
    return sanitized, state.to_pass()


def build_manifest(
    submission_id: str,
    config: SanitizerConfig,
    pre_pass: dict,
    post_pass: dict,
) -> dict:
    """Combine pre-LLM and post-LLM passes into a schema-compliant manifest."""
    from datetime import datetime, timezone

    appendix = {
        "local_ips_redacted": pre_pass["counts"]["local_ips"] + post_pass["counts"]["local_ips"],
        "passwords_secrets_redacted": pre_pass["counts"]["secrets"] + post_pass["counts"]["secrets"],
        "sandbox_paths_redacted": pre_pass["counts"]["sandbox_paths"] + post_pass["counts"]["sandbox_paths"],
        "sandbox_hostnames_users_redacted": (
            pre_pass["counts"]["sandbox_hostnames"] + post_pass["counts"]["sandbox_hostnames"]
        ),
        "remote_indicators_preserved": pre_pass["counts"]["remote_indicators_preserved"],
    }
    return {
        "schema_version": "sanitization-manifest/1.0",
        "submission_id": submission_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sanitizer_version": SANITIZER_VERSION,
        "config_sha256": config.config_sha256,
        "pre_llm": pre_pass,
        "post_llm": post_pass,
        "redaction_appendix": appendix,
    }
