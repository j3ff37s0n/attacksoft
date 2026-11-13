"""Render every prompt template against the fixture set and verify:
    - all placeholders present in the template are known,
    - all expected placeholders are present,
    - rendered text is valid UTF-8,
    - conservative token estimate fits under the model context budget.

Also offers a `smoke` mode that calls Ollama once with the exec prompt and
confirms the returned content parses as JSON with the required top-level keys.

Run:
    python -m app.prompt_lint lint
    python -m app.prompt_lint smoke
"""
import json
import re
import sys
from pathlib import Path

PROMPTS_DIR = Path("/opt/pipeline/prompts")
FIXTURES = PROMPTS_DIR / "fixtures.json"

# Conservative token estimate: 1 token >= 3 characters for JSON+English.
# Real Qwen tokenizer typically runs 15-25% cheaper; this is an upper bound.
CHARS_PER_TOKEN = 3.0
CONTEXT_BUDGET = 14000  # leaves 2384 of 16384 for system + response

EXPECTED = {
    "exec_risk.txt": {
        "EVIDENCE_FACTS_JSON",
        "RETRIEVAL_CHUNKS_JSON",
        "INSUFFICIENT_EVIDENCE_JSON",
        "RETRIEVAL_CONFIDENCE_JSON",
    },
    "timeline.txt": {
        "EVIDENCE_FACTS_JSON",
        "TIMELINE_CANDIDATES_JSON",
        "RETRIEVAL_CHUNKS_JSON",
        "INSUFFICIENT_EVIDENCE_JSON",
        "PCAP_PRESENT",
        "SYSMON_PRESENT",
    },
    "remediation.txt": {
        "EVIDENCE_FACTS_JSON",
        "RETRIEVAL_CHUNKS_JSON",
        "ATTACK_CHAIN_PHASES_JSON",
        "INSUFFICIENT_EVIDENCE_JSON",
    },
    "repair.txt": {
        "VALIDATION_ERRORS_JSON",
        "PRIOR_OUTPUT",
        "EVIDENCE_FACTS_JSON",
        "RETRIEVAL_CHUNKS_JSON",
    },
}

PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")


def _substitute(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _render(template_text: str, fixtures: dict) -> str:
    def repl(match: re.Match) -> str:
        name = match.group(1)
        if name not in fixtures:
            raise KeyError(f"fixture missing value for {name}")
        return _substitute(fixtures[name])
    return PLACEHOLDER.sub(repl, template_text)


def lint() -> int:
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
    failures = 0
    print(f"{'template':<20} {'tokens(est)':>12} {'placeholders':>14} {'status':>8}")
    for name, expected in sorted(EXPECTED.items()):
        path = PROMPTS_DIR / name
        if not path.is_file():
            print(f"{name:<20} {'-':>12} {'-':>14} {'MISSING':>8}")
            failures += 1
            continue
        text = path.read_text(encoding="utf-8")
        found = {m.group(1) for m in PLACEHOLDER.finditer(text)}
        missing = expected - found
        extra = found - expected
        try:
            rendered = _render(text, fixtures)
            rendered.encode("utf-8")
        except Exception as exc:
            print(f"{name:<20} {'-':>12} {'-':>14} {'RENDER':>8}  {exc}")
            failures += 1
            continue
        est = int(len(rendered) / CHARS_PER_TOKEN)
        status = "ok" if (not missing and not extra and est <= CONTEXT_BUDGET) else "FAIL"
        print(f"{name:<20} {est:>12} {len(found):>14} {status:>8}")
        if missing:
            print(f"    missing placeholders: {sorted(missing)}")
            failures += 1
        if extra:
            print(f"    unexpected placeholders: {sorted(extra)}")
            failures += 1
        if est > CONTEXT_BUDGET:
            print(f"    token estimate {est} > {CONTEXT_BUDGET}")
            failures += 1
    if failures:
        print(f"{failures} failure(s)", file=sys.stderr)
        return 1
    print("all templates OK")
    return 0


def smoke() -> int:
    import httpx
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
    system = (PROMPTS_DIR / "system.txt").read_text(encoding="utf-8")
    user = _render((PROMPTS_DIR / "exec_risk.txt").read_text(encoding="utf-8"), fixtures)
    body = {
        "model": "qwen2.5:7b-instruct",
        "format": "json",
        "stream": False,
        "keep_alive": "30m",
        "options": {"temperature": 0, "seed": 42, "num_predict": 2048, "num_ctx": 16384},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    with httpx.Client(timeout=300.0) as c:
        resp = c.post("http://127.0.0.1:11434/api/chat", json=body)
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
    try:
        parsed = json.loads(content)
    except Exception as exc:
        print(f"smoke FAIL: response is not JSON: {exc}")
        print(f"response length: {len(content)} chars")
        print("first 2000 chars:")
        print(content[:2000])
        return 1
    required = {"risk_level", "summary_claim_id", "key_finding_ids",
                "mitre_techniques", "claims", "abstentions",
                "insufficient_evidence"}
    missing = required - set(parsed.keys())
    if missing:
        print(f"smoke FAIL: missing top-level keys: {sorted(missing)}")
        print(json.dumps(parsed, indent=2)[:800])
        return 1
    if isinstance(parsed.get("summary_claim_id"), dict):
        print("smoke FAIL: summary_claim_id is an object; prompt not updated")
        return 1
    if parsed.get("key_finding_ids") and isinstance(parsed["key_finding_ids"][0], dict):
        print("smoke FAIL: key_finding_ids entries are objects; prompt not updated")
        return 1
    print("smoke OK")
    print(json.dumps(parsed, indent=2)[:1200])
    return 0


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"lint", "smoke"}:
        print("usage: python -m app.prompt_lint lint|smoke", file=sys.stderr)
        return 2
    return lint() if sys.argv[1] == "lint" else smoke()


if __name__ == "__main__":
    sys.exit(main())
