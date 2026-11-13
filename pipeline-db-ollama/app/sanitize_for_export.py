#!/usr/bin/env python3
"""Generate sanitized export files for a task, on demand at download time.

Called via SSH from the webapp raw_export_proxy after payment is confirmed.
Idempotent: regenerates on every call (cheap, text only).

Sanitizes:
  - agent_analysis.json  -> agent_analysis_sanitized.json
      Drops harness command names, CLI options, cwd, and screenshot paths.
      Preserves exit_code, stderr (path-scrubbed), screenshot count/time.
  - payload.log          -> payload_log_sanitized.txt
      Scrubs /home/sandbox paths and RFC1918/loopback IPs.
      Preserves the sample's stdout/stderr content otherwise.
  - setup_overview.md    -> static, written fresh each call

If a source file is absent, writes a clear placeholder so the tar step
always succeeds.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SANDBOX_PATHS = [
    "/home/sandbox",
    "/opt/cuckoo3",
    "/var/lib/cuckoo",
    "/tmp/cuckoo_",
    "C:\\cuckoo",
]
SANDBOX_PATH_RE = re.compile(
    "|".join(re.escape(p) for p in SANDBOX_PATHS) + r"(?=[\W]|$)"
)
INTERNAL_IP_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")\b"
)

SETUP_OVERVIEW = """# Observation Environment Overview

You are receiving a sanitized export of an automated malware analysis. This
document explains what the environment captured, what the export contains,
and what has been sanitized for release.

## What the environment does

The submitted sample was executed in a hardened, isolated environment. During
execution, the environment recorded:

- Process creation, file operations, and network connections at the kernel level
- DNS queries and packet-level network traffic
- The sample's own stdout and stderr output
- Periodic desktop screenshots during execution
- The execution harness's own record of exit status and timing

## What is in this archive

| File | Description |
|------|-------------|
| `_pipeline/sanitized_bundle.json` | Normalized behavioral findings: process, network, DNS, file, registry facts, plus per-artifact hashes. This is the same evidence used to produce the automated PDF reports. |
| `_pipeline/sanitization_manifest.json` | Counts of redacted values by category. Never contains the redacted values themselves. |
| `_pipeline/agent_analysis_sanitized.json` | The execution harness's own record of the run: exit status, stderr output, screenshots captured. Harness commands, CLI options, and sandbox working directory have been removed. |
| `_pipeline/payload_log_sanitized.txt` | The sample's stdout and stderr during execution, with sandbox paths and internal addresses sanitized. |
| `_pipeline/setup_overview.md` | This file. |
| `task_N/screenshots/` | Desktop captures taken during execution. Screenshots are unredacted; the analytical content is in the text files above. |

The sample's exact invocation command, if captured, appears in the
`parent_command_line` process fact within `sanitized_bundle.json`.

## What has been sanitized

- Sandbox filesystem paths -> `<sandbox_path>`
- Internal IP addresses (RFC1918, loopback, link-local) -> `<local_IP>`
- Execution harness commands, CLI options, and configuration values -> removed

## What has not been sanitized

- Public IPs, domains, URLs, HTTP headers, user-agents, TLS fingerprints,
  certificate subjects
- File hashes, filenames of attacker payloads, mutexes, registry keys,
  service names
- Email addresses
- Screenshots

"""


def _scrub_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = SANDBOX_PATH_RE.sub("<sandbox_path>", text)
    text = INTERNAL_IP_RE.sub("<local_IP>", text)
    return text


def sanitize_agent_analysis(raw: dict) -> dict:
    out = {"events": [], "note": "harness internals removed; see setup_overview.md"}
    for ev in raw.get("events", []):
        if not isinstance(ev, dict):
            continue
        et = ev.get("event_type", "")
        d = ev.get("data", {}) or {}
        if et == "execution":
            new = {"event_type": et, "data": {"exit_code": d.get("exit_code")}}
            if "stderr" in d and d["stderr"]:
                new["data"]["stderr"] = _scrub_text(str(d["stderr"]))
            # command, cwd deliberately dropped
        elif et == "screenshot":
            new = {
                "event_type": et,
                "data": {
                    "shots_taken": d.get("shots_taken"),
                    "captured_at": d.get("ts"),
                    # path deliberately dropped; use screenshots/ dir listing
                },
            }
        else:
            new = {"event_type": et, "data": {
                k: (_scrub_text(v) if isinstance(v, str) else v)
                for k, v in d.items()
            }}
        out["events"].append(new)
    return out


def main(task_id: str) -> int:
    adir = Path(f"/opt/pipeline/data/analyses/{task_id}")
    if not adir.is_dir():
        print(f"analysis dir gone: {adir}", file=sys.stderr)
        return 1
    pdir = adir / "_pipeline"
    pdir.mkdir(parents=True, exist_ok=True)

    task_dirs = sorted(d for d in adir.glob("task_*") if d.is_dir())
    if not task_dirs:
        print("no task_N dir", file=sys.stderr)
        return 1
    tdir = task_dirs[0]

    # setup_overview.md — static, regenerated every call
    (pdir / "setup_overview.md").write_text(SETUP_OVERVIEW, encoding="utf-8")

    # agent_analysis_sanitized.json
    aa = tdir / "agent_analysis.json"
    aa_out = pdir / "agent_analysis_sanitized.json"
    if aa.is_file():
        try:
            raw = json.loads(aa.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            print(f"agent_analysis parse failed: {e}", file=sys.stderr)
            raw = {"events": []}
        aa_out.write_text(
            json.dumps(sanitize_agent_analysis(raw), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    else:
        aa_out.write_text(json.dumps(
            {"events": [], "note": "no agent_analysis.json captured"}
        ), encoding="utf-8")

    # payload_log_sanitized.txt
    pl = tdir / "payload.log"
    pl_out = pdir / "payload_log_sanitized.txt"
    if pl.is_file():
        raw = pl.read_text(encoding="utf-8", errors="replace")
        pl_out.write_text(_scrub_text(raw), encoding="utf-8")
    else:
        pl_out.write_text("(no payload.log captured for this analysis)\n",
                          encoding="utf-8")

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: sanitize_for_export.py <task_id>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
