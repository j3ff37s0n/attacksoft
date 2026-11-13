"""Knowledge sync CLI.

Usage:
  python -m app.sync_knowledge full [--sources baseline,mitre,kev,nvd] [--nvd-years 2024,2025]
  python -m app.sync_knowledge daily
  python -m app.sync_knowledge status
  python -m app.sync_knowledge verify
"""
from __future__ import annotations

import argparse
import json
import sys

from app.ingest import run_sync, state_summary, verify
from app.knowledge import get_collection


def _parse_sources(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def _parse_years(s: str | None) -> list[int] | None:
    if not s:
        return None
    return [int(x.strip()) for x in s.split(",") if x.strip()]


def main() -> int:
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    p_full = sub.add_parser("full")
    p_full.add_argument("--sources", default="baseline,mitre,kev,nvd,epss,rss")
    p_full.add_argument("--nvd-years", default=None)

    sub.add_parser("daily")
    sub.add_parser("status")
    sub.add_parser("verify")

    args = p.parse_args()

    if args.cmd == "full":
        counts, errors = run_sync("full", _parse_sources(args.sources), _parse_years(args.nvd_years))
        print(json.dumps({"counts": counts, "errors": errors}, indent=2))
        return 0 if not errors else 1

    if args.cmd == "daily":
        counts, errors = run_sync("daily", ["baseline", "mitre", "kev", "nvd", "epss", "rss"])
        print(json.dumps({"counts": counts, "errors": errors}, indent=2))
        return 0 if not errors else 1

    if args.cmd == "status":
        print(json.dumps(state_summary(), indent=2))
        c = get_collection()
        print(json.dumps({"collection_count": c.count()}, indent=2))
        return 0

    if args.cmd == "verify":
        result = verify(get_collection())
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
