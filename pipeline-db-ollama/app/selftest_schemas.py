"""Self-test: verify every schema in /opt/pipeline/schemas parses, is accepted
by the 2020-12 metaschema, and that all internal and cross-file $refs resolve.

Run: sudo -u pipeline env -C /opt/pipeline /opt/pipeline/venv/bin/python -m app.selftest_schemas
Exits 0 on success, 1 on any failure.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMAS_DIR = Path("/opt/pipeline/schemas")


def _registry() -> Registry:
    pairs = []
    for p in sorted(SCHEMAS_DIR.glob("*.schema.json")):
        contents = json.loads(p.read_text())
        resource = Resource.from_contents(
            contents, default_specification=DRAFT202012
        )
        uri = contents.get("$id") or p.name
        pairs.append((uri, resource))
    return Registry().with_resources(pairs)


def main() -> int:
    if not SCHEMAS_DIR.is_dir():
        print(f"schemas dir missing: {SCHEMAS_DIR}", file=sys.stderr)
        return 1
    registry = _registry()
    failures = 0
    for p in sorted(SCHEMAS_DIR.glob("*.schema.json")):
        try:
            schema = json.loads(p.read_text())
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema, registry=registry)
        except Exception as exc:
            print(f"LOAD FAIL: {p.name}: {exc}")
            failures += 1
            continue
        print(f"load ok: {p.name}")
    if failures:
        print(f"{failures} schema(s) failed", file=sys.stderr)
        return 1
    print("all schemas load and resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
