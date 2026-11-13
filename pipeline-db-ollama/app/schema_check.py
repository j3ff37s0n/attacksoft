"""Validate a JSON instance against a schema in /opt/pipeline/schemas.

Usage:
    python -m app.schema_check <schema-filename> <instance-path>

Returns 0 on success, 1 on validation failure, 2 on a load error.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMAS_DIR = Path("/opt/pipeline/schemas")


def _load_registry() -> Registry:
    pairs = []
    for p in sorted(SCHEMAS_DIR.glob("*.schema.json")):
        contents = json.loads(p.read_text())
        resource = Resource.from_contents(
            contents, default_specification=DRAFT202012
        )
        uri = contents.get("$id") or p.name
        pairs.append((uri, resource))
    return Registry().with_resources(pairs)


def validate(schema_filename: str, instance):
    schema_path = SCHEMAS_DIR / schema_filename
    if not schema_path.is_file():
        raise FileNotFoundError(f"schema not found: {schema_path}")
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema, registry=_load_registry())
    return sorted(validator.iter_errors(instance), key=lambda e: list(e.path))


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    schema_file, instance_path = sys.argv[1], sys.argv[2]
    try:
        instance = json.loads(Path(instance_path).read_text())
    except Exception as exc:
        print(f"load error: {exc}", file=sys.stderr)
        return 2
    try:
        errors = validate(schema_file, instance)
    except Exception as exc:
        print(f"schema error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for e in errors[:10]:
            print(f"FAIL at {list(e.path)}: {e.message}")
        if len(errors) > 10:
            print(f"... and {len(errors) - 10} more")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
