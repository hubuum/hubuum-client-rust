#!/usr/bin/env python3
import argparse
import difflib
import hashlib
import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "openapi" / "operations.json"
DEFAULT_SPEC = "https://raw.githubusercontent.com/hubuum/hubuum/v0.0.2/docs/openapi.json"
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def load_spec(source: str) -> dict:
    path = pathlib.Path(source)
    if path.exists():
        return json.loads(path.read_text())
    with urllib.request.urlopen(source, timeout=30) as response:
        return json.load(response)


def normalize(spec: dict) -> dict:
    operations = []
    for path, path_item in spec.get("paths", {}).items():
        inherited = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method not in METHODS:
                continue
            parameters = inherited + operation.get("parameters", [])
            responses = operation.get("responses", {})
            operations.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "operation_id": operation.get("operationId"),
                    "security": operation.get("security", spec.get("security", [])),
                    "parameters": sorted(
                        {
                            f"{parameter.get('in')}:{parameter.get('name')}"
                            for parameter in parameters
                            if isinstance(parameter, dict)
                        }
                    ),
                    "request_content": sorted(
                        operation.get("requestBody", {}).get("content", {}).keys()
                    ),
                    "responses": {
                        status: sorted(response.get("content", {}).keys())
                        for status, response in sorted(responses.items())
                    },
                }
            )
    operations.sort(key=lambda operation: (operation["path"], operation["method"]))
    schema_names = sorted(spec.get("components", {}).get("schemas", {}).keys())
    canonical_spec = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    return {
        "openapi": spec.get("openapi"),
        "api_version": spec.get("info", {}).get("version"),
        "spec_sha256": hashlib.sha256(canonical_spec).hexdigest(),
        "path_count": len(spec.get("paths", {})),
        "operation_count": len(operations),
        "schema_count": len(schema_names),
        "schema_names": schema_names,
        "operations": operations,
    }


def encoded(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("update", "check", "validate"))
    parser.add_argument("--spec", default=DEFAULT_SPEC)
    args = parser.parse_args()

    if args.mode == "validate":
        snapshot = json.loads(SNAPSHOT.read_text())
        operations = snapshot.get("operations", [])
        unique = {(item["method"], item["path"]) for item in operations}
        if len(unique) != snapshot.get("operation_count"):
            print("OpenAPI snapshot has duplicate or missing operations", file=sys.stderr)
            return 1
        if len({item["path"] for item in operations}) != snapshot.get("path_count"):
            print("OpenAPI snapshot path count is inconsistent", file=sys.stderr)
            return 1
        return 0

    current = normalize(load_spec(args.spec))
    if args.mode == "update":
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(encoded(current))
        print(
            f"recorded {current['operation_count']} operations across "
            f"{current['path_count']} paths"
        )
        return 0

    expected = json.loads(SNAPSHOT.read_text())
    if expected == current:
        print("OpenAPI operation contract is unchanged")
        return 0
    diff = difflib.unified_diff(
        encoded(expected).splitlines(),
        encoded(current).splitlines(),
        fromfile=str(SNAPSHOT),
        tofile=args.spec,
        lineterm="",
    )
    print("\n".join(diff), file=sys.stderr)
    print("Run scripts/openapi-contract.py update after reviewing drift", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
