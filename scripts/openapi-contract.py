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
DEFAULT_SPEC = "https://raw.githubusercontent.com/hubuum/hubuum/v0.0.9/docs/openapi.json"
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
SCHEMA_KEYS = {
    "$ref",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "discriminator",
    "enum",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "format",
    "items",
    "maxItems",
    "maxLength",
    "maxProperties",
    "maximum",
    "minItems",
    "minLength",
    "minProperties",
    "minimum",
    "multipleOf",
    "nullable",
    "not",
    "oneOf",
    "pattern",
    "properties",
    "readOnly",
    "required",
    "type",
    "uniqueItems",
    "writeOnly",
}


def load_spec(source: str) -> dict:
    path = pathlib.Path(source)
    if path.exists():
        return json.loads(path.read_text())
    with urllib.request.urlopen(source, timeout=30) as response:
        return json.load(response)


def normalize_schema(schema):
    if isinstance(schema, list):
        return [normalize_schema(value) for value in schema]
    if not isinstance(schema, dict):
        return schema

    normalized = {}
    for key, value in schema.items():
        if key not in SCHEMA_KEYS:
            continue
        if key == "required":
            normalized[key] = sorted(value)
        elif key == "properties":
            normalized[key] = {
                name: normalize_schema(property_schema)
                for name, property_schema in sorted(value.items())
            }
        else:
            normalized[key] = normalize_schema(value)
    return normalized


def component_ref_name(reference: str):
    prefix = "#/components/schemas/"
    return reference[len(prefix) :] if reference.startswith(prefix) else None


def direct_schema_refs(schema) -> set[str]:
    references = set()
    if isinstance(schema, list):
        for value in schema:
            references.update(direct_schema_refs(value))
    elif isinstance(schema, dict):
        reference = schema.get("$ref")
        if isinstance(reference, str):
            name = component_ref_name(reference)
            if name is not None:
                references.add(name)
        for value in schema.values():
            references.update(direct_schema_refs(value))
    return references


def transitive_schema_refs(schema, schemas: dict) -> list[str]:
    pending = list(direct_schema_refs(schema))
    references = set()
    while pending:
        name = pending.pop()
        if name in references:
            continue
        references.add(name)
        pending.extend(direct_schema_refs(schemas.get(name, {})) - references)
    return sorted(references)


def normalize(spec: dict) -> dict:
    operations = []
    schemas = spec.get("components", {}).get("schemas", {})
    for path, path_item in spec.get("paths", {}).items():
        inherited = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method not in METHODS:
                continue
            parameters = inherited + operation.get("parameters", [])
            responses = operation.get("responses", {})
            request_content = operation.get("requestBody", {}).get("content", {})
            request_schemas = {
                content_type: normalize_schema(content.get("schema", {}))
                for content_type, content in sorted(request_content.items())
            }
            response_schemas = {
                status: {
                    content_type: normalize_schema(content.get("schema", {}))
                    for content_type, content in sorted(
                        response.get("content", {}).items()
                    )
                }
                for status, response in sorted(responses.items())
            }
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
                        request_content.keys()
                    ),
                    "request_schemas": request_schemas,
                    "request_schema_refs": transitive_schema_refs(
                        list(request_schemas.values()), schemas
                    ),
                    "responses": {
                        status: sorted(response.get("content", {}).keys())
                        for status, response in sorted(responses.items())
                    },
                    "response_schemas": response_schemas,
                    "response_schema_refs": transitive_schema_refs(
                        response_schemas, schemas
                    ),
                }
            )
    operations.sort(key=lambda operation: (operation["path"], operation["method"]))
    schema_names = sorted(schemas.keys())
    canonical_spec = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    return {
        "openapi": spec.get("openapi"),
        "api_version": spec.get("info", {}).get("version"),
        "spec_sha256": hashlib.sha256(canonical_spec).hexdigest(),
        "path_count": len(spec.get("paths", {})),
        "operation_count": len(operations),
        "schema_count": len(schema_names),
        "schema_names": schema_names,
        "schemas": {
            name: normalize_schema(schema) for name, schema in sorted(schemas.items())
        },
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
        schemas = snapshot.get("schemas", {})
        schema_names = snapshot.get("schema_names", [])
        if sorted(schemas) != schema_names or len(schemas) != snapshot.get("schema_count"):
            print("OpenAPI snapshot schema index is inconsistent", file=sys.stderr)
            return 1
        known_schemas = set(schema_names)
        for operation in operations:
            for key in ("request_schema_refs", "response_schema_refs"):
                unknown = set(operation.get(key, [])) - known_schemas
                if unknown:
                    print(
                        f"OpenAPI operation {operation['method']} {operation['path']} "
                        f"references unknown schemas: {sorted(unknown)}",
                        file=sys.stderr,
                    )
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
