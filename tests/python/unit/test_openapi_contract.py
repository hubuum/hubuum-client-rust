"""Repository-tool regressions; Python standard library only."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "openapi-contract.py"
SPEC = importlib.util.spec_from_file_location("openapi_contract", SCRIPT)
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


def source_spec():
    return {"openapi": "3.1.0", "info": {"version": "fixture"}, "paths": {
        "/auth": {"get": {"responses": {"200": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Outer"}}}}}}},
        "/unrelated": {"get": {"responses": {"204": {}}}}},
        "components": {"schemas": {"Outer": {"type": "object", "properties": {
            "nested": {"$ref": "#/components/schemas/Inner"}}},
            "Inner": {"type": "string"}, "Unused": {"type": "boolean"}}}}


class ContractTests(unittest.TestCase):
    def test_subset_keeps_transitive_schemas_and_prunes_unrelated_inputs(self):
        result = contract.select_paths(contract.normalize(source_spec()), ["/auth"])
        self.assertEqual(result["schema_names"], ["Inner", "Outer"])
        self.assertEqual(result["operation_count"], 1)
        self.assertEqual(result["path_count"], 1)

    def test_empty_selection_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "selected no operations"):
            contract.select_paths(contract.normalize(source_spec()), ["/absent"])

    def test_cli_uses_explicit_snapshot_without_modifying_release_snapshot(self):
        baseline = (ROOT / "openapi" / "operations.json").read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "spec.json"
            output = Path(temp) / "snapshot.json"
            source.write_text(json.dumps(source_spec()))
            result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "update",
                "--spec", str(source), "--snapshot", str(output), "--path-prefix", "/auth"],
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["operation_count"], 1)
        self.assertEqual((ROOT / "openapi" / "operations.json").read_bytes(), baseline)

    def test_cli_validation_rejects_unknown_schema_references(self):
        snapshot = contract.normalize(source_spec())
        snapshot["operations"][0]["response_schema_refs"].append("Missing")
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "snapshot.json"
            output.write_text(json.dumps(snapshot))
            result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "validate",
                "--snapshot", str(output)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("unknown schemas", result.stderr)


if __name__ == "__main__":
    unittest.main()
