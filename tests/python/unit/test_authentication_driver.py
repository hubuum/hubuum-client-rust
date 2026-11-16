"""Failure and buffering regressions for the disposable live-system controller."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "authentication_driver", ROOT / "tests/python/integration/authentication.py")
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


class ControllerTests(unittest.TestCase):
    def consumer_fixture(self, root):
        return SimpleNamespace(root=root, origin="https://localhost:48480",
            local_password="fixture-local-secret", client_secret="fixture-provider-secret",
            provider_origin="https://localhost:48479", provider_port=48479)

    def test_burst_output_is_drained_without_waiting_for_another_pipe_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "consumer"
            events = [{"event": "passed", "check": "first"}, {"event": "passed", "check": "second"},
                      {"event": "complete"}]
            binary.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write({''.join(json.dumps(e) + chr(10) for e in events)!r})\nsys.stdout.flush()\n")
            binary.chmod(0o700)
            checks = []
            driver.consumer(self.consumer_fixture(root), binary, "async", "oauth", checks)
            self.assertEqual(checks, ["first", "second"])
            self.assertFalse((root / "sdk-input.json").exists())

    def test_successful_process_without_completion_is_not_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "consumer"
            binary.write_text(f"#!{sys.executable}\n")
            binary.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "qualification failed"):
                driver.consumer(self.consumer_fixture(root), binary, "blocking", "oauth", [])
            self.assertFalse((root / "sdk-input.json").exists())

    def test_unqualified_image_fails_before_provisioning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture.py"
            fixture.write_text("# fixture\n")
            fixtures = {"fixture.py": hashlib.sha256(fixture.read_bytes()).hexdigest()}
            args = ["driver", "--server-source", str(root), "--image", "unqualified:tag",
                    "--consumer", str(root / "consumer"), "--profile", "oauth", "--evidence", str(root / "evidence")]
            with mock.patch.object(sys, "argv", args), mock.patch.dict(driver.SOURCE,
                    {"source_live_fixture_sha256": fixtures}), mock.patch.object(driver.subprocess,
                    "check_output", side_effect=[driver.SOURCE["accepted_server_source"] + "\n",
                                                json.dumps([{"Id": "sha256:unqualified"}])]) as command:
                with self.assertRaisesRegex(RuntimeError, "not a qualified immutable candidate"):
                    driver.main()
            self.assertEqual(command.call_count, 2)
            self.assertFalse((root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
