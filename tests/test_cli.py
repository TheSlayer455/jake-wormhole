import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from wormhole.runs import SOURCE_ROOT


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name) / "runs"

    def command(self, *arguments):
        result = subprocess.run([sys.executable, "-m", "wormhole", *arguments], cwd=SOURCE_ROOT,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.stderr, "", result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_actual_quickstart_commands_fixture_only_and_publication_refused(self):
        status, doctor = self.command("doctor")
        self.assertEqual(status, 0)
        self.assertFalse(doctor["runtime_pipeline_complete"])
        status, manifest = self.command("run", "--workspace", str(self.workspace), "--fixture")
        self.assertEqual(status, 0)
        self.assertEqual(manifest["mode"], "fixture")
        self.assertEqual(manifest["outcome"], "passed")
        identifier = manifest["run_id"]
        self.assertEqual(manifest["source_dirty"], doctor["source_dirty"])
        status, report = self.command("report", identifier, "--workspace", str(self.workspace))
        self.assertEqual(status, 0)
        self.assertEqual(report["artifacts"]["inventory"]["status"], "unsupported")
        self.assertNotIn(str(self.workspace), json.dumps(report))
        status, verified = self.command("verify", identifier, "--workspace", str(self.workspace))
        self.assertEqual(status, 0)
        self.assertTrue(verified["fixture_subset_passed"])
        self.assertFalse(verified["reference_eligible"])
        status, refusal = self.command("publish-reference", identifier, "--workspace", str(self.workspace))
        self.assertEqual(status, 2)
        self.assertEqual(refusal["error"]["code"], "publication_unsupported")
        status, receipt = self.command("cleanup", identifier, "--workspace", str(self.workspace))
        self.assertEqual(status, 0)
        self.assertTrue(receipt["private_state_removed"])
        self.assertFalse(receipt["infrastructure_removed"])
        self.assertTrue((self.workspace / identifier / "evidence" / "test-results.json").exists())
        self.assertEqual(self.command("verify", identifier, "--workspace", str(self.workspace))[0], 0)

    def test_unfinished_real_run_is_durable_nonzero_not_a_fake_pipeline_pass(self):
        status, manifest = self.command("run", "--workspace", str(self.workspace))
        self.assertEqual(status, 1)
        self.assertEqual(manifest["outcome"], "failed")
        self.assertEqual(manifest["mode"], "container-reference")
        self.assertEqual(manifest["stages"][0]["status"], "unsupported")
        identifier = manifest["run_id"]
        status, report = self.command("report", identifier, "--workspace", str(self.workspace))
        self.assertEqual(status, 0)
        self.assertEqual(report["manifest"]["stages"][0]["status"], "unsupported")
        status, verified = self.command("verify", identifier, "--workspace", str(self.workspace))
        self.assertEqual(status, 1)
        self.assertFalse(verified["fixture_subset_passed"])
        self.assertEqual(self.command("cleanup", identifier, "--workspace", str(self.workspace))[0], 2)

    def test_invalid_run_id_unsafe_workspace_and_malformed_records_fail_cleanly(self):
        for identifier in ("../another-run", "wrong"):
            self.assertEqual(self.command("report", identifier, "--workspace", str(self.workspace))[0], 2)
        status, result = self.command("run", "--fixture", "--workspace", str(SOURCE_ROOT / "runs"))
        self.assertEqual(status, 2)
        self.assertEqual(result["error"]["code"], "unsafe_workspace")
        _, manifest = self.command("run", "--fixture", "--workspace", str(self.workspace))
        path = self.workspace / manifest["run_id"] / "evidence" / "inventory.json"
        path.write_text('{"schema_version":"999.0"}')
        status, result = self.command("verify", manifest["run_id"], "--workspace", str(self.workspace))
        self.assertEqual(status, 2)
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
