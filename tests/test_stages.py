import copy
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from wormhole.contracts import ContractError
from wormhole.runs import RunError, cleanup_run, create_run
from wormhole.stages import (FIXTURE_SHA256, LOG_LIMIT, STAGES, _ADAPTERS, _run_process,
                            execute_run, execute_stage, stage_catalog, verify_run)


class StageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name) / "runs"

    def new(self):
        return create_run(self.workspace, fixture=True, identity=("b" * 40, True))

    def completed(self):
        run = self.new()
        with run.locked():
            execute_run(run)
        return run

    def test_registered_unfinished_stage_declares_contract_and_fails_honestly(self):
        run = self.new()
        entry = next(item for item in stage_catalog() if item["name"] == "provisioning")
        self.assertFalse(entry["implemented"])
        self.assertEqual(entry["location"], "provisioner")
        self.assertGreater(entry["timeout_seconds"], 0)
        result = execute_stage("provisioning", run)
        self.assertEqual(result["status"], "unsupported")
        self.assertIsNone(result["returncode"])
        self.assertIsNotNone(result["error"])
        with self.assertRaises(RunError):
            execute_stage("not-registered", run)

    @unittest.skipUnless(os.name == "posix", "Arbitrary diagnostic adapters are unsupported on Windows")
    def test_fixed_subprocess_nonzero_and_streaming_log_bound(self):
        arguments = (sys.executable, "-I", "-c", "import sys; sys.stdout.write('x'*2000000); sys.stderr.write('failure'); sys.exit(7)")
        result = _run_process(arguments, cwd=self.temporary.name, timeout=5)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(len(result["log"]), LOG_LIMIT)
        self.assertTrue(result["log_truncated"])
        self.assertIsNotNone(result["error"])

    @unittest.skipUnless(os.name == "posix", "Arbitrary diagnostic adapters are unsupported on Windows")
    def test_timeout_terminates_actual_child_and_propagates_primary_failure(self):
        arguments = (sys.executable, "-I", "-c", "import os,time; open('pid.txt','w').write(str(os.getpid())); time.sleep(60)")
        started = time.monotonic()
        result = _run_process(arguments, cwd=self.temporary.name, timeout=0.3)
        self.assertEqual(result["status"], "timeout")
        self.assertLess(time.monotonic() - started, 6)
        self.assertIsNotNone(result["returncode"])
        if os.name == "posix":
            identifier = int((Path(self.temporary.name) / "pid.txt").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(identifier, 0)
        run = self.new()
        with patch.dict(_ADAPTERS, {"fixture-integrity": (sys.executable, "-I", "-c", "import sys; sys.exit(9)")}):
            with run.locked():
                manifest = execute_run(run)
        self.assertEqual(manifest["outcome"], "failed")
        self.assertEqual(manifest["stages"][-1]["returncode"], 9)
        self.assertFalse(verify_run(run)["fixture_subset_passed"])
        with run.locked():
            cleanup_run(run)
        self.assertEqual(run.manifest()["outcome"], "failed")
        self.assertEqual(run.manifest()["stages"][-1]["returncode"], 9)

    @unittest.skipUnless(os.name == "posix", "Process-tree execution is unsupported on Windows")
    def test_parent_exit_with_descendant_held_pipe_obeys_absolute_deadline(self):
        child = "import os,time; open('descendant.pid','w').write(str(os.getpid())); time.sleep(60)"
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-I','-c'," + repr(child) + "]);"
        started = time.monotonic()
        result = _run_process((sys.executable, "-I", "-c", code), cwd=self.temporary.name, timeout=0.3)
        self.assertEqual(result["status"], "timeout")
        self.assertLess(time.monotonic() - started, 2)
        identifier = int((Path(self.temporary.name) / "descendant.pid").read_text())
        proc = Path("/proc") / str(identifier) / "stat"
        delivery_deadline = time.monotonic() + 1
        while time.monotonic() < delivery_deadline:
            try:
                if proc.exists() and proc.read_text().split()[2] == "Z":
                    break  # A dead orphan can await the OS reaper; it is not running.
                os.kill(identifier, 0)
            except (FileNotFoundError, ProcessLookupError):
                break
            time.sleep(0.01)
        else:
            self.fail("SIGKILL did not terminate the descendant within the cleanup observation bound")

    @unittest.skipUnless(os.name == "nt", "Windows fixed-leaf boundary regression")
    def test_windows_registry_injection_cannot_launch_an_unreviewed_adapter(self):
        arguments = (sys.executable, "-I", "-c", "raise SystemExit(0)")
        with patch.dict(_ADAPTERS, {"injected": arguments}), patch("wormhole.stages.subprocess.Popen") as launch:
            result = _run_process(arguments, cwd=self.temporary.name, timeout=0.1)
        self.assertEqual(result["status"], "unsupported")
        self.assertIsNone(result["returncode"])
        launch.assert_not_called()

    def test_fixture_verification_rejects_missing_check_and_valid_schema_wrong_hash(self):
        run = self.completed()
        original = run.artifact("test-results")
        for field, replacement in (("expected", "0" * 64), ("observed", "1" * 64), ("required", False), ("target_id", "another-target")):
            value = copy.deepcopy(original); value["checks"][0][field] = replacement
            run.save_artifact("test-results", value)  # Structurally valid, semantically false.
            with self.subTest(field=field), self.assertRaises(RunError):
                verify_run(run)
        value = copy.deepcopy(original); value["checks"] = []
        run.save_artifact("test-results", value)
        with self.assertRaises(RunError):
            verify_run(run)
        run.save_artifact("test-results", original)
        self.assertEqual(original["checks"][0]["expected"], FIXTURE_SHA256)

    def test_wrong_source_mode_and_inconsistent_pass_results_are_rejected(self):
        run = self.completed()
        original = run.artifact("test-results")
        for field, replacement in (("source_revision", "c" * 40), ("source_dirty", False), ("mode", "container-reference")):
            value = {**original, field: replacement}
            run.save_artifact("test-results", value)
            with self.subTest(field=field), self.assertRaises(RunError):
                verify_run(run)
        value = copy.deepcopy(original); value["checks"][0]["status"] = "fail"
        run.save_artifact("test-results", value)
        with self.assertRaises(RunError):
            verify_run(run)
        run.save_artifact("test-results", original)
        value = run.manifest(); value["outcome"] = "failed"
        run.save_manifest(value)
        with self.assertRaises(RunError):
            verify_run(run)

    def test_forged_stage_placeholder_and_release_eligibility_are_rejected(self):
        run = self.completed()
        original = run.manifest()
        for field, replacement in (("returncode", 7), ("error", "failure"), ("timeout_seconds", 12), ("location", "helper")):
            value = copy.deepcopy(original); value["stages"][0][field] = replacement
            run.save_manifest(value)
            with self.subTest(field=field), self.assertRaises(RunError):
                verify_run(run)
        run.save_manifest(original)
        for kind in ("inventory", "svd", "assessment", "release-decision"):
            original_record = run.artifact(kind)
            value = {**original_record, "status": "pass"}
            run.save_artifact(kind, value)
            with self.subTest(kind=kind), self.assertRaises(RunError):
                verify_run(run)
            run.save_artifact(kind, original_record)
        decision = run.artifact("release-decision"); decision["reference_eligible"] = True
        with self.assertRaises(ContractError):
            run.save_artifact("release-decision", decision)
        with self.assertRaises(RunError):
            execute_run(run)


if __name__ == "__main__":
    unittest.main()
