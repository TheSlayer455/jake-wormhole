import concurrent.futures
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole.contracts import ContractError
from wormhole.runs import (MAX_JSON_BYTES, SOURCE_ROOT, Run, RunError, atomic_bytes,
                           atomic_json, cleanup_run, create_run, report_run, workspace_path)
from wormhole.stages import execute_run, verify_run


def _concurrent_create(workspace, barrier, results):
    """Both processes observe a missing workspace before either mkdir executes."""
    original = Path.exists
    first = True

    def exists(path):
        nonlocal first
        if path == Path(workspace) and first:
            first = False
            barrier.wait(timeout=10)
            return False
        return original(path)

    try:
        with patch.object(Path, "exists", exists):
            run = create_run(workspace, fixture=True, identity=("a" * 40, False))
            with run.locked():
                execute_run(run)
        results.put((run.id, None))
    except Exception as error:
        results.put((None, type(error).__name__))


class RunTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "runs"

    def new(self, fixture=True):
        return create_run(self.workspace, fixture=fixture, identity=("a" * 40, False))

    def completed(self, fixture=True):
        run = self.new(fixture)
        with run.locked():
            execute_run(run)
        return run

    def test_simultaneous_fixtures_have_disjoint_private_and_evidence_paths(self):
        def fixture(_):
            return self.completed()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            first, second = list(executor.map(fixture, range(2)))
        self.assertNotEqual(first.id, second.id)
        for relative in ("private/credentials", "private/inventory", "private/terraform", "evidence"):
            self.assertNotEqual(first.file(relative), second.file(relative))
            self.assertTrue(first.file(relative).is_dir())
            self.assertTrue(second.file(relative).is_dir())
        for run in (first, second):
            with run.locked():
                self.assertTrue(verify_run(run)["fixture_subset_passed"])
                portable = json.dumps(report_run(run))
                self.assertNotIn(str(run.path), portable)
                self.assertNotIn(str(self.root), portable)
        if os.name == "posix":
            self.assertEqual(first.path.stat().st_mode & 0o777, 0o700)
            self.assertEqual(first.file("manifest.json").stat().st_mode & 0o777, 0o600)

    def test_two_processes_can_create_an_initially_absent_workspace(self):
        context = multiprocessing.get_context("spawn")
        barrier, results = context.Barrier(2), context.Queue()
        processes = [context.Process(target=_concurrent_create, args=(str(self.workspace), barrier, results)) for _ in range(2)]
        for process in processes:
            process.start()
        try:
            outcomes = [results.get(timeout=15) for _ in processes]
            self.assertEqual([error for _, error in outcomes], [None, None])
            self.assertNotEqual(outcomes[0][0], outcomes[1][0])
        finally:
            for process in processes:
                process.join(timeout=5)
                if process.is_alive():
                    process.kill(); process.join(timeout=5)
            results.close()

    def test_rejects_traversal_checkout_vault_missing_and_foreign_ownership(self):
        for identifier in ("../anything", str(uuid4()).upper(), "not-a-run", ""):
            with self.subTest(identifier=identifier), self.assertRaises(RunError):
                Run(self.workspace, identifier)
        with self.assertRaises(RunError):
            workspace_path(SOURCE_ROOT / "runs", create=True)
        vault = self.root / "vault"
        vault.mkdir(); (vault / ".obsidian").mkdir()
        with self.assertRaises(RunError):
            workspace_path(vault / "runs", create=True)
        run = self.new()
        with self.assertRaises(RunError):
            run.file("../outside")
        atomic_json(run.file("owner.json"), {"application": "another-project"})
        with self.assertRaises(RunError):
            Run(self.workspace, run.id)

    def test_symlink_components_and_private_cleanup_are_rejected(self):
        target = self.root / "target"
        target.mkdir()
        sentinel = target / "preserve.txt"
        sentinel.write_text("unrelated fixture")
        link = self.root / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("Creating symlink fixtures requires OS support/permission.")
        with self.assertRaises(RunError):
            workspace_path(link / "nested", create=True)
        run = self.completed()
        (run.path / "private" / "linked").symlink_to(target, target_is_directory=True)
        with run.locked(), self.assertRaises(RunError):
            cleanup_run(run)
        self.assertEqual(sentinel.read_text(), "unrelated fixture")

    @unittest.skipUnless(os.name == "nt", "NTFS junction regression requires Windows")
    def test_windows_junction_is_rejected_without_touching_target(self):
        target, link = self.root / "target", self.root / "junction"
        target.mkdir()
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        if result.returncode:
            self.skipTest("Junction fixture is unavailable on this filesystem.")
        try:
            with self.assertRaises(RunError):
                workspace_path(link / "nested", create=True)
        finally:
            link.rmdir()
        self.assertTrue(target.is_dir())

    def test_json_byte_bounds_duplicates_nonfinite_and_unsupported_schema(self):
        run = self.new()
        before = run.file("manifest.json").read_bytes()
        with self.assertRaises(RunError):
            atomic_json(run.file("manifest.json"), {"oversize": "x" * MAX_JSON_BYTES})
        self.assertEqual(run.file("manifest.json").read_bytes(), before)
        with self.assertRaises(RunError):
            atomic_json(run.file("bad.json"), {"number": float("nan")})
        atomic_bytes(run.file("manifest.json"), b'{"schema_version":"1.0","schema_version":"2.0"}')
        with self.assertRaises(RunError):
            run.manifest()
        atomic_bytes(run.file("manifest.json"), before)
        value = run.manifest(); value["schema_version"] = "2.0"
        with self.assertRaises(ContractError):
            run.save_manifest(value)

    def test_exact_lock_and_cleanup_preserve_evidence_and_primary_outcome(self):
        run = self.completed()
        original = run.manifest()
        with run.locked():
            with self.assertRaises(RunError):
                with Run(self.workspace, run.id).locked():
                    self.fail("A second writer acquired the same run")
            atomic_bytes(run.file("private/credentials/synthetic.txt"), b"synthetic-only")
            receipt = cleanup_run(run)
            self.assertEqual(receipt["status"], "completed")
            self.assertFalse(receipt["infrastructure_removed"])
            self.assertFalse(run.file("private").exists())
            self.assertEqual(run.manifest(), original)
            self.assertTrue(verify_run(run)["fixture_subset_passed"])
            self.assertEqual(cleanup_run(run)["status"], "completed")
        self.assertTrue(run.file("evidence/test-results.json").is_file())
        unsupported = self.completed(False)
        with unsupported.locked(), self.assertRaises(RunError):
            cleanup_run(unsupported)
        self.assertTrue(unsupported.file("private").exists())

    def test_wrong_run_evidence_and_malformed_cleanup_receipts_are_rejected(self):
        run = self.completed()
        inventory = run.artifact("inventory"); inventory["run_id"] = str(uuid4())
        run.save_artifact("inventory", inventory)
        with self.assertRaises(RunError):
            report_run(run)
        inventory["run_id"] = run.id; run.save_artifact("inventory", inventory)
        with run.locked():
            receipt = cleanup_run(run)
        for field, value in (("private_state_removed", "yes"), ("status", []), ("created_at", 23), ("created_at", "yesterday"), ("error", {"private": "data"})):
            malformed = {**receipt, field: value}
            atomic_json(run.file("cleanup.json"), malformed)
            with self.subTest(field=field, value=value), self.assertRaises(RunError):
                report_run(run)

    def test_failed_cleanup_retains_truthful_receipt_and_primary_run_status(self):
        run = self.completed()
        before = run.manifest()
        with run.locked(), patch("wormhole.runs.shutil.rmtree", side_effect=OSError("synthetic failure")):
            with self.assertRaises(RunError):
                cleanup_run(run)
        report = report_run(run)
        self.assertEqual(report["manifest"], before)
        self.assertEqual(report["cleanup"]["status"], "failed")
        self.assertFalse(report["cleanup"]["private_state_removed"])
        self.assertFalse(report["cleanup"]["infrastructure_removed"])
        self.assertTrue(run.file("private").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX private-mode assertion")
    def test_insecure_workspace_permissions_are_rejected(self):
        self.workspace.mkdir(mode=0o755)
        self.workspace.chmod(0o755)
        with self.assertRaises(RunError):
            self.new()


if __name__ == "__main__":
    unittest.main()
