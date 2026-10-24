"""Actual local lock/fixture adapters; no Docker, SSH or infrastructure."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from wormhole import assessments,chunks,runs

SHA='a'*40


class HeldAdapters(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='wormhole-pipeline-lock-synthetic-');self.addCleanup(temporary.cleanup)
        self.run=runs.create_run(Path(temporary.name)/'runs',fixture=False,identity=(SHA,False),kernel_lock=sys.platform.startswith('linux'))
        for module in (assessments,chunks):
            item=patch.object(module,'source_identity',return_value=(SHA,False));item.start();self.addCleanup(item.stop)

    def test_issued_exact_guard_runs_local_components_and_public_nested_calls_still_refuse(self):
        with self.run.locked() as guard:
            self.assertTrue(guard.check(self.run))
            with self.assertRaises(runs.RunError):chunks.execute_fixture(self.run)
            with self.assertRaises(runs.RunError):assessments.assess_run(self.run,assessments.fixture('pass'),assessments.FIXTURE_EXPECTED)
            self.assertEqual(chunks.execute_fixture_held(self.run,guard,size=2051,chunk_size=512)['status'],'passed')
            self.assertEqual(assessments.assess_run_held(self.run,guard,assessments.fixture('pass'),assessments.FIXTURE_EXPECTED)['status'],'passed')
        self.assertEqual(chunks.report_chunks(self.run)['result']['status'],'passed')
        self.assertEqual(assessments.report_assessment(self.run)['result']['status'],'passed')
        with self.assertRaises(runs.RunError):guard.check(self.run)

    def test_arbitrary_descriptor_stale_closed_foreign_and_thread_guards_refuse(self):
        path=self.run.file('private/not-a-lock');path.write_bytes(b'x');path.chmod(0o600)
        with path.open('rb') as stream,self.assertRaises(runs.RunError):runs.HeldRunGuard(self.run,stream.fileno(),path)
        with self.run.locked() as guard:
            other=runs.create_run(self.run.workspace,fixture=False,identity=(SHA,False))
            with self.assertRaises(runs.RunError):guard.check(other)
            saved=guard.descriptor;guard.descriptor=-1
            with self.assertRaises(runs.RunError):guard.check(self.run)
            guard.descriptor=saved;errors=[]
            def worker():
                try:guard.check(self.run)
                except runs.RunError as error:errors.append(error.code)
            thread=threading.Thread(target=worker);thread.start();thread.join(3)
            self.assertEqual(errors,['run_lock_required'])

    @unittest.skipUnless(sys.platform.startswith('linux'),'Actual fork/flock requires Linux')
    def test_inherited_guard_cannot_authorize_child_and_stable_inode_survives_release(self):
        with self.run.locked() as guard:
            inode=self.run.file('operation.lock').stat().st_ino
            child=os.fork()
            if child==0:
                try:guard.check(self.run)
                except runs.RunError:os._exit(0)
                os._exit(8)
            _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        with self.run.locked() as guard:self.assertEqual(self.run.file('operation.lock').stat().st_ino,inode)


if __name__=='__main__':unittest.main()
