"""Disposable real Linux flock/crash fixtures; never recover production locks."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

from wormhole.runs import SOURCE_ROOT, RunError, atomic_bytes, atomic_json, create_run


@unittest.skipUnless(sys.platform.startswith('linux'), 'Stable real-run flock requires Linux')
class KernelRunLock(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.run = create_run(self.root / 'runs', fixture=False, identity=('a' * 40, False), kernel_lock=True)

    def test_competing_process_crash_releases_same_inode_without_deleting_lock(self):
        source = '''import sys,time
from wormhole.runs import Run
run=Run(sys.argv[1],sys.argv[2])
with run.locked():
 print('LOCKED',flush=True)
 time.sleep(30)
'''
        child = subprocess.Popen([sys.executable, '-B', '-c', source, str(self.run.workspace), self.run.id],
                                 cwd=SOURCE_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 10)[0], 'Lock holder did not report readiness')
            self.assertEqual(child.stdout.readline().strip(), 'LOCKED')
            lock = self.run.file('operation.lock')
            inode = (lock.stat().st_dev, lock.stat().st_ino)
            with self.assertRaises(RunError) as denied:
                with self.run.locked(): self.fail('Competing writer acquired the lock')
            self.assertEqual(denied.exception.code, 'run_busy')
            policy = self.run.file('lock-policy.json')
            original_policy = policy.read_bytes()
            policy.unlink()  # Disposable corruption fixture; holder is still live.
            with self.assertRaises(RunError) as denied:
                with self.run.locked(): self.fail('Missing policy downgraded to a legacy lock')
            self.assertEqual(denied.exception.code, 'invalid_lock_policy')
            self.assertFalse(self.run.file('.lock').exists())
            atomic_bytes(policy, original_policy)
            child.kill(); child.wait(timeout=5)
            with self.run.locked():
                self.assertEqual((lock.stat().st_dev, lock.stat().st_ino), inode)
            self.assertEqual((lock.stat().st_dev, lock.stat().st_ino), inode)
            self.assertFalse(self.run.file('.lock').exists())
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=5)
            child.stdout.close(); child.stderr.close()

    def test_legacy_residue_is_preserved_even_with_kernel_policy(self):
        legacy = self.run.file('.lock')
        atomic_bytes(legacy, b'999999999')
        with self.assertRaises(RunError) as denied:
            with self.run.locked(): self.fail('Legacy residue was ignored')
        self.assertEqual(denied.exception.code, 'run_busy')
        self.assertEqual(legacy.read_bytes(), b'999999999')
        self.assertFalse(self.run.file('operation.lock').exists())

    def test_linked_lock_or_wrong_policy_cannot_authorize_a_writer(self):
        lock = self.run.file('operation.lock')
        external = self.root / 'preserve'
        atomic_bytes(external, b'unrelated fixture')
        lock.symlink_to(external)
        with self.assertRaises(RunError):
            with self.run.locked(): self.fail('Symlink accepted')
        lock.unlink()  # Only this disposable fixture link.
        os.link(external, lock)
        with self.assertRaises(RunError):
            with self.run.locked(): self.fail('Hard link accepted')
        self.assertEqual(external.read_bytes(), b'unrelated fixture')
        atomic_json(self.run.file('lock-policy.json'), {'schema_version': '1.0', 'run_id': self.run.id, 'kind': 'unlocked'})
        with self.assertRaises(RunError):
            with self.run.locked(): self.fail('Unknown policy accepted')


class LockPolicySelection(unittest.TestCase):
    def test_fixture_policy_stays_legacy_and_new_kernel_fixture_is_refused_before_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run = create_run(root / 'runs', fixture=True, identity=('a' * 40, False))
            with run.locked(): self.assertTrue(run.file('.lock').exists())
            self.assertFalse(run.file('.lock').exists())
            self.assertFalse(run.file('lock-policy.json').exists())
            with self.assertRaises(RunError):
                create_run(root / 'refused', fixture=True, identity=('a' * 40, False), kernel_lock=True)
            self.assertFalse((root / 'refused').exists())


if __name__ == '__main__': unittest.main()
