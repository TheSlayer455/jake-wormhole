"""Local synthetic APIs and disposable Git/process/ordinary-file boundaries only."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wormhole import parity as p
from wormhole import parity_records as records

REVISION = 'a' * 40


@contextmanager
def synthetic_source():
    # Explicitly synthetic source attribution for direct API tests. Actual child
    # CLI tests below use a new ordinary clean Git commit and no identity mocks.
    with ExitStack() as stack:
        for module in (p, p.chunks, p.assessments):
            stack.enter_context(patch.object(module, 'source_identity', return_value=(REVISION, False)))
        yield


class ParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        with synthetic_source():
            cls.result = p.run_parity(cls.root / 'initial')
        cls.files = p.read_export_files(cls.root / 'initial')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_all_native_cases_and_original_fingerprints(self):
        self.assertEqual(self.result['exit_code'], 0)
        self.assertEqual(self.result['passed_cases'], 17)
        result = json.loads(self.files['results.json'])
        execution = json.loads(self.files['execution.json'])
        self.assertEqual(len(set(execution['case_run_ids'])), 17)
        self.assertTrue(all(row['plan_sha256'] and row['receipt_sha256'] for row in execution['original_records']))
        self.assertTrue(all(row['cleanup'] == {'status': 'completed', 'private_removed': True} for row in result['cases']))
        self.assertEqual([row['actual_status'] for row in result['cases'][-5:]], ['passed', 'rejected', 'failed', 'failed', 'failed'])
        self.assertEqual(result['cases'][0]['details']['output_sha256'], result['cases'][0]['details']['input_sha256'])
        self.assertEqual([row['size'] for row in result['cases'][0]['details']['checked_chunks']], [65536] * 4 + [37])
        self.assertEqual(result['cases'][-4]['details']['counts']['Open'], 1)
        self.assertFalse(result['reference_eligible'])
        self.assertEqual(execution['exit_code_kind'], 'computed-runner-return-code')
        self.assertTrue(all(row['exit_code_kind'] == 'domain-cli-contract-mapping' for row in result['cases']))

    def test_two_fresh_runs_have_equal_normalized_semantics(self):
        with tempfile.TemporaryDirectory() as folder, synthetic_source():
            p.run_parity(Path(folder) / 'next')
            second = p.read_export_files(Path(folder) / 'next')
        for name in ('plan.json', 'results.json', 'decision.json'):
            self.assertEqual(second[name], self.files[name])
        self.assertNotEqual(json.loads(second['execution.json'])['case_run_ids'], json.loads(self.files['execution.json'])['case_run_ids'])

    def test_required_failure_and_unexpected_success_remain_failed(self):
        for mode, case, actual in (('required-failure', 'assessment-reject', 'rejected'),
                                   ('unexpected-success', 'assessment-pass', 'passed')):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder, synthetic_source():
                result = p.run_parity(Path(folder) / 'negative', mode)
                files = p.read_export_files(Path(folder) / 'negative')
                row = next(item for item in json.loads(files['results.json'])['cases'] if item['case_id'] == case)
                self.assertEqual((result['exit_code'], row['actual_status'], row['status']), (1, actual, 'failed'))
                self.assertEqual(result['cleanup'], {'status': 'completed', 'private_removed': True})
                self.assertEqual(records.validate_exports(files)['decision_status'], 'failed')

    def test_source_change_preserves_full_unattempted_grid(self):
        with tempfile.TemporaryDirectory() as folder, synthetic_source(), patch.object(p, 'source_identity',
                side_effect=[(REVISION, False), (REVISION, False), ('b' * 40, False)]):
            result = p.run_parity(Path(folder) / 'failed')
            rows = json.loads(p.read_export_files(Path(folder) / 'failed')['results.json'])['cases']
        self.assertEqual(result['primary_failure']['code'], 'parity_source_changed')
        self.assertEqual(len(rows), 17)
        self.assertEqual(rows[0]['status'], 'passed')
        self.assertTrue(all(row['status'] == 'not-run' for row in rows[1:]))
        self.assertTrue(result['cleanup']['private_removed'])

    def test_early_operation_failure_is_not_expected_negative_success(self):
        with tempfile.TemporaryDirectory() as folder, synthetic_source(), patch.object(p.chunks, 'execute_fixture',
                side_effect=p.ParityError('synthetic_operation_refused', 'Fixture refuses before execution.')):
            result = p.run_parity(Path(folder) / 'failed')
            rows = json.loads(p.read_export_files(Path(folder) / 'failed')['results.json'])['cases']
        self.assertEqual(result['primary_failure']['code'], 'synthetic_operation_refused')
        self.assertTrue(all(row['status'] == 'failed' for row in rows[:12]))
        self.assertTrue(all(row['details']['output_sha256'] is None for row in rows[:12]))
        self.assertTrue(result['cleanup']['private_removed'])

    def test_assessment_report_refusal_keeps_actual_native_outcome(self):
        with tempfile.TemporaryDirectory() as folder, synthetic_source(), patch.object(p.assessments, 'report_assessment',
                side_effect=p.ParityError('synthetic_replay_refused', 'Fixture refuses original replay.')):
            result = p.run_parity(Path(folder) / 'failed')
            rows = json.loads(p.read_export_files(Path(folder) / 'failed')['results.json'])['cases'][-5:]
        self.assertEqual(result['primary_failure']['code'], 'synthetic_replay_refused')
        self.assertEqual([row['actual_status'] for row in rows], ['passed', 'rejected', 'failed', 'failed', 'failed'])
        self.assertTrue(all(row['status'] == 'failed' and row['checks'][1]['status'] == 'fail' for row in rows))

    def test_cleanup_failure_retains_private_area_and_fails_every_attempt(self):
        made = []
        original = p.PrivateFixtures
        def create(revision, **options):
            area = original(revision, **options); made.append(area); return area
        try:
            with tempfile.TemporaryDirectory() as folder, synthetic_source(), patch.object(p, 'PrivateFixtures', side_effect=create), \
                    patch.object(original, 'cleanup', side_effect=p.ParityError('synthetic_cleanup_refused', 'Synthetic cleanup refusal.')):
                result = p.run_parity(Path(folder) / 'failed')
                rows = json.loads(p.read_export_files(Path(folder) / 'failed')['results.json'])['cases']
            self.assertTrue(made[0].path.exists())
            self.assertEqual(result['primary_failure']['code'], 'synthetic_cleanup_refused')
            self.assertFalse(result['cleanup']['private_removed'])
            self.assertTrue(all(row['status'] == 'failed' and row['checks'][-1]['status'] == 'fail' for row in rows))
        finally:
            for area in made:
                original.cleanup(area)

    def test_partial_private_setup_cannot_claim_cleanup_completed(self):
        made = []
        original = p.PrivateFixtures
        def create(revision, **options):
            area = original(revision, **options); made.append(area); return area
        try:
            with tempfile.TemporaryDirectory() as folder, synthetic_source(), patch.object(p, 'PrivateFixtures', side_effect=create), \
                    patch.object(p, 'atomic_json', side_effect=OSError('Synthetic marker write failure.')):
                result = p.run_parity(Path(folder) / 'failed')
                rows = json.loads(p.read_export_files(Path(folder) / 'failed')['results.json'])['cases']
            self.assertTrue(made[0].path.exists())
            self.assertEqual(result['primary_failure']['code'], 'parity_operation_failed')
            self.assertEqual(result['cleanup'], {'status': 'failed', 'private_removed': False})
            self.assertTrue(all(row['status'] == 'not-run' for row in rows))
        finally:
            for area in made:
                p.atomic_json(area.path / 'owner.json', area.marker); area.cleanup()

    def test_fresh_export_only_and_exact_original_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'safe'
            p.write_export_files(output, self.files)
            self.assertEqual(p.read_export_files(output), self.files)
            with self.assertRaises(p.ParityError): p.write_export_files(output, self.files)
            (output / 'unexpected.json').write_bytes(b'{}')
            with self.assertRaises(p.ParityError): p.read_export_files(output)

    def test_invalid_export_never_creates_destination(self):
        files = dict(self.files); files['decision.json'] = b'{}\n'
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'safe'
            with self.assertRaises(p.RunError): p.write_export_files(output, files)
            self.assertFalse(output.exists())

    def test_dirty_source_refuses_before_private_state_or_exports(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(p, 'source_identity', return_value=(REVISION, True)), \
                patch.object(p, 'PrivateFixtures') as allocate:
            output = Path(folder) / 'safe'
            with self.assertRaises(p.ParityError) as failure: p.run_parity(output)
            self.assertEqual(failure.exception.code, 'parity_source_dirty')
            allocate.assert_not_called()
            self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX ordinary-file and descriptor race fixtures')
    def test_export_hardlink_symlink_and_oversize_refuse(self):
        for kind in ('hardlink', 'symlink', 'oversize'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                output = Path(folder) / 'safe'; p.write_export_files(output, self.files)
                victim = output / 'plan.json'
                outside = Path(folder) / 'outside'; outside.write_bytes(b'untouched'); outside.chmod(0o600)
                victim.unlink()
                if kind == 'hardlink': os.link(outside, victim)
                elif kind == 'symlink': victim.symlink_to(outside)
                else: victim.write_bytes(b'x' * (p.MAX_FILE + 1)); victim.chmod(0o600)
                with self.assertRaises(p.RunError): p.read_export_files(output)
                self.assertEqual(outside.read_bytes(), b'untouched')

    @unittest.skipUnless(os.name == 'posix', 'POSIX held descriptor rename fixture')
    def test_parent_replacement_after_mkdir_refuses_without_adopting(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder) / 'parent'; parent.mkdir(mode=0o700)
            old = Path(folder) / 'old'; target = parent / 'safe'
            mkdir = os.mkdir
            def swap(name, *args, **kwargs):
                value = mkdir(name, *args, **kwargs)
                if name == 'safe':
                    parent.rename(old); mkdir(parent, 0o700); mkdir(target, 0o700)
                    (target / 'unrelated.txt').write_bytes(b'keep')
                return value
            with patch.object(p.os, 'mkdir', side_effect=swap), self.assertRaises(p.ParityError):
                p.write_export_files(target, self.files)
            self.assertEqual([item.name for item in target.iterdir()], ['unrelated.txt'])
            self.assertEqual(list((old / 'safe').iterdir()), [])

    @unittest.skipUnless(os.name == 'posix', 'POSIX child fd/name replacement fixture')
    def test_destination_rename_during_write_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'safe'; old = Path(folder) / 'old'
            actual_open = os.open; changed = False
            def swap(name, flags, *args, **kwargs):
                nonlocal changed
                fd = actual_open(name, flags, *args, **kwargs)
                if name == 'plan.json' and flags & os.O_CREAT and not changed:
                    changed = True; output.rename(old); output.mkdir(mode=0o700)
                return fd
            with patch.object(p.os, 'open', side_effect=swap), self.assertRaises(p.ParityError):
                p.write_export_files(output, self.files)
            self.assertEqual(list(output.iterdir()), [])
            self.assertFalse((old / 'results.json').exists())

    def test_cleanup_unknown_child_refuses_and_preserves_sentinel(self):
        area = p.PrivateFixtures(REVISION)
        try:
            sentinel = area.path / 'unrelated'; sentinel.write_bytes(b'keep'); sentinel.chmod(0o600)
            with self.assertRaises(p.ParityError): area.cleanup()
            self.assertEqual(sentinel.read_bytes(), b'keep')
            sentinel.unlink()
        finally:
            area.cleanup()

    def test_cleanup_replaced_marker_refuses(self):
        area = p.PrivateFixtures(REVISION)
        try:
            p.atomic_json(area.path / 'owner.json', {**area.marker, 'source_revision': 'b' * 40})
            with self.assertRaises(p.ParityError): area.cleanup()
            self.assertTrue(area.path.exists())
        finally:
            p.atomic_json(area.path / 'owner.json', area.marker); area.cleanup()

    def test_cleanup_replaced_root_never_deletes_foreign_directory(self):
        area = p.PrivateFixtures(REVISION)
        old = area.path.with_name(area.path.name + '-saved')
        try:
            area.path.rename(old); area.path.mkdir(mode=0o700)
            sentinel = area.path / 'unrelated'; sentinel.write_bytes(b'keep')
            with self.assertRaises(p.ParityError): area.cleanup()
            self.assertEqual(sentinel.read_bytes(), b'keep')
        finally:
            # Restore only this test's own empty replacement and exact saved tree.
            (area.path / 'unrelated').unlink(); area.path.rmdir(); old.rename(area.path); area.cleanup()


class ParityProcessTests(unittest.TestCase):
    def test_real_cli_exits_match_computed_metadata_in_disposable_git(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'fixture'; (root / 'wormhole').mkdir(parents=True)
            for name in ('__init__', 'parity', 'parity_records', 'chunks', 'assessments', 'runs', 'contracts'):
                source = Path(records.__file__) if name == 'parity_records' else p.SOURCE_ROOT / 'wormhole' / (name + '.py')
                shutil.copyfile(source, root / 'wormhole' / (name + '.py'))
            (root / '.gitignore').write_text('/ci-safe/\n/ci-artifacts/\n__pycache__/\n', encoding='utf-8')
            for args in (('init',), ('config', 'user.name', 'Synthetic fixture'), ('config', 'user.email', 'synthetic@example.invalid'),
                         ('add', '.'), ('commit', '-m', 'Disposable synthetic parity fixture')):
                subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, timeout=15)
            environment = dict(os.environ)
            for key in tuple(environment):
                if key.startswith(('GITHUB_', 'RUNNER_')) or key == 'GITLAB_CI': del environment[key]
            for mode, code in (('all', 0), ('required-failure', 1), ('unexpected-success', 1)):
                command = [sys.executable, '-B', '-m', 'wormhole.parity']
                process = subprocess.run([*command, 'run', '--output', 'ci-safe', '--mode', mode], cwd=root,
                    env=environment, capture_output=True, timeout=60)
                self.assertEqual(process.returncode, code, process.stdout.decode() + process.stderr.decode())
                files = p.read_export_files(root / 'ci-safe')
                self.assertEqual(json.loads(files['execution.json'])['exit_code'], process.returncode)
                self.assertEqual(json.loads(files['decision.json'])['exit_code'], process.returncode)
                check = subprocess.run([*command, 'validate', '--output', 'ci-safe'], cwd=root,
                    env=environment, capture_output=True, timeout=15)
                self.assertEqual(check.returncode, 0, check.stdout.decode() + check.stderr.decode())
                self.assertEqual(json.loads(check.stdout)['decision_status'], 'passed' if code == 0 else 'failed')
                shutil.rmtree(root / 'ci-safe')  # Exact disposable test-owned output, never caller state.


if __name__ == '__main__':
    unittest.main()
