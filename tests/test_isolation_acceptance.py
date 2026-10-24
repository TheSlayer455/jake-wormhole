"""Synthetic allocation adapters; real disposable Linux locks and own forks.

No Docker, host capacity change, SSH or real publication is performed here.
Actual complete isolation qualification remains an operator-only operation.
"""
from contextlib import nullcontext
from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from wormhole import admission as a, isolation_acceptance as i, isolation_records as p, recovery
from wormhole.runs import RunError, atomic_bytes, atomic_json, common, create_run, read_json
from tests.test_admission import observed

SHA = 'a' * 40


@unittest.skipUnless(sys.platform.startswith('linux'), 'Real Linux Run/infrastructure locks and own-process fixtures')
class IsolationFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wormhole-isolation-synthetic-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.base.chmod(0o700)
        self.root, self.runs = self.base / 'infrastructure', self.base / 'runs'
        self.patch(i.images, 'RUNS_ROOT', self.runs)
        self.patch(i.images, 'INFRASTRUCTURE', self.root)
        self.patch(a, 'CANONICAL_INFRASTRUCTURE_ROOT', self.root)
        self.patch(i, 'source_identity', return_value=(SHA, False))
        self.patch(recovery, 'source_identity', return_value=(SHA, False))
        self.patch(i.images, 'docker', side_effect=AssertionError('Actual Docker is forbidden in synthetic fixtures'))
        self.patch(i.images, 'create_auth', side_effect=self.auth)
        self.patch(i, 'create_run', side_effect=lambda workspace, **kwargs:
                   create_run(workspace, identity=(SHA, False), **kwargs))
        self.suite = i.fresh(authentication=False)

    def patch(self, target, key, *args, **kwargs):
        item = patch.object(target, key, *args, **kwargs); value = item.start()
        self.addCleanup(item.stop); return value

    def auth(self, run):
        for name in ('id_ed25519', 'id_ed25519.pub'):
            atomic_bytes(run.file('private/credentials/' + name), ('SYNTHETIC UNUSABLE KEY ' + run.id + name).encode())
        atomic_json(run.file('private/credentials/auth.json'), {'synthetic': True, 'run_id': run.id})

    def function(self, name, count):
        def result(suite, _sentinel):
            ids = [str(uuid4()) for _ in range(count)]
            i.track(suite, name, ids)
            return ids, {'checks': {key: True for key in p.checks_for(name)}, 'synthetic_adapter': True}
        return result

    def test_coordinator_binds_each_exact_proof_and_complete_declared_grid(self):
        self.patch(i, 'fresh', return_value=self.suite)
        for name, function in zip(p.CASE_NAMES, ('overlap', 'interrupted_run', 'interrupted_publication', 'oversized_capacity')):
            self.patch(i, function, side_effect=self.function(name, p.CASE_RUN_COUNTS[name]))
        value = i.acceptance('f' * 64)
        self.assertEqual(value['status'], 'passed')
        self.assertEqual(read_json(self.suite.file(i.RECEIPT)), value)
        self.assertFalse(value['twenty_target_execution'])
        for row in value['cases']:
            raw = i.raw_file(self.suite.file(row['proof']['logical_path']))
            self.assertEqual(i.digest(raw), row['proof']['sha256'])
            self.assertEqual(len(raw), row['proof']['size_bytes'])
            self.assertEqual(json.loads(raw)['run_ids'], row['run_ids'])

    def test_partial_created_children_survive_unexpected_failure_with_controlled_suite_error(self):
        self.patch(i, 'fresh', return_value=self.suite)
        known = [str(uuid4()), str(uuid4())]
        def fail(suite, _sentinel):
            i.track(suite, 'overlap', known)
            error = ValueError('Synthetic private diagnostic must not escape')
            error.run_id = str(uuid4())
            raise error
        self.patch(i, 'overlap', side_effect=fail)
        next_case = self.patch(i, 'interrupted_run')
        with self.assertRaises(i.IsolationError) as caught:
            i.acceptance('f' * 64)
        value = read_json(self.suite.file(i.RECEIPT))
        self.assertEqual(caught.exception.suite_run_id, self.suite.id)
        self.assertEqual(value['status'], 'failed')
        self.assertEqual(value['cases'][0]['run_ids'][:2], known)
        self.assertEqual(value['cases'][0]['run_ids'][2], caught.exception.run_id)
        self.assertEqual(value['cases'][1]['status'], 'not-run')
        next_case.assert_not_called()
        self.assertNotIn('private diagnostic', str(caught.exception))

    def test_missing_supplied_check_refuses_before_the_next_case(self):
        self.patch(i, 'fresh', return_value=self.suite)
        def fail(suite, _sentinel):
            ids, proof = self.function('overlap', 3)(suite, _sentinel)
            del proof['checks']['distinct-authentication']
            return ids, proof
        self.patch(i, 'overlap', side_effect=fail)
        next_case = self.patch(i, 'interrupted_run')
        with self.assertRaises(i.IsolationError): i.acceptance('f' * 64)
        next_case.assert_not_called()
        self.assertEqual(read_json(self.suite.file(i.RECEIPT))['cases'][0]['status'], 'failed')

    def test_source_change_after_case_does_not_credit_or_start_next_allocation(self):
        self.patch(i, 'fresh', return_value=self.suite)
        def fail(suite, sentinel):
            result = self.function('overlap', 3)(suite, sentinel)
            i.source_identity.return_value = ('b' * 40, False)
            return result
        self.patch(i, 'overlap', side_effect=fail)
        later = self.patch(i, 'interrupted_run')
        with self.assertRaises(i.IsolationError) as caught: i.acceptance('f' * 64)
        self.assertEqual(caught.exception.code, 'isolation_source_changed')
        later.assert_not_called()
        self.assertEqual(len(read_json(self.suite.file(i.RECEIPT))['cases'][0]['run_ids']), 3)

    def test_synthetic_oversized_capacity_keeps_prior_archive_journal_and_sentinel(self):
        ids, proof = i.oversized_capacity(self.suite, 'f' * 64)
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(proof['checks'].values()))
        self.assertTrue(proof['synthetic'])
        self.assertFalse(proof['allocation_performed'])
        self.assertFalse(proof['twenty_target_execution'])
        self.assertEqual(proof['refusal_code'], 'capacity_refused')
        root = self.suite.file('private/isolation-capacity-fixture')
        self.assertEqual(read_json(root / 'admission.json')['run_id'], ids[0])
        self.assertFalse((root / 'history' / (ids[1] + '.json')).exists())
        self.assertFalse(self.root.exists())

    def fork_probe(self, run, role):
        process = os.fork()
        if process == 0:
            try:
                i._probe_worker(self.suite, run, role)
                os._exit(0)
            except BaseException:
                os._exit(1)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            waited, status = os.waitpid(process, os.WNOHANG)
            if waited:
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                return read_json(i.ipc(self.suite, 'workers', role))
            time.sleep(.01)
        os.kill(process, signal.SIGKILL)  # Own fixture worker forbids every Docker adapter.
        os.waitpid(process, 0)
        self.fail('Bounded local proof worker did not complete')

    def test_real_competing_process_refuses_pending_lease_without_collector_or_docker(self):
        owner, contender = i.fresh(), i.fresh()
        with a.AdmissionLease(self.root, owner.id, SHA, collector=lambda _: observed(), allow_synthetic=True) as lease:
            lease.set_phase('provisioning')
            lease.register_resource('container', '1' * 64)
            raw = i.raw_file(self.root / 'admission.json')
            value = self.fork_probe(contender, 'busy')
            self.assertEqual(value['refusal_code'], 'infrastructure_busy')
            self.assertEqual(value['collector_calls'], 0)
            self.assertEqual(value['docker_calls'], 0)
            self.assertEqual(i.raw_file(self.root / 'admission.json'), raw)
            self.assertFalse(contender.file('private/terraform/controller.json').exists())
            self.assertFalse(contender.file('inventory.json').exists())

    def test_both_real_recovery_guard_barriers_preserve_the_active_other_journal(self):
        first, second = i.fresh(), i.fresh()
        with a.AdmissionLease(self.root, second.id, SHA, collector=lambda _: observed(), allow_synthetic=True) as lease:
            lease.set_phase('provisioning'); lease.register_resource('container', '2' * 64)
            original = i.raw_file(self.root / 'admission.json')
            with first.locked():
                value = self.fork_probe(first, 'first-recovery')
                self.assertEqual(value['refusal_code'], 'run_busy')
            value = self.fork_probe(first, 'second-recovery')
            self.assertEqual(value['refusal_code'], 'infrastructure_busy')
            self.assertEqual(value['docker_calls'], 0)
            self.assertEqual(i.raw_file(self.root / 'admission.json'), original)

    def test_known_prebarrier_provision_failure_cleans_normally_but_unknown_never_does(self):
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                run = i.fresh(); error = i.IsolationError('synthetic_provision_failure', 'Synthetic fixed failure')
                session = SimpleNamespace(receipt={'unknown_outcome': unknown, 'primary_failure': None})
                session.provision = Mock(side_effect=error)
                session.failure = lambda e: session.receipt.update(primary_failure={'code': e.code, 'recorded_at': i.now()})
                lease = SimpleNamespace(finish=Mock(), record={'resources': []})
                cleanup = Mock(return_value={'status': 'completed', 'unknown_outcome': False})
                with patch.object(i.admission, 'AdmissionLease', return_value=nullcontext(lease)), \
                        patch.object(i, 'ProvisioningSession', return_value=session), patch.object(i, 'cleanup_session', cleanup):
                    with self.assertRaises(i.IsolationError) as caught: i._active_worker(self.suite, run, 'a')
                self.assertIs(caught.exception, error)
                if unknown:
                    cleanup.assert_not_called(); lease.finish.assert_not_called()
                else:
                    cleanup.assert_called_once(); lease.finish.assert_called_once_with(reconciliation_complete=True)
                self.assertEqual(read_json(i.ipc(self.suite, 'workers', 'a'))['phase'], 'failed')

    def test_invalid_terminal_checkpoint_never_kills_or_recovers_owned_worker(self):
        from wormhole import recovery_acceptance as old
        run, refused = i.fresh(), i.fresh()
        atomic_json(run.file(old.CHECKPOINT), {'synthetic': 'invalid checkpoint'})
        child = SimpleNamespace(process=SimpleNamespace(pid=12345, kill=Mock(), wait=Mock()), alive=Mock())
        with patch.object(i, 'case_runs', return_value=[run, refused]), patch.object(i, 'OwnedProcess', return_value=child), \
                patch.object(i, 'snapshot', return_value='synthetic-sentinel'), \
                patch.object(old, '_checkpoint_proof', side_effect=i.IsolationError('checkpoint_not_terminal', 'Synthetic refusal')), \
                patch.object(i, 'recover_run') as recover:
            with self.assertRaises(i.IsolationError): i.interrupted_run(self.suite, 'f' * 64)
        child.process.kill.assert_not_called(); recover.assert_not_called()

    def test_authentication_uniqueness_exports_only_boolean_and_reused_material_refuses(self):
        runs = [i.fresh() for _ in range(3)]
        self.assertIs(i.distinct_auth(runs), True)
        atomic_bytes(runs[1].file('private/credentials/id_ed25519'), i.raw_file(runs[0].file('private/credentials/id_ed25519')))
        with self.assertRaises(i.IsolationError): i.distinct_auth(runs)

    def test_control_cannot_cross_run_or_skip_the_fixed_order(self):
        run, other = i.fresh(), i.fresh()
        i.command(self.suite, run, 'a', 'cleanup', 1)
        i.await_command(self.suite, run, 'a', 'cleanup', 1, timeout=.1)
        with self.assertRaises(i.IsolationError): i.control(self.suite, other, 'a')
        i.command(self.suite, run, 'a', 'exit', 3)
        with self.assertRaises(i.IsolationError): i.await_command(self.suite, run, 'a', 'cleanup', 1, timeout=.1)

    def test_worker_proof_wrong_pid_or_run_cannot_authorize_an_active_barrier(self):
        run = i.fresh()
        proof = i.event(self.suite, run, 'a', 'active')
        fake = i.OwnedProcess.__new__(i.OwnedProcess)
        fake.suite, fake.run, fake.role = self.suite, run, 'a'
        fake.log = i.ipc(self.suite, 'logs', 'a'); atomic_bytes(fake.log, b'SYNTHETIC WORKER\n')
        fake.process = SimpleNamespace(pid=proof['pid'] + 1, poll=Mock(return_value=None))
        with self.assertRaises(i.IsolationError) as caught: fake.wait('active', timeout=.1)
        self.assertEqual(caught.exception.code, 'isolation_worker_identity')


class InputGuards(unittest.TestCase):
    def test_nonlinux_refuses_before_any_run_creation(self):
        with patch.object(i.sys, 'platform', 'win32'), patch.object(i, 'fresh') as fresh:
            with self.assertRaises(i.IsolationError): i.acceptance('f' * 64)
            fresh.assert_not_called()

    def test_worker_rejects_arbitrary_role_and_paths_before_loading_runs(self):
        with patch.object(i, 'Run') as load:
            for role in ('shell', '', '../a'):
                with self.subTest(role=role), self.assertRaises(i.IsolationError):
                    i.worker(role, '../suite', '../target')
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
