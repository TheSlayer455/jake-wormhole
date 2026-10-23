"""Synthetic orchestration/capture fixtures; no actual host/container allocation."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
import os
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import recovery_acceptance as a, recovery as r, images
from wormhole.runs import atomic_json, common, now, read_json
import test_provisioning as fixture


class Boundaries(unittest.TestCase):
    def test_invalid_requests_cannot_create_a_run_or_launch_a_worker(self):
        with patch.object(a, '_fresh') as fresh, patch.object(a, 'source_identity', return_value=(fixture.SHA, False)):
            for scenario, sentinel in (('arbitrary', 'e' * 64), ('normal', '../unsafe'), ('normal', None)):
                with self.assertRaises(r.RecoveryError): a.qualify_case(scenario, sentinel)
            fresh.assert_not_called()

    @unittest.skipUnless(hasattr(signal, 'SIGKILL'), 'Owned-coordinator SIGKILL acceptance is Linux only; process handle is mocked')
    def test_owned_worker_is_killed_only_after_proof_and_never_from_stored_pid(self):
        process = Mock(pid=123)
        process.poll.return_value = None; process.wait.return_value = -signal.SIGKILL
        run = Mock(); run.file.return_value.stat.return_value.st_size = 0
        with patch.object(a, '_checkpoint_proof', side_effect=r.RecoveryError('unproven', 'Synthetic unproven checkpoint')):
            with self.assertRaises(r.RecoveryError): a._interrupt_owned_worker(process, run)
            process.kill.assert_not_called()
        events = []
        process.kill.side_effect = lambda: events.append('kill-owned-handle')
        with patch.object(a, '_checkpoint_proof', side_effect=lambda run, pid: events.append('proof') or {'status': 'pass'}):
            value = a._interrupt_owned_worker(process, run)
        self.assertEqual(events, ['proof', 'kill-owned-handle'])
        self.assertFalse(value['docker_cli_killed'])
        process.wait.assert_called_once_with(timeout=5)


@unittest.skipUnless(os.name == 'posix', 'Real-controller temporary fixtures; every Docker/Terraform operation mocked')
class Controller(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Controller('test_actual_workflow_policy_orders_pid_and_inspection_before_start_then_provider_refresh_destroy')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.run, self.session, self.lease = self.f.run, self.f.session, self.f.lease
        self.lease.finish = Mock()
        self.root = patch.object(images, 'RUNS_ROOT', self.run.workspace); self.root.start(); self.addCleanup(self.root.stop)

    def harness(self):
        from contextlib import ExitStack
        stack = ExitStack(); stack.enter_context(self.f.patches())
        stack.enter_context(patch.object(a, '_fresh', return_value=self.run))
        stack.enter_context(patch.object(images, 'docker_scope', return_value=nullcontext()))
        stack.enter_context(patch.object(a, 'AdmissionLease', return_value=nullcontext(self.lease)))
        stack.enter_context(patch.object(a, 'ProvisioningSession', return_value=self.session))
        stack.enter_context(patch.object(a, 'snapshot', return_value='synthetic-stable-sentinel-fingerprint'))
        stack.enter_context(patch.object(a, 'scan_private_material', return_value={'status': 'pass', 'synthetic': True}))
        stack.enter_context(patch.object(a, 'disk_sample', return_value={'synthetic': True, 'logical_file_bytes': 0}))
        stack.enter_context(patch.object(a, 'infrastructure_status', side_effect=lambda _: {'admission': {
            'run_id': self.run.id, 'source_revision': fixture.SHA, 'state': 'finished', 'resources': self.lease.record['resources']}}))
        return stack

    def test_normal_case_uses_product_cleanup_preserves_artifacts_and_finishes_only_after_absence(self):
        with self.harness(): value = a._case('normal', 'e' * 64)
        self.assertEqual(value['status'], 'pass')
        self.assertTrue(value['checks']['cleanup']['unrelated_sentinel_unchanged'])
        self.assertEqual(read_json(self.run.file('evidence/cleanup.json'))['status'], 'completed')
        self.lease.finish.assert_called_once_with(reconciliation_complete=True)
        self.assertTrue(self.session.state.exists())

    def test_actual_fixed_nonzero_check_and_secondary_ack_fault_preserve_original_failure(self):
        original = self.f.operation
        def after_destroy(name):
            if fixture.CID in self.f.removed and fixture.NET in self.f.removed:
                if name in ('show-state', 'final-state'): return {'values': {'root_module': {'resources': []}}}
                if name == 'show-destroy-plan': return {'format_version': '1.2', 'terraform_version': '1.17.0', 'resource_changes': []}
            return original(name)
        result = {'status': 'fail', 'returncode': 17, 'log': a.EXPECTED_CHECK, 'log_truncated': False}
        with self.harness(), patch.object(self.session, 'operation', side_effect=after_destroy), \
             patch.object(images, 'docker_configuration', return_value='/synthetic/config'), patch.object(a, '_run_process', return_value=result) as execute:
            value = a._case('functional-failure', 'e' * 64)
        self.assertEqual(value['status'], 'pass')
        self.assertEqual(value['checks']['cleanup']['primary_failure'], 'controlled_functional_failure')
        self.assertTrue(value['checks']['secondary_cleanup_failure']['original_primary_retained'])
        self.assertEqual(execute.call_args.args[0][-1], 'import sys;print("WORM-008 controlled functional check failure");sys.exit(17)')
        attempts = [read_json(x) for x in self.run.file('evidence/cleanup-attempts').iterdir()]
        self.assertEqual({x['status'] for x in attempts}, {'failed', 'completed'})

    def test_unknown_check_does_not_turn_into_known_failure_or_cleanup_permission(self):
        with self.harness(): self.session.provision()
        with self.f.patches(), patch.object(images, 'docker_configuration', return_value='/synthetic/config'), \
             patch.object(a, '_run_process', return_value={'status': 'timeout', 'returncode': -9, 'log': b'', 'log_truncated': False}):
            with self.assertRaises(r.RecoveryError): a._functional_failure(self.session)
        self.assertTrue(self.session.receipt['unknown_outcome'])
        self.assertFalse(self.f.removed)

    def test_unexpected_unknown_case_preserves_resources_and_never_finishes_admission(self):
        with self.harness(), patch.object(images, 'docker_configuration', return_value='/synthetic/config'), \
             patch.object(a, '_run_process', return_value={'status': 'timeout', 'returncode': -9, 'log': b'', 'log_truncated': False}):
            with self.assertRaises(r.RecoveryError): a._case('functional-failure', 'e' * 64)
        self.assertTrue(self.session.receipt['unknown_outcome'])
        self.assertFalse(self.f.removed)
        self.lease.finish.assert_not_called()
        self.assertFalse(read_json(self.run.file('evidence/recovery-acceptance.json'))['cleanup_claimed'])

    def test_cancel_uses_separate_cli_under_held_lock_then_safe_poll_and_helper_cleanup(self):
        run, lease = self.run, self.lease
        class Helper:
            def __init__(self, provisioning):
                self.run, self.lease, self.helper = run, lease, 'e' * 64
                self.deadline = a.time.monotonic() + 90
                self.receipt = {**common(run.manifest()), 'primary_failure': None, 'unknown_outcome': False}
            def start_helper(self): lease.register_resource('container', self.helper)
            def wait_ready(self, *, on_poll):
                for _ in range(100):
                    try: on_poll(0)
                    except r.RecoveryError as error:
                        self.receipt['primary_failure'] = {'code': error.code, 'recorded_at': now()}; raise
                    a.time.sleep(.001)
                raise AssertionError('Synthetic cancellation was not polled')
            def cleanup(self): lease.reconcile_resource('container', self.helper)
        def cancel(arguments, **kwargs):
            self.assertEqual(arguments[:5], (a.sys.executable, '-B', '-m', 'wormhole', 'cancel'))
            self.assertTrue(run.file('.lock').exists(), 'The coordinator must retain its run lock')
            r.request_cancel(run)
            return {'status': 'pass', 'returncode': 0, 'log': b'bounded synthetic CLI response', 'log_truncated': False}
        with self.harness(), patch.dict(a.sys.modules, {'wormhole.readiness': SimpleNamespace(ReadinessSession=Helper)}), \
             patch.object(a, '_run_process', side_effect=cancel):
            value = a._case('cancelled', 'e' * 64)
        self.assertEqual(value['status'], 'pass')
        self.assertEqual(value['checks']['cleanup']['primary_failure'], 'cancelled')
        self.assertFalse(value['checks']['cancellation']['docker_cli_killed'])
        self.assertTrue(self.run.file('cancel-request.json').exists())

    def _terminal_checkpoint(self):
        with self.f.patches(): self.session.provision()
        folder = self.session.state / 'operations'; folder.mkdir(mode=0o700)
        captures = []
        for operation, raw in (('destroy', b'Synthetic complete saved destroy'), ('final-state', b'{"values":{"root_module":{"resources":[]}}}')):
            stem = folder / (operation + '-1'); stem.with_suffix('.out').write_bytes(raw); stem.with_suffix('.out').chmod(0o600)
            record = {'operation': operation, 'attempt': 1, 'returncode': 0, 'duration_seconds': .01,
                'output_bytes': len(raw), 'output_sha256': hashlib.sha256(raw).hexdigest(), 'truncated': False, 'timed_out': False, 'passed': True}
            atomic_json(stem.with_suffix('.json'), record)
            captures.append({**record, 'client_status': 'pass', 'client_returncode': 0, 'client_log_truncated': False,
                'evidence': 'private/terraform/operations/' + stem.name + '.out'})
        self.session.receipt['operations'] = captures
        self.session.receipt['cleanup_progress'] = {'terraform_final_state_empty': True}
        self.session.save(); self.f.removed.update({fixture.CID, fixture.NET})
        atomic_json(self.run.file(a.CHECKPOINT), {**common(self.run.manifest()), 'operation': 'known-terminal-destroy-before-journal',
            'worker_pid': 123, 'provisioner_id': fixture.CONTROLLER, 'owned': deepcopy(self.session.owned), 'created_at': now()})
        return {**self.lease.record, 'run_id': self.run.id, 'source_revision': fixture.SHA}

    def test_checkpoint_requires_actual_absence_and_bound_terminal_results_before_owned_child_kill(self):
        journal = self._terminal_checkpoint()
        with self.f.patches(), patch.object(a, 'infrastructure_status', return_value={'admission': journal}):
            self.assertEqual(a._checkpoint_proof(self.run, 123)['status'], 'pass')
            with self.assertRaises(r.RecoveryError): a._checkpoint_proof(self.run, 124)
            self.f.removed.remove(fixture.CID)
            with self.assertRaises(r.RecoveryError): a._checkpoint_proof(self.run, 123)
            self.f.removed.add(fixture.CID)
            self.run.file('private/terraform/operations/final-state-1.out').write_bytes(b'changed capture')
            with self.assertRaises(r.RecoveryError): a._checkpoint_proof(self.run, 123)

    def test_parent_uses_normal_recovery_after_own_worker_proof_without_manual_state_or_journal_edits(self):
        atomic_json(self.run.file(a.CHECKPOINT), {'synthetic': True})
        process = Mock(pid=123); process.poll.return_value = None
        receipt = {'status': 'completed', 'unknown_outcome': False, 'primary_failure': {'code': 'controlled_teardown_interruption'}}
        with self.harness(), patch.object(a.subprocess, 'Popen', return_value=process) as launch, \
             patch.object(a, '_interrupt_owned_worker', return_value={'status': 'pass', 'docker_cli_killed': False}) as interrupt, \
             patch.object(a, 'recover_run', return_value=receipt) as recover:
            value = a._interrupted_case('e' * 64)
        interrupt.assert_called_once_with(process, self.run); recover.assert_called_once_with(self.run)
        self.assertEqual(launch.call_args.args[0], (a.sys.executable, '-B', '-m', 'wormhole.recovery_acceptance', '--worker-run', self.run.id))
        self.assertEqual(value['status'], 'pass')

    def test_uncheckpointed_child_failure_never_becomes_a_kill_or_cleanup_claim(self):
        process = Mock(pid=123); process.poll.return_value = 2
        with self.harness(), patch.object(a.subprocess, 'Popen', return_value=process), \
             patch.object(a, 'recover_run') as recover:
            with self.assertRaises(r.RecoveryError): a._interrupted_case('e' * 64)
        process.kill.assert_not_called(); recover.assert_not_called()
        result = read_json(self.run.file('evidence/recovery-acceptance.json'))
        self.assertEqual(result['status'], 'fail'); self.assertFalse(result['cleanup_claimed'])


if __name__ == '__main__': unittest.main()
