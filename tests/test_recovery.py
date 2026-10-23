"""Owned temporary-state fixtures; no actual Docker/Terraform execution."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from copy import deepcopy
import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from wormhole import recovery as r, provisioning as p, images
from wormhole.runs import create_run, atomic_json, read_json, now, RunError
import test_provisioning as fixture


class LocalRecords(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='wormhole-cancel-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.run = create_run(Path(self.temporary.name) / 'runs', fixture=True, identity=(fixture.SHA, False))

    def test_cancel_is_atomic_idempotent_and_does_not_steal_the_live_run_lock(self):
        with self.run.locked():
            with ThreadPoolExecutor(max_workers=4) as executor:
                requests = list(executor.map(lambda _: r.request_cancel(self.run), range(12)))
            self.assertEqual(len({x['request_id'] for x in requests}), 1)
            self.assertTrue(r.cancellation_requested(self.run))
            self.assertTrue(self.run.file('.lock').exists())
            self.assertEqual(self.run.manifest()['outcome'], 'running')
        self.assertFalse(any(x.name.startswith('.cancel-') for x in self.run.path.iterdir()))
        self.assertEqual(r.inspect_recovery(self.run)['cancellation'], requests[0])

    def test_malformed_or_wrong_run_cancel_never_becomes_an_execution_instruction(self):
        value = r.request_cancel(self.run)
        for key, wrong in (('source_revision', 'b' * 40), ('run_id', '12345678-1234-4234-9234-123456789abc'),
                           ('reason', 'run arbitrary command'), ('request_id', '../unsafe')):
            bad = {**value, key: wrong}; atomic_json(self.run.file('cancel-request.json'), bad)
            with self.subTest(field=key), self.assertRaises(r.RecoveryError): r.cancellation_requested(self.run)

    def test_published_cleanup_schema_matches_source_definitions(self):
        source = Path(r.__file__).resolve().parents[1] / 'schemas/cleanup-v1.schema.json'
        self.assertEqual(json.loads(source.read_text()), r.cleanup_schema())


@unittest.skipUnless(os.name == 'posix', 'Linux cleanup-controller fixtures; all Docker/Terraform calls mocked')
class Cleanup(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Controller('test_actual_workflow_policy_orders_pid_and_inspection_before_start_then_provider_refresh_destroy')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.run, self.session, self.lease = self.f.run, self.f.session, self.f.lease
        self.canonical = patch.object(images, 'RUNS_ROOT', self.run.workspace); self.canonical.start(); self.addCleanup(self.canonical.stop)

    def test_normal_cleanup_accounts_every_id_preserves_private_state_and_has_readable_same_outcome(self):
        with self.f.patches():
            self.session.provision()
            value = r.cleanup_session(self.session, self.lease)
        self.assertEqual(value['status'], 'completed')
        self.assertIsNone(value['primary_failure'])
        self.assertTrue(all(x['disposition'] == 'absent' for x in value['resources']))
        self.assertTrue(self.session.state.exists())
        self.assertEqual(read_json(self.run.file('evidence/cleanup.json')), value)
        self.assertEqual(read_json(self.run.file('evidence/cleanup-attempts/' + value['attempt_id'] + '.json')), value)
        self.assertIn('cleanup completed', r.readable_cleanup(value))
        self.assertEqual(r.inspect_recovery(self.run)['cleanup'], value)
        self.assertFalse(value['production_iso_eligible'])
        for mutate in (lambda x: x.update(arbitrary='unknown'), lambda x: x.update(production_iso_eligible=True),
                       lambda x: x['resources'].append(deepcopy(x['resources'][0])),
                       lambda x: x['resources'][0].update(disposition='pending'),
                       lambda x: x['resources'][0].update(id='../unsafe')):
            bad = deepcopy(value); mutate(bad)
            with self.assertRaises(r.RecoveryError): r.validate_cleanup(bad)

    def test_primary_failure_survives_helper_cleanup_error_and_target_teardown_does_not_run(self):
        with self.f.patches():
            self.session.provision()
            primary = {'code': 'functional_check_failed', 'recorded_at': now()}
            self.session.receipt['primary_failure'] = deepcopy(primary)
            helper = Mock(run=self.run, lease=self.lease, receipt={})
            helper.cleanup.side_effect = RunError('helper_cleanup_failed', 'Sensitive synthetic detail must not be exported')
            with patch.object(self.session, 'destroy') as destroy:
                value = r.cleanup_session(self.session, self.lease, reason='failure', helper=helper)
                destroy.assert_not_called()
        self.assertEqual(value['status'], 'failed')
        self.assertEqual(value['primary_failure'], primary)
        self.assertEqual(self.session.receipt['primary_failure'], primary)
        self.assertEqual(value['secondary_failures'][0]['code'], 'helper_cleanup_failed')
        self.assertNotIn('Sensitive synthetic', json.dumps(value))
        self.assertIn('functional_check_failed', r.readable_cleanup(value))
        self.assertIn('helper_cleanup_failed', r.readable_cleanup(value))

    def test_cancellation_is_acknowledged_as_failure_and_cleanup_does_not_accept_deliverable(self):
        with self.f.patches():
            self.session.provision(); r.request_cancel(self.run)
            value = r.cleanup_session(self.session, self.lease, reason='cancelled')
        self.assertEqual(value['status'], 'completed')
        self.assertEqual(value['primary_failure']['code'], 'cancelled')
        self.assertEqual(self.session.receipt['status'], 'failed')
        self.assertTrue(self.run.file('cancel-request.json').exists())

    def test_unknown_allocation_blocks_native_or_terraform_cleanup_and_remains_visible(self):
        with self.f.patches(): self.session.provision()
        self.session.receipt['unknown_outcome'] = True
        with patch.object(self.session, 'destroy') as destroy:
            value = r.cleanup_session(self.session, self.lease, reason='failure')
            destroy.assert_not_called()
        self.assertEqual(value['status'], 'blocked')
        self.assertTrue(value['unknown_outcome'])
        self.assertTrue(all(x['disposition'] == 'unknown' for x in value['resources']))

    def test_helper_primary_and_uncertain_outcome_are_not_lost_at_component_boundary(self):
        with self.f.patches(): self.session.provision()
        primary = {'code': 'readiness_failed', 'recorded_at': now()}
        helper = Mock(run=self.run, lease=self.lease, receipt={'primary_failure': primary, 'unknown_outcome': True})
        with patch.object(self.session, 'destroy') as destroy:
            value = r.cleanup_session(self.session, self.lease, reason='failure', helper=helper)
            destroy.assert_not_called(); helper.cleanup.assert_not_called()
        self.assertEqual(value['primary_failure'], primary)
        self.assertEqual(self.session.receipt['primary_failure'], primary)
        self.assertEqual(value['status'], 'blocked')
        self.assertTrue(value['unknown_outcome'])

    def test_preallocation_reservation_can_finish_but_empty_allocation_intent_cannot(self):
        self.lease.record['phase'] = 'reserved'
        self.session.receipt['primary_failure'] = {'code': 'tool_download_failed', 'recorded_at': now()}
        with patch.object(self.session, 'destroy') as destroy:
            value = r.cleanup_session(self.session, self.lease, reason='failure')
            destroy.assert_not_called()
        self.assertEqual(value['status'], 'completed')
        self.assertEqual(value['primary_failure']['code'], 'tool_download_failed')
        self.lease.record['phase'] = 'provisioning'
        with patch.object(self.session, 'destroy', side_effect=RunError('provisioner_missing', 'No returned allocation ID')):
            value = r.cleanup_session(self.session, self.lease, reason='failure')
        self.assertEqual(value['status'], 'failed')

    def test_recovery_refusal_records_primary_and_pending_ids_without_overriding_unknown(self):
        with self.f.patches(): self.session.provision()
        self.session.receipt['unknown_outcome'] = True; self.session.save()
        self.lease._reconciliation_only = True
        with patch.object(r, 'source_identity', return_value=(fixture.SHA, False)), \
             patch.object(p, 'provisioner_identity', return_value=(0, 0, [])), \
             patch.object(r.AdmissionLease, 'resume', return_value=nullcontext(self.lease)), \
             patch.object(images, 'docker_scope', return_value=nullcontext()), \
             patch.object(images, 'inspect', side_effect=AssertionError('No Docker execution for an unknown outcome')):
            value = r.recover_run(self.run)
        self.assertEqual(value['status'], 'blocked')
        self.assertEqual(value['secondary_failures'][0]['code'], 'daemon_outcome_unknown')
        self.assertTrue(value['unknown_outcome'])
        self.assertEqual(len(value['resources']), 3)

    def test_interrupted_after_tf_destroy_preserves_ids_and_retries_only_empty_saved_destroy(self):
        with self.f.patches():
            self.session.provision()
            historical = deepcopy(self.session.owned)
            original = self.lease.reconcile_resource
            first = True
            def interrupt(kind, identifier):
                nonlocal first
                if first:
                    first = False
                    raise RunError('synthetic_ack_interrupted', 'Synthetic interruption after positive absence')
                return original(kind, identifier)
            self.lease.reconcile_resource = interrupt
            failed = r.cleanup_session(self.session, self.lease)
            self.assertEqual(failed['status'], 'failed')
            self.assertEqual(self.session.owned, historical)
            self.assertTrue(self.session.state.exists())
            self.assertTrue(self.session.receipt['cleanup_progress']['terraform_final_state_empty'])
            def empty(name):
                self.f.calls.append(('retry-operation', name))
                if name in ('show-state', 'final-state'): return {'values': {'root_module': {'resources': []}}}
                if name == 'show-destroy-plan': return {'format_version': '1.2', 'terraform_version': '1.17.0', 'resource_changes': []}
                return {'synthetic': True}
            with patch.object(self.session, 'operation', side_effect=empty):
                complete = r.cleanup_session(self.session, self.lease, reason='failure')
        self.assertEqual(complete['status'], 'completed')
        self.assertEqual(complete['primary_failure']['code'], 'synthetic_ack_interrupted')
        self.assertEqual(self.session.owned, historical)
        self.assertTrue(all(x['disposition'] == 'absent' for x in complete['resources']))
        self.assertEqual(len(list(self.run.file('evidence/cleanup-attempts').iterdir())), 2)

    def test_missing_controller_after_known_empty_destroy_is_reconciled_without_restart_or_tf_execution(self):
        with self.f.patches(): self.session.provision()
        folder = self.session.state / 'operations'; folder.mkdir(mode=0o700)
        raw = b'{"values":{"root_module":{"resources":[]}}}'
        stem = folder / 'final-state-1'; stem.with_suffix('.out').write_bytes(raw); stem.with_suffix('.out').chmod(0o600)
        record = {'operation': 'final-state', 'attempt': 1, 'returncode': 0, 'duration_seconds': .01,
            'output_bytes': len(raw), 'output_sha256': hashlib.sha256(raw).hexdigest(), 'truncated': False, 'timed_out': False, 'passed': True}
        atomic_json(stem.with_suffix('.json'), record)
        destroy_raw = b'Synthetic completed saved Terraform destroy'
        destroy_record = {**record, 'operation': 'destroy', 'output_bytes': len(destroy_raw), 'output_sha256': hashlib.sha256(destroy_raw).hexdigest()}
        (folder / 'destroy-1.out').write_bytes(destroy_raw); (folder / 'destroy-1.out').chmod(0o600)
        atomic_json(folder / 'destroy-1.json', destroy_record)
        self.session.receipt['operations'] = [
            {**destroy_record, 'client_returncode': 0, 'client_log_truncated': False, 'client_status': 'pass'},
            {**record, 'client_status': 'pass', 'client_returncode': 0, 'client_log_truncated': False,
             'evidence': 'private/terraform/operations/final-state-1.out'}]
        self.session.receipt['cleanup_progress'] = {'terraform_final_state_empty': True, 'controller_remove_requested': True}
        self.f.removed.update({fixture.CID, fixture.NET, fixture.CONTROLLER})
        with self.f.patches(), patch.object(self.session, 'operation', side_effect=AssertionError('No Terraform execution without retained controller')):
            complete = r.cleanup_session(self.session, self.lease)
        self.assertEqual(complete['status'], 'completed')
        self.assertFalse(any(call[:2] == ('docker', 'start') for call in self.f.calls[-5:]))
        self.assertTrue(self.session.state.exists())
        stem.with_suffix('.out').write_bytes(b'changed capture')
        with self.f.patches(), self.assertRaises(p.ProvisioningError): self.session.destroy()

    def test_missing_tf_state_cannot_adopt_surviving_owned_resource_or_delete_it_natively(self):
        with self.f.patches():
            self.session.provision()
            with patch.object(self.session, 'operation', return_value={'values': {'root_module': {'resources': []}}}):
                value = r.cleanup_session(self.session, self.lease, reason='failure')
        self.assertEqual(value['status'], 'blocked')
        self.assertFalse(any(call[:2] == ('docker', 'rm') for call in self.f.calls))
        self.assertTrue(self.session.state.exists())

    def test_normal_recover_resumes_partly_acknowledged_known_teardown_with_historical_ids(self):
        with self.f.patches(): self.session.provision()
        original_ids = deepcopy(self.session.owned)
        self.f.removed.update({fixture.CID, fixture.NET})
        for item in self.lease.record['resources']:
            if item['id'] == fixture.CID: item['outcome'] = 'absent'
        (self.session.state / 'operations').mkdir(mode=0o700)
        self.lease._reconciliation_only = True
        self.lease.finish = Mock()
        def empty(session, name):
            if name in ('show-state', 'final-state'): return {'values': {'root_module': {'resources': []}}}
            if name == 'show-destroy-plan': return {'format_version': '1.2', 'terraform_version': '1.17.0', 'resource_changes': []}
            return {'synthetic': True}
        with self.f.patches(), patch.object(r, 'source_identity', return_value=(fixture.SHA, False)), \
             patch.object(r.AdmissionLease, 'resume', return_value=nullcontext(self.lease)), \
             patch.object(images, 'docker_scope', return_value=nullcontext()), \
             patch.object(p.ProvisioningSession, 'operation', autospec=True, side_effect=empty):
            value = r.recover_run(self.run)
        self.assertEqual(value['status'], 'completed')
        self.assertEqual(original_ids, self.session.owned)
        self.assertTrue(all(x['disposition'] == 'absent' for x in value['resources']))
        self.lease.finish.assert_called_once_with(reconciliation_complete=True)
        self.assertFalse(any(call[:2] == ('docker', 'rm') and fixture.CID in call for call in self.f.calls))

    def test_wrong_source_noncanonical_run_or_busy_lease_cannot_start_recovery(self):
        with patch.object(r, 'source_identity', return_value=('b' * 40, False)), patch.object(r.AdmissionLease, 'resume') as resume:
            with self.assertRaises(r.RecoveryError): r.recover_run(self.run)
            resume.assert_not_called()
        with patch.object(images, 'RUNS_ROOT', self.run.workspace / 'different'), \
             patch.object(r, 'source_identity', return_value=(fixture.SHA, False)), patch.object(r.AdmissionLease, 'resume') as resume:
            with self.assertRaises(r.RecoveryError): r.recover_run(self.run)
            resume.assert_not_called()
        with patch.object(r, 'source_identity', return_value=(fixture.SHA, False)), \
             patch.object(images, 'docker_scope', return_value=nullcontext()), \
             patch.object(r.AdmissionLease, 'resume', side_effect=r.AdmissionError('infrastructure_busy', 'Synthetic busy lease')):
            with self.assertRaises(r.RecoveryError) as error: r.recover_run(self.run)
            self.assertEqual(error.exception.code, 'infrastructure_busy')


if __name__ == '__main__': unittest.main()
