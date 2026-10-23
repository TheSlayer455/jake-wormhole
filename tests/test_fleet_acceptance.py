"""Acceptance coordinator fixtures: no Docker, SSH, Ansible or host allocation."""
from contextlib import nullcontext, redirect_stdout
from copy import deepcopy
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import fleet_acceptance as a
from wormhole import fleet_validation as v, readiness as r
from wormhole.runs import RunError, read_json
from wormhole.targets import TargetPlan
import test_fleet_helper as helper_fixtures

SHA, SENTINEL, TARGET = 'a' * 40, 'b' * 64, 'c' * 64


class FleetAcceptanceBoundaries(unittest.TestCase):
    def test_invalid_profile_case_sentinel_and_platform_refuse_before_run_creation(self):
        with patch.object(a, 'create_run') as create:
            for profile, scenario, sentinel, code in (
                ('twenty-targets', 'healthy', SENTINEL, 'unsupported_acceptance_profile'),
                ('smoke', 'wrong-key', SENTINEL, 'unsupported_acceptance_case'),
                ('five-targets', 'ticket-command', SENTINEL, 'unsupported_acceptance_case'),
                ('five-targets', 'healthy', '../foreign', 'invalid_sentinel')):
                with self.subTest(code=code), self.assertRaises(RunError) as error:
                    a.qualify_case(profile, scenario, sentinel)
                self.assertEqual(error.exception.code, code)
            with patch.object(a.sys, 'platform', 'win32'), self.assertRaises(RunError) as error:
                a.qualify_case('five-targets', 'healthy', SENTINEL)
            self.assertEqual(error.exception.code, 'linux_required')
            create.assert_not_called()

    def test_wrong_expected_endpoint_and_network_restore_only_memory_after_failed_check(self):
        for scenario, expected in (('wrong-endpoint', 'inventory_endpoint_mismatch'), ('wrong-network', 'inventory_network_mismatch')):
            with self.subTest(scenario=scenario):
                rows = [{'target_id': target, 'host': '172.31.77.' + str(index)} for index, target in enumerate(TargetPlan('five-targets').target_ids, 2)]
                session = SimpleNamespace(run=SimpleNamespace(id='run'), receipt={'inventory': {'targets': rows}}, save=Mock())
                before = deepcopy(session.receipt)
                view = SimpleNamespace(expected_network_id='d' * 64)
                def wait(**_):
                    if scenario == 'wrong-endpoint':
                        self.assertEqual(rows[-1]['host'], '127.0.0.1')
                        self.assertEqual(rows[0]['host'], '172.31.77.2')
                    else: self.assertNotEqual(view.expected_network_id, 'd' * 64)
                    raise r.ReadinessError(expected, 'Controlled pre-contact identity failure.')
                readiness = SimpleNamespace(_states={'target-005': {'provisioning': view}}, wait_ready=wait, save=Mock())
                self.assertEqual(a.wait_case(session, readiness, scenario, 'target-005')[0], expected)
                self.assertEqual(session.receipt, before)
                self.assertEqual(view.expected_network_id, 'd' * 64)
                session.save.assert_called_once(); readiness.save.assert_called_once()

    def test_delayed_callback_starts_exact_fifth_subset_once_after_two_seconds(self):
        session = SimpleNamespace(receipt={'inventory': None}, start_and_inventory=Mock())
        def wait(*, on_poll):
            for elapsed in (0, 1.99, 2, 2.1, 3): on_poll(elapsed)
        readiness = SimpleNamespace(_states={'target-005': {'provisioning': SimpleNamespace(expected_network_id='d' * 64)}}, wait_ready=wait)
        code, delay = a.wait_case(session, readiness, 'delayed-start', 'target-005')
        self.assertIsNone(code); self.assertEqual(delay, {'invoked': True, 'elapsed_seconds': 2})
        session.start_and_inventory.assert_called_once_with(['target-005'])

    def test_owned_restart_rejects_identity_before_mutation_and_retains_unknown_if_stop_reply_lost(self):
        session = SimpleNamespace(held=Mock(), target_plan=TargetPlan('five-targets'), target_resources={'target-005': TARGET},
            receipt={'unknown_outcome': False}, verify_target=Mock(side_effect=RunError('ownership_mismatch', 'Wrong target.')), save=Mock())
        with patch.object(a.images, 'inspect', return_value={}), patch.object(a.images, 'docker') as docker, self.assertRaises(RunError):
            a.restart_owned_target(session, 'target-005')
        docker.assert_not_called(); session.save.assert_not_called()
        session.verify_target.side_effect = None
        captures = []; session.save = lambda: captures.append(deepcopy(session.receipt))
        with patch.object(a.images, 'inspect', return_value={'State': {'Running': True, 'Pid': 10}}), \
                patch.object(a.images, 'docker', side_effect=OSError('Lost stopped response')), self.assertRaises(OSError):
            a.restart_owned_target(session, 'target-005')
        self.assertEqual(captures, [{'unknown_outcome': True}]); self.assertTrue(session.receipt['unknown_outcome'])

    def test_hostkey_rotation_retries_only_key_generation_and_preserves_original_pin(self):
        pending = a.images.ImageError('qualification_attempt_failed', 'Pending generated public key.')
        readiness = SimpleNamespace(deadline=100, pin_trust=Mock(return_value=True),
            target_state=Mock(return_value={'hostkey_fingerprint': 'old'}), observe_hostkey=Mock(side_effect=[pending,
                {'fingerprint': 'new', 'matches_original_pin': False}]))
        with patch.object(a, 'restart_owned_target', return_value={'target_id': 'target-005'}) as restart, \
                patch.object(a.time, 'monotonic', return_value=1), patch.object(a.time, 'sleep'):
            result = a.rotate_hostkey(object(), readiness, 'target-005')
        self.assertTrue(result['new_public_identity_observed']); self.assertEqual(readiness.deadline, 100)
        self.assertEqual(readiness.observe_hostkey.call_count, 2)
        self.assertEqual(restart.call_args.args[1], 'target-005')
        readiness.observe_hostkey.side_effect = RunError('ownership_mismatch', 'Wrong object.')
        with patch.object(a, 'restart_owned_target', return_value={}), patch.object(a.time, 'monotonic', return_value=1), \
                self.assertRaises(RunError) as error: a.rotate_hostkey(object(), readiness, 'target-005')
        self.assertEqual(error.exception.code, 'ownership_mismatch')
        self.assertEqual(readiness.deadline, 100)

    def test_diagnostic_failure_does_not_skip_normal_cleanup_or_overwrite_original_failure(self):
        first = RunError('ssh_key_rejected', 'Primary controlled failure.')
        scan = RunError('scan_bound', 'Synthetic bounded observation failure.')
        session = SimpleNamespace(receipt={'primary_failure': {'code': first.code}}, failure=Mock())
        value = {'checks': {}, 'disk_samples': []}; cleanup = {'status': 'blocked', 'primary_failure': {'code': first.code},
            'secondary_failures': [], 'unknown_outcome': True, 'terraform_state_retained': True}
        with patch.object(a, 'scan_private_material', side_effect=scan), patch.object(a, 'cleanup_session', return_value=cleanup) as clean:
            result, error = a.cleanup_case(object(), value, session, 'lease', 'helper', first, first.code)
        self.assertIs(error, first); self.assertIs(result, cleanup)
        clean.assert_called_once_with(session, 'lease', reason='failure', helper='helper')
        session.failure.assert_called_once_with(scan)
        self.assertEqual(value['checks']['pre_cleanup_observation_error']['code'], 'scan_bound')

    def test_suite_refuses_source_change_reused_run_or_resource_and_stops_at_first_failure(self):
        def case(run_id, ids, revision=SHA):
            return {'source_revision': revision, 'source_dirty': False, 'status': 'pass', 'run_id': run_id, 'owned_resource_ids': ids}
        for values, expected in (([case('one', ['1']), case('one', ['2'])], 'run_identity_reused'),
            ([case('one', ['1']), case('two', ['1'])], 'run_identity_reused'),
            ([case('one', ['1'], 'f' * 40)], 'source_changed')):
            with self.subTest(expected=expected), patch.object(a, 'source_identity', return_value=(SHA, False)), \
                    patch.object(a, 'qualify_case', side_effect=values), self.assertRaises(RunError) as error:
                a.acceptance('five-targets', SENTINEL, ('healthy', 'delayed-start'))
            self.assertEqual(error.exception.code, expected)
        with patch.object(a, 'source_identity', side_effect=[(SHA, False), (SHA, False), (SHA, False), ('f' * 40, False)]), \
                patch.object(a, 'qualify_case', return_value=case('one', ['1'])) as run, self.assertRaises(RunError) as error:
            a.acceptance('five-targets', SENTINEL, ('healthy', 'delayed-start'))
        self.assertEqual(error.exception.code, 'source_changed'); self.assertEqual(run.call_count, 1)
        with patch.object(a, 'source_identity', return_value=(SHA, False)), patch.object(a, 'qualify_case',
                side_effect=RunError('daemon_outcome_unknown', 'Unresolved request.')) as run, self.assertRaises(RunError):
            a.acceptance('five-targets', SENTINEL, ('healthy', 'delayed-start'))
        self.assertEqual(run.call_count, 1)

    def test_cli_fixed_choices_and_all_smoke_refusal_do_not_allocate(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(a, 'create_run') as create:
            self.assertEqual(a.main(['--profile', 'smoke', '--scenario', 'all', '--sentinel-id', SENTINEL]), 2)
        create.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['error']['code'], 'unsupported_acceptance_case')


class FleetGridIntegrationFixtures(unittest.TestCase):
    def fixture(self):
        fixture = helper_fixtures.FleetHelper('test_one_helper_five_independent_ready_records_and_fifty_batch_rows')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        return fixture

    def test_complete_healthy_and_mixed_actual_event_fixtures_retain_fifty_declared_rows(self):
        for scenario in ('healthy', 'validation-interpreter-unavailable'):
            with self.subTest(scenario=scenario):
                f = self.fixture(); f.make_ready()
                validation = v.BatchValidationSession(f.session, scenarios={'target-005': 'configured-interpreter-unavailable'} if
                    scenario != 'healthy' else {})
                plan = deepcopy(validation.plan)
                def result(*args, **kwargs):
                    reply = f.batch(*args, **kwargs)
                    if scenario != 'healthy':
                        value = json.loads(reply['log']); value.update(status='fail', returncode=2)
                        value['targets'][-1].update(status='fail', category='configured_interpreter_unavailable', module_returncode=127, observation=None)
                        reply['log'] = json.dumps(value).encode()
                    return reply
                with patch.object(v, '_run_process', side_effect=result):
                    if scenario == 'healthy': validation.validate()
                    else:
                        with self.assertRaises(a.ValidationError): validation.validate()
                record = a.check_grid(f.run, validation, plan, 'five-targets', scenario, 'target-005', f.session)
                self.assertEqual(record['required_rows'], 50); self.assertEqual(record['configured_ansible_forks'], 2)
                self.assertEqual(sum(item['passed_rows'] for item in record['targets'].values()), 50 if scenario == 'healthy' else 40)
                changed = deepcopy(plan); changed['checks'].pop()
                with self.assertRaises(RunError): a.check_grid(f.run, validation, changed, 'five-targets', scenario, 'target-005', f.session)

    def test_known_prehelper_failure_preserves_original_error_and_still_runs_normal_cleanup(self):
        f = self.fixture(); failure = RunError('controlled_init_failure', 'No provider mutation started.')
        f.ps.create_stopped = Mock(side_effect=failure)
        cleanup = {'status': 'completed', 'primary_failure': {'code': failure.code}, 'secondary_failures': [],
            'unknown_outcome': False, 'terraform_state_retained': True}
        f.lease.finish = Mock()
        with patch.object(a.sys, 'platform', 'linux'), patch.object(a, 'source_identity', return_value=(SHA, False)), \
                patch.object(a, 'create_run', return_value=f.run), patch.object(a, 'execute_run'), patch.object(a.images, 'create_auth'), \
                patch.object(a.images, 'docker_scope', return_value=nullcontext()), patch.object(a, 'AdmissionLease', return_value=nullcontext(f.lease)), \
                patch.object(a, 'ProvisioningSession', return_value=f.ps), patch.object(a, 'snapshot', return_value='stable'), \
                patch.object(a, 'scan_private_material', return_value={'status': 'pass'}), patch.object(a, 'disk_sample', return_value={'phase': 'synthetic'}), \
                patch.object(a, 'cleanup_session', return_value=cleanup) as clean, self.assertRaises(RunError) as error:
            a.qualify_case('five-targets', 'healthy', SENTINEL)
        self.assertIs(error.exception, failure)
        clean.assert_called_once_with(f.ps, f.lease, reason='failure', helper=None)
        stored = read_json(f.run.file('evidence/fleet-acceptance.json'))
        self.assertEqual(stored['status'], 'fail'); self.assertTrue(stored['cleanup_claimed'])
        self.assertEqual(stored['error']['code'], failure.code)
        self.assertEqual(stored['checks']['cleanup']['primary_failure']['code'], failure.code)


if __name__ == '__main__': unittest.main()
