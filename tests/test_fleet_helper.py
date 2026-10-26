"""Scoped policy/protocol fixtures; no Docker, SSH or Ansible execution."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import admission, images, readiness as r, fleet_readiness as f, fleet_validation as v
from wormhole.runs import atomic_json, common, create_run, read_json
from wormhole.targets import TargetPlan
from validation import runtime
from test_admission import observed as host_observations
from test_readiness import Lease, HOST_KEY, SHA, NETWORK, CONTROLLER, HELPER
import test_readiness as old_readiness
from test_validation import observed


class FleetHelper(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='wormhole-fleet-helper-synthetic-')
        self.addCleanup(temporary.cleanup)
        profile = getattr(self, 'fixture_profile', 'five-targets')
        self.run = create_run(Path(temporary.name) / 'runs', fixture=False, identity=(SHA, False), profile=profile)
        self.lease = Lease(self.run); self.lease.plan = admission.build_plan(profile, host_observations()); self.lease.plan['synthetic'] = False
        self.target_plan = TargetPlan(profile)
        self.target_resources = {target: format(index, '064x') for index, target in enumerate(self.target_plan.target_ids, 11)}
        self.starts = {target: datetime.now(timezone.utc).isoformat() for target in self.target_plan.target_ids}
        self.running = {target: True for target in self.target_plan.target_ids}
        self.addresses = {target: '172.31.77.' + str(index) for index, target in enumerate(self.target_plan.target_ids, 2)}
        self.helper_started, self.removed, self.calls = False, False, []
        self.image_labels = {images.LABEL + '.source_revision': 'f' * 40, images.LABEL + '.role': 'helper'}
        self.lease.record['resources'] = [{'kind': 'container', 'id': CONTROLLER, 'outcome': 'pending'},
            {'kind': 'network', 'id': NETWORK, 'outcome': 'pending'},
            *({'kind': 'container', 'id': identifier, 'outcome': 'pending'} for identifier in self.target_resources.values())]
        self.ps = SimpleNamespace(run=self.run, lease=self.lease, target_plan=self.target_plan, target_resources=self.target_resources,
            network_id=NETWORK, variables={'image': v.v.TARGET_IMAGE}, held=Mock(),
            owned={self.target_plan.address_for(target): identifier for target, identifier in self.target_resources.items()},
            receipt={'unknown_outcome': False, 'primary_failure': None, 'secondary_failures': []}, verify_target=self.verify_target)
        self.ps.owned['docker_network.run'] = NETWORK
        self.ps.target_inventory = lambda target: {'target_id': target, 'resource_id': self.target_resources[target], 'host': self.addresses[target],
            'ssh_user': 'wormhole', 'ssh_port': 2222} if self.running[target] else None
        def failure(error):
            if self.ps.receipt['primary_failure'] is None: self.ps.receipt['primary_failure'] = {'code': error.code}
            else: self.ps.receipt['secondary_failures'].append({'code': error.code})
        self.ps.failure = failure
        for module in (r, f, v):
            setting = patch.object(module, 'source_identity', return_value=(SHA, False)); setting.start(); self.addCleanup(setting.stop)
        for module, name, options in ((r.ReadinessSession, 'helper_reference', {'return_value': self.image_labels}),
            (images, 'inspect', {'side_effect': self.inspect}), (images, 'docker', {'side_effect': self.docker}),
            (images, 'cgroup_limits', {'return_value': {'synthetic': True}}), (images, 'docker_configuration', {'return_value': '/synthetic/empty-config'}),
            (r.ReadinessSession, 'public_key', {'return_value': HOST_KEY}), (f.BatchReadinessSession, 'inject_inputs', {}),
            (v.v.qualification, 'build_reference', {'return_value': {'image_id': v.v.TARGET_IMAGE, 'source_revision': v.v.TARGET_BUILD_SOURCE}})):
            setting = patch.object(module, name, **options); setting.start(); self.addCleanup(setting.stop)
        self.session = f.BatchReadinessSession(self.ps, fleet_inventory=getattr(self, 'fixture_inventory', False))
        self.failures = {}

    def verify_target(self, actual, *, target_id, **_):
        self.assertIn(target_id, self.target_plan.target_ids)
        self.assertEqual(actual['Id'], self.target_resources[target_id])

    def target(self, target):
        return {'Id': self.target_resources[target], 'State': {'Status': 'running' if self.running[target] else 'created',
            'Running': self.running[target], 'StartedAt': self.starts[target] if self.running[target] else '0001-01-01T00:00:00Z'},
            'NetworkSettings': {'Networks': {'run': {'NetworkID': NETWORK, 'IPAddress': self.addresses[target] if self.running[target] else ''}}}}

    def helper(self):
        value = old_readiness.ReadinessPolicy.helper(self)
        value['State']['StartedAt'] = min(self.starts.values()) if self.helper_started else '0001-01-01T00:00:00Z'
        value['Mounts'].append({'Type': 'bind', 'Source': str(self.run.file('private/helper-source/validation.py')),
                                'Destination': r.VALIDATION_MOUNT, 'RW': False})
        return value

    def inspect(self, kind, identifier, **_):
        self.calls.append(('inspect', kind, identifier))
        if kind == 'image': return {'Config': {'Labels': self.image_labels}}
        if identifier == HELPER: return None if self.removed else self.helper()
        targets = [target for target, value in self.target_resources.items() if value == identifier]
        self.assertEqual(len(targets), 1, 'No unknown target/resource may be touched')
        return self.target(targets[0])

    def docker(self, arguments, **_):
        self.calls.append(('docker', *arguments))
        if arguments[0] == 'create': return {'log': (HELPER + '\n').encode(), 'log_truncated': False}
        self.assertEqual(arguments[-1], HELPER)
        if arguments[0] == 'start': self.helper_started = True
        if arguments[0] == 'stop': self.helper_started = False
        if arguments[0] == 'rm': self.removed = True
        return {'log': b'', 'log_truncated': False}

    def probe(self, arguments, **_):
        request = json.loads(base64.b64decode(arguments[-1])); target, operation = request['target_id'], request['operation']
        self.assertEqual(request['resource_layout'], 'indexed-targets-v1')
        self.calls.append(('probe', target, operation))
        failure = self.failures.get(target) if operation == 'ssh' else None
        observation = {'tcp': {'tcp_connected': True}, 'ssh': {'uid': 10001}, 'python': {'configured_interpreter_usable': True},
            'ansible-wait': {'structured_target_result': True}, 'ansible-ping': {'structured_target_result': True, 'ping': 'pong'}}[operation]
        value = {**{key: request[key] for key in ('schema_version', 'run_id', 'source_revision', 'target_id', 'operation', 'attempt')},
            'status': 'fail' if failure else 'pass', 'category': failure, 'returncode': 1 if failure else 0, 'timed_out': False,
            'truncated': False, 'duration_seconds': .001, 'observation': observation, 'private_diagnostic': 'synthetic private per-target'}
        return {'status': 'pass', 'returncode': 0, 'duration_seconds': .001, 'log_truncated': False, 'log': json.dumps(value).encode()}

    def make_ready(self):
        self.session.start_helper()
        with patch.object(r, '_run_process', side_effect=self.probe): self.session.wait_ready()

    def batch(self, arguments, **_):
        value = runtime.decode_batch(base64.b64decode(arguments[-1])); targets = []
        self.assertEqual(value['controller_concurrency'], 2)
        for target in value['targets']:
            targets.append({'target_id': target['target_id'], 'status': 'pass', 'category': None, 'module_returncode': 0, 'observation': observed()})
        result = {**{key: value[key] for key in ('schema_version', 'run_id', 'source_revision', 'resource_layout', 'plan_sha256')},
            'status': 'pass', 'returncode': 0, 'timed_out': False, 'truncated': False, 'duration_seconds': .01,
            'targets': targets, 'private_diagnostic': 'synthetic private batch'}
        return {'status': 'pass', 'returncode': 0, 'duration_seconds': .02, 'log_truncated': False, 'log': json.dumps(result).encode()}

    def test_one_helper_five_independent_ready_records_and_fifty_batch_rows(self):
        self.make_ready()
        self.assertEqual(len([item for item in self.calls if item[:2] == ('docker', 'create')]), 1)
        self.assertEqual(len(self.session.receipt['targets']), 5)
        self.assertEqual(len(self.session.receipt['expected_pairs']), 40)
        for target in self.target_plan.target_ids:
            self.assertEqual({row['target_id'] for row in self.session.target_state(target)['transitions']}, {target})
        validation = v.BatchValidationSession(self.session)
        with patch.object(v, '_run_process', side_effect=self.batch): result = validation.validate()
        self.assertEqual(result['status'], 'passed'); self.assertEqual(len(result['checks']), 50)
        report = v.report_batch_validation(self.run)
        self.assertEqual(report['result']['checks'], result['checks'])
        self.assertIn('Targets 5; configured Ansible forks 2', report['text'])
        self.assertNotIn('synthetic private batch', json.dumps(report))

    def test_one_failed_target_does_not_hide_four_healthy_targets_or_drop_grid_rows(self):
        self.failures['target-002'] = 'ssh_key_rejected'; self.session.start_helper()
        with patch.object(r, '_run_process', side_effect=self.probe), self.assertRaises(r.ReadinessError) as error: self.session.wait_ready()
        self.assertEqual(error.exception.code, 'ssh_key_rejected')
        self.assertEqual(self.session.ready_target_ids, ('target-001', 'target-003', 'target-004', 'target-005'))
        validation = v.BatchValidationSession(self.session)
        with patch.object(v, '_run_process', side_effect=self.batch), self.assertRaises(v.v.ValidationError): validation.validate(diagnostic_subset=True)
        report = v.report_batch_validation(self.run)['result']
        self.assertEqual(len(report['checks']), 50)
        self.assertEqual(sum(item['status'] == 'pass' for item in report['checks']), 40)
        self.assertEqual(report['blocked_targets'], {'target-002': 'ssh_key_rejected'})
        self.assertEqual(self.ps.receipt['primary_failure']['code'], 'required_batch_check_failed')

    def test_incomplete_readiness_blocks_full_catalog_and_accounts_for_every_row(self):
        self.failures['target-002'] = 'ssh_key_rejected'; self.session.start_helper()
        with patch.object(r, '_run_process', side_effect=self.probe), self.assertRaises(r.ReadinessError):
            self.session.wait_ready()
        validation = v.BatchValidationSession(self.session)
        with patch.object(v, '_run_process') as execute, self.assertRaises(v.v.ValidationError) as error:
            validation.validate()
        self.assertEqual(error.exception.code, 'readiness_required')
        execute.assert_not_called()
        report = v.report_batch_validation(self.run)
        self.assertEqual(report['result']['attempted_targets'], [])
        self.assertEqual(len(report['result']['checks']), 50)
        self.assertEqual(len(report['result']['blocked_targets']), 5)
        self.assertEqual(report['result']['primary_failure']['code'], 'ssh_key_rejected')
        self.assertEqual(report['progress']['summary']['tests_blocked'], 50)
        self.assertEqual(report['progress']['summary']['targets_ansible_ready'], 4)
        invocation = read_json(self.run.file(v.INVOCATION))
        self.assertEqual(invocation['scope'], 'full-fleet-acceptance')
        self.assertEqual(invocation['outcome'], 'failed')
        self.assertIsNotNone(invocation['finished_at'])

    def test_expired_inherited_deadline_never_invokes_catalog_and_persists_failure(self):
        self.make_ready(); validation = v.BatchValidationSession(self.session)
        with patch.object(v, '_run_process') as execute, self.assertRaises(v.v.ValidationError) as error:
            validation.validate(absolute_deadline=time.monotonic() - 1)
        self.assertEqual(error.exception.code, 'validation_timeout'); execute.assert_not_called()
        result = v.report_batch_validation(self.run)['result']
        self.assertEqual(result['status'], 'failed'); self.assertEqual(len(result['checks']), 50)
        self.assertEqual(read_json(self.run.file(v.INVOCATION))['budget_seconds'], 0)

    def test_unexpected_dispatch_exception_remains_failed_with_complete_grid(self):
        self.make_ready(); validation = v.BatchValidationSession(self.session)
        failure = RuntimeError('Controlled dispatch failure')
        with patch.object(v, '_run_process', side_effect=failure), self.assertRaises(RuntimeError) as error:
            validation.validate()
        self.assertIs(error.exception, failure)
        result = v.report_batch_validation(self.run)['result']
        self.assertEqual(result['status'], 'failed'); self.assertEqual(len(result['checks']), 50)
        self.assertEqual(result['attempted_targets'], [])
        self.assertEqual(read_json(self.run.file(v.INVOCATION))['outcome'], 'failed')

    def test_later_timing_write_error_does_not_replace_dispatch_failure(self):
        self.make_ready(); validation = v.BatchValidationSession(self.session)
        original = v.atomic_json; writes = 0
        def write(path, value):
            nonlocal writes
            if path == self.run.file(v.INVOCATION):
                writes += 1
                if writes == 2: raise OSError('Controlled timing evidence failure')
            return original(path, value)
        failure = RuntimeError('Controlled original dispatch failure')
        with patch.object(v, '_run_process', side_effect=failure), patch.object(v, 'atomic_json', side_effect=write), \
                self.assertRaises(RuntimeError) as error:
            validation.validate()
        self.assertIs(error.exception, failure)
        self.assertEqual(self.ps.receipt['secondary_failures'][-1]['code'], 'validation_evidence_write_failed')

    def test_delayed_target_does_not_repin_others_and_distinct_logs_survive(self):
        self.running['target-005'] = False; self.session.start_helper()
        def delayed(elapsed):
            if elapsed > .04: self.running['target-005'] = True
        with patch.object(r, '_run_process', side_effect=self.probe): self.session.wait_ready(on_poll=delayed)
        self.assertEqual(len(self.session.ready_target_ids), 5)
        names = [attempt['private_log'] for state in self.session.receipt['targets'] for attempt in state['attempts']]
        self.assertEqual(len(names), len(set(names)))
        pins = {target: self.session._states[target]['pinned_key'] for target in self.target_plan.target_ids}
        self.session.pin_trust('target-005')
        self.assertEqual(pins, {target: self.session._states[target]['pinned_key'] for target in self.target_plan.target_ids})

    def test_context_three_exact_map_cleanup_is_idempotent_and_wrong_map_refuses(self):
        self.make_ready()
        atomic_json(self.run.file('evidence/provisioning.json'), {**common(self.run.manifest()),
            'resources': [{'address': key, 'id': value} for key, value in self.ps.owned.items()]})
        self.lease._reconciliation_only = True
        resumed = r.ReadinessSession.resume_cleanup(self.run, self.lease)
        self.assertIsInstance(resumed, f.BatchReadinessSession)
        resumed.cleanup(); resumed.cleanup()
        self.assertTrue(self.removed)
        self.assertEqual(len([item for item in self.calls if item[:2] == ('docker', 'rm')]), 1)
        context = read_json(self.run.file('private/readiness-controller.json'))
        context['target_resource_ids']['target-005'] = 'f' * 64
        atomic_json(self.run.file('private/readiness-controller.json'), context)
        with self.assertRaises(r.ReadinessError): r.ReadinessSession.resume_cleanup(self.run, self.lease)

    def test_foreign_or_malformed_child_outcome_refuses_before_any_cleanup(self):
        self.make_ready()
        atomic_json(self.run.file('evidence/provisioning.json'), {**common(self.run.manifest()),
            'resources': [{'address': key, 'id': value} for key, value in self.ps.owned.items()]})
        self.lease._reconciliation_only = True
        original = read_json(self.run.file('evidence/readiness.json'))
        mutations = [('source_revision', 'f' * 40), ('primary_failure', 'not a failure record'),
                     ('status', 'complete'), ('transitions', [])]
        for field, value in mutations:
            with self.subTest(field=field):
                changed = deepcopy(original); changed['targets'][2][field] = value
                atomic_json(self.run.file('evidence/readiness.json'), changed)
                before = len(self.calls)
                with self.assertRaises(r.ReadinessError): r.ReadinessSession.resume_cleanup(self.run, self.lease)
                self.assertFalse(any(item[:2] in {('docker', 'stop'), ('docker', 'rm')} for item in self.calls[before:]))
                self.assertEqual(read_json(self.run.file('evidence/readiness.json')), changed)

    def test_never_started_target_retains_four_ready_and_explicit_pending_failure(self):
        self.running['target-005'] = False; self.session.start_helper(); shortened = False
        def end_window(_):
            nonlocal shortened
            if not shortened and len(self.session.ready_target_ids) == 4:
                self.session.deadline = time.monotonic() + .03; shortened = True
        with patch.object(r, '_run_process', side_effect=self.probe), self.assertRaises(r.ReadinessError) as error:
            self.session.wait_ready(on_poll=end_window)
        self.assertEqual(error.exception.code, 'target_not_started')
        self.assertEqual(len(self.session.ready_target_ids), 4)
        state = self.session.target_state('target-005')
        self.assertEqual(state['primary_failure']['code'], 'target_not_started')
        self.assertFalse(state['probes'])
        self.assertEqual(state['transitions'][0]['check_id'], 'created')

    def test_unknown_helper_exec_blocks_normal_cleanup_without_touching_targets(self):
        self.session.start_helper()
        response = {'status': 'timeout', 'returncode': -9, 'duration_seconds': .01, 'log_truncated': False, 'log': b''}
        with patch.object(r, '_run_process', return_value=response), self.assertRaises(r.ReadinessError): self.session.wait_ready()
        self.assertTrue(self.session.receipt['unknown_outcome'])
        before = len(self.calls)
        with self.assertRaises(r.ReadinessError): self.session.cleanup()
        self.assertFalse(any(item[0] == 'docker' for item in self.calls[before:]))

    def test_batch_capture_wrong_target_missing_row_and_changed_capture_cannot_report_pass(self):
        self.make_ready(); validation = v.BatchValidationSession(self.session)
        with patch.object(v, '_run_process', side_effect=self.batch): validation.validate()
        value = read_json(self.run.file('evidence/batch-validation.json')); value['checks'].pop()
        atomic_json(self.run.file('evidence/batch-validation.json'), value)
        with self.assertRaises(v.v.ValidationError): v.report_batch_validation(self.run)

    def test_complete_mixed_ansible_exit_preserves_four_successful_targets_but_blocks_aggregate(self):
        self.make_ready(); validation = v.BatchValidationSession(self.session)
        def mixed(*args, **kwargs):
            response = self.batch(*args, **kwargs); value = json.loads(response['log'])
            value.update(status='fail', returncode=2)
            value['targets'][2].update(status='fail', category='configured_interpreter_unavailable', module_returncode=127, observation=None)
            response['log'] = json.dumps(value).encode(); return response
        with patch.object(v, '_run_process', side_effect=mixed), self.assertRaises(v.v.ValidationError): validation.validate()
        result = v.report_batch_validation(self.run)['result']
        self.assertEqual(sum(row['status'] == 'pass' for row in result['checks']), 40)
        self.assertEqual(sum(row['status'] == 'fail' for row in result['checks']), 10)
        self.assertFalse(result['blocked_targets']); self.assertEqual(result['status'], 'failed')
        atomic_json(self.run.file('evidence/batch-validation.json'), validation.receipt)
        self.run.file(v.LOG).write_bytes(b'{}')
        with self.assertRaises(v.v.ValidationError): v.report_batch_validation(self.run)


if __name__ == '__main__': unittest.main()
