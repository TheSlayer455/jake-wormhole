"""Original synthetic capture replay, never Docker, SSH or target qualification."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wormhole import fleet_inventory as f, fleet_validation as functional, images, readiness, validation
from wormhole.runs import atomic_bytes, atomic_json, common, create_run, now, read_json
from wormhole.targets import TargetPlan
from validation import runtime as functional_runtime
from test_fleet_inventory_records import observation


class CapturedFleet(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='worm-stock-evidence-'); self.addCleanup(self.tmp.cleanup)
        self.run = create_run(Path(self.tmp.name) / 'runs', fixture=False, profile='twenty-targets', identity=('a' * 40, False))
        self.target_plan = TargetPlan('twenty-targets')
        self.ids = {target: format(index, '064x') for index, target in enumerate(f.TARGET_IDS, 1)}
        self.plan = f.make_plan(self.run, self.target_plan, self.ids, '9' * 64, 4)
        self.common = common(self.run.manifest()); self.stamp = now()
        self.tools = {'terraform_version': '1.17.0', 'platform': 'linux_amd64', 'provider_version': '4.6.0',
            'offline_readonly_lock_h1_confirmed': f.H1, 'provider_schema_observed': True}
        atomic_json(self.run.file(f.PLAN), self.plan)
        atomic_json(self.run.file('private/terraform/controller.json'), {'schema_version': '1.0', 'run_id': self.run.id,
            'source_revision': self.common['source_revision'], 'id': '7' * 64, 'target_plan': self.target_plan.record()})
        self.ps = {**self.common, 'resources': [{'address': 'docker_network.run', 'id': '9' * 64}] +
            [{'address': self.target_plan.address_for(target), 'id': self.ids[target]} for target in f.TARGET_IDS],
            'target_image': validation.TARGET_IMAGE, 'target_binding': None, 'actual_tools': self.tools,
            'status': 'provisioned'}
        self.ready = {**self.common, 'target_resource_ids': self.ids, 'network_id': '9' * 64, 'helper_id': '8' * 64,
            'fleet_inventory_enabled': True, 'fleet_inventory_source_sha256': f.source_hash(), 'status': 'ready'}
        atomic_json(self.run.file('evidence/provisioning.json'), self.ps)
        atomic_json(self.run.file('private/readiness-controller.json'), self.ready)
        self.controller = {**self.common, 'operation': 'stock-fleet-controller-v1',
            'targets': {target: f.target_value(target, self.ids[target]) for target in f.TARGET_IDS},
            'network_id': '9' * 64, 'helper_id': '8' * 64, 'helper_image': readiness.HELPER_IMAGE,
            'provisioner_id': '7' * 64, 'provisioner_image': validation.TARGET_IMAGE, 'actual_tools': self.tools}
        atomic_json(self.run.file(f.CONTROLLER), self.controller)
        f.directory(self.run, 'private/fleet-inventory')
        for target in f.TARGET_IDS: f.directory(self.run, str(Path(f.exports(target)[0]).parent))
        self.transport = {**self.common, 'operation': 'stock-fleet-transport-v1', 'plan_sha256': self.plan['plan_sha256'],
            'attempts': [], 'primary_failure': None, 'unknown_outcome': False, 'updated_at': self.stamp}
        self.responses = {}
        for batch, targets in f.runtime.BATCHES.items():
            value = observation(); value['runtime_sha256'] = self.plan['stock_build']['runtime_sha256']
            packet = base64.b64encode(f.canonical(value)).decode()
            response = {**{key: self.plan[key] for key in ('schema_version', 'run_id', 'source_revision', 'plan_sha256')},
                'batch_id': batch, 'status': 'pass', 'returncode': 0, 'timed_out': False, 'duration_seconds': .1,
                'targets': [{'target_id': target, 'status': 'pass', 'category': None, 'module_returncode': 0,
                    'collector_base64': packet} for target in targets],
                'helper_provenance': {'python_version': '3.12.3', 'ansible_core_version': '2.21.5'},
                'diagnostic_bytes': 0, 'diagnostic_truncated': False}
            self.responses[batch] = response
            self.store_response(batch)
        atomic_json(self.run.file(f.TRANSPORT), self.transport)
        self.session = f.FleetInventorySession.__new__(f.FleetInventorySession); self.session.run = self.run

    def store_response(self, batch):
        raw = f.canonical(self.responses[batch]); atomic_bytes(self.run.file(f.log_path(batch)), raw, limit=f.runtime.MAX_RESPONSE)
        attempt = {'batch_id': batch, 'path': f.log_path(batch), 'sha256': f.digest(raw), 'size_bytes': len(raw),
            'status': 'pass', 'returncode': 0, 'duration_seconds': .2, 'log_truncated': False, 'budget_seconds': 25,
            'response_validation': 'valid'}
        position = list(f.runtime.BATCHES).index(batch)
        if len(self.transport['attempts']) > position: self.transport['attempts'][position] = attempt
        else: self.transport['attempts'].append(attempt)
        atomic_json(self.run.file(f.TRANSPORT), self.transport)

    def export(self):
        return self.session.export()

    def runnable_session(self):
        """Fixed synthetic control plane; actual callback/capture tested separately."""
        lease = SimpleNamespace(_active=lambda: None, run_id=self.run.id, source_revision=self.common['source_revision'],
            plan={'synthetic': False}, _reconciliation_only=False)
        self.ps.update(primary_failure=None, unknown_outcome=False)
        ps = SimpleNamespace(run=self.run, lease=lease, held=lambda: None, receipt=self.ps, provisioner='7' * 64,
            verify_provisioner=lambda actual: None, verify_target=lambda actual, **kwargs: None)
        def save_ps(): atomic_json(self.run.file('evidence/provisioning.json'), ps.receipt)
        ps.save = save_ps
        def failure(error):
            ps.receipt['primary_failure'] = ps.receipt['primary_failure'] or {'code': error.code, 'recorded_at': now()}; save_ps()
        ps.failure = failure
        states = {target: {'trust_address': '10.88.0.' + str(i)} for i, target in enumerate(f.TARGET_IDS, 2)}
        ps.target_inventory = lambda target: {'resource_id': self.ids[target], 'host': states[target]['trust_address']}
        ready = SimpleNamespace(run=self.run, lease=lease, parent_provisioning=ps, reconciliation_only=False,
            helper='8' * 64, verify_helper=lambda actual: None, require_ready=lambda *args, **kwargs: None,
            helper_policy=lambda: {'wait_seconds': 300, 'input_tmpfs_bytes': 524288}, _states=states,
            receipt={'status': 'ready', 'primary_failure': None, 'unknown_outcome': False})
        def held():
            if ps.receipt['unknown_outcome']: raise f.FleetInventoryError('provisioning_not_ready', 'Synthetic guarded probe')
        ready.held = held; ready.save = lambda: None
        self.session.readiness, self.session.ps, self.session.lease = ready, ps, lease
        self.session.plan, self.session.transport, self.session.started = self.plan, deepcopy(self.transport), False
        self.session.transport.update(attempts=[], primary_failure=None, unknown_outcome=False)
        self.session.save()
        started = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        def inspect(kind, identifier, **kwargs):
            return {'Id': identifier, 'Image': readiness.HELPER_IMAGE if identifier == '8' * 64 else validation.TARGET_IMAGE,
                'State': {'StartedAt': started}}
        return inspect

    def test_twenty_full_native_reports_replay_after_cleanup_without_live_inspection(self):
        self.assertEqual(self.export()['status'], 'passed')
        self.ps['status'] = 'destroyed'; self.ready['status'] = 'cleaned'
        atomic_json(self.run.file('evidence/provisioning.json'), self.ps)
        atomic_json(self.run.file('private/readiness-controller.json'), self.ready)
        with patch.object(images, 'inspect', side_effect=AssertionError('Replay cannot inspect freed resources')):
            value = f.report_fleet_inventory(self.run)
        self.assertEqual(len(value['targets']), 20)
        self.assertEqual(sum(len(row['checks']) for row in value['index']['targets']), 200)
        for target in value['targets']:
            self.assertEqual(len(target['record']['observation']['packages']), 8)
            self.assertIn('2:2.39-0ubuntu8.9~synthetic', target['text'])
            self.assertNotIn('private/', target['text'])
            self.assertNotIn('candidate_sha256', f.canonical(target['record']).decode())

    def test_original_capture_not_edited_matching_record_and_index_is_replay_authority(self):
        self.export(); path = self.run.file(f.exports('target-001')[0]); value = read_json(path)
        value['observation']['os']['name'] = 'Changed synthetic name'
        packet = f.canonical(value['observation'])
        value['capture'].update(collector_sha256=f.digest(packet), collector_bytes=len(packet))
        raw = f.pure().render_json(value); text = f.pure().render_text(value).encode()
        atomic_bytes(path, raw); atomic_bytes(self.run.file(f.exports('target-001')[1]), text)
        index = read_json(self.run.file(f.INDEX)); row = index['targets'][0]
        row['record'].update(sha256=f.digest(raw), size_bytes=len(raw)); row['text'].update(sha256=f.digest(text), size_bytes=len(text))
        atomic_json(self.run.file(f.INDEX), index)
        with self.assertRaises(f.FleetInventoryError): f.report_fleet_inventory(self.run)

    def test_raw_capture_changed_or_missing_refuses_even_when_exports_are_unchanged(self):
        self.export(); path = self.run.file(f.log_path('batch-001')); raw = path.read_bytes()
        atomic_bytes(path, raw + b' ')
        with self.assertRaises(f.FleetInventoryError): f.report_fleet_inventory(self.run)
        path.unlink()
        with self.assertRaises(Exception): f.report_fleet_inventory(self.run)

    def test_typed_plan_common_and_actual_tool_boolean_cannot_alias_integer(self):
        for location, key in ((f.PLAN, 'source_dirty'), (f.PLAN, 'runtime_pipeline_complete'),
                ('private/readiness-controller.json', 'source_dirty')):
            path = self.run.file(location); original = read_json(path); bad = deepcopy(original); bad[key] = 0
            atomic_json(path, bad)
            with self.subTest(location=location, key=key), self.assertRaises(f.FleetInventoryError): self.export()
            atomic_json(path, original)
        bad = deepcopy(self.controller); bad['actual_tools']['provider_schema_observed'] = 1
        atomic_json(self.run.file(f.CONTROLLER), bad)
        with self.assertRaises(f.FleetInventoryError): self.export()

    def test_wrong_source_target_map_network_or_forged_index_common_refuses(self):
        self.export()
        for key, wrong in (('source_revision', 'b' * 40), ('network_id', '6' * 64),
                ('target_resource_ids', {**self.ids, 'target-001': '6' * 64})):
            bad = deepcopy(self.ready); bad[key] = wrong; atomic_json(self.run.file('private/readiness-controller.json'), bad)
            with self.subTest(key=key), self.assertRaises(f.FleetInventoryError): self.export()
        atomic_json(self.run.file('private/readiness-controller.json'), self.ready)
        index = read_json(self.run.file(f.INDEX)); index['run_id'] = '12345678-1234-4234-9234-123456789abc'
        atomic_json(self.run.file(f.INDEX), index)
        with self.assertRaises(f.FleetInventoryError): f.report_fleet_inventory(self.run)

    def test_cli_zero_missing_duplicate_foreign_skipped_or_bad_packet_never_passes(self):
        original = deepcopy(self.responses['batch-001'])
        for fault in ('missing', 'duplicate', 'foreign', 'skipped', 'packet', 'oversized'):
            value = deepcopy(original)
            if fault == 'missing': value['targets'].pop()
            elif fault == 'duplicate': value['targets'][1] = deepcopy(value['targets'][0])
            elif fault == 'foreign': value['targets'][3]['target_id'] = 'target-020'
            elif fault == 'skipped': value['targets'][3].update(status='skipped', category='skipped', collector_base64=None)
            elif fault == 'packet': value['targets'][0]['collector_base64'] = base64.b64encode(b'{}').decode()
            else: value['targets'][0]['collector_base64'] = base64.b64encode(b'x' * 32769).decode()
            with self.subTest(fault=fault), self.assertRaises(Exception): f.parse_response(f.canonical(value), self.plan, 'batch-001', 25)

    def test_actual_unreachable_retains_other_observations_and_full_failed_grid(self):
        response = self.responses['batch-005']; response.update(status='fail', returncode=2)
        response['targets'][3].update(status='unreachable', category='ssh_unreachable', module_returncode=None, collector_base64=None)
        self.store_response('batch-005')
        self.transport['primary_failure'] = {'code': 'fleet_inventory_required_check_failed', 'recorded_at': self.stamp}
        atomic_json(self.run.file(f.TRANSPORT), self.transport)
        index = self.export(); report = f.report_fleet_inventory(self.run)
        self.assertEqual(index['status'], 'failed'); self.assertEqual(len(index['targets']), 20)
        self.assertEqual(sum(row['status'] == 'passed' for row in index['targets']), 19)
        final = report['targets'][19]['record']; self.assertIsNone(final['observation'])
        self.assertTrue(all(row['status'] == 'unverified' for row in final['checks'][1:]))
        self.assertEqual(len(final['checks']), 10)

    def test_timeout_or_truncation_retains_twenty_explicit_failed_records_without_fake_observations(self):
        self.transport['attempts'] = self.transport['attempts'][:1]
        self.transport['attempts'][0].update(status='timeout', returncode=None, log_truncated=True, response_validation='not-validated')
        self.transport['unknown_outcome'] = True
        self.transport['primary_failure'] = {'code': 'fleet_inventory_probe_incomplete', 'recorded_at': self.stamp}
        atomic_json(self.run.file(f.TRANSPORT), self.transport)
        self.export(); report = f.report_fleet_inventory(self.run)
        self.assertTrue(report['index']['unknown_outcome'])
        self.assertTrue(all(row['record']['status'] == 'failed' and row['record']['observation'] is None for row in report['targets']))

    def test_initial_malformed_missing_or_foreign_reply_still_exports_all_twenty_failed_records(self):
        for fault in ('malformed', 'missing', 'foreign'):
            inspect = self.runnable_session(); response = deepcopy(self.responses['batch-001'])
            if fault == 'missing': response['targets'].pop()
            elif fault == 'foreign': response['targets'][0]['target_id'] = 'target-020'
            raw = b'{' if fault == 'malformed' else f.canonical(response)
            result = {'status': 'pass', 'returncode': 0, 'duration_seconds': .1, 'log': raw, 'log_truncated': False}
            with self.subTest(fault=fault), patch.object(images, 'inspect', side_effect=inspect), \
                    patch.object(f, 'capture_inventory', return_value=result), self.assertRaises(f.FleetInventoryError):
                self.session.collect()
            report = f.report_fleet_inventory(self.run)
            self.assertEqual(len(report['targets']), 20)
            self.assertTrue(all(row['record']['status'] == 'failed' and row['record']['observation'] is None for row in report['targets']))
            self.assertEqual(read_json(self.run.file(f.TRANSPORT))['attempts'][0]['response_validation'], 'invalid')

    def test_outer_timeout_preserves_primary_unknown_and_failed_grid_despite_batch_held_refusal(self):
        inspect = self.runnable_session()
        result = {'status': 'timeout', 'returncode': -9, 'duration_seconds': 27, 'log': b'', 'log_truncated': False}
        with patch.object(images, 'inspect', side_effect=inspect), patch.object(f, 'capture_inventory', return_value=result), \
                self.assertRaises(f.FleetInventoryError) as caught:
            self.session.collect()
        self.assertEqual(caught.exception.code, 'fleet_inventory_probe_incomplete')
        report = f.report_fleet_inventory(self.run)
        self.assertTrue(self.session.ps.receipt['unknown_outcome']); self.assertTrue(self.session.readiness.receipt['unknown_outcome'])
        self.assertEqual(self.session.ps.receipt['primary_failure']['code'], 'fleet_inventory_probe_incomplete')
        self.assertTrue(report['index']['unknown_outcome']); self.assertEqual(len(report['targets']), 20)
        self.assertTrue(all(row['record']['observation'] is None for row in report['targets']))

    def test_late_final_replay_cannot_leave_passed_inventory_or_overwrite_readiness(self):
        inspect = self.runnable_session(); clock = [0.0]
        def capture(_, encoded, **kwargs):
            request = f.runtime.decode(base64.b64decode(encoded))
            return {'status': 'pass', 'returncode': 0, 'duration_seconds': .1,
                'log': f.canonical(self.responses[request['batch_id']]), 'log_truncated': False}
        def delayed_replay():
            self.assertTrue(f.report_fleet_inventory(self.run)['index']['status'] == 'passed')
            clock[0] = f.TIMEOUT + 1
            return True
        with patch.object(images, 'inspect', side_effect=inspect), patch.object(f, 'capture_inventory', side_effect=capture), \
                patch.object(f.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(self.session, 'require_passed', side_effect=delayed_replay), self.assertRaises(f.FleetInventoryError):
            self.session.collect()
        self.assertEqual(f.report_fleet_inventory(self.run)['index']['primary_failure']['code'], 'fleet_inventory_timeout')
        self.assertEqual(self.session.readiness.receipt['status'], 'ready')

    def test_primary_failure_is_durable_before_inventory_save_and_does_not_change_readiness(self):
        events = []
        lease = SimpleNamespace(_active=lambda: None, run_id=self.run.id, source_revision=self.common['source_revision'],
            plan={'synthetic': False}, _reconciliation_only=False)
        ps = SimpleNamespace(run=self.run, lease=lease, held=lambda: events.append('held'), receipt={'primary_failure': None})
        def failure(error): ps.receipt['primary_failure'] = {'code': error.code}; events.append('ps-primary')
        ps.failure = failure
        ready = SimpleNamespace(run=self.run, lease=lease, parent_provisioning=ps, reconciliation_only=False,
            receipt={'status': 'ready', 'primary_failure': None})
        self.session.ps = ps; self.session.lease = ps.lease; self.session.readiness = ready; self.session.transport = self.transport
        def fail_save(): events.append('validation-save'); raise OSError('Synthetic interruption')
        with patch.object(self.session, 'save', side_effect=fail_save), self.assertRaises(OSError):
            self.session.failure(f.FleetInventoryError('synthetic_failure', 'fixed'))
        self.assertLess(events.index('ps-primary'), events.index('validation-save'))
        self.assertEqual(ps.receipt['primary_failure']['code'], 'synthetic_failure')
        self.assertEqual(ready.receipt, {'status': 'ready', 'primary_failure': None})


class FunctionalTwenty(unittest.TestCase):
    def test_two_hundred_functional_rows_and_count_separate_from_forks(self):
        run = SimpleNamespace(manifest=lambda: {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc',
            'source_revision': 'a' * 40, 'source_dirty': False, 'mode': 'container-reference'})
        plan = TargetPlan('twenty-targets'); mapping = {target: format(i, '064x') for i, target in enumerate(plan.target_ids, 1)}
        scenarios = {target: 'healthy' for target in plan.target_ids}
        for forks in range(1, 5):
            value = functional.make_plan(run, plan, mapping, '9' * 64, forks, scenarios)
            self.assertEqual(len(value['checks']), 200); self.assertEqual(value['controller_concurrency'], forks)
            self.assertEqual(functional.validate_plan(run, value), plan)
            bad = deepcopy(value); bad['source_dirty'] = 0
            with self.assertRaises(Exception): functional.validate_plan(run, bad)
        for forks in (True, 0, 5):
            with self.assertRaises(Exception): functional.make_plan(run, plan, mapping, '9' * 64, forks, scenarios)
        five = TargetPlan('five-targets')
        with self.assertRaises(Exception):
            functional.make_plan(run, five, {key: mapping[key] for key in five.target_ids}, '9' * 64, 3,
                {key: scenarios[key] for key in five.target_ids})

    def test_fixed_functional_runtime_twenty_forks_four_without_changing_legacy_capture_bound(self):
        plan = TargetPlan('twenty-targets')
        value = {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc', 'source_revision': 'a' * 40,
            'resource_layout': 'indexed-targets-v1', 'plan_sha256': 'b' * 64, 'target_plan': plan.record(),
            'targets': [{'target_id': key, 'address': '10.88.0.' + str(i), 'scenario': 'healthy'} for i, key in enumerate(plan.target_ids, 2)],
            'controller_concurrency': 4, 'expected_payload_sha256': 'c' * 64,
            'readiness_source_sha256': 'd' * 64, 'timeout_seconds': 40}
        self.assertEqual(len(functional_runtime.decode_batch(f.canonical(value))['targets']), 20)
        value['controller_concurrency'] = True
        with self.assertRaises(Exception): functional_runtime.decode_batch(f.canonical(value))
        from wormhole import stages
        self.assertEqual(stages.LOG_LIMIT, 65536)


if __name__ == '__main__': unittest.main()
