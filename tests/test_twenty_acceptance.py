"""No Docker: typed proof failures and disposable Linux lifecycle adapters."""
from contextlib import nullcontext
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import Mock, patch

from wormhole import twenty_acceptance as t, cli
from wormhole.runs import RunError, create_run, read_json

SHA = 'a' * 40
SENTINEL = 'f' * 64


def graph():
    return [{'kind': 'container', 'role': 'target', 'target_id': name, 'id': format(number, '064x')}
        for number, name in enumerate(t.TARGET_IDS, 1)] + [
        {'kind': 'network', 'role': 'network', 'target_id': None, 'id': format(21, '064x')},
        {'kind': 'container', 'role': 'provisioner', 'target_id': None, 'id': format(22, '064x')},
        {'kind': 'container', 'role': 'helper', 'target_id': None, 'id': format(23, '064x')}]


class PureProofTests(unittest.TestCase):
    def test_graph_requires_twenty_unique_ordered_targets_and_exact_three_other_resources(self):
        t.validate_graph(graph())
        for change in ('missing', 'duplicate-target', 'duplicate-id', 'foreign-kind', 'reorder', 'extra-field'):
            value = graph()
            if change == 'missing': value.pop()
            elif change == 'duplicate-target': value[19]['target_id'] = value[18]['target_id']
            elif change == 'duplicate-id': value[19]['id'] = value[18]['id']
            elif change == 'foreign-kind': value[19]['kind'] = 'image'
            elif change == 'reorder': value.reverse()
            else: value[0]['unexpected'] = 'SYNTHETIC'
            with self.subTest(change=change), self.assertRaises(t.TwentyError): t.validate_graph(value)

    def test_totals_recompute_original_rows_and_log_limits_are_explicit(self):
        point = {'containers': [{'usage': {'memory_current_bytes': 12, 'pids_current': 3},
            'writable_layer_bytes': 17, 'log_tail': {'captured_bytes': 19, 'maximum_bytes': 65536,
                'maximum_lines': 1000, 'full_history': False, 'truncated': False}}],
            'totals': {'memory_current_bytes': 12, 'pids_current': 3, 'writable_layer_bytes': 17,
                'log_tail_captured_bytes': 19}}
        self.assertEqual(t.sample_totals(point), point['totals'])
        for key in point['totals']:
            value = deepcopy(point); value['totals'][key] += 1
            with self.subTest(key=key), self.assertRaises(t.TwentyError): t.sample_totals(value)
        for key, bad in (('maximum_bytes', 65537), ('truncated', 0), ('full_history', True), ('captured_bytes', -1)):
            value = deepcopy(point); value['containers'][0]['log_tail'][key] = bad
            with self.subTest(key=key), self.assertRaises(t.TwentyError): t.sample_totals(value)

    def test_functional_twenty_grid_cannot_credit_missing_or_failed_target(self):
        targets = {row['target_id']: row['id'] for row in graph()[:20]}
        plan = {'target_plan': {'profile': 'twenty-targets', 'target_ids': list(t.TARGET_IDS)},
            'target_resource_ids': targets, 'controller_concurrency': 4, 'plan_sha256': 'b' * 64}
        rows = [{'target_id': name, 'check_id': check, 'required': True, 'status': 'pass'}
            for name in t.TARGET_IDS for check in t.v.CHECKS]
        result = {'status': 'passed', 'unknown_outcome': False, 'primary_failure': None,
            'attempted_targets': list(t.TARGET_IDS), 'blocked_targets': {}, 'checks': rows}
        report = {'result': result, 'text': '\n'.join(row['target_id'] + ' / ' + row['check_id'] + ': pass' for row in rows)}
        with patch.object(t, 'read_json', return_value=plan), patch.object(t, 'report_batch_validation', return_value=report), \
                patch.object(t, 'fingerprint', return_value={}) :
            self.assertEqual(t.functional_summary(Mock(), targets, 4)['passed_rows'], 200)
            result['checks'] = rows[:-1]
            with self.assertRaises(t.TwentyError): t.functional_summary(Mock(), targets, 4)
            result['checks'] = deepcopy(rows); result['checks'][-1]['status'] = 'unverified'
            with self.assertRaises(t.TwentyError): t.functional_summary(Mock(), targets, 4)

    def test_cli_typed_concurrency_and_fixed_no_workspace_replay(self):
        options = cli.parser().parse_args(['twenty-check', '--sentinel-id', SENTINEL, '--concurrency', '2'])
        self.assertEqual(options.concurrency, 2)
        self.assertFalse(hasattr(options, 'workspace'))

    def test_usage_replay_binds_original_runtime_limits_totals_and_oom(self):
        from tests.test_fleet_samples import pair
        from wormhole.runs import common
        first, last = pair()
        runtime = {'targets_live': {}}
        for point in (first, last):
            point.update(guaranteed_peak=False, disk_quota=False, production_iso_eligible=False)
            for row in point['containers']:
                role = row['role']; expected = t.admission._projection(t.admission.load_profile('twenty-targets')['limits'][role])['docker_create']
                row['usage']['limits'] = {'memory.max': str(expected['memory_bytes']), 'memory.swap.max': '0',
                    'cpu.max': str(expected['nano_cpus'] // 10000) + ' 100000', 'pids.max': str(expected['pids_limit'])}
                row['usage']['memory_events'] = {'oom': 0, 'oom_kill': 0}
                row['log_tail'] = {'captured_bytes': 0, 'maximum_bytes': 65536, 'maximum_lines': 1000,
                    'truncated': False, 'full_history': False}
                observed = {'Id': row['resource_id'], 'Image': row['image_id'],
                    'State': {'Running': True, 'Pid': row['usage']['pid']}}
                if role == 'target': runtime['targets_live'][row['target_id']] = observed
                else: runtime[role] = observed
            point['totals'] = {'memory_current_bytes': 22528, 'pids_current': 88,
                'writable_layer_bytes': 2706, 'log_tail_captured_bytes': 0}
        bound_graph = graph(); bound_graph[20]['id'] = format(23, '064x'); bound_graph[22]['id'] = format(21, '064x')
        run = SimpleNamespace(manifest=lambda: common(first), file=lambda relative: relative)
        files = {t.SAMPLE_BEFORE: first, t.SAMPLE_AFTER: last, 'private/twenty-runtime.json': runtime,
            t.USAGE: t.compare_samples(first, last)}
        with patch.object(t, 'read_json', side_effect=lambda path: deepcopy(files[path])), patch.object(t, 'fingerprint', return_value={}):
            self.assertEqual(t.usage_summary(run, bound_graph)['container_count'], 22)
            for mode in ('pid', 'image', 'oom', 'totals', 'limit', 'claim'):
                originals = deepcopy(files)
                if mode == 'pid': runtime['targets_live']['target-020']['State']['Pid'] += 1
                elif mode == 'image': runtime['targets_live']['target-020']['Image'] = 'sha256:' + 'd' * 64
                elif mode == 'oom': first['containers'][-1]['usage']['memory_events']['oom'] = 1
                elif mode == 'totals': first['totals']['memory_current_bytes'] -= 1
                elif mode == 'limit':
                    for point in (first,last): point['containers'][0]['usage']['limits']['memory.max'] = '9999999'
                    files[t.USAGE] = t.compare_samples(first,last)
                else: first['guaranteed_peak'] = True
                with self.subTest(mode=mode), self.assertRaises(RunError): t.usage_summary(run, bound_graph)
                files.clear(); files.update(originals)
                first, last, runtime = files[t.SAMPLE_BEFORE], files[t.SAMPLE_AFTER], files['private/twenty-runtime.json']
        for bad in ('0', '5', '20', 'true'):
            with patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                cli.parser().parse_args(['twenty-check', '--sentinel-id', SENTINEL, '--concurrency', bad])
        options = cli.parser().parse_args(['twenty-report', '53727065-09e4-4ad7-81e5-2f2679a925a6'])
        self.assertFalse(hasattr(options, 'workspace'))

    def test_cli_returns_failure_and_exact_run_identity_for_refusal(self):
        error = t.TwentyError('capacity_refused', 'Synthetic bounded refusal')
        error.run_id = '53727065-09e4-4ad7-81e5-2f2679a925a6'
        out = io.StringIO()
        with patch.object(t, 'acceptance', side_effect=error), patch('sys.stdout', out):
            self.assertEqual(cli.main(['twenty-check', '--sentinel-id', SENTINEL]), 2)
        self.assertEqual(json.loads(out.getvalue())['run_id'], error.run_id)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Disposable original Linux Run locks, synthetic domain adapters')
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wormhole-synthetic-twenty-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.runs = Path(self.tmp.name) / 'runs'
        self.patch(t.images, 'RUNS_ROOT', self.runs)
        self.patch(t, 'source_identity', return_value=(SHA, False))
        self.patch(t, 'create_run', side_effect=lambda root, **kw: create_run(root, identity=(SHA, False), **kw))
        self.patch(t.images, 'create_auth')
        self.patch(t.images, 'docker_scope', side_effect=lambda _: nullcontext())
        self.patch(t.images, 'docker', side_effect=AssertionError('Actual Docker forbidden in synthetic fixture'))
        self.patch(t, 'snapshot', return_value='c' * 64)
        self.lease = SimpleNamespace(plan={'requirements': {'runtime_memory_bytes': 1000, 'pids_peak': 1000, 'disk_bytes': 1000}}, finish=Mock())
        self.admission = self.patch(t.admission, 'AdmissionLease', return_value=nullcontext(self.lease))
        self.ps = SimpleNamespace(target_resources={row['target_id']: row['id'] for row in graph()[:20]},
            network_id=graph()[20]['id'], provisioner=graph()[21]['id'], create_stopped=Mock(),
            start_and_inventory=Mock(), verify_target=Mock(), verify_provisioner=Mock(), receipt={'primary_failure': None})
        def fail(error):
            self.ps.receipt['primary_failure'] = {'code': getattr(error, 'code', 'cleanup_failed'), 'recorded_at': '2026-10-24T17:00:00Z'}
        self.ps.failure = fail
        self.patch(t, 'ProvisioningSession', return_value=self.ps)
        self.ready = SimpleNamespace(helper=graph()[22]['id'], start_helper=Mock(), wait_ready=Mock(), verify_helper=Mock(), receipt={'primary_failure': None})
        self.patch(t, 'BatchReadinessSession', return_value=self.ready)
        self.validation = SimpleNamespace(validate=Mock(), require_passed=Mock())
        self.patch(t, 'BatchValidationSession', return_value=self.validation)
        self.inventory = SimpleNamespace(collect=Mock(), require_passed=Mock())
        module = ModuleType('wormhole.fleet_inventory'); module.FleetInventorySession = Mock(return_value=self.inventory)
        replay = ModuleType('wormhole.twenty_replay'); replay.RUNTIME = 'private/twenty-runtime.json'
        # Mutate the import cache in place. Replacing sys.modules itself can
        # leave CPython's original cached modules active after full discovery.
        modules = patch.dict(sys.modules, {'wormhole.fleet_inventory': module, 'wormhole.twenty_replay': replay})
        modules.start(); self.addCleanup(modules.stop)
        self.inventory_factory = module.FleetInventorySession
        self.patch(t.images, 'inspect', side_effect=lambda kind, identifier:
            {'Id': identifier, 'State': {'Pid': 0, 'Status': 'created', 'StartedAt': '0001-01-01T00:00:00Z'},
             'HostConfig': {'PidsLimit': 64}})
        for name in ('readiness_summary', 'functional_summary', 'inventory_summary', 'usage_summary', 'archive_summary', 'fingerprint', 'original_summary'):
            self.patch(t, name, return_value={'synthetic': True})
        self.patch(t, 'collect_sample', return_value={'totals': {'memory_current_bytes': 1, 'pids_current': 1, 'writable_layer_bytes': 1}})
        self.patch(t, 'compare_samples', return_value={'synthetic': True})
        self.patch(t, 'scan_private_material', return_value={'status': 'pass'})
        self.patch(t, 'disk_sample', return_value={'synthetic': True})
        self.cleanup = self.patch(t, 'cleanup_session', return_value={'status': 'completed', 'unknown_outcome': False, 'primary_failure': None})
        from wormhole import candidate_acceptance
        self.sweep = self.patch(candidate_acceptance, 'sweep')
        self.patch(t, 'report_twenty', side_effect=lambda run: read_json(run.file(t.EVIDENCE)))
        self.patch(t, 'gate_twenty', return_value={'stock_twenty_scope_complete': True})

    def patch(self, obj, key, *args, **kwargs):
        item = patch.object(obj, key, *args, **kwargs); value = item.start(); self.addCleanup(item.stop); return value

    def only_receipt(self):
        paths = list(self.runs.glob('*/' + t.EVIDENCE)); self.assertEqual(len(paths), 1)
        return read_json(paths[0])

    def test_coordinator_allocates_full_twenty_once_and_replays_after_exact_cleanup(self):
        try:
            value = t.acceptance(SENTINEL, controller_concurrency=2)
        except t.TwentyError as error:
            self.fail('Synthetic adapter failure: ' + repr(error.__context__))
        self.assertEqual(value['status'], 'passed'); self.assertEqual(value['target_count'], 20)
        self.assertEqual(len(value['owned_resources']), 23); self.assertEqual(len(value['stopped_targets']), 20)
        self.assertFalse(value['reference_eligible']); self.assertFalse(value['production_iso_eligible'])
        self.admission.assert_called_once(); self.ps.create_stopped.assert_called_once(); self.cleanup.assert_called_once()
        self.lease.finish.assert_called_once_with(reconciliation_complete=True)
        self.inventory_factory.assert_called_once_with(self.ready, controller_concurrency=2)

    def test_capacity_refusal_has_no_domain_or_cleanup_allocation_and_durable_failed_attempt(self):
        self.admission.side_effect = t.admission.AdmissionError('capacity_refused', 'Synthetic private diagnostic')
        with self.assertRaises(t.TwentyError) as caught: t.acceptance(SENTINEL)
        self.assertEqual(caught.exception.code, 'capacity_refused')
        self.ps.create_stopped.assert_not_called(); self.cleanup.assert_not_called()
        value = self.only_receipt(); self.assertEqual(value['owned_resources'], [])
        self.assertFalse(value['stock_twenty_scope_complete']); self.assertEqual(value['status'], 'failed')
        self.assertNotIn('private diagnostic', json.dumps(value))

    def test_functional_failure_preserves_first_primary_and_always_cleans_without_inventory(self):
        self.validation.require_passed.side_effect = RunError('synthetic_functional_failure', 'PRIVATE FIXTURE')
        with self.assertRaises(RunError): t.acceptance(SENTINEL)
        self.cleanup.assert_called_once(); self.inventory.collect.assert_not_called()
        value = self.only_receipt(); self.assertEqual(value['primary_failure'], self.ps.receipt['primary_failure'])
        self.assertEqual(value['status'], 'failed'); self.assertFalse(value['stock_twenty_scope_complete'])

    def test_cleanup_unknown_preserves_original_primary_and_never_finishes_admission(self):
        self.validation.validate.side_effect = RunError('original_failure', 'PRIVATE FIXTURE')
        self.cleanup.return_value = {'status': 'failed', 'unknown_outcome': True, 'primary_failure': {'code': 'cleanup_later'}}
        with self.assertRaises(RunError): t.acceptance(SENTINEL)
        self.lease.finish.assert_not_called(); self.sweep.assert_not_called()
        self.assertEqual(self.only_receipt()['primary_failure'], self.ps.receipt['primary_failure'])

    def test_invalid_operation_concurrency_refuses_before_auth_or_run_creation(self):
        for bad in (True, 0, 5, 20, '4'):
            with self.subTest(bad=bad), self.assertRaises(t.TwentyError): t.acceptance(SENTINEL, controller_concurrency=bad)
        self.admission.assert_not_called(); t.images.create_auth.assert_not_called()


if __name__ == '__main__': unittest.main()
