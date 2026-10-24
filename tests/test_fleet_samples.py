"""Synthetic counters/identities and disposable Linux nodes; no Docker access."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import fleet_samples as f

ID = 'a' * 64
EXPECTED = {'memory_bytes': 256 * 1024**2, 'nano_cpus': 250_000_000, 'pids_limit': 64}
# Actual key spellings observed by the separate read-only host diagnostic.
# These values are synthetic; this fixture is not a live CPU measurement.
CPU_STAT = ('usage_usec 100000\nuser_usec 60000\nsystem_usec 40000\ncore_sched.force_idle_usec 0\n'
    'nr_periods 80\nnr_throttled 2\nthrottled_usec 400\nnr_bursts 0\nburst_usec 0')
CPU_REQUIRED = ('usage_usec', 'user_usec', 'system_usec')


def pair():
    first = {'schema_version': '1.0', 'run_id': '53727065-09e4-4ad7-81e5-2f2679a925a6',
        'source_revision': 'b' * 40, 'source_dirty': False, 'mode': 'container-reference',
        'operation': 'twenty-owned-point-sample-v1', 'profile': 'twenty-targets', 'target_count': 20, 'phase': 'before-checks',
        'started_monotonic': 10.0, 'finished_monotonic': 20.0, 'containers': []}
    for number in range(1, 23):
        first['containers'].append({'target_id': 'target-' + str(number).zfill(3) if number <= 20 else None,
            'role': 'target' if number <= 20 else 'helper' if number == 21 else 'provisioner',
            'resource_id': format(number, '064x'), 'image_id': 'sha256:' + 'c' * 64,
            'writable_layer_bytes': 123, 'usage': {'pid': number + 100, 'cgroup': 'synthetic/' + str(number),
                'cgroup_device': 1, 'cgroup_inode': number, 'limits': {'cpu.max': '25000 100000'},
                'monotonic': 15.0, 'cpu_stat': {'usage_usec': 100_000, 'user_usec': 50_000, 'system_usec': 50_000},
                'memory_current_bytes': 1024, 'pids_current': 4}})
    last = deepcopy(first)
    last.update(phase='after-checks', started_monotonic=30.0, finished_monotonic=40.0)
    for row in last['containers']:
        row['usage']['monotonic'] = 35.0
        row['usage']['cpu_stat'] = {'usage_usec': 5_100_000, 'user_usec': 2_550_000, 'system_usec': 2_550_000}
    return first, last


class PureSamples(unittest.TestCase):
    def test_usage_is_delta_over_actual_elapsed_and_not_quota_or_claimed_peak(self):
        first, last = pair(); before = deepcopy((first, last))
        result = f.compare_samples(first, last)
        self.assertEqual(len(result['containers']), 22)
        self.assertEqual(result['target_count'], 20)
        self.assertEqual(result['containers'][0]['elapsed_seconds'], 20)
        self.assertEqual(result['containers'][0]['observed_average_cpu_cores'], .25)
        self.assertEqual(result['containers'][0]['cpu_delta_usec']['usage_usec'], 5_000_000)
        self.assertFalse(result['guaranteed_peak']); self.assertFalse(result['disk_quota'])
        self.assertEqual((first, last), before)

    def test_wrong_run_profile_or_missing_resource_refuses(self):
        for field, wrong in (('run_id', 'different'), ('source_revision', 'd' * 40),
                ('profile', 'five-targets'), ('phase', 'before-checks')):
            first, last = pair(); last[field] = wrong
            with self.subTest(field=field), self.assertRaises(f.SamplingError): f.compare_samples(first, last)
        first, last = pair(); last['containers'].pop()
        with self.assertRaises(f.SamplingError): f.compare_samples(first, last)

    def test_pid_cgroup_image_or_target_replacement_cannot_form_interval(self):
        for section, key, wrong in (('root', 'target_id', 'target-021'), ('root', 'image_id', 'foreign'),
                ('root', 'resource_id', 'f' * 64), ('usage', 'pid', 9999), ('usage', 'cgroup_inode', 999),
                ('usage', 'cgroup', 'foreign'), ('usage', 'limits', {'cpu.max': 'max 100000'})):
            first, last = pair(); row = last['containers'][0]
            target = row if section == 'root' else row['usage']; target[key] = wrong
            with self.subTest(key=key), self.assertRaises(f.SamplingError): f.compare_samples(first, last)

    def test_coordinated_duplicate_or_omitted_targets_in_both_samples_refuse(self):
        for changed in ('duplicate-target', 'duplicate-helper', 'shared-resource-id', 'wrong-count', 'reordered'):
            first, last = pair()
            for value in (first, last):
                if changed == 'duplicate-target': value['containers'][19] = deepcopy(value['containers'][18])
                elif changed == 'duplicate-helper': value['containers'][21] = deepcopy(value['containers'][20])
                elif changed == 'shared-resource-id': value['containers'][19]['resource_id'] = value['containers'][18]['resource_id']
                elif changed == 'wrong-count': value['target_count'] = True
                else: value['containers'][0], value['containers'][1] = value['containers'][1], value['containers'][0]
            with self.subTest(changed=changed), self.assertRaises(f.SamplingError): f.compare_samples(first, last)

    def test_reset_boolean_or_negative_cpu_counters_and_late_measurements_refuse(self):
        for wrong in (0, -1, True, 1.5):
            first, last = pair(); last['containers'][0]['usage']['cpu_stat']['usage_usec'] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(f.SamplingError): f.compare_samples(first, last)
        for wrong in (float('nan'), 29, 41):
            first, last = pair(); last['containers'][0]['usage']['monotonic'] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(f.SamplingError): f.compare_samples(first, last)
        first, last = pair(); last['started_monotonic'] = 19
        with self.assertRaises(f.SamplingError): f.compare_samples(first, last)

    def test_counter_parser_rejects_duplicates_missing_nonfinite_or_private_text(self):
        for value in ('-1', '01', '1\n', str(2**63), 'max', True, 'PRIVATE FIXTURE'):
            with self.subTest(value=value), self.assertRaises(f.SamplingError): f.counter(value)
        for value in ('usage_usec 1\nusage_usec 2', 'user_usec 2', 'usage_usec NaN', 'usage_usec 1 extra'):
            with self.subTest(value=value), self.assertRaises(f.SamplingError): f.counters(value, ('usage_usec',))

    def test_observed_dotted_kernel_key_shape_preserves_all_synthetic_counters(self):
        value = f.counters(CPU_STAT, CPU_REQUIRED)
        self.assertEqual(value, {'usage_usec': 100000, 'user_usec': 60000, 'system_usec': 40000,
            'core_sched.force_idle_usec': 0, 'nr_periods': 80, 'nr_throttled': 2, 'throttled_usec': 400,
            'nr_bursts': 0, 'burst_usec': 0})
        self.assertEqual(f.counters('oom 0\noom_kill 0\noom_group_kill 0', ('oom', 'oom_kill')),
            {'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0})

    def test_dotted_counter_names_require_nonempty_ascii_components_and_total64_bound(self):
        name = 'a' * 31 + '.' + 'b' * 32
        self.assertEqual(f.counters(name + ' 1', (name,)), {name: 1})
        for key in (name + 'b', '.core_sched', 'core_sched.', 'core_sched..force_idle_usec',
            'core_sched./force_idle_usec', r'core_sched.\force_idle_usec', 'core_sched.force-idle-usec',
            'Core_sched.force_idle_usec', 'core_sched.1force_idle_usec', 'core_sched.\x00force_idle_usec',
            'core_sched.\x1bforce_idle_usec', 'core_sched.f\u00f6rce_idle_usec', 'core_sched.force idle_usec'):
            with self.subTest(key=key), self.assertRaises(f.SamplingError): f.counters(key + ' 1', ())

    def test_extra_dotted_counter_cannot_hide_duplicates_or_invalid_values(self):
        for extra in ('core_sched.force_idle_usec 0', 'usage_usec 2', 'core_sched.force_idle_usec -1',
            'core_sched.force_idle_usec 01', 'core_sched.force_idle_usec NaN', 'core_sched.force_idle_usec max',
            'core_sched.force_idle_usec ' + str(2**63), 'core_sched.force_idle_usec 1 extra'):
            with self.subTest(extra=extra), self.assertRaises(f.SamplingError): f.counters(CPU_STAT + '\n' + extra, CPU_REQUIRED)
        # Validate an optional field's value too, rather than ignoring it.
        for value in ('-1', '01', str(2**63), 'NaN', 'max'):
            with self.subTest(value=value), self.assertRaises(f.SamplingError):
                f.counters('usage_usec 1\ncore_sched.force_idle_usec ' + value, ('usage_usec',))

    def test_required_cpu_oom_fields_and_counter_line_bound_remain_mandatory(self):
        for required in CPU_REQUIRED:
            raw = '\n'.join(row for row in CPU_STAT.splitlines() if not row.startswith(required + ' '))
            with self.subTest(missing=required), self.assertRaises(f.SamplingError): f.counters(raw, CPU_REQUIRED)
        for raw in ('oom 0', 'oom_kill 0', 'oom.extra 0\noom_kill 0'):
            with self.subTest(raw=raw), self.assertRaises(f.SamplingError): f.counters(raw, ('oom', 'oom_kill'))
        rows = ['usage_usec 0'] + ['optional.field_' + str(i) + ' 0' for i in range(31)]
        self.assertEqual(len(f.counters('\n'.join(rows), ('usage_usec',))), 32)
        with self.assertRaises(f.SamplingError): f.counters('\n'.join(rows + ['optional.extra 0']), ('usage_usec',))

    def test_unsupported_platform_refuses_before_any_inspection(self):
        with patch.object(f.sys, 'platform', 'win32'), patch.object(f.images, 'inspect') as inspection:
            with self.assertRaises(f.SamplingError): f.collect_sample(None, None, 'before-checks')
        inspection.assert_not_called()

    def test_foreign_unregistered_container_refuses_before_docker(self):
        ids = tuple('target-' + str(number).zfill(3) for number in range(1, 21))
        run = SimpleNamespace(id='synthetic-run', manifest=lambda: {'profile': 'twenty-targets'})
        lease = SimpleNamespace(record={'resources': []})
        ps = SimpleNamespace(run=run, lease=lease, target_plan=SimpleNamespace(target_ids=ids),
            target_resources={name: format(number, '064x') for number, name in enumerate(ids, 1)},
            provisioner='e' * 64, network_id='d' * 64, held=Mock(), receipt={'unknown_outcome': False})
        ready = SimpleNamespace(run=run, lease=lease, helper='f' * 64, held=Mock(), receipt={'unknown_outcome': False})
        with patch.object(f.images, 'inspect') as inspection:
            with self.assertRaises(f.SamplingError): f.resources(ps, ready)
        inspection.assert_not_called()
        lease.record['resources'] = [{'kind': 'container', 'id': identifier, 'outcome': 'pending'} for identifier in
            (*ps.target_resources.values(), ready.helper, ps.provisioner)] + [
                {'kind': 'network', 'id': ps.network_id, 'outcome': 'pending'}]
        self.assertEqual(len(f.resources(ps, ready)), 22)
        lease.record['resources'][0]['outcome'] = 'absent'
        with self.assertRaises(f.SamplingError): f.resources(ps, ready)
        lease.record['resources'][0]['outcome'] = 'retained'
        with self.assertRaises(f.SamplingError): f.resources(ps, ready)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Disposable Linux proc/cgroup-style filesystem fixtures')
class KernelNodeFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wormhole-synthetic-cgroups-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.proc = self.root / 'proc'; self.cg = self.root / 'cgroup'
        (self.proc / '123').mkdir(parents=True)
        self.location = '/system.slice/docker-' + ID + '.scope'
        (self.proc / '123' / 'cgroup').write_text('0::' + self.location + '\n')
        self.folder = self.cg / self.location[1:]; self.folder.mkdir(parents=True)
        contents = {'memory.max': str(EXPECTED['memory_bytes']), 'memory.swap.max': '0',
            'cpu.max': '25000 100000', 'pids.max': '64', 'memory.current': '1024', 'memory.peak': '2048',
            'pids.current': '4', 'cpu.stat': CPU_STAT,
            'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0'}
        for name, value in contents.items(): (self.folder / name).write_text(value + '\n')
        a = patch.object(f, 'PROC_ROOT', self.proc); a.start(); self.addCleanup(a.stop)
        b = patch.object(f, 'CGROUP_ROOT', self.cg); b.start(); self.addCleanup(b.stop)

    def test_actual_disposable_nodes_are_bound_to_exact_container_and_limits(self):
        value = f.cgroup_sample(ID, 123, EXPECTED)
        self.assertEqual(value['memory_current_bytes'], 1024)
        self.assertEqual(value['pids_current'], 4)
        self.assertEqual(value['cpu_stat']['usage_usec'], 100000)
        self.assertEqual(value['cpu_stat']['core_sched.force_idle_usec'], 0)
        self.assertEqual(len(value['cpu_stat']), 9)
        self.assertEqual(value['memory_peak_status'], 'observed')
        self.assertEqual(value['cgroup'], self.location[1:])

    def test_missing_optional_peak_is_unavailable_not_zero(self):
        (self.folder / 'memory.peak').unlink()
        value = f.cgroup_sample(ID, 123, EXPECTED)
        self.assertIsNone(value['memory_peak_bytes']); self.assertEqual(value['memory_peak_status'], 'unsupported')

    def test_wrong_container_path_traversal_or_duplicate_unified_path_refuses(self):
        for location in ('0::/system.slice/docker-' + 'f' * 64 + '.scope', '0::/../../private',
                '0::' + self.location + '\n0::' + self.location):
            (self.proc / '123' / 'cgroup').write_text(location)
            with self.subTest(location=location), self.assertRaises(f.SamplingError): f.cgroup_sample(ID, 123, EXPECTED)

    def test_unsafe_link_oversized_node_or_wrong_actual_limit_refuses(self):
        peak = self.folder / 'memory.peak'; peak.unlink(); peak.symlink_to(self.root / 'absent')
        with self.assertRaises(f.SamplingError): f.cgroup_sample(ID, 123, EXPECTED)
        peak.unlink(); peak.write_text('2048')
        (self.folder / 'cpu.stat').write_text('x' * 4097)
        with self.assertRaises(f.SamplingError): f.cgroup_sample(ID, 123, EXPECTED)
        (self.folder / 'cpu.stat').write_text('usage_usec 1\nuser_usec 1\nsystem_usec 0')
        (self.folder / 'memory.max').write_text('max')
        with self.assertRaises(f.SamplingError): f.cgroup_sample(ID, 123, EXPECTED)


if __name__ == '__main__':
    unittest.main()
