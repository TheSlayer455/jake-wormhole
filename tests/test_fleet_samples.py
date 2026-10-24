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


def pair():
    first = {'schema_version': '1.0', 'run_id': '53727065-09e4-4ad7-81e5-2f2679a925a6',
        'source_revision': 'b' * 40, 'source_dirty': False, 'mode': 'container-reference',
        'operation': 'twenty-owned-point-sample-v1', 'profile': 'twenty-targets', 'phase': 'before-checks',
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
            provisioner='e' * 64, held=Mock(), receipt={'unknown_outcome': False})
        ready = SimpleNamespace(run=run, lease=lease, helper='f' * 64, held=Mock(), receipt={'unknown_outcome': False})
        with patch.object(f.images, 'inspect') as inspection:
            with self.assertRaises(f.SamplingError): f.resources(ps, ready)
        inspection.assert_not_called()


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
            'pids.current': '4', 'cpu.stat': 'usage_usec 100000\nuser_usec 60000\nsystem_usec 40000\nnr_throttled 2',
            'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0'}
        for name, value in contents.items(): (self.folder / name).write_text(value + '\n')
        a = patch.object(f, 'PROC_ROOT', self.proc); a.start(); self.addCleanup(a.stop)
        b = patch.object(f, 'CGROUP_ROOT', self.cg); b.start(); self.addCleanup(b.stop)

    def test_actual_disposable_nodes_are_bound_to_exact_container_and_limits(self):
        value = f.cgroup_sample(ID, 123, EXPECTED)
        self.assertEqual(value['memory_current_bytes'], 1024)
        self.assertEqual(value['pids_current'], 4)
        self.assertEqual(value['cpu_stat']['usage_usec'], 100000)
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
