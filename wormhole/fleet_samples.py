"""Read-only, exact-owned twenty-target cgroup/disk/log point observations.

The caller holds the Run lock, canonical lease and Docker scope. These samples
are observations, not guaranteed peaks, disk quotas or host-wide telemetry.
No Docker exec, host agent, package installation or arbitrary path is exposed.
"""
from fractions import Fraction
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

from . import images
from .runs import RunError, common, now

PROC_ROOT = Path('/proc')
CGROUP_ROOT = Path('/sys/fs/cgroup')
PHASES = ('before-checks', 'after-checks')
USAGE_FILES = ('memory.current', 'pids.current', 'cpu.stat', 'memory.events')
LIMIT_FILES = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
MAX_INTEGER = 2**63 - 1


class SamplingError(RunError):
    pass


def require(value, code='fleet_sample_invalid'):
    if not value:
        raise SamplingError(code, 'Owned-container measurement failed; retain source-bound diagnostics and normal cleanup.')


def integer(value):
    return type(value) is int and 0 <= value <= MAX_INTEGER


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def read_kernel_file(path, maximum=4096):
    """Small proc/cgroup nodes report size zero; inode identity still binds reads."""
    require(path.is_absolute(), 'fleet_sample_path')
    for item in (path, *path.parents): require(not item.is_symlink(), 'fleet_sample_path')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'fleet_sample_path')
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(identity(os.fstat(descriptor)) == identity(before), 'fleet_sample_changed')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream: raw = stream.read(maximum + 1)
        require(0 < len(raw) <= maximum and identity(os.fstat(descriptor)) == identity(before) and
            identity(path.lstat()) == identity(before), 'fleet_sample_changed')
        for item in (path, *path.parents): require(not item.is_symlink(), 'fleet_sample_path')
        return raw.decode('ascii').strip()
    except UnicodeError:
        raise SamplingError('fleet_sample_encoding', 'A kernel measurement was not bounded ASCII.') from None
    finally:
        os.close(descriptor)


def counter(value):
    require(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,18}', value), 'fleet_sample_counter')
    result = int(value); require(integer(result), 'fleet_sample_counter')
    return result


def counters(value, required):
    require(type(value) is str and 1 <= len(value.splitlines()) <= 32, 'fleet_sample_counters')
    result = {}
    for line in value.splitlines():
        fields = line.split()
        require(len(fields) == 2 and re.fullmatch('[a-z][a-z0-9_]{0,63}', fields[0]) and
            fields[0] not in result, 'fleet_sample_counters')
        result[fields[0]] = counter(fields[1])
    require(set(required) <= set(result), 'fleet_sample_counters')
    return result


def cgroup_sample(identifier, pid, expected):
    require(sys.platform.startswith('linux'), 'fleet_sample_platform')
    require(type(identifier) is str and re.fullmatch('[a-f0-9]{64}', identifier) and
        type(pid) is int and pid > 0, 'fleet_sample_identity')
    location = read_kernel_file(PROC_ROOT / str(pid) / 'cgroup')
    paths = [line[3:] for line in location.splitlines() if line.startswith('0::')]
    require(len(paths) == 1 and paths[0].startswith('/') and
        re.fullmatch(r'(?:[A-Za-z0-9_.:-]+/)*docker-' + identifier + r'\.scope', paths[0][1:]),
        'fleet_sample_cgroup_identity')
    folder = CGROUP_ROOT / paths[0][1:]
    for item in (folder, *folder.parents): require(not item.is_symlink(), 'fleet_sample_path')
    before = folder.stat()
    require(stat.S_ISDIR(before.st_mode), 'fleet_sample_path')
    limits = {name: read_kernel_file(folder / name) for name in LIMIT_FILES}
    quota = limits['cpu.max'].split()
    require(len(quota) == 2 and all(item.isdigit() for item in quota) and int(quota[1]) > 0 and
        limits['memory.max'] == str(expected['memory_bytes']) and limits['memory.swap.max'] == '0' and
        limits['pids.max'] == str(expected['pids_limit']) and
        Fraction(int(quota[0]), int(quota[1])) == Fraction(expected['nano_cpus'], 1_000_000_000),
        'fleet_sample_limits')
    memory = counter(read_kernel_file(folder / 'memory.current'))
    pids = counter(read_kernel_file(folder / 'pids.current'))
    cpu = counters(read_kernel_file(folder / 'cpu.stat'), ('usage_usec', 'user_usec', 'system_usec'))
    events = counters(read_kernel_file(folder / 'memory.events'), ('oom', 'oom_kill'))
    peak_path = folder / 'memory.peak'
    require(not peak_path.is_symlink(), 'fleet_sample_path')
    peak = counter(read_kernel_file(peak_path)) if peak_path.exists() else None
    after = folder.stat()
    require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and
        read_kernel_file(PROC_ROOT / str(pid) / 'cgroup') == location and
        memory <= expected['memory_bytes'] and pids <= expected['pids_limit'] and
        (peak is None or peak >= memory), 'fleet_sample_changed')
    return {'pid': pid, 'cgroup': paths[0][1:], 'cgroup_device': before.st_dev, 'cgroup_inode': before.st_ino,
        'limits': limits, 'memory_current_bytes': memory, 'memory_peak_bytes': peak,
        'memory_peak_status': 'observed' if peak is not None else 'unsupported',
        'pids_current': pids, 'cpu_stat': cpu, 'memory_events': events, 'monotonic': time.monotonic()}


def resources(provisioning, readiness):
    ps = provisioning
    require(ps.run.id == readiness.run.id and ps.lease is readiness.lease and ps.run.manifest()['profile'] == 'twenty-targets' and
        tuple(ps.target_plan.target_ids) == tuple('target-' + str(number).zfill(3) for number in range(1, 21)),
        'fleet_sample_scope')
    ps.held(); readiness.held()
    require(ps.receipt['unknown_outcome'] is False and readiness.receipt['unknown_outcome'] is False,
        'fleet_sample_unknown')
    result = [(target_id, 'target', ps.target_resources[target_id]) for target_id in ps.target_plan.target_ids]
    result.extend((('helper', 'helper', readiness.helper), ('provisioner', 'provisioner', ps.provisioner)))
    require(len(result) == 22 and len({row[2] for row in result}) == 22 and
        all(type(row[2]) is str and re.fullmatch('[a-f0-9]{64}', row[2]) for row in result),
        'fleet_sample_resource_set')
    graph = {(row['kind'], row['id']) for row in ps.lease.record['resources']}
    require(all(('container', row[2]) in graph for row in result), 'fleet_sample_resource_set')
    return result


def collect_sample(provisioning, readiness, phase):
    require(sys.platform.startswith('linux'), 'fleet_sample_platform')
    require(phase in PHASES and type(phase) is str, 'fleet_sample_phase')
    ps = provisioning; rows = resources(ps, readiness)
    value = {**common(ps.run.manifest()), 'operation': 'twenty-owned-point-sample-v1', 'profile': 'twenty-targets',
        'phase': phase, 'observed_at': now(), 'started_monotonic': time.monotonic(), 'target_count': 20,
        'containers': [], 'guaranteed_peak': False, 'disk_quota': False, 'production_iso_eligible': False}
    for target_id, role, identifier in rows:
        actual = images.inspect('container', identifier, size=True)
        require(actual['Id'] == identifier and actual['State']['Running'] is True, 'fleet_sample_identity')
        if role == 'target': ps.verify_target(actual, target_id=target_id)
        elif role == 'helper': readiness.verify_helper(actual)
        else: ps.verify_provisioner(actual)
        expected = ps.lease.plan['limits'][role]['docker_create']
        usage = cgroup_sample(identifier, actual['State']['Pid'], expected)
        require(integer(actual.get('SizeRw')), 'fleet_sample_disk')
        logs = images.docker(('logs', '--tail', '1000', identifier), timeout=10)
        require(type(logs['log']) is bytes and len(logs['log']) <= 65536 and
            type(logs['log_truncated']) is bool, 'fleet_sample_logs')
        again = images.inspect('container', identifier)
        require(again['Id'] == identifier and again['State']['Running'] is True and
            again['State']['Pid'] == usage['pid'], 'fleet_sample_identity_changed')
        value['containers'].append({'target_id': target_id if role == 'target' else None, 'role': role,
            'resource_id': identifier, 'image_id': actual['Image'], 'usage': usage,
            'writable_layer_bytes': actual['SizeRw'], 'log_tail': {'captured_bytes': len(logs['log']),
                'truncated': logs['log_truncated'], 'maximum_bytes': 65536, 'maximum_lines': 1000,
                'full_history': False}})
    value['finished_monotonic'] = time.monotonic()
    value['totals'] = {key: sum(row[field] if section is None else row[section][field] for row in value['containers'])
        for key, section, field in (('memory_current_bytes', 'usage', 'memory_current_bytes'),
            ('pids_current', 'usage', 'pids_current'), ('writable_layer_bytes', None, 'writable_layer_bytes'),
            ('log_tail_captured_bytes', 'log_tail', 'captured_bytes'))}
    require(len(json.dumps(value, allow_nan=False).encode()) <= 65536, 'fleet_sample_bound')
    return value


def compare_samples(first, last):
    require(first['operation'] == last['operation'] == 'twenty-owned-point-sample-v1' and
        common(first) == common(last) and first['profile'] == last['profile'] == 'twenty-targets' and
        first['phase'] == 'before-checks' and last['phase'] == 'after-checks' and
        first['source_dirty'] is False and first['mode'] == 'container-reference' and
        all(number(row[key]) for row in (first, last) for key in ('started_monotonic', 'finished_monotonic')) and
        first['started_monotonic'] <= first['finished_monotonic'] < last['started_monotonic'] <= last['finished_monotonic'] and
        len(first['containers']) == len(last['containers']) == 22,
        'fleet_sample_pair')
    output = []
    for a, b in zip(first['containers'], last['containers']):
        require(all(a[key] == b[key] for key in ('target_id', 'role', 'resource_id', 'image_id')), 'fleet_sample_pair_identity')
        x, y = a['usage'], b['usage']
        require(all(x[key] == y[key] for key in ('pid', 'cgroup', 'cgroup_device', 'cgroup_inode', 'limits')) and
            type(x['pid']) is int and x['pid'] > 0 and number(x['monotonic']) and number(y['monotonic']) and
            first['started_monotonic'] <= x['monotonic'] <= first['finished_monotonic'] and
            last['started_monotonic'] <= y['monotonic'] <= last['finished_monotonic'], 'fleet_sample_pair_identity')
        elapsed = y['monotonic'] - x['monotonic']
        require(all(integer(row['cpu_stat'][key]) for row in (x, y) for key in ('usage_usec', 'user_usec', 'system_usec')) and
            all(integer(row[key]) for row in (x, y) for key in ('memory_current_bytes', 'pids_current')) and
            integer(a['writable_layer_bytes']) and integer(b['writable_layer_bytes']), 'fleet_sample_counter')
        delta = {key: y['cpu_stat'][key] - x['cpu_stat'][key] for key in ('usage_usec', 'user_usec', 'system_usec')}
        require(all(integer(value) for value in delta.values()), 'fleet_sample_cpu_regressed')
        output.append({'resource_id': a['resource_id'], 'target_id': a['target_id'], 'role': a['role'],
            'elapsed_seconds': elapsed, 'cpu_delta_usec': delta,
            'observed_average_cpu_cores': delta['usage_usec'] / (elapsed * 1_000_000),
            'memory_current_bytes': [x['memory_current_bytes'], y['memory_current_bytes']],
            'pids_current': [x['pids_current'], y['pids_current']],
            'writable_layer_bytes': [a['writable_layer_bytes'], b['writable_layer_bytes']]})
    return {**common(first), 'operation': 'twenty-owned-usage-interval-v1', 'target_count': 20, 'containers': output,
        'method': 'Two identity-bound point samples spanning the declared checks; not guaranteed peak consumption.',
        'guaranteed_peak': False, 'disk_quota': False, 'production_iso_eligible': False}
