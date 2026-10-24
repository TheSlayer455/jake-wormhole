"""Bounded smoke isolation qualification; only an operator invokes allocation.

Live coordinator lifetimes overlap; canonical allocation intervals never do.
Faults terminate only an owned filesystem/control child or a coordinator whose
terminal Terraform destroy and exact absence have already been proved.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from uuid import uuid4

from . import admission, images
from .candidate_acceptance import sweep
from .provisioning import ProvisioningSession
from .provisioning_acceptance import snapshot
from .recovery import cleanup_session, recover_run, safe_code
from .runs import Run, RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, create_run, now, read_json, run_id, source_identity

RECEIPT = 'evidence/isolation-acceptance.json'
ROLES = ('a', 'b', 'busy', 'first-recovery', 'second-recovery', 'terminal-destroy', 'unreconciled')
WAIT_SECONDS = 120
START_SECONDS = 600
MAX_JSON = 262144


class IsolationError(RunError):
    pass


def require(value, code='isolation_acceptance_invalid'):
    if not value:
        raise IsolationError(code, 'Isolation qualification stopped; retain exact Run state, workers and admission evidence.')


def records():
    from . import isolation_records
    return isolation_records


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source(revision=None):
    current, dirty = source_identity()
    require(dirty is False and (revision is None or current == revision), 'isolation_source_changed')
    return current


def raw_file(path, maximum=MAX_JSON):
    _owned(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 'isolation_file_bound')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        identity = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        require(identity(os.fstat(descriptor)) == identity(before), 'isolation_file_changed')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and identity(os.fstat(descriptor)) == identity(before) and
                identity(path.lstat()) == identity(before), 'isolation_file_changed')
        return raw
    finally:
        os.close(descriptor)


def fresh(*, authentication=True):
    revision = source()
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    require(run.manifest()['source_revision'] == revision, 'isolation_source_changed')
    if authentication:
        try:
            images.create_auth(run)  # Owns its own Run lock; never nest this call.
        except BaseException as error:
            error.run_id = run.id
            raise
    return run


def track(suite, name, identifiers):
    require(name in records().CASE_NAMES and len(identifiers) <= 4 and len(set(identifiers)) == len(identifiers), 'isolation_run_reused')
    for identifier in identifiers:
        run_id(identifier)
        require(identifier != suite.id, 'isolation_run_reused')
    atomic_json(suite.file('private/isolation-run-ids-' + name + '.json'),
        {**common(suite.manifest()), 'case': name, 'run_ids': identifiers})


def case_runs(suite, name, count):
    result = []
    for _ in range(count):
        result.append(fresh())
        track(suite, name, [run.id for run in result])
    return result


def ipc(suite, folder, role):
    require(role in ROLES and folder in ('controls', 'workers', 'logs'), 'isolation_worker_scope')
    directory = suite.file('private/isolation-' + folder)
    directory.mkdir(mode=0o700, exist_ok=True); _owned(directory, directory=True)
    return directory / (role + ('.log' if folder == 'logs' else '.json'))


def command(suite, run, role, value='wait', sequence=0):
    require(value in ('wait', 'cleanup', 'unlock', 'exit') and type(sequence) is int and 0 <= sequence <= 3, 'isolation_control')
    atomic_json(ipc(suite, 'controls', role), {**common(suite.manifest()), 'operation': 'isolation-control-v1',
        'target_run_id': run.id, 'role': role, 'command': value, 'sequence': sequence})


def control(suite, run, role):
    value = read_json(ipc(suite, 'controls', role))
    require(set(value) == {*common(suite.manifest()), 'operation', 'target_run_id', 'role', 'command', 'sequence'} and
            common(value) == common(suite.manifest()) and value['operation'] == 'isolation-control-v1' and
            value['target_run_id'] == run.id and value['role'] == role and
            value['command'] in ('wait', 'cleanup', 'unlock', 'exit') and type(value['sequence']) is int and
            0 <= value['sequence'] <= 3, 'isolation_control')
    return value


def event(suite, run, role, phase, previous=None, **details):
    value = {} if previous is None else deepcopy(previous)
    stamp = time.monotonic()
    value.update({**common(run.manifest()), 'operation': 'isolation-worker-v1', 'suite_run_id': suite.id,
                  'role': role, 'pid': os.getpid(), 'phase': phase, 'monotonic': stamp, **details})
    value.setdefault('events', []).append({'phase': phase, 'monotonic': stamp})
    atomic_json(ipc(suite, 'workers', role), value)
    return value


def await_command(suite, run, role, expected, sequence, *, timeout=WAIT_SECONDS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = control(suite, run, role)
        if value['sequence'] == sequence:
            require(value['command'] == expected, 'isolation_control')
            return
        require(value['sequence'] < sequence, 'isolation_control')
        time.sleep(.03)
    require(False, 'isolation_control_timeout')


def archive(run):
    path = images.INFRASTRUCTURE / 'history' / (run.id + '.json')
    raw = raw_file(path); value = json.loads(raw)
    require(value['run_id'] == run.id and value['source_revision'] == run.manifest()['source_revision'] and
            value['state'] == 'finished' and value['phase'] == 'reconciling' and
            all(item['outcome'] == ('retained' if item['kind'] == 'image' else 'absent') for item in value['resources']),
            'isolation_archive_unfinished')
    return {'sha256': digest(raw), 'size_bytes': len(raw), 'resources': value['resources']}


def _active_worker(suite, run, role):
    value = None; session = None; lease = None
    try:
        with run.locked():
            with images.docker_scope(run), admission.AdmissionLease(images.INFRASTRUCTURE, run.id,
                    run.manifest()['source_revision'], 'smoke') as lease:
                acquired = time.monotonic()
                session = ProvisioningSession(run, lease)
                primary = None
                try:
                    inventory = session.provision()
                    require(session.receipt['unknown_outcome'] is False and len(inventory['targets']) == 1, 'isolation_graph_unknown')
                    names = {address: images.inspect('container' if address.startswith('docker_container.') else 'network', identifier)['Name']
                             for address, identifier in session.owned.items()}
                    value = event(suite, run, role, 'active', lease_acquired=acquired, inventory=inventory,
                        resources=deepcopy(lease.record['resources']), owned=deepcopy(session.owned),
                        provisioner_id=session.provisioner, resource_names=names, unknown_outcome=False)
                    await_command(suite, run, role, 'cleanup', 1)
                except BaseException as error:
                    primary = error
                    if session.receipt['primary_failure'] is None:
                        session.failure(error)
                finally:
                    if session.receipt['unknown_outcome'] is False:
                        try:
                            result = cleanup_session(session, lease, reason='failure' if session.receipt['primary_failure'] else 'success')
                            require(result['status'] == 'completed' and result['unknown_outcome'] is False, 'isolation_cleanup_failed')
                            lease.finish(reconciliation_complete=True)
                        except BaseException as cleanup_error:
                            if primary is None:
                                primary = cleanup_error
                if primary is not None:
                    raise primary
            value = event(suite, run, role, 'lease-finished', value, lease_released=time.monotonic(), archive=archive(run))
            # No resource graph remains. Let A stay alive while B uses its
            # independent finite provisioning/cleanup budgets, without changing
            # any target/helper/controller lifetime.
            await_command(suite, run, role, 'unlock', 2, timeout=START_SECONDS + WAIT_SECONDS)
        value = event(suite, run, role, 'unlocked', value, run_lock_released=time.monotonic())
        await_command(suite, run, role, 'exit', 3, timeout=START_SECONDS + WAIT_SECONDS)
        event(suite, run, role, 'completed', value)
    except BaseException as error:
        event(suite, run, role, 'failed', value, error_code=safe_code(error),
              unknown_outcome=None if session is None else session.receipt['unknown_outcome'])
        raise


def _probe_worker(suite, run, role):
    calls = {'collector': 0, 'docker': 0}
    def forbidden_collector(_root):
        calls['collector'] += 1
        require(False, 'isolation_unexpected_admission')
    def forbidden_docker(*_args, **_kwargs):
        calls['docker'] += 1
        require(False, 'isolation_probe_reached_docker')
    original = images.docker; images.docker = forbidden_docker
    caught = None
    try:
        if role in ('first-recovery', 'second-recovery'):
            recover_run(run)
        else:
            with run.locked(), admission.AdmissionLease(images.INFRASTRUCTURE, run.id, run.manifest()['source_revision'],
                    'smoke', collector=forbidden_collector):
                require(False, 'isolation_unexpected_admission')
    except BaseException as error:
        caught = safe_code(error)
    finally:
        images.docker = original
    event(suite, run, role, 'completed', refusal_code=caught, collector_calls=calls['collector'], docker_calls=calls['docker'])


def worker(role, suite_id, target_id):
    require(sys.platform.startswith('linux') and role in ROLES, 'isolation_worker_scope')
    suite = Run(images.RUNS_ROOT, run_id(suite_id)); run = Run(images.RUNS_ROOT, run_id(target_id))
    require(common(suite.manifest())['source_revision'] == source(run.manifest()['source_revision']) and
            run.manifest()['mode'] == suite.manifest()['mode'] == 'container-reference' and run.id != suite.id,
            'isolation_worker_scope')
    require(run.manifest()['source_dirty'] is False and suite.manifest()['source_dirty'] is False and
            run.manifest()['profile'] == suite.manifest()['profile'] == 'smoke', 'isolation_worker_scope')
    control(suite, run, role)
    if role in ('a', 'b'):
        _active_worker(suite, run, role)
    elif role in ('busy', 'unreconciled', 'first-recovery', 'second-recovery'):
        _probe_worker(suite, run, role)
    elif role == 'terminal-destroy':
        from .recovery_acceptance import _worker
        _worker(run)


class OwnedProcess:
    """Only an exact locally created Popen handle; never adopt a stored PID."""
    def __init__(self, suite, run, role):
        self.suite, self.run, self.role = suite, run, role
        command(suite, run, role)
        self.log = ipc(suite, 'logs', role)
        descriptor = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            self.process = subprocess.Popen((sys.executable, '-B', '-m', 'wormhole.isolation_worker', role, suite.id, run.id),
                cwd=SOURCE_ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, close_fds=True,
                env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
                     'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'GIT_TERMINAL_PROMPT': '0'})

    def alive(self):
        require(self.process.poll() is None, 'isolation_worker_exited')
        require(self.log.stat().st_size <= 65536, 'isolation_worker_output_bound')

    def wait(self, phase, timeout=START_SECONDS):
        deadline = time.monotonic() + timeout
        path = ipc(self.suite, 'workers', self.role)
        while time.monotonic() < deadline:
            require(self.log.stat().st_size <= 65536, 'isolation_worker_output_bound')
            if path.exists():
                value = json.loads(raw_file(path))
                require(common(value) == common(self.run.manifest()) and value['role'] == self.role and
                        value['suite_run_id'] == self.suite.id and type(value['pid']) is int and
                        value['pid'] == self.process.pid, 'isolation_worker_identity')
                require(value['phase'] != 'failed', 'isolation_worker_failed')
                if value['phase'] == phase:
                    return value
            self.alive(); time.sleep(.03)
        require(False, 'isolation_worker_timeout')

    def finish(self):
        require(self.process.wait(timeout=10) == 0 and self.log.stat().st_size <= 65536, 'isolation_worker_failed')


def probe(suite, run, role, expected):
    process = OwnedProcess(suite, run, role)
    value = process.wait('completed', timeout=15); process.finish()
    require(value['refusal_code'] == expected and value['collector_calls'] == value['docker_calls'] == 0,
            'isolation_expected_refusal_missing')
    return value


def stable_run(run):
    """Internal comparison only; credential bytes/hashes never escape."""
    paths = ['manifest.json', 'owner.json', 'inventory.json', 'private/terraform/controller.json',
             'private/terraform/terraform.tfstate']
    for directory in ('evidence', 'private/terraform/operations'):
        folder = run.file(directory)
        if folder.exists():
            for root, children, files in os.walk(folder, followlinks=False):
                require(len(children) <= 32 and all(not (Path(root) / name).is_symlink() for name in children), 'isolation_file_bound')
                paths.extend((Path(root) / name).relative_to(run.path).as_posix() for name in files)
                require(len(paths) <= 512, 'isolation_file_bound')
    result = {}
    for relative in sorted(set(paths)):
        path = run.file(relative)
        if path.exists():
            result[relative] = raw_file(path, 2 * 1024 * 1024)
    for relative in ('private/credentials/id_ed25519', 'private/credentials/id_ed25519.pub', 'private/credentials/auth.json'):
        result[relative] = raw_file(run.file(relative), 8192)
    return result


def distinct_auth(runs):
    private = [raw_file(run.file('private/credentials/id_ed25519'), 8192) for run in runs]
    public = [raw_file(run.file('private/credentials/id_ed25519.pub'), 8192) for run in runs]
    require(len(set(private)) == len(runs) and len(set(public)) == len(runs) and
            len({str(run.file('private/credentials')) for run in runs}) == len(runs), 'isolation_auth_collision')
    return True  # No private/public key bytes or private hashes in evidence.


def resource_snapshots(value):
    expected = [('container', value['provisioner_id'])] + [
        ('container' if address.startswith('docker_container.') else 'network', identifier)
        for address, identifier in value['owned'].items()]
    return {(kind, identifier): snapshot(kind, identifier) for kind, identifier in expected}


def overlap(suite, sentinel):
    a, busy, b = case_runs(suite, 'overlap', 3)
    require(len({a.id, busy.id, b.id, suite.id}) == 4, 'isolation_run_reused')
    authentication = distinct_auth((a, busy, b))
    with images.docker_scope(suite):
        sentinel_before = snapshot('container', sentinel, unrelated=True)
        first = OwnedProcess(suite, a, 'a'); av = first.wait('active')
        original_journal = raw_file(images.INFRASTRUCTURE / 'admission.json')
        a_live = resource_snapshots(av); a_before = stable_run(a)
        refused = probe(suite, busy, 'busy', 'infrastructure_busy')
        sweep(busy)
        require(raw_file(images.INFRASTRUCTURE / 'admission.json') == original_journal and
                resource_snapshots(av) == a_live and stable_run(a) == a_before, 'isolation_busy_changed_owner')
        command(suite, a, 'a', 'cleanup', 1); a_done = first.wait('lease-finished')
        first.alive(); a_after = stable_run(a); a_archive = archive(a)
        second = OwnedProcess(suite, b, 'b'); bv = second.wait('active')
        first.alive(); second.alive()
        require(a_done['lease_released'] <= bv['lease_acquired'], 'isolation_overlapping_graphs')
        require(set(av['owned'].values()).isdisjoint(bv['owned'].values()) and av['provisioner_id'] != bv['provisioner_id'] and
                set(av['resource_names'].values()).isdisjoint(bv['resource_names'].values()) and
                av['inventory']['run_id'] != bv['inventory']['run_id'] and av['inventory']['targets'][0]['resource_id'] !=
                bv['inventory']['targets'][0]['resource_id'], 'isolation_resource_collision')
        b_live = resource_snapshots(bv); b_state = stable_run(b); journal = raw_file(images.INFRASTRUCTURE / 'admission.json')
        first_refusal = probe(suite, a, 'first-recovery', 'run_busy')
        require(stable_run(a) == a_after, 'isolation_a_changed')
        command(suite, a, 'a', 'unlock', 2); a_unlocked = first.wait('unlocked')
        first.alive(); second.alive()
        second_refusal = probe(suite, a, 'second-recovery', 'infrastructure_busy')
        require(stable_run(a) == a_after and archive(a) == a_archive and stable_run(b) == b_state and
                resource_snapshots(bv) == b_live and raw_file(images.INFRASTRUCTURE / 'admission.json') == journal,
                'isolation_cross_run_change')
        command(suite, b, 'b', 'cleanup', 1); b_done = second.wait('lease-finished')
        command(suite, b, 'b', 'unlock', 2); second.wait('unlocked')
        command(suite, b, 'b', 'exit', 3); b_final = second.wait('completed'); second.finish()
        first.alive(); command(suite, a, 'a', 'exit', 3); a_final = first.wait('completed'); first.finish()
        sweep(a); sweep(b)
        require(snapshot('container', sentinel, unrelated=True) == sentinel_before, 'isolation_sentinel_changed')
    require(av['lease_acquired'] < a_done['lease_released'] <= bv['lease_acquired'] < a_unlocked['run_lock_released'] <
            b_done['lease_released'] <= b_final['monotonic'] < a_final['monotonic'], 'isolation_intervals_invalid')
    checks = {key: True for key in records().checks_for('overlap')}
    require(authentication, 'isolation_auth_collision')
    return [a.id, busy.id, b.id], {'checks': checks, 'overlap_model': 'overlapping-live-processes-serialized-resource-graphs',
        'finite_budgets': {'startup_observation_seconds': START_SECONDS, 'active_control_seconds': WAIT_SECONDS,
                          'resource_free_report_barrier_seconds': START_SECONDS + WAIT_SECONDS},
        'a_events': a_final['events'], 'b_events': b_final['events'], 'a_pid': first.process.pid, 'b_pid': second.process.pid,
        'a_lease': [av['lease_acquired'], a_done['lease_released']], 'b_lease': [bv['lease_acquired'], b_done['lease_released']],
        'refusals': [refused, first_refusal, second_refusal], 'a_archive': a_archive, 'b_archive': archive(b),
        'safe_uniqueness': {'credentials': True, 'run_paths': True, 'inventory': True, 'resource_names_and_ids': True},
        'private_key_material_exported': False}


def interrupted_run(suite, sentinel):
    from . import recovery_acceptance as old
    run, refused_run = case_runs(suite, 'interrupted-run', 2)
    with run.locked():
        atomic_json(run.file(old.CONTROL), {**common(run.manifest()), 'operation': 'owned-teardown-interruption'})
    with images.docker_scope(run):
        before = snapshot('container', sentinel, unrelated=True)
        child = OwnedProcess(suite, run, 'terminal-destroy')
        deadline = time.monotonic() + START_SECONDS
        while not run.file(old.CHECKPOINT).exists():
            child.alive(); require(time.monotonic() < deadline, 'isolation_worker_timeout'); time.sleep(.03)
        # Original capture proof precedes termination, so no daemon request is
        # killed or inferred stopped from a dead Docker CLI.
        proof = old._checkpoint_proof(run, child.process.pid)
        child.alive(); child.process.kill()
        require(child.process.wait(timeout=5) == -signal.SIGKILL, 'isolation_interruption_missing')
        refused = probe(suite, refused_run, 'unreconciled', 'unreconciled_run')
        result = recover_run(run)
        require(result['status'] == 'completed' and result['unknown_outcome'] is False and
                result['primary_failure']['code'] == 'controlled_teardown_interruption' and result['terraform_state_retained'] is True,
                'isolation_recovery_failed')
        sweep(run); sweep(refused_run)
        require(snapshot('container', sentinel, unrelated=True) == before, 'isolation_sentinel_changed')
        state = raw_file(run.file('private/terraform/terraform.tfstate'))
    return [run.id, refused_run.id], {'checks': {key: True for key in records().checks_for('interrupted-run')},
        'terminal_checkpoint': proof, 'refusal': refused, 'recovered_primary': result['primary_failure'],
        'cleanup': result, 'finished_archive': archive(run), 'terraform_state_retained': True,
        'retained_state_bytes': len(state), 'docker_cli_killed': False}


def interrupted_publication(suite, sentinel):
    from .isolation_publication import publication_case
    result = publication_case(sentinel, suite_run_id=suite.id)
    track(suite, 'interrupted-publication', result['run_ids'])
    return result['run_ids'], {**result['proof'], 'checks': result['checks']}


def oversized_capacity(suite, _sentinel):
    root = suite.file('private/isolation-capacity-fixture')
    require(root != images.INFRASTRUCTURE and root.parent == suite.file('private'), 'isolation_synthetic_scope')
    root.mkdir(mode=0o700); _owned(root, directory=True)
    prior_id, refused_id = str(uuid4()), str(uuid4())
    track(suite, 'oversized-capacity', [prior_id, refused_id])
    observed = {'schema_version': '1.0', 'synthetic': True, 'observed_at': now(), 'boot_id': str(uuid4()),
        'memory_total_bytes': 32 * 1024 * admission.MIB, 'memory_available_bytes': 24 * 1024 * admission.MIB,
        'runtime_disk_free_bytes': 100 * 1024 * admission.MIB, 'docker_disk_free_bytes': 100 * 1024 * admission.MIB,
        'cpu_count': 16, 'load1': 1, 'docker': {'server_version': '29.6.0', 'cgroup_version': '2', 'cgroup_driver': 'systemd',
            'controllers': ['cpu', 'memory', 'pids'], 'memory_limit': True, 'swap_limit': True, 'cpu_quota': True, 'pids_limit': True},
        'workloads': {'running_count': 7, 'cpu_cores': .75, 'memory_bytes': 2 * 1024 * admission.MIB}}
    def generous(_root): return {**deepcopy(observed), 'observed_at': now()}
    with admission.AdmissionLease(root, prior_id, suite.manifest()['source_revision'], 'smoke',
            collector=generous, allow_synthetic=True) as lease:
        lease.finish(reconciliation_complete=True)
    sentinel = suite.file('private/isolation-capacity-sentinel.txt'); atomic_bytes(sentinel, b'ISOLATED SYNTHETIC SENTINEL\n')
    initial = {str(path.relative_to(suite.path)): raw_file(path) for path in
        (root / 'admission.json', root / 'history' / (prior_id + '.json'), sentinel)}
    sufficient = admission.build_plan('twenty-targets', generous(root))
    low = generous(root)
    low['memory_available_bytes'] = sufficient['requirements']['peak_memory_bytes'] + \
        admission.load_profile('twenty-targets')['headroom']['memory_mib'] * admission.MIB - 1
    refused = admission.build_plan('twenty-targets', low)
    require(refused['admitted'] is False and refused['allocation_performed'] is False and
            'host_memory_headroom' in refused['refusal_reasons'], 'isolation_capacity_fixture_invalid')
    code = None
    try:
        with admission.AdmissionLease(root, refused_id, suite.manifest()['source_revision'], 'twenty-targets',
                collector=lambda _root: deepcopy(low), allow_synthetic=True):
            require(False, 'isolation_unexpected_admission')
    except admission.AdmissionError as error: code = error.code
    require(code == 'capacity_refused' and not (root / 'history' / (refused_id + '.json')).exists() and
            initial == {name: raw_file(suite.file(name)) for name in initial}, 'isolation_capacity_changed_prior')
    return [prior_id, refused_id], {'checks': {key: True for key in records().checks_for('oversized-capacity')},
        'synthetic': True, 'allocation_performed': False, 'twenty_target_execution': False,
        'refusal_code': code, 'refused_plan': refused, 'previous_admission_and_sentinel_unchanged': True}


def acceptance(sentinel_id):
    require(sys.platform.startswith('linux') and type(sentinel_id) is str and
            len(sentinel_id) == 64 and all(char in '0123456789abcdef' for char in sentinel_id), 'isolation_input')
    revision = source(); suite = fresh(authentication=False); p = records()
    value = {**common(suite.manifest()), 'operation': p.OPERATION, 'profile': 'smoke', 'status': 'running',
        'cases': [{'name': name, 'status': 'not-run', 'run_ids': [], 'proof': None, 'failure_code': None,
                   'checks': {check: None for check in p.checks_for(name)}} for name in p.CASE_NAMES],
        'primary_failure': None, 'created_at': now(), 'updated_at': now(),
        **{key: definition['const'] for key, definition in p.FLAGS.items()}}
    def save():
        value['updated_at'] = now()
        atomic_bytes(suite.file(RECEIPT), p.render_receipt(value), limit=p.MAX_RECEIPT_BYTES)
    functions = (overlap, interrupted_run, interrupted_publication, oversized_capacity)
    with suite.locked():
        try:
            save()
            seen = {suite.id}
            for row, function in zip(value['cases'], functions):
                source(revision); row['status'] = 'running'; save()
                ids, proof = function(suite, sentinel_id)
                require(len(set(ids)) == len(ids) and not set(ids) & seen and proof['checks'] ==
                        {check: True for check in p.checks_for(row['name'])}, 'isolation_incomplete_case')
                source(revision); seen.update(ids)
                proof.update({**common(suite.manifest()), 'operation': 'isolation-case-proof-v1', 'case': row['name'],
                              'run_ids': ids, 'twenty_target_execution': False, 'production_iso_eligible': False})
                relative = 'evidence/isolation-' + row['name'] + '.json'
                raw = json.dumps(proof, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
                require(len(raw) <= p.MAX_PROOF_BYTES, 'isolation_proof_bound')
                atomic_bytes(suite.file(relative), raw, limit=p.MAX_PROOF_BYTES)
                row.update(status='passed', run_ids=ids, checks=proof['checks'],
                           proof={'logical_path': relative, 'sha256': digest(raw), 'size_bytes': len(raw)})
                save()
            source(revision); value['status'] = 'passed'; save(); return deepcopy(value)
        except BaseException as error:
            code = safe_code(error)
            error.suite_run_id = suite.id
            for row in value['cases']:
                if row['status'] == 'running':
                    path = suite.file('private/isolation-run-ids-' + row['name'] + '.json')
                    try:
                        identifiers = []
                        if path.exists():
                            partial = read_json(path)
                            require(common(partial) == common(suite.manifest()) and partial['case'] == row['name'], 'isolation_worker_identity')
                            identifiers = partial['run_ids']
                        child = getattr(error, 'run_id', None)
                        if child is not None and child != suite.id and child not in identifiers:
                            identifiers = [*identifiers, run_id(child)]
                        require(type(identifiers) is list and len(identifiers) <= 4 and len(set(identifiers)) == len(identifiers) and
                                not set(identifiers) & seen, 'isolation_worker_identity')
                        for identifier in identifiers: run_id(identifier)
                        row['run_ids'] = identifiers
                    except Exception:
                        pass  # Never replace the primary error with a damaged partial registry.
                    row.update(status='failed', failure_code=code)
            value.update(status='failed', primary_failure={'code': code, 'recorded_at': now()})
            try: save()
            except Exception: pass
            if isinstance(error, RunError):
                raise
            converted = IsolationError(code, 'Isolation qualification stopped; retain the failed suite and owned workers.')
            converted.suite_run_id = suite.id
            converted.run_id = getattr(error, 'run_id', None)
            raise converted from None


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Actual smoke isolation with serialized infrastructure graphs.')
    parser.add_argument('--sentinel-id', required=True)
    options = parser.parse_args(arguments)
    try:
        print(json.dumps(acceptance(options.sentinel_id), sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({'error': {'code': safe_code(error)}, 'run_id': getattr(error, 'run_id', None),
                          'suite_run_id': getattr(error, 'suite_run_id', None),
                          'private_evidence_retained': True, 'twenty_target_execution': False, 'production_iso_eligible': False})); return 1


if __name__ == '__main__':
    raise SystemExit(main())
