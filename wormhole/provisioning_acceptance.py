"""Explicit real WORM-006 acceptance, never a fixture or full-pipeline gate.

Root must review and invoke this operator on the approved Linux host. It uses
three fresh serial Runs and the production provisioning policy. The supplied
sentinel is an existing exact container ID: it is observed, never allocated or
modified. Unexpected failures stop here and preserve state/admission for review.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from . import images
from .admission import AdmissionLease
from .provisioning import ADDRESSES, ID, ProvisioningError, ProvisioningSession, layout_addresses
from .runs import (RunError, _owned, atomic_json, common, create_run, now,
                   source_identity)
from .stages import execute_run

MAX_FILES = 4096
MAX_SCAN_BYTES = 128 * 1024 * 1024
MAX_SCAN_FILE = 8 * 1024 * 1024
SCAN_SECONDS = 15
CHUNK = 65536


class AcceptanceError(RunError):
    pass


def require(value, code):
    if not value:
        raise AcceptanceError(code, "Acceptance failed; retain private Run evidence and resource accounting.")


def error_code(error):
    code = getattr(error, 'code', 'acceptance_failed')
    return code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', code) else 'acceptance_failed'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def snapshot(kind, identifier, *, unrelated=False):
    """Stable, allowlisted fields only; never Config.Env, key files or statistics."""
    require(type(identifier) is str and ID.fullmatch(identifier), 'invalid_resource_id')
    value = images.inspect(kind, identifier)
    require(value.get('Id') == identifier, 'observation_identity')
    if kind == 'container':
        labels = value.get('Config', {}).get('Labels') or {}
        require(not unrelated or not labels.get(images.LABEL + '.run_id'), 'sentinel_is_wormhole_owned')
        state = value.get('State', {})
        projection = {key: value.get(key) for key in ('Id', 'Name', 'Image', 'RestartCount')}
        projection['state'] = {key: state.get(key) for key in ('Status', 'Running', 'StartedAt', 'FinishedAt', 'ExitCode')}
    else:
        require(kind == 'network', 'invalid_observation_kind')
        projection = {key: value.get(key) for key in ('Id', 'Name', 'Driver', 'Internal', 'Scope', 'Ingress')}
        projection['containers'] = {key: {field: item.get(field) for field in ('Name', 'EndpointID', 'IPv4Address', 'IPv6Address')}
            for key, item in value.get('Containers', {}).items()}
    return digest(projection)


def _walk(root, *, skip_data=False):
    """Finite metadata walk; never follows a link, including provider cache links."""
    deadline, count, stack = time.monotonic() + SCAN_SECONDS, 0, [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= MAX_FILES and time.monotonic() < deadline, 'scan_bound')
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                if skip_data and directory == root and entry.name == '.terraform':
                    require(stat.S_ISDIR(info.st_mode), 'scan_unsafe_path')
                    continue  # Installed public provider binaries, not state/config/evidence.
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                else:
                    yield path, info


def disk_sample(run, phase):
    """Logical bytes sampled at checkpoints; not allocated blocks or a quota."""
    total = files = links = 0
    for _, info in _walk(run.path):
        require(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), 'scan_unsafe_path')
        if stat.S_ISLNK(info.st_mode):
            links += 1  # Terraform's mirror links are not traversed or double counted.
        else:
            require(info.st_nlink == 1, 'scan_unsafe_path')
            total += info.st_size
            files += 1
    return {'phase': phase, 'logical_file_bytes': total, 'ordinary_files': files,
            'unfollowed_links': links, 'sampled_at': now(), 'hard_quota': False}


def scan_private_material(run):
    """Bounded streaming check; no key contents, key hashes or raw matches escape."""
    key_path = run.file('private/credentials/id_ed25519')
    public_path = run.file('private/target-input/authorized_keys')
    _owned(key_path)
    with key_path.open('rb') as stream:
        key = stream.read(8193)
    require(32 <= len(key) <= 8192 and b'PRIVATE KEY' in key, 'scan_key_invalid')
    # authorized_keys intentionally has public0644 input permissions.
    info = public_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'scan_unsafe_path')
    with public_path.open('rb') as stream:
        public = stream.read(514).strip()
    require(32 <= len(public) <= 512 and public.startswith(b'ssh-ed25519 '), 'scan_key_invalid')
    needles = [key.strip(), public, str(key_path).encode(), b'private/credentials/id_ed25519',
        str(run.file('private/credentials')).encode(), b'PRIVATE KEY-----']
    needles.extend(line for line in key.splitlines() if len(line) >= 40 and not line.startswith(b'-----'))
    overlap = max(map(len, needles)) - 1
    total = files = 0
    deadline = time.monotonic() + SCAN_SECONDS
    for root in (run.file('private/terraform'), run.file('evidence')):
        _owned(root, directory=True)
        for path, info in _walk(root, skip_data=True):
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_SCAN_FILE, 'scan_unsafe_path')
            _owned(path)
            files += 1
            require(files <= MAX_FILES, 'scan_bound')
            tail, size = b'', 0
            with path.open('rb') as stream:
                while chunk := stream.read(CHUNK):
                    size += len(chunk)
                    total += len(chunk)
                    require(size <= MAX_SCAN_FILE and total <= MAX_SCAN_BYTES and time.monotonic() < deadline, 'scan_bound')
                    window = tail + chunk
                    require(not any(needle in window for needle in needles), 'credential_material_exposed')
                    tail = window[-overlap:]
            require(size == info.st_size, 'scan_changed')
    return {'status': 'pass', 'files_scanned': files, 'bytes_scanned': total,
            'scope': 'Terraform state, plans, configuration, operation captures and portable evidence',
            'public_provider_cache_excluded': True, 'secret_contents_exported': False}


def ownership_negative(session, sentinel):
    """Change only an expected ID in memory, then invoke the normal destroy API."""
    require(set(session.owned) == layout_addresses(getattr(session, 'target_plan', None)) and session.receipt['unknown_outcome'] is False and
            session.receipt['primary_failure'] is None, 'negative_not_ready')
    original = deepcopy(session.owned)
    target_address = session.target_plan.address_for('target-001') if getattr(session, 'target_plan', None) is not None else 'docker_container.target'
    target, network = original[target_address], original['docker_network.run']
    require(sentinel not in {target, network, session.provisioner}, 'sentinel_is_owned')
    before = {'target': snapshot('container', target), 'network': snapshot('network', network),
              'sentinel': snapshot('container', sentinel, unrelated=True)}
    prior = len(session.receipt['operations'])
    wrong = hashlib.sha256(('WORM-006 expected-ID negative:' + session.run.id).encode()).hexdigest()
    require(wrong not in {*original.values(), sentinel, session.provisioner}, 'negative_id_collision')
    observed = None
    try:
        session.owned[session.target_plan.address_for('target-001') if getattr(session, 'target_plan', None) is not None else 'docker_container.target'] = wrong
        try:
            session.destroy()
        except ProvisioningError as error:
            observed = error.code
    finally:
        session.owned = original  # No Terraform state, file or source edits.
        session.save()  # Refresh the application receipt's accounting; never edit Terraform state.
    require(observed == 'ownership_mismatch', 'ownership_guard_not_observed')
    operations = session.receipt['operations'][prior:]
    require([item['operation'] for item in operations] == ['show-state'], 'destructive_operation_ran')
    require(session.receipt['primary_failure']['code'] == 'ownership_mismatch' and
            session.receipt['unknown_outcome'] is False, 'negative_failure_not_preserved')
    after = {'target': snapshot('container', target), 'network': snapshot('network', network),
             'sentinel': snapshot('container', sentinel, unrelated=True)}
    require(before == after, 'ownership_negative_changed_resources')
    return {'status': 'pass', 'check': 'expected-ownership-ID negative', 'observed_error': observed,
        'terraform_state_modified': False, 'expected_id_memory_restored': True,
        'destroy_plan_or_delete_ran': False, 'stable_object_fingerprints': after}


def _identity(session, inventory):
    manifest = session.run.manifest()
    require(manifest['mode'] == 'container-reference' and manifest['source_dirty'] is False and
            set(session.owned) == layout_addresses(getattr(session, 'target_plan', None)) and inventory['run_id'] == session.run.id and
            inventory['source_revision'] == manifest['source_revision'] and len(inventory['targets']) == 1 and
            inventory['targets'][0]['resource_id'] == session.owned[session.target_plan.address_for('target-001') if getattr(session, 'target_plan', None) is not None else 'docker_container.target'], 'acceptance_identity')
    return {'run_id': session.run.id, 'source_revision': manifest['source_revision'],
        'state_path': str(session.state), 'public_input': session.variables['public_input'],
        'target_name': 'wormhole-' + session.run.id + '-target-001',
        'network_name': 'wormhole-' + session.run.id + '-network',
        'resources': deepcopy(session.owned), 'provisioner_id': session.provisioner,
        'inventory': deepcopy(inventory)}


def isolation(first, second):
    require(first['source_revision'] == second['source_revision'], 'source_changed')
    fields = ('run_id', 'state_path', 'public_input', 'target_name', 'network_name', 'provisioner_id')
    require(all(first[key] != second[key] for key in fields) and
            not ((set(first['resources'].values()) | {first['provisioner_id']}) &
                 (set(second['resources'].values()) | {second['provisioner_id']})), 'runs_not_isolated')
    require(first['inventory']['run_id'] != second['inventory']['run_id'] and
            first['inventory']['targets'][0]['resource_id'] != second['inventory']['targets'][0]['resource_id'], 'inventory_not_isolated')
    return {'status': 'pass', 'same_clean_source': True, 'distinct_run_ids_state_inputs_names_ids_inventory': True,
            'endpoint_addresses_required_unique': False}


def _case(scenario, sentinel, *, negative=False):
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    result = {**common(run.manifest()), 'operation': 'terraform-acceptance-case', 'scenario': scenario,
              'status': 'running', 'checks': {}, 'disk_samples': [], 'created_at': now(),
              'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    session, identity = None, None
    try:
        with run.locked():
            execute_run(run)  # Retain unsupported complete-pipeline outcome separately.
        images.create_auth(run)
        with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE, run.id, run.manifest()['source_revision'], 'smoke') as lease:
            baseline = snapshot('container', sentinel, unrelated=True)
            session = ProvisioningSession(run, lease, scenario=scenario)
            if scenario == 'provider-unavailable':
                observed = None
                try:
                    session.provision()
                except ProvisioningError as error:
                    observed = error.code
                require(observed == 'terraform_failed', 'provider_failure_not_observed')
                proof = session.prove_provider_unavailable()
                require(type(proof) is dict and proof.get('scenario') == 'provider-unavailable' and
                        proof.get('status') == 'proved-zero-contact' and
                        proof.get('endpoint') == 'unix:///run/wormhole/provider-unavailable.sock' and
                        all(proof.get(key) is True for key in ('before_and_after_enoent', 'actual_saved_apply_failed', 'terraform_state_empty')) and
                        proof.get('run_resources') == [{'kind': 'container', 'count': 1}, {'kind': 'network', 'count': 0}] and
                        type(proof.get('source_sha256')) is str and ID.fullmatch(proof['source_sha256']) and
                        proof['source_sha256'] == session.inputs['main.tf'] and
                        not session.owned and session.receipt['unknown_outcome'] is False and
                        session.receipt['primary_failure']['code'] == 'terraform_failed', 'provider_failure_unproven')
                result['checks']['provider_unavailable'] = {'status': 'pass', 'observed_error': observed,
                    'proof_retained_in_private_run': True}
            else:
                inventory = session.provision()
                identity = _identity(session, inventory)
                atomic_json(run.file('private/acceptance-identity.json'), identity)
                result['checks']['real_provisioning'] = {'status': 'pass', 'actual_provider_inventory': True}
            result['disk_samples'].append(disk_sample(run, 'after-provision-or-expected-provider-failure'))
            result['checks']['credential_scan_before_cleanup'] = scan_private_material(run)
            if negative:
                result['checks']['ownership_negative'] = ownership_negative(session, sentinel)
            result['disk_samples'].append(disk_sample(run, 'before-cleanup'))
            receipt = session.destroy()
            require(receipt['cleanup'] == 'completed' and receipt['unknown_outcome'] is False, 'cleanup_not_completed')
            expected_failure = 'terraform_failed' if scenario == 'provider-unavailable' else 'ownership_mismatch' if negative else None
            require((receipt['primary_failure'] or {}).get('code') == expected_failure and
                    receipt['status'] == ('failed' if expected_failure else 'completed'), 'primary_failure_changed')
            require(snapshot('container', sentinel, unrelated=True) == baseline, 'sentinel_changed')
            result['checks']['cleanup'] = {'status': 'pass', 'underlying_operation_status': receipt['status'],
                'primary_error': expected_failure, 'unrelated_sentinel_unchanged': True}
            result['checks']['credential_scan_after_cleanup'] = scan_private_material(run)
            result['disk_samples'].append(disk_sample(run, 'after-cleanup'))
            lease.finish(reconciliation_complete=True)
            result['status'] = 'pass'
    except BaseException as error:
        result['status'] = 'fail'
        result['error'] = {'code': error_code(error)}
        result['cleanup_claimed'] = False
        error.run_id = run.id
        raise
    finally:
        result['updated_at'] = now()
        # Evidence persistence cannot replace the original operation failure.
        try:
            with run.locked():
                atomic_json(run.file('evidence/provisioning-acceptance.json'), result)
        except Exception:
            if result['status'] == 'pass':
                raise
    return result, identity


def acceptance(sentinel):
    require(sys.platform.startswith('linux'), 'linux_required')
    require(type(sentinel) is str and ID.fullmatch(sentinel), 'invalid_sentinel_id')
    revision, dirty = source_identity()
    require(dirty is False, 'source_dirty')
    first, first_identity = _case('healthy', sentinel)
    require(source_identity() == (revision, False), 'source_changed')
    second, second_identity = _case('healthy', sentinel, negative=True)
    separate = isolation(first_identity, second_identity)
    require(source_identity() == (revision, False), 'source_changed')
    third, _ = _case('provider-unavailable', sentinel)
    result = {'schema_version': '1.0', 'operation': 'terraform-acceptance', 'source_revision': revision,
        'status': 'pass', 'cases': [first, second, third], 'isolation': separate,
        'criteria': {'AC-01': 'pass: two actual provider lifecycles and attributed inventories',
            'AC-02': 'pass: isolated Runs, bounded credential scans and policy-controlled exposure',
            'AC-03': 'pass: expected-ID guard, fixed provider failure proof and scoped cleanup'},
        'existing_sentinel_modified': False, 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    require(all(case['source_revision'] == revision for case in result['cases']), 'source_changed')
    # Retain a bounded suite record with the final Run; stdout receives this same sanitized record.
    from .runs import Run
    last = Run(images.RUNS_ROOT, third['run_id'])
    with last.locked():
        atomic_json(last.file('evidence/provisioning-acceptance-suite.json'), result)
    return result


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Real WORM-006 acceptance; uses three fresh admitted Runs and an existing read-only sentinel.')
    parser.add_argument('--sentinel-id', required=True, help='Existing unrelated exact64hex container ID; never created or modified.')
    options = parser.parse_args(arguments)
    try:
        print(json.dumps(acceptance(options.sentinel_id), sort_keys=True, indent=2))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'fail', 'error': {'code': error_code(error), 'run_id': getattr(error, 'run_id', None)},
            'message': 'Acceptance stopped. Preserve private Run state and admission; cleanup is not implied.',
            'runtime_pipeline_complete': False, 'production_iso_eligible': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
