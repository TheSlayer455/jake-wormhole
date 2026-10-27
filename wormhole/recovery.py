"""Scoped cancellation and cleanup; no allocation, adoption or unknown override.

The coordinator owns the run lock, Docker scope and canonical admission lease.
Terraform retains authority over its targets/networks; helpers remove themselves
through their own exact ownership-checked adapter before Terraform destruction.
"""
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime
import json
import os
import re
import time
from uuid import UUID, uuid4

from . import images
from .admission import AdmissionLease, AdmissionError
from .runs import RunError, _owned, atomic_json, common, now, read_json, source_identity

STATUSES = ('in-progress', 'completed', 'failed', 'blocked')
REASONS = ('success', 'failure', 'cancelled')
CODE = r'[a-z][a-z0-9_-]{0,79}'
RESOURCE_ID = r'(?:[a-f0-9]{64}|sha256:[a-f0-9]{64})'
FIELDS = {'schema_version', 'run_id', 'source_revision', 'source_dirty', 'mode',
    'operation', 'attempt_id', 'reason', 'status', 'created_at', 'updated_at',
    'primary_failure', 'secondary_failures', 'resources', 'unknown_outcome',
    'terraform_state_retained', 'private_state_removed', 'runtime_pipeline_complete', 'production_iso_eligible'}


class RecoveryError(RunError):
    pass


def require(value, code, message):
    if not value:
        raise RecoveryError(code, message)


def safe_code(error):
    value = getattr(error, 'code', 'cleanup_failed')
    return value if type(value) is str and re.fullmatch(CODE, value) else 'cleanup_failed'


def _timestamp(value):
    try:
        return type(value) is str and len(value) <= 32 and value.endswith('Z') and \
            datetime.fromisoformat(value.replace('Z', '+00:00')).utcoffset().total_seconds() == 0
    except (ValueError, AttributeError, TypeError):
        return False


def _uuid(value):
    try: return type(value) is str and str(UUID(value)) == value
    except (ValueError, AttributeError): return False


def valid_failure(value):
    return value is None or type(value) is dict and set(value) == {'code', 'recorded_at'} and \
        type(value['code']) is str and re.fullmatch(CODE, value['code']) and _timestamp(value['recorded_at'])


def validate_cleanup(value):
    require(type(value) is dict and set(value) == FIELDS, 'invalid_cleanup', 'Cleanup fields differ from the versioned contract.')
    require(value['schema_version'] == '1.0' and _uuid(value['run_id']) and _uuid(value['attempt_id']) and
            type(value['source_revision']) is str and re.fullmatch(r'[a-f0-9]{40}', value['source_revision']) and
            type(value['source_dirty']) is bool and value['mode'] in ('fixture', 'container-reference') and
            value['operation'] == 'scoped-cleanup' and value['reason'] in REASONS and value['status'] in STATUSES and
            _timestamp(value['created_at']) and _timestamp(value['updated_at']), 'invalid_cleanup', 'Cleanup identity, status or time is invalid.')
    failure = value['primary_failure']
    require(failure is None or type(failure) is dict and set(failure) == {'code', 'recorded_at'} and
            type(failure['code']) is str and re.fullmatch(CODE, failure['code']) and _timestamp(failure['recorded_at']),
            'invalid_cleanup', 'Primary failure must be a bounded structured identity.')
    errors = value['secondary_failures']
    require(type(errors) is list and len(errors) <= 64 and all(type(x) is dict and set(x) == {'code', 'recorded_at'} and
            type(x['code']) is str and re.fullmatch(CODE, x['code']) and _timestamp(x['recorded_at']) for x in errors),
            'invalid_cleanup', 'Secondary failures must remain bounded and structured.')
    resources = value['resources']
    require(type(resources) is list and len(resources) <= 100 and all(type(x) is dict and
            set(x) == {'kind', 'id', 'role', 'disposition'} and x['kind'] in ('container', 'network', 'image') and
            type(x['id']) is str and re.fullmatch(RESOURCE_ID, x['id']) and
            x['role'] in ('provisioner', 'terraform-target', 'terraform-network', 'helper', 'retained-image', 'other-owned') and
            x['disposition'] in ('pending', 'absent', 'retained', 'unknown') for x in resources) and
            len({(x['kind'], x['id']) for x in resources}) == len(resources), 'invalid_cleanup', 'Cleanup resources are malformed or repeated.')
    require(type(value['unknown_outcome']) is bool and value['terraform_state_retained'] is True and
            value['private_state_removed'] is False and value['runtime_pipeline_complete'] is False and
            value['production_iso_eligible'] is False and (value['status'] != 'completed' or
            not value['unknown_outcome'] and all(x['disposition'] in ('absent', 'retained') for x in resources)),
            'invalid_cleanup', 'Cleanup cannot imply uncertain completion, removed state or pipeline eligibility.')
    return value


def cleanup_schema():
    failure = {'type': 'object', 'additionalProperties': False, 'required': ['code', 'recorded_at'],
        'properties': {'code': {'type': 'string', 'pattern': '^' + CODE + '$'}, 'recorded_at': {'type': 'string', 'format': 'date-time', 'maxLength': 32}}}
    props = {'schema_version': {'const': '1.0'}, 'run_id': {'type': 'string', 'format': 'uuid'},
        'attempt_id': {'type': 'string', 'format': 'uuid'}, 'source_revision': {'type': 'string', 'pattern': '^[a-f0-9]{40}$'},
        'source_dirty': {'type': 'boolean'}, 'mode': {'enum': ['fixture', 'container-reference']},
        'operation': {'const': 'scoped-cleanup'}, 'reason': {'enum': list(REASONS)}, 'status': {'enum': list(STATUSES)},
        'created_at': {'type': 'string', 'format': 'date-time', 'maxLength': 32},
        'updated_at': {'type': 'string', 'format': 'date-time', 'maxLength': 32},
        'primary_failure': {'anyOf': [{'type': 'null'}, failure]},
        'secondary_failures': {'type': 'array', 'maxItems': 64, 'items': failure},
        'resources': {'type': 'array', 'maxItems': 100, 'items': {'type': 'object', 'additionalProperties': False,
            'required': ['kind', 'id', 'role', 'disposition'], 'properties': {'kind': {'enum': ['container', 'network', 'image']},
                'id': {'type': 'string', 'pattern': '^' + RESOURCE_ID + '$'},
                'role': {'enum': ['provisioner', 'terraform-target', 'terraform-network', 'helper', 'retained-image', 'other-owned']},
                'disposition': {'enum': ['pending', 'absent', 'retained', 'unknown']}}}},
        'unknown_outcome': {'type': 'boolean'}, 'terraform_state_retained': {'const': True}, 'private_state_removed': {'const': False},
        'runtime_pipeline_complete': {'const': False}, 'production_iso_eligible': {'const': False}}
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:jake-wormhole:cleanup:1.0',
        'title': 'Scoped cleanup attempt v1', 'type': 'object', 'additionalProperties': False,
        'required': sorted(FIELDS), 'properties': props,
        '$comment': 'The generated Python validator also checks canonical identities, unique resource IDs and completed-outcome consistency.'}


def _request(run):
    path = run.file('cancel-request.json')
    if not path.exists(): return None
    value = read_json(path)
    manifest = run.manifest()
    require(type(value) is dict and set(value) == {'schema_version', 'run_id', 'source_revision', 'request_id', 'requested_at', 'reason'} and
            value['schema_version'] == '1.0' and value['run_id'] == run.id and value['source_revision'] == manifest['source_revision'] and
            _uuid(value['request_id']) and _timestamp(value['requested_at']) and value['reason'] == 'operator-request',
            'invalid_cancellation', 'The scoped cancellation request is malformed or belongs to another run.')
    return value


def request_cancel(run):
    """Record intent without stealing a live run lock or signalling a reused PID."""
    require(run.manifest()['mode'] == 'fixture' or run.workspace == images.RUNS_ROOT,
            'recovery_scope', 'Real cancellation requires the fixed canonical run storage.')
    with _cancel_publication(run):
        existing = _request(run)
        if existing is not None: return existing
        value = {'schema_version': '1.0', 'run_id': run.id, 'source_revision': run.manifest()['source_revision'],
            'request_id': str(uuid4()), 'requested_at': now(), 'reason': 'operator-request'}
        atomic_json(run.file('cancel-request.json'), value)
        return value


@contextmanager
def _cancel_publication(run):
    """Separate stable kernel lock; never steal the coordinator's run lock."""
    path = run.file('cancel-publication.lock')
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        _owned(path)
        identity = os.fstat(descriptor)
        deadline = time.monotonic() + 2
        while True:
            try:
                if os.name == 'posix':
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    import msvcrt
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                require(time.monotonic() < deadline, 'cancellation_busy', 'Another cancellation publisher remains active; retry without lock takeover.')
                time.sleep(.005)
        require((identity.st_dev, identity.st_ino) == (path.stat().st_dev, path.stat().st_ino),
                'unsafe_lock', 'Cancellation publication lock changed.')
        yield
    finally:
        os.close(descriptor)  # Stable inode remains; crash releases only the kernel lock.


def cancellation_requested(run):
    return _request(run) is not None


def _resources(session, lease):
    owned = getattr(session, 'owned', {})
    helper = getattr(session, '_cleanup_helper_id', None)
    result = []
    for item in lease.record['resources']:
        identifier = item['id']
        role = ('provisioner' if identifier == session.provisioner else
            'terraform-target' if any(address.startswith('docker_container.') and identifier == resource_id for address, resource_id in owned.items()) else
            'terraform-network' if identifier == owned.get('docker_network.run') else
            'helper' if identifier == helper else 'retained-image' if item['kind'] == 'image' else 'other-owned')
        result.append({'kind': item['kind'], 'id': identifier, 'role': role,
            'disposition': 'unknown' if session.receipt['unknown_outcome'] and item['outcome'] == 'pending' else item['outcome']})
    return result


def _save(run, value):
    value['updated_at'] = now()
    validate_cleanup(value)
    folder = run.file('evidence/cleanup-attempts')
    if not folder.exists(): folder.mkdir(mode=0o700)
    _owned(folder, directory=True)
    atomic_json(folder / (value['attempt_id'] + '.json'), value)
    atomic_json(run.file('evidence/cleanup.json'), value)


def cleanup_session(session, lease, *, reason='success', helper=None):
    """Return a truthful terminal receipt; caller still finalizes admission."""
    require(reason in REASONS, 'invalid_cleanup', 'Cleanup reason must be a fixed supported value.')
    session.held()
    require(session.lease is lease, 'admission_scope', 'Cleanup requires the session own held admission lease.')
    if helper is not None:
        require(helper.run.id == session.run.id and helper.run.path == session.run.path and helper.lease is lease,
                'ownership_mismatch', 'Helper cleanup must belong to this exact run and lease.')
    helper_record = getattr(helper, 'receipt', {}) if helper is not None else {}
    require(type(helper_record) is dict and type(helper_record.get('unknown_outcome', False)) is bool,
            'invalid_cleanup', 'Helper cleanup requires its bounded structured outcome record.')
    require(valid_failure(helper_record.get('primary_failure')), 'invalid_cleanup', 'Helper primary failure must have a bounded validated identity before persistence.')
    if helper is not None:
        require(common(helper_record) == common(session.run.manifest()), 'identity_mismatch', 'Helper outcome belongs to another run or source.')
    helper_id = getattr(helper, 'helper', None) if helper is not None else None
    if type(helper_id) is str and re.fullmatch(r'[a-f0-9]{64}', helper_id): session._cleanup_helper_id = helper_id
    if session.receipt['primary_failure'] is None and helper_record.get('primary_failure') is not None:
        session.receipt['primary_failure'] = deepcopy(helper_record['primary_failure'])
        session.receipt['status'] = 'failed'
        session.save()
    if reason == 'cancelled' and session.receipt['primary_failure'] is None:
        session.failure(RecoveryError('cancelled', 'The run was cancelled before cleanup.'))
    stamp = now()
    value = {**common(session.run.manifest()), 'operation': 'scoped-cleanup', 'attempt_id': str(uuid4()),
        'reason': reason, 'status': 'in-progress', 'created_at': stamp, 'updated_at': stamp,
        'primary_failure': deepcopy(session.receipt['primary_failure']), 'secondary_failures': [],
        'resources': _resources(session, lease), 'unknown_outcome': session.receipt['unknown_outcome'],
        'terraform_state_retained': True, 'private_state_removed': False,
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    _save(session.run, value)
    try:
        require(session.receipt['unknown_outcome'] is False and helper_record.get('unknown_outcome', False) is False,
                'daemon_outcome_unknown', 'Uncertain allocation or mutation remains blocked; cleanup cannot adopt or override it.')
        if helper is not None:
            require(helper.run.id == session.run.id and helper.lease is lease, 'ownership_mismatch', 'Helper cleanup must belong to this exact run and lease.')
            helper.cleanup()
        if session.provisioner is None and not session.owned and not lease.record['resources'] and lease.record.get('phase') == 'reserved':
            require(not session.receipt['operations'], 'cleanup_unresolved', 'Empty preparation can only finish before any runtime operation or allocation intent.')
        else:
            session.destroy()
        require(all(x['outcome'] in ('absent', 'retained') for x in lease.record['resources']) and
                session.receipt['unknown_outcome'] is False, 'cleanup_unresolved', 'Every exact journaled resource must be accounted for.')
        value['status'] = 'completed'
    except BaseException as error:
        value['status'] = 'blocked' if safe_code(error) in {'daemon_outcome_unknown', 'ownership_mismatch', 'recovery_scope', 'admission_scope'} else 'failed'
        value['secondary_failures'].append({'code': safe_code(error), 'recorded_at': now()})
        value['resources'] = _resources(session, lease)
        value['unknown_outcome'] = session.receipt['unknown_outcome'] or helper_record.get('unknown_outcome', False)
        _save(session.run, value)
        if not isinstance(error, Exception): raise
        return value
    value['resources'] = _resources(session, lease)
    value['unknown_outcome'] = session.receipt['unknown_outcome']
    _save(session.run, value)
    return value


def inspect_recovery(run):
    """Read existing bounded application records only; no Docker calls."""
    latest = run.file('evidence/cleanup.json')
    value = validate_cleanup(read_json(latest)) if latest.exists() else None
    if value is not None:
        require(common(value) == common(run.manifest()), 'identity_mismatch', 'Cleanup receipt does not belong to this run and source.')
    return {'run_id': run.id, 'cleanup': value, 'cancellation': _request(run),
        'allocation_performed': False, 'production_iso_eligible': False}


def recover_run(run):
    try:
        return _recover_run(run)
    except AdmissionError as error:
        raise RecoveryError(safe_code(error), 'The exact infrastructure lease could not be resumed; preserve its journal and run evidence.') from None


def _recover_run(run):
    """Reconcile only the exact current run at its immutable clean source."""
    from .provisioning import ProvisioningSession
    revision, dirty = source_identity()
    manifest = run.manifest()
    require(run.workspace == images.RUNS_ROOT and not dirty and not manifest['source_dirty'] and revision == manifest['source_revision'] and
            manifest['mode'] == 'container-reference', 'recovery_scope', 'Recovery requires the original exact clean real-run source.')
    with run.locked(), images.docker_scope(run), AdmissionLease.resume(images.INFRASTRUCTURE, run.id, revision, manifest['profile']) as lease:
        if getattr(lease, '_completion_archive', None) is not None:
            value = inspect_recovery(run)['cleanup']
            require(value is not None and value['status'] == 'completed', 'recovery_scope', 'An archived admission needs its matching completed cleanup receipt.')
            lease.finish(reconciliation_complete=True)
            return value
        if lease.record.get('phase') == 'reserved' and not lease.record['resources']:
            require(not run.file('private/terraform/controller.json').exists() and not run.file('private/readiness-controller.json').exists(),
                    'recovery_scope', 'Reserved recovery cannot hide a runtime controller context.')
            folder = run.file('private/terraform')
            require(not folder.exists() or not any(folder.glob('*.tfplan')) and not any(folder.glob('terraform.tfstate*')) and
                    (not (folder / 'operations').exists() or not any((folder / 'operations').iterdir())),
                    'recovery_scope', 'Reserved recovery requires no runtime operations, plans or state.')
            path = run.file('evidence/provisioning.json')
            prior = read_json(path) if path.exists() else {**common(manifest), 'primary_failure': None,
                'unknown_outcome': False, 'resources': [], 'operations': []}
            require(common(prior) == common(manifest) and prior['unknown_outcome'] is False and
                    not prior['resources'] and not prior['operations'] and not prior.get('provisioner_id') and valid_failure(prior['primary_failure']),
                    'recovery_scope', 'Reserved recovery requires exact evidence that no allocation or runtime operation began.')
            stamp = now(); cancelled = cancellation_requested(run)
            primary = prior['primary_failure'] or ({'code': 'cancelled', 'recorded_at': stamp} if cancelled else None)
            value = {**common(manifest), 'operation': 'scoped-cleanup', 'attempt_id': str(uuid4()),
                'reason': 'cancelled' if cancelled else 'failure' if primary else 'success', 'status': 'completed',
                'created_at': stamp, 'updated_at': stamp, 'primary_failure': primary, 'secondary_failures': [],
                'resources': [], 'unknown_outcome': False, 'terraform_state_retained': True, 'private_state_removed': False,
                'runtime_pipeline_complete': False, 'production_iso_eligible': False}
            _save(run, value); lease.finish(reconciliation_complete=True)
            return value
        helper_summary = {'primary_failure': None, 'unknown_outcome': False}
        try:
            helper = None
            bound_provisioning = read_json(run.file('evidence/provisioning.json'))
            require(common(bound_provisioning) == common(manifest) and valid_failure(bound_provisioning.get('primary_failure')) and
                    type(bound_provisioning.get('unknown_outcome')) is bool,
                    'identity_mismatch', 'Provisioning status must be bound to this exact run and source before component cleanup.')
            initialization_path=run.file('evidence/initialization.json')
            if initialization_path.exists():
                from .initialization import InitializationSession
                initial=read_json(initialization_path)
                require(common(initial)==common(manifest) and type(initial.get('unknown_outcome')) is bool,
                    'initialization_recovery_scope','Initialization intent must belong to this exact source and Run.')
                if initial['unknown_outcome']:
                    resumed=InitializationSession.resume(run,lease)
                    target=resumed.record['attempts'][-1]['target_id']
                    try:
                        terminal=resumed.reconcile(target)
                        code=terminal['category'] if terminal['status']=='failed' else 'coordinator_interrupted'
                    except Exception:
                        resumed.cancel_and_confirm(target)
                        code='coordinator_interrupted'
                    resumed.provisioning.failure(RecoveryError(code,'Interrupted initialization was reconciled; acceptance was not resumed.'))
                    bound_provisioning=read_json(run.file('evidence/provisioning.json'))
            if run.file('private/readiness-controller.json').exists():
                from .readiness import ReadinessSession, readiness_status
                helper_summary['unknown_outcome'] = True  # Missing/invalid status cannot conceal uncertainty.
                summary = readiness_status(run)
                require(type(summary) is dict and valid_failure(summary.get('primary_failure')) and
                        type(summary.get('unknown_outcome')) is bool, 'invalid_cleanup', 'Readiness recovery status is malformed.')
                helper_summary = summary
            require(bound_provisioning['unknown_outcome'] is False and helper_summary['unknown_outcome'] is False,
                    'daemon_outcome_unknown', 'A component has unresolved daemon work; preserve every component before teardown.')
            if run.file('private/readiness-controller.json').exists():
                helper = ReadinessSession.resume_cleanup(run, lease)
                helper.cleanup()  # Helper must be absent before Terraform's exact pending view is resumed.
            session = ProvisioningSession.resume_destroy(run, lease)
            if helper is not None: session._cleanup_helper_id = helper.helper
            if session.receipt['primary_failure'] is None and helper_summary['primary_failure'] is not None:
                session.receipt['primary_failure'] = deepcopy(helper_summary['primary_failure'])
                session.receipt['status'] = 'failed'; session.save()
        except Exception as error:
            # Reporting has no execution authority. Keep recovery refusal visible
            # even when a component cannot produce an executable cleanup adapter.
            from types import SimpleNamespace
            prior = read_json(run.file('evidence/provisioning.json'))
            require(common(prior) == common(manifest), 'identity_mismatch', 'Recovery evidence belongs to another run or source.')
            if helper is not None:
                record = helper.receipt
                require(type(record) is dict and valid_failure(record.get('primary_failure')) and type(record.get('unknown_outcome')) is bool,
                        'invalid_cleanup', 'Readiness outcome could not be preserved safely.')
                helper_summary = record
            prior = deepcopy(prior)
            if prior['primary_failure'] is None: prior['primary_failure'] = deepcopy(helper_summary.get('primary_failure'))
            prior['unknown_outcome'] = prior['unknown_outcome'] or helper_summary.get('unknown_outcome', True)
            context_path = run.file('private/terraform/controller.json')
            context = read_json(context_path) if context_path.exists() else None
            if context is None: prior['unknown_outcome'] = True  # Allocation phase without an exact returned controller cannot be cleared.
            view = SimpleNamespace(run=run, lease=lease, provisioner=context['id'] if context is not None else None, receipt=prior,
                owned={x['address']: x['id'] for x in prior['resources']})
            stamp = now()
            value = {**common(manifest), 'operation': 'scoped-cleanup', 'attempt_id': str(uuid4()),
                'reason': 'cancelled' if cancellation_requested(run) else 'failure', 'status': 'blocked',
                'created_at': stamp, 'updated_at': stamp, 'primary_failure': deepcopy(prior['primary_failure']),
                'secondary_failures': [{'code': safe_code(error), 'recorded_at': stamp}],
                'resources': _resources(view, lease), 'unknown_outcome': prior['unknown_outcome'],
                'terraform_state_retained': True, 'private_state_removed': False,
                'runtime_pipeline_complete': False, 'production_iso_eligible': False}
            component_failure = helper_summary.get('primary_failure')
            if component_failure is not None and component_failure != value['primary_failure']:
                value['secondary_failures'].append(deepcopy(component_failure))
            _save(run, value)
            return value
        reason = 'cancelled' if cancellation_requested(run) else 'failure' if session.receipt['primary_failure'] else 'success'
        value = cleanup_session(session, lease, reason=reason)
        if value['status'] == 'completed': lease.finish(reconciliation_complete=True)
        return value


def readable_cleanup(value):
    validate_cleanup(value)
    primary = value['primary_failure']['code'] if value['primary_failure'] else 'none'
    lines = [f"Run {value['run_id']}: cleanup {value['status']}", f"Primary failure: {primary}",
        'Terraform state and private evidence retained.']
    lines.extend(f"{x['kind']} {x['id']}: {x['disposition']} ({x['role']})" for x in value['resources'])
    lines.extend('Secondary cleanup error: ' + x['code'] for x in value['secondary_failures'])
    return '\n'.join(lines) + '\n'
