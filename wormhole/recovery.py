"""Scoped cancellation and cleanup; no allocation, adoption or unknown override.

The coordinator owns the run lock, Docker scope and canonical admission lease.
Terraform retains authority over its targets/networks; helpers remove themselves
through their own exact ownership-checked adapter before Terraform destruction.
"""
from copy import deepcopy
from datetime import datetime
import json
import os
import re
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
    existing = _request(run)
    if existing is not None: return existing
    value = {'schema_version': '1.0', 'run_id': run.id, 'source_revision': run.manifest()['source_revision'],
        'request_id': str(uuid4()), 'requested_at': now(), 'reason': 'operator-request'}
    path = run.file('cancel-request.json')
    temporary = run.file('.cancel-' + str(uuid4()) + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write((json.dumps(value, sort_keys=True) + '\n').encode()); stream.flush(); os.fsync(stream.fileno())
        try: os.link(temporary, path)  # Atomic publish without replacing a concurrent request.
        except FileExistsError: return _request(run)
    finally:
        temporary.unlink(missing_ok=True)
    return value


def cancellation_requested(run):
    return _request(run) is not None


def _resources(session, lease):
    owned = getattr(session, 'owned', {})
    helper = getattr(session, '_cleanup_helper_id', None)
    result = []
    for item in lease.record['resources']:
        identifier = item['id']
        role = ('provisioner' if identifier == session.provisioner else
            'terraform-target' if identifier == owned.get('docker_container.target') else
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
    helper_record = getattr(helper, 'receipt', {}) if helper is not None else {}
    require(type(helper_record) is dict and type(helper_record.get('unknown_outcome', False)) is bool,
            'invalid_cleanup', 'Helper cleanup requires its bounded structured outcome record.')
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
        try:
            if run.file('private/readiness-controller.json').exists():
                from .readiness import ReadinessSession
                helper = ReadinessSession.resume_cleanup(run, lease)
                helper.cleanup()  # Helper must be absent before Terraform's exact pending view is resumed.
            session = ProvisioningSession.resume_destroy(run, lease)
        except Exception as error:
            # Reporting has no execution authority. Keep recovery refusal visible
            # even when a component cannot produce an executable cleanup adapter.
            from types import SimpleNamespace
            prior = read_json(run.file('evidence/provisioning.json'))
            require(common(prior) == common(manifest), 'identity_mismatch', 'Recovery evidence belongs to another run or source.')
            context = read_json(run.file('private/terraform/controller.json'))
            view = SimpleNamespace(run=run, lease=lease, provisioner=context['id'], receipt=prior,
                owned={x['address']: x['id'] for x in prior['resources']})
            stamp = now()
            value = {**common(manifest), 'operation': 'scoped-cleanup', 'attempt_id': str(uuid4()),
                'reason': 'cancelled' if cancellation_requested(run) else 'failure', 'status': 'blocked',
                'created_at': stamp, 'updated_at': stamp, 'primary_failure': deepcopy(prior['primary_failure']),
                'secondary_failures': [{'code': safe_code(error), 'recorded_at': stamp}],
                'resources': _resources(view, lease), 'unknown_outcome': prior['unknown_outcome'],
                'terraform_state_retained': True, 'private_state_removed': False,
                'runtime_pipeline_complete': False, 'production_iso_eligible': False}
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
