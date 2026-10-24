"""Compact isolation-qualification receipts, without process or resource access.

The coordinator must derive every check from its retained, source-bound proof.
This pure contract only checks the declared grid, identity and truthful progress
states. A valid receipt proves no live overlap, lock, recovery or publication.
Authentication is represented by a uniqueness boolean, never key bytes/hashes.
"""
from copy import deepcopy
from datetime import datetime
import json

from .contracts import ContractError, _bounded_json, _validate
from .runs import RunError

VERSION = '1.0'
OPERATION = 'real-isolation-acceptance-v1'
MAX_RECEIPT_BYTES = 32768
MAX_PROOF_BYTES = 256 * 1024
CASE_NAMES = ('overlap', 'interrupted-run', 'interrupted-publication', 'oversized-capacity')
CHECKS = {
    'overlap': ('busy-no-allocation', 'live-process-overlap', 'serialized-admission',
        'distinct-owned-state', 'distinct-owned-resources', 'distinct-authentication',
        'first-recovery-run-busy', 'second-recovery-infrastructure-busy',
        'original-a-preserved', 'cleanup-completed', 'sentinel-unchanged'),
    'interrupted-run': ('terminal-destroy-before-interruption', 'no-unknown-mutation',
        'unreconciled-refusal', 'exact-source-recovery', 'primary-preserved',
        'owned-state-retained', 'cleanup-completed', 'sentinel-unchanged'),
    'interrupted-publication': ('same-source-reference-passed', 'before-complete-owned-child',
        'both-markers-absent', 'inspector-incomplete', 'duplicate-preserved',
        'original-evidence-unchanged', 'sentinel-unchanged'),
    'oversized-capacity': ('synthetic-fixed-root', 'capacity-refused', 'no-allocation',
        'prior-state-preserved', 'no-twenty-runtime'),
}


class IsolationRecordError(RunError):
    pass


def require(condition, code='isolation_receipt_invalid'):
    if not condition:
        raise IsolationRecordError(code, 'Isolation receipt refused; retain the original proof.')


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                          allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise IsolationRecordError('isolation_receipt_invalid', 'Isolation data is not bounded JSON.') from None


def _object(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


def _text(maximum, pattern):
    return {'type': 'string', 'minLength': 1, 'maxLength': maximum,
            'pattern': '^(?:' + pattern + r')$(?![\s\S])'}


def _constant(value):
    return {'type': 'boolean' if type(value) is bool else 'string', 'const': value}


def _nullable(definition):
    return {**deepcopy(definition), 'type': [definition['type'], 'null']}


UUID = {**_text(36, '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), 'format': 'uuid'}
DATE = {**_text(32, r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z'), 'format': 'date-time'}
CODE = _text(80, '[a-z][a-z0-9_]{0,79}')
SHA = _text(64, '[a-f0-9]{64}')
CHECK = {'type': ['boolean', 'null']}
COMMON = {'schema_version': _constant(VERSION), 'run_id': UUID,
    'source_revision': _text(40, '[a-f0-9]{40}'), 'source_dirty': _constant(False),
    'mode': _constant('container-reference')}
FLAGS = {'simulation': _constant(False),
    'overlap_model': _constant('overlapping-live-processes-serialized-resource-graphs'),
    'allocation_scope': _constant('smoke-one-target'),
    'oversized_capacity_synthetic': _constant(True), 'twenty_target_execution': _constant(False),
    'production_iso_eligible': _constant(False)}


def checks_for(name):
    require(type(name) is str and name in CHECKS, 'isolation_case_invalid')
    return CHECKS[name]


def _proof(name=None):
    path = ('evidence/isolation-' + name + '.json') if name else None
    return _object({'logical_path': _constant(path) if path else
        _text(80, r'evidence/isolation-(?:overlap|interrupted-run|interrupted-publication|oversized-capacity)\.json'),
        'sha256': SHA, 'size_bytes': {'type': 'integer', 'minimum': 1, 'maximum': MAX_PROOF_BYTES}})


def _case(name=None):
    checks = _object({key: CHECK for key in (checks_for(name) if name else
        tuple(dict.fromkeys(key for names in CHECKS.values() for key in names)))})
    if name is None:
        checks['required'] = []
    return _object({'name': _constant(name) if name else {'type': 'string', 'enum': list(CASE_NAMES)},
        'status': {'type': 'string', 'enum': ['not-run', 'running', 'passed', 'failed']},
        'run_ids': {'type': 'array', 'items': UUID, 'minItems': 0, 'maxItems': 4, 'uniqueItems': True},
        'proof': _nullable(_proof(name)), 'failure_code': _nullable(CODE), 'checks': checks})


RECEIPT = _object({**COMMON, **FLAGS, 'operation': _constant(OPERATION), 'profile': _constant('smoke'),
    'status': {'type': 'string', 'enum': ['running', 'passed', 'failed']},
    'cases': {'type': 'array', 'items': _case(), 'minItems': 4, 'maxItems': 4},
    'primary_failure': _nullable(_object({'code': CODE, 'recorded_at': DATE})),
    'created_at': DATE, 'updated_at': DATE})


def schema():
    result = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
        '$id': 'urn:jake-wormhole:isolation-receipt:1.0',
        'title': 'Wormhole isolation qualification receipt v1',
        '$comment': 'Generated by isolation_records. Fixed validation additionally checks truthful progress, '
            'fresh child Run identities and failure chronology. Check booleans require independent '
            'coordinator proof; structural validity establishes no execution or eligibility.',
        'x-maxEncodedBytes': MAX_RECEIPT_BYTES, **deepcopy(RECEIPT)}
    result['properties']['cases'] = {'type': 'array', 'minItems': 4, 'maxItems': 4,
        'prefixItems': [_case(name) for name in CASE_NAMES], 'items': False}
    return result


def _date(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate_receipt(value):
    """Return an isolated validated copy; never load proof files or resources."""
    try:
        require(type(value) is dict)
        _bounded_json(value)
        require(len(canonical(value)) <= MAX_RECEIPT_BYTES)
        _validate(RECEIPT, value, '$')
        created, updated = _date(value['created_at']), _date(value['updated_at'])
        require(created <= updated, 'isolation_time_order')
        require(tuple(row['name'] for row in value['cases']) == CASE_NAMES, 'isolation_case_grid')
        used = {value['run_id']}
        frontier = False
        for name, row in zip(CASE_NAMES, value['cases']):
            _validate(_case(name), row, '$.cases.' + name)
            require(not used.intersection(row['run_ids']), 'isolation_run_reused')
            used.update(row['run_ids'])
            status = row['status']
            if status == 'not-run':
                require(not row['run_ids'] and row['proof'] is None and row['failure_code'] is None and
                    all(flag is None for flag in row['checks'].values()), 'isolation_unrun_claim')
            elif status == 'passed':
                require(not frontier and row['run_ids'] and row['proof'] is not None and row['failure_code'] is None and
                    all(flag is True for flag in row['checks'].values()), 'isolation_case_false_pass')
            elif status == 'running':
                require(not frontier and row['failure_code'] is None, 'isolation_case_progress')
            else:
                require(not frontier and row['failure_code'] is not None and
                    any(flag is not True for flag in row['checks'].values()), 'isolation_case_failure')
            frontier = frontier or status != 'passed'
        primary = value['primary_failure']
        if value['status'] == 'passed':
            require(primary is None and all(row['status'] == 'passed' for row in value['cases']),
                    'isolation_false_pass')
        elif value['status'] == 'running':
            require(primary is None and not any(row['status'] == 'failed' for row in value['cases']),
                    'isolation_running_failure')
        else:
            require(primary is not None and not any(row['status'] == 'running' for row in value['cases']),
                    'isolation_failure_missing')
        if primary is not None:
            require(created <= _date(primary['recorded_at']) <= updated, 'isolation_failure_time')
        return deepcopy(value)
    except IsolationRecordError:
        raise
    except (ContractError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise IsolationRecordError('isolation_receipt_invalid',
            'Isolation data is malformed, incorrectly typed or exceeds its bound.') from None


def render_receipt(value):
    return canonical(validate_receipt(value)) + b'\n'
