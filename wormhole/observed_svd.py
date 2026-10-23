"""Pure observed SVD validation/rendering; no reads, commands or eligibility gate.

The domain collector replays the original frozen plan/capture and independently
checks resource ownership before it calls this module. Structural validity is
not evidence that these observations actually occurred.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re

from .contracts import ContractError, _bounded_json, _validate
from .runs import RunError

MAX_RECORD_BYTES = 262144
MAX_OBSERVATION_BYTES = 32768
FILES = ('source.synthetic.bin', 'payload.py', 'version.txt', 'config.json')
CORE_CHECKS = ('target-identity', 'userland', 'package-inventory', 'payload-version',
               'payload-sha256', 'candidate-manifest-sha256', 'candidate-content-sha256',
               'candidate-source-sha256')
LOG = 'private/qualification-helper-software-inventory-0.log'
LIMITS = ('Container userland observation; the kernel is shared with the host.',
          'Helper and provisioner versions are execution provenance, not target packages.',
          'No VM installation, ISO boot, operating-system STIG or scanner acceptance.',
          'Complete runtime pipeline and production ISO eligibility remain false.')


class ObservedSVDError(RunError):
    pass


def require(value, code='observed_svd_invalid'):
    if not value:
        raise ObservedSVDError(code, 'Observed SVD refused; retain original evidence and inspect the failure category.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def same(left, right):
    return canonical(left) == canonical(right)


def obj(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def string(maximum=240, minimum=1, pattern=r'[ -~]*'):
    return {'type': 'string', 'minLength': minimum, 'maxLength': maximum,
            'pattern': '^(?:' + pattern + r')$(?![\s\S])'}


def const(value):
    return {'type': 'boolean' if type(value) is bool else 'string', 'const': value}


def integer(maximum, minimum=0):
    return {'type': 'integer', 'minimum': minimum, 'maximum': maximum}


def array(items, maximum, minimum=0):
    return {'type': 'array', 'items': items, 'minItems': minimum, 'maxItems': maximum}


def nullable(value):
    return {**deepcopy(value), 'type': [value['type'], 'null']}


SHA = string(64, pattern='[a-f0-9]{64}')
IMAGE = string(71, pattern='sha256:[a-f0-9]{64}')
ID = string(64, pattern='[a-z][a-z0-9_-]{0,63}')
DATE = {**string(32, pattern=r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z'), 'format': 'date-time'}
PATH = string(1024, pattern=r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*')
VERSION = string(240, pattern=r'[A-Za-z0-9][A-Za-z0-9.+:~^_-]{0,239}')
NAME = string(240, pattern=r'[A-Za-z0-9][A-Za-z0-9+._-]{0,239}')
ARCH = string(64, pattern=r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
DPKG = obj({'name': NAME, 'version': VERSION, 'architecture': ARCH})
RPM = obj({'name': NAME, 'epoch': integer(2**32 - 1), 'version': VERSION, 'release': VERSION, 'arch': ARCH})
KEY = obj({'name': const('gpg-pubkey'), 'epoch': integer(2**32 - 1), 'version': VERSION,
           'release': VERSION, 'arch': nullable(ARCH)})
PAYLOAD = obj({'version': VERSION, 'sha256': SHA, 'manifest_sha256': SHA, 'content_sha256': SHA,
               'source_sha256': SHA, 'files': array(obj({'path': {'type': 'string', 'enum': list(FILES)},
                   'bytes': integer(16 * 1024 * 1024, 1), 'sha256': SHA}), 4, 4)})
OBSERVATION_BASE = {
    'schema_version': const('1.0'),
    'os': obj({'id': ID, 'version_id': VERSION, 'name': string(240), 'architecture': ARCH}),
    'package_manager': None, 'packages': None,
    'rpm_key_headers': array(KEY, 16), 'payload': PAYLOAD,
    'shared_kernel': obj({'scope': const('host-shared'), 'release': string(240)})}


def observation_definition(family):
    properties = deepcopy(OBSERVATION_BASE)
    properties['package_manager'] = const(family)
    properties['packages'] = array(DPKG if family == 'dpkg' else RPM, 2048, 1)
    if family == 'dpkg':
        properties['rpm_key_headers'] = array(KEY, 0)
    return obj(properties)


RECORD = obj({
    'schema_version': const('1.0'),
    'run_id': {**string(36, pattern=r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), 'format': 'uuid'},
    'source_revision': string(40, pattern='[a-f0-9]{40}'), 'source_dirty': const(False),
    'mode': const('container-reference'), 'operation': const('observed-software-description-v1'),
    'status': {'type': 'string', 'enum': ['passed', 'failed']}, 'plan_sha256': SHA,
    'collector': obj({'version': const('1.0'), 'sha256': SHA, 'helper_source_sha256': SHA, 'readiness_source_sha256': SHA}),
    'target': nullable(obj({'target_id': const('target-001'), 'resource_id': SHA, 'image_digest': IMAGE,
        'candidate_sha256': SHA, 'source_candidate_sha256': SHA, 'content_sha256': SHA})),
    'observation': {'oneOf': [{'type': 'null'}, observation_definition('dpkg'), observation_definition('rpm')]},
    'execution_provenance': nullable(obj({
        'helper': obj({'image_digest': IMAGE, 'python_version': VERSION, 'ansible_core_version': VERSION}),
        'provisioner': obj({'image_digest': IMAGE, 'terraform_version': VERSION, 'provider_version': VERSION})})),
    'checks': array(obj({'check_id': ID, 'target_id': const('target-001'), 'required': const(True),
        'expected': string(4000, 0), 'observed': string(4000, 0),
        'status': {'type': 'string', 'enum': ['pass', 'fail', 'error', 'unverified']}, 'evidence': array(PATH, 16)}), 64, 8),
    'capture': nullable(obj({'path': const(LOG), 'sha256': SHA, 'size_bytes': integer(65536),
        'budget_seconds': {'type': 'number', 'minimum': 0, 'maximum': 35}, 'complete': {'type': 'boolean'},
        'collector_sha256': nullable(SHA), 'collector_bytes': integer(MAX_OBSERVATION_BYTES)})),
    'primary_failure': nullable(obj({'code': string(80, pattern='[a-z][a-z0-9_]{0,79}'), 'recorded_at': DATE})),
    'unknown_outcome': {'type': 'boolean'}, 'updated_at': DATE,
    'runtime_pipeline_complete': const(False), 'production_iso_eligible': const(False)})


def schema():
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema',
        '$id': 'urn:jake-wormhole:observed-svd:1.0', 'title': 'Observed container Software Version Description v1',
        '$comment': 'Generated by wormhole.observed_svd.schema(). Fixed domain validation additionally enforces canonical ordering, complete check IDs, capture/content hashes and status consistency. Original plan/capture/resource provenance must be replayed by software_inventory; this structural contract alone establishes no execution or eligibility.',
        'x-maxEncodedBytes': MAX_RECORD_BYTES, 'x-maxObservationBytes': MAX_OBSERVATION_BYTES, **deepcopy(RECORD)}


def validate_observation(value):
    """Validate native fields without dropping/reordering any package or key."""
    require(type(value) is dict and value.get('package_manager') in ('dpkg', 'rpm'))
    try:
        _bounded_json(value)
        _validate(observation_definition(value['package_manager']), value, '$.observation')
        require(len(canonical(value)) <= MAX_OBSERVATION_BYTES, 'observed_svd_observation_bound')
    except (ContractError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ObservedSVDError('observed_svd_invalid', 'Native observation is invalid or exceeds its bound.') from None
    packages = value['packages']
    if value['package_manager'] == 'dpkg':
        identities = [(p['name'], p['architecture']) for p in packages]
    else:
        identities = [(p['name'], p['epoch'], p['version'], p['release'], p['arch']) for p in packages]
        require(not any(p['name'] == 'gpg-pubkey' for p in packages), 'observed_svd_key_as_package')
    require(identities == sorted(identities) and len(set(identities)) == len(identities), 'observed_svd_package_order')
    keys = [(k['name'], k['epoch'], k['version'], k['release'], k['arch'] or '') for k in value['rpm_key_headers']]
    require(keys == sorted(keys) and len(set(keys)) == len(keys), 'observed_svd_key_order')
    payload = value['payload']; files = payload['files']
    require([f['path'] for f in files] == list(FILES), 'observed_svd_payload_files')
    manifest_files = [{'path': f['path'], 'size': f['bytes'], 'sha256': f['sha256']} for f in files]
    require(payload['sha256'] == files[1]['sha256'] and payload['source_sha256'] == files[0]['sha256'] and
        payload['content_sha256'] == hashlib.sha256(canonical({'files': manifest_files})).hexdigest(), 'observed_svd_payload_hash')
    return deepcopy(value)


def validate_record(record):
    """Return an independent exact copy; reject malformed/incomplete claims."""
    try:
        require(type(record) is dict)
        _bounded_json(record)
        require(len(canonical(record)) <= MAX_RECORD_BYTES, 'observed_svd_record_bound')
        # Select exactly one fixed published oneOf branch. The common fixed
        # contract validator is intentionally not a general JSON Schema engine.
        definition = deepcopy(RECORD)
        observation = record.get('observation')
        definition['properties']['observation'] = {'type': 'null'} if observation is None else observation_definition(
            observation.get('package_manager') if type(observation) is dict else None)
        _validate(definition, record, '$')
        for timestamp in (record['updated_at'], None if record['primary_failure'] is None else record['primary_failure']['recorded_at']):
            if timestamp is not None:
                require(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).utcoffset() is not None)
    except ObservedSVDError:
        raise
    except (ContractError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ObservedSVDError('observed_svd_invalid', 'Observed SVD record is malformed or exceeds its bound.') from None
    checks = record['checks']; ids = [row['check_id'] for row in checks]
    require(ids[:len(CORE_CHECKS)] == list(CORE_CHECKS) and len(set(ids)) == len(ids) and
        all(re.fullmatch(r'package-[a-z0-9][a-z0-9_-]{0,55}', key) for key in ids[len(CORE_CHECKS):]) and
        ids[len(CORE_CHECKS):] == sorted(ids[len(CORE_CHECKS):]), 'observed_svd_check_set')
    require(all(row['status'] != 'pass' or row['expected'] == row['observed'] for row in checks), 'observed_svd_check_mismatch')
    require(all(len(set(row['evidence'])) == len(row['evidence']) for row in checks), 'observed_svd_evidence_duplicate')
    observation = record['observation']; target = record['target']; capture = record['capture']
    if observation is None:
        require(record['status'] == 'failed' and all(row['status'] == 'unverified' for row in checks[1:]), 'observed_svd_missing_observation')
        require(target is not None or checks[0]['status'] != 'pass', 'observed_svd_missing_target')
    else:
        validate_observation(observation)
        raw = canonical(observation)
        require(target is not None and record['execution_provenance'] is not None and capture is not None and capture['complete'] is True and
            capture['collector_sha256'] == hashlib.sha256(raw).hexdigest() and capture['collector_bytes'] == len(raw) and
            capture['size_bytes'] >= len(raw), 'observed_svd_capture_binding')
        require(observation['payload']['manifest_sha256'] == target['candidate_sha256'] and
            observation['payload']['content_sha256'] == target['content_sha256'], 'observed_svd_candidate_binding')
    if record['status'] == 'passed':
        require(observation is not None and all(row['status'] == 'pass' for row in checks) and record['primary_failure'] is None and
            record['unknown_outcome'] is False, 'observed_svd_false_pass')
    else:
        require(record['primary_failure'] is not None, 'observed_svd_missing_failure')
    return deepcopy(record)


def render_json(record):
    """Stable UTF-8 artifact bytes from the same validated record as text."""
    value = validate_record(record)
    return canonical(value) + b'\n'


def render_text(record):
    """Complete deterministic projection; no package, failed row or identity hidden."""
    value = validate_record(record)
    lines = ['WORMHOLE OBSERVED SOFTWARE VERSION DESCRIPTION', 'Status: ' + value['status'],
        'Run: ' + value['run_id'], 'Controller source: ' + value['source_revision'], 'Plan SHA256: ' + value['plan_sha256'],
        'Collector version: ' + value['collector']['version'], 'Collector program SHA256: ' + value['collector']['sha256'],
        'Helper source SHA256: ' + value['collector']['helper_source_sha256'],
        'Readiness source SHA256: ' + value['collector']['readiness_source_sha256']]
    target = value['target']
    if target is None:
        lines.append('Target identity: unverified')
    else:
        lines.extend(['Target: ' + target['target_id'], 'Resource: ' + target['resource_id'], 'Image: ' + target['image_digest'],
            'Candidate SHA256: ' + target['candidate_sha256'], 'Source candidate SHA256: ' + target['source_candidate_sha256'],
            'Candidate content SHA256: ' + target['content_sha256']])
    capture = value['capture']
    if capture is None:
        lines.append('Capture: unavailable')
    else:
        lines.extend(['Capture: ' + capture['path'], 'Capture SHA256: ' + capture['sha256'], 'Capture bytes: ' + str(capture['size_bytes']),
            'Capture complete: ' + str(capture['complete']).lower(), 'Canonical collector bytes: ' + str(capture['collector_bytes']),
            'Canonical collector SHA256: ' + (capture['collector_sha256'] or 'unverified')])
    observation = value['observation']
    if observation is None:
        lines.extend(['', 'Target software: unverified; no complete observation.'])
    else:
        system = observation['os']
        lines.extend(['', 'Target userland: ' + system['name'] + ' (' + system['id'] + ' ' + system['version_id'] + ')',
            'Target architecture: ' + system['architecture'], 'Package manager: ' + observation['package_manager'],
            'Installed target packages: ' + str(len(observation['packages']))])
        for package in observation['packages']:
            if observation['package_manager'] == 'dpkg':
                lines.append('  ' + package['name'] + ' | version=' + package['version'] + ' | architecture=' + package['architecture'])
            else:
                lines.append('  ' + package['name'] + ' | epoch=' + str(package['epoch']) + ' | version=' + package['version'] +
                    ' | release=' + package['release'] + ' | arch=' + package['arch'])
        lines.append('RPM virtual key headers (not application packages): ' + str(len(observation['rpm_key_headers'])))
        for key in observation['rpm_key_headers']:
            lines.append('  gpg-pubkey | epoch=' + str(key['epoch']) + ' | version=' + key['version'] + ' | release=' + key['release'] +
                ' | arch=' + ('null (reported absent)' if key['arch'] is None else key['arch']))
        payload = observation['payload']
        lines.extend(['Payload version: ' + payload['version'], 'Payload SHA256: ' + payload['sha256'],
            'Payload manifest SHA256: ' + payload['manifest_sha256'], 'Payload content SHA256: ' + payload['content_sha256'],
            'Payload source SHA256: ' + payload['source_sha256']])
        lines.extend('  ' + item['path'] + ' | bytes=' + str(item['bytes']) + ' | sha256=' + item['sha256'] for item in payload['files'])
        lines.append('Shared host kernel release (not target package inventory): ' + observation['shared_kernel']['release'])
    lines.extend(['', 'Execution provenance (separate from installed target packages)'])
    provenance = value['execution_provenance']
    if provenance is None:
        lines.append('  unverified')
    else:
        lines.extend(['  Helper image: ' + provenance['helper']['image_digest'], '  Helper Python: ' + provenance['helper']['python_version'],
            '  Helper Ansible Core: ' + provenance['helper']['ansible_core_version'], '  Provisioner image: ' + provenance['provisioner']['image_digest'],
            '  Provisioner Terraform: ' + provenance['provisioner']['terraform_version'], '  Provisioner provider: ' + provenance['provisioner']['provider_version']])
    lines.extend(['', 'Required checks: ' + str(len(value['checks']))])
    for row in value['checks']:
        lines.extend([row['target_id'] + ' / ' + row['check_id'] + ': ' + row['status'], '  expected: ' + row['expected'],
            '  observed: ' + row['observed'], '  evidence: ' + ', '.join(row['evidence'])])
    lines.extend(['Primary failure: ' + ('none' if value['primary_failure'] is None else value['primary_failure']['code']),
        'Unknown outcome: ' + str(value['unknown_outcome']).lower(), 'Updated: ' + value['updated_at'], *LIMITS])
    return '\n'.join(lines) + '\n'
