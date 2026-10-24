"""Pure stock-container fleet inventory records; never runtime evidence replay.

The collector/domain must bind the original plan, actual resource inspections,
captured packets and exported bytes. These structural contracts perform no I/O,
source discovery, host operation or eligibility decision.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re

from .contracts import ContractError, _bounded_json, _validate
from .runs import RunError

VERSION = '1.0'
OPERATION = 'stock-fleet-software-description-v1'
INDEX_OPERATION = 'stock-fleet-software-inventory-index-v1'
MAX_OBSERVATION_BYTES = 32768
MAX_RECORD_BYTES = 131072
MAX_INDEX_BYTES = 65536
MAX_TEXT_BYTES = 262144
TARGET_IDS = tuple('target-' + str(number).zfill(3) for number in range(1, 21))
BATCH_IDS = tuple('batch-' + str(number).zfill(3) for number in range(1, 6))
STOCK_IMAGE = 'sha256:6d15eb2c495d48c1eb6485a74d1adaef3e0e3a6e7c83063ba8459f90c27c683e'
STOCK_BUILD_RUN = '759b5541-a077-46ca-97a1-1cdfb782ba15'
STOCK_BUILD_SOURCE = '5c4656c683f02b4dca51ee6e24bd9b476a6c781a'
PACKAGES = ('ca-certificates', 'python3', 'python3.12', 'openssh-client', 'openssh-server', 'openssh-sftp-server')
CORE_CHECKS = ('target-identity', 'userland', 'package-inventory', 'runtime-sha256')
CHECK_IDS = CORE_CHECKS + tuple('package-' + name.replace('.', '-') for name in PACKAGES)
PLAN_PATH = 'evidence/fleet-inventory-plan.json'
STATUSES = ('pass', 'fail', 'error', 'unverified')
LIMITS = ('Stock Ubuntu container userland, not a candidate-derived image or a candidate version.',
    'Full installed native package records preserve Debian versions and architecture.',
    'Helper/provisioner tools are execution provenance, separate from target packages.',
    'The observed kernel is shared with the host, not installed target userland.',
    'Structural validity does not prove collection, twenty live targets or measured capacity.',
    'Complete reference pipeline and production ISO eligibility remain false.')
UNSAFE_TEXT = re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|private/|(?i:tfstate|tfplan)|'
    r'[A-Za-z]:[\\/]|/(?:srv|home|root|Users)/|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}')


class FleetInventoryRecordError(RunError):
    pass


def require(value, code='fleet_inventory_record_invalid'):
    if not value:
        raise FleetInventoryRecordError(code, 'Stock fleet inventory refused; retain original evidence and inspect the failure category.')


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise FleetInventoryRecordError('fleet_inventory_record_invalid', 'Stock fleet inventory is not bounded JSON.') from None


def obj(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def string(maximum=240, minimum=1, pattern=r'[ -~]*'):
    return {'type': 'string', 'minLength': minimum, 'maxLength': maximum, 'pattern': '^(?:' + pattern + r')$(?![\s\S])'}


def const(value):
    if type(value) is int:
        return {'type': 'integer', 'const': value, 'minimum': value, 'maximum': value}
    return {'type': 'boolean' if type(value) is bool else 'string', 'const': value}


def integer(maximum, minimum=0):
    return {'type': 'integer', 'minimum': minimum, 'maximum': maximum}


def array(items, maximum, minimum=0):
    return {'type': 'array', 'items': items, 'minItems': minimum, 'maxItems': maximum}


def nullable(value):
    return {**deepcopy(value), 'type': [value['type'], 'null']}


SHA = string(64, pattern='[a-f0-9]{64}')
IMAGE = string(71, pattern='sha256:[a-f0-9]{64}')
UUID = {**string(36, pattern='[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), 'format': 'uuid'}
DATE = {**string(32, pattern=r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z'), 'format': 'date-time'}
NATIVE_VERSION = string(240, pattern=r'[A-Za-z0-9][A-Za-z0-9.+:~^_-]{0,239}')
NAME = string(240, pattern=r'[a-z0-9][a-z0-9+.-]{0,199}(?::[a-z0-9][a-z0-9-]{0,38})?')
ARCH = string(64, pattern=r'[a-z0-9][a-z0-9_-]{0,63}')
TARGET_ID = {'type': 'string', 'enum': list(TARGET_IDS)}
BATCH_ID = {'type': 'string', 'enum': list(BATCH_IDS)}
CHECK_STATUS = {'type': 'string', 'enum': list(STATUSES)}
PATH = string(160, pattern=r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,63})*')
COMMON = {'schema_version': const(VERSION), 'run_id': UUID, 'source_revision': string(40, pattern='[a-f0-9]{40}'),
    'source_dirty': const(False), 'mode': const('container-reference')}
FAILURE = obj({'code': string(80, pattern='[a-z][a-z0-9_]{0,79}'), 'recorded_at': DATE})
FLAGS = {'runtime_pipeline_complete': const(False), 'production_iso_eligible': const(False)}
TARGET = obj({'target_id': TARGET_ID, 'resource_id': SHA, 'image_digest': const(STOCK_IMAGE)})
STOCK_BUILD = obj({'run_id': const(STOCK_BUILD_RUN), 'source_revision': const(STOCK_BUILD_SOURCE),
    'recipe_sha256': SHA, 'runtime_sha256': SHA})
COLLECTOR = obj({'version': const(VERSION), 'sha256': SHA, 'helper_source_sha256': SHA, 'readiness_source_sha256': SHA})
PROVENANCE = obj({'helper': obj({'image_digest': IMAGE, 'python_version': NATIVE_VERSION, 'ansible_core_version': NATIVE_VERSION}),
    'provisioner': obj({'image_digest': IMAGE, 'terraform_version': NATIVE_VERSION, 'provider_version': NATIVE_VERSION})})
OBSERVATION = obj({'schema_version': const(VERSION),
    'os': obj({'id': string(64, pattern='[a-z][a-z0-9_-]{0,63}'), 'version_id': NATIVE_VERSION,
        'name': string(240), 'architecture': ARCH}), 'package_manager': const('dpkg'),
    'packages': array(obj({'name': NAME, 'version': NATIVE_VERSION, 'architecture': ARCH}), 2048, 1),
    'runtime_sha256': SHA, 'shared_kernel': obj({'scope': const('host-shared'), 'release': string(240)})})
CHECK = obj({'check_id': {'type': 'string', 'enum': list(CHECK_IDS)}, 'target_id': TARGET_ID, 'required': const(True),
    'expected': string(4000, 0), 'observed': string(4000, 0), 'status': CHECK_STATUS, 'evidence': array(PATH, 16)})
CAPTURE = obj({'batch_id': BATCH_ID, 'path': {'type': 'string', 'enum': ['captures/stock-inventory/' + item for item in BATCH_IDS]},
    'sha256': SHA, 'size_bytes': integer(262144, 1), 'complete': {'type': 'boolean'},
    'collector_sha256': nullable(SHA), 'collector_bytes': integer(MAX_OBSERVATION_BYTES)})
RECORD = obj({**COMMON, 'operation': const(OPERATION), 'profile': const('twenty-targets'), 'status': {'type': 'string', 'enum': ['passed', 'failed']},
    'plan_sha256': SHA, 'target_id': TARGET_ID, 'target': nullable(TARGET), 'stock_build': STOCK_BUILD, 'collector': COLLECTOR,
    'observation': nullable(OBSERVATION), 'execution_provenance': nullable(PROVENANCE), 'checks': array(CHECK, 10, 10),
    'capture': nullable(CAPTURE), 'primary_failure': nullable(FAILURE), 'unknown_outcome': {'type': 'boolean'},
    'updated_at': DATE, **FLAGS})
FILE = obj({'path': PATH, 'sha256': SHA, 'size_bytes': integer(MAX_TEXT_BYTES, 1)})
INDEX_TARGET = obj({'target_id': TARGET_ID, 'status': {'type': 'string', 'enum': ['passed', 'failed']},
    'record': FILE, 'text': FILE, 'checks': array(obj({'check_id': {'type': 'string', 'enum': list(CHECK_IDS)}, 'status': CHECK_STATUS}), 10, 10)})
INDEX = obj({**COMMON, 'operation': const(INDEX_OPERATION), 'profile': const('twenty-targets'), 'target_count': const(20),
    'controller_concurrency': integer(4, 1), 'status': {'type': 'string', 'enum': ['passed', 'failed']}, 'plan_sha256': SHA,
    'targets': array(INDEX_TARGET, 20, 20), 'primary_failure': nullable(FAILURE), 'unknown_outcome': {'type': 'boolean'},
    'updated_at': DATE, **FLAGS})


def _schema(definition, name, maximum):
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:jake-wormhole:' + name + ':1.0',
        'title': 'Stock fleet ' + name + ' v1',
        '$comment': 'Generated by fleet_inventory_records. Fixed validation also enforces ordering, exact check/target grids, '
            'canonical packet hashes, failure consistency and logical namespaces. Runtime domain replay of the frozen plan, '
            'actual resource identity, original captures and exported bytes is required; structural validity proves no execution or eligibility.',
        'x-maxEncodedBytes': maximum, **deepcopy(definition)}


def schema():
    return _schema(RECORD, 'fleet-software-inventory', MAX_RECORD_BYTES)


def observation_schema():
    return _schema(OBSERVATION, 'fleet-software-observation', MAX_OBSERVATION_BYTES)


def index_schema():
    return _schema(INDEX, 'fleet-software-inventory-index', MAX_INDEX_BYTES)


def _bounded(definition, value, maximum):
    try:
        require(type(value) is dict)
        _bounded_json(value)
        require(len(canonical(value)) <= maximum, 'fleet_inventory_record_bound')
        _validate(definition, value, '$')
        _safe_projection(value)
    except FleetInventoryRecordError:
        raise
    except (ContractError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise FleetInventoryRecordError('fleet_inventory_record_invalid', 'Stock fleet inventory is malformed or exceeds its bound.') from None


def _safe_projection(value):
    """Closed fields plus narrow accidental-secret/path checks, not a scanner."""
    if type(value) is str:
        require(UNSAFE_TEXT.search(value) is None, 'fleet_inventory_unsafe_projection')
    elif type(value) is dict:
        for item in value.values():_safe_projection(item)
    elif type(value) is list:
        for item in value:_safe_projection(item)


def _dates(value):
    updated = datetime.fromisoformat(value['updated_at'].replace('Z', '+00:00'))
    failure = value['primary_failure']
    if failure is not None:
        recorded = datetime.fromisoformat(failure['recorded_at'].replace('Z', '+00:00'))
        require(recorded <= updated, 'fleet_inventory_failure_time')


def batch_for(target_id):
    require(type(target_id) is str and target_id in TARGET_IDS, 'fleet_inventory_target')
    return BATCH_IDS[TARGET_IDS.index(target_id) // 4]


def evidence_for(target_id):
    return [PLAN_PATH, 'captures/stock-inventory/' + batch_for(target_id)]


def validate_observation(value):
    """Preserve the complete sorted installed native database without truncation."""
    _bounded(OBSERVATION, value, MAX_OBSERVATION_BYTES)
    identities = [(package['name'], package['architecture']) for package in value['packages']]
    require(identities == sorted(identities) and len(set(identities)) == len(identities), 'fleet_inventory_package_order')
    return deepcopy(value)


def observed_values(record):
    """Exact row text from validated-shaped actual metadata/observation only.

    This helper does not validate a full record (the domain uses it while building
    the rows). Missing observations never produce passing dependent row values.
    """
    require(type(record) is dict)
    target = record.get('target'); observation = record.get('observation')
    if target is not None:
        _bounded(TARGET, target, 4096)
    result = {'target-identity': '' if target is None else canonical(target).decode('ascii')}
    result.update({key: '' for key in CHECK_IDS[1:]})
    if observation is not None:
        value = validate_observation(observation)
        result.update({'userland': canonical({key: value['os'][key] for key in ('id', 'version_id', 'architecture')}).decode('ascii'),
            'package-inventory': 'complete-installed-dpkg-inventory', 'runtime-sha256': value['runtime_sha256']})
        for name in PACKAGES:
            packages = [package for package in value['packages'] if package['name'] == name]
            result['package-' + name.replace('.', '-')] = ('not installed' if not packages else
                packages[0]['version'] if len(packages) == 1 else 'ambiguous installed architectures')
    return result


def validate_record(value):
    _bounded(RECORD, value, MAX_RECORD_BYTES)
    _dates(value)
    checks = value['checks']; target_id = value['target_id']
    require([row['check_id'] for row in checks] == list(CHECK_IDS) and
        all(row['target_id'] == target_id for row in checks), 'fleet_inventory_check_grid')
    require(all(row['status'] != 'pass' or row['expected'] == row['observed'] for row in checks), 'fleet_inventory_check_mismatch')
    require(all(row['evidence'] == evidence_for(target_id) for row in checks), 'fleet_inventory_evidence')
    target, observation, capture = value['target'], value['observation'], value['capture']
    require(target is None or target['target_id'] == target_id, 'fleet_inventory_target')
    if capture is not None:
        batch = batch_for(target_id)
        require(capture['batch_id'] == batch and capture['path'] == 'captures/stock-inventory/' + batch, 'fleet_inventory_capture_namespace')
    observed = observed_values(value)
    require(all(row['observed'] == observed[row['check_id']] for row in checks), 'fleet_inventory_observed_rows')
    if observation is None:
        require(value['status'] == 'failed' and all(row['status'] == 'unverified' for row in checks[1:]), 'fleet_inventory_missing_observation')
        require(target is not None or checks[0]['status'] in ('error', 'unverified'), 'fleet_inventory_missing_target')
        require(capture is None or capture['collector_sha256'] is None and capture['collector_bytes'] == 0, 'fleet_inventory_missing_packet')
    else:
        raw = canonical(observation)
        require(target is not None and value['execution_provenance'] is not None and capture is not None and capture['complete'] is True and
            capture['collector_sha256'] == hashlib.sha256(raw).hexdigest() and capture['collector_bytes'] == len(raw) and
            capture['size_bytes'] >= len(raw), 'fleet_inventory_capture_binding')
    if value['status'] == 'passed':
        require(observation is not None and observation['runtime_sha256'] == value['stock_build']['runtime_sha256'] and
            all(observed[key] not in ('not installed', 'ambiguous installed architectures') for key in CHECK_IDS[4:]) and
            {key: observation['os'][key] for key in ('id', 'version_id', 'architecture')} ==
                {'id': 'ubuntu', 'version_id': '24.04', 'architecture': 'amd64'} and
            all(row['status'] == 'pass' for row in checks) and value['primary_failure'] is None and value['unknown_outcome'] is False,
            'fleet_inventory_false_pass')
    else:
        require(value['primary_failure'] is not None, 'fleet_inventory_missing_failure')
    return deepcopy(value)


def validate_index(value):
    _bounded(INDEX, value, MAX_INDEX_BYTES)
    _dates(value)
    require([row['target_id'] for row in value['targets']] == list(TARGET_IDS), 'fleet_inventory_index_target_grid')
    for row in value['targets']:
        target_id = row['target_id']; prefix = 'evidence/fleet-inventory/targets/' + target_id + '/svd.'
        require(row['record']['path'] == prefix + 'json' and row['text']['path'] == prefix + 'txt' and
            row['record']['size_bytes'] <= MAX_RECORD_BYTES, 'fleet_inventory_index_namespace')
        require([check['check_id'] for check in row['checks']] == list(CHECK_IDS), 'fleet_inventory_index_check_grid')
        require(row['status'] != 'passed' or all(check['status'] == 'pass' for check in row['checks']), 'fleet_inventory_index_false_target_pass')
    if value['status'] == 'passed':
        require(all(row['status'] == 'passed' for row in value['targets']) and value['primary_failure'] is None and
            value['unknown_outcome'] is False, 'fleet_inventory_index_false_pass')
    else:
        require(value['primary_failure'] is not None, 'fleet_inventory_index_missing_failure')
    return deepcopy(value)


def render_json(value):
    return canonical(validate_record(value)) + b'\n'


def render_text(record):
    value = validate_record(record)
    lines = ['WORMHOLE STOCK FLEET SOFTWARE VERSION DESCRIPTION', 'Status: ' + value['status'],
        'Run: ' + value['run_id'], 'Controller source: ' + value['source_revision'], 'Plan SHA256: ' + value['plan_sha256'],
        'Target namespace: ' + value['target_id'], 'Stock build Run: ' + value['stock_build']['run_id'],
        'Stock build source: ' + value['stock_build']['source_revision'], 'Stock recipe SHA256: ' + value['stock_build']['recipe_sha256'],
        'Stock baked runtime SHA256: ' + value['stock_build']['runtime_sha256'], 'Collector version: ' + value['collector']['version'],
        'Collector program SHA256: ' + value['collector']['sha256'], 'Helper source SHA256: ' + value['collector']['helper_source_sha256'],
        'Readiness source SHA256: ' + value['collector']['readiness_source_sha256']]
    target = value['target']
    lines.extend(['Actual target identity: unverified'] if target is None else ['Resource: ' + target['resource_id'], 'Image: ' + target['image_digest']])
    capture = value['capture']
    if capture is None:
        lines.append('Capture: unavailable')
    else:
        lines.extend(['Capture logical reference: ' + capture['path'], 'Capture SHA256: ' + capture['sha256'],
            'Capture bytes: ' + str(capture['size_bytes']), 'Capture complete: ' + str(capture['complete']).lower(),
            'Canonical collector packet SHA256: ' + (capture['collector_sha256'] or 'unverified'),
            'Canonical collector packet bytes: ' + str(capture['collector_bytes'])])
    observation = value['observation']
    if observation is None:
        lines.append('Target software: unverified; no complete observation.')
    else:
        system = observation['os']
        lines.extend(['', 'Target userland: ' + system['name'] + ' (' + system['id'] + ' ' + system['version_id'] + ')',
            'Target architecture: ' + system['architecture'], 'Package manager: dpkg',
            'Installed target packages: ' + str(len(observation['packages']))])
        lines.extend('  ' + package['name'] + ' | version=' + package['version'] + ' | architecture=' + package['architecture']
            for package in observation['packages'])
        lines.extend(['Observed baked runtime SHA256: ' + observation['runtime_sha256'],
            'Shared host kernel release (separate from target packages): ' + observation['shared_kernel']['release']])
    lines.extend(['', 'Execution provenance (separate from installed target packages)'])
    provenance = value['execution_provenance']
    if provenance is None:
        lines.append('  unverified')
    else:
        lines.extend(['  Helper image: ' + provenance['helper']['image_digest'], '  Helper Python: ' + provenance['helper']['python_version'],
            '  Helper Ansible Core: ' + provenance['helper']['ansible_core_version'], '  Provisioner image: ' + provenance['provisioner']['image_digest'],
            '  Provisioner Terraform: ' + provenance['provisioner']['terraform_version'], '  Provisioner provider: ' + provenance['provisioner']['provider_version']])
    lines.append('\nRequired target checks: ' + str(len(value['checks'])))
    for row in value['checks']:
        lines.extend([row['target_id'] + ' / ' + row['check_id'] + ': ' + row['status'], '  expected: ' + row['expected'],
            '  observed: ' + row['observed'], '  evidence: ' + ', '.join(row['evidence'])])
    lines.extend(['Primary failure: ' + ('none' if value['primary_failure'] is None else value['primary_failure']['code']),
        'Unknown outcome: ' + str(value['unknown_outcome']).lower(), 'Updated: ' + value['updated_at'], *LIMITS])
    raw = '\n'.join(lines) + '\n'
    require(len(raw.encode('utf-8')) <= MAX_TEXT_BYTES, 'fleet_inventory_text_bound')
    return raw
