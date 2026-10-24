"""Closed reference-publication records; no filesystem or eligibility operations.

The publisher must independently replay the held Run, read exact source bytes,
observe privacy and commit the destination. These pure validators prove none of
those operations. COMPLETE describes a logically complete reference artifact;
only a successful producer receipt acknowledges its later directory fsync.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import json

from .contracts import ContractError, _bounded_json, _validate
from .runs import RunError

VERSION = '1.0'
COMPLETE_OPERATION = 'reference-publication-complete-v1'
CHECKSUMS_OPERATION = 'reference-publication-checksums-v1'
RECEIPT_OPERATION = 'reference-publication-receipt-v1'
ARTIFACT_KIND = 'tested-candidate-files-with-evidence'
LABEL = 'WORMHOLE REFERENCE ARTIFACT'
COMMON_KEYS = ('schema_version', 'run_id', 'source_revision', 'source_dirty', 'mode')
MAX_RECORD_BYTES = 65536
MAX_RECEIPT_BYTES = 16384
MAX_FILES = 32
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CANDIDATE_BYTES = 8 * 1024 * 1024 + 65536
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
CANDIDATE_NAMES = ('source.synthetic.bin', 'payload.py', 'version.txt', 'config.json')
EVIDENCE_PATHS = (
    'manifest.json', 'plan.json', 'summary.json', 'report.json', 'report.txt', 'report.junit.xml',
    'targets/target-001/readiness.json', 'targets/target-001/tests.json', 'targets/target-001/svd.json',
    'targets/target-001/assessment.json', 'targets/target-001/logs.json', 'cleanup.json',
    'targets/target-001/observed-svd.json', 'targets/target-001/observed-svd.txt',
    'checksums.json', 'decision.json',
)
EULA_PATH = 'licenses/UBI-EULA-20190422.pdf'
EULA_BYTES = 248785
EULA_SHA256 = 'a07025b9f5b71a816febe6ac76f21c9f759c806fa0a66874af90a50c3293f1b6'
REFERENCE_BYTES = (
    'WORMHOLE REFERENCE ARTIFACT\n'
    'Scope: one container target, generated candidate bytes and a synthetic assessment.\n'
    'This bundle contains exact tested candidate files and safe reference evidence.\n'
    'The tested image digest is metadata; no image or remote release is published.\n'
    'Production eligible: false\n'
    'Production ISO eligible: false\n'
    'No VM installation, ISO boot, scanner or operating-system STIG acceptance.\n'
).encode('ascii')


class PublicationRecordError(RunError):
    pass


def require(condition, code='publication_record_invalid'):
    if not condition:
        raise PublicationRecordError(code, 'Reference publication record refused; preserve the original evidence.')


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise PublicationRecordError('publication_record_invalid', 'Publication data is not bounded JSON.') from None


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def obj(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def text(maximum, pattern, minimum=1):
    return {'type': 'string', 'minLength': minimum, 'maxLength': maximum,
            'pattern': '^(?:' + pattern + r')$(?![\s\S])'}


def const(value):
    return {'type': 'boolean' if type(value) is bool else 'string', 'const': value}


def integer(maximum, minimum=0):
    return {'type': 'integer', 'minimum': minimum, 'maximum': maximum}


def nullable(definition):
    return {**deepcopy(definition), 'type': [definition['type'], 'null']}


SHA = text(64, '[a-f0-9]{64}')
UUID = {**text(36, '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), 'format': 'uuid'}
DATE = {**text(32, r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z'), 'format': 'date-time'}
COMMON = {'schema_version': const(VERSION), 'run_id': UUID,
    'source_revision': text(40, '[a-f0-9]{40}'), 'source_dirty': const(False), 'mode': const('container-reference')}
FLAGS = {'artifact_kind': const(ARTIFACT_KIND), 'label': const(LABEL), 'simulation': const(True),
    'production_eligible': const(False), 'production_iso_eligible': const(False),
    'image_published': const(False), 'remote_release': const(False)}
FILE = obj({'sha256': SHA, 'size_bytes': integer(MAX_TOTAL_BYTES, 1)})
CANDIDATE = obj({**{key: SHA for key in ('manifest_sha256', 'source_candidate_sha256', 'content_sha256', 'source_sha256')},
    'image_digest': text(71, 'sha256:[a-f0-9]{64}')})
GATE = obj({key: SHA for key in ('plan_sha256', 'record_sha256', 'decision_sha256', 'final_decision_sha256', 'archive_sha256')})
VISIBILITY = obj({'kind': const('private-posix'), 'owner_uid': integer(2**32 - 2), 'owner_gid': integer(2**32 - 2),
    'directory_mode': const('0700'), 'file_mode': const('0600'), 'owner_readable': const(True),
    'unprivileged_denied': const(True), 'probe_uid': integer(2**32 - 2, 1), 'probe_gid': integer(2**32 - 2)})


def copied_paths(platform):
    """Only literal original candidate/evidence/license paths, never a glob."""
    require(platform in ('ubuntu', 'ubi'), 'publication_platform_invalid')
    names = ['candidate/' + name for name in (*CANDIDATE_NAMES, 'manifest.json')]
    names += ['evidence/' + name for name in EVIDENCE_PATHS]
    if platform == 'ubi':
        names.append(EULA_PATH)
    return tuple(sorted(names))


def artifact_paths(platform):
    """Every entry covered by top-level checksums; excludes cyclic metadata."""
    return tuple(sorted((*copied_paths(platform), 'REFERENCE.txt')))


def publication_paths(platform):
    return tuple(sorted((*artifact_paths(platform), 'checksums.json', 'COMPLETE.json')))


def _files_definition(platform):
    return obj({path: deepcopy(FILE) for path in artifact_paths(platform)})


def _checksums_definition(platform):
    return obj({**COMMON, 'operation': const(CHECKSUMS_OPERATION), 'platform': const(platform),
                'files': _files_definition(platform)})


def _complete_definition(platform):
    return obj({**COMMON, **FLAGS, 'operation': const(COMPLETE_OPERATION), 'platform': const(platform),
        'profile': const('smoke'), 'release_id': text(46, 'reference-[a-f0-9-]{36}'),
        'synthetic_assessment': const(True), 'candidate': CANDIDATE, 'gate': GATE,
        'files': _files_definition(platform), 'checksums_sha256': SHA, 'visibility': VISIBILITY, 'created_at': DATE})


RECEIPT = obj({**COMMON, **FLAGS, 'operation': const(RECEIPT_OPERATION), 'attempt_id': UUID,
    'release_id': text(46, 'reference-[a-f0-9-]{36}'),
    'platform': {'type': ['string', 'null'], 'enum': ['ubuntu', 'ubi', None]},
    'status': {'type': 'string', 'enum': ['running', 'completed', 'failed', 'refused']},
    'logical_complete': {'type': 'boolean'}, 'durability_acknowledged': {'type': 'boolean'},
    'completion_sha256': nullable(SHA), 'error_code': nullable(text(80, '[a-z][a-z0-9_]{0,79}')),
    'created_at': DATE, 'updated_at': DATE})


def _schema(kind, definition, maximum=MAX_RECORD_BYTES):
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema',
        '$id': 'urn:jake-wormhole:publication-' + kind + ':1.0',
        'title': 'Wormhole reference publication ' + kind + ' v1',
        '$comment': 'Generated by publication_records. Fixed validation additionally enforces exact platform files, bounds, cross-record hashes and status semantics. This pure contract proves no source replay, filesystem bytes, privacy or successful publication operation.',
        'x-maxEncodedBytes': maximum, **deepcopy(definition)}


def schema():
    return _schema('complete', {'oneOf': [_complete_definition(p) for p in ('ubuntu', 'ubi')]})


def checksums_schema():
    return _schema('checksums', {'oneOf': [_checksums_definition(p) for p in ('ubuntu', 'ubi')]})


def receipt_schema():
    return _schema('receipt', RECEIPT, MAX_RECEIPT_BYTES)


def _validate_bounded(definition, value, maximum, code):
    try:
        require(type(value) is dict, code)
        _bounded_json(value)
        require(len(canonical(value)) <= maximum, code)
        _validate(definition, value, '$')
    except PublicationRecordError:
        raise
    except (ContractError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise PublicationRecordError(code, 'Publication data is malformed, incorrectly typed or exceeds its bound.') from None


def _platform(value):
    require(type(value) is dict and type(value.get('platform')) is str and value['platform'] in ('ubuntu', 'ubi'),
            'publication_platform_invalid')
    return value['platform']


def _files(files, platform):
    require(set(files) == set(artifact_paths(platform)) and len(files) <= MAX_FILES, 'publication_file_set')
    require(sum(item['size_bytes'] for item in files.values()) <= MAX_TOTAL_BYTES, 'publication_byte_bound')
    require(all(files['candidate/' + name]['size_bytes'] <= 8 * 1024 * 1024 for name in CANDIDATE_NAMES) and
            sum(files['candidate/' + name]['size_bytes'] for name in CANDIDATE_NAMES) <= MAX_CANDIDATE_BYTES,
            'publication_candidate_bound')
    require(files['candidate/manifest.json']['size_bytes'] <= (16384 if platform == 'ubuntu' else 32768),
            'publication_candidate_bound')
    require(all(files['evidence/' + path]['size_bytes'] <= 1024 * 1024 for path in EVIDENCE_PATHS) and
            sum(files['evidence/' + path]['size_bytes'] for path in EVIDENCE_PATHS) <= MAX_EVIDENCE_BYTES,
            'publication_evidence_bound')
    require(files['REFERENCE.txt'] == {'sha256': hashlib.sha256(REFERENCE_BYTES).hexdigest(), 'size_bytes': len(REFERENCE_BYTES)},
            'publication_label_changed')
    if platform == 'ubi':
        require(files[EULA_PATH] == {'sha256': EULA_SHA256, 'size_bytes': EULA_BYTES}, 'publication_eula_changed')


def validate_checksums(value):
    platform = _platform(value)
    _validate_bounded(_checksums_definition(platform), value, MAX_RECORD_BYTES, 'publication_checksums_invalid')
    _files(value['files'], platform)
    return deepcopy(value)


def render_checksums(value):
    return canonical(validate_checksums(value)) + b'\n'


def validate_completion(value, checksums=None):
    platform = _platform(value)
    _validate_bounded(_complete_definition(platform), value, MAX_RECORD_BYTES, 'publication_complete_invalid')
    _files(value['files'], platform)
    require(value['release_id'] == 'reference-' + value['run_id'], 'publication_release_identity')
    require(value['visibility']['owner_uid'] != value['visibility']['probe_uid'], 'publication_visibility_invalid')
    table = value['files']; candidate = value['candidate']; gate = value['gate']
    source_files = [{'path': name, 'sha256': table['candidate/' + name]['sha256'],
                     'size': table['candidate/' + name]['size_bytes']} for name in CANDIDATE_NAMES]
    require(candidate['manifest_sha256'] == table['candidate/manifest.json']['sha256'] and
            candidate['source_sha256'] == table['candidate/source.synthetic.bin']['sha256'] and
            candidate['content_sha256'] == digest({'files': source_files}), 'publication_candidate_identity')
    if platform == 'ubuntu':
        require(candidate['source_candidate_sha256'] == candidate['manifest_sha256'], 'publication_candidate_identity')
    require(gate['record_sha256'] == table['evidence/report.json']['sha256'] and
            gate['decision_sha256'] == gate['final_decision_sha256'] == table['evidence/decision.json']['sha256'],
            'publication_gate_identity')
    expected = {**{key: value[key] for key in COMMON_KEYS}, 'operation': CHECKSUMS_OPERATION,
                'platform': platform, 'files': deepcopy(table)}
    raw = render_checksums(expected)
    require(value['checksums_sha256'] == hashlib.sha256(raw).hexdigest(), 'publication_checksums_changed')
    if checksums is not None:
        require(canonical(validate_checksums(checksums)) == canonical(expected), 'publication_checksums_changed')
    return deepcopy(value)


def render_completion(value, checksums=None):
    return canonical(validate_completion(value, checksums)) + b'\n'


def validate_receipt(value):
    _validate_bounded(RECEIPT, value, MAX_RECEIPT_BYTES, 'publication_receipt_invalid')
    require(value['release_id'] == 'reference-' + value['run_id'], 'publication_release_identity')
    require(datetime.fromisoformat(value['created_at'].replace('Z', '+00:00')) <=
            datetime.fromisoformat(value['updated_at'].replace('Z', '+00:00')), 'publication_receipt_time')
    status = value['status']
    if status == 'completed':
        require(value['platform'] is not None and value['logical_complete'] and value['durability_acknowledged'] and
                value['completion_sha256'] is not None and value['error_code'] is None, 'publication_receipt_status')
    else:
        require(value['durability_acknowledged'] is False, 'publication_receipt_status')
        require((value['completion_sha256'] is not None) is value['logical_complete'], 'publication_receipt_status')
        if status == 'running':
            require(not value['logical_complete'] and value['error_code'] is None, 'publication_receipt_status')
        elif status == 'refused':
            require(not value['logical_complete'] and value['error_code'] is not None, 'publication_receipt_status')
        else:
            require(value['error_code'] is not None and (not value['logical_complete'] or value['platform'] is not None),
                    'publication_receipt_status')
    return deepcopy(value)


def render_receipt(value):
    return canonical(validate_receipt(value)) + b'\n'
