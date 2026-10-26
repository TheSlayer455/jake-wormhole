"""Pure limited-reference records and reports, not runtime evidence replay.

The pipeline domain must replay its original plans, captures, candidate bytes
and finished admission archive before using this structural layer. No function
here opens files, imports a runtime adapter or observes infrastructure.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re
from xml.etree import ElementTree as ET

from .contracts import ContractError, _bounded_json, _validate
from .runs import RunError
from . import observed_svd
from .execution_state import READINESS_CHECKS

POLICY = 'reference-smoke-v1'
PLAN_OPERATION = 'reference-pipeline-plan-v1'
OPERATION = 'reference-pipeline-result-v1'
MAX_RECORD_BYTES = 524288
MAX_PLAN_BYTES = 262144
STATUSES = ('pass', 'fail', 'error', 'unreachable', 'skipped', 'blocked', 'unverified')
ARTIFACT_KINDS = ('fixed-projection', 'log-capture', 'plan', 'component', 'candidate', 'cleanup', 'admission')
COMMON_KEYS = ('schema_version', 'run_id', 'source_revision', 'source_dirty', 'mode')
ROW_KEYS = ('component', 'scope', 'target_id', 'check_id', 'required')
LIMITATIONS = (
    'WORMHOLE REFERENCE ARTIFACT: one container target and generated candidate bytes.',
    'Synthetic assessment is reference policy evidence, not a scanner or STIG acceptance.',
    'The kernel is shared with the host; helper and provisioner tools are execution provenance.',
    'No VM installation, ISO boot, production approval or remote publication is established.',
    'Production ISO eligibility is always false; optional PowerShell is excluded.',
)
READINESS = READINESS_CHECKS
UBUNTU_FUNCTIONAL = ('candidate-userland', 'candidate-source-sha256', 'candidate-manifest-sha256',
    'candidate-payload-sha256', 'candidate-version', 'candidate-configuration', 'candidate-function')
UBI_FUNCTIONAL = ('rpm-userland', 'rpm-python3', 'rpm-openssh', 'rpm-openssh-server', 'rpm-shadow-utils',
    'candidate-source-sha256', 'candidate-manifest-sha256', 'candidate-content-sha256',
    'candidate-payload-sha256', 'candidate-version', 'candidate-configuration', 'candidate-function')
SVD_CORE = ('target-identity', 'userland', 'package-inventory', 'payload-version', 'payload-sha256',
    'candidate-manifest-sha256', 'candidate-content-sha256', 'candidate-source-sha256')
SVD_PACKAGES = {
    'ubuntu': ('ca-certificates', 'openssh-client', 'openssh-server', 'openssh-sftp-server', 'python3', 'python3-12'),
    'ubi': ('openssh', 'openssh-server', 'python3', 'shadow-utils'),
}
ASSESSMENT = ('fixture-alpha', 'fixture-beta', 'fixture-gamma', 'fixture-delta')
EXPORT_PATHS = (
    'manifest.json', 'plan.json', 'summary.json', 'report.json', 'report.txt', 'report.junit.xml',
    'targets/target-001/readiness.json', 'targets/target-001/tests.json', 'targets/target-001/svd.json',
    'targets/target-001/assessment.json', 'targets/target-001/logs.json', 'cleanup.json',
    'targets/target-001/observed-svd.json', 'targets/target-001/observed-svd.txt',
    'checksums.json', 'decision.json',
)


class PipelineRecordError(RunError):
    pass


def require(value, code='pipeline_record_invalid'):
    if not value:
        raise PipelineRecordError(code, 'Pipeline record refused; preserve original evidence and inspect the named category.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


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
CODE = string(80, pattern='[a-z][a-z0-9_]{0,79}')
DATE = {**string(32, pattern=r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z'), 'format': 'date-time'}
COMMON = {
    'schema_version': const('1.0'),
    'run_id': {**string(36, pattern='[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), 'format': 'uuid'},
    'source_revision': string(40, pattern='[a-f0-9]{40}'), 'source_dirty': const(False), 'mode': const('container-reference'),
}
DECLARATION = {'component': ID, 'scope': {'type': 'string', 'enum': ['run', 'target']},
    'target_id': nullable(ID), 'check_id': ID, 'required': const(True)}
CANDIDATE = obj({key: SHA for key in ('manifest_sha256', 'source_candidate_sha256', 'content_sha256', 'source_sha256')})
FAILURE = obj({'code': CODE, 'recorded_at': DATE})
PLAN = obj({**COMMON, 'operation': const(PLAN_OPERATION), 'policy': const(POLICY),
    'platform': {'type': 'string', 'enum': ['ubuntu', 'ubi']}, 'profile': const('smoke'),
    'targets': array(const('target-001'), 1, 1), 'capabilities': array(ID, 0),
    'candidate': nullable(CANDIDATE),
    'expected_rows': array(obj({**DECLARATION, 'expected': string(4000, 0)}), 128, 1), 'plan_sha256': SHA})
RECORD = obj({**COMMON, 'operation': const(OPERATION), 'policy': const(POLICY), 'plan_sha256': SHA,
    'status': {'type': 'string', 'enum': ['passed', 'failed', 'blocked']},
    'candidate': nullable(obj({**CANDIDATE['properties'], 'image_digest': IMAGE})),
    'targets': array(obj({'target_id': const('target-001'), 'resource_id': SHA, 'image_digest': IMAGE}), 1),
    'rows': array(obj({**DECLARATION, 'expected': string(4000, 0), 'observed': string(4000, 0),
        'status': {'type': 'string', 'enum': list(STATUSES)}, 'reason_code': CODE, 'message': string(1000, 0),
        'evidence': array(ID, 16)}), 128, 1),
    'artifacts': array(obj({'artifact_id': ID, 'kind': {'type': 'string', 'enum': list(ARTIFACT_KINDS)},
        'sha256': SHA, 'size_bytes': integer(64 * 1024 * 1024)}), 64),
    'primary_failure': nullable(FAILURE), 'secondary_failures': array(FAILURE, 64),
    'cleanup': obj({'status': {'type': 'string', 'enum': ['not-started', 'completed', 'failed', 'blocked']},
        'admission_finished': {'type': 'boolean'}, 'archive_sha256': nullable(SHA), 'pending_resources': integer(128)}),
    'unknown_outcome': {'type': 'boolean'}, 'reference_scope_complete': {'type': 'boolean'},
    'reference_eligible': {'type': 'boolean'}, 'production_iso_eligible': const(False), 'updated_at': DATE})


def schema():
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:jake-wormhole:pipeline-result:1.0',
        'title': 'Limited container reference pipeline result v1', 'x-maxEncodedBytes': MAX_RECORD_BYTES,
        '$comment': 'Generated by pipeline_records.schema(). The fixed validator additionally checks exact ordered platform grids, typed plan/candidate binding, row/evidence consistency and finished-archive eligibility. Domain original-capture replay remains mandatory; this structural schema proves no runtime observation.',
        **deepcopy(RECORD)}


def plan_schema():
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:jake-wormhole:pipeline-plan:1.0',
        'title': 'Limited container reference pipeline plan v1', 'x-maxEncodedBytes': MAX_PLAN_BYTES,
        '$comment': 'Generated by pipeline_records.plan_schema(). Exact mandatory grid and canonical plan digest are enforced by the fixed validator, not by caller-provided row counts.',
        **deepcopy(PLAN)}


def grid(platform):
    """The developer-defined required grid; observations cannot remove rows."""
    require(type(platform) is str and platform in SVD_PACKAGES, 'pipeline_platform_unsupported')
    result = []

    def add(component, scope, checks):
        result.extend({'component': component, 'scope': scope, 'target_id': 'target-001' if scope == 'target' else None,
                       'check_id': check, 'required': True} for check in checks)

    for component, checks in (('preflight', ('clean-source',)), ('chunks', ('source-integrity',)),
        ('candidate', ('candidate-binding',)), ('admission', ('measured-capacity',))):
        add(component, 'run', checks)
    add('provisioning', 'target', ('terraform-lifecycle', 'owned-network', 'target-confinement'))
    add('readiness', 'target', READINESS)
    add('functional', 'target', UBUNTU_FUNCTIONAL if platform == 'ubuntu' else UBI_FUNCTIONAL)
    add('svd', 'target', SVD_CORE + tuple('package-' + name for name in SVD_PACKAGES[platform]))
    add('assessment', 'target', ASSESSMENT)
    add('evidence', 'run', ('original-replay',))
    add('cleanup', 'run', ('owned-teardown', 'admission-finalized'))
    return result


expected_grid = grid


def _validate_bounded(definition, value, maximum, code):
    try:
        require(type(value) is dict, code)
        _bounded_json(value)
        require(len(canonical(value)) <= maximum, code)
        _validate(definition, value, '$')
    except PipelineRecordError:
        raise
    except (ContractError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise PipelineRecordError(code, 'Pipeline data is malformed, incorrectly typed or exceeds its bound.') from None


def validate_plan(plan):
    _validate_bounded(PLAN, plan, MAX_PLAN_BYTES, 'pipeline_plan_invalid')
    declared = [{key: row[key] for key in ROW_KEYS} for row in plan['expected_rows']]
    require(same(declared, grid(plan['platform'])), 'pipeline_plan_grid')
    require(next(row for row in plan['expected_rows'] if row['component'] == 'svd' and
        row['check_id'] == 'target-identity')['expected'] == 'exact-owned-target-001', 'pipeline_identity_expectation')
    require(plan['plan_sha256'] == digest({key: value for key, value in plan.items() if key != 'plan_sha256'}), 'pipeline_plan_hash')
    return deepcopy(plan)


def _common(value):
    return {key: value[key] for key in COMMON_KEYS}


def _row_key(row):
    return '/'.join((row['component'], row['target_id'] or 'run', row['check_id']))


def counts(record):
    """Derived status counts; callers must validate the record first."""
    return {status: sum(row['status'] == status for row in record['rows']) for status in STATUSES}


def refusal_reasons(record):
    """Intrinsic reasons only; the domain adds original-evidence replay reasons."""
    reasons = [{'code': 'required_' + row['status'], 'row': _row_key(row)} for row in record['rows'] if row['status'] != 'pass']
    if record['candidate'] is None:
        reasons.append({'code': 'candidate_missing', 'row': None})
    if not record['targets']:
        reasons.append({'code': 'target_missing', 'row': None})
    if record['primary_failure'] is not None:
        reasons.append({'code': record['primary_failure']['code'], 'row': None})
    if record['unknown_outcome']:
        reasons.append({'code': 'unknown_outcome', 'row': None})
    cleanup = record['cleanup']
    if cleanup['status'] != 'completed' or cleanup['pending_resources']:
        reasons.append({'code': 'cleanup_incomplete', 'row': None})
    if cleanup['admission_finished'] is not True or cleanup['archive_sha256'] is None:
        reasons.append({'code': 'admission_unfinished', 'row': None})
    return reasons


def validate_record(record, plan):
    """Check structure/completeness; no claim that a capture or archive exists."""
    original_plan = validate_plan(plan)
    _validate_bounded(RECORD, record, MAX_RECORD_BYTES, 'pipeline_record_invalid')
    require(same(_common(record), _common(original_plan)) and record['plan_sha256'] == original_plan['plan_sha256'], 'pipeline_record_identity')
    expected = [{key: row[key] for key in (*ROW_KEYS, 'expected')} for row in record['rows']]
    require(same(expected, original_plan['expected_rows']), 'pipeline_result_grid')
    artifacts = record['artifacts']; ids = [item['artifact_id'] for item in artifacts]
    require(len(set(ids)) == len(ids), 'pipeline_artifact_duplicate')
    for row in record['rows']:
        require(len(set(row['evidence'])) == len(row['evidence']) and set(row['evidence']) <= set(ids), 'pipeline_evidence_reference')
        require(row['status'] != 'pass' or (row['expected'] == row['observed'] and bool(row['evidence'])), 'pipeline_pass_mismatch')
    candidate, planned = record['candidate'], original_plan['candidate']
    require((planned is None and candidate is None) or (planned is not None and
        (candidate is None or same({key: candidate[key] for key in planned}, planned))), 'pipeline_candidate_identity')
    require(not record['targets'] or candidate is not None and record['targets'][0]['image_digest'] == candidate['image_digest'], 'pipeline_target_identity')
    if original_plan['platform'] == 'ubuntu' and planned is not None:
        require(planned['manifest_sha256'] == planned['source_candidate_sha256'], 'pipeline_candidate_identity')
    cleanup = record['cleanup']
    require(not cleanup['admission_finished'] or cleanup['archive_sha256'] is not None, 'pipeline_archive_missing')
    require(cleanup['archive_sha256'] is None or cleanup['admission_finished'], 'pipeline_archive_inconsistent')
    require(cleanup['status'] != 'completed' or cleanup['pending_resources'] == 0, 'pipeline_cleanup_pending')
    if cleanup['status'] != 'completed':
        require(next(row for row in record['rows'] if row['component'] == 'cleanup' and row['check_id'] == 'owned-teardown')['status'] != 'pass', 'pipeline_cleanup_false_pass')
    if not cleanup['admission_finished']:
        require(next(row for row in record['rows'] if row['component'] == 'cleanup' and row['check_id'] == 'admission-finalized')['status'] != 'pass', 'pipeline_cleanup_false_pass')
    for failure in [record['primary_failure'], *record['secondary_failures']]:
        if failure is not None:
            try:
                require(datetime.fromisoformat(failure['recorded_at'].replace('Z', '+00:00')).utcoffset().total_seconds() == 0)
            except (ValueError, AttributeError):
                raise PipelineRecordError('pipeline_record_invalid', 'Pipeline failure time is malformed.') from None
    eligible = not refusal_reasons(record)
    require(record['reference_scope_complete'] is eligible and record['reference_eligible'] is eligible and
        (record['status'] == 'passed') is eligible, 'pipeline_false_eligibility')
    require(eligible or any(row['status'] != 'pass' for row in record['rows']), 'pipeline_failure_not_in_grid')
    require(record['status'] != 'failed' or record['primary_failure'] is not None, 'pipeline_primary_missing')
    return deepcopy(record)


def render_json(record, plan):
    return canonical(validate_record(record, plan)) + b'\n'


def render_text(record, plan):
    value = validate_record(record, plan)
    lines = ['WORMHOLE LIMITED REFERENCE PIPELINE', 'Status: ' + value['status'], 'Run: ' + value['run_id'],
        'Controller source: ' + value['source_revision'], 'Plan SHA256: ' + value['plan_sha256'],
        'Platform: ' + plan['platform'], 'Reference scope complete: ' + str(value['reference_scope_complete']).lower(),
        'Reference eligible: ' + str(value['reference_eligible']).lower(), 'Production ISO eligible: false',
        'Counts: ' + canonical(counts(value)).decode(), '']
    for row in value['rows']:
        lines.extend([_row_key(row) + ': ' + row['status'], '  Expected: ' + row['expected'], '  Observed: ' + row['observed'],
            '  Reason: ' + row['reason_code'] + ': ' + row['message'], '  Evidence IDs: ' + ', '.join(row['evidence'])])
    lines.extend(['', 'Cleanup: ' + value['cleanup']['status'], 'Admission finalized: ' + str(value['cleanup']['admission_finished']).lower(),
        'Pending resources: ' + str(value['cleanup']['pending_resources']), 'Unknown outcome: ' + str(value['unknown_outcome']).lower(),
        'Primary failure: ' + (value['primary_failure']['code'] if value['primary_failure'] else 'none'),
        'Secondary failures: ' + ', '.join(item['code'] for item in value['secondary_failures'])])
    for artifact in value['artifacts']:
        lines.append('Artifact ' + artifact['artifact_id'] + ' | kind=' + artifact['kind'] + ' | sha256=' + artifact['sha256'] + ' | bytes=' + str(artifact['size_bytes']))
    lines.extend(['', *LIMITATIONS])
    return '\n'.join(lines) + '\n'


def render_junit(record, plan):
    """One testcase per expected tuple; every required nonpass visibly fails."""
    value = validate_record(record, plan); rows = value['rows']
    suite = ET.Element('testsuite', {'name': POLICY, 'tests': str(len(rows)),
        'failures': str(sum(row['status'] == 'fail' for row in rows)),
        'errors': str(sum(row['status'] not in ('pass', 'fail') for row in rows)), 'skipped': '0'})
    props = ET.SubElement(suite, 'properties')
    for name, content in (('run_id', value['run_id']), ('source_revision', value['source_revision']),
        ('plan_sha256', value['plan_sha256']), ('reference_eligible', str(value['reference_eligible']).lower()),
        ('production_iso_eligible', 'false'), ('scope', '; '.join(LIMITATIONS))):
        ET.SubElement(props, 'property', {'name': name, 'value': content})
    for row in rows:
        case = ET.SubElement(suite, 'testcase', {'name': _row_key(row), 'classname': 'wormhole.' + POLICY})
        metadata = ET.SubElement(case, 'properties')
        for name in ('status', 'required', 'expected', 'observed', 'reason_code', 'message'):
            content = str(row[name]).lower() if type(row[name]) is bool else row[name]
            ET.SubElement(metadata, 'property', {'name': name, 'value': content})
        ET.SubElement(metadata, 'property', {'name': 'evidence', 'value': canonical(row['evidence']).decode()})
        if row['status'] != 'pass':
            failed = ET.SubElement(case, 'failure' if row['status'] == 'fail' else 'error',
                {'type': row['status'], 'message': row['reason_code'] + ': ' + row['message']})
            failed.text = 'Expected: ' + row['expected'] + '\nObserved: ' + row['observed']
    return ET.tostring(suite, encoding='unicode', short_empty_elements=True) + '\n'


def decision(record, plan):
    """A structural projection, not a substitute for domain replay/gate."""
    value = validate_record(record, plan)
    return {**_common(value), 'operation': 'reference-pipeline-decision-v1', 'policy': POLICY,
        'plan_sha256': value['plan_sha256'], 'reference_scope_complete': value['reference_scope_complete'],
        'reference_eligible': value['reference_eligible'], 'production_iso_eligible': False,
        'reasons': refusal_reasons(value), 'cleanup': deepcopy(value['cleanup']), 'limitations': list(LIMITATIONS)}


def _safe_export_text(value):
    """Defense in depth; a fixed domain projection, not scanning, is authority."""
    forbidden = re.compile(r'-----BEGIN .*PRIVATE KEY-----|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}|'
        r'[A-Za-z]:[\\/]|(?:^|[^A-Za-z0-9])/(?:srv|home|root|Users|var/lib)/|'
        r'(?i:tfstate|tfplan|private/|file://|https?://[^ /]+:[^ /]+@|"(?:password|secret|token|environment)"\s*:)')
    if type(value) is str:
        require(not forbidden.search(value), 'pipeline_unsafe_projection')
    elif type(value) is dict:
        for key, child in value.items():
            _safe_export_text(key); _safe_export_text(child)
    elif type(value) is list:
        for child in value: _safe_export_text(child)


def _svd_projection(value, source):
    """Keep every observation; replace private evidence paths with logical IDs."""
    original = observed_svd.validate_record(source)
    require(same(_common(original), _common(value)), 'pipeline_svd_identity')
    actual_rows = [{key: row[key] for key in ('target_id', 'check_id', 'required', 'expected', 'observed', 'status')}
        for row in original['checks']]
    planned_rows = [{key: row[key] for key in ('target_id', 'check_id', 'required', 'expected', 'observed', 'status')}
        for row in value['rows'] if row['component'] == 'svd']
    # The pipeline plan precedes allocation. Its fixed semantic identity check
    # is backed here by the original collector's independently observed ID.
    if planned_rows[0]['status'] == 'pass':
        require(len(value['targets']) == 1 and actual_rows[0]['status'] == 'pass' and
            actual_rows[0]['expected'] == actual_rows[0]['observed'] == value['targets'][0]['resource_id'] and
            planned_rows[0]['expected'] == planned_rows[0]['observed'] == 'exact-owned-target-001', 'pipeline_svd_identity')
        actual_rows[0].update(expected='exact-owned-target-001', observed='exact-owned-target-001')
    require(same(actual_rows, planned_rows), 'pipeline_svd_grid')
    target, candidate = original['target'], value['candidate']
    if target is not None:
        require(candidate is not None and len(value['targets']) == 1 and
            target['resource_id'] == value['targets'][0]['resource_id'] and
            target['image_digest'] == candidate['image_digest'] and
            target['candidate_sha256'] == candidate['manifest_sha256'] and
            target['source_candidate_sha256'] == candidate['source_candidate_sha256'] and
            target['content_sha256'] == candidate['content_sha256'], 'pipeline_svd_identity')
    if original['observation'] is not None:
        require(candidate is not None and original['observation']['payload']['source_sha256'] == candidate['source_sha256'],
            'pipeline_svd_identity')
    source_hash = hashlib.sha256(observed_svd.render_json(original)).hexdigest()
    sanitized = deepcopy(original)
    for row in sanitized['checks']:
        row['evidence'] = ['observed-svd-original-record']
    if sanitized['capture'] is not None:
        del sanitized['capture']['path']
        sanitized['capture']['artifact_id'] = 'observed-svd-private-capture'
    projection = {**_common(value), 'operation': 'reference-pipeline-observed-svd-projection-v1',
        'projection': 'full-observed-record-with-logical-evidence-references', 'source_record_sha256': source_hash,
        'source_record_artifact_id': 'observed-svd-original-record', 'raw_capture_exported': False, 'record': sanitized}
    _safe_export_text(projection)
    raw = canonical(projection) + b'\n'
    text = ('WORMHOLE SAFE OBSERVED SOFTWARE VERSION DESCRIPTION\n'
        'Complete native records and provenance; evidence IDs refer to retained originals.\n'
        'Original validated record SHA256: ' + source_hash + '\nSafe JSON projection SHA256: ' + hashlib.sha256(raw).hexdigest() +
        '\nNo raw capture or private filesystem path is included.\n' +
        json.dumps(projection, sort_keys=True, ensure_ascii=True, indent=2) + '\n')
    return raw, text.encode('utf-8')


def safe_export(record, plan, *, svd_record=None):
    """Return a closed portable path->bytes map; perform no filesystem copy.

    The domain supplies the strict replayed complete SVD when collection was
    attempted. Its full records are retained with logical private evidence IDs.
    """
    value = validate_record(record, plan); original_plan = validate_plan(plan)
    _safe_export_text(value); _safe_export_text(original_plan)
    svd_rows = [row for row in value['rows'] if row['component'] == 'svd']
    require(svd_record is not None or all(row['status'] != 'pass' for row in svd_rows), 'pipeline_svd_missing')
    common = _common(value)
    manifest = {**common, 'operation': 'reference-pipeline-export-v1', 'policy': POLICY,
        'plan_sha256': value['plan_sha256'], 'platform': original_plan['platform'],
        'targets': deepcopy(value['targets']), 'candidate': deepcopy(value['candidate']), 'limitations': list(LIMITATIONS),
        'production_iso_eligible': False}
    summary = {**common, 'operation': 'reference-pipeline-summary-v1', 'status': value['status'], 'counts': counts(value),
        'primary_failure': deepcopy(value['primary_failure']), 'secondary_failures': deepcopy(value['secondary_failures']),
        'unknown_outcome': value['unknown_outcome'], 'reference_scope_complete': value['reference_scope_complete'],
        'reference_eligible': value['reference_eligible'], 'production_iso_eligible': False}
    files = {'manifest.json': canonical(manifest) + b'\n', 'plan.json': canonical(original_plan) + b'\n',
        'summary.json': canonical(summary) + b'\n', 'report.json': render_json(value, original_plan),
        'report.txt': render_text(value, original_plan).encode(), 'report.junit.xml': render_junit(value, original_plan).encode(),
        'cleanup.json': canonical({**common, 'operation': 'reference-pipeline-cleanup-projection-v1',
            **value['cleanup'], 'primary_failure': value['primary_failure'], 'secondary_failures': value['secondary_failures']}) + b'\n'}
    for name, component in (('readiness', 'readiness'), ('tests', 'functional'), ('svd', 'svd'), ('assessment', 'assessment')):
        projection = {**common, 'operation': 'reference-pipeline-' + name + '-projection-v1', 'target_id': 'target-001',
            'projection': 'normalized-result-rows-only', 'candidate': value['candidate'],
            'rows': [deepcopy(row) for row in value['rows'] if row['component'] == component],
            'synthetic': component == 'assessment', 'production_iso_eligible': False}
        files['targets/target-001/' + name + '.json'] = canonical(projection) + b'\n'
    files['targets/target-001/logs.json'] = canonical({**common, 'operation': 'reference-pipeline-log-metadata-v1',
        'target_id': 'target-001', 'raw_captures_exported': False,
        'captures': [deepcopy(item) for item in value['artifacts'] if item['kind'] == 'log-capture']}) + b'\n'
    if svd_record is not None:
        svd_json, svd_text = _svd_projection(value, svd_record)
    else:
        unavailable = {**common, 'operation': 'reference-pipeline-observed-svd-projection-v1',
            'status': 'unverified', 'reason_code': 'collection_not_completed', 'record': None, 'raw_capture_exported': False}
        svd_json = canonical(unavailable) + b'\n'
        svd_text = ('WORMHOLE OBSERVED SOFTWARE VERSION DESCRIPTION\n'
            'Unverified: no complete collected record exists; no empty successful inventory is claimed.\n').encode()
    files['targets/target-001/observed-svd.json'] = svd_json
    files['targets/target-001/observed-svd.txt'] = svd_text
    checksum = {**common, 'operation': 'reference-pipeline-checksums-v1',
        'files': [{'path': path, 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)} for path, raw in sorted(files.items())]}
    files['checksums.json'] = canonical(checksum) + b'\n'
    final = decision(value, original_plan)
    final.update(record_sha256=hashlib.sha256(files['report.json']).hexdigest(),
                 checksums_sha256=hashlib.sha256(files['checksums.json']).hexdigest())
    files['decision.json'] = canonical(final) + b'\n'
    require(set(files) == set(EXPORT_PATHS) and sum(map(len, files.values())) <= 4 * 1024 * 1024, 'pipeline_export_bound')
    return {path: files[path] for path in EXPORT_PATHS}
