"""Original synthetic checklist parsing and reference policy, separate from release gates."""
import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import math
import re
import time

from .contracts import validate_artifact
from .runs import (Run, RunError, _owned, atomic_bytes, atomic_json, common,
                   create_run, now, read_json, source_identity)

FORMAT = 'wormhole.synthetic-checklist'
POLICY = 'wormhole.synthetic-reference-v1'
STATUSES = ('Open', 'Not a Finding', 'Not Reviewed', 'Not Applicable')
MAX_INPUT = 65536
MAX_FINDINGS = 128
PLAN = 'evidence/synthetic-assessment-plan.json'
RECEIPT = 'evidence/synthetic-assessment.json'
ORIGINAL = 'private/synthetic-assessment-original.json'
LIMITATIONS = ['Synthetic assessment only.', 'No ISO installation or boot evidence.',
               'Production acceptance policy is undecided.', 'Complete reference-release gate is not evaluated.']
FIXTURE_EXPECTED = [
    {'finding_id': 'fixture-alpha', 'applicable': True, 'reason': ''},
    {'finding_id': 'fixture-beta', 'applicable': True, 'reason': ''},
    {'finding_id': 'fixture-gamma', 'applicable': True, 'reason': ''},
    {'finding_id': 'fixture-delta', 'applicable': False, 'reason': 'Synthetic fixture excludes this capability.'},
]


class AssessmentError(RunError):
    pass


def require(value, code):
    if not value:
        raise AssessmentError(code, 'Synthetic assessment refused; preserve the original and inspect the named failure category.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def same_json(left, right):
    """JSON booleans and numbers are distinct even though Python False == 0."""
    try:
        return canonical(left) == canonical(right)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False


def text(value, maximum=1000, *, empty=False):
    if type(value) is not str:
        return False
    try:
        return ((empty or bool(value.strip())) and len(value.encode('utf-8')) <= maximum
                and all(ord(char) >= 32 and not 127 <= ord(char) <= 159 for char in value))
    except UnicodeError:
        return False


def expected_findings(expected):
    require(type(expected) is list and 1 <= len(expected) <= MAX_FINDINGS, 'invalid_expected_findings')
    ids = []
    for item in expected:
        require(type(item) is dict and set(item) == {'finding_id', 'applicable', 'reason'}
                and type(item['finding_id']) is str and re.fullmatch('[a-z][a-z0-9_-]{0,63}', item['finding_id'])
                and type(item['applicable']) is bool and text(item['reason'], empty=item['applicable'])
                and (not item['applicable'] or item['reason'] == ''), 'invalid_expected_findings')
        ids.append(item['finding_id'])
    require(len(set(ids)) == len(ids), 'duplicate_expected_finding')
    return deepcopy(expected)


def make_plan(run, expected):
    value = {**common(run.manifest()), 'component': 'synthetic-assessment', 'policy_id': POLICY,
             'format': FORMAT, 'synthetic': True, 'expected_findings': expected_findings(expected),
             'reference_eligible': False, 'production_iso_eligible': False}
    return {**value, 'plan_sha256': digest(value)}


def validate_plan(run, value):
    require(type(value) is dict and 'expected_findings' in value, 'assessment_plan_changed')
    require(same_json(value, make_plan(run, value['expected_findings'])), 'assessment_plan_changed')
    return value


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AssessmentError('duplicate_json_member', 'A synthetic checklist contains duplicate JSON members.')
        value[key] = item
    return value


def parse_checklist(raw, expected):
    """Parse bounded bytes; declarations precede observations and never grant authority."""
    expected = expected_findings(expected)
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_INPUT, 'assessment_input_bound')
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except AssessmentError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise AssessmentError('malformed_assessment', 'Synthetic checklist JSON is malformed.') from None
    require(type(value) is dict and set(value) == {'format', 'schema_version', 'synthetic', 'findings'}, 'invalid_assessment_shape')
    require(value['format'] == FORMAT and value['schema_version'] == '1.0' and value['synthetic'] is True, 'unsupported_assessment_format')
    require(type(value['findings']) is list and 1 <= len(value['findings']) <= MAX_FINDINGS, 'incomplete_assessment')
    found = {}
    for item in value['findings']:
        require(type(item) is dict and set(item) == {'finding_id', 'status', 'summary', 'reason'}, 'invalid_finding_shape')
        require(type(item['finding_id']) is str and re.fullmatch('[a-z][a-z0-9_-]{0,63}', item['finding_id'])
                and type(item['status']) is str and item['status'] in STATUSES
                and text(item['summary']) and text(item['reason'], empty=True), 'invalid_finding')
        require(item['finding_id'] not in found, 'duplicate_finding')
        found[item['finding_id']] = deepcopy(item)
    require(set(found) == {item['finding_id'] for item in expected}, 'incomplete_assessment')
    normalized = [found[item['finding_id']] for item in expected]
    counts = {status: sum(item['status'] == status for item in normalized) for status in STATUSES}
    reasons = []
    for declaration, finding in zip(expected, normalized):
        ident, status = finding['finding_id'], finding['status']
        if status == 'Not Reviewed':
            reasons.append(ident + ': not reviewed')
        elif status == 'Open':
            reasons.append(ident + ': open finding')
        elif status == 'Not Applicable':
            if declaration['applicable'] or finding['reason'] != declaration['reason']:
                reasons.append(ident + ': applicability was not declared with this reason')
        elif not declaration['applicable']:
            reasons.append(ident + ': contradicts declared applicability')
    return {'findings': normalized, 'counts': counts, 'policy_verdict': 'reject' if reasons else 'pass',
            'policy_reasons': reasons}


def fixture(case):
    require(case in ('pass', 'reject', 'malformed', 'unsupported', 'incomplete'), 'unsupported_assessment_fixture')
    value = {'format': FORMAT, 'schema_version': '1.0', 'synthetic': True, 'findings': [
        {'finding_id': row['finding_id'], 'status': 'Not a Finding' if row['applicable'] else 'Not Applicable',
         'summary': 'Generated synthetic finding ' + row['finding_id'] + '.', 'reason': row['reason']}
        for row in FIXTURE_EXPECTED]}
    if case == 'reject':
        value['findings'][0]['status'] = 'Open'
        value['findings'][2]['status'] = 'Not Reviewed'
    elif case == 'malformed':
        return b'{"format":'
    elif case == 'unsupported':
        value['format'] = 'not-a-supported-scanner-format'
    elif case == 'incomplete':
        value['findings'].pop()
    return canonical(value)


def assess_run(run, raw, expected):
    """Write once under the exact Run lock. This component allocates no infrastructure."""
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_INPUT, 'assessment_input_bound')
    with run.locked():
        manifest = run.manifest()
        require(source_identity() == (manifest['source_revision'], False) and not manifest['source_dirty'], 'assessment_source_changed')
        require(not any(run.file(path).exists() for path in (PLAN, RECEIPT, ORIGINAL)), 'assessment_attempt_reused')
        plan = make_plan(run, expected)
        atomic_json(run.file(PLAN), plan)
        receipt = {**common(manifest), 'component': 'synthetic-assessment', 'policy_id': POLICY,
                   'plan_sha256': plan['plan_sha256'], 'synthetic': True, 'original_path': ORIGINAL,
                   'original_sha256': hashlib.sha256(raw).hexdigest(), 'original_size_bytes': len(raw),
                   'status': 'running', 'result': None, 'assessment_artifact': None, 'primary_failure': None,
                   'duration_seconds': 0, 'created_at': now(), 'updated_at': now(),
                   'runtime_pipeline_complete': False, 'reference_eligible': False,
                   'production_iso_eligible': False, 'limitations': list(LIMITATIONS)}
        atomic_json(run.file(RECEIPT), receipt)
        started = time.monotonic()
        try:
            atomic_bytes(run.file(ORIGINAL), raw, limit=MAX_INPUT)
            result = parse_checklist(raw, plan['expected_findings'])
            artifact = {**common(manifest), 'status': 'pass' if result['policy_verdict'] == 'pass' else 'fail',
                        'synthetic': True, 'policy_id': POLICY,
                        'findings': [{key: row[key] for key in ('finding_id', 'status', 'summary')} for row in result['findings']]}
            validate_artifact('assessment', artifact)
            receipt.update(status='passed' if result['policy_verdict'] == 'pass' else 'rejected',
                           result=result, assessment_artifact=artifact)
        except AssessmentError as error:
            receipt.update(status='failed', primary_failure={'code': error.code})
            raise
        except BaseException:
            receipt.update(status='failed', primary_failure={'code': 'assessment_operation_incomplete'})
            raise
        finally:
            receipt.update(duration_seconds=time.monotonic() - started, updated_at=now())
            atomic_json(run.file(RECEIPT), receipt)
        return deepcopy(receipt)


def original_bytes(run):
    path = run.file(ORIGINAL)
    _owned(path)
    before = path.stat()
    require(1 <= before.st_size <= MAX_INPUT, 'assessment_original_changed')
    with path.open('rb') as stream:
        raw = stream.read(MAX_INPUT + 1)
    after = path.stat()
    require(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_size) ==
            (after.st_dev, after.st_ino, after.st_size), 'assessment_original_changed')
    return raw


def report_assessment(run):
    """Reparse retained originals. Edited counts, outcomes or eligibility cannot pass."""
    plan = validate_plan(run, read_json(run.file(PLAN)))
    receipt = read_json(run.file(RECEIPT))
    raw = original_bytes(run)
    fields = {*common(run.manifest()), 'component', 'policy_id', 'plan_sha256', 'synthetic', 'original_path',
              'original_sha256', 'original_size_bytes', 'status', 'result', 'assessment_artifact', 'primary_failure',
              'duration_seconds', 'created_at', 'updated_at', 'runtime_pipeline_complete', 'reference_eligible',
              'production_iso_eligible', 'limitations'}
    require(type(receipt) is dict and set(receipt) == fields and same_json(common(receipt), common(run.manifest()))
            and receipt['component'] == 'synthetic-assessment' and receipt['policy_id'] == POLICY
            and receipt['plan_sha256'] == plan['plan_sha256'] and receipt['synthetic'] is True
            and receipt['original_path'] == ORIGINAL and receipt['original_sha256'] == hashlib.sha256(raw).hexdigest()
            and type(receipt['original_size_bytes']) is int and receipt['original_size_bytes'] == len(raw)
            and type(receipt['duration_seconds']) in (int, float) and math.isfinite(receipt['duration_seconds'])
            and 0 <= receipt['duration_seconds'] <= 60 and receipt['limitations'] == LIMITATIONS
            and all(receipt[key] is False for key in ('runtime_pipeline_complete', 'reference_eligible', 'production_iso_eligible')),
            'assessment_receipt_changed')
    for field in ('created_at', 'updated_at'):
        require(type(receipt[field]) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', receipt[field]), 'assessment_receipt_changed')
        try:
            datetime.fromisoformat(receipt[field].replace('Z', '+00:00'))
        except ValueError:
            raise AssessmentError('assessment_receipt_changed', 'Assessment timestamp is malformed.') from None
    try:
        result = parse_checklist(raw, plan['expected_findings'])
    except AssessmentError as error:
        require(receipt['status'] == 'failed' and receipt['primary_failure'] == {'code': error.code}
                and receipt['result'] is None and receipt['assessment_artifact'] is None, 'assessment_receipt_changed')
        return {'result': receipt, 'text': 'Synthetic assessment failed: ' + error.code + '. No policy or release approval.'}
    artifact = {**common(run.manifest()), 'status': 'pass' if result['policy_verdict'] == 'pass' else 'fail',
                'synthetic': True, 'policy_id': POLICY,
                'findings': [{key: row[key] for key in ('finding_id', 'status', 'summary')} for row in result['findings']]}
    validate_artifact('assessment', artifact)
    require(same_json(receipt['result'], result) and same_json(receipt['assessment_artifact'], artifact) and receipt['primary_failure'] is None
            and receipt['status'] == ('passed' if result['policy_verdict'] == 'pass' else 'rejected'), 'assessment_receipt_changed')
    readable = ['Synthetic assessment ' + run.id + ': reference policy ' + result['policy_verdict']]
    readable.extend(status + ': ' + str(result['counts'][status]) for status in STATUSES)
    readable.extend(row['finding_id'] + ': ' + row['status'] for row in result['findings'])
    readable.extend(result['policy_reasons'] + LIMITATIONS)
    return {'result': receipt, 'text': '\n'.join(readable)}


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Original synthetic checklist component; no scanner or release gate.')
    sub = parser.add_subparsers(dest='command', required=True)
    generate = sub.add_parser('fixture')
    generate.add_argument('--case', choices=('pass', 'reject', 'malformed', 'unsupported', 'incomplete'), default='pass')
    generate.add_argument('--workspace', required=True)
    report = sub.add_parser('report')
    report.add_argument('run_id')
    report.add_argument('--workspace', required=True)
    options = parser.parse_args(arguments)
    run = None
    try:
        if options.command == 'fixture':
            from .stages import execute_run
            run = create_run(options.workspace, fixture=True)
            with run.locked():
                execute_run(run)  # Existing synthetic subset stays separate and unchanged.
            try:
                assess_run(run, fixture(options.case), FIXTURE_EXPECTED)
            except AssessmentError:
                value = report_assessment(run)
                print(json.dumps(value, sort_keys=True, indent=2))
                return 2
        else:
            run = Run(options.workspace, options.run_id)
        value = report_assessment(run)
        print(json.dumps(value, sort_keys=True, indent=2))
        return 0 if value['result']['status'] == 'passed' else 1 if value['result']['status'] == 'rejected' else 2
    except (RunError, OSError) as error:
        print(json.dumps({'error': {'code': getattr(error, 'code', 'assessment_io_error')},
                          'run_id': run.id if run else None, 'production_iso_eligible': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
