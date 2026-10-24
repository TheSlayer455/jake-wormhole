"""Fresh actual reference pipelines and a separate-process, read-only gate replay.

The fixed operator invokes this explicitly on approved Linux storage. Expected
negative harness success never changes the failed underlying pipeline record.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import sys
from uuid import UUID
from xml.etree import ElementTree as ET

from . import candidate as c, images
from .candidate_acceptance import sweep
from .provisioning_acceptance import snapshot, scan_private_material, disk_sample, error_code
from .runs import SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, create_run, now, read_json, source_identity
from .stages import _run_process

CASES = (('ubuntu', 'healthy'), ('ubi', 'healthy'), ('ubuntu', 'version-expectation-mismatch'))
NEGATIVE = 'candidate_required_check_mismatch'


def require(value, code='reference_acceptance_invalid'):
    c.require(value, code)


def row_key(row):
    return '/'.join((row['component'], row['target_id'] or 'run', row['check_id']))


def checked_reports(platform, scenario, report, declarations):
    record = report['record']; rows = record['rows']
    require((platform, scenario) in CASES and len(rows) == (43 if platform == 'ubuntu' else 46), 'reference_acceptance_grid')
    keys = ('component', 'scope', 'target_id', 'check_id', 'required')
    require([{key: row[key] for key in keys} for row in rows] == declarations and
        len({row_key(row) for row in rows}) == len(rows) and all(row['required'] is True for row in rows), 'reference_acceptance_grid')
    require(type(report['json']) is bytes and json.loads(report['json']) == record, 'reference_json_disagreement')
    require(type(report['text']) is str and type(report['junit']) is str, 'reference_format_disagreement')
    for row in rows:
        require(report['text'].splitlines().count(row_key(row) + ': ' + row['status']) == 1, 'reference_text_disagreement')
    xml = ET.fromstring(report['junit']); cases = xml.findall('testcase')
    require(xml.tag == 'testsuite' and int(xml.get('tests')) == len(rows) and len(cases) == len(rows) and
        int(xml.get('failures')) == sum(row['status'] == 'fail' for row in rows) and
        int(xml.get('errors')) == sum(row['status'] not in ('pass', 'fail') for row in rows) and xml.get('skipped') == '0',
        'reference_junit_disagreement')
    for row, case in zip(rows, cases):
        metadata = case.findall('./properties/property')
        values = {item.get('name'): item.get('value') for item in metadata}
        require(case.get('name') == row_key(row) and case.get('classname') == 'wormhole.reference-smoke-v1' and
            len(values) == len(metadata) == 7 and set(values) == {'status', 'required', 'expected', 'observed', 'reason_code', 'message', 'evidence'} and
            all(values[name] == row[name] for name in ('status', 'expected', 'observed', 'reason_code', 'message')) and
            values['required'] == 'true' and json.loads(values['evidence']) == row['evidence'], 'reference_junit_disagreement')
        require(len(case.findall('failure')) == (1 if row['status'] == 'fail' else 0) and
            len(case.findall('error')) == (1 if row['status'] not in ('pass', 'fail') else 0), 'reference_junit_false_pass')
    healthy = scenario == 'healthy'
    require(record['status'] == ('passed' if healthy else 'failed') and
        record['reference_eligible'] is healthy and record['reference_scope_complete'] is healthy and
        record['production_iso_eligible'] is False and record['unknown_outcome'] is False, 'reference_false_eligibility')
    decision = report['decision']
    require(decision['reference_eligible'] is healthy and decision['production_iso_eligible'] is False and
        (decision['reasons'] == [] if healthy else bool(decision['reasons'])), 'reference_gate_disagreement')
    if healthy:
        require(record['primary_failure'] is None and all(row['status'] == 'pass' for row in rows), 'reference_required_result_missing')
    else:
        require(record['primary_failure']['code'] == NEGATIVE and
            [row['check_id'] for row in rows if row['component'] == 'functional' and row['status'] != 'pass'] == ['candidate-version'] and
            all(row['status'] == 'blocked' for row in rows if row['component'] == 'svd'), 'reference_negative_not_observed')
    cleanup = record['cleanup']
    require(cleanup['status'] == 'completed' and cleanup['admission_finished'] is True and
        cleanup['pending_resources'] == 0 and c.IDENTIFIER.fullmatch(cleanup['archive_sha256']), 'reference_cleanup_incomplete')
    return deepcopy(record)


def qualify_case(platform, scenario, sentinel, base_run_id):
    from .pipeline import PipelineSession, make_request, report_pipeline, gate_pipeline
    from .pipeline_records import grid
    require((platform, scenario) in CASES and type(sentinel) is str and c.IDENTIFIER.fullmatch(sentinel), 'reference_acceptance_input')
    require(type(base_run_id) is str and str(UUID(base_run_id)) == base_run_id, 'rpm_base_probe_required')
    revision, dirty = source_identity(); require(sys.platform.startswith('linux') and dirty is False, 'reference_acceptance_source')
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    result = {**common(run.manifest()), 'operation': 'real-reference-pipeline-acceptance', 'platform': platform,
        'scenario': scenario, 'status': 'running', 'phase': 'execute', 'created_at': now(), 'production_iso_eligible': False}
    def save(): atomic_json(run.file('evidence/reference-acceptance.json'), result)
    save()
    try:
        with images.docker_scope(run):
            before = snapshot('container', sentinel, unrelated=True)
            request = make_request(run, platform=platform, scenario=scenario, base_run_id=base_run_id if platform == 'ubi' else None)
            observed = None
            try:
                PipelineSession(run, request).execute()
            except Exception as error:
                observed = error_code(error)
            result['pipeline_failure_code'] = observed; save()
            require(observed == (None if scenario == 'healthy' else NEGATIVE), 'reference_unexpected_outcome')
            with run.locked():
                report = report_pipeline(run)
                record = checked_reports(platform, scenario, report, grid(platform))
                require(gate_pipeline(run) == report['decision'], 'reference_gate_disagreement')
                require(record['run_id'] == run.id and record['source_revision'] == revision and record['source_dirty'] is False,
                    'reference_acceptance_source')
                archive_path = images.INFRASTRUCTURE / 'history' / (run.id + '.json'); _owned(archive_path)
                require(archive_path.stat().st_size <= 262144, 'reference_archive_bound')
                archive_bytes = archive_path.read_bytes(); archive = json.loads(archive_bytes)
                require(hashlib.sha256(archive_bytes).hexdigest() == record['cleanup']['archive_sha256'] and
                    archive['run_id'] == run.id and archive['source_revision'] == revision and archive['state'] == 'finished' and
                    all(item['outcome'] == ('retained' if item['kind'] == 'image' else 'absent') for item in archive['resources']) and
                    sentinel not in {item['id'] for item in archive['resources']}, 'reference_archive_incomplete')
            # This child acquires its own Run lock only after the parent releases it.
            cli = _run_process((sys.executable, '-B', '-m', 'wormhole', 'reference-gate', run.id,
                '--workspace', str(images.RUNS_ROOT)), cwd=SOURCE_ROOT, timeout=30)
            atomic_bytes(run.file('private/reference-cli-gate.log'), cli['log'], limit=65536)
            expected_status = 0 if scenario == 'healthy' else 1
            require(cli['returncode'] == expected_status and cli['status'] == ('pass' if expected_status == 0 else 'fail') and
                cli['log_truncated'] is False and json.loads(cli['log']) == report['decision'], 'reference_cli_replay_failed')
            sweep(run)
            require(snapshot('container', sentinel, unrelated=True) == before, 'reference_sentinel_changed')
            require(source_identity() == (revision, False), 'reference_acceptance_source')
            result.update(status='passed', phase='completed', operation_status=record['status'], failure_code=observed,
                record=record, decision=report['decision'], unrelated_sentinel_unchanged=True,
                counts={status: sum(row['status'] == status for row in record['rows']) for status in
                    ('pass', 'fail', 'error', 'unreachable', 'skipped', 'blocked', 'unverified')},
                report_sha256={kind: hashlib.sha256(report[kind] if type(report[kind]) is bytes else report[kind].encode()).hexdigest()
                    for kind in ('json', 'text', 'junit')},
                cli_gate={'returncode': cli['returncode'], 'duration_seconds': cli['duration_seconds'],
                    'output_sha256': hashlib.sha256(cli['log']).hexdigest(), 'entrypoint': 'python -B -m wormhole reference-gate'},
                admission_resources=deepcopy(archive['resources']), credential_scan=scan_private_material(run),
                disk_sample=disk_sample(run, 'reference-cleaned'), finished_at=now()); save()
        return result
    except BaseException as error:
        # The coordinator owns normal cleanup. Unknown operations remain blocked;
        # this wrapper never adopts resources or clears uncertainty after a timeout.
        result.update(status='failed', error_code=error_code(error), finished_at=now()); save()
        error.run_id = run.id; raise


def acceptance(sentinel, base_run_id):
    revision = source_identity(); require(revision[1] is False, 'reference_acceptance_source')
    suite = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    result = {**common(suite.manifest()), 'operation': 'real-reference-pipeline-acceptance-suite', 'status': 'running',
        'suite_run_id': suite.id, 'cases': [], 'pending_case': None, 'production_iso_eligible': False}
    def save(): atomic_json(suite.file('evidence/reference-acceptance-suite.json'), result)
    with suite.locked():
        save()
        try:
            for platform, scenario in CASES:
                require(source_identity() == revision, 'reference_acceptance_source')
                result['pending_case'] = [platform, scenario]; save()
                value = qualify_case(platform, scenario, sentinel, base_run_id)
                require(value['status'] == 'passed' and value['source_revision'] == revision[0] and value['source_dirty'] is False and
                    value['run_id'] not in {suite.id, *(row['run_id'] for row in result['cases'])}, 'reference_acceptance_source')
                result['cases'].append(value); result['pending_case'] = None; save()
            require(len({case['record']['candidate']['image_digest'] for case in result['cases']}) == 3 and
                len({case['record']['candidate']['content_sha256'] for case in result['cases']}) == 1, 'reference_runs_not_isolated')
            result.update(status='passed', finished_at=now()); save(); return result
        except BaseException as error:
            result.update(status='failed', error_code=error_code(error), failed_child_run_id=getattr(error, 'run_id', None)); save()
            error.suite_run_id = suite.id; raise


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Actual one-target Ubuntu/UBI reference report/gate qualification.')
    parser.add_argument('--sentinel-id', required=True); parser.add_argument('--base-run', required=True)
    options = parser.parse_args(arguments)
    try:
        print(json.dumps(acceptance(options.sentinel_id, options.base_run), sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({'error': {'code': error_code(error)}, 'run_id': getattr(error, 'run_id', None),
            'suite_run_id': getattr(error, 'suite_run_id', None), 'private_evidence_retained': True})); return 1


if __name__ == '__main__':
    raise SystemExit(main())
