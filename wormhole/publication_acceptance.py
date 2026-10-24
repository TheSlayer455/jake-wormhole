"""Actual private local publication qualification on approved Linux storage.

Fresh same-source pipelines supply the original tested bytes. Expected refusal
and interrupted-publisher cases never promote a failed or incomplete artifact.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from uuid import UUID

from . import candidate, images
from .pipeline_records import EXPORT_PATHS
from .provisioning_acceptance import error_code
from .reference_acceptance import qualify_case
from .runs import SOURCE_ROOT, Run, _owned, atomic_bytes, atomic_json, common, create_run, now, read_json, source_identity
from .stages import _run_process

CASES = (('ubuntu', 'healthy', 'complete'), ('ubi', 'healthy', 'complete'),
         ('ubuntu', 'healthy', 'marker-linked-interruption'),
         ('ubuntu', 'version-expectation-mismatch', 'ineligible'))
MAX_BYTES = 64 * 1024 * 1024
CRASH_EXIT = 86
CRASH_WORKER = '''import os,sys
from wormhole.images import RUNS_ROOT
from wormhole.publication import publish_reference
from wormhole.runs import Run,atomic_json
run=Run(RUNS_ROOT,sys.argv[1])
def checkpoint(event,metadata):
    if event == "marker-linked":
        atomic_json(run.file("private/publication-acceptance-crash.json"),{"event":event,"metadata":metadata,"publisher_pid":os.getpid()})
        os._exit(86)
publish_reference(run,checkpoint=checkpoint)
raise SystemExit(87)
'''


def require(value, code='publication_acceptance_invalid'):
    candidate.require(value, code)


def file_bytes(path):
    _owned(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_BYTES,
            'publication_acceptance_file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size),
                'publication_acceptance_file_changed')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        require(len(raw) == info.st_size and os.fstat(descriptor).st_mtime_ns == opened.st_mtime_ns,
                'publication_acceptance_file_changed')
        return raw
    finally:
        os.close(descriptor)


def identity(raw):
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}


def release_files(root):
    """Bounded tree identity, also able to record the incomplete link window."""
    result = {}; total = 0
    for directory, children, files in os.walk(root, followlinks=False):
        folder = Path(directory); _owned(folder, directory=True)
        require(all(not (folder / name).is_symlink() for name in children), 'publication_acceptance_link')
        for name in sorted(files):
            path = folder / name; info = path.lstat()
            links = (1, 2) if folder == root and name in ('COMPLETE.json', '.COMPLETE.pending') else (1,)
            require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size <= MAX_BYTES and
                    info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink in links,
                    'publication_acceptance_file')
            total += info.st_size
            require(len(result) < 32 and total <= MAX_BYTES, 'publication_acceptance_bound')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opened = os.fstat(descriptor)
                attributes = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mode,
                                            item.st_uid, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
                require(attributes(opened) == attributes(info), 'publication_acceptance_file_changed')
                with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                    raw = stream.read(MAX_BYTES + 1)
                require(len(raw) == info.st_size and attributes(os.fstat(descriptor)) == attributes(opened) and
                        attributes(path.lstat()) == attributes(opened), 'publication_acceptance_file_changed')
            finally:
                os.close(descriptor)
            result[path.relative_to(root).as_posix()] = {**identity(raw), 'links': info.st_nlink,
                                                        'mode': stat.S_IMODE(info.st_mode)}
    return result


def compare_originals(run, platform, inspection):
    from .publication import RELEASE_ROOT
    from .rpm_source import EULA_NAME, validate_eula
    require(inspection['status'] == 'complete' and inspection['logical_complete'] is True and
            inspection['historical_durability'] == 'not-inferred', 'publication_acceptance_false_complete')
    completion = inspection['completion']
    release = RELEASE_ROOT / ('reference-' + run.id)
    candidate_dir = run.file('private/candidate' if platform == 'ubuntu' else 'private/rpm-candidate')
    originals = {'candidate/' + name: candidate_dir / name for name in (*candidate.NAMES, 'manifest.json')}
    originals.update({'evidence/' + name: run.file('evidence/reference/' + name) for name in EXPORT_PATHS})
    if platform == 'ubi':
        originals['licenses/' + EULA_NAME] = validate_eula(run)
    require(set(completion['files']) == set(originals) | {'REFERENCE.txt'}, 'publication_acceptance_allowlist')
    for name, source in originals.items():
        original, copied = file_bytes(source), file_bytes(release / name)
        require(original == copied and completion['files'][name] == identity(original),
                'publication_acceptance_bytes_changed')
    files = release_files(release)
    require(set(files) == set(completion['files']) | {'checksums.json', 'COMPLETE.json'} and
            len(files) == (24 if platform == 'ubuntu' else 25) and
            all(row['mode'] == 0o600 and row['links'] == 1 for row in files.values()),
            'publication_acceptance_closed_tree')
    require(files['COMPLETE.json']['sha256'] == inspection['completion_sha256'],
            'publication_acceptance_completion_hash')
    return {'files': files, 'original_files_compared': len(originals), 'exact_byte_identity': True,
            'completion_sha256': inspection['completion_sha256']}


def cli_inspect(run_id, expected_status):
    observed = _run_process((sys.executable, '-B', '-m', 'wormhole', 'publication-status', run_id),
                            cwd=SOURCE_ROOT, timeout=45)
    require(observed['returncode'] == expected_status and observed['status'] == ('pass' if expected_status == 0 else 'fail') and
            observed['log_truncated'] is False,
            'publication_acceptance_cli')
    value = json.loads(observed['log'])
    return value, {'returncode': observed['returncode'], 'duration_seconds': observed['duration_seconds'],
                   'output_sha256': hashlib.sha256(observed['log']).hexdigest()}


def visibility_proof(run, receipt, inspection):
    identifier = receipt['attempt_id']
    require(str(UUID(identifier)) == identifier, 'publication_acceptance_visibility')
    path = run.file('private/publication-visibility-' + identifier + '.json')
    raw = file_bytes(path); proof = read_json(path)
    expected = {'owner_pid', 'owner_uid', 'owner_gid', 'probe_pid', 'probe_uid', 'probe_gid',
                'probe_path', 'errno', 'outcome'}
    require(set(proof) == expected and proof['outcome'] == 'denied' and proof['errno'] == errno.EACCES and
            proof['probe_path'] == 'REFERENCE.txt' and proof['owner_uid'] == os.getuid() and
            proof['owner_gid'] == os.getgid() and proof['owner_uid'] != proof['probe_uid'] and
            proof['probe_uid'] > 0 and proof['probe_pid'] > 1 and proof['owner_pid'] > 1 and
            proof['probe_pid'] != proof['owner_pid'], 'publication_acceptance_visibility')
    visibility = inspection['completion']['visibility']
    require(all(visibility[key] == proof[key] for key in ('owner_uid', 'owner_gid', 'probe_uid', 'probe_gid')) and
            visibility['owner_readable'] is True and visibility['unprivileged_denied'] is True,
            'publication_acceptance_visibility')
    require(file_bytes(path) == raw, 'publication_acceptance_visibility_changed')
    return {'logical_path': 'private/publication-visibility-' + identifier + '.json',
            **identity(raw), 'observation': proof}


def case_projection(value):
    """Keep the suite bounded; retain the full original case separately by hash."""
    run = Run(images.RUNS_ROOT, value['run_id'])
    raw = file_bytes(run.file('evidence/publication-acceptance.json'))
    pipeline = value['pipeline']; record = pipeline['record']
    summary = {key: value[key] for key in (*common(run.manifest()).keys(), 'operation', 'platform',
        'scenario', 'publication_case', 'status', 'simulation', 'production_eligible',
        'production_iso_eligible', 'image_published', 'remote_release', 'created_at', 'finished_at',
        'original_reference_unchanged')}
    summary['case_evidence'] = {'logical_path': 'evidence/publication-acceptance.json', **identity(raw)}
    summary['pipeline'] = {key: pipeline[key] for key in ('status', 'operation_status', 'failure_code',
        'unrelated_sentinel_unchanged', 'counts', 'report_sha256', 'cli_gate', 'admission_resources')}
    summary['pipeline'].update(candidate=record['candidate'], cleanup=record['cleanup'],
                               decision=pipeline['decision'])
    for key in ('receipt', 'inspection', 'comparison', 'cli_inspection', 'duplicate_refusal',
                'interrupted_output', 'publisher_exit', 'crash_observation', 'visibility_proof', 'refusal'):
        if key in value:
            summary[key] = value[key]
    require(len(json.dumps(summary, sort_keys=True).encode()) <= 48 * 1024,
            'publication_acceptance_summary_bound')
    return summary


def qualify_publication(platform, scenario, operation, sentinel, base_run_id):
    from .pipeline import gate_pipeline
    from .publication import RELEASE_ROOT, inspect_publication, publish_reference
    pipeline = qualify_case(platform, scenario, sentinel, base_run_id)
    run = Run(images.RUNS_ROOT, pipeline['run_id'])
    result = {**common(run.manifest()), 'operation': 'real-reference-publication-case-v1', 'platform': platform,
              'scenario': scenario, 'publication_case': operation, 'status': 'running', 'created_at': now(),
              'pipeline': pipeline, 'simulation': True, 'production_eligible': False,
              'production_iso_eligible': False, 'image_published': False, 'remote_release': False}
    def save(): atomic_json(run.file('evidence/publication-acceptance.json'), result)
    save()
    try:
        before = {name: identity(file_bytes(run.file('evidence/reference/' + name))) for name in EXPORT_PATHS}
        with run.locked(): decision_before = gate_pipeline(run)
        if operation == 'complete':
            receipt = publish_reference(run)
            require(receipt['status'] == 'completed' and receipt['logical_complete'] is True and
                    receipt['durability_acknowledged'] is True, 'publication_acceptance_receipt')
            inspection = inspect_publication(run.id)
            with run.locked():
                comparison = compare_originals(run, platform, inspection)
                visibility = visibility_proof(run, receipt, inspection)
            independently, cli = cli_inspect(run.id, 0)
            require(independently['completion'] == inspection['completion'] and
                    independently['completion_sha256'] == receipt['completion_sha256'],
                    'publication_acceptance_cli_disagreement')
            duplicate = None
            try: publish_reference(run)
            except Exception as error: duplicate = error_code(error)
            require(duplicate == 'publication_duplicate' and
                    release_files(RELEASE_ROOT / ('reference-' + run.id)) == comparison['files'],
                    'publication_acceptance_overwrite')
            result.update(receipt=receipt, inspection=inspection, comparison=comparison,
                          cli_inspection=cli, duplicate_refusal=duplicate, visibility_proof=visibility)
        elif operation == 'marker-linked-interruption':
            child = _run_process((sys.executable, '-B', '-c', CRASH_WORKER, run.id), cwd=SOURCE_ROOT, timeout=60)
            require(child['returncode'] == CRASH_EXIT and child['status'] == 'fail' and child['log_truncated'] is False,
                    'publication_acceptance_crash_not_observed')
            inspection, cli = cli_inspect(run.id, 1)
            require(inspection['status'] == 'incomplete' and inspection['logical_complete'] is False,
                    'publication_acceptance_false_complete')
            preserved = release_files(RELEASE_ROOT / ('reference-' + run.id))
            crash = read_json(run.file('private/publication-acceptance-crash.json'))
            require(crash['event'] == 'marker-linked' and crash['publisher_pid'] > 1 and
                    crash['metadata']['run_id'] == run.id and crash['metadata']['release_id'] == 'reference-' + run.id and
                    str(UUID(crash['metadata']['attempt_id'])) == crash['metadata']['attempt_id'],
                    'publication_acceptance_crash_not_observed')
            marker = preserved.get('COMPLETE.json'); pending = preserved.get('.COMPLETE.pending')
            release = RELEASE_ROOT / ('reference-' + run.id)
            marker_stat = (release / 'COMPLETE.json').stat()
            pending_stat = (release / '.COMPLETE.pending').stat()
            require(marker is not None and pending == marker and marker['links'] == 2 and
                    (marker_stat.st_dev, marker_stat.st_ino) == (pending_stat.st_dev, pending_stat.st_ino) and
                    all(row['links'] == 1 for name, row in preserved.items() if name not in ('COMPLETE.json', '.COMPLETE.pending')),
                    'publication_acceptance_crash_not_observed')
            duplicate = None
            try: publish_reference(run)
            except Exception as error: duplicate = error_code(error)
            require(duplicate == 'publication_duplicate' and
                    release_files(RELEASE_ROOT / ('reference-' + run.id)) == preserved,
                    'publication_acceptance_overwrite')
            result.update(inspection=inspection, cli_inspection=cli, duplicate_refusal=duplicate,
                          interrupted_output=preserved, publisher_exit=child['returncode'], crash_observation=crash)
        else:
            require(operation == 'ineligible' and decision_before['reference_eligible'] is False,
                    'publication_acceptance_negative')
            refusal = None
            try: publish_reference(run)
            except Exception as error: refusal = error_code(error)
            inspection = inspect_publication(run.id)
            require(refusal == 'publication_ineligible' and inspection['status'] == 'absent' and
                    inspection['logical_complete'] is False, 'publication_acceptance_negative')
            result.update(refusal=refusal, inspection=inspection)
        with run.locked(): require(gate_pipeline(run) == decision_before, 'publication_acceptance_mutated_gate')
        require(before == {name: identity(file_bytes(run.file('evidence/reference/' + name))) for name in EXPORT_PATHS},
                'publication_acceptance_mutated_sources')
        result.update(status='passed', finished_at=now(), original_reference_unchanged=True)
        save(); return result
    except BaseException as error:
        result.update(status='failed', error_code=error_code(error), finished_at=now()); save()
        error.run_id = run.id; raise


def acceptance(sentinel, base_run_id):
    from .publication import initialize_publication_root
    require(sys.platform.startswith('linux') and type(sentinel) is str and candidate.IDENTIFIER.fullmatch(sentinel),
            'publication_acceptance_platform')
    require(type(base_run_id) is str and str(UUID(base_run_id)) == base_run_id, 'publication_acceptance_input')
    revision, dirty = source_identity(); require(dirty is False, 'publication_acceptance_source')
    suite = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    result = {**common(suite.manifest()), 'operation': 'real-reference-publication-suite-v1',
              'status': 'running', 'suite_run_id': suite.id, 'cases': [], 'pending_case': None,
              'simulation': True, 'production_eligible': False, 'production_iso_eligible': False,
              'image_published': False, 'remote_release': False}
    def save():
        raw = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        atomic_bytes(suite.file('evidence/publication-acceptance-suite.json'), raw)
    with suite.locked():
        save()
        try:
            result['root_initialization'] = initialize_publication_root(); save()
            for platform, scenario, operation in CASES:
                require(source_identity() == (revision, False), 'publication_acceptance_source')
                result['pending_case'] = [platform, scenario, operation]; save()
                case = qualify_publication(platform, scenario, operation, sentinel, base_run_id)
                require(case['status'] == 'passed' and case['source_revision'] == revision and
                        case['source_dirty'] is False and case['run_id'] not in
                        {suite.id, *(row['run_id'] for row in result['cases'])} and
                        source_identity() == (revision, False),
                        'publication_acceptance_source')
                result['cases'].append(case_projection(case)); result['pending_case'] = None; save()
            require(source_identity() == (revision, False), 'publication_acceptance_source')
            result.update(status='passed', finished_at=now()); save(); return result
        except BaseException as error:
            result.update(status='failed', error_code=error_code(error),
                          failed_child_run_id=getattr(error, 'run_id', None)); save()
            error.suite_run_id = suite.id; raise


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Actual private local tested-byte publication qualification.')
    parser.add_argument('--sentinel-id', required=True); parser.add_argument('--base-run', required=True)
    options = parser.parse_args(arguments)
    try:
        print(json.dumps(acceptance(options.sentinel_id, options.base_run), sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({'error': {'code': error_code(error)}, 'run_id': getattr(error, 'run_id', None),
                          'suite_run_id': getattr(error, 'suite_run_id', None), 'private_evidence_retained': True})); return 1


if __name__ == '__main__':
    raise SystemExit(main())
