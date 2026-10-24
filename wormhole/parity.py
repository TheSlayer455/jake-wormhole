"""One fixed synthetic parity operation; no Docker, scanner or release proof.

Each component runs through its existing API and original-record replay. Case
exit codes describe that component's CLI contract; no component subprocess is
claimed. The module's real process exit is independently observed by its caller.
"""
import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import tempfile
import time

from . import assessments, chunks
from .runs import (Run, RunError, SOURCE_ROOT, _linked, _owned, _path_chain,
    atomic_json, create_run, now, read_json, source_identity, workspace_path)

FILES = ('plan.json', 'results.json', 'decision.json', 'execution.json', 'checksums.json')
MAX_FILE = 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024
MODES = ('all', 'required-failure', 'unexpected-success')
CHECKS = ('execution', 'report-replay', 'domain-result', 'cleanup')


class ParityError(RunError):
    pass


def require(value, code='parity_refused'):
    if not value:
        raise ParityError(code, 'Controlled parity operation refused; retain the bounded failure result.')


def records():
    from . import parity_records
    return parity_records


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink


def directory_identity(info):
    return identity(info)[:4]  # Creating our child changes only parent nlink.


def safe_code(error):
    value = getattr(error, 'code', 'parity_operation_failed')
    return value if type(value) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', value) else 'parity_operation_failed'


def export_path(value):
    path = Path(value)
    require('..' not in path.parts, 'parity_export_path')
    path = path.absolute()
    _path_chain(path)
    return path


@contextmanager
def directory(path):
    _owned(path, directory=True); initial = identity(path.lstat())
    fd = None
    try:
        if os.name == 'posix':
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            require(identity(os.fstat(fd)) == initial, 'parity_export_changed')
        yield fd, initial
        require(identity(path.lstat()) == initial, 'parity_export_changed')
        _path_chain(path)
    finally:
        if fd is not None: os.close(fd)


def bound(path, fd, initial):
    require(identity(path.lstat()) == initial and (fd is None or identity(os.fstat(fd)) == initial), 'parity_export_changed')
    _path_chain(path)


def read_export_files(path):
    """Read only the exact five bounded ordinary files; validate original bytes."""
    path = export_path(path)
    output = {}
    with directory(path) as (parent, root_identity):
        names = lambda: sorted(os.listdir(parent) if parent is not None else [item.name for item in path.iterdir()])
        require(names() == sorted(FILES), 'parity_export_files')
        for name in FILES:
            bound(path, parent, root_identity)
            part = path / name
            _owned(part); initial = part.lstat()
            require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and 0 < initial.st_size <= MAX_FILE, 'parity_export_file')
            fd = os.open(name if parent is not None else part, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0),
                **({'dir_fd': parent} if parent is not None else {}))
            try:
                require(identity(os.fstat(fd)) == identity(initial), 'parity_export_changed')
                with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(MAX_FILE + 1)
                require(len(raw) == initial.st_size and identity(os.fstat(fd)) == identity(initial) and
                    identity(part.lstat()) == identity(initial), 'parity_export_changed')
            finally:
                os.close(fd)
            output[name] = raw
        bound(path, parent, root_identity)
        require(sum(map(len, output.values())) <= MAX_TOTAL and names() == sorted(FILES), 'parity_export_changed')
    records().validate_exports(output)
    return output


def write_export_files(path, files):
    """Validate first; exclusive fresh destination, no repair or overwrite."""
    records().validate_exports(files)
    require(set(files) == set(FILES) and all(type(raw) is bytes and 0 < len(raw) <= MAX_FILE for raw in files.values()) and
        sum(map(len, files.values())) <= MAX_TOTAL, 'parity_export_bound')
    path = export_path(path)
    require(not path.exists() and not _linked(path), 'parity_export_exists')
    require(path.parent.is_dir(), 'parity_export_path')
    parent = directory_identity(path.parent.lstat())
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) if os.name == 'posix' else None
    try:
        require(parent_fd is None or directory_identity(os.fstat(parent_fd)) == parent, 'parity_export_changed')
        os.mkdir(path.name if parent_fd is not None else path, 0o700, **({'dir_fd': parent_fd} if parent_fd is not None else {}))
        require(directory_identity(path.parent.lstat()) == parent, 'parity_export_changed')
        with directory(path) as (root_fd, opened):
            for name in FILES:
                bound(path, root_fd, opened)
                require(directory_identity(path.parent.lstat()) == parent, 'parity_export_changed')
                fd = os.open(name if root_fd is not None else path / name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600,
                    **({'dir_fd': root_fd} if root_fd is not None else {}))
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(files[name]); stream.flush(); os.fsync(stream.fileno())
    finally:
        if parent_fd is not None: os.close(parent_fd)
    require(read_export_files(path) == files, 'parity_export_changed')


def initial_case(spec):
    expected = {'status': spec['expected_status'], 'component_cli_exit_code': spec['expected_exit_code'], 'error_code': spec['expected_error_code']}
    checks = [{'check_id': name, 'required': True, 'expected': value, 'observed': None, 'status': 'unverified'}
        for name, value in [('execution', canonical(expected).decode()), ('report-replay', 'identical'),
            ('domain-result', 'validated-native-result'), ('cleanup', 'private-fixture-removed')]]
    return {'case_id': spec['case_id'], 'run_id': None, 'updated_at': now(), 'duration_seconds': 0., 'loopback_port': None,
        'status': 'not-run', 'actual_status': 'unverified', 'component_cli_exit_code': None,
        'exit_code_kind': 'domain-cli-contract-mapping', 'error_code': None, 'checks': checks,
        'details': {'input_sha256': None, 'output_sha256': None, 'checked_chunks': [], 'findings': [], 'counts': None, 'policy_verdict': None},
        'cleanup': {'status': 'not-started', 'private_removed': False}}


def check(row, name, observed, passed):
    value = next(item for item in row['checks'] if item['check_id'] == name)
    value.update(observed=observed, status='pass' if passed else 'fail')


def raw_fingerprint(path):
    _owned(path)
    before = path.lstat(); require(0 < before.st_size <= 262144, 'parity_record_bound')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        require(identity(os.fstat(fd)) == identity(before), 'parity_record_changed')
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(262145)
        require(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before) and
            identity(path.lstat()) == identity(before), 'parity_record_changed')
        _path_chain(path)
    finally:
        os.close(fd)
    return digest(raw)


def execute_case(run, spec, row):
    """Return original plan/receipt hashes after successful strict replay."""
    if spec['component'] == 'chunks':
        result = chunks.execute_fixture(run, transport=spec['transport'], scenario=spec['scenario'])
        row.update(actual_status=result['status'], component_cli_exit_code=0 if result['status'] == 'passed' else 1,
            error_code=None if result['failure'] is None else result['failure']['code'])
        report = chunks.report_chunks(run)
        require(report['result'] == result and report['plan']['scenario'] == spec['scenario'] and
            report['plan']['transport'] == spec['transport'], 'parity_report_mismatch')
        original = chunks.validate_manifest(read_json(run.file('evidence/chunk-original-manifest.json')))
        source_sha, size = chunks.file_hash(run.file('private/chunks/source.synthetic.bin'), time.monotonic() + 10)
        require(source_sha == original['whole_sha256'] and size == original['total_size'] == 262181 and original['chunk_size'] == 65536,
            'parity_chunk_identity')
        if result['status'] == 'passed': chunks.verified_source(run)
        else:
            require(result['verified_output'] is None and not run.file('private/chunks/reconstructed.synthetic.bin').exists(), 'parity_chunk_unexpected_output')
        row['details'].update(input_sha256=source_sha, output_sha256=None if result['verified_output'] is None else result['verified_output']['sha256'],
            checked_chunks=deepcopy(result['checked_chunks']))
        plan_path, receipt_path = 'evidence/chunk-plan.json', 'evidence/chunks.json'
    else:
        require(spec['component'] == 'assessment' and spec['transport'] is None, 'parity_case_policy')
        raw = assessments.fixture(spec['scenario'])
        try:
            result = assessments.assess_run(run, raw, assessments.FIXTURE_EXPECTED)
        except assessments.AssessmentError:
            result = read_json(run.file(assessments.RECEIPT))
        row.update(actual_status=result['status'], component_cli_exit_code={'passed': 0, 'rejected': 1, 'failed': 2}[result['status']],
            error_code=None if result['primary_failure'] is None else result['primary_failure']['code'])
        declared = {item['finding_id']: item for item in assessments.FIXTURE_EXPECTED}
        parsed = result['result']
        row['details'].update(input_sha256=digest(raw), output_sha256=None if parsed is None else digest(assessments.canonical(parsed)),
            findings=[] if parsed is None else [{**item, 'applicable': declared[item['finding_id']]['applicable']} for item in parsed['findings']],
            counts=None if parsed is None else deepcopy(parsed['counts']), policy_verdict=None if parsed is None else parsed['policy_verdict'])
        report = assessments.report_assessment(run)
        require(report['result'] == result and assessments.original_bytes(run) == raw, 'parity_report_mismatch')
        plan_path, receipt_path = assessments.PLAN, assessments.RECEIPT
    check(row, 'report-replay', 'identical', True)
    check(row, 'domain-result', 'validated-native-result', True)
    return {'case_id': spec['case_id'], 'plan_sha256': raw_fingerprint(run.file(plan_path)), 'receipt_sha256': raw_fingerprint(run.file(receipt_path))}


def existing_originals(run, spec):
    paths = ('evidence/chunk-plan.json', 'evidence/chunks.json') if spec['component'] == 'chunks' else (assessments.PLAN, assessments.RECEIPT)
    hashes = [raw_fingerprint(run.file(name)) if run.file(name).exists() else None for name in paths]
    return dict(zip(('case_id', 'plan_sha256', 'receipt_sha256'), (spec['case_id'], *hashes)))


class PrivateFixtures:
    """Fresh local fixture tree; never a caller-selected cleanup target."""
    def __init__(self, revision, *, prepare=True):
        self.home = Path.home().resolve()
        self.path, self.original = None, None
        self.marker = {'application': 'wormhole-parity-fixtures', 'schema_version': '1.0', 'source_revision': revision}
        self.runs = []
        if prepare: self.prepare()

    def prepare(self):
        require(self.path is None, 'parity_private_reused')
        self.path = Path(tempfile.mkdtemp(prefix='wormhole-parity-', dir=self.home))
        self.original = directory_identity(self.path.lstat())
        self.path = workspace_path(self.path)
        atomic_json(self.path / 'owner.json', self.marker)

    def new(self, revision):
        run = create_run(self.path, fixture=False, kernel_lock=sys.platform.startswith('linux'), identity=(revision, False))
        self.runs.append(run)
        return run

    def cleanup(self):
        path = self.path
        if path is None: return  # The allocator never created a private directory.
        require(path.is_absolute() and path.resolve() == path and path.parent == self.home and
            path.name.startswith('wormhole-parity-') and directory_identity(path.lstat()) == self.original, 'parity_cleanup_scope')
        _owned(path, directory=True)
        require(read_json(path / 'owner.json') == self.marker and set(item.name for item in path.iterdir()) ==
            {'owner.json', *(run.id for run in self.runs)}, 'parity_cleanup_scope')
        for run in self.runs:
            require(Run(path, run.id).path == run.path and run.manifest()['source_revision'] == self.marker['source_revision'], 'parity_cleanup_scope')
        count, size = 0, 0
        for folder, directories, files in os.walk(path, followlinks=False):
            for name in [*directories, *files]:
                part = Path(folder) / name; count += 1
                require(not _linked(part), 'parity_cleanup_scope')
                _owned(part, directory=part.is_dir()); value = part.lstat()
                require(value.st_dev == self.original[0] and count <= 1024, 'parity_cleanup_scope')
                if not part.is_dir():
                    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1, 'parity_cleanup_scope')
                    size += value.st_size; require(size <= 32*1024**2, 'parity_cleanup_scope')
        require(directory_identity(path.lstat()) == self.original and path.resolve() == self.home / path.name, 'parity_cleanup_scope')
        # Resolved exact current-owned target has been verified before recursive
        # deletion. No source, output, arbitrary path or unrelated Run is passed.
        shutil.rmtree(path)
        require(not path.exists(), 'parity_cleanup_incomplete')


def provenance(revision, mode, code, rows, originals):
    github = None
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        github = {'repository': os.environ.get('GITHUB_REPOSITORY'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
            'run_attempt': int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')), 'runner_os': os.environ.get('RUNNER_OS'),
            'runner_arch': os.environ.get('RUNNER_ARCH')}
    return {'source_revision': revision, 'python_version': platform.python_version(), 'platform': sys.platform,
        'architecture': platform.machine(), 'execution_mode': 'github-actions' if github is not None else
            'gitlab' if os.environ.get('GITLAB_CI') == 'true' else 'manual',
        'command': ['python3', '-B', '-m', 'wormhole.parity', 'run', '--output', 'ci-safe', '--mode', mode],
        'exit_code': code, 'exit_code_kind': 'computed-runner-return-code', 'created_at': now(),
        'case_run_ids': [row['run_id'] for row in rows if row['run_id'] is not None], 'original_records': originals, 'github': github}


def run_parity(output, mode='all'):
    require(mode in MODES, 'parity_mode')
    output = export_path(output)
    require(not output.exists() and not _linked(output), 'parity_export_exists')
    revision, dirty = source_identity(); require(dirty is False, 'parity_source_dirty')
    plan = records().build_plan(mode, revision)
    record = {'schema_version': '1.0', 'operation': 'synthetic-parity-results-v1', 'source_revision': revision, 'source_dirty': False,
        'mode': mode, 'synthetic': True, 'plan_sha256': plan['plan_sha256'], 'status': 'failed',
        'cases': [initial_case(spec) for spec in plan['cases']], 'primary_failure': None,
        'cleanup': {'status': 'failed', 'private_removed': False}, 'reference_eligible': False, 'production_iso_eligible': False}
    area, originals = None, []
    def failure(code, case_id=None):
        if record['primary_failure'] is None: record['primary_failure'] = {'code': code, 'case_id': case_id}
    try:
        # Retain the object before its first write so a partial setup failure
        # cannot be reported as "private removed" merely because __init__ raised.
        area = PrivateFixtures(revision, prepare=False)
        area.prepare()
        for spec, row in zip(plan['cases'], record['cases']):
            require(source_identity() == (revision, False), 'parity_source_changed')
            began = time.monotonic()
            try:
                run = area.new(revision); row['run_id'] = run.id
                originals.append({'case_id': row['case_id'], 'plan_sha256': None, 'receipt_sha256': None})
                originals[-1] = execute_case(run, spec, row)
            except Exception as error:
                if row['run_id'] is not None:
                    try: originals[-1] = existing_originals(run, spec)
                    except (RunError, OSError): pass  # Original-read refusal remains a failed replay, never a pass.
                if row['actual_status'] == 'unverified': row.update(actual_status='failed', component_cli_exit_code=2, error_code=safe_code(error))
                check(row, 'report-replay', 'refused:' + safe_code(error), False)
                failure(safe_code(error), row['case_id'])
            row.update(updated_at=now(), duration_seconds=time.monotonic() - began, status='failed')
            observed = canonical({'status': row['actual_status'], 'component_cli_exit_code': row['component_cli_exit_code'], 'error_code': row['error_code']}).decode()
            matches = observed == row['checks'][0]['expected']
            check(row, 'execution', observed, matches)
            if not matches: failure('parity_unexpected_outcome', row['case_id'])
        require(source_identity() == (revision, False), 'parity_source_changed')
    except Exception as error:
        failure(safe_code(error))
    finally:
        try:
            if area is not None: area.cleanup()
            record['cleanup'] = {'status': 'completed', 'private_removed': True}
        except Exception as error:
            failure(safe_code(error))
        for row in record['cases']:
            if row['run_id'] is not None:
                row['cleanup'] = dict(record['cleanup'])
                check(row, 'cleanup', 'private-fixture-removed' if record['cleanup']['private_removed'] else 'private-fixture-retained',
                    record['cleanup']['private_removed'])
                row['status'] = 'passed' if all(item['status'] == 'pass' for item in row['checks']) else 'failed'
    if record['primary_failure'] is None and all(row['status'] == 'passed' for row in record['cases']) and record['cleanup']['private_removed']:
        record['status'] = 'passed'
    else:
        failure('parity_incomplete')
    records().validate_record(record, plan)
    code = 0 if record['status'] == 'passed' else 1
    files = records().export_files(record, plan, provenance(revision, mode, code, record['cases'], originals))
    write_export_files(output, files)
    return {'status': record['status'], 'exit_code': code, 'source_revision': revision, 'mode': mode,
        'case_count': len(record['cases']), 'passed_cases': sum(row['status'] == 'passed' for row in record['cases']),
        'primary_failure': record['primary_failure'], 'cleanup': record['cleanup'], 'reference_eligible': False, 'production_iso_eligible': False}


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Fixed local synthetic parity; no infrastructure or release eligibility.')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('run', 'validate'):
        command = sub.add_parser(name); command.add_argument('--output', required=True)
        if name == 'run': command.add_argument('--mode', choices=MODES, default='all')
    options = parser.parse_args(arguments)
    try:
        allowed = {'ci-safe'} if options.command == 'run' else {'ci-safe', 'ci-artifacts'}
        require(options.output in allowed, 'parity_export_path')
        if options.command == 'run':
            result = run_parity(SOURCE_ROOT / options.output, options.mode)
            print(json.dumps(result, sort_keys=True)); return result['exit_code']
        summary = records().validate_exports(read_export_files(SOURCE_ROOT / options.output))
        print(json.dumps(summary, sort_keys=True)); return 0
    except (RunError, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'failed', 'error': {'code': safe_code(error)}, 'reference_eligible': False, 'production_iso_eligible': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
