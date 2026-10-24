"""Linux-local publication of literal tested bytes, never a build or deployment.

Run lock -> fixed publication-root flock is the only acquisition order. COMPLETE
describes logical bytes/privacy. A producer receipt separately acknowledges its
later directory fsync; inspecting a tree cannot prove past fsync or power loss.
"""
from contextlib import contextmanager
from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import time
from uuid import uuid4

from . import candidate, images, pipeline
from .runs import (Run, RunError, _owned, atomic_bytes, atomic_json, common, now,
                   run_id, source_identity)

RELEASE_ROOT = Path('/srv/homelab/jake-wormhole/releases')
OWNER = {'schema_version': '1.0', 'application': 'jake-wormhole',
         'kind': 'private-reference-publications'}
MAX_SECONDS = 120
CHUNK = 65536
CHECKPOINTS = ('reserved', 'file-copied', 'before-complete', 'marker-linked',
               'committed-before-receipt')


class PublicationError(RunError):
    pass


def require(value, code='publication_refused'):
    if not value:
        raise PublicationError(code, 'Reference publication refused; preserve the Run and publication attempt for inspection.')


def records():
    from . import publication_records
    return publication_records


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_code(error):
    value = getattr(error, 'code', 'publication_io_error')
    return value if type(value) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', value) else 'publication_io_error'


def _linux():
    require(sys.platform.startswith('linux'), 'publication_linux_required')


def _remaining(deadline):
    require(time.monotonic() < deadline, 'publication_timeout')


def _canonical(value):
    return records().canonical(value) + b'\n'


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory_info(value, *, private=False):
    require(stat.S_ISDIR(value.st_mode) and value.st_uid in (0, os.geteuid()) and
            not stat.S_IMODE(value.st_mode) & 0o022, 'publication_unsafe_directory')
    if private:
        require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700,
                'publication_private_directory_required')


def _directory(path, *, private=False):
    """Open every absolute component without following links or writable parents."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'publication_unsafe_path')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _directory_info(os.fstat(descriptor))
        for index, part in enumerate(path.parts[1:], 1):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            try:
                _directory_info(os.fstat(child), private=private and index == len(path.parts) - 1)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _regular(value, *, exact_mode=None):
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and
            value.st_uid == os.geteuid() and not stat.S_IMODE(value.st_mode) & 0o077,
            'publication_unsafe_file')
    if exact_mode is not None:
        require(stat.S_IMODE(value.st_mode) == exact_mode, 'publication_private_file_required')


def _sync(descriptor):
    os.fsync(descriptor)  # Failure is an explicit failure, never successful durability.


def _read_at(parent, name, maximum, *, mode=0o600):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        value = os.fstat(descriptor)
        _regular(value, exact_mode=mode)
        require(value.st_size <= maximum, 'publication_byte_bound')
        data = bytearray()
        while chunk := os.read(descriptor, min(CHUNK, maximum + 1 - len(data))):
            data.extend(chunk)
            require(len(data) <= maximum, 'publication_byte_bound')
        require(_identity(os.fstat(descriptor)) == _identity(value) and
                _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _identity(value),
                'publication_destination_changed')
        return bytes(data)
    finally:
        os.close(descriptor)


def _write_new(parent, name, raw):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
    try:
        _regular(os.fstat(descriptor), exact_mode=0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, 'publication_io_error')
            view = view[written:]
        _sync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _root_locked():
    _linux()
    import fcntl
    root = _directory(RELEASE_ROOT, private=True)
    lock = None
    try:
        marker = _read_at(root, 'owner.json', 4096)
        require(marker == _canonical(OWNER), 'publication_root_unowned')
        lock = os.open('publication.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        _regular(os.fstat(lock), exact_mode=0o600)
        identity = _identity(os.fstat(lock))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PublicationError('publication_busy', 'Another publisher holds the stable publication lock; no takeover is permitted.') from None
        def check():
            current = _directory(RELEASE_ROOT, private=True)
            try:
                require((os.fstat(root).st_dev, os.fstat(root).st_ino) ==
                        (os.fstat(current).st_dev, os.fstat(current).st_ino), 'publication_root_changed')
                require(_identity(os.fstat(lock)) == identity and
                        _identity(os.stat('publication.lock', dir_fd=root, follow_symlinks=False)) == identity and
                        _read_at(root, 'owner.json', 4096) == marker, 'publication_root_changed')
            finally:
                os.close(current)
        check()
        yield root, check
    finally:
        if lock is not None:
            os.close(lock)  # Persistent inode; kernel releases the held flock.
        os.close(root)


def initialize_publication_root():
    """Explicit fixed-root initialization; never adopt a preexisting unmarked dir."""
    _linux()
    parent = _directory(RELEASE_ROOT.parent)
    root = None
    created = False
    try:
        try:
            os.mkdir(RELEASE_ROOT.name, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        root = os.open(RELEASE_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=parent)
        _directory_info(os.fstat(root), private=True)
        def check_path():
            current_parent = _directory(RELEASE_ROOT.parent)
            current_root = None
            try:
                require((os.fstat(current_parent).st_dev, os.fstat(current_parent).st_ino) ==
                        (os.fstat(parent).st_dev, os.fstat(parent).st_ino), 'publication_root_changed')
                current_root = os.open(RELEASE_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=current_parent)
                _directory_info(os.fstat(current_root), private=True)
                require((os.fstat(current_root).st_dev, os.fstat(current_root).st_ino) ==
                        (os.fstat(root).st_dev, os.fstat(root).st_ino), 'publication_root_changed')
            finally:
                if current_root is not None:
                    os.close(current_root)
                os.close(current_parent)
        # All writes stay anchored to the newly created leaf, even if a trusted
        # parent is concurrently renamed. Never mark a replacement directory.
        check_path()
        if created:
            _write_new(root, 'owner.json', _canonical(OWNER))
            _write_new(root, 'publication.lock', b'')
            _sync(root)
            _sync(parent)
        with _root_locked() as (_, check):
            check()
            check_path()
        return {'operation': 'reference-publication-root-init', 'initialized': True,
                'created': created, 'remote_release': False, 'production_iso_eligible': False}
    except OSError:
        raise PublicationError('publication_root_unavailable', 'The fixed private publication root could not be initialized; preserve existing paths.') from None
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)


class _Source:
    def __init__(self, path, descriptor, deadline):
        self.path, self.expected, self.deadline = Path(path), descriptor, deadline
        self.parent = _directory(self.path.parent, private=True)
        self.fd = None
        try:
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=self.parent)
            value = os.fstat(self.fd)
            _regular(value)
            self.identity = _identity(value)
            self.parent_identity = (os.fstat(self.parent).st_dev, os.fstat(self.parent).st_ino)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        _remaining(self.deadline)
        require(_identity(os.fstat(self.fd)) == self.identity, 'publication_source_changed')
        parent = _directory(self.path.parent, private=True)
        try:
            require((os.fstat(parent).st_dev, os.fstat(parent).st_ino) == self.parent_identity and
                    _identity(os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)) == self.identity,
                    'publication_source_changed')
        finally:
            os.close(parent)
        require(self.identity[6] == self.expected['size_bytes'], 'publication_source_changed')
        os.lseek(self.fd, 0, os.SEEK_SET)
        hashed, size = hashlib.sha256(), 0
        while chunk := os.read(self.fd, CHUNK):
            _remaining(self.deadline)
            size += len(chunk)
            require(size <= self.expected['size_bytes'], 'publication_source_changed')
            hashed.update(chunk)
        require(size == self.expected['size_bytes'] and hashed.hexdigest() == self.expected['sha256'] and
                _identity(os.fstat(self.fd)) == self.identity, 'publication_source_changed')

    def copy(self, output):
        self.verify()
        os.lseek(self.fd, 0, os.SEEK_SET)
        hashed, size = hashlib.sha256(), 0
        while chunk := os.read(self.fd, CHUNK):
            _remaining(self.deadline)
            size += len(chunk)
            require(size <= self.expected['size_bytes'], 'publication_source_changed')
            hashed.update(chunk)
            view = memoryview(chunk)
            while view:
                count = os.write(output, view)
                require(count > 0, 'publication_io_error')
                view = view[count:]
        require(size == self.expected['size_bytes'] and hashed.hexdigest() == self.expected['sha256'],
                'publication_source_changed')
        self.verify()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None


def _scope(run, guard):
    _linux()
    guard.check(run)
    require(guard.path == run.file('operation.lock'), 'publication_run_lock_required')
    manifest = run.manifest()
    require(run.workspace == images.RUNS_ROOT and manifest['mode'] == 'container-reference' and
            manifest['profile'] == 'smoke' and manifest['source_dirty'] is False and
            source_identity() == (manifest['source_revision'], False), 'publication_source_changed')
    return manifest


def _snapshot(run, guard, deadline):
    """Replay original proof, then hold/verify exact literal allowlisted sources."""
    manifest = _scope(run, guard)
    sources = {}
    try:
        try:
            report = pipeline.report_pipeline(run)
            decision = report['decision']
            require(decision['reference_eligible'] is True and decision['reference_scope_complete'] is True and
                    decision['production_iso_eligible'] is False and report['record']['status'] == 'passed',
                    'publication_ineligible')
            platform = json.loads(pipeline.replay.raw_file(run, pipeline.REQUEST, 262144))['platform']
            plan = json.loads(pipeline.replay.raw_file(run, pipeline.PLAN, 262144))
            expected_exports = pipeline.export_files(run, report['record'], plan)
            require(set(expected_exports) == set(records().EVIDENCE_PATHS), 'publication_ineligible')
            if platform == 'ubuntu':
                bundle = candidate.validate_bundle(run)
            elif platform == 'ubi':
                from . import rpm_candidate
                bundle = rpm_candidate.validate_bundle(run)
            else:
                require(False, 'publication_ineligible')
            identity = pipeline.candidate_identity(bundle['manifest'])
            require(all(report['record']['candidate'][key] == value for key, value in identity.items()),
                    'publication_ineligible')
        except RunError as error:
            if isinstance(error, PublicationError):
                raise
            raise PublicationError('publication_ineligible', 'Original reference evidence is not eligible for publication.') from None
        def add(relative, path, expected):
            descriptor = {'sha256': digest(expected), 'size_bytes': len(expected)} if type(expected) is bytes else expected
            sources[relative] = _Source(path, descriptor, deadline)
        for item in bundle['manifest']['files']:
            add('candidate/' + item['path'], bundle['directory'] / item['path'],
                {'sha256': item['sha256'], 'size_bytes': item['size']})
        add('candidate/manifest.json', bundle['directory'] / 'manifest.json', candidate.canonical(bundle['manifest']))
        for relative, raw in expected_exports.items():
            add('evidence/' + relative, run.file(pipeline.EXPORT + '/' + relative), raw)
        if platform == 'ubi':
            from .rpm_source import validate_eula
            add(records().EULA_PATH, validate_eula(run), {'sha256': records().EULA_SHA256, 'size_bytes': records().EULA_BYTES})
        table = {name: deepcopy(source.expected) for name, source in sources.items()}
        table['REFERENCE.txt'] = {'sha256': digest(records().REFERENCE_BYTES), 'size_bytes': len(records().REFERENCE_BYTES)}
        checksums = {**common(manifest), 'operation': records().CHECKSUMS_OPERATION, 'platform': platform, 'files': table}
        records().validate_checksums(checksums)
        _scope(run, guard)
        _remaining(deadline)
        return {'platform': platform, 'candidate': deepcopy(report['record']['candidate']),
                'gate': {'plan_sha256': report['record']['plan_sha256'], 'record_sha256': decision['record_sha256'],
                         'decision_sha256': table['evidence/decision.json']['sha256'],
                         'final_decision_sha256': table['evidence/decision.json']['sha256'],
                         'archive_sha256': report['record']['cleanup']['archive_sha256']},
                'checksums': checksums, 'sources': sources}
    except BaseException:
        for source in sources.values():
            source.close()
        raise


def _close(snapshot):
    if snapshot is not None:
        for source in snapshot['sources'].values():
            source.close()


def _parent_at(root, relative, *, create=False):
    descriptor = os.dup(root)
    try:
        for part in relative.split('/')[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    _sync(descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            try:
                _directory_info(os.fstat(child), private=True)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _tree(directory, expected, deadline):
    """Hash a closed destination tree via held directory descriptors, no links."""
    directories = {''}
    for name in expected:
        parts = name.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    seen, count = {}, 0
    def names(parent):
        result = []
        with os.scandir(parent) as entries:
            for entry in entries:
                _remaining(deadline)
                require(len(result) < 64, 'publication_file_set')
                result.append(entry.name)
        return tuple(sorted(result))
    def walk(parent, prefix):
        nonlocal count
        _remaining(deadline)
        before = os.fstat(parent)
        _directory_info(before, private=True)
        entries = names(parent)
        for name in entries:
            count += 1
            require(count <= 64, 'publication_file_set')
            relative = prefix + name
            value = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(value.st_mode):
                require(relative in directories, 'publication_file_set')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    opened = os.fstat(child)
                    _directory_info(opened, private=True)
                    require(_identity(opened) == _identity(value), 'publication_destination_changed')
                    walk(child, relative + '/')
                    require(_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _identity(opened),
                            'publication_destination_changed')
                finally:
                    os.close(child)
            else:
                require(relative in expected, 'publication_file_set')
                raw = _read_at(parent, name, expected[relative]['size_bytes'])
                seen[relative] = {'sha256': digest(raw), 'size_bytes': len(raw)}
                require(seen[relative] == expected[relative], 'publication_destination_changed')
        require(_identity(os.fstat(parent)) == _identity(before) and names(parent) == entries,
                'publication_destination_changed')
    walk(directory, '')
    require(set(seen) == set(expected), 'publication_file_set')
    _remaining(deadline)
    return seen


def probe_private_visibility(directory):
    """Bounded own fork drops all groups/UID; only attempts one fixed public file."""
    _linux()
    require(os.geteuid() == 0, 'publication_visibility_unavailable')
    import pwd
    target = pwd.getpwnam('nobody')
    require(target.pw_uid > 0, 'publication_visibility_unavailable')
    path = Path(directory) / 'REFERENCE.txt'
    parent = _directory(directory, private=True)
    try:
        require(_read_at(parent, 'REFERENCE.txt', 4096) == records().REFERENCE_BYTES, 'publication_label_changed')
    finally:
        os.close(parent)
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    process = os.fork()
    if process == 0:
        try:
            os.close(read_end)
            # Inherited readable descriptors must not bypass the path probe.
            for item in os.listdir('/proc/self/fd'):
                descriptor = int(item)
                if descriptor > 2 and descriptor != write_end:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            os.setgroups([])
            os.setgid(target.pw_gid)
            os.setuid(target.pw_uid)
            if os.geteuid() != target.pw_uid or os.getegid() != target.pw_gid or os.getgroups():
                os._exit(3)
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError as error:
                result = b'EACCES' if error.errno == errno.EACCES else b'OTHER'
            else:
                os.close(descriptor)
                result = b'ALLOWED'
            os.write(write_end, result)
            os._exit(0)
        except BaseException:
            os._exit(3)
    os.close(write_end)
    ended = False
    try:
        require(bool(select.select([read_end], [], [], 3)[0]), 'publication_visibility_timeout')
        result = os.read(read_end, 32)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            waited, status = os.waitpid(process, os.WNOHANG)
            if waited:
                ended = True
                require(os.waitstatus_to_exitcode(status) == 0, 'publication_visibility_unavailable')
                break
            time.sleep(0.01)
        require(ended and result == b'EACCES', 'publication_visibility_unproven')
        return {'owner_pid': os.getpid(), 'owner_uid': os.geteuid(), 'owner_gid': os.getegid(),
                'probe_pid': process, 'probe_uid': target.pw_uid, 'probe_gid': target.pw_gid,
                'probe_path': 'REFERENCE.txt', 'errno': errno.EACCES, 'outcome': 'denied'}
    finally:
        os.close(read_end)
        if not ended:
            os.kill(process, signal.SIGKILL)  # Exact own fork, never a stored PID.
            os.waitpid(process, 0)


def _attempt(run):
    folder = run.file('private/publication-attempts')
    folder.mkdir(mode=0o700, exist_ok=True)
    _owned(folder, directory=True)
    attempt = str(uuid4())
    stamp = now()
    receipt = {**common(run.manifest()), **{key: value['const'] for key, value in records().FLAGS.items()},
               'operation': records().RECEIPT_OPERATION, 'attempt_id': attempt, 'release_id': 'reference-' + run.id,
               'platform': None, 'status': 'running', 'logical_complete': False,
               'durability_acknowledged': False, 'completion_sha256': None, 'error_code': None,
               'created_at': stamp, 'updated_at': stamp}
    return receipt, 'private/publication-attempts/' + attempt + '.json'


def _save_attempt(run, receipt, relative):
    receipt['updated_at'] = now()
    atomic_bytes(run.file(relative), records().render_receipt(receipt), limit=records().MAX_RECEIPT_BYTES)


def publish_reference(run, *, checkpoint=None):
    """No arbitrary path or build adapter. Checkpoint is a trusted test callback."""
    snapshot = final = receipt = None
    relative = None
    directory = None
    reserved = False
    destination_check = None
    committed = False
    deadline = time.monotonic() + MAX_SECONDS
    try:
        _linux()
        with run.locked() as guard:
            _scope(run, guard)
            receipt, relative = _attempt(run)
            _save_attempt(run, receipt, relative)
            def point(event, **detail):
                require(event in CHECKPOINTS, 'publication_checkpoint_invalid')
                if checkpoint is not None:
                    checkpoint(event, {'run_id': run.id, 'attempt_id': receipt['attempt_id'],
                                       'release_id': receipt['release_id'], **detail})
                if destination_check is not None:
                    destination_check()
                _remaining(deadline)
            try:
                with _root_locked() as (root, check):
                    snapshot = _snapshot(run, guard, deadline)
                    receipt['platform'] = snapshot['platform']
                    check()
                    try:
                        os.mkdir(receipt['release_id'], 0o700, dir_fd=root)
                    except FileExistsError:
                        raise PublicationError('publication_duplicate', 'The exact destination already exists; complete and incomplete releases are never overwritten.') from None
                    reserved = True
                    _sync(root)
                    directory = os.open(receipt['release_id'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                    _directory_info(os.fstat(directory), private=True)
                    destination_identity = os.fstat(directory).st_dev, os.fstat(directory).st_ino
                    def check_destination():
                        check()
                        named = os.stat(receipt['release_id'], dir_fd=root, follow_symlinks=False)
                        _directory_info(named, private=True)
                        require((named.st_dev, named.st_ino) == destination_identity and
                                (os.fstat(directory).st_dev, os.fstat(directory).st_ino) == destination_identity,
                                'publication_destination_changed')
                    destination_check = check_destination
                    point('reserved')
                    for index, name in enumerate(records().artifact_paths(snapshot['platform']), 1):
                        parent = _parent_at(directory, name, create=True)
                        try:
                            if name == 'REFERENCE.txt':
                                _write_new(parent, name.split('/')[-1], records().REFERENCE_BYTES)
                            else:
                                output = os.open(name.split('/')[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                 0o600, dir_fd=parent)
                                try:
                                    _regular(os.fstat(output), exact_mode=0o600)
                                    snapshot['sources'][name].copy(output)
                                    _sync(output)
                                finally:
                                    os.close(output)
                            _sync(parent)
                        finally:
                            os.close(parent)
                        point('file-copied', path=name, copied_files=index)
                    checksums_raw = records().render_checksums(snapshot['checksums'])
                    _write_new(directory, 'checksums.json', checksums_raw)
                    _sync(directory)
                    expected = deepcopy(snapshot['checksums']['files'])
                    expected['checksums.json'] = {'sha256': digest(checksums_raw), 'size_bytes': len(checksums_raw)}
                    _tree(directory, expected, deadline)
                    proof = probe_private_visibility(RELEASE_ROOT / receipt['release_id'])
                    atomic_json(run.file('private/publication-visibility-' + receipt['attempt_id'] + '.json'), proof)
                    point('before-complete')
                    final = _snapshot(run, guard, deadline)
                    require(all(records().canonical(final[key]) == records().canonical(snapshot[key])
                                for key in ('platform', 'candidate', 'gate', 'checksums')), 'publication_source_changed')
                    for source in snapshot['sources'].values():
                        source.verify()
                    _tree(directory, expected, deadline)
                    check_destination()
                    _scope(run, guard)
                    completion = {**common(run.manifest()), **{key: value['const'] for key, value in records().FLAGS.items()},
                        'operation': records().COMPLETE_OPERATION, 'platform': snapshot['platform'], 'profile': 'smoke',
                        'release_id': receipt['release_id'], 'synthetic_assessment': True,
                        'candidate': snapshot['candidate'], 'gate': final['gate'], 'files': snapshot['checksums']['files'],
                        'checksums_sha256': digest(checksums_raw), 'created_at': now(),
                        'visibility': {'kind': 'private-posix', 'owner_uid': proof['owner_uid'], 'owner_gid': proof['owner_gid'],
                            'directory_mode': '0700', 'file_mode': '0600', 'owner_readable': True, 'unprivileged_denied': True,
                            'probe_uid': proof['probe_uid'], 'probe_gid': proof['probe_gid']}}
                    complete_raw = records().render_completion(completion, snapshot['checksums'])
                    _write_new(directory, '.COMPLETE.pending', complete_raw)
                    _sync(directory)
                    _remaining(deadline)
                    os.link('.COMPLETE.pending', 'COMPLETE.json', src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                    point('marker-linked')
                    _sync(directory)
                    os.unlink('.COMPLETE.pending', dir_fd=directory)
                    expected['COMPLETE.json'] = {'sha256': digest(complete_raw), 'size_bytes': len(complete_raw)}
                    _tree(directory, expected, deadline)
                    check_destination()
                    _remaining(deadline)
                    # This closed, single-link tree is logically complete now.
                    # A subsequent fsync failure must not erase that observed
                    # fact or claim durability was acknowledged.
                    committed = True
                    receipt.update(logical_complete=True, completion_sha256=digest(complete_raw))
                    _sync(directory)
                    point('committed-before-receipt')
                    receipt.update(status='completed', durability_acknowledged=True)
                    _save_attempt(run, receipt, relative)
                    _remaining(deadline)
                    return deepcopy(receipt)
            except BaseException as error:
                code = safe_code(error)
                receipt.update(status='failed' if reserved else 'refused', error_code=code,
                               durability_acknowledged=False, logical_complete=committed)
                if not committed:
                    receipt['completion_sha256'] = None
                try:
                    _save_attempt(run, receipt, relative)
                except BaseException:
                    pass  # The original error stays primary; no receipt success is implied.
                raise
    except BaseException as error:
        if not isinstance(error, RunError):
            error = PublicationError(safe_code(error), 'Publication did not acknowledge completion; preserve the destination and Run.')
        error.run_id = run.id
        error.attempt_id = None if receipt is None else receipt['attempt_id']
        error.receipt = relative
        raise error from None
    finally:
        if directory is not None:
            os.close(directory)
        _close(snapshot)
        _close(final)


def _verify_completion(run, guard, directory, completion_raw, deadline):
    value = json.loads(completion_raw)
    checksums_raw = _read_at(directory, 'checksums.json', records().MAX_RECORD_BYTES)
    checksums = records().validate_checksums(json.loads(checksums_raw))
    completion = records().validate_completion(value, checksums)
    require(completion_raw == records().render_completion(completion, checksums) and
            checksums_raw == records().render_checksums(checksums) and
            records().canonical(common(completion)) == records().canonical(common(run.manifest())),
            'publication_completion_changed')
    snapshot = _snapshot(run, guard, deadline)
    try:
        require(records().canonical(completion['candidate']) == records().canonical(snapshot['candidate']) and
                records().canonical(completion['gate']) == records().canonical(snapshot['gate']) and
                records().canonical(checksums) == records().canonical(snapshot['checksums']), 'publication_source_changed')
        expected = deepcopy(checksums['files'])
        expected.update({'checksums.json': {'sha256': digest(checksums_raw), 'size_bytes': len(checksums_raw)},
                         'COMPLETE.json': {'sha256': digest(completion_raw), 'size_bytes': len(completion_raw)}})
        _tree(directory, expected, deadline)
        return completion
    finally:
        _close(snapshot)


def inspect_publication(identifier):
    """Read-only logical verification, with original replay and no durability inference."""
    _linux()
    identifier = run_id(identifier)
    run = Run(images.RUNS_ROOT, identifier)
    deadline = time.monotonic() + MAX_SECONDS
    with run.locked() as guard:
        manifest = _scope(run, guard)
        result = {**common(manifest), 'operation': 'reference-publication-inspection-v1',
                  'release_id': 'reference-' + identifier, 'status': 'absent', 'logical_complete': False,
                  'completion_sha256': None, 'completion': None, 'reason_code': None,
                  'historical_durability': 'not-inferred', 'simulation': True,
                  'production_eligible': False, 'production_iso_eligible': False,
                  'image_published': False, 'remote_release': False}
        with _root_locked() as (root, check):
            try:
                directory = os.open(result['release_id'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            except FileNotFoundError:
                return result
            try:
                result.update(status='incomplete', reason_code='publication_incomplete')
                _directory_info(os.fstat(directory), private=True)
                if '.COMPLETE.pending' in os.listdir(directory) or 'COMPLETE.json' not in os.listdir(directory):
                    return result
                try:
                    raw = _read_at(directory, 'COMPLETE.json', records().MAX_RECORD_BYTES)
                    completion = _verify_completion(run, guard, directory, raw, deadline)
                    check()
                    named = os.stat(result['release_id'], dir_fd=root, follow_symlinks=False)
                    require((named.st_dev, named.st_ino) == (os.fstat(directory).st_dev, os.fstat(directory).st_ino),
                            'publication_destination_changed')
                    _remaining(deadline)
                except (RunError, OSError, ValueError, KeyError, TypeError) as error:
                    result['reason_code'] = safe_code(error)
                    return result
                result.update(status='complete', logical_complete=True, completion=completion,
                              completion_sha256=digest(raw), reason_code=None)
                return result
            finally:
                os.close(directory)
