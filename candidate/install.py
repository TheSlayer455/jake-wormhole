"""Fixed offline installer, executed only in the admitted candidate builder."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time

INPUT = Path('/candidate-input')
OUTPUT = Path('/opt/wormhole/reference')
LIMIT = 8 * 1024 * 1024


def expired(*_):
    raise TimeoutError('Candidate installation deadline exceeded')


def enable_deadline(seconds=45):
    if type(seconds) is not int or not 1 <= seconds <= 45: raise ValueError('Installer deadline bound')
    # Linux PID1 ignores default-action signals; an explicit handler is required.
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)


def install_files():
    raw = (INPUT / 'manifest.json').read_bytes()
    if len(raw) > 16384: raise ValueError('Manifest bound')
    manifest = json.loads(raw)
    if set(os.listdir(INPUT)) != {'manifest.json', 'source.synthetic.bin', 'payload.py', 'version.txt', 'config.json'}:
        raise ValueError('Exact candidate file set required')
    OUTPUT.mkdir(mode=0o755)
    OUTPUT.chmod(0o755)  # Public synthetic target data, independent of private host umask.
    checked = []
    for item in manifest['files']:
        if item['path'] not in {'source.synthetic.bin', 'payload.py', 'version.txt', 'config.json'}:
            raise ValueError('Fixed candidate path required')
        source = INPUT / item['path']; info = source.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= LIMIT:
            raise ValueError('Ordinary bounded candidate input required')
        digest = hashlib.sha256(); size = 0
        descriptor = os.open(OUTPUT / item['path'], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
        os.fchmod(descriptor, 0o444)
        with source.open('rb') as incoming, os.fdopen(descriptor, 'wb') as outgoing:
            while chunk := incoming.read(65536):
                size += len(chunk)
                if size > LIMIT: raise ValueError('Candidate input bound')
                digest.update(chunk); outgoing.write(chunk)
            outgoing.flush(); os.fsync(outgoing.fileno())
        if (size, digest.hexdigest()) != (item['size'], item['sha256']): raise ValueError('Candidate changed')
        checked.append(item)
    if len(checked) != 4: raise ValueError('Exact candidate file count required')
    with (OUTPUT / 'manifest.json').open('xb') as stream: stream.write(raw)
    (OUTPUT / 'manifest.json').chmod(0o444)
    record = {'status': 'installed', 'candidate_sha256': hashlib.sha256(raw).hexdigest(), 'files': checked}
    return record


def main():
    enable_deadline()
    if not Path('/.dockerenv').is_file() or os.getuid() != 0 or Path('/etc/wormhole/role').read_text().strip() != 'target' or any(
        Path(path).exists() for path in ('/var/run/docker.sock', '/run/docker.sock')):
        raise ValueError('Fixed container builder required')
    record = install_files()
    with Path('/opt/wormhole/candidate-installed.json').open('x') as stream: json.dump(record, stream, sort_keys=True)
    # Leave a short observation window for the host to inspect actual cgroups.
    time.sleep(1)


if __name__ == '__main__': main()
