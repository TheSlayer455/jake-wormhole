"""Fixed, read-only UBI facts collector. Runs only in the capped probe container.

No repository loading, package downloads, transactions or signature approval.
"""
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

SECONDS = 45
MAX_OUTPUT = 49152
MAX_PACKAGES = 1024
RELEASE = Path('/run/wormhole-rpm-probe.start')
KEYS = ('/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release',)
LICENSES = ('/usr/share/doc/redhat-release/EULA', '/usr/share/licenses/redhat-release/EULA',
            '/usr/share/licenses/ubi9-release/EULA', '/etc/redhat-release', '/etc/system-release-cpe')
EXECUTABLES = ('/usr/bin/python3', '/usr/libexec/platform-python', '/usr/bin/rpm', '/usr/bin/dnf',
               '/usr/sbin/sshd', '/usr/bin/ssh-keygen', '/usr/sbin/useradd', '/usr/bin/getent')


def require(value):
    if not value:
        raise ValueError('fixed_probe_invalid')


def deadline(seconds=SECONDS):
    require(type(seconds) is int and 1 <= seconds <= SECONDS)
    def expired(signum, frame):
        raise TimeoutError('fixed_probe_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)  # Explicit handler also applies when this process is PID1.


def text(value, maximum=160):
    require(type(value) is str and 0 < len(value) <= maximum and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def file_bytes(path, maximum=65536):
    path = Path(path)
    require(path.is_file() and path.stat().st_size <= maximum)
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    require(len(value) <= maximum)
    return value


def fingerprints(raw):
    """Compute v4 OpenPGP primary fingerprints; this is NOT signature verification."""
    blocks = re.findall(rb'-----BEGIN PGP PUBLIC KEY BLOCK-----\s+(.*?)-----END PGP PUBLIC KEY BLOCK-----', raw, re.S)
    require(1 <= len(blocks) <= 8)
    result = []
    for block in blocks:
        lines = [line.strip() for line in block.splitlines()]
        encoded = b''.join(line for line in lines if line and b':' not in line and not line.startswith(b'='))
        binary = base64.b64decode(encoded, validate=True)
        offset = 0
        while offset < len(binary):
            first = binary[offset]; offset += 1
            require(first & 128)
            if first & 64:
                tag = first & 63; require(offset < len(binary))
                length = binary[offset]; offset += 1
                if 192 <= length <= 223:
                    require(offset < len(binary)); length = ((length - 192) << 8) + binary[offset] + 192; offset += 1
                elif length == 255:
                    require(offset + 4 <= len(binary)); length = int.from_bytes(binary[offset:offset+4], 'big'); offset += 4
                else:
                    require(length < 192)  # Partial packet lengths are unnecessary for these fixed key files.
            else:
                tag = (first >> 2) & 15; count = (1, 2, 4, 0)[first & 3]
                require(count and offset + count <= len(binary))
                length = int.from_bytes(binary[offset:offset+count], 'big'); offset += count
            require(0 < length <= 65535 and offset + length <= len(binary))
            packet = binary[offset:offset+length]; offset += length
            if tag == 6:
                require(packet[0] == 4)
                result.append(hashlib.sha1(b'\x99' + length.to_bytes(2, 'big') + packet).hexdigest().upper())
    require(1 <= len(result) <= 8 and len(result) == len(set(result)))
    return sorted(result)


def os_release():
    values = {}
    for line in file_bytes('/etc/os-release').decode('utf-8').splitlines():
        if '=' not in line or line.startswith('#'):
            continue
        key, value = line.split('=', 1)
        if key in ('ID', 'VERSION_ID', 'NAME', 'PRETTY_NAME', 'CPE_NAME', 'PLATFORM_ID'):
            require(key not in values)
            # Data parsing only; never source this file as shell input.
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'": value = value[1:-1]
            values[key] = text(value, 256)
    require('ID' in values and 'VERSION_ID' in values)
    return values


def packages(rpm):
    result = []
    transaction = rpm.TransactionSet('/')
    try:
        for header in transaction.dbMatch():
            require(len(result) < MAX_PACKAGES)
            epoch = header['epoch']
            require(epoch is None or type(epoch) is int and 0 <= epoch <= 2**31-1)
            name = text(header['name']); arch = header['arch']
            require(arch is None and name == 'gpg-pubkey' or type(arch) is str)
            result.append({'name': name, 'epoch': 0 if epoch is None else epoch,
                'version': text(header['version']), 'release': text(header['release']), 'arch': None if arch is None else text(arch)})
    finally:
        transaction.closeDB()
    require(result)
    result.sort(key=lambda row: (row['name'], row['epoch'], row['version'], row['release'], row['arch'] or ''))
    require(len({tuple(row.values()) for row in result}) == len(result))
    return result


def collect():
    rpm = importlib.import_module('rpm')
    installed = packages(rpm)
    try:
        dnf = importlib.import_module('dnf')
        # Do not call read_all_repos, fill_sack, resolve, download or do_transaction.
        base = dnf.Base()
        try:
            base.conf.cachedir = '/tmp/wormhole-rpm-cache'; base.conf.persistdir = '/tmp/wormhole-rpm-persist'
            base.conf.logdir = '/tmp'; base.conf.plugins = False; base.conf.install_weak_deps = False
            dnf_record = {'available': True, 'version': text(dnf.__version__),
                'base_api': callable(base.resolve) and callable(base.fill_sack), 'repos_loaded': False, 'transaction_run': False}
        finally:
            base.close()
    except ImportError:
        dnf_record = {'available': False, 'version': None, 'base_api': False, 'repos_loaded': False, 'transaction_run': False}
    keys = []
    for path in KEYS:
        if Path(path).is_file():
            raw = file_bytes(path)
            keys.append({'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'primary_fingerprints': fingerprints(raw), 'signature_verification': 'not-performed'})
    licenses = []
    for path in LICENSES:
        if Path(path).is_file():
            raw = file_bytes(path)
            licenses.append({'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    return {'schema_version': '1.0', 'operation': 'ubi-base-observation-v1', 'status': 'observed',
        'run_id': os.environ['WORMHOLE_RUN_ID'], 'source_revision': os.environ['WORMHOLE_SOURCE_REVISION'],
        'probe_sha256': hashlib.sha256(file_bytes(__file__, 32768)).hexdigest(),
        'os_release': os_release(), 'installed_packages': installed,
        'python': {'version': sys.version.split()[0], 'executable': sys.executable},
        'rpm': {'version': text(rpm.__version__)}, 'dnf': dnf_record,
        'key_files': keys, 'license_files': licenses,
        'executables': {path: os.path.isfile(path) and os.access(path, os.X_OK) for path in EXECUTABLES},
        'execution': {'uid': os.getuid(), 'gid': os.getgid(), 'pid': os.getpid()},
        'shared_kernel_release': text(os.uname().release),
        'packages_installed': False, 'production_iso_eligible': False}


def main():
    emitted = False
    try:
        require(sys.platform.startswith('linux') and os.getuid() == 0 and os.getpid() == 1 and
            os.environ.get('WORMHOLE_ROLE') == 'rpm-base-probe' and
            re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', os.environ.get('WORMHOLE_RUN_ID', '')) and
            re.fullmatch(r'[a-f0-9]{40}', os.environ.get('WORMHOLE_SOURCE_REVISION', '')))
        deadline()
        def stopped(signum, frame): raise SystemExit(0)
        signal.signal(signal.SIGTERM, stopped)
        waiting = time.monotonic() + 15
        while not RELEASE.exists():
            require(time.monotonic() < waiting)
            time.sleep(.02)
        require(file_bytes(RELEASE, 2) == b'1\n')
        value = collect()
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        require(len(raw) <= MAX_OUTPUT)
        sys.stdout.buffer.write(raw + b'\n'); sys.stdout.buffer.flush(); emitted = True
        while True: time.sleep(.2)  # Parent copies bounded stdout then stops this exact container.
    except TimeoutError:
        return 0 if emitted else 124
    except Exception:
        if not emitted: print('{"status":"failed","code":"rpm_base_probe_failed"}', flush=True)
        return 1
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    raise SystemExit(main())
