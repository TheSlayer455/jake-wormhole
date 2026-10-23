"""Fixed Terraform operations inside the separately capped trusted provisioner.

No caller supplies executable paths, Terraform flags, arbitrary URLs or commands.
Outputs/state remain private in the one explicit host bind; stdout is a receipt.
"""
import hashlib
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

STATE = Path('/state')
TOOL = '/opt/toolchain/bin/terraform'
JSON_LIMIT = 4 * 1024 * 1024
LOG_LIMIT = 65536
OPERATION_TIMEOUT = 120
OPERATIONS = {
    'probe-unavailable': (),
    'version': ('version', '-json'),
    'init': ('init', '-input=false', '-no-color', '-lockfile=readonly', '-get=false'),
    'schema': ('providers', 'schema', '-json'),
    'plan': ('plan', '-input=false', '-no-color', '-lock-timeout=0s', '-out=apply.tfplan'),
    'show-plan': ('show', '-json', 'apply.tfplan'),
    'apply': ('apply', '-input=false', '-no-color', '-lock-timeout=0s', 'apply.tfplan'),
    'show-state': ('show', '-json'),
    'refresh-plan': ('plan', '-refresh-only', '-input=false', '-no-color', '-lock-timeout=0s', '-out=refresh.tfplan'),
    'show-refresh-plan': ('show', '-json', 'refresh.tfplan'),
    'refresh-apply': ('apply', '-input=false', '-no-color', '-lock-timeout=0s', 'refresh.tfplan'),
    'output': ('output', '-json'),
    'destroy-plan': ('plan', '-destroy', '-input=false', '-no-color', '-lock-timeout=0s', '-out=destroy.tfplan'),
    'show-destroy-plan': ('show', '-json', 'destroy.tfplan'),
    'destroy': ('apply', '-input=false', '-no-color', '-lock-timeout=0s', 'destroy.tfplan'),
    'final-state': ('show', '-json'),
}
JSON_OPERATIONS = {'version', 'schema', 'show-plan', 'show-state', 'show-refresh-plan',
                   'output', 'show-destroy-plan', 'final-state', 'probe-unavailable'}
UNAVAILABLE_PATH = '/run/wormhole/provider-unavailable.sock'


def probe_unavailable():
    """One fixed local endpoint; no caller-provided path, DNS or TCP request."""
    def absent():
        try: os.lstat(UNAVAILABLE_PATH)
        except FileNotFoundError: return
        raise ValueError('The fixed unavailable endpoint must not exist')
    absent()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        try: client.connect(UNAVAILABLE_PATH)
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise ValueError('The fixed endpoint did not return ENOENT') from None
        else:
            raise ValueError('The fixed endpoint unexpectedly accepted a connection')
    absent()
    return {'endpoint': 'unix://' + UNAVAILABLE_PATH, 'path_absent': True, 'connect_errno': 'ENOENT'}


def environment():
    return {'PATH': '/usr/bin:/bin', 'HOME': '/run/wormhole/home', 'TMPDIR': '/tmp',
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TF_CLI_CONFIG_FILE': '/state/wormhole.tfrc',
            'TF_DATA_DIR': '/state/.terraform', 'TF_INPUT': '0', 'TF_IN_AUTOMATION': '1',
            'CHECKPOINT_DISABLE': '1'}


def guard():
    if not Path('/.dockerenv').is_file() or os.environ.get('WORMHOLE_ROLE') != 'provisioner' or \
            not STATE.is_dir() or not Path('/var/run/docker.sock').is_socket():
        raise ValueError('Fixed provisioner execution location required')
    Path('/run/wormhole/home').mkdir(mode=0o700, parents=True, exist_ok=True)


def operation(name, attempt):
    if name not in OPERATIONS or type(attempt) is not int or not 1 <= attempt <= 4:
        raise ValueError('Unsupported fixed operation')
    folder = STATE / 'operations'
    folder.mkdir(mode=0o700, exist_ok=True)
    if folder.is_symlink():
        raise ValueError('Linked output refused')
    stem = folder / (name + '-' + str(attempt))
    output = stem.with_suffix('.out')
    receipt = stem.with_suffix('.json')
    if receipt.exists() or receipt.is_symlink():
        raise ValueError('Operation attempts cannot be overwritten')
    limit = JSON_LIMIT if name in JSON_OPERATIONS else LOG_LIMIT
    started = time.monotonic()
    process = None
    size, truncated, timed_out = 0, False, False
    digest = hashlib.sha256()
    # O_EXCL prevents following or replacing any preexisting output file.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            command = [sys.executable, str(Path(__file__).resolve()), 'probe-unavailable-internal'] if name == 'probe-unavailable' else \
                [TOOL, '-chdir=/state', *OPERATIONS[name]]
            process = subprocess.Popen(command, cwd=STATE,
                env=environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True, close_fds=True, bufsize=0)
            os.set_blocking(process.stdout.fileno(), False)
            deadline = started + OPERATION_TIMEOUT
            while True:
                try:
                    chunk = os.read(process.stdout.fileno(), 65536)
                except BlockingIOError:
                    chunk = None
                if chunk:
                    size += len(chunk)
                    if size <= limit:
                        stream.write(chunk); digest.update(chunk)
                    else:
                        truncated = True
                        break
                if chunk == b'' and process.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                if not chunk:
                    time.sleep(.01)
            if timed_out or truncated:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            process.wait(timeout=5)
            # Also reap an adapter child that inherited stdout after the parent exited.
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            stream.flush(); os.fsync(stream.fileno())
    finally:
        if process is not None:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=5)
            process.stdout.close()
    value = {'operation': name, 'attempt': attempt, 'returncode': process.returncode,
             'duration_seconds': time.monotonic() - started, 'output_bytes': output.stat().st_size,
             'output_sha256': digest.hexdigest(), 'truncated': truncated, 'timed_out': timed_out,
             'passed': process.returncode == 0 and not truncated and not timed_out}
    descriptor = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps(value), flush=True)
    return 0 if value['passed'] else 2


def main(arguments=None):
    args = sys.argv[1:] if arguments is None else arguments
    try:
        os.umask(0o077)
        guard()
        if args == ['probe-unavailable-internal']:
            print(json.dumps(probe_unavailable()), flush=True)
            return 0
        if args == ['serve']:
            if os.getpid() != 1:
                raise ValueError('Serve requires container PID1')
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
            signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                time.sleep(min(.1, max(0, deadline - time.monotonic())))
            return 124
        if len(args) != 2 or not args[1].isascii() or not args[1].isdigit():
            raise ValueError('Fixed operation and bounded attempt required')
        return operation(args[0], int(args[1]))
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({'error': {'code': 'provisioner_runtime_refused',
              'message': 'Fixed operation, private state or execution boundary failed; preserve private outputs.'}}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
