"""Fixed Docker-free helper probes. No target exec, local connection or repair."""
import importlib.util
import base64
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path('/run/wormhole/readiness')
IMAGE_RUNTIME = Path('/opt/wormhole/runtime.py')
MAX_LOG = 8192
OPERATIONS = ('tcp', 'ssh', 'python', 'ansible-wait', 'ansible-ping')
SCENARIOS = ('healthy', 'wrong-key', 'wrong-user', 'configured-interpreter-unavailable')


def require(value):
    if not value:
        raise ValueError('Fixed readiness request refused')


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def request(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= 8192)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    fields = {'schema_version', 'run_id', 'source_revision', 'target_id', 'address', 'operation', 'attempt', 'scenario', 'timeout_seconds'}
    batch = type(value) is dict and value.get('resource_layout') == 'indexed-targets-v1'
    twenty = batch and 'target_plan' in value
    if twenty:
        expected = {'schema_version': '1.0', 'resource_layout': 'indexed-targets-v1', 'profile': 'twenty-targets',
            'target_count': 20, 'target_ids': ['target-' + str(i).zfill(3) for i in range(1, 21)]}
        require(type(value['target_plan']) is dict and type(value['target_plan'].get('target_count')) is int and value['target_plan'] == expected)
    require(type(value) is dict and set(value) == fields | ({'resource_layout'} if batch else set()) | ({'target_plan'} if twenty else set()))
    from uuid import UUID
    require(value['schema_version'] == '1.0' and type(value['run_id']) is str and str(UUID(value['run_id'])) == value['run_id'] and
        type(value['source_revision']) is str and re.fullmatch('[a-f0-9]{40}', value['source_revision']) and
        value['target_id'] in (tuple('target-' + str(i).zfill(3) for i in range(1, 21 if twenty else 6)) if batch else ('target-001',)) and
        value['operation'] in OPERATIONS and value['scenario'] in SCENARIOS and
        type(value['attempt']) is int and 1 <= value['attempt'] <= 64 and
        type(value['timeout_seconds']) in (int, float) and 0.1 <= value['timeout_seconds'] <= 30)
    address = ipaddress.ip_address(value['address'])
    require(address.version == 4 and not any((address.is_loopback, address.is_unspecified, address.is_multicast,
                                            address.is_link_local, address.is_reserved)))
    require(str(address) == value['address'])
    return value


def qualified_runtime():
    spec = importlib.util.spec_from_file_location('qualified_image_runtime', IMAGE_RUNTIME)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.guard('helper')
    module.identity()
    return module


def prepare_auth(module, value):
    require(module.identity() == value['run_id'])
    require(not any(path.is_symlink() for path in (ROOT, *ROOT.parents)))
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = ROOT.stat()
    require(info.st_uid == 10001 and stat.S_IMODE(info.st_mode) == 0o700)
    for name, private in (('id_ed25519', True), ('known_hosts', False)):
        raw = module.bounded_input(module.INPUT / name, private=private)
        destination = ROOT / name
        if destination.exists() or destination.is_symlink():
            require(module.bounded_input(destination, private=True) == raw)
        else:
            module.write_private(destination, raw)
    if value['scenario'] == 'wrong-key':
        wrong = ROOT / 'wrong_key'
        if not wrong.exists():
            result = capture(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'readiness-negative', '-f', str(wrong)], 5,
                             {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT), 'LC_ALL': 'C'})
            require(result['returncode'] == 0 and not result['timed_out'] and not result['truncated'])
        module.bounded_input(wrong, private=True)


def capture(arguments, timeout, environment):
    """Absolute child/pipe deadline and bounded memory on the supported Linux host."""
    began = time.monotonic()
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=environment, cwd=ROOT, start_new_session=True, bufsize=0)
    os.set_blocking(process.stdout.fileno(), False)
    output, eof, expired, truncated = bytearray(), False, False, False
    try:
        while True:
            try:
                chunk = os.read(process.stdout.fileno(), 65536)
                if chunk:
                    room = MAX_LOG - len(output)
                    output.extend(chunk[:room])
                    if len(chunk) > room:
                        truncated = True
                        break
                else:
                    eof = True
            except BlockingIOError:
                pass
            if time.monotonic() >= began + timeout:
                expired = True
                break
            if eof and process.poll() is not None:
                break
            time.sleep(0.01)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        process.stdout.close()
    return {'returncode': process.returncode, 'timed_out': expired, 'truncated': truncated,
            'log': output.decode('utf-8', errors='replace'), 'duration_seconds': time.monotonic() - began}


def environment():
    return {'PATH': '/opt/wormhole/venv/bin:/usr/bin:/bin', 'HOME': str(ROOT), 'TMPDIR': '/tmp', 'LC_ALL': 'C.UTF-8',
        'ANSIBLE_CONFIG': str(ROOT / 'ansible.cfg'), 'ANSIBLE_LOCAL_TEMP': str(ROOT / 'ansible-local'),
        'ANSIBLE_REMOTE_TEMP': '/tmp/wormhole-ansible', 'ANSIBLE_HOST_KEY_CHECKING': 'True',
        'ANSIBLE_NOCOLOR': '1', 'ANSIBLE_SSH_PASSWORD_MECHANISM': 'disable'}


def ssh_options(value, *, root=None):
    root = ROOT if root is None else root
    key = root / ('wrong_key' if value['scenario'] == 'wrong-key' else 'id_ed25519')
    return ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(root / 'known_hosts'),
        '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no', '-o', 'ForwardAgent=no',
        '-o', 'ClearAllForwardings=yes', '-o', 'ControlMaster=no', '-o', 'ControlPersist=no',
        '-o', 'ConnectTimeout=3', '-o', 'ConnectionAttempts=1', '-i', str(key), '-p', '2222']


def classify(value, result):
    if result['truncated']:
        return 'output_bound'
    if result['timed_out']:
        return 'probe_timeout'
    if result['returncode'] == 0:
        return None
    log = result['log']
    if 'Host key verification failed' in log or 'REMOTE HOST IDENTIFICATION HAS CHANGED' in log:
        return 'ssh_host_key_mismatch'
    if 'Permission denied' in log:
        return 'ssh_key_rejected' if value['scenario'] == 'wrong-key' else 'ssh_user_rejected' if value['scenario'] == 'wrong-user' else 'ssh_authentication_refused'
    if value['operation'] == 'python' and result['returncode'] == 1:
        return 'configured_interpreter_unavailable'
    if any(x in log for x in ('Connection refused', 'Connection timed out', 'No route to host', 'Connection closed', 'Connection reset')):
        return 'ssh_transport_pending'
    return 'ansible_unusable' if value['operation'].startswith('ansible-') else 'ssh_probe_failed'


def ansible(value, attempt):
    target_id = value['target_id']
    user = 'wormhole-nonexistent' if value['scenario'] == 'wrong-user' else 'wormhole'
    interpreter = '/run/wormhole/no-such-python' if value['scenario'] == 'configured-interpreter-unavailable' else '/usr/bin/python3'
    # Exact inventory and fixed SSH arguments; no imported vars/plugins/connection overrides.
    import shlex
    variables = {'ansible_host': value['address'], 'ansible_port': 2222, 'ansible_user': user,
        'ansible_connection': 'ssh', 'ansible_python_interpreter': interpreter,
        'ansible_ssh_args': shlex.join(ssh_options(value)), 'ansible_ssh_retries': 0,
        # Pinned2.21.5 ssh.py: use_tty defaults true (-tt); piped selects SSH/dd.
        # The target deliberately forbids TTY allocation. Do not weaken sshd.
        'ansible_ssh_use_tty': False, 'ansible_ssh_transfer_method': 'piped',
        'ansible_remote_tmp': '/tmp/wormhole-ansible'}
    inventory = attempt / 'inventory.json'
    inventory.write_text(json.dumps({'all': {'hosts': {target_id: variables}}}))
    inventory.chmod(0o600)
    module = 'ansible.builtin.wait_for_connection' if value['operation'] == 'ansible-wait' else 'ansible.builtin.ping'
    args = {'timeout': 15, 'connect_timeout': 3, 'sleep': 1} if value['operation'] == 'ansible-wait' else {}
    arguments = ['/opt/wormhole/venv/bin/ansible', '-i', str(inventory), target_id, '-m', module]
    # Pinned adhoc.py falls back from falsey decoded {} to raw-parameter parsing.
    # Ping has no arguments; omit -a instead of submitting the literal "{}".
    if args:
        arguments.extend(['-a', json.dumps(args)])
    arguments.extend(['--tree', str(attempt / 'results'), '--forks', '1', '--timeout', '3'])
    result = capture(arguments, value['timeout_seconds'], environment())
    path = attempt / 'results' / target_id
    observed = None
    if path.exists():
        require(not path.is_symlink() and path.is_file() and path.stat().st_nlink == 1 and path.stat().st_size <= 32768)
        with path.open('rb') as stream:
            raw = stream.read(32769)
        require(len(raw) <= 32768)
        observed = json.loads(raw, object_pairs_hook=unique)
    # CLI exit0 without the one expected target result cannot pass.
    allowed = {'changed', 'failed', 'unreachable', 'skipped'} | ({'ping'} if value['operation'] == 'ansible-ping' else {'elapsed'})
    # tree callback output may omit a failure flag. The pinned wait action puts
    # msg on timeout, never on success: reject unexpected/msg/exception records
    # as well as nonzero/incomplete captures, even if elapsed looks plausible.
    good = (result['returncode'] == 0 and result['timed_out'] is False and result['truncated'] is False and
        type(observed) is dict and set(observed) <= allowed and
        all(observed.get(key, False) is False for key in ('changed', 'failed', 'unreachable', 'skipped')))
    if value['operation'] == 'ansible-ping':
        good = good and observed.get('ping') == 'pong'
    else:
        good = good and type(observed.get('elapsed')) in (int, float) and math.isfinite(observed['elapsed']) and 0 <= observed['elapsed'] <= 60
    if result['returncode'] == 0 and not good:
        result['returncode'] = 2
    return result, {'structured_target_result': good, 'ping': 'pong' if good and value['operation'] == 'ansible-ping' else None}


def probe(value, module=None):
    global ROOT
    began = time.monotonic()
    module = qualified_runtime() if module is None else module
    require(module.identity() == value['run_id'])
    if value.get('resource_layout') == 'indexed-targets-v1':
        # One fixed probe process, never a global ROOT switch across threads.
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not ROOT.is_symlink() and ROOT.stat().st_uid == 10001 and stat.S_IMODE(ROOT.stat().st_mode) == 0o700)
        ROOT = ROOT / value['target_id']
        module.INPUT = module.INPUT / value['target_id']
    if value['operation'] == 'tcp':
        try:
            with socket.create_connection((value['address'], 2222), timeout=min(3, value['timeout_seconds'])):
                pass
            status, category = 'pass', None
        except (TimeoutError, OSError):
            status, category = 'fail', 'tcp_pending'
        result = {'returncode': 0 if status == 'pass' else 1, 'timed_out': False, 'truncated': False, 'log': ''}
        observed = {'tcp_connected': status == 'pass'}
    else:
        prepare_auth(module, value)
        value = {**value, 'timeout_seconds': value['timeout_seconds'] - (time.monotonic() - began)}
        require(value['timeout_seconds'] >= 0.1)
        attempt = ROOT / (value['operation'] + '-' + str(value['attempt']))
        attempt.mkdir(mode=0o700)  # No attempt overwrite or opaque replay.
        config = ROOT / 'ansible.cfg'
        raw_config = '[defaults]\nhost_key_checking = True\nretry_files_enabled = False\ninterpreter_python = /usr/bin/python3\n'
        if config.exists():
            require(config.is_file() and not config.is_symlink() and config.read_text() == raw_config)
        else:
            module.write_private(config, raw_config.encode())
        if value['operation'].startswith('ansible-'):
            result, observed = ansible(value, attempt)
        else:
            user = 'wormhole-nonexistent' if value['scenario'] == 'wrong-user' else 'wormhole'
            interpreter = '/run/wormhole/no-such-python' if value['scenario'] == 'configured-interpreter-unavailable' else '/usr/bin/python3'
            remote = '/usr/bin/id -u' if value['operation'] == 'ssh' else '/usr/bin/test -x ' + interpreter
            result = capture(['/usr/bin/ssh', *ssh_options(value), '--', user + '@' + value['address'], remote],
                             value['timeout_seconds'], environment())
            observed = {'uid': 10001 if value['operation'] == 'ssh' and result['log'].strip() == '10001' else None,
                        'configured_interpreter_usable': value['operation'] == 'python' and result['returncode'] == 0}
            if value['operation'] == 'ssh' and result['returncode'] == 0 and observed['uid'] != 10001:
                result['returncode'] = 2
        category = classify(value, result)
        status = 'pass' if category is None else 'fail'
    return {**{key: value[key] for key in ('schema_version', 'run_id', 'source_revision', 'target_id', 'operation', 'attempt')},
        'status': status, 'category': category, 'returncode': result['returncode'], 'timed_out': result['timed_out'],
        'truncated': result['truncated'], 'duration_seconds': time.monotonic() - began,
        'observation': observed, 'private_diagnostic': result['log']}


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 11000)
        value = request(base64.b64decode(sys.argv[1], validate=True))
        result = probe(value)
        print(json.dumps(result, sort_keys=True))
        return 0  # A complete failed probe is data, not a lost control-plane response.
    except Exception:
        print(json.dumps({'error': {'code': 'readiness_runtime_refused'}}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
