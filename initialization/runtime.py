"""Fixed owned-container initialization observations and bounded fault fixtures.

This file has no host operator interface. Mutations are confined to target tmpfs;
an account-missing case selects a deliberately absent final identity. It does
not remove a host or image account or emulate a successful OS installation.
"""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from uuid import UUID

SCENARIOS = ('healthy', 'initialization-command-fails', 'account-missing', 'home-inaccessible',
    'authorized-key-missing', 'hardening-breaks-home', 'installation-source-missing', 'observer-lost')
FIELDS = ('runtime_ready', 'final_account', 'home_usable', 'authorized_key', 'configuration_complete')


def as_final_user(action):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([]); os.setgid(10001); os.setuid(10001)
            os._exit(0 if action() else 1)
        except BaseException: os._exit(2)
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status) == 0


def tmpfs_home():
    rows = Path('/proc/self/mountinfo').read_text().splitlines()
    return any(row.split()[4] == '/home/wormhole' and row.split(' - ', 1)[1].split()[0] == 'tmpfs'
        for row in rows if ' - ' in row)


def execute(scenario, mutable_home):
    import pwd
    identifier = os.environ.get('WORMHOLE_RUN_ID', '')
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0 or str(UUID(identifier)) != identifier or
        scenario not in SCENARIOS or Path('/var/run/docker.sock').exists() or Path('/run/docker.sock').exists()):
        raise ValueError('owned target runtime required')
    signal.alarm(10)
    if scenario == 'observer-lost': time.sleep(2)
    result = {'schema_version': '1.0', 'operation': 'container-initialization-v1', 'run_id': identifier,
        'scenario': scenario, 'status': 'pending', 'stage': 'initialization', 'category': None,
        'command_returncode': None, 'checks': dict.fromkeys(FIELDS, False), 'events': ['initialization-started'],
        'simulated_installation': scenario == 'installation-source-missing', 'production_iso_eligible': False}
    if scenario == 'initialization-command-fails':
        command = subprocess.run([sys.executable, '-I', '-S', '-c', 'raise SystemExit(23)'],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        result.update(status='failed', category='initialization_command_failed', command_returncode=command.returncode)
        return result
    if scenario == 'installation-source-missing':
        result.update(status='failed', category='simulated_installation_source_missing')
        return result
    runtime = Path('/run/wormhole')
    key = runtime / 'auth/authorized_keys'
    result['checks']['runtime_ready'] = (runtime / 'hostkeys/ssh_host_ed25519_key.pub').is_file() and Path('/run/sshd').is_dir()
    if not result['checks']['runtime_ready']: return result
    result['events'].extend(['initialization-complete', 'configuration-started'])
    result['stage'] = 'configuration'
    try:
        account = pwd.getpwnam('wormhole-nonexistent' if scenario == 'account-missing' else 'wormhole')
        result['checks']['final_account'] = account.pw_uid == 10001 and account.pw_shell == '/bin/sh'
    except KeyError: pass
    if scenario in {'home-inaccessible', 'hardening-breaks-home'}:
        if not mutable_home or not tmpfs_home(): raise ValueError('the bounded mutable-home fixture is required')
        # The directory owner changes only this target's dedicated 4MiB tmpfs.
        if not as_final_user(lambda: os.chmod('/home/wormhole', 0) is None):
            raise ValueError('controlled home permission change did not finish')
        if scenario == 'hardening-breaks-home':
            result['stage'] = 'hardening'; result['events'].append('hardening-applied')
    if scenario == 'authorized-key-missing':
        if key.is_symlink(): raise ValueError('linked runtime key refused')
        key.unlink(missing_ok=True)
    result['checks']['home_usable'] = as_final_user(lambda: os.access('/home/wormhole', os.R_OK | os.X_OK))
    result['checks']['authorized_key'] = key.is_file() and as_final_user(lambda: os.access(key, os.R_OK))
    failures = (('final_account', 'final_account_missing'), ('home_usable', 'final_home_inaccessible'),
                ('authorized_key', 'authorized_key_missing'))
    for check, category in failures:
        if not result['checks'][check]:
            result.update(status='failed', category=category)
            return result
    result['checks']['configuration_complete'] = True
    result['events'].append('configuration-complete'); result['status'] = 'passed'
    return result


def main(arguments=None):
    args = sys.argv[1:] if arguments is None else arguments
    try:
        if len(args) != 3 or args[1] not in {'true', 'false'} or not args[2].isdigit() or not 0 <= int(args[2]) < 80:
            raise ValueError('fixed request required')
        result = execute(args[0], args[1] == 'true')
        directory = Path('/run/wormhole/initialization')
        if any(path.is_symlink() for path in (directory, *directory.parents)): raise ValueError('linked journal refused')
        directory.mkdir(mode=0o700, exist_ok=True)
        destination = directory / (args[2] + '.json')
        temporary = destination.with_suffix('.partial')
        if destination.exists(): raise ValueError('terminal record already exists')
        with temporary.open('x', encoding='utf-8') as output:
            os.chmod(temporary, 0o600)
            json.dump(result, output, sort_keys=True); output.flush(); os.fsync(output.fileno())
        os.replace(temporary,destination)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['status'] != 'failed' else result['command_returncode'] or 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({'error': 'container_initialization_refused'})); return 2


if __name__ == '__main__': raise SystemExit(main())
