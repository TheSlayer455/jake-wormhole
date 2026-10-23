"""Fixed read-only functional collection through the qualified SSH Ansible helper."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import sys
import time
from uuid import UUID

READINESS = Path('/opt/readiness/runtime.py')
PACKAGES = ('ca-certificates', 'python3', 'python3.12', 'openssh-client', 'openssh-server', 'openssh-sftp-server')
SCENARIOS = ('healthy', 'version-expectation-mismatch', 'functional-expectation-mismatch',
             'configured-interpreter-unavailable', 'unexpected-skip', 'unreachable')
MAX_TREE = 65536

# Developer-authored fixed command, not a command supplied by a ticket or target.
# It reads only public OS/package/config/code data. No repairs or main entrypoint.
TARGET_PROGRAM = r'''import base64,hashlib,json,os,re,signal,stat,struct,subprocess,sys,time,types
from pathlib import Path
def read(path,maximum):
 p=Path(path); before=p.lstat()
 if not stat.S_ISREG(before.st_mode) or p.is_symlink() or before.st_nlink!=1 or before.st_size>maximum: raise ValueError('ordinary bounded input required')
 with p.open('rb') as stream: raw=stream.read(maximum+1)
 after=p.lstat()
 if len(raw)>maximum or (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size): raise ValueError('input changed')
 return raw
def packages():
 names=['ca-certificates','python3','python3.12','openssh-client','openssh-server','openssh-sftp-server']
 child=subprocess.Popen(['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\n',*names],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},start_new_session=True,bufsize=0)
 os.set_blocking(child.stdout.fileno(),False); raw=bytearray(); deadline=time.monotonic()+3; eof=False
 try:
  while True:
   try:
    chunk=os.read(child.stdout.fileno(),4096)
    if chunk: raw.extend(chunk)
    else: eof=True
   except BlockingIOError: pass
   if len(raw)>8192 or time.monotonic()>=deadline: raise ValueError('dpkg bound exceeded')
   if eof and child.poll() is not None: break
   time.sleep(.01)
  if child.returncode not in (0,1): raise ValueError('dpkg query failed')
 finally:
  try: os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError: pass
  child.wait(timeout=1);child.stdout.close()
 result={name:None for name in names}
 for line in raw.decode('utf-8').splitlines():
  name,version=line.split('\t'); name=name.split(':')[0]
  if name not in result or result[name] is not None or not 1<=len(version)<=240: raise ValueError('dpkg output invalid')
  result[name]=version
 return result
expected=sys.argv[1]
if not re.fullmatch('[a-f0-9]{64}',expected): raise ValueError('fixed payload hash required')
release={}
for line in read('/usr/lib/os-release',16384).decode().splitlines():
 if line.startswith(('ID=','VERSION_ID=')):
  key,value=line.split('=',1);release[key]=value.strip('"')
payload=read('/opt/wormhole/runtime.py',65536)
digest=hashlib.sha256(payload).hexdigest()
function={'status':'unverified','valid_normalized':None,'invalid_rejected':None}
if digest==expected:
 module=types.ModuleType('verified_baked_runtime')
 exec(compile(payload,'/opt/wormhole/runtime.py','exec'),module.__dict__)
 key='ssh-ed25519 '+base64.b64encode(struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes(range(32))).decode()
 valid=module.public_key(key+' synthetic-input')==key
 rejected=False
 try: module.public_key('command="false" '+key)
 except module.RuntimeFailure: rejected=True
 if hashlib.sha256(read('/opt/wormhole/runtime.py',65536)).hexdigest()!=digest: raise ValueError('payload changed')
 function={'status':'observed','valid_normalized':valid,'invalid_rejected':rejected}
print(json.dumps({'schema_version':'1.0','os':{'id':release.get('ID'),'version_id':release.get('VERSION_ID')},'packages':packages(),'sshd_config_sha256':hashlib.sha256(read('/etc/ssh/sshd_config',65536)).hexdigest(),'payload_sha256':digest,'function':function},sort_keys=True))
'''


def require(value):
    if not value:
        raise ValueError('Fixed validation request or result refused')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= 8192)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    fields = {'schema_version', 'run_id', 'source_revision', 'target_id', 'address', 'scenario', 'plan_sha256',
              'expected_payload_sha256', 'readiness_source_sha256', 'timeout_seconds'}
    require(type(value) is dict and set(value) == fields and value['schema_version'] == '1.0' and
        type(value['run_id']) is str and str(UUID(value['run_id'])) == value['run_id'] and
        type(value['source_revision']) is str and re.fullmatch('[a-f0-9]{40}', value['source_revision']) and
        value['target_id'] == 'target-001' and value['scenario'] in SCENARIOS and
        all(type(value[k]) is str and re.fullmatch('[a-f0-9]{64}', value[k]) for k in
            ('plan_sha256', 'expected_payload_sha256', 'readiness_source_sha256')) and
        type(value['timeout_seconds']) in (int, float) and math.isfinite(value['timeout_seconds']) and
        .1 <= value['timeout_seconds'] <= 40)
    address = ipaddress.ip_address(value['address'])
    require(address.version == 4 and str(address) == value['address'] and not any((address.is_loopback,
        address.is_unspecified, address.is_multicast, address.is_link_local, address.is_reserved)))
    return value


def readiness_runtime(expected):
    require(READINESS.is_file() and not READINESS.is_symlink() and READINESS.stat().st_size <= 65536)
    with READINESS.open('rb') as stream:
        raw = stream.read(65537)
    require(1 <= len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == expected)
    spec = importlib.util.spec_from_file_location('fixed_readiness_runtime', READINESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def observation(value):
    require(type(value) is dict and set(value) == {'schema_version', 'os', 'packages', 'sshd_config_sha256',
        'payload_sha256', 'function'} and value['schema_version'] == '1.0' and
        type(value['os']) is dict and set(value['os']) == {'id', 'version_id'} and
        all(type(x) is str and 1 <= len(x) <= 64 for x in value['os'].values()) and
        type(value['packages']) is dict and set(value['packages']) == set(PACKAGES) and
        all(x is None or type(x) is str and 1 <= len(x) <= 240 for x in value['packages'].values()) and
        all(type(value[k]) is str and re.fullmatch('[a-f0-9]{64}', value[k]) for k in ('sshd_config_sha256', 'payload_sha256')))
    function = value['function']
    require(type(function) is dict and set(function) == {'status', 'valid_normalized', 'invalid_rejected'} and
        ((function['status'] == 'observed' and type(function['valid_normalized']) is bool and type(function['invalid_rejected']) is bool) or
         (function['status'] == 'unverified' and function['valid_normalized'] is None and function['invalid_rejected'] is None)))
    return value


def collect(value, rr=None):
    began = time.monotonic()
    rr = readiness_runtime(value['readiness_source_sha256']) if rr is None else rr
    module = rr.qualified_runtime()
    require(module.identity() == value['run_id'])
    rr.prepare_auth(module, {'run_id': value['run_id'], 'scenario': 'healthy'})
    attempt = rr.ROOT / 'functional-validation'
    attempt.mkdir(mode=0o700)  # An attempt is never silently repeated.
    interpreter = '/run/wormhole/no-such-python' if value['scenario'] == 'configured-interpreter-unavailable' else '/usr/bin/python3'
    variables = {'ansible_host': value['address'], 'ansible_port': 2222, 'ansible_user': 'wormhole',
        'ansible_connection': 'ssh', 'ansible_python_interpreter': interpreter,
        'ansible_ssh_args': shlex.join(rr.ssh_options({'scenario': 'healthy'})), 'ansible_ssh_retries': 0,
        'ansible_ssh_use_tty': False, 'ansible_ssh_transfer_method': 'piped', 'ansible_remote_tmp': '/tmp/wormhole-ansible'}
    inventory = attempt / 'inventory.json'
    inventory.write_text(json.dumps({'all': {'hosts': {'target-001': variables}}})); inventory.chmod(0o600)
    command = ['/usr/bin/python3', '-I', '-B', '-c', TARGET_PROGRAM, value['expected_payload_sha256']]
    arguments = ['/opt/wormhole/venv/bin/ansible', '-i', str(inventory), 'target-001', '-m', 'ansible.builtin.command',
        '-a', json.dumps({'argv': command, 'expand_argument_vars': False}), '--tree', str(attempt / 'results'),
        '--forks', '1', '--timeout', '3']
    if value['scenario'] == 'unexpected-skip':
        arguments.append('--check')  # Pinned command.py explicitly returns skipped without creates/removes.
    budget = value['timeout_seconds'] - (time.monotonic() - began)
    require(budget > .05)
    result = rr.capture(arguments, budget, rr.environment())
    tree, observed = None, None
    path = attempt / 'results/target-001'
    if path.exists():
        require(not path.is_symlink() and path.is_file() and path.stat().st_nlink == 1 and path.stat().st_size <= MAX_TREE)
        with path.open('rb') as stream:
            raw = stream.read(MAX_TREE + 1)
        require(len(raw) <= MAX_TREE)
        tree = json.loads(raw, object_pairs_hook=unique)
        require(type(tree) is dict)
    status, category = 'error', 'ansible_result_invalid'
    if result['timed_out']:
        category = 'validation_timeout'
    elif result['truncated']:
        category = 'output_bound'
    elif tree is not None and tree.get('unreachable') is True:
        status, category = 'unreachable', 'ansible_unreachable'
    elif tree is not None and tree.get('skipped') is True:
        status, category = 'skipped', 'unexpected_skip'
    elif result['returncode'] != 0:
        status, category = 'fail', 'ansible_failed'
        if value['scenario'] == 'configured-interpreter-unavailable' and '/run/wormhole/no-such-python' in result['log'] + json.dumps(tree):
            category = 'configured_interpreter_unavailable'
    elif tree is not None:
        allowed = {'changed', 'stdout', 'stderr', 'rc', 'cmd', 'start', 'end', 'delta', 'msg',
                   'stdout_lines', 'stderr_lines', 'failed', 'unreachable', 'skipped'}
        require(set(tree) <= allowed and tree.get('cmd') == command and type(tree.get('rc')) is int and tree['rc'] == 0 and
            tree.get('stderr') == '' and tree.get('msg', '') == '' and type(tree.get('stdout')) is str and
            len(tree['stdout'].encode()) <= 16384 and
            all(tree.get(key, False) is False for key in ('failed', 'unreachable', 'skipped')))
        observed = observation(json.loads(tree['stdout'], object_pairs_hook=unique))
        status, category = 'pass', None
    if time.monotonic() - began >= value['timeout_seconds']:
        status, category, observed = 'error', 'validation_timeout', None
    return {**{key: value[key] for key in ('schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256')},
        'status': status, 'category': category, 'returncode': result['returncode'], 'timed_out': result['timed_out'],
        'truncated': result['truncated'], 'duration_seconds': time.monotonic() - began,
        'observation': observed, 'private_diagnostic': result['log']}


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 11000)
        value = decode(base64.b64decode(sys.argv[1], validate=True))
        print(json.dumps(collect(value), sort_keys=True))
        return 0  # A complete failed observation is data, not an unknown exec.
    except Exception:
        print(json.dumps({'error': {'code': 'validation_runtime_refused'}}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
