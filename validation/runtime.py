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
import stat
import sys
import time
from uuid import UUID

READINESS = Path('/opt/readiness/runtime.py')
PACKAGES = ('ca-certificates', 'python3', 'python3.12', 'openssh-client', 'openssh-server', 'openssh-sftp-server')
SCENARIOS = ('healthy', 'version-expectation-mismatch', 'functional-expectation-mismatch',
             'configured-interpreter-unavailable', 'unexpected-skip', 'unreachable')
MAX_TREE = 65536

# Original fixed callback, embedded in this hash-bound helper source. Ansible's
# pinned tree callback has no skipped handler. No imported callback code/path.
CALLBACK_SOURCE = r'''import importlib.metadata,json,os,stat
from pathlib import Path
from ansible.plugins.callback import CallbackBase
DOCUMENTATION = """
name: wormhole_validation
type: aggregate
short_description: Fixed one-target Wormhole validation events
description: Stores the fixed command event and final completeness record.
"""
RESULTS=Path('/run/wormhole/readiness/functional-validation/results')
class CallbackModule(CallbackBase):
 CALLBACK_VERSION=2.0
 CALLBACK_TYPE='aggregate'
 CALLBACK_NAME='wormhole_validation'
 CALLBACK_NEEDS_ENABLED=True
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs)
  self.seen=0;self.invalid=False;self.finished=False
  self.version=importlib.metadata.version('ansible-core')
  if self.version!='2.21.5': self.invalid=True
 def directory(self):
  if any(p.is_symlink() for p in (RESULTS,*RESULTS.parents)): raise ValueError('linked results')
  info=RESULTS.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError('private results required')
 def fail(self):
  self.invalid=True
  try:
   self.directory()
   (RESULTS/'complete.json').unlink(missing_ok=True)
  except Exception: pass
 def write(self,name,value):
  self.directory()
  raw=json.dumps(value,sort_keys=True,allow_nan=False).encode()
  if not 1<=len(raw)<=65536: raise ValueError('result bound')
  fd=os.open(RESULTS/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as stream:
   stream.write(raw);stream.flush();os.fsync(stream.fileno())
 def record(self,result,event):
  self.seen+=1
  try:
   if self.invalid or self.finished or self.seen!=1 or result.host.get_name()!='target-001' or result.task.action!='ansible.builtin.command' or result.task.no_log is True or result.result.get('_ansible_no_log') is True: raise ValueError('event scope')
   raw=self._dump_results(result.result)
   if not isinstance(raw,str) or len(raw.encode())>49152: raise ValueError('event bound')
   value=json.loads(raw)
   if not isinstance(value,dict) or 'censored' in value: raise ValueError('censored event')
   self.write('target-001.json',{'schema_version':'1.0','host':'target-001','action':'ansible.builtin.command','event':event,'result':value})
  except Exception: self.fail()
 def v2_runner_on_ok(self,result): self.record(result,'ok')
 def v2_runner_on_failed(self,result,ignore_errors=False): self.record(result,'failed')
 def v2_runner_on_unreachable(self,result): self.record(result,'unreachable')
 def v2_runner_on_skipped(self,result): self.record(result,'skipped')
 def v2_playbook_on_stats(self,stats):
  try:
   if self.invalid or self.finished or self.seen!=1: raise ValueError('incomplete events')
   self.finished=True
   self.write('complete.json',{'schema_version':'1.0','host':'target-001','events':1,'ansible_core_version':self.version,'status':'complete'})
  except Exception: self.fail()
'''

BATCH_CALLBACK_SOURCE = CALLBACK_SOURCE.replace('name: wormhole_validation\n', 'name: wormhole_validation_batch\n') + r'''
RESULTS=Path('/run/wormhole/readiness/functional-batch/results')
class CallbackModule(CallbackModule):
 CALLBACK_NAME='wormhole_validation_batch'
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs);self.seen={}
  path=RESULTS.parent/'expected.json';info=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096: raise ValueError('fixed expected manifest')
  with path.open('rb') as stream: raw=stream.read(4097)
  self.expected=json.loads(raw)
  if not isinstance(self.expected,dict) or set(self.expected)!={'schema_version','target_ids','plan_sha256'} or self.expected['schema_version']!='1.0': raise ValueError('expected fields')
  ids=self.expected['target_ids'];allowed=tuple('target-'+str(i).zfill(3) for i in range(1,6))
  if not isinstance(ids,list) or not 1<=len(ids)<=5 or ids!=sorted(set(ids)) or any(x not in allowed for x in ids): raise ValueError('expected targets')
  import re
  if not isinstance(self.expected['plan_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',self.expected['plan_sha256']): raise ValueError('plan hash')
 def record(self,result,event):
  try:
   host=result.host.get_name()
   if self.invalid or self.finished or host not in self.expected['target_ids'] or host in self.seen or result.task.action!='ansible.builtin.command' or result.task.no_log is True or result.result.get('_ansible_no_log') is True: raise ValueError('event scope')
   self.seen[host]=event;raw=self._dump_results(result.result)
   if not isinstance(raw,str) or len(raw.encode())>49152: raise ValueError('event bound')
   value=json.loads(raw)
   if not isinstance(value,dict) or 'censored' in value: raise ValueError('censored event')
   self.write(host+'.json',{'schema_version':'1.0','host':host,'action':'ansible.builtin.command','event':event,'result':value})
  except Exception: self.fail()
 def v2_playbook_on_stats(self,stats):
  try:
   if self.invalid or self.finished or set(self.seen)!=set(self.expected['target_ids']): raise ValueError('incomplete batch')
   self.finished=True
   self.write('complete.json',{'schema_version':'1.0','target_ids':self.expected['target_ids'],'events':len(self.seen),'ansible_core_version':self.version,'plan_sha256':self.expected['plan_sha256'],'status':'complete'})
  except Exception: self.fail()
'''

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
    callbacks = attempt / 'callbacks'; callbacks.mkdir(mode=0o700)
    module.write_private(callbacks / 'wormhole_validation.py', CALLBACK_SOURCE.encode())
    results = attempt / 'results'; results.mkdir(mode=0o700)
    interpreter = '/run/wormhole/no-such-python' if value['scenario'] == 'configured-interpreter-unavailable' else '/usr/bin/python3'
    variables = {'ansible_host': value['address'], 'ansible_port': 2222, 'ansible_user': 'wormhole',
        'ansible_connection': 'ssh', 'ansible_python_interpreter': interpreter,
        'ansible_ssh_args': shlex.join(rr.ssh_options({'scenario': 'healthy'})), 'ansible_ssh_retries': 0,
        'ansible_ssh_use_tty': False, 'ansible_ssh_transfer_method': 'piped', 'ansible_remote_tmp': '/tmp/wormhole-ansible'}
    inventory = attempt / 'inventory.json'
    inventory.write_text(json.dumps({'all': {'hosts': {'target-001': variables}}})); inventory.chmod(0o600)
    command = ['/usr/bin/python3', '-I', '-B', '-c', TARGET_PROGRAM, value['expected_payload_sha256']]
    arguments = ['/opt/wormhole/venv/bin/ansible', '-i', str(inventory), 'target-001', '-m', 'ansible.builtin.command',
        '-a', json.dumps({'argv': command, 'expand_argument_vars': False}), '--forks', '1', '--timeout', '3']
    if value['scenario'] == 'unexpected-skip':
        arguments.append('--check')  # Pinned command.py explicitly returns skipped without creates/removes.
    budget = value['timeout_seconds'] - (time.monotonic() - began)
    require(budget > .05)
    env = {**rr.environment(), 'ANSIBLE_CALLBACK_PLUGINS': str(callbacks),
        'ANSIBLE_CALLBACKS_ENABLED': 'wormhole_validation', 'ANSIBLE_LOAD_CALLBACK_PLUGINS': '1',
        'PYTHONDONTWRITEBYTECODE': '1'}
    result = rr.capture(arguments, budget, env)
    tree, observed = None, None
    event = None
    directory = results.lstat()
    require(stat.S_ISDIR(directory.st_mode) and not results.is_symlink() and directory.st_uid == os.getuid() and
            stat.S_IMODE(directory.st_mode) == 0o700)
    if set(os.listdir(results)) == {'target-001.json', 'complete.json'}:
        records = {}
        for name in ('target-001.json', 'complete.json'):
            path = results / name
            info = path.lstat()
            require(not path.is_symlink() and path.is_file() and info.st_nlink == 1 and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_TREE)
            with path.open('rb') as stream:
                raw = stream.read(MAX_TREE + 1)
            require(len(raw) <= MAX_TREE)
            records[name] = json.loads(raw, object_pairs_hook=unique)
        record, complete = records['target-001.json'], records['complete.json']
        require(complete == {'schema_version': '1.0', 'host': 'target-001', 'events': 1,
            'ansible_core_version': '2.21.5', 'status': 'complete'} and type(record) is dict and set(record) ==
            {'schema_version', 'host', 'action', 'event', 'result'} and record['schema_version'] == '1.0' and
            record['host'] == 'target-001' and record['action'] == 'ansible.builtin.command' and
            record['event'] in {'ok', 'failed', 'unreachable', 'skipped'} and type(record['result']) is dict)
        tree, event = record['result'], record['event']
    status, category = 'error', 'ansible_result_invalid'
    if result['timed_out']:
        category = 'validation_timeout'
    elif result['truncated']:
        category = 'output_bound'
    elif event == 'unreachable':
        status, category = 'unreachable', 'ansible_unreachable'
    elif event == 'skipped':
        status, category = 'skipped', 'unexpected_skip'
    elif result['returncode'] != 0 or event == 'failed':
        status, category = 'fail', 'ansible_failed'
        if value['scenario'] == 'configured-interpreter-unavailable' and '/run/wormhole/no-such-python' in result['log'] + json.dumps(tree):
            category = 'configured_interpreter_unavailable'
    elif tree is not None and event == 'ok':
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


def decode_batch(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= 8192)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    fields = {'schema_version', 'run_id', 'source_revision', 'resource_layout', 'plan_sha256', 'target_plan', 'targets',
              'controller_concurrency', 'expected_payload_sha256', 'readiness_source_sha256', 'timeout_seconds'}
    require(type(value) is dict and set(value) == fields and value['schema_version'] == '1.0' and
        value['resource_layout'] == 'indexed-targets-v1' and type(value['run_id']) is str and str(UUID(value['run_id'])) == value['run_id'] and
        type(value['source_revision']) is str and re.fullmatch('[a-f0-9]{40}', value['source_revision']) and
        all(type(value[k]) is str and re.fullmatch('[a-f0-9]{64}', value[k]) for k in
            ('plan_sha256', 'expected_payload_sha256', 'readiness_source_sha256')) and
        type(value['timeout_seconds']) in (int, float) and math.isfinite(value['timeout_seconds']) and .1 <= value['timeout_seconds'] <= 45)
    plan = value['target_plan']; require(type(plan) is dict and plan.get('profile') in {'smoke', 'five-targets'})
    count = 1 if plan['profile'] == 'smoke' else 5
    ids = ['target-' + str(i).zfill(3) for i in range(1, count + 1)]
    require(plan == {'schema_version': '1.0', 'resource_layout': 'indexed-targets-v1', 'profile': plan['profile'],
        'target_count': count, 'target_ids': ids} and type(value['controller_concurrency']) is int and
        1 <= value['controller_concurrency'] <= min(count, 2) and type(value['targets']) is list and 1 <= len(value['targets']) <= count)
    seen, addresses = [], set()
    for target in value['targets']:
        require(type(target) is dict and set(target) == {'target_id', 'address', 'scenario'} and target['target_id'] in ids and
            target['scenario'] in SCENARIOS)
        address = ipaddress.ip_address(target['address'])
        require(address.version == 4 and str(address) == target['address'] and not any((address.is_loopback,
            address.is_unspecified, address.is_multicast, address.is_link_local, address.is_reserved)) and str(address) not in addresses)
        addresses.add(str(address)); seen.append(target['target_id'])
    require(seen == sorted(set(seen)))
    return value


def private_json(path):
    info = path.lstat()
    require(not path.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
        stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_TREE)
    with path.open('rb') as stream: raw = stream.read(MAX_TREE + 1)
    require(len(raw) <= MAX_TREE)
    return json.loads(raw, object_pairs_hook=unique)


def collect_batch(value, rr=None):
    began = time.monotonic()
    rr = readiness_runtime(value['readiness_source_sha256']) if rr is None else rr
    module = rr.qualified_runtime(); require(module.identity() == value['run_id'])
    config = rr.ROOT / 'ansible.cfg'
    raw_config = b'[defaults]\nhost_key_checking = True\nretry_files_enabled = False\ninterpreter_python = /usr/bin/python3\n'
    if not config.exists(): module.write_private(config, raw_config)
    info = config.lstat()
    require(stat.S_ISREG(info.st_mode) and not config.is_symlink() and info.st_uid == os.getuid() and
        stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == len(raw_config))
    with config.open('rb') as stream: require(stream.read(len(raw_config) + 1) == raw_config)
    attempt = rr.ROOT / 'functional-batch'; attempt.mkdir(mode=0o700)
    callbacks = attempt / 'callbacks'; callbacks.mkdir(mode=0o700)
    results = attempt / 'results'; results.mkdir(mode=0o700)
    ids = [target['target_id'] for target in value['targets']]
    module.write_private(attempt / 'expected.json', json.dumps({'schema_version': '1.0', 'target_ids': ids, 'plan_sha256': value['plan_sha256']}).encode())
    module.write_private(callbacks / 'wormhole_validation_batch.py', BATCH_CALLBACK_SOURCE.encode())
    hosts = {}
    for target in value['targets']:
        root = rr.ROOT / target['target_id']
        for name in ('id_ed25519', 'known_hosts'):
            module.bounded_input(root / name, private=True)  # Already established by that target's readiness, never repinned.
        hosts[target['target_id']] = {'ansible_host': target['address'], 'ansible_port': 2222, 'ansible_user': 'wormhole',
            'ansible_connection': 'ssh', 'ansible_python_interpreter': '/run/wormhole/no-such-python' if target['scenario'] == 'configured-interpreter-unavailable' else '/usr/bin/python3',
            'ansible_ssh_args': shlex.join(rr.ssh_options({'scenario': 'healthy'}, root=root)), 'ansible_ssh_retries': 0,
            'ansible_ssh_use_tty': False, 'ansible_ssh_transfer_method': 'piped', 'ansible_remote_tmp': '/tmp/wormhole-ansible'}
    inventory = attempt / 'inventory.json'; module.write_private(inventory, json.dumps({'all': {'hosts': hosts}}).encode())
    command = ['/usr/bin/python3', '-I', '-B', '-c', TARGET_PROGRAM, value['expected_payload_sha256']]
    arguments = ['/opt/wormhole/venv/bin/ansible', '-i', str(inventory), 'all', '-m', 'ansible.builtin.command',
        '-a', json.dumps({'argv': command, 'expand_argument_vars': False}), '--forks', str(value['controller_concurrency']), '--timeout', '3']
    # The explicit fixed skip scenario applies to this complete attempted subset.
    if any(target['scenario'] == 'unexpected-skip' for target in value['targets']):
        require(all(target['scenario'] == 'unexpected-skip' for target in value['targets']))
        arguments.append('--check')
    env = {**rr.environment(), 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_CALLBACK_PLUGINS': str(callbacks), 'ANSIBLE_CALLBACKS_ENABLED': 'wormhole_validation_batch',
        'ANSIBLE_LOAD_CALLBACK_PLUGINS': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    budget = value['timeout_seconds'] - (time.monotonic() - began); require(budget > .05)
    rr.MAX_LOG = 32768  # Explicit five-target response budget, in this one helper process only.
    result = rr.capture(arguments, budget, env)
    completed = False
    expected_files = {target + '.json' for target in ids} | {'complete.json'}
    info = results.lstat(); require(stat.S_ISDIR(info.st_mode) and not results.is_symlink() and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    if set(os.listdir(results)) == expected_files:
        completed = private_json(results / 'complete.json') == {'schema_version': '1.0', 'target_ids': ids, 'events': len(ids),
            'ansible_core_version': '2.21.5', 'plan_sha256': value['plan_sha256'], 'status': 'complete'}
    observations = []
    for target in value['targets']:
        status, category, observed, module_code = 'error', 'ansible_result_invalid', None, None
        if result['timed_out']: category = 'validation_timeout'
        elif result['truncated']: category = 'output_bound'
        elif completed:
            record = private_json(results / (target['target_id'] + '.json'))
            require(type(record) is dict and set(record) == {'schema_version', 'host', 'action', 'event', 'result'} and
                record['schema_version'] == '1.0' and record['host'] == target['target_id'] and record['action'] == 'ansible.builtin.command' and
                record['event'] in {'ok', 'failed', 'unreachable', 'skipped'} and type(record['result']) is dict)
            tree = record['result']; module_code = tree.get('rc')
            require(module_code is None or type(module_code) is int)
            if record['event'] == 'skipped': status, category = 'skipped', 'unexpected_skip'
            elif record['event'] == 'unreachable': status, category = 'unreachable', 'ansible_unreachable'
            elif record['event'] == 'failed':
                status, category = 'fail', 'ansible_failed'
                if target['scenario'] == 'configured-interpreter-unavailable' and '/run/wormhole/no-such-python' in json.dumps(tree): category = 'configured_interpreter_unavailable'
            else:
                allowed = {'changed', 'stdout', 'stderr', 'rc', 'cmd', 'start', 'end', 'delta', 'msg', 'stdout_lines', 'stderr_lines', 'failed', 'unreachable', 'skipped'}
                require(set(tree) <= allowed and tree.get('cmd') == command and type(tree.get('rc')) is int and tree['rc'] == 0 and
                    tree.get('stderr') == '' and tree.get('msg', '') == '' and type(tree.get('stdout')) is str and len(tree['stdout'].encode()) <= 16384 and
                    all(tree.get(key, False) is False for key in ('failed', 'unreachable', 'skipped')))
                observed = observation(json.loads(tree['stdout'], object_pairs_hook=unique)); status, category = 'pass', None
        observations.append({'target_id': target['target_id'], 'status': status, 'category': category,
                             'module_returncode': module_code, 'observation': observed})
    if time.monotonic() - began >= value['timeout_seconds']:
        observations = [{'target_id': target['target_id'], 'status': 'error', 'category': 'validation_timeout', 'module_returncode': None, 'observation': None} for target in value['targets']]
    status = 'pass' if result['returncode'] == 0 and not result['timed_out'] and not result['truncated'] and all(x['status'] == 'pass' for x in observations) else 'fail'
    return {**{key: value[key] for key in ('schema_version', 'run_id', 'source_revision', 'resource_layout', 'plan_sha256')},
        'status': status, 'returncode': result['returncode'], 'timed_out': result['timed_out'], 'truncated': result['truncated'],
        'duration_seconds': time.monotonic() - began, 'targets': observations, 'private_diagnostic': result['log']}


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 11000)
        raw = base64.b64decode(sys.argv[1], validate=True)
        probe = json.loads(raw, object_pairs_hook=unique)
        batch = type(probe) is dict and probe.get('resource_layout') == 'indexed-targets-v1'
        value = decode_batch(raw) if batch else decode(raw)
        print(json.dumps(collect_batch(value) if batch else collect(value), sort_keys=True))
        return 0  # A complete failed observation is data, not an unknown exec.
    except Exception:
        print(json.dumps({'error': {'code': 'validation_runtime_refused'}}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
