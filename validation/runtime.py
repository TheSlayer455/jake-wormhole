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

# Pinned 2.21.5 CallbackBase is a no-op; TQM loads this fixed stdout plugin
# separately from the authoritative aggregate. Twenty repeated command dumps
# must not consume the unchanged bounded functional response.
# https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/plugins/callback/__init__.py
QUIET_CALLBACK_SOURCE = r'''from ansible.plugins.callback import CallbackBase
DOCUMENTATION="""
name: wormhole_validation_quiet
type: stdout
short_description: Fixed twenty-target console suppression
description: Structured aggregate events remain authoritative.
"""
class CallbackModule(CallbackBase):
 CALLBACK_VERSION=2.0
 CALLBACK_TYPE='stdout'
 CALLBACK_NAME='wormhole_validation_quiet'
'''

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
  ids=self.expected['target_ids'];allowed=tuple('target-'+str(i).zfill(3) for i in range(1,21))
  if not isinstance(ids,list) or not 1<=len(ids)<=20 or ids!=sorted(set(ids)) or any(x not in allowed for x in ids): raise ValueError('expected targets')
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


CANDIDATE_PROGRAM = r'''import hashlib,json,os,stat,sys,types
from pathlib import Path
root=Path('/opt/wormhole/reference')
def read(name,limit):
 path=root/name
 if any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('linked candidate')
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 1<=info.st_size<=limit: raise ValueError('candidate file bound')
 with path.open('rb') as stream: raw=stream.read(limit+1)
 if len(raw)!=info.st_size or len(raw)>limit: raise ValueError('candidate changed')
 return raw
manifest=read('manifest.json',16384)
source=read('source.synthetic.bin',8388608)
payload=read('payload.py',16384)
version=read('version.txt',128).decode('ascii').strip()
configuration=json.loads(read('config.json',4096))
source_sha=hashlib.sha256(source).hexdigest();payload_sha=hashlib.sha256(payload).hexdigest()
function={'status':'unverified','value':None}
if payload_sha==sys.argv[1]:
 module=types.ModuleType('verified_reference_payload')
 exec(compile(payload,'/opt/wormhole/reference/payload.py','exec'),module.__dict__)
 result=module.describe(configuration,source_sha)
 if hashlib.sha256(read('payload.py',16384)).hexdigest()!=payload_sha: raise ValueError('payload changed')
 function={'status':'observed','value':result}
release={}
for line in Path('/usr/lib/os-release').read_text().splitlines():
 if line.startswith(('ID=','VERSION_ID=')):
  key,value=line.split('=',1);release[key]=value.strip('"')
print(json.dumps({'schema_version':'1.0','os':{'id':release.get('ID'),'version_id':release.get('VERSION_ID')},
 'candidate_sha256':hashlib.sha256(manifest).hexdigest(),'source_sha256':source_sha,'payload_sha256':payload_sha,
 'version':version,'configuration':configuration,'function':function},sort_keys=True))
'''


RPM_PROGRAM = r'''import hashlib,json,os,stat,sys,types,rpm
from pathlib import Path
root=Path('/opt/wormhole/reference')
def read(name,limit):
 path=root/name
 if any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('linked candidate')
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 1<=info.st_size<=limit: raise ValueError('candidate bound')
 with path.open('rb') as stream: raw=stream.read(limit+1)
 if len(raw)!=info.st_size or len(raw)>limit: raise ValueError('candidate changed')
 return raw
manifest=read('manifest.json',32768);value=json.loads(manifest)
source=read('source.synthetic.bin',8388608);payload=read('payload.py',16384)
version_raw=read('version.txt',128);config_raw=read('config.json',4096)
version=version_raw.decode('ascii').strip();configuration=json.loads(config_raw)
source_sha=hashlib.sha256(source).hexdigest();payload_sha=hashlib.sha256(payload).hexdigest()
function={'status':'unverified','value':None}
if payload_sha==sys.argv[1]:
 module=types.ModuleType('verified_reference_payload');exec(compile(payload,'/opt/wormhole/reference/payload.py','exec'),module.__dict__)
 result=module.describe(configuration,source_sha)
 if hashlib.sha256(read('payload.py',16384)).hexdigest()!=payload_sha: raise ValueError('payload changed')
 function={'status':'observed','value':result}
release={}
with Path('/usr/lib/os-release').open('rb') as stream: raw=stream.read(4097)
if len(raw)>4096: raise ValueError('os release bound')
for line in raw.decode().splitlines():
 if line.startswith(('ID=','VERSION_ID=')):
  key,item=line.split('=',1);release[key]=item.strip('"')
packages={};transaction=rpm.TransactionSet('/')
try:
 for name in ('python3','openssh','openssh-server','shadow-utils','openssh-clients'):
  records=[]
  for header in transaction.dbMatch('name',name):
   if records: raise ValueError('ambiguous RPM package')
   row={'epoch':0 if header['epoch'] is None else header['epoch'],'version':header['version'],'release':header['release'],'arch':header['arch']}
   if type(row['epoch']) is not int or not 0<=row['epoch']<=2147483647 or any(type(row[k]) is not str or not 1<=len(row[k])<=160 or any(ord(c)<32 or ord(c)==127 for c in row[k]) for k in ('version','release','arch')): raise ValueError('RPM header bound')
   records.append(row)
  packages[name]=records[0] if records else None
finally: transaction.closeDB()
files=value.get('files');names=('source.synthetic.bin','payload.py','version.txt','config.json')
if type(files) is not list or len(files)!=4 or [x.get('path') for x in files]!=list(names): raise ValueError('content file set')
actual=[{'path':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in zip(names,(source,payload,version_raw,config_raw))]
content=hashlib.sha256(json.dumps({'files':actual},sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
print(json.dumps({'schema_version':'1.0','os':{'id':release.get('ID'),'version_id':release.get('VERSION_ID')},
 'candidate_sha256':hashlib.sha256(manifest).hexdigest(),'content_sha256':content,'source_sha256':source_sha,'payload_sha256':payload_sha,
 'version':version,'configuration':configuration,'function':function,'packages':packages,'shared_kernel_release':os.uname().release},sort_keys=True))
'''


def rpm_observation(value):
    require(type(value) is dict and set(value) == {'schema_version','os','candidate_sha256','content_sha256','source_sha256',
        'payload_sha256','version','configuration','function','packages','shared_kernel_release'})
    candidate_observation({key:item for key,item in value.items() if key not in {'content_sha256','packages','shared_kernel_release'}})
    require(type(value['content_sha256']) is str and re.fullmatch('[a-f0-9]{64}',value['content_sha256']) and
        type(value['shared_kernel_release']) is str and 1<=len(value['shared_kernel_release'])<=256 and
        not any(ord(c)<32 or ord(c)==127 for c in value['shared_kernel_release']) and type(value['packages']) is dict and
        set(value['packages'])=={'python3','openssh','openssh-server','shadow-utils','openssh-clients'})
    for package in value['packages'].values():
        require(package is None or type(package) is dict and set(package)=={'epoch','version','release','arch'} and
            type(package['epoch']) is int and 0<=package['epoch']<=2**31-1 and
            all(type(package[key]) is str and 1<=len(package[key])<=160 and not any(ord(c)<32 or ord(c)==127 for c in package[key])
                for key in ('version','release','arch')))
    return value


def candidate_observation(value):
    require(type(value) is dict and set(value) == {'schema_version', 'os', 'candidate_sha256', 'source_sha256',
        'payload_sha256', 'version', 'configuration', 'function'} and value['schema_version'] == '1.0' and
        type(value['os']) is dict and set(value['os']) == {'id', 'version_id'} and
        all(type(x) is str and 1 <= len(x) <= 64 for x in value['os'].values()) and
        all(type(value[key]) is str and re.fullmatch('[a-f0-9]{64}', value[key]) for key in
            ('candidate_sha256', 'source_sha256', 'payload_sha256')) and
        type(value['version']) is str and 1 <= len(value['version']) <= 128 and
        type(value['configuration']) is dict and set(value['configuration']) == {'format', 'greeting'} and
        all(type(x) is str and 1 <= len(x) <= 128 for x in value['configuration'].values()))
    function = value['function']
    require(type(function) is dict and set(function) == {'status', 'value'} and
        ((function['status'] == 'unverified' and function['value'] is None) or
         (function['status'] == 'observed' and type(function['value']) is dict and
          set(function['value']) == {'version', 'message', 'source_sha256'} and
          all(type(x) is str and 1 <= len(x) <= 128 for x in function['value'].values()))))
    return value


def decode(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= 8192)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    fields = {'schema_version', 'run_id', 'source_revision', 'target_id', 'address', 'scenario', 'plan_sha256',
              'expected_payload_sha256', 'readiness_source_sha256', 'timeout_seconds'}
    candidate = type(value) is dict and value.get('operation') in {'candidate-functional-v1','rpm-functional-v1'}
    if candidate: fields |= {'operation'}
    require(type(value) is dict and set(value) == fields and value['schema_version'] == '1.0' and
        type(value['run_id']) is str and str(UUID(value['run_id'])) == value['run_id'] and
        type(value['source_revision']) is str and re.fullmatch('[a-f0-9]{40}', value['source_revision']) and
        value['target_id'] == 'target-001' and (value['scenario'] == 'healthy' if candidate else value['scenario'] in SCENARIOS) and
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
    candidate = value.get('operation') == 'candidate-functional-v1'
    rpm_candidate = value.get('operation') == 'rpm-functional-v1'
    command = ['/usr/bin/python3', '-I', '-B', '-c', RPM_PROGRAM if rpm_candidate else CANDIDATE_PROGRAM if candidate else TARGET_PROGRAM, value['expected_payload_sha256']]
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
        observed = (rpm_observation if rpm_candidate else candidate_observation if candidate else observation)(json.loads(tree['stdout'], object_pairs_hook=unique))
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
    plan = value['target_plan']; require(type(plan) is dict and plan.get('profile') in {'smoke', 'five-targets', 'twenty-targets'})
    count = {'smoke': 1, 'five-targets': 5, 'twenty-targets': 20}[plan['profile']]
    ids = ['target-' + str(i).zfill(3) for i in range(1, count + 1)]
    require(plan == {'schema_version': '1.0', 'resource_layout': 'indexed-targets-v1', 'profile': plan['profile'],
        'target_count': count, 'target_ids': ids} and type(value['controller_concurrency']) is int and
        1 <= value['controller_concurrency'] <= min(count, 4 if count == 20 else 2) and
        type(value['targets']) is list and 1 <= len(value['targets']) <= count)
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
    if value['target_plan']['profile'] == 'twenty-targets':
        module.write_private(callbacks / 'wormhole_validation_quiet.py', QUIET_CALLBACK_SOURCE.encode())
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
    if value['target_plan']['profile'] == 'twenty-targets': env['ANSIBLE_STDOUT_CALLBACK'] = 'wormhole_validation_quiet'
    budget = value['timeout_seconds'] - (time.monotonic() - began); require(budget > .05)
    rr.MAX_LOG = 32768  # Existing functional diagnostic budget, in this helper process only.
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


SVD_RAW_LIMIT = 32768
SVD_PACKET_LIMIT = 43692
SVD_VERSION = '1.0'

# Original read-only target program. No caller supplies a package command/path.
SVD_PROGRAM = r'''import base64,hashlib,json,os,re,signal,stat,subprocess,sys,time
from pathlib import Path
ROOT=Path('/opt/wormhole/reference')
NAMES=('source.synthetic.bin','payload.py','version.txt','config.json')
def require(value):
 if not value: raise ValueError('software inventory refused')
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def alarm(*_): raise TimeoutError('software inventory deadline')
signal.signal(signal.SIGALRM,alarm);signal.alarm(20)
def text(value,maximum=240):
 require(type(value) is str and 1<=len(value)<=maximum and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.:~^\-]*',value));return value
def read(path,maximum):
 require(not any(p.is_symlink() for p in (path,*path.parents)))
 info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=maximum)
 with path.open('rb') as stream: raw=stream.read(maximum+1)
 require(0<len(raw)<=maximum and len(raw)==info.st_size);return raw
def read_release(path=Path('/etc/os-release'),canonical_path=Path('/usr/lib/os-release')):
 # The standard release-file link is the sole allowed link in this collector.
 if path.is_symlink():
  require(os.readlink(path) in ('../usr/lib/os-release','/usr/lib/os-release'))
  path=canonical_path
 return read(path,8192)
def query(arguments,maximum=524288):
 process=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  env={'PATH':'/usr/bin:/bin','HOME':'/tmp','LC_ALL':'C'},close_fds=True,bufsize=0)
 os.set_blocking(process.stdout.fileno(),False);os.set_blocking(process.stderr.fileno(),False)
 outputs=[bytearray(),bytearray()];ended=[False,False];end=time.monotonic()+10
 try:
  while not all(ended) or process.poll() is None:
   require(time.monotonic()<end)
   for index,stream in enumerate((process.stdout,process.stderr)):
    try:
     chunk=os.read(stream.fileno(),4096)
     if chunk: outputs[index].extend(chunk);require(len(outputs[index])<=(maximum if index==0 else 2048))
     else: ended[index]=True
    except BlockingIOError: pass
   time.sleep(.002)
  require(time.monotonic()<end and process.returncode==0 and not outputs[1]);return bytes(outputs[0])
 finally:
  if process.poll() is None: process.kill()
  process.wait(timeout=2);process.stdout.close();process.stderr.close()
def dpkg_rows(raw):
 require(type(raw) is bytes and 0<len(raw)<=524288)
 rows=[]
 for line in raw.decode('ascii').splitlines():
  parts=line.split('\t');require(len(parts)==4)
  name,version,architecture,status=parts
  if status in ('not-installed','config-files'): continue
  require(status=='installed')
  rows.append({'name':text(name),'version':text(version),'architecture':text(architecture,64)});require(len(rows)<=2048)
 rows.sort(key=lambda x:(x['name'],x['architecture']))
 require(rows and len({(x['name'],x['architecture']) for x in rows})==len(rows));return rows
def rpm_rows(module):
 packages=[];keys=[];transaction=module.TransactionSet('/')
 try:
  for header in transaction.dbMatch():
   epoch=header['epoch'];epoch=0 if epoch is None else epoch
   require(type(epoch) is int and 0<=epoch<=2147483647)
   name=text(header['name']);arch=header['arch']
   row={'name':name,'epoch':epoch,'version':text(header['version']),'release':text(header['release']),'arch':None if name=='gpg-pubkey' and arch is None else text(arch,64)}
   (keys if name=='gpg-pubkey' else packages).append(row);require(len(packages)<=2048 and len(keys)<=16)
 finally: transaction.closeDB()
 key=lambda x:(x['name'],x['epoch'],x['version'],x['release'],x['arch'] or '')
 packages.sort(key=key);keys.sort(key=key)
 require(packages and len({key(x) for x in packages})==len(packages) and len({key(x) for x in keys})==len(keys));return packages,keys
def collect():
 release={}
 for line in read_release().decode().splitlines():
  key,sep,value=line.partition('=')
  if sep and key in ('ID','VERSION_ID','NAME'): release[key]=value.strip().strip('"').strip("'")
 require(set(release)=={'ID','VERSION_ID','NAME'} and all(0<len(x)<=128 and not any(ord(c)<32 for c in x) for x in release.values()))
 if release['ID']=='ubuntu':
  manager='dpkg';packages=dpkg_rows(query(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n']));keys=[]
  architecture=text(query(['/usr/bin/dpkg','--print-architecture'],128).decode('ascii').strip(),64)
 elif release['ID']=='rhel':
  import rpm
  manager='rpm';packages,keys=rpm_rows(rpm);architecture=text(rpm.expandMacro('%{_arch}'),64)
 else: raise ValueError('unsupported package manager')
 files=[]
 for name in NAMES:
  raw=read(ROOT/name,16*1024*1024);files.append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
 content=hashlib.sha256(canonical({'files':[{'path':x['path'],'size':x['bytes'],'sha256':x['sha256']} for x in files]})).hexdigest()
 version=text(read(ROOT/'version.txt',128).decode('ascii').strip(),128)
 manifest=read(ROOT/'manifest.json',32768)
 value={'schema_version':'1.0','os':{'id':release['ID'],'version_id':release['VERSION_ID'],'name':release['NAME'],'architecture':architecture},
  'package_manager':manager,'packages':packages,'rpm_key_headers':keys,
  'payload':{'version':version,'sha256':files[1]['sha256'],'manifest_sha256':hashlib.sha256(manifest).hexdigest(),'content_sha256':content,'source_sha256':files[0]['sha256'],'files':files},
  'shared_kernel':{'scope':'host-shared','release':os.uname().release}}
 raw=canonical(value);require(len(raw)<=32768);return raw
if __name__=='__main__':
 try: sys.stdout.buffer.write(base64.b64encode(collect())+b'\n')
 except Exception: sys.stderr.write('software_inventory_collection_failed\n');raise SystemExit(2)
'''

SVD_CALLBACK_SOURCE = r'''import hashlib,importlib.metadata,json,os,stat
from pathlib import Path
from ansible.plugins.callback import CallbackBase
DOCUMENTATION="""
name: wormhole_inventory
type: aggregate
short_description: Fixed one-target software inventory event
description: Bounded single original collector packet with terminal event proof.
"""
RESULTS=Path('/run/wormhole/readiness/software-inventory/results')
class CallbackModule(CallbackBase):
 CALLBACK_VERSION=2.0
 CALLBACK_TYPE='aggregate'
 CALLBACK_NAME='wormhole_inventory'
 CALLBACK_NEEDS_ENABLED=True
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs);self.seen=0;self.invalid=False;self.finished=False;self.version=importlib.metadata.version('ansible-core')
  if self.version!='2.21.5': self.invalid=True
 def directory(self):
  if any(p.is_symlink() for p in (RESULTS,*RESULTS.parents)): raise ValueError('linked results')
  info=RESULTS.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError('private results')
 def fail(self):
  self.invalid=True
  try: self.directory();(RESULTS/'complete.json').unlink(missing_ok=True)
  except Exception: pass
 def write(self,name,value):
  self.directory();raw=json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False).encode()
  if len(raw)>49152: raise ValueError('event bound')
  fd=os.open(RESULTS/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
 def record(self,result,event):
  self.seen+=1
  try:
   if self.invalid or self.finished or self.seen!=1 or result.host.get_name()!='target-001' or result.task.action!='ansible.builtin.command' or result.task.no_log is True or result.result.get('_ansible_no_log') is True: raise ValueError('event scope')
   original=result.result
   if not isinstance(original,dict) or 'censored' in original: raise ValueError('event type')
   selected={key:original.get(key,default) for key,default in (('rc',None),('stdout',''),('stderr',''),('msg',''),('failed',False),('unreachable',False),('skipped',False))}
   if not all(type(selected[key]) is str and len(selected[key].encode())<=limit for key,limit in (('stdout',43692),('stderr',2048),('msg',2048))): raise ValueError('stream bound')
   if not all(type(selected[key]) is bool for key in ('failed','unreachable','skipped')) or not(selected['rc'] is None or type(selected['rc']) is int): raise ValueError('event status')
   command=original.get('cmd');selected['command_sha256']=hashlib.sha256(json.dumps(command,sort_keys=True,separators=(',',':')).encode()).hexdigest() if isinstance(command,list) and all(type(x) is str for x in command) and len(json.dumps(command).encode())<=16384 else None
   self.write('target-001.json',{'schema_version':'1.0','host':'target-001','action':'ansible.builtin.command','event':event,'result':selected})
  except Exception: self.fail()
 def v2_runner_on_ok(self,result): self.record(result,'ok')
 def v2_runner_on_failed(self,result,ignore_errors=False): self.record(result,'failed')
 def v2_runner_on_unreachable(self,result): self.record(result,'unreachable')
 def v2_runner_on_skipped(self,result): self.record(result,'skipped')
 def v2_playbook_on_stats(self,stats):
  try:
   if self.invalid or self.finished or self.seen!=1: raise ValueError('incomplete events')
   self.finished=True;self.write('complete.json',{'schema_version':'1.0','host':'target-001','events':1,'ansible_core_version':self.version,'status':'complete'})
  except Exception: self.fail()
'''


def decode_software_inventory(raw):
    require(type(raw) is bytes and 1<=len(raw)<=8192)
    value=json.loads(raw,object_pairs_hook=unique)
    fields={'schema_version','run_id','source_revision','target_id','plan_sha256','operation','address','scenario','readiness_source_sha256','timeout_seconds'}
    require(type(value) is dict and set(value)==fields and value['schema_version']=='1.0' and value['operation']=='software-inventory-v1' and
        type(value['run_id']) is str and str(UUID(value['run_id']))==value['run_id'] and value['target_id']=='target-001' and
        value['scenario'] in {'healthy','collector-unavailable'} and
        all(type(value[key]) is str and re.fullmatch('[a-f0-9]{'+str(length)+'}',value[key]) for key,length in
            (('source_revision',40),('plan_sha256',64),('readiness_source_sha256',64))))
    require(type(value['timeout_seconds']) in (int,float) and math.isfinite(value['timeout_seconds']) and .1<=value['timeout_seconds']<=33)
    address=ipaddress.ip_address(value['address'])
    require(address.version==4 and str(address)==value['address'] and not any((address.is_loopback,address.is_unspecified,address.is_multicast,address.is_link_local,address.is_reserved)))
    return value


def collect_software_inventory(value,rr=None):
    import importlib.metadata,platform
    began=time.monotonic();rr=readiness_runtime(value['readiness_source_sha256']) if rr is None else rr
    module=rr.qualified_runtime();require(module.identity()==value['run_id'])
    rr.prepare_auth(module,{'run_id':value['run_id'],'scenario':'healthy'})
    attempt=rr.ROOT/'software-inventory';attempt.mkdir(mode=0o700)
    callbacks=attempt/'callbacks';callbacks.mkdir(mode=0o700)
    module.write_private(callbacks/'wormhole_inventory.py',SVD_CALLBACK_SOURCE.encode())
    results=attempt/'results';results.mkdir(mode=0o700)
    interpreter='/run/wormhole/no-such-python' if value['scenario']=='collector-unavailable' else '/usr/bin/python3'
    variables={'ansible_host':value['address'],'ansible_port':2222,'ansible_user':'wormhole','ansible_connection':'ssh',
        'ansible_python_interpreter':interpreter,'ansible_ssh_args':shlex.join(rr.ssh_options({'scenario':'healthy'})),
        'ansible_ssh_retries':0,'ansible_ssh_use_tty':False,'ansible_ssh_transfer_method':'piped','ansible_remote_tmp':'/tmp/wormhole-ansible'}
    inventory=attempt/'inventory.json';module.write_private(inventory,json.dumps({'all':{'hosts':{'target-001':variables}}}).encode())
    command=['/usr/bin/python3','-I','-B','-c',SVD_PROGRAM]
    arguments=['/opt/wormhole/venv/bin/ansible','-i',str(inventory),'target-001','-m','ansible.builtin.command',
        '-a',json.dumps({'argv':command,'expand_argument_vars':False}),'--forks','1','--timeout','3']
    budget=value['timeout_seconds']-(time.monotonic()-began);require(budget>.05)
    environment={**rr.environment(),'ANSIBLE_CALLBACK_PLUGINS':str(callbacks),'ANSIBLE_CALLBACKS_ENABLED':'wormhole_inventory',
        'ANSIBLE_LOAD_CALLBACK_PLUGINS':'1','PYTHONDONTWRITEBYTECODE':'1'}
    rr.MAX_LOG=65536
    result=rr.capture(arguments,budget,environment)
    directory=results.lstat()
    require(not any(path.is_symlink() for path in (results,*results.parents)) and stat.S_ISDIR(directory.st_mode) and
        directory.st_uid==os.getuid() and stat.S_IMODE(directory.st_mode)==0o700)
    tree,event=None,None
    if set(os.listdir(results))=={'target-001.json','complete.json'}:
        records={}
        for name in ('target-001.json','complete.json'):
            records[name]=private_json(results/name)
        record,complete=records['target-001.json'],records['complete.json']
        require(complete=={'schema_version':'1.0','host':'target-001','events':1,'ansible_core_version':'2.21.5','status':'complete'} and
            type(record) is dict and set(record)=={'schema_version','host','action','event','result'} and record['schema_version']=='1.0' and
            record['host']=='target-001' and record['action']=='ansible.builtin.command' and record['event'] in {'ok','failed','unreachable','skipped'} and type(record['result']) is dict)
        tree,event=record['result'],record['event']
    status,category='error','ansible_result_invalid';packet=None
    if result['timed_out']:category='validation_timeout'
    elif result['truncated']:category='output_bound'
    elif event=='unreachable':category='ansible_unreachable'
    elif event=='skipped':category='unexpected_skip'
    elif result['returncode']!=0 or event=='failed':
        category='configured_interpreter_unavailable' if value['scenario']=='collector-unavailable' and '/run/wormhole/no-such-python' in result['log']+json.dumps(tree) else 'svd_collector_failed'
    elif event=='ok':
        require(set(tree)=={'rc','stdout','stderr','msg','failed','unreachable','skipped','command_sha256'} and
            type(tree['rc']) is int and tree['rc']==0 and tree['stderr']=='' and tree['msg']=='' and
            all(tree[key] is False for key in ('failed','unreachable','skipped')) and
            tree['command_sha256']==hashlib.sha256(json.dumps(command,sort_keys=True,separators=(',',':')).encode()).hexdigest() and
            type(tree['stdout']) is str and 0<len(tree['stdout'])<=SVD_PACKET_LIMIT)
        packet=tree['stdout'];raw=base64.b64decode(packet,validate=True);require(0<len(raw)<=SVD_RAW_LIMIT)
        observed=json.loads(raw,object_pairs_hook=unique)
        require(json.dumps(observed,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()==raw)
        status,category='pass',None
    if time.monotonic()-began>=value['timeout_seconds']:status,category,packet='error','validation_timeout',None
    return {**{key:value[key] for key in ('schema_version','run_id','source_revision','target_id','plan_sha256')},'status':status,
        'category':category,'returncode':result['returncode'],'timed_out':result['timed_out'],'truncated':result['truncated'],
        'duration_seconds':time.monotonic()-began,'collector_base64':packet,
        'helper_provenance':{'python_version':platform.python_version(),'ansible_core_version':importlib.metadata.version('ansible-core')},
        'private_diagnostic':'Bounded Ansible output: '+str(len(result['log'].encode()))+' bytes; SHA256 '+hashlib.sha256(result['log'].encode()).hexdigest()}


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 11000)
        raw = base64.b64decode(sys.argv[1], validate=True)
        probe = json.loads(raw, object_pairs_hook=unique)
        batch = type(probe) is dict and probe.get('resource_layout') == 'indexed-targets-v1'
        inventory = type(probe) is dict and probe.get('operation')=='software-inventory-v1'
        value = decode_software_inventory(raw) if inventory else decode_batch(raw) if batch else decode(raw)
        print(json.dumps(collect_software_inventory(value) if inventory else collect_batch(value) if batch else collect(value), sort_keys=True))
        return 0  # A complete failed observation is data, not an unknown exec.
    except Exception:
        print(json.dumps({'error': {'code': 'validation_runtime_refused'}}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
