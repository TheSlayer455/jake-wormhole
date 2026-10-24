"""Fixed stock-Ubuntu native inventory through authenticated SSH and Ansible.

This separately hash-bound helper source has a dedicated four-target envelope.
It never changes targets, accepts commands, repins trust or controls Docker.
"""
import base64
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import sys
import time
import types
from uuid import UUID

MAX_RESPONSE = 262144
MAX_PACKET = 32768
MAX_BASE64 = 43692
READINESS = Path('/opt/readiness/runtime.py')
TARGET_IDS = tuple('target-' + str(i).zfill(3) for i in range(1, 21))
BATCHES = {f'batch-{i + 1:03}': TARGET_IDS[i * 4:(i + 1) * 4] for i in range(5)}

# Pinned Ansible2.21.5's ad-hoc minimal callback prints command stdout. Full
# native packets belong only to the bounded aggregate, not the 4KiB console.
# CallbackBase's inherited stdout handlers are no-ops; failures remain events
# in CALLBACK and the actual Ansible return code still controls batch success.
QUIET_CALLBACK_SOURCE = r'''from ansible.plugins.callback import CallbackBase
DOCUMENTATION="""
name: wormhole_stock_inventory_quiet
type: stdout
short_description: Fixed stock inventory console suppression
description: Structured aggregate events remain authoritative.
"""
class CallbackModule(CallbackBase):
 CALLBACK_VERSION=2.0
 CALLBACK_TYPE='stdout'
 CALLBACK_NAME='wormhole_stock_inventory_quiet'
'''

# The native read/query/dpkg parser is the reviewed SVD collector subset. No
# candidate payload, manifest or application version is invented for stock images.
STOCK_PROGRAM = r'''import base64,hashlib,json,os,re,signal,stat,subprocess,sys,time
from pathlib import Path
def require(value):
 if not value: raise ValueError('stock inventory refused')
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def alarm(*_): raise TimeoutError('stock inventory deadline')
signal.signal(signal.SIGALRM,alarm);signal.alarm(20)
def text(value,maximum=240):
 require(type(value) is str and 1<=len(value)<=maximum and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.:~^\-]*',value));return value
def read(path,maximum):
 require(not any(p.is_symlink() for p in (path,*path.parents)))
 info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=maximum)
 with path.open('rb') as stream: raw=stream.read(maximum+1)
 require(0<len(raw)<=maximum and len(raw)==info.st_size);return raw
def read_release(path=Path('/etc/os-release'),canonical_path=Path('/usr/lib/os-release')):
 if path.is_symlink():
  require(os.readlink(path) in ('../usr/lib/os-release','/usr/lib/os-release'));path=canonical_path
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
  parts=line.split('\t');require(len(parts)==5)
  name,version,architecture,status,error=parts
  require(error=='ok')
  if status in ('not-installed','config-files'): continue
  require(status=='installed');rows.append({'name':text(name),'version':text(version),'architecture':text(architecture,64)});require(len(rows)<=2048)
 rows.sort(key=lambda x:(x['name'],x['architecture']))
 require(rows and len({(x['name'],x['architecture']) for x in rows})==len(rows));return rows
def collect():
 release={}
 for line in read_release().decode().splitlines():
  key,sep,value=line.partition('=')
  if sep and key in ('ID','VERSION_ID','NAME'): release[key]=value.strip().strip('"').strip("'")
 require(set(release)=={'ID','VERSION_ID','NAME'} and release['ID']=='ubuntu' and all(0<len(x)<=128 and not any(ord(c)<32 for c in x) for x in release.values()))
 packages=dpkg_rows(query(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\t${db:Status-Eflag}\n']))
 architecture=text(query(['/usr/bin/dpkg','--print-architecture'],128).decode('ascii').strip(),64)
 runtime=read(Path('/opt/wormhole/runtime.py'),65536)
 value={'schema_version':'1.0','os':{'id':release['ID'],'version_id':release['VERSION_ID'],'name':release['NAME'],'architecture':architecture},
  'package_manager':'dpkg','packages':packages,'runtime_sha256':hashlib.sha256(runtime).hexdigest(),
  'shared_kernel':{'scope':'host-shared','release':os.uname().release}}
 raw=canonical(value);require(len(raw)<=32768);return raw
if __name__=='__main__':
 try: sys.stdout.buffer.write(base64.b64encode(collect())+b'\n')
 except Exception: sys.stderr.write('stock_inventory_collection_failed\n');raise SystemExit(2)
'''

CALLBACK = r'''import hashlib,importlib.metadata,json,os,re,stat
from pathlib import Path
from ansible.plugins.callback import CallbackBase
DOCUMENTATION="""
name: wormhole_stock_inventory
type: aggregate
short_description: Fixed four-target stock native inventory
description: Complete fixed authenticated terminal-event inventory.
"""
ROOT=Path('/run/wormhole/readiness/stock-inventory')
class CallbackModule(CallbackBase):
 CALLBACK_VERSION=2.0
 CALLBACK_TYPE='aggregate'
 CALLBACK_NAME='wormhole_stock_inventory'
 CALLBACK_NEEDS_ENABLED=True
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs);self.seen=set();self.invalid=False;self.finished=False
  self.version=importlib.metadata.version('ansible-core')
  path=Path(os.environ['WORMHOLE_STOCK_EXPECTED'])
  if path.parent.parent!=ROOT or path.name!='expected.json' or path.parent.name not in tuple('batch-'+str(i).zfill(3) for i in range(1,6)):raise ValueError('fixed batch')
  if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('linked batch')
  info=path.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4096:raise ValueError('expected input')
  with path.open('rb') as stream:raw=stream.read(4097)
  self.expected=json.loads(raw)
  if set(self.expected)!={'batch_id','target_ids','plan_sha256'} or self.version!='2.21.5' or self.expected['batch_id']!=path.parent.name or type(self.expected['plan_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',self.expected['plan_sha256']):raise ValueError('expected identity')
  number=int(path.parent.name[-3:])-1;ids=tuple('target-'+str(i).zfill(3) for i in range(number*4+1,number*4+5))
  if self.expected['target_ids']!=list(ids):raise ValueError('exact batch targets')
  self.results=path.parent/'results'
 def directory(self):
  if any(p.is_symlink() for p in (self.results,*self.results.parents)):raise ValueError('linked results')
  info=self.results.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private results')
 def fail(self):
  self.invalid=True
  try:self.directory();(self.results/'complete.json').unlink(missing_ok=True)
  except Exception:pass
 def write(self,name,value):
  self.directory();raw=json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False).encode()
  if len(raw)>49152:raise ValueError('event bound')
  fd=os.open(self.results/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 def record(self,result,event):
  try:
   host=result.host.get_name()
   if self.invalid or self.finished or host not in self.expected['target_ids'] or host in self.seen or result.task.action!='ansible.builtin.command' or result.task.no_log is True or not isinstance(result.result,dict) or result.result.get('_ansible_no_log') is True or 'censored' in result.result:raise ValueError('event scope')
   self.seen.add(host);original=result.result
   selected={k:original.get(k,d) for k,d in (('rc',None),('stdout',''),('stderr',''),('msg',''),('failed',False),('unreachable',False),('skipped',False))}
   if not all(type(selected[k]) is str and len(selected[k].encode())<=limit for k,limit in (('stdout',43692),('stderr',2048),('msg',2048))):raise ValueError('stream bound')
   if not all(type(selected[k]) is bool for k in ('failed','unreachable','skipped')) or not(selected['rc'] is None or type(selected['rc']) is int):raise ValueError('status type')
   cmd=original.get('cmd');selected['command_sha256']=hashlib.sha256(json.dumps(cmd,sort_keys=True,separators=(',',':')).encode()).hexdigest() if isinstance(cmd,list) and all(type(x)is str for x in cmd) and len(json.dumps(cmd).encode())<=16384 else None
   self.write(host+'.json',{'host':host,'event':event,'result':selected})
  except Exception:self.fail()
 def v2_runner_on_ok(self,result):self.record(result,'ok')
 def v2_runner_on_failed(self,result,ignore_errors=False):self.record(result,'failed')
 def v2_runner_on_unreachable(self,result):self.record(result,'unreachable')
 def v2_runner_on_skipped(self,result):self.record(result,'skipped')
 def v2_playbook_on_stats(self,stats):
  try:
   if self.invalid or self.finished or self.seen!=set(self.expected['target_ids']):raise ValueError('incomplete batch')
   self.finished=True;self.write('complete.json',{**self.expected,'events':4,'ansible_core_version':self.version,'status':'complete'})
  except Exception:self.fail()
'''


def require(value):
    if not value:
        raise ValueError('Fixed stock inventory request or result refused')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result); result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def decode(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= 8192)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    fields = {'schema_version', 'operation', 'run_id', 'source_revision', 'plan_sha256', 'batch_id',
              'targets', 'controller_concurrency', 'readiness_source_sha256', 'timeout_seconds'}
    require(type(value) is dict and set(value) == fields and value['schema_version'] == '1.0' and
        value['operation'] == 'stock-fleet-inventory-batch-v1' and type(value['run_id']) is str and
        str(UUID(value['run_id'])) == value['run_id'] and type(value['source_revision']) is str and
        re.fullmatch('[a-f0-9]{40}', value['source_revision']) and
        all(type(value[k]) is str and re.fullmatch('[a-f0-9]{64}', value[k]) for k in ('plan_sha256', 'readiness_source_sha256')) and
        type(value['batch_id']) is str and value['batch_id'] in BATCHES and
        type(value['controller_concurrency']) is int and 1 <= value['controller_concurrency'] <= 4 and
        type(value['timeout_seconds']) in (int, float) and math.isfinite(value['timeout_seconds']) and
        .1 <= value['timeout_seconds'] <= 25 and type(value['targets']) is list and len(value['targets']) == 4)
    addresses = set()
    for target, expected in zip(value['targets'], BATCHES[value['batch_id']]):
        require(type(target) is dict and set(target) == {'target_id', 'address'} and target['target_id'] == expected)
        address = ipaddress.ip_address(target['address'])
        require(address.version == 4 and str(address) == target['address'] and
            not any((address.is_loopback, address.is_unspecified, address.is_multicast, address.is_link_local, address.is_reserved)) and
            str(address) not in addresses)
        addresses.add(str(address))
    return value


def load_readiness(expected):
    info = READINESS.lstat()
    require(stat.S_ISREG(info.st_mode) and not any(p.is_symlink() for p in (READINESS, *READINESS.parents)) and
        info.st_nlink == 1 and info.st_size <= 65536)
    with READINESS.open('rb') as stream: raw = stream.read(65537)
    require(1 <= len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == expected)
    module = types.ModuleType('verified_stock_readiness_runtime')
    exec(compile(raw, str(READINESS), 'exec'), module.__dict__)
    return module


def private_json(path):
    info = path.lstat()
    require(not any(p.is_symlink() for p in (path, *path.parents)) and stat.S_ISREG(info.st_mode) and
        info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 49152)
    with path.open('rb') as stream: raw = stream.read(49153)
    require(len(raw) <= 49152)
    return json.loads(raw, object_pairs_hook=unique)


def collect(value, rr=None):
    import importlib.metadata
    began = time.monotonic()
    rr = load_readiness(value['readiness_source_sha256']) if rr is None else rr
    image = rr.qualified_runtime(); require(image.identity() == value['run_id'])
    root = rr.ROOT / 'stock-inventory'
    root.mkdir(mode=0o700, exist_ok=True)
    attempt = root / value['batch_id']; attempt.mkdir(mode=0o700)
    callbacks = attempt / 'callbacks'; callbacks.mkdir(mode=0o700)
    results = attempt / 'results'; results.mkdir(mode=0o700)
    ids = list(BATCHES[value['batch_id']])
    expected = {'batch_id': value['batch_id'], 'target_ids': ids, 'plan_sha256': value['plan_sha256']}
    image.write_private(attempt / 'expected.json', canonical(expected))
    image.write_private(callbacks / 'wormhole_stock_inventory.py', CALLBACK.encode())
    image.write_private(callbacks / 'wormhole_stock_inventory_quiet.py', QUIET_CALLBACK_SOURCE.encode())
    config = attempt / 'ansible.cfg'
    image.write_private(config, b'[defaults]\nhost_key_checking = True\nretry_files_enabled = False\ninterpreter_python = /usr/bin/python3\n')
    hosts = {}
    for target in value['targets']:
        private = rr.ROOT / target['target_id']
        for name in ('id_ed25519', 'known_hosts'): image.bounded_input(private / name, private=True)
        hosts[target['target_id']] = {'ansible_host': target['address'], 'ansible_port': 2222, 'ansible_user': 'wormhole',
            'ansible_connection': 'ssh', 'ansible_python_interpreter': '/usr/bin/python3',
            'ansible_ssh_args': shlex.join(rr.ssh_options({'scenario': 'healthy'}, root=private)),
            'ansible_ssh_retries': 0, 'ansible_ssh_use_tty': False, 'ansible_ssh_transfer_method': 'piped',
            'ansible_remote_tmp': '/tmp/wormhole-ansible'}
    inventory = attempt / 'inventory.json'; image.write_private(inventory, canonical({'all': {'hosts': hosts}}))
    command = ['/usr/bin/python3', '-I', '-B', '-c', STOCK_PROGRAM]
    argv = ['/opt/wormhole/venv/bin/ansible', '-i', str(inventory), 'all', '-m', 'ansible.builtin.command',
        '-a', json.dumps({'argv': command, 'expand_argument_vars': False}), '--forks', str(value['controller_concurrency']), '--timeout', '3']
    env = {**rr.environment(), 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_CALLBACK_PLUGINS': str(callbacks),
        'ANSIBLE_CALLBACKS_ENABLED': 'wormhole_stock_inventory', 'ANSIBLE_LOAD_CALLBACK_PLUGINS': '1',
        'ANSIBLE_STDOUT_CALLBACK': 'wormhole_stock_inventory_quiet',
        'PYTHONDONTWRITEBYTECODE': '1', 'WORMHOLE_STOCK_EXPECTED': str(attempt / 'expected.json')}
    rr.MAX_LOG = 4096  # Human console output is diagnostic; packets come only from the callback.
    budget = value['timeout_seconds'] - (time.monotonic() - began); require(budget > .05)
    result = rr.capture(argv, budget, env)
    complete = (set(os.listdir(results)) == {*[target + '.json' for target in ids], 'complete.json'} and
        private_json(results / 'complete.json') == {**expected, 'events': 4, 'ansible_core_version': '2.21.5', 'status': 'complete'})
    targets = []
    for target in ids:
        status, category, packet, code = 'error', 'ansible_result_invalid', None, None
        if result['timed_out']: category = 'inventory_timeout'
        elif complete:
            record = private_json(results / (target + '.json'))
            require(type(record) is dict and set(record) == {'host', 'event', 'result'} and record['host'] == target and
                record['event'] in ('ok', 'failed', 'unreachable', 'skipped') and type(record['result']) is dict)
            tree = record['result']; code = tree.get('rc')
            require(set(tree) == {'rc', 'stdout', 'stderr', 'msg', 'failed', 'unreachable', 'skipped', 'command_sha256'})
            if record['event'] != 'ok':
                status, category = ('unreachable', 'ansible_unreachable') if record['event'] == 'unreachable' else ('skipped', 'unexpected_skip') if record['event'] == 'skipped' else ('error', 'inventory_collector_failed')
            else:
                require(type(code) is int and code == 0 and tree['stderr'] == tree['msg'] == '' and
                    all(tree[key] is False for key in ('failed', 'unreachable', 'skipped')) and
                    tree['command_sha256'] == hashlib.sha256(canonical(command)).hexdigest() and type(tree['stdout']) is str and
                    0 < len(tree['stdout']) <= MAX_BASE64)
                raw = base64.b64decode(tree['stdout'], validate=True)
                require(1 <= len(raw) <= MAX_PACKET and canonical(json.loads(raw, object_pairs_hook=unique)) == raw)
                packet = tree['stdout']; status, category = 'pass', None
        targets.append({'target_id': target, 'status': status, 'category': category,
                        'module_returncode': code, 'collector_base64': packet})
    if time.monotonic() - began >= value['timeout_seconds']:
        targets = [{'target_id': target, 'status': 'error', 'category': 'inventory_timeout',
                    'module_returncode': None, 'collector_base64': None} for target in ids]
    passed = result['returncode'] == 0 and not result['timed_out'] and all(item['status'] == 'pass' for item in targets)
    reply = {**{key: value[key] for key in ('schema_version', 'run_id', 'source_revision', 'plan_sha256', 'batch_id')},
        'status': 'pass' if passed else 'fail', 'returncode': result['returncode'], 'timed_out': result['timed_out'],
        'duration_seconds': time.monotonic() - began, 'targets': targets,
        'helper_provenance': {'python_version': platform.python_version(), 'ansible_core_version': importlib.metadata.version('ansible-core')},
        'diagnostic_bytes': len(result['log'].encode()), 'diagnostic_truncated': result['truncated']}
    require(len(canonical(reply)) + 1 <= MAX_RESPONSE)
    return reply


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 11000)
        value = decode(base64.b64decode(sys.argv[1], validate=True))
        print(json.dumps(collect(value), sort_keys=True, separators=(',', ':')))
        return 0
    except Exception:
        print('{"error":{"code":"stock_inventory_runtime_refused"}}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
