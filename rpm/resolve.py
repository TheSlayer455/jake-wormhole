"""Fixed offline DNF resolution only; no package download or transaction call."""
import gzip
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
import xml.etree.ElementTree as ET

ROOT = Path('/metadata')
LOCK = Path('/recipe/lock.json')
REQUEST = Path('/request/resolve.json')
BASE = 'sha256:3bd1aa8b49948633375021c22ef5601ae644f5c08c869751ac2b542884622ea1'
BASE_CONFIG = 'sha256:9be18d9ba921714e79e390694315e3341047fe758ac79b62e671d92d4217c3fb'
MAX_JSON = 262144
RESOLVER_SECONDS = 60
START_MARKER = Path('/run/wormhole-rpm-resolve.start')
PHASE = 'bootstrap'
PHASES = ('bootstrap','startup-guard','release-wait','inputs','module-import','metadata','base-create',
    'repo-config','sack-load','rpmdb-match','request-selection','dependency-solve','transaction-export','result')


def require(value):
    if not value: raise ValueError('Offline RPM resolution refused')


def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()


def phase(value):
    global PHASE
    require(value in PHASES);PHASE=value


def failure(error):
    name=type(error).__name__
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}',name):name='UnknownError'
    return {'operation':'ubi-offline-resolution-v1','status':'failed','code':'rpm_resolution_refused',
        'phase':PHASE if PHASE in PHASES else 'bootstrap','exception_class':name}


def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result);result[key]=value
    return result


def read(path, maximum=MAX_JSON):
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1 and 0<path.stat().st_size<=maximum)
    with path.open('rb') as stream:raw=stream.read(maximum+1)
    require(0<len(raw)<=maximum)
    return raw


def record(package):
    return {'name':str(package.name),'epoch':int(package.epoch or 0),'version':str(package.version),
        'release':str(package.release),'arch':str(package.arch)}


def metadata(lock):
    sources=lock['sources'];require(sources['base_url']=='https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/' and sources['repository_id']=='wormhole-ubi9-baseos')
    items=[sources['repomd'],*sources['metadata']];require(len(items)==9)
    for item in items:
        path=item['path'];require(type(path) is str and re.fullmatch(r'repodata/[A-Za-z0-9._-]+',path) and '..' not in path)
        raw=read(ROOT/path,16*1024*1024);require(len(raw)==item['bytes'] and sha(raw)==item['sha256'])
    primary=next(x for x in sources['metadata'] if x['kind']=='primary')
    with gzip.open(ROOT/primary['path'],'rb') as stream:raw=stream.read(32*1024*1024+1)
    require(len(raw)==primary['open_bytes'] and len(raw)<=32*1024*1024 and sha(raw)==primary['open_sha256'] and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper())
    ns={'c':'http://linux.duke.edu/metadata/common'};catalog={}
    nodes=ET.fromstring(raw).findall('c:package',ns);require(0<len(nodes)<=8192)
    for node in nodes:
        arch=node.findtext('c:arch',namespaces=ns)
        if arch not in ('x86_64','noarch'):continue
        version=node.find('c:version',ns);checksum=node.find('c:checksum',ns)
        row={'name':node.findtext('c:name',namespaces=ns),'epoch':int(version.get('epoch')),'version':version.get('ver'),
            'release':version.get('rel'),'arch':arch,'path':node.find('c:location',ns).get('href'),
            'bytes':int(node.find('c:size',ns).get('package')),'sha256':checksum.text,'repo_id':sources['repository_id']}
        require(checksum.get('type')=='sha256' and re.fullmatch(r'Packages/[a-z0-9]/[A-Za-z0-9+_.~:-]+\.rpm',row['path']) and
            re.fullmatch('[a-f0-9]{64}',row['sha256']) and 0<row['bytes']<=64*1024*1024)
        key=canonical({k:row[k] for k in ('name','epoch','version','release','arch')});require(key not in catalog);catalog[key]=row
    return catalog


def installed_packages(rpm_module):
    values=[];transaction=rpm_module.TransactionSet('/')
    try:
        for header in transaction.dbMatch():
            require(len(values)<1024)
            row={'name':header['name'],'epoch':0 if header['epoch'] is None else header['epoch'],
                'version':header['version'],'release':header['release'],'arch':header['arch']}
            require(type(row['epoch']) is int and 0<=row['epoch']<=2**31 and
                all(type(row[k]) is str and 0<len(row[k])<=240 and not any(ord(c)<32 or ord(c)==127 for c in row[k]) for k in ('name','version','release')) and
                (type(row['arch']) is str and 0<len(row['arch'])<=40 or row['name']=='gpg-pubkey' and row['arch'] is None))
            values.append(row)
    finally:transaction.closeDB()
    require(values and len({canonical(x) for x in values})==len(values))
    return sorted(values,key=canonical)


def resolve(request, lock, dnf_module, rpm_module):
    sources=lock['sources'];require(request['operation']=='ubi-offline-resolution-request-v1' and request['base_image_id']==BASE and
        request['sources_sha256']==sha(canonical(sources)) and canonical(request['requested_packages'])==canonical(sources['requested_packages']) and
        sources['policy']['allow_erasing'] is False and sources['policy']['plugins'] is False and sources['policy']['install_weak_deps'] is False)
    phase('metadata');catalog=metadata(lock)
    phase('base-create')
    with dnf_module.Base() as base:
        # Do not read ambient config/repository files or initialize plugins.
        phase('repo-config')
        base.conf.plugins=False;base.conf.install_weak_deps=False;base.conf.best=True;base.conf.strict=True
        base.conf.cachedir='/tmp/wormhole-rpm-resolver/cache';base.conf.persistdir='/tmp/wormhole-rpm-resolver/persist';base.conf.logdir='/tmp/wormhole-rpm-resolver/log'
        base.conf.substitutions['releasever']='9';base.conf.substitutions['basearch']='x86_64'
        require(not list(base.repos.iter_enabled()))
        repo=base.repos.add_new_repo(sources['repository_id'],base.conf,baseurl=['file:///metadata'])
        repo.skip_if_unavailable=False;repo.metadata_expire=-1
        phase('sack-load');base.fill_sack(load_system_repo=True,load_available_repos=True)
        # Match the same RPM DB source as the public base probe, including key
        # pseudo-packages which DNF's @System view can omit.
        phase('rpmdb-match');installed=installed_packages(rpm_module)
        require(canonical(installed)==canonical(request['installed_packages']) and sha(canonical(installed))==request['base_packages_sha256'])
        phase('request-selection')
        for expected in request['requested_packages']:
            matches=[x for x in base.sack.query().filter(name=expected['name']) if canonical(record(x))==canonical(expected)]
            require(matches)
            available=[x for x in matches if not x.installed and x.reponame==sources['repository_id']]
            if available:require(len(available)==1);base.package_install(available[0],strict=True)
            else:require(any(x.installed for x in matches))
        phase('dependency-solve');base.resolve(allow_erasing=False)
        require(base.transaction is not None and not list(base.transaction.remove_set))
        phase('transaction-export')
        packages=[]
        for package in base.transaction.install_set:
            key=canonical(record(package));require(package.reponame==sources['repository_id'] and key in catalog)
            row=catalog[key];require(int(package.downloadsize)==row['bytes'])
            packages.append(row)
        packages.sort(key=canonical)
        require(len(packages)<=128 and len({p['path'] for p in packages})==len(packages) and sum(p['bytes'] for p in packages)<=512*1024*1024)
    return {'operation':'ubi-offline-resolution-v1','status':'passed','base_image_id':BASE,'request_sha256':sha(canonical(request)),
        'base_packages_sha256':request['base_packages_sha256'],'sources_sha256':request['sources_sha256'],
        'requested_packages':request['requested_packages'],'packages':packages,'remove_packages':[]}


def emit_output(raw):
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()


def supervise(action, seconds=RESOLVER_SECONDS, *, grace_seconds=.2):
    """PID1 owns a finite fixed solver child; this is not a general sandbox."""
    sys.stdout.flush();sys.stderr.flush()
    reader,writer=os.pipe();interrupted=[False];child=os.fork()
    if child==0:
        os.close(reader);os.dup2(writer,1);os.dup2(writer,2);os.close(writer)
        try:
            os.setsid();signal.signal(signal.SIGTERM,signal.SIG_DFL)
            code=action()
        except BaseException as error:
            print(canonical(failure(error)).decode(),flush=True);code=2
        sys.stdout.flush();sys.stderr.flush();os._exit(code if type(code) is int and 0<=code<=255 else 2)
    os.close(writer);os.set_blocking(reader,False)
    previous=signal.signal(signal.SIGTERM,lambda *_:interrupted.__setitem__(0,True))
    deadline=time.monotonic()+seconds;reaped=False;status=None;output=bytearray();eof=False;overflow=False
    def collect():
        nonlocal reaped,status
        if not reaped:
            pid,value=os.waitpid(child,os.WNOHANG)
            if pid:reaped,status=True,value
    def terminate(number):
        try:os.killpg(child,number)
        except (ProcessLookupError,PermissionError):
            if not reaped:
                try:os.kill(child,number)
                except (ProcessLookupError,PermissionError):pass
    try:
        while not interrupted[0] and time.monotonic()<deadline:
            collect()
            if select.select([reader],[],[],min(.02,max(0,deadline-time.monotonic())))[0]:
                try:raw=os.read(reader,65536)
                except BlockingIOError:raw=None
                if raw==b'':eof=True
                elif raw:
                    if len(output)+len(raw)>MAX_JSON+1:overflow=True;break
                    output.extend(raw)
            if reaped and eof:break
        outcome=143 if interrupted[0] else 2 if overflow else 124 if not (reaped and eof) or time.monotonic()>=deadline else os.waitstatus_to_exitcode(status)
        terminate(signal.SIGTERM);end=time.monotonic()+grace_seconds
        while not reaped and time.monotonic()<end:collect();time.sleep(.01)
        terminate(signal.SIGKILL);end=time.monotonic()+1
        while not reaped and time.monotonic()<end:collect();time.sleep(.01)
        if not overflow and reaped and eof:emit_output(bytes(output))
        else:emit_output(b'{"operation":"ubi-offline-resolution-v1","status":"failed","code":"rpm_resolution_bound"}\n')
        return outcome if outcome>=0 else 128-outcome
    finally:
        os.close(reader);signal.signal(signal.SIGTERM,previous)


def solver_main():
    phase('startup-guard')
    require(len(sys.argv)==1 and Path('/.dockerenv').is_file() and os.geteuid()==0 and
        not any(Path(p).exists() for p in ('/var/run/docker.sock','/run/docker.sock')))
    phase('release-wait');wait_for_start();phase('inputs')
    lock_raw=read(LOCK,65536);request_raw=read(REQUEST);lock=json.loads(lock_raw,object_pairs_hook=unique);request=json.loads(request_raw,object_pairs_hook=unique)
    require(request['lock_sha256']==sha(lock_raw) and request['run_id']==os.environ.get('WORMHOLE_RUN_ID') and
        lock['base']['image_id']==BASE and lock['base']['config_digest']==BASE_CONFIG and
        lock['target_family']=='ubi9-rpm' and lock['platform']=='linux/amd64')
    phase('module-import');import dnf,rpm
    result=resolve(request,lock,dnf,rpm)
    phase('result')
    raw=canonical(result);require(len(raw)<=MAX_JSON);print(raw.decode())
    return 0


def wait_for_start(seconds=15):
    """Fixed release after the caller verifies this live container's cgroups."""
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        require(not START_MARKER.is_symlink())
        if START_MARKER.exists():
            before=START_MARKER.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.geteuid() and stat.S_IMODE(before.st_mode)==0o600 and before.st_size==2)
            descriptor=os.open(START_MARKER,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                actual=os.fstat(descriptor)
                require((actual.st_dev,actual.st_ino)==(before.st_dev,before.st_ino) and os.read(descriptor,3)==b'1\n')
            finally:os.close(descriptor)
            require(time.monotonic()<deadline);return
        time.sleep(.02)
    require(False)


def main():
    require(os.getpid()==1 and os.environ.get('WORMHOLE_ROLE')=='rpm-resolver')
    return supervise(solver_main)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print(json.dumps({'operation':'ubi-offline-resolution-v1','status':'failed','code':'rpm_resolution_refused'}));raise SystemExit(2)
