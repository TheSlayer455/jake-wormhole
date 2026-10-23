"""Fixed public UBI metadata/RPM cache; never installs or executes packages."""
import bz2
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from uuid import UUID

from .runs import Run, RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, read_json, source_identity
from .stages import _run_process

LOCK = SOURCE_ROOT / 'rpm/lock.json'
URL = 'https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/'
BASE_IMAGE = 'sha256:3bd1aa8b49948633375021c22ef5601ae644f5c08c869751ac2b542884622ea1'
BASE_CONFIG = 'sha256:9be18d9ba921714e79e390694315e3341047fe758ac79b62e671d92d4217c3fb'
EULA_URL = 'https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf'
EULA_NAME = 'UBI-EULA-20190422.pdf'
EULA_BYTES = 248785
EULA_SHA256 = 'a07025b9f5b71a816febe6ac76f21c9f759c806fa0a66874af90a50c3293f1b6'
TIMEOUT = 180
CHUNK = 65536
POLICY = {'worker_seconds': TIMEOUT, 'metadata_file_bytes': 16*1024*1024,
    'metadata_total_bytes': 32*1024*1024, 'metadata_open_file_bytes': 32*1024*1024,
    'metadata_open_total_bytes': 128*1024*1024, 'rpm_file_bytes': 64*1024*1024,
    'rpm_total_bytes': 512*1024*1024, 'rpm_count': 128, 'resolution_bytes': 262144,
    'allow_erasing': False, 'install_weak_deps': False, 'plugins': False}
REQUESTED = [{'name':'openssh-server','epoch':0,'version':'9.9p1','release':'13.el9_8','arch':'x86_64'},
    {'name':'python3','epoch':0,'version':'3.9.25','release':'7.el9_8.3','arch':'x86_64'},
    {'name':'shadow-utils','epoch':2,'version':'4.9','release':'16.el9','arch':'x86_64'}]
WORKER = """import json,sys
from wormhole.runs import Run
from wormhole.rpm_source import _worker
try: _worker(Run(sys.argv[1],sys.argv[2]),sys.argv[3])
except Exception as error:
 print(json.dumps({'code':getattr(error,'code','rpm_source_failed')}))
 raise SystemExit(2)
"""


class SourceError(RunError):
    pass


def require(condition, code):
    if not condition:
        raise SourceError(code, 'Pinned UBI source preparation refused; preserve private evidence and exact inputs.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw): return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'rpm_duplicate_json_key'); result[key] = value
    return result


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= POLICY['resolution_bytes'], 'rpm_resolution_bound')
    try:
        return json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise SourceError('rpm_invalid_json', 'Bounded exact JSON is required.') from None


def safe_relative(value):
    return type(value) is str and len(value) <= 240 and re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*', value) is not None and all(x not in ('.','..') for x in value.split('/'))


def safe_package_path(value):
    if type(value) is not str or len(value)>240 or re.fullmatch(r'Packages/[a-z0-9]/[A-Za-z0-9][A-Za-z0-9+_.~-]*\.rpm',value) is None:return False
    stem=value.rsplit('/',1)[1].split('.',1)[0].lower()
    return re.fullmatch(r'con|prn|aux|nul|com[1-9]|lpt[1-9]',stem) is None


def digest_pin(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def lock_bytes():
    _owned_source = LOCK
    require(not any(p.is_symlink() for p in (_owned_source,*_owned_source.parents)), 'rpm_lock_path')
    require(LOCK.is_file() and LOCK.stat().st_size<=65536,'rpm_lock_bound')
    with LOCK.open('rb') as stream:raw=stream.read(65537)
    require(len(raw)<=65536,'rpm_lock_bound')
    return raw


def load_lock(supplied=None):
    value = parse(lock_bytes()); sources = value['sources']
    require(value['schema_version'] == '1.0' and value['target_family'] == 'ubi9-rpm' and
        value['platform'] == 'linux/amd64' and value['base']['image_id'] == BASE_IMAGE and
        value['base']['config_digest'] == BASE_CONFIG and
        sources['base_url'] == URL and sources['repository_id'] == 'wormhole-ubi9-baseos' and
        canonical(sources['policy']) == canonical(POLICY) and canonical(sources['requested_packages']) == canonical(REQUESTED), 'rpm_source_lock_invalid')
    require(supplied is None or canonical(supplied) == canonical(value), 'rpm_source_lock_changed')
    items = [sources['repomd'],*sources['metadata']]
    require(type(sources['metadata']) is list and len(sources['metadata']) == 8 and
        sources['repomd']['path'] == 'repodata/repomd.xml' and
        sources['repomd']['sha256'] == 'd1739e3e97d5200cc684e7a6a0f3eba8ca0a1aa9b60bbc4bde5c070ec08ecf99' and
        len({x['path'] for x in items}) == len(items), 'rpm_metadata_lock_invalid')
    total, expanded = 0, 0
    for item in items:
        require(safe_relative(item['path']) and item['path'].startswith('repodata/') and digest_pin(item['sha256']) and
            type(item['bytes']) is int and 0 < item['bytes'] <= POLICY['metadata_file_bytes'], 'rpm_metadata_lock_invalid')
        total += item['bytes']
        if 'open_bytes' in item:
            require(type(item['open_bytes']) is int and 0 < item['open_bytes'] <= POLICY['metadata_open_file_bytes'] and
                digest_pin(item['open_sha256']) and item['path'].endswith(('.gz','.bz2')), 'rpm_metadata_lock_invalid')
            expanded += item['open_bytes']
    require(total <= POLICY['metadata_total_bytes'] and expanded <= POLICY['metadata_open_total_bytes'], 'rpm_metadata_lock_bound')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise SourceError('rpm_redirect_refused', 'Only exact official pinned source URLs are allowed.')


def fetch_eula(destination, *, opener=None):
    """One exact official license artifact; never a caller-supplied URL."""
    if opener is None:opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open
    require(not destination.exists() and not destination.is_symlink(),'rpm_eula_exists')
    partial=destination.with_name(destination.name+'.partial');digest=hashlib.sha256();total=0
    with opener(EULA_URL,timeout=20) as response:
        require(response.geturl()==EULA_URL,'rpm_redirect_refused')
        with os.fdopen(os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as output:
            while raw:=response.read1(CHUNK):
                total+=len(raw);require(total<=EULA_BYTES,'rpm_eula_bound');digest.update(raw);output.write(raw)
            output.flush();os.fsync(output.fileno())
    require(total==EULA_BYTES and digest.hexdigest()==EULA_SHA256,'rpm_eula_changed');os.replace(partial,destination)


def fetch(item, destination, *, opener=None):
    require((safe_relative(item['path']) and item['path'].startswith('repodata/') or safe_package_path(item['path'])) and digest_pin(item['sha256']) and
        type(item['bytes']) is int and 0 < item['bytes'] <= POLICY['rpm_file_bytes'], 'rpm_download_invalid')
    url = URL + item['path']
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open
    partial = destination.with_name(destination.name+'.partial')
    require(not destination.exists() and not destination.is_symlink(), 'rpm_cache_exists')
    digest, total = hashlib.sha256(), 0
    with opener(url, timeout=20) as response:
        require(response.geturl() == url, 'rpm_redirect_refused')
        with os.fdopen(os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as output:
            while raw := response.read1(CHUNK):
                total += len(raw); require(total <= item['bytes'], 'rpm_download_size')
                output.write(raw); digest.update(raw)
            output.flush(); os.fsync(output.fileno())
    require(total == item['bytes'] and digest.hexdigest() == item['sha256'], 'rpm_download_hash')
    os.replace(partial,destination)


def hash_file(path, item):
    _owned(path); require(path.stat().st_size == item['bytes'], 'rpm_cache_size')
    digest,total=hashlib.sha256(),0
    with path.open('rb') as stream:
        while raw := stream.read(CHUNK):
            total+=len(raw); require(total<=item['bytes'],'rpm_cache_size');digest.update(raw)
    require(total == item['bytes'] and digest.hexdigest()==item['sha256'],'rpm_cache_hash')


def expanded(path, item):
    if 'open_bytes' not in item:
        return None
    opener = gzip.open if item['path'].endswith('.gz') else bz2.open
    total,digest=0,hashlib.sha256()
    with opener(path,'rb') as stream:
        while raw := stream.read1(CHUNK):
            total+=len(raw);require(total<=item['open_bytes'] and total<=POLICY['metadata_open_file_bytes'],'rpm_metadata_expansion_bound');digest.update(raw)
    require(total==item['open_bytes'] and digest.hexdigest()==item['open_sha256'],'rpm_metadata_open_hash')


def xml_bytes(path, maximum):
    with gzip.open(path,'rb') if path.name.endswith('.gz') else path.open('rb') as stream:
        raw=stream.read(maximum+1)
    require(0<len(raw)<=maximum and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),'rpm_xml_bound')
    return raw


def metadata_items(lock): return [lock['sources']['repomd'],*lock['sources']['metadata']]


def validate_metadata(run, lock=None):
    lock=load_lock(lock);folder=run.file('private/rpm-sources/metadata');_owned(folder,directory=True)
    expected={x['path'] for x in metadata_items(lock)}
    actual=set()
    directories=set()
    for parent,dirs,files in os.walk(folder,followlinks=False):
        for name in dirs:
            path=Path(parent)/name;_owned(path,directory=True);directories.add(path.relative_to(folder).as_posix())
        for name in files:
            path=Path(parent)/name;_owned(path);actual.add(path.relative_to(folder).as_posix())
    require(actual==expected and directories=={'repodata'},'rpm_metadata_file_set')
    for item in metadata_items(lock):hash_file(folder/item['path'],item);expanded(folder/item['path'],item)
    ns={'r':'http://linux.duke.edu/metadata/repo'}
    root=ET.fromstring(xml_bytes(folder/'repodata/repomd.xml',131072));found=[]
    for node in root.findall('r:data',ns):
        checksum=node.find('r:checksum',ns);opened=node.find('r:open-checksum',ns)
        require(checksum is not None and checksum.get('type')=='sha256','rpm_metadata_contract')
        row={'kind':node.get('type'),'path':node.find('r:location',ns).get('href'),
            'bytes':int(node.findtext('r:size',namespaces=ns)),'sha256':checksum.text}
        if opened is not None:
            require(opened.get('type')=='sha256','rpm_metadata_contract')
            row.update(open_bytes=int(node.findtext('r:open-size',namespaces=ns)),open_sha256=opened.text)
        found.append(row)
    require(canonical(found)==canonical(lock['sources']['metadata']),'rpm_metadata_contract')
    return folder


def package_catalog(run, lock=None):
    lock=load_lock(lock);folder=validate_metadata(run,lock)
    primary=next(x for x in lock['sources']['metadata'] if x['kind']=='primary')
    root=ET.fromstring(xml_bytes(folder/primary['path'],POLICY['metadata_open_file_bytes']))
    ns={'c':'http://linux.duke.edu/metadata/common'};catalog={}
    nodes=root.findall('c:package',ns);require(0<len(nodes)<=8192,'rpm_catalog_bound')
    for node in nodes:
        arch=node.findtext('c:arch',namespaces=ns)
        if arch not in ('x86_64','noarch'):continue
        version=node.find('c:version',ns);checksum=node.find('c:checksum',ns)
        row={'name':node.findtext('c:name',namespaces=ns),'epoch':int(version.get('epoch')),'version':version.get('ver'),
            'release':version.get('rel'),'arch':arch,'path':node.find('c:location',ns).get('href'),
            'bytes':int(node.find('c:size',ns).get('package')),'sha256':checksum.text,'repo_id':lock['sources']['repository_id']}
        require(checksum.get('type')=='sha256' and safe_package_path(row['path']) and
            digest_pin(row['sha256']) and 0<row['bytes']<=POLICY['rpm_file_bytes'],'rpm_catalog_invalid')
        key=canonical({k:row[k] for k in ('name','epoch','version','release','arch')})
        require(key not in catalog,'rpm_catalog_duplicate');catalog[key]=row
    return catalog


def guard(run):
    manifest=run.manifest()
    require(manifest['mode']=='container-reference' and manifest['source_dirty'] is False and
        source_identity()==(manifest['source_revision'],False),'rpm_source_identity')


def _worker(run, operation):
    guard(run);lock=load_lock();root=run.file('private/rpm-sources');root.mkdir(mode=0o700,exist_ok=True);_owned(root,directory=True)
    if operation=='metadata':
        folder=root/'metadata';folder.mkdir(mode=0o700)
        (folder/'repodata').mkdir(mode=0o700)
        for item in metadata_items(lock):fetch(item,folder/item['path'])
        validate_metadata(run,lock)
    elif operation=='packages':
        request=read_json(root/'resolve-request.json')
        resolution_path=root/'resolution.json';_owned(resolution_path)
        with resolution_path.open('rb') as stream:raw=stream.read(POLICY['resolution_bytes']+1)
        result=validate_resolution(run,raw,request,lock)
        folder=root/'packages';folder.mkdir(mode=0o700)
        for item in result['packages']:fetch(item,folder/Path(item['path']).name)
    elif operation=='eula':fetch_eula(root/EULA_NAME)
    else:require(False,'rpm_worker_operation')


def supervised(run, operation):
    require(operation in ('metadata','packages','eula'),'rpm_worker_operation')
    guard(run);lock=load_lock();identity=sha(lock_bytes())
    result=_run_process((sys.executable,'-c',WORKER,str(run.workspace),run.id,operation),cwd=SOURCE_ROOT,timeout=TIMEOUT)
    atomic_bytes(run.file('private/rpm-'+operation+'-preparation.log'),result['log'],limit=65536)
    require(result['status']=='pass' and not result['log_truncated'],
        'rpm_source_timeout' if result['status']=='timeout' else 'rpm_source_preparation_failed')
    guard(run);require(sha(lock_bytes())==identity,'rpm_source_lock_changed')
    return lock


def prepare_metadata(run, lock=None):
    load_lock(lock);supervised(run,'metadata');return validate_metadata(run,lock)


def validate_eula(run):
    path=run.file('private/rpm-sources/'+EULA_NAME)
    hash_file(path,{'bytes':EULA_BYTES,'sha256':EULA_SHA256})
    return path


def prepare_eula(run):
    guard(run);path=run.file('private/rpm-sources/'+EULA_NAME)
    if not path.exists() and not path.is_symlink():supervised(run,'eula')
    return validate_eula(run)


def validate_observation(observation):
    # Origin/capture checks belong to read_base_observation; this normalizes its
    # installed-package records without rewriting the original observed body.
    require(type(observation) is dict and observation.get('status')=='observed' and
        observation.get('operation')=='ubi-base-observation-v1' and
        type(observation.get('installed_packages')) is list and 0<len(observation['installed_packages'])<=1024,'rpm_base_observation_required')
    packages=observation['installed_packages']
    for row in packages:
        require(type(row) is dict and set(row)=={'name','epoch','version','release','arch'} and type(row['epoch']) is int and
            0<=row['epoch']<=2**31 and all(type(row[k]) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.~:-]{0,239}',row[k]) for k in ('name','version','release')) and
            (type(row['arch']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,39}|\(none\)',row['arch']) or
                row['arch'] is None and row['name']=='gpg-pubkey'),'rpm_base_packages_invalid')
    require(len({canonical(x) for x in packages})==len(packages),'rpm_base_packages_invalid')
    return sorted(packages,key=canonical)


def resolve_request(run, lock, base_observation, *, base_run=None):
    from .rpm_target import read_base_observation
    base_run=run if base_run is None else base_run
    require(base_run.workspace==run.workspace,'rpm_base_observation_scope')
    guard(run);lock=load_lock(lock);validate_metadata(run,lock)
    observed=read_base_observation(base_run)
    require(canonical(observed)==canonical(base_observation),'rpm_base_observation_changed')
    require(observed['dnf']['available'] is True and observed['dnf']['base_api'] is True and
        observed['dnf']['version']=='4.14.0','rpm_resolver_unsupported')
    packages=validate_observation(observed)
    receipt=read_json(base_run.file('evidence/rpm-base-probe.json'))
    value={**common(run.manifest()),'operation':'ubi-offline-resolution-request-v1','base_image_id':BASE_IMAGE,
        'lock_sha256':sha(lock_bytes()),'base_observation_sha256':sha(canonical(base_observation)),
        'base_packages_sha256':sha(canonical(packages)),'installed_packages':packages,
        'base_probe':{key:receipt[key] for key in ('run_id','source_revision','recipe_sha256','capture_sha256')},
        'sources_sha256':sha(canonical(lock['sources'])),'requested_packages':REQUESTED}
    path=run.file('private/rpm-sources/resolve-request.json')
    require(not path.exists() or canonical(read_json(path))==canonical(value),'rpm_resolution_request_changed')
    if not path.exists():atomic_json(path,value)
    return value


def validate_resolution(run, raw, request, lock=None):
    lock=load_lock(lock);value=parse(raw);base=common(run.manifest())
    require(type(request) is dict and set(request)==set(base)|{'operation','base_image_id','lock_sha256','base_observation_sha256',
        'base_packages_sha256','installed_packages','base_probe','sources_sha256','requested_packages'},'rpm_resolution_request_changed')
    reference=request['base_probe']
    require(type(reference) is dict and set(reference)=={'run_id','source_revision','recipe_sha256','capture_sha256'} and
        type(reference['run_id']) is str and str(UUID(reference['run_id']))==reference['run_id'] and
        type(reference['source_revision']) is str and re.fullmatch('[a-f0-9]{40}',reference['source_revision']) and
        all(digest_pin(reference[k]) for k in ('recipe_sha256','capture_sha256')) and digest_pin(request['base_observation_sha256']),
        'rpm_resolution_request_changed')
    require(canonical({k:request[k] for k in base})==canonical(base) and request['operation']=='ubi-offline-resolution-request-v1' and
        request['base_image_id']==BASE_IMAGE and request['lock_sha256']==sha(lock_bytes()) and
        request['base_packages_sha256']==sha(canonical(request['installed_packages'])) and
        request['sources_sha256']==sha(canonical(lock['sources'])) and canonical(request['requested_packages'])==canonical(REQUESTED),'rpm_resolution_request_changed')
    fields={'operation','status','base_image_id','request_sha256','base_packages_sha256','sources_sha256','requested_packages','packages','remove_packages'}
    require(type(value) is dict and set(value)==fields and value['operation']=='ubi-offline-resolution-v1' and value['status']=='passed' and
        value['base_image_id']==BASE_IMAGE and value['request_sha256']==sha(canonical(request)) and
        value['base_packages_sha256']==request['base_packages_sha256'] and value['sources_sha256']==request['sources_sha256'] and
        canonical(value['requested_packages'])==canonical(REQUESTED) and value['remove_packages']==[] and
        type(value['packages']) is list and len(value['packages'])<=POLICY['rpm_count'],'rpm_resolution_invalid')
    catalog=package_catalog(run,lock);names=set();total=0
    for package in value['packages']:
        key=canonical({k:package[k] for k in ('name','epoch','version','release','arch')})
        require(key in catalog and canonical(package)==canonical(catalog[key]) and package['path'] not in names,'rpm_resolution_package_invalid')
        names.add(package['path']);total+=package['bytes']
    installed={canonical(x) for x in request['installed_packages']}
    planned={canonical({k:p[k] for k in ('name','epoch','version','release','arch')}) for p in value['packages']}
    require(all(canonical(x) in installed|planned for x in REQUESTED),'rpm_resolution_requested_missing')
    require(total<=POLICY['rpm_total_bytes'] and len({Path(p).name for p in names})==len(names),'rpm_resolution_bound')
    return value


def prepare_packages(run, lock, resolution):
    request=read_json(run.file('private/rpm-sources/resolve-request.json'))
    from .rpm_target import read_base_observation
    reference=request['base_probe'];base_run=Run(run.workspace,reference['run_id'])
    require(set(reference)=={'run_id','source_revision','recipe_sha256','capture_sha256'},'rpm_base_observation_changed')
    observed=read_base_observation(base_run);receipt=read_json(base_run.file('evidence/rpm-base-probe.json'))
    require(canonical(reference)==canonical({key:receipt[key] for key in reference}) and
        sha(canonical(observed))==request['base_observation_sha256'] and
        sha(canonical(validate_observation(observed)))==request['base_packages_sha256'],'rpm_base_observation_changed')
    value=validate_resolution(run,canonical(resolution),request,lock)
    path=run.file('private/rpm-sources/resolution.json')
    require(not path.exists() or canonical(read_json(path))==canonical(value),'rpm_resolution_changed')
    if not path.exists():atomic_json(path,value)
    supervised(run,'packages');return validate_packages(run,lock,value)


def validate_packages(run, lock, resolution):
    request=read_json(run.file('private/rpm-sources/resolve-request.json'))
    value=validate_resolution(run,canonical(resolution),request,lock);folder=run.file('private/rpm-sources/packages');_owned(folder,directory=True)
    require(set(os.listdir(folder))=={Path(x['path']).name for x in value['packages']},'rpm_package_file_set')
    for item in value['packages']:hash_file(folder/Path(item['path']).name,item)
    return folder
