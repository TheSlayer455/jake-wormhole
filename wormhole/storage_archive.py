"""Selective encrypted off-host retention, using Store's existing ownership/cleanup.

The authenticated workstation pulls bytes; only fresh decrypted destination
readback permits reclamation. No listener, network calls or remote restore inside
the hypervisor admission/resolve paths. Runtime configuration is owner-private.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

from .runs import RunError, _owned, _path_chain, atomic_json, now, read_json, run_id, workspace_path
from .storage import Store, admission, require, signature
from .vm_inputs import sha256

SHA = re.compile(r'[a-f0-9]{64}')
DIAGNOSTICS = ('console.log', 'terraform-apply.log', 'terraform-cleanup.log')
ASSESSMENTS = ('assessment/arf.xml', 'assessment/xccdf.xml', 'assessment/report.html')
EVIDENCE = ('inputs/build-manifest.json', 'installed-svd.json', 'installed-svd.txt',
            'build-svd/svd.json', 'build-svd/svd.txt')


def directory(store):
    return store.infrastructure/'storage-archive'


def configuration(store):
    path = store.infrastructure/'archive-config.json'
    if not path.exists():
        return None
    value = read_json(path)
    require(set(value) == {'schema_version', 'archive_id', 'keep_local_digests'} and
            value['schema_version'] == '1.0', 'archive_configuration_invalid')
    run_id(value['archive_id'])
    require(type(value['keep_local_digests']) is list and
            all(type(x) is str and SHA.fullmatch(x) for x in value['keep_local_digests']),
            'archive_configuration_invalid')
    return value


def record(store, digest):
    require(type(digest) is str and SHA.fullmatch(digest), 'archive_digest_invalid')
    value = read_json(directory(store)/(digest+'.json'))
    config = configuration(store)
    require(config and value['archive_id'] == config['archive_id'] and
            value['sha256'] == digest and 0 < value['bytes'] <= 32*1024**3,
            'archive_destination_changed')
    return value


def archived(store, identifier, digest):
    path=directory(store)/(digest+'.json')
    if not path.exists():return False
    value=record(store,digest)
    require(value['state']=='committed' and value.get('receipt',{}).get('verified') is True,'archive_not_verified')
    return any(s['run_id']==identifier and s['kind']=='candidate' for s in value['sources'])


def restored_candidate(store,digest):
    if not (directory(store)/(digest+'.json')).exists():return None
    for source in record(store,digest)['sources']:
        if source['kind']!='candidate':continue
        path=source_path(store,source)
        if path.exists():
            store.checked(path,[])
            require(store.digest(path)==digest,'storage_candidate_changed')
            return path
    return None


def source_path(store, source):
    identifier = run_id(source['run_id'])
    kind, name = source['kind'], source['name']
    if kind == 'candidate':
        require(name == 'candidate.iso')
        return store.shared/identifier/name
    if kind == 'probe':
        require(name == 'artifact.bin')
        return store.root/'archive-probes'/identifier/name
    require(kind in {'diagnostic', 'assessment', 'evidence'} and name in DIAGNOSTICS+ASSESSMENTS+EVIDENCE)
    return store.runs/identifier/name


def protected(store,references=None):
    """Unknown historical attempts pin their shared bytes even after teardown."""
    pins = set(configuration(store)['keep_local_digests'])
    for run in store.runs.iterdir():
        try:
            value = read_json(run/'result.json')
            if value.get('outcome') in {'unknown', 'running'} or value.get('lab_iso_qualified'):
                pins.add(value.get('build', {}).get('candidate_sha256'))
            if references is not None:
                try:store.proof(run.name,references)
                except (RunError,OSError,KeyError,ValueError):pins.add(value.get('build',{}).get('candidate_sha256'))
        except (RunError, OSError, ValueError):
            try:pins.add(read_json(run/'inputs/build-manifest.json')['candidate_sha256'])
            except (RunError, OSError, ValueError):pass
    return pins


def preview(store, references, *, current=None):
    config = configuration(store)
    if not config:return {'configured': False, 'objects': [], 'blocked': []}
    objects, blocked = {}, []
    pins = protected(store)

    def add(path, identifier, kind, name, reclaim):
        info = store.checked(path, references)
        if not 0 < info[2] <= 32*1024**3:return
        digest = store.digest(path)
        value = objects.setdefault(digest, {'schema_version': '1.0', 'archive_id': config['archive_id'],
            'sha256': digest, 'bytes': info[2], 'state': 'pending', 'sources': []})
        value['sources'].append({'run_id': identifier, 'kind': kind, 'name': name,
            'signature': info, 'reclaim': reclaim and digest not in pins})

    for run in sorted(store.runs.iterdir()):
        try:
            _, value, manifest = store.proof(run.name, references, current=current)
            require(value['outcome'] not in {'unknown','running'} and
                    not value.get('lab_iso_qualified'), 'archive_run_protected')
            candidate = store.shared/run.name/'candidate.iso'
            if candidate.exists():
                require(store.digest(candidate) == manifest['candidate_sha256'])
                add(candidate, run.name, 'candidate', candidate.name, True)
            for name in DIAGNOSTICS+ASSESSMENTS+EVIDENCE:
                path = run/name
                if path.is_file():add(path, run.name, 'evidence' if name in EVIDENCE else 'assessment' if name in ASSESSMENTS else 'diagnostic',
                                      name, name in DIAGNOSTICS)
        except (RunError, OSError, ValueError, KeyError) as error:
            blocked.append({'run_id': run.name, 'reason': getattr(error,'code',type(error).__name__)})
            try:pins.add(read_json(run/'inputs/build-manifest.json')['candidate_sha256'])
            except (RunError,OSError,ValueError):pass
    probes = store.root/'archive-probes'
    for probe in sorted(probes.iterdir() if probes.exists() else []):
        try:
            owner = read_json(probe/'owner.json')
            require(owner == {'application':'jake-wormhole','schema_version':'1.0',
                'kind':'archive-roundtrip-probe','run_id':run_id(probe.name)})
            path = probe/'artifact.bin'
            if path.exists():add(path, probe.name, 'probe', path.name, True)
        except (RunError,OSError,ValueError) as error:
            blocked.append({'run_id':probe.name,'reason':getattr(error,'code',type(error).__name__)})
    for value in objects.values():
        for source in value['sources']:source['reclaim']=source['reclaim'] and value['sha256'] not in pins
    return {'configured':True,'archive_id':config['archive_id'],'objects':list(objects.values()),
            'blocked':blocked,'reclaimable_after_verification_bytes':sum(s['signature'][3]
                for v in objects.values() for s in v['sources'] if s['reclaim'])}


def queue(store, references, *, current=None):
    plan = preview(store, references, current=current)
    if not plan['configured']:return plan
    workspace_path(directory(store), create=True)
    for value in plan['objects']:
        path = directory(store)/(value['sha256']+'.json')
        if path.exists():
            old = record(store, value['sha256'])
            # Retain locations of reclaimed sources and immutable original receipt.
            sources = {(s['run_id'],s['kind'],s['name']):s for s in old['sources']}
            sources.update({(s['run_id'],s['kind'],s['name']):s for s in value['sources']})
            value = {**old, 'sources':list(sources.values())}
        atomic_json(path, value)
    return plan


def status(store):
    config = configuration(store)
    if not config:return {'configured':False}
    values = [record(store,p.stem) for p in directory(store).glob('*.json')]
    return {'configured':True,'archive_id':config['archive_id'],
        'availability':'not-probed; workstation initiates authenticated reconciliation',
        'verified_archived_bytes':sum(v['bytes'] for v in values if v['state']=='committed'),
        'pending_bytes':sum(v['bytes'] for v in values if v['state']!='committed'),
        'failures':sum(v['state']=='failed' for v in values),
        'last_destination_verified_at':max((v.get('verified_at','') for v in values),default=None),
        'potential_reclaimable_bytes':sum(s['signature'][3] for v in values for s in v['sources']
            if s['reclaim'] and source_path(store,s).exists()),
        'reclamation_requires_fresh_destination_readback':True,
        'objects':len(values),'live_destination_free_bytes':None,
        'journal_states':{name:read_json(store.infrastructure/name)['state'] for name in
            ('admission.json','vm-admission.json') if (store.infrastructure/name).exists()}}


def prove_source(store, value, source, references):
    path = source_path(store,source)
    if source['kind']=='probe':
        require(read_json(path.parent/'owner.json') == {'application':'jake-wormhole',
            'schema_version':'1.0','kind':'archive-roundtrip-probe','run_id':source['run_id']})
    else:
        _, result, manifest = store.proof(source['run_id'],references)
        require(result['outcome'] not in {'running','unknown'} and not result.get('lab_iso_qualified'))
        if source['kind']=='candidate':require(manifest['candidate_sha256']==value['sha256'])
    require(store.checked(path,references)==source['signature'],'archive_source_changed')
    require(path.stat().st_size==value['bytes'] and store.digest(path)==value['sha256'], 'archive_source_changed')
    return path


def cleanup_actions(store, references, verified):
    actions=[];pins=protected(store,references)
    for digest in verified:
        value=record(store,digest)
        require(value['state']=='committed' and value['receipt']['verified'] is True)
        for source in value['sources']:
            path=source_path(store,source)
            if not source['reclaim'] or digest in pins or not path.exists():continue
            prove_source(store,value,source,references)
            actions.append({'path':str(path),'signature':source['signature'], 'reason':'verified-offhost-archive',
                            'run_id':source['run_id'],'sha256':digest,'archive_kind':source['kind']})
    return actions


def export(store,digest):
    # Opening under the lock pins the source through /proc fd observation while
    # the bounded SSH stream proceeds WITHOUT holding VM admission.
    with store.locked():
        value=record(store,digest);references=store.observe()
        source=next((s for s in value['sources'] if source_path(store,s).exists()),None)
        require(source is not None,'archive_source_unavailable')
        path=prove_source(store,value,source,references);stream=path.open('rb')
        value.update(state='transfer-started',transfer_started_at=now())
        atomic_json(directory(store)/(digest+'.json'),value)
    h=hashlib.sha256()
    with stream:
        for block in iter(lambda:stream.read(1024**2),b''):
            h.update(block);sys.stdout.buffer.write(block)
        require(h.hexdigest()==digest and signature(path)==source['signature'],'archive_source_changed')
    sys.stdout.buffer.flush()


def commit(store,digest,payload):
    with store.locked():
        value=record(store,digest)
        require(type(payload) is dict and set(payload)=={'archive_id','sha256','bytes',
            'ciphertext_sha256','ciphertext_bytes','verified'} and payload['archive_id']==value['archive_id']
            and payload['sha256']==digest and payload['bytes']==value['bytes'] and payload['verified'] is True
            and type(payload['ciphertext_sha256']) is str and SHA.fullmatch(payload['ciphertext_sha256'])
            and type(payload['ciphertext_bytes']) is int and value['bytes']<payload['ciphertext_bytes']<value['bytes']+16*1024**2,
            'archive_receipt_invalid')
        references=store.observe()
        for source in value['sources']:
            if source_path(store,source).exists():prove_source(store,value,source,references)
        value.update(state='committed',receipt=payload,verified_at=now())
        atomic_json(directory(store)/(digest+'.json'),value)
        if not any(source['reclaim'] for source in value['sources']):
            return {'sha256':digest,'state':'committed','cleanup':{'state':'retained-local',
                'actions':0,'unlinked_allocated_bytes':0,'retention_budget_exceeded':None}}
        # Ordinary post-run clean never authorizes archival deletion from an old
        # receipt. Only this fresh destination readback enables these actions.
        cleanup=store.clean_held(archive_verified={digest})
        return {'sha256':digest,'state':'committed','cleanup':{key:cleanup[key] for key in
            ('state','actions','unlinked_allocated_bytes','retention_budget_exceeded')}}


def restore(store,digest):
    with store.locked():
        value=record(store,digest);references=store.observe()
        require(value['state']=='committed','archive_not_verified')
        source=next((s for s in value['sources'] if s['kind']=='candidate'),value['sources'][0])
        path=source_path(store,source)
        _path_chain(path)
        require(not path.exists() and not path.is_symlink(),'archive_restore_conflict')
        # Retain original authority and refuse unreconciled/active runs. Restore
        # cannot reinterpret a missing receipt as a new accepted run.
        if source['kind']!='probe':store.proof(source['run_id'],references)
        _owned(path.parent,directory=True) if source['kind']!='candidate' else require(
            path.parent.stat().st_uid==os.getuid() and not path.parent.stat().st_mode&0o022)
        measured=store.status();admission(store.root,value['bytes'],
            managed_bytes=measured['total_allocated_bytes']+value['bytes'],
            candidate_bytes=measured['allocated_bytes']['candidates']+(value['bytes'] if source['kind']=='candidate' else 0))
        temporary=path.with_name(path.name+'.archive-part')
        require(not temporary.is_symlink(),'archive_restore_conflict')
        if temporary.exists():
            store.checked(temporary,references);temporary.unlink() # fixed, private interrupted restore only
        try:
            with temporary.open('xb') as out:
                os.chmod(temporary,0o600);remaining=value['bytes'];h=hashlib.sha256()
                while remaining:
                    block=sys.stdin.buffer.read(min(1024**2,remaining))
                    require(bool(block),'archive_restore_truncated');out.write(block);h.update(block);remaining-=len(block)
                require(not sys.stdin.buffer.read(1) and h.hexdigest()==digest,'archive_restore_corrupt')
                out.flush();os.fsync(out.fileno())
                os.fchown(out.fileno(),source['signature'][6],source['signature'][7])
                os.fchmod(out.fileno(),source['signature'][9]&0o777)
            os.rename(temporary,path)
            fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
            source['signature']=signature(path)
            value['restored_at']=now();atomic_json(directory(store)/(digest+'.json'),value)
            return {'sha256':digest,'bytes':value['bytes'],'state':'restored','mode':oct(path.stat().st_mode&0o777)}
        finally:
            if temporary.exists():temporary.unlink()


def operate(operation,digest=None):
    require(sys.platform.startswith('linux') and os.geteuid()==0,'runtime_owner_required')
    os.umask(0o077);store=Store()
    # Includes stalled stdin/stdout: archive work cannot lock admission forever.
    def timeout(*_):raise RunError('archive_deadline','Bounded archive operation expired; original evidence retained.')
    previous=signal.signal(signal.SIGALRM,timeout);signal.alarm(900)
    try:
        require(configuration(store) is not None,'archive_not_configured')
        if operation=='archive-export':export(store,digest);return None
        if operation=='archive-import':return restore(store,digest)
        if operation=='archive-commit':return commit(store,digest,json.loads(sys.stdin.buffer.read(16385)))
        with store.locked():
            if operation=='archive-failed':
                payload=json.loads(sys.stdin.buffer.read(16385));value=record(store,digest)
                require(payload.get('archive_id')==value['archive_id'],'archive_destination_changed')
                value.update(state='failed',error_category='destination_verification_failed',failed_at=now())
                atomic_json(directory(store)/(digest+'.json'),value);return {'state':'failed','sha256':digest}
            refs=store.observe()
            if operation=='archive-preview':return preview(store,refs)
            queue(store,refs)
            pins=protected(store,refs)
            return {'archive_id':configuration(store)['archive_id'],
                    'objects':[{**{key:value[key] for key in ('sha256','bytes','state')},
                        'needs_sync':value['state']!='committed' or (value['sha256'] not in pins and any(
                            s['reclaim'] and source_path(store,s).exists() for s in value['sources']))}
                        for p in directory(store).glob('*.json') for value in [record(store,p.stem)]]}
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,previous)
