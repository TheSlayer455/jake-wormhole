"""Completed directory deliveries -> existing foreground VM acceptance.

The producer atomically renames a bounded *.ready.json manifest LAST. An inbox
is not immutable storage. Only verified independent copies enter private intake.
No source builds, watcher daemon, publication or arbitrary executable profiles.
"""
import json
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

from .media_store import MAX_BYTES, SHA, file_lock, fingerprint, stream_chunk
from .runs import RunError, SOURCE_ROOT, _no_duplicates, _owned, _path_chain, atomic_json, now, read_json, workspace_path
from .storage import Store, admission
from .vm_inputs import sha256


def require(value, code):
    if not value:raise RunError(code,'Intake refused; preserve the delivery and original run evidence.')


def acceptance_context(distribution='rhel10'):
    if distribution=='ubuntu':
        from .ubuntu_assessment import POLICY
        files=('vm_baseline.py','ubuntu_intake.py','ubuntu_assessment.py','ubuntu_svd.py',
            'ubuntu_release.py','ubuntu_catalog.py','vm_admission.py','intake.py')
        policy=json.loads(POLICY.read_text())
        return {'implementation_sha256':fingerprint({n:sha256(SOURCE_ROOT/'wormhole'/n) for n in files}),
            'assessment_content_sha256':policy['content']['datastream_sha256'],
            'assessment_profile':policy['content']['profile_id'],'qualification_policy':sha256(POLICY)}
    from .rhel_assessment import CONTENT_SHA, PROFILE
    files=('vm_baseline.py','vm_inputs.py','rhel_inputs.py','rhel_assessment.py','vm_admission.py','intake.py')
    return {'implementation_sha256':fingerprint({n:sha256(SOURCE_ROOT/'wormhole'/n) for n in files}),
        'assessment_content_sha256':CONTENT_SHA,'assessment_profile':PROFILE,
        'qualification_policy':'installation-baseline-ineligible-v1'}


def read_manifest(path, limit):
    _path_chain(path)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),'delivery_manifest_invalid')
        raw=stream.read(limit+1)
    require(len(raw)<=limit,'delivery_manifest_bound')
    try:value=json.loads(raw,object_pairs_hook=_no_duplicates)
    except (ValueError,UnicodeError):raise RunError('delivery_manifest_invalid','Expected a completed JSON delivery manifest.') from None
    require(type(value) is dict,'delivery_manifest_invalid')
    return value,raw


def distribution(delivery):
    from .rhel_inputs import installation_contract as rhel
    from .ubuntu_intake import installation_contract as ubuntu
    if delivery['contract_sha256']==fingerprint(rhel()):return 'rhel10'
    require(delivery['contract_sha256']==fingerprint(ubuntu()),'unsupported_installation_contract')
    return 'ubuntu'


def completed_delivery(marker):
    import hashlib
    marker=Path(marker).absolute()
    require(marker.name.endswith('.ready.json'),'delivery_completion_marker_required')
    value,_=read_manifest(marker,16384)
    fields={'schema_version','iso','bytes','sha256','contract_sha256'}
    require(type(value.get('schema_version')) is str and value['schema_version'] in {'1.0','2.0'} and
        set(value)==fields | ({'build_manifest','build_manifest_sha256'} if value['schema_version']=='2.0' else set()),
        'delivery_manifest_invalid')
    require(type(value['iso']) is str and
        re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.iso',value['iso']) and
        type(value['bytes']) is int and 32774<=value['bytes']<=MAX_BYTES and
        type(value['sha256']) is str and SHA.fullmatch(value['sha256']),'delivery_manifest_invalid')
    target=distribution(value)
    require((target=='ubuntu')==(value['schema_version']=='2.0'),'delivery_manifest_invalid')
    if target=='ubuntu':
        name=value['build_manifest']
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.json',name),
            'delivery_manifest_invalid')
        build,raw=read_manifest(marker.parent/name,65536)
        require(hashlib.sha256(raw).hexdigest()==value['build_manifest_sha256'],'delivery_build_manifest_mismatch')
        value['build']=build
    return marker.parent/value['iso'],value


def register(marker, *, generation='initial', scenario='healthy', store=None):
    """One acceptance key per bytes+installation+tests/content/policy+generation."""
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',generation) and
        scenario in {'healthy','marker-inaccessible'},'intake_request_invalid')
    source,delivery=completed_delivery(marker)
    context=acceptance_context(distribution(delivery))
    key=fingerprint({'sha256':delivery['sha256'],'bytes':delivery['bytes'],
        'contract_sha256':delivery['contract_sha256'],'acceptance':context,
        'generation':generation,'scenario':scenario})
    store=store or Store()
    existing=store.root/'intake/requests'/(key+'.json')
    if existing.exists():return read_json(existing) # Observe a known request even while its VM owns admission.
    with store.locked():
        references=store.observe() # Same host lock/journals as builds and VM operations.
        root=workspace_path(store.root/'intake',create=True)
        candidates=workspace_path(root/'candidates',create=True)
        requests=workspace_path(root/'requests',create=True)
        staged=candidates/(delivery['sha256']+'.iso')
        origin=None
        if not staged.exists():
            # Existing protected, independently verified copies may be reused.
            # The writable inbox itself is never aliased or cleanup-owned.
            for previous in sorted(store.runs.glob('*/result.json')):
                try:
                    if read_json(previous).get('build',{}).get('candidate_sha256')!=delivery['sha256']:continue
                    _,_,manifest=store.proof(previous.parent.name,references)
                    candidate=store.resolve(previous.parent.name)
                    store.checked(candidate,references)
                    if manifest['candidate_sha256']==delivery['sha256'] and store.digest(candidate)==delivery['sha256']:
                        origin=previous.parent.name;staged=candidate;break
                except (RunError,OSError,KeyError,ValueError):continue
        if origin is not None:
            _path_chain(source)
            with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as incoming:
                info=os.fstat(incoming.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size==delivery['bytes'] and
                    stream_chunk(incoming,delivery['bytes'])==delivery['sha256'] and not incoming.read(1),'delivery_changed_or_corrupt')
        elif not staged.exists():
            usage=store.status()
            admission(store.root,delivery['bytes'],managed_bytes=usage['total_allocated_bytes']+delivery['bytes'],
                candidate_bytes=usage['allocated_bytes']['candidates']+delivery['bytes'])
            _path_chain(source)
            # Exclusive private output is never a hard link to producer-writable bytes.
            temporary=staged.with_suffix('.'+str(uuid4())+'.partial')
            try:
                with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as incoming, temporary.open('xb') as outgoing:
                    before=os.fstat(incoming.fileno())
                    require(stat.S_ISREG(before.st_mode) and before.st_size==delivery['bytes'],'delivery_incomplete')
                    digest=stream_chunk(incoming,delivery['bytes'],output=outgoing)
                    after=os.fstat(incoming.fileno())
                    require(not incoming.read(1) and digest==delivery['sha256'] and
                        (before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                        (after.st_size,after.st_mtime_ns,after.st_ctime_ns),'delivery_changed_or_corrupt')
                    outgoing.flush();os.fsync(outgoing.fileno())
                temporary.chmod(0o400);os.replace(temporary,staged)
                directory=os.open(candidates,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(directory)
                finally:os.close(directory)
            finally:
                if temporary.exists():temporary.unlink() # Only this invocation's incomplete private copy.
        if origin is None:_owned(staged)
        require(staged.stat().st_size==delivery['bytes'] and
            sha256(staged)==delivery['sha256'],'staged_delivery_changed')
        record=requests/(key+'.json')
        if record.exists():return read_json(record)
        value={'schema_version':'1.0','request_id':key,'run_id':str(uuid4()),'state':'registered',
            'created_at':now(),'delivery':delivery,'acceptance':context,'generation':generation,
            'scenario':scenario,'candidate_origin_run':origin,'lab_iso_qualified':False,'production_iso_eligible':False}
        atomic_json(record,value)
        return value


def submit(key, terraform, *, store=None, dependency_store=None):
    """Persist dispatch intent first. Repeated submissions observe the same run."""
    from . import vm_baseline
    require(type(key) is str and SHA.fullmatch(key),'intake_request_invalid')
    store=store or Store();root=workspace_path(store.root/'intake')
    record=root/'requests'/(key+'.json')
    with file_lock(record.with_suffix('.lock')):
        value=read_json(record)
        if value['state']!='registered':
            run=store.runs/value['run_id']/'result.json'
            if run.exists():
                result=read_json(run)
                require(result['run_id']==value['run_id'] and result.get('delivery')==value['delivery'],'intake_run_identity')
                if result['outcome']!='running':
                    value.update(state='completed',outcome=result['outcome'],cleanup=result['cleanup'],
                        error_category=result.get('error_category'),checks=result.get('checks',{}))
                    atomic_json(record,value)
                else:value['observation']=vm_baseline.status(value['run_id'])
            else:value['observation']='launch-outcome-unknown'
            return value
        target=distribution(value['delivery'])
        require(value['acceptance']==acceptance_context(target),'intake_acceptance_changed')
        arguments={}
        if target=='ubuntu':
            from .ubuntu_intake import validate_manifest
            validate_manifest(value['delivery'],dependency_store)
            arguments={'ubuntu_mode':'hardened','sandbox':True,'dependency_store':dependency_store}
        if value.get('candidate_origin_run'):
            source=store.resolve(value['candidate_origin_run'])
        else:
            source=root/'candidates'/(value['delivery']['sha256']+'.iso');_owned(source)
        require(sha256(source)==value['delivery']['sha256'],'staged_delivery_changed')
        value.update(state='submitted',submitted_at=now());atomic_json(record,value)
        # No shared storage lock here: execute acquires the canonical VM lease.
        try:
            result=vm_baseline.execute(source,terraform,distribution=target,delivery=value['delivery'],
                request_run=value['run_id'],scenario=value['scenario'],**arguments)
        except RunError as error:
            if error.code in {'unverified_execution_inputs','media_store_busy','unreconciled_vm_run','unreconciled_container_run'} and not (store.runs/value['run_id']).exists():
                # These checks precede admission; no launch occurred. A later scan
                # may retry this same recorded identity after the cause clears.
                value.update(state='registered',last_prelaunch_refusal=error.code)
                atomic_json(record,value)
            raise
        require(result['run_id']==value['run_id'] and result.get('delivery')==value['delivery'],'intake_run_identity')
        value.update(state='completed',outcome=result['outcome'],cleanup=result['cleanup'],
            error_category=result.get('error_category'),checks=result.get('checks',{}))
        atomic_json(record,value)
        return value


def scan(directory, *, execute=False, terraform=None, generation='initial', scenario='healthy', store=None, dependency_store=None):
    """Bounded reconciliation pass, also used by a timer/producer notification."""
    directory=Path(directory).absolute();_path_chain(directory)
    require(directory.is_dir(),'intake_directory_unavailable')
    results=[]
    for marker in sorted(directory.glob('*.ready.json')):
        try:
            value=register(marker,generation=generation,scenario=scenario,store=store)
            if execute:value=submit(value['request_id'],terraform,store=store,dependency_store=dependency_store)
            results.append(value)
        except (RunError,OSError) as error:
            results.append({'delivery':marker.name,'state':'refused','error_category':getattr(error,'code',type(error).__name__)})
    return results


def add_parser(commands):
    p=commands.add_parser('intake',help='Register completed ISO deliveries and use the existing VM acceptance path.')
    p.add_argument('operation',choices=['contract','register','submit','scan'])
    p.add_argument('input',nargs='?',help='Completion manifest, request hash, or inbox directory.')
    p.add_argument('--terraform',help='Existing pinned Terraform executable for submission.')
    p.add_argument('--distribution',choices=['rhel10','ubuntu'],default='rhel10',help='Installation contract to display; deliveries bind their own contract.')
    p.add_argument('--store',help='Existing pinned Ubuntu offline dependency store; intake does not prepare or update it.')
    p.add_argument('--submit',action='store_true',help='Submit registered requests during this reconciliation scan.')
    p.add_argument('--generation',default='initial',help='Explicit new requalification generation; repeats deduplicate.')
    p.add_argument('--scenario',choices=['healthy','marker-inaccessible'],default='healthy')


def operate(options):
    os.umask(0o077)
    if options.operation=='contract':
        if options.distribution=='ubuntu':from .ubuntu_intake import installation_contract
        else:from .rhel_inputs import installation_contract
        contract=installation_contract()
        return {'contract':contract,'contract_sha256':fingerprint(contract)},0
    require(options.input is not None,'intake_input_required')
    require(not (options.operation=='submit' or options.submit) or options.terraform is not None,'intake_terraform_required')
    if options.operation=='register':value=register(options.input,generation=options.generation,scenario=options.scenario)
    elif options.operation=='submit':value=submit(options.input,options.terraform,dependency_store=options.store)
    else:value=scan(options.input,execute=options.submit,terraform=options.terraform,generation=options.generation,
        scenario=options.scenario,dependency_store=options.store)
    rows=value if isinstance(value,list) else [value]
    return value,0 if all(r['state']=='registered' or (r['state']=='completed' and
        r.get('outcome')=='baseline-passed' and r.get('cleanup')=='verified-absent-inputs-retained') for r in rows) else 1
