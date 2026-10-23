"""Fixed offline DNF resolution in one capped, run-owned public UBI container.

The library caller holds its Run lock, Docker scope and canonical smoke lease.
It gets a validated package selection, never permission to skip RPM signatures.
"""
import argparse
from copy import deepcopy
import os
from pathlib import Path
import re
import stat
import sys
import time

from . import images, rpm_source as sources, rpm_target as base
from .admission import AdmissionLease
from .runs import Run, RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, create_run, now, read_json, source_identity

ID = re.compile(r'[a-f0-9]{64}\Z')
ROLE = 'rpm-resolver'
DESTINATION = '/opt/wormhole-rpm/resolve.py'
TMPFS = {'/run':'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=0,gid=0',
         '/tmp':'rw,nosuid,nodev,noexec,size=256m,mode=1777,uid=0,gid=0'}
RELEASE = "import os; p='/run/.wormhole-rpm-resolve.start'; f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.write(f,b'1\\n'); os.fsync(f); os.close(f); os.replace(p,'/run/wormhole-rpm-resolve.start')"
EVIDENCE = 'evidence/rpm-resolution.json'


class ResolutionError(RunError): pass


def require(value, code='rpm_resolution_invalid'):
    if not value: raise ResolutionError(code,'Offline UBI resolution refused; preserve its private Run, capture and exact resource journal.')


def save(run, receipt):
    receipt['updated_at']=now();atomic_json(run.file(EVIDENCE),receipt)


def scope(run, lease):
    base._scope(run,lease)
    require(os.geteuid()==0 and images.docker_configuration()==str(images.safe_bind(run.file('private/docker-config'))), 'rpm_resolution_scope')
    require(not any(x['outcome']=='pending' for x in lease.record['resources']), 'rpm_resolution_overlap')


def recipe_identity():
    records={}
    for name in ('lock.json','probe.py','resolve.py'):
        path=images.safe_bind(SOURCE_ROOT/'rpm'/name)
        require(path.is_file() and 0<path.stat().st_size<=65536,'rpm_resolution_source_changed')
        with path.open('rb') as stream:raw=stream.read(65537)
        require(len(raw)<=65536,'rpm_resolution_source_changed');records[name]=sources.sha(raw)
    return sources.sha(sources.canonical(records)),records


def binding(path, *, public=False, directory=False):
    path=images.safe_bind(path)
    if not public:_owned(path,directory=directory)
    info=path.stat()
    require(info.st_uid==os.getuid() and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1), 'rpm_resolution_binding')
    require(stat.S_IMODE(info.st_mode)==(0o700 if directory else 0o444 if public else 0o600),'rpm_resolution_binding')
    value={'path':str(path),'device':info.st_dev,'inode':info.st_ino,'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid}
    if not directory:
        maximum=65536 if public else sources.POLICY['resolution_bytes']
        require(0<info.st_size<=maximum,'rpm_resolution_binding')
        with path.open('rb') as stream:raw=stream.read(maximum+1)
        require(len(raw)==info.st_size,'rpm_resolution_binding');value.update(bytes=len(raw),sha256=sources.sha(raw))
    return value


def public_sources(run, files):
    folder=run.file('private/rpm-resolver-source')
    if not folder.exists():folder.mkdir(mode=0o700)
    _owned(folder,directory=True)
    result={}
    for name in ('lock.json','resolve.py'):
        path=folder/name
        if not path.exists():atomic_bytes(path,(SOURCE_ROOT/'rpm'/name).read_bytes(),limit=65536);path.chmod(0o444)
        result['/recipe/lock.json' if name=='lock.json' else DESTINATION]=binding(path,public=True)
        require(result['/recipe/lock.json' if name=='lock.json' else DESTINATION]['sha256']==files[name],'rpm_resolution_source_changed')
    return result


def revalidate(run, receipt):
    require(source_identity()==(receipt['source_revision'],False) and
        recipe_identity()==(receipt['recipe_sha256'],receipt['source_files']),'rpm_resolution_source_changed')
    require(sources.canonical(common(receipt))==sources.canonical(common(run.manifest())),'rpm_resolution_identity')
    sources.validate_metadata(run,sources.load_lock())
    require(public_sources(run,receipt['source_files'])=={k:v for k,v in receipt['bindings'].items() if k in (DESTINATION,'/recipe/lock.json')},'rpm_resolution_binding')
    require(binding(run.file('private/rpm-sources/metadata'),directory=True)==receipt['bindings']['/metadata'] and
        binding(run.file('private/rpm-sources/resolve-request.json'))==receipt['bindings']['/request/resolve.json'],'rpm_resolution_binding')
    require(sources.canonical(read_json(run.file('private/rpm-sources/resolve-request.json')))==sources.canonical(receipt['request']),'rpm_resolution_request_changed')
    observed=base.read_base_observation(Run(run.workspace,receipt['request']['base_probe']['run_id']))
    require(sources.sha(sources.canonical(observed))==receipt['request']['base_observation_sha256'],'rpm_resolution_base_changed')


def expected_labels(run, recipe, lock):
    return {**lock['base']['labels'],images.LABEL+'.run_id':run.id,images.LABEL+'.source_revision':run.manifest()['source_revision'],
        images.LABEL+'.role':ROLE,images.LABEL+'.rpm_recipe_sha256':recipe}


def verify_container(run, receipt, value, limits, *, stopped=False):
    host,config,state=value['HostConfig'],value['Config'],value['State'];expected=limits['docker_create']
    require(value.get('Id')==receipt['container_id'] and value.get('Image')==sources.BASE_IMAGE and
        value.get('Name')=='/wormhole-'+run.id+'-rpm-resolver' and config.get('Labels')==expected_labels(run,receipt['recipe_sha256'],sources.load_lock()) and
        config.get('User')=='0:0' and config.get('WorkingDir')=='/' and config.get('Entrypoint')==['/usr/bin/python3'] and
        config.get('Cmd')==['-I','-B',DESTINATION] and not config.get('Tty') and not config.get('OpenStdin'),'rpm_resolution_identity')
    environment=config.get('Env') or []
    require(type(environment) is list and len(environment)==len(set(x.split('=',1)[0] for x in environment)) and
        {x for x in environment if x.startswith('WORMHOLE_')}=={'WORMHOLE_ROLE='+ROLE,'WORMHOLE_RUN_ID='+run.id} and
        all(x in environment for x in ('HOME=/tmp','PATH=/usr/sbin:/usr/bin:/sbin:/bin','LANG=C','PYTHONDONTWRITEBYTECODE=1')),'rpm_resolution_identity')
    require(host.get('NetworkMode')=='none' and host.get('ReadonlyRootfs') is True and host.get('Privileged') is False and
        images.capability_names(host.get('CapDrop'))=={'ALL'} and not host.get('CapAdd') and
        all(type(host.get(actual)) is int and host.get(actual)==expected[key] for actual,key in
            (('Memory','memory_bytes'),('MemorySwap','memory_swap_bytes'),('NanoCpus','nano_cpus'),('PidsLimit','pids_limit'))) and
        host.get('LogConfig')=={'Type':expected['log_driver'],'Config':expected['log_opts']} and host.get('Tmpfs')==TMPFS and
        host.get('PidMode','')=='' and host.get('IpcMode') in ('','private') and host.get('UTSMode','')=='' and
        not host.get('PortBindings') and not host.get('PublishAllPorts') and not host.get('Devices') and
        not host.get('Binds') and not host.get('VolumesFrom') and not host.get('Links') and
        host.get('RestartPolicy',{}).get('Name')=='no' and set(host.get('SecurityOpt') or []) in
            ({'no-new-privileges:true'},{'no-new-privileges=true'},{'no-new-privileges'}),'rpm_resolution_limits')
    mounts=value.get('Mounts',[]);binds=[x for x in mounts if x.get('Type')=='bind']
    require(len(binds)==len(receipt['bindings']) and {x.get('Destination') for x in binds}==set(receipt['bindings']) and
        all(x.get('RW') is False and x.get('Source')==receipt['bindings'][x['Destination']]['path'] for x in binds) and
        all(x.get('Type')=='bind' or x.get('Type')=='tmpfs' and x.get('Destination') in TMPFS for x in mounts),'rpm_resolution_mounts')
    if stopped:require(state.get('Running') is False and state.get('Status')=='created' and state.get('StartedAt')=='0001-01-01T00:00:00Z','rpm_resolution_started')


def mutation(run,receipt,arguments,**options):
    receipt['unknown_outcome']=True;save(run,receipt)
    result=images.docker(arguments,**options)
    require(result['status']=='pass' and result['returncode']==0 and not result['log_truncated'],'rpm_resolution_request_incomplete')
    return result


def empty(run):
    result=images.docker(('ps','-a','--no-trunc','--filter','label='+images.LABEL+'.run_id='+run.id,'--format','{{.ID}}'))
    require(not result['log_truncated'] and not result['log'].strip(),'rpm_resolution_leftovers')


def cleanup(run,lease,receipt):
    require(receipt['unknown_outcome'] is False,'rpm_resolution_unknown')
    identifier=receipt['container_id']
    if identifier is not None:
        entries=[x for x in lease.record['resources'] if x['kind']=='container' and x['id']==identifier]
        require(len(entries)==1 and entries[0]['outcome'] in ('pending','absent'),'rpm_resolution_cleanup')
        value=images.inspect('container',identifier,missing=True)
        if value is not None:
            require(entries[0]['outcome']=='pending','rpm_resolution_cleanup')
            verify_container(run,receipt,value,lease.plan['limits']['build'])
            if value['State']['Running']:
                mutation(run,receipt,('stop','--time','2',identifier),timeout=10)
                require(images.inspect('container',identifier)['State']['Running'] is False,'rpm_resolution_cleanup')
                receipt['unknown_outcome']=False;save(run,receipt)
            mutation(run,receipt,('rm',identifier))
            require(images.inspect('container',identifier,missing=True) is None,'rpm_resolution_cleanup')
            receipt['unknown_outcome']=False;save(run,receipt)
        require(images.inspect('container',identifier,missing=True) is None,'rpm_resolution_cleanup')
        if entries[0]['outcome']=='pending':lease.reconcile_resource('container',identifier)
    empty(run);receipt['cleanup']='completed';save(run,receipt)


def resolve_packages(run,lease,*,base_run):
    """Return exact validated selection, with no pending resolver and lease held."""
    scope(run,lease);lock=sources.load_lock();recipe,files=recipe_identity()
    require(not run.file(EVIDENCE).exists(),'rpm_resolution_reused')
    receipt={**common(run.manifest()),'operation':'ubi-offline-resolution','status':'pending','started_at':now(),
        'base_image_id':sources.BASE_IMAGE,'recipe_sha256':recipe,'source_files':files,'container_id':None,'bindings':{},
        'request':None,'capture_sha256':None,'capture_bytes':None,'resolution':None,'cgroups':None,'unknown_outcome':False,
        'primary_failure':None,'secondary_cleanup_failure':None,'cleanup':'pending','runtime_pipeline_complete':False,'production_iso_eligible':False}
    save(run,receipt)
    try:
        lease.set_phase('assembling');sources.prepare_metadata(run,lock)
        observed=base.read_base_observation(base_run);request=sources.resolve_request(run,lock,observed,base_run=base_run)
        receipt['request']=request;receipt['bindings']={**public_sources(run,files),
            '/metadata':binding(run.file('private/rpm-sources/metadata'),directory=True),
            '/request/resolve.json':binding(run.file('private/rpm-sources/resolve-request.json'))};save(run,receipt)
        revalidate(run,receipt);image=images.inspect('image',base.BASE);base.verify_base(image,lock)
        lease.set_phase('materializing')
        if not any(x['kind']=='image' and x['id']==sources.BASE_IMAGE for x in lease.record['resources']):
            lease.register_resource('image',sources.BASE_IMAGE);lease.reconcile_resource('image',sources.BASE_IMAGE,outcome='retained',size_bytes=image['Size'])
        lease.set_phase('assembling');limits=lease.plan['limits']['build'];labels=expected_labels(run,recipe,lock)
        args=['create','--name','wormhole-'+run.id+'-rpm-resolver','--network','none','--user','0:0','--read-only','--workdir','/',
            '--entrypoint','/usr/bin/python3',*images.limits_arguments(limits)]
        for key,value in TMPFS.items():args.extend(('--tmpfs',key+':'+value))
        for value in ('HOME=/tmp','PATH=/usr/sbin:/usr/bin:/sbin:/bin','LANG=C','PYTHONDONTWRITEBYTECODE=1','WORMHOLE_ROLE='+ROLE,'WORMHOLE_RUN_ID='+run.id):args.extend(('--env',value))
        for key,value in labels.items():args.extend(('--label',key+'='+value))
        for destination,value in receipt['bindings'].items():args.extend(('--mount','type=bind,source='+value['path']+',target='+destination+',readonly,bind-propagation=rprivate'))
        args.extend((sources.BASE_IMAGE,'-I','-B',DESTINATION));revalidate(run,receipt)
        result=mutation(run,receipt,tuple(args));identifier=result['log'].decode('ascii').strip()
        require(ID.fullmatch(identifier),'rpm_resolution_create_unknown');lease.register_resource('container',identifier)
        receipt.update(container_id=identifier,unknown_outcome=False);save(run,receipt)
        verify_container(run,receipt,images.inspect('container',identifier),limits,stopped=True);revalidate(run,receipt)
        deadline=time.monotonic()+70;mutation(run,receipt,('start',identifier));value=images.inspect('container',identifier)
        verify_container(run,receipt,value,limits)
        receipt['unknown_outcome']=False;save(run,receipt)
        require(value['State']['Running'] is True and value['State']['Status']=='running' and value['State'].get('Paused') is not True and value['State'].get('Restarting') is not True,'rpm_resolution_runtime')
        receipt['cgroups']=images.cgroup_limits(value['State']['Pid'],limits['docker_create']);save(run,receipt)
        revalidate(run,receipt);require(time.monotonic()<deadline,'rpm_resolution_deadline')
        mutation(run,receipt,('exec',identifier,'/usr/bin/python3','-I','-B','-c',RELEASE),timeout=10)
        receipt['unknown_outcome']=False;save(run,receipt)
        while True:
            require(time.monotonic()<deadline,'rpm_resolution_deadline')
            value=images.inspect('container',identifier,timeout=min(5,max(.01,deadline-time.monotonic())))
            require(time.monotonic()<deadline,'rpm_resolution_deadline');verify_container(run,receipt,value,limits)
            if value['State']['Running'] is False:break
            time.sleep(.05)
        capture=images.docker(('logs',identifier),timeout=min(5,max(.01,deadline-time.monotonic())))
        require(time.monotonic()<deadline and not capture['log_truncated'] and len(capture['log'])<=sources.POLICY['resolution_bytes']+1,'rpm_resolution_capture_bound')
        raw=capture['log'];atomic_bytes(run.file('private/rpm-resolution.log'),raw,limit=sources.POLICY['resolution_bytes']+1)
        receipt.update(capture_sha256=sources.sha(raw),capture_bytes=len(raw));save(run,receipt)
        require(value['State'].get('Status')=='exited' and type(value['State'].get('ExitCode')) is int and
            value['State']['ExitCode']==0 and value['State'].get('OOMKilled') is not True and raw.endswith(b'\n'),'rpm_resolution_runtime')
        resolution=sources.validate_resolution(run,raw,request,lock);revalidate(run,receipt)
        require(time.monotonic()<deadline,'rpm_resolution_deadline')
        receipt.update(resolution=resolution,status='passed');save(run,receipt);cleanup(run,lease,receipt)
        return deepcopy(resolution)
    except BaseException as error:
        receipt.update(status='failed',primary_failure={'code':getattr(error,'code','rpm_resolution_failed'),'recorded_at':now()});save(run,receipt)
        if receipt['unknown_outcome'] is False:
            try:cleanup(run,lease,receipt)
            except Exception as secondary:
                receipt.update(cleanup='blocked',secondary_cleanup_failure={'code':getattr(secondary,'code','rpm_resolution_cleanup'),'recorded_at':now()});save(run,receipt)
        raise


def qualify(base_id,sentinel):
    from .provisioning_acceptance import snapshot
    require(sys.platform.startswith('linux') and type(sentinel) is str and ID.fullmatch(sentinel),'rpm_resolution_input')
    old=Run(images.RUNS_ROOT,base_id);revision,dirty=source_identity();require(dirty is False,'rpm_resolution_source_dirty')
    base.read_base_observation(old);run=create_run(images.RUNS_ROOT,fixture=False,kernel_lock=True)
    try:
        with run.locked(),images.docker_scope(run),AdmissionLease(images.INFRASTRUCTURE,run.id,revision) as lease:
            before=snapshot('container',sentinel,unrelated=True)
            try:result=resolve_packages(run,lease,base_run=old)
            except BaseException:
                receipt=read_json(run.file(EVIDENCE))
                if receipt['cleanup']=='completed' and receipt['unknown_outcome'] is False:
                    require(snapshot('container',sentinel,unrelated=True)==before,'rpm_resolution_sentinel_changed');lease.finish(reconciliation_complete=True)
                raise
            require(snapshot('container',sentinel,unrelated=True)==before,'rpm_resolution_sentinel_changed')
            lease.finish(reconciliation_complete=True);receipt=read_json(run.file(EVIDENCE))
            receipt.update(admission_finished=True,unrelated_sentinel_unchanged=True);save(run,receipt)
            return {'run_id':run.id,'status':'passed','evidence':EVIDENCE,'selected_packages':len(result['packages']),
                'selected_bytes':sum(x['bytes'] for x in result['packages']),'packages_installed':False,
                'runtime_pipeline_complete':False,'production_iso_eligible':False}
    except BaseException as error:error.run_id=run.id;raise


def main(arguments=None):
    parser=argparse.ArgumentParser(description='Fixed public UBI offline dependency resolution; no installation.')
    commands=parser.add_subparsers(dest='command',required=True);command=commands.add_parser('qualify')
    command.add_argument('--base-run',required=True);command.add_argument('--sentinel-id',required=True);options=parser.parse_args(arguments)
    try:print(sources.canonical(qualify(options.base_run,options.sentinel_id)).decode());return 0
    except (RunError,OSError,ValueError,KeyError,TypeError) as error:
        print(sources.canonical({'status':'failed','code':getattr(error,'code','rpm_resolution_failed'),'run_id':getattr(error,'run_id',None),
            'evidence':EVIDENCE,'production_iso_eligible':False}).decode());return 1


if __name__=='__main__':raise SystemExit(main())
