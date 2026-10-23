"""Reviewed fixed offline RPM builder; caller holds the canonical Run/lease.

Only the exact derived candidate is returned. It does not run target checks or
replace Terraform, the ordinary helper or the trusted stock provisioner.
"""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time

from . import candidate as c, images, rpm_candidate as rc, rpm_target as t, rpm_source as sources
from .runs import SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, now, read_json, source_identity

SELECT = 'exec /usr/bin/python3 -I -B /recipe/assemble.py'
RELEASE = 'umask 077; printf "1\\n" > /run/.wormhole-rpm-build.start.tmp && /usr/bin/mv -T /run/.wormhole-rpm-build.start.tmp /run/wormhole-rpm-build.start'
TMPFS = {'/run':'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=0,gid=0',
         '/tmp':'rw,nosuid,nodev,noexec,size=128m,mode=1777,uid=0,gid=0'}
KEY_SHA = '0db3dc1b6228f29d60f37c5ad91d9f4cd3547895e8ebedb242469b1c0a0cdf08'
KEY_FINGERPRINTS = ['567E347AD0044ADE55BA8A5F199E2F91FD431D51','7E4624258C406535D56D6F135054E4A45A6340B3']


def config():
    path=images.safe_bind(rc.CONTEXT/'assembly.json');t.require(path.is_file() and path.stat().st_size<=16384,'rpm_assembly_config_invalid')
    value=json.loads(path.read_bytes())
    t.require(type(value) is dict and set(value)=={'schema_version','operation','seconds','tmpfs_bytes','eula','trusted_primary_fingerprints',
        'key_sources','signature_policy','production_iso_eligible'} and value['schema_version']=='1.0' and
        value['operation']=='offline-ubi9-candidate-assembly' and type(value['seconds']) is int and value['seconds']==600 and
        type(value['tmpfs_bytes']) is int and value['tmpfs_bytes']==128*1024*1024 and value['production_iso_eligible'] is False and
        value['trusted_primary_fingerprints']==KEY_FINGERPRINTS and
        value['key_sources']==['https://access.redhat.com/security/team/key','https://security.access.redhat.com/data/fd431d51.txt',
            'https://security.access.redhat.com/data/5a6340b3.txt'] and value['eula']=={
                'url':sources.EULA_URL,'bytes':sources.EULA_BYTES,'sha256':sources.EULA_SHA256,
                'destination':'/licenses/ubi9-container/UBI-EULA-20190422.pdf'}, 'rpm_assembly_config_invalid')
    return value


def _copy(run,name,raw):
    directory=run.file('private/rpm-assembly-source');directory.mkdir(mode=0o700,exist_ok=True);_owned(directory,directory=True)
    path=directory/name
    t.require(not path.exists(),'rpm_assembly_source_reused')
    atomic_bytes(path,raw,limit=262144);path.chmod(0o444)
    info=path.lstat()
    return {'path':str(path),'bytes':len(raw),'sha256':c.sha(raw),'device':info.st_dev,'inode':info.st_ino}


def _check_copies(run,records):
    _owned(run.file('private/rpm-assembly-source'),directory=True)
    t.require(set(path.name for path in run.file('private/rpm-assembly-source').iterdir())=={Path(row['path']).name for row in records.values()},'rpm_assembly_source_changed')
    for row in records.values():
        path=images.safe_bind(Path(row['path']));info=path.lstat()
        t.require(path.parent==run.file('private/rpm-assembly-source') and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
            info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o444 and (info.st_dev,info.st_ino,info.st_size)==
            (row['device'],row['inode'],row['bytes']) and info.st_size<=262144 and c.sha(path.read_bytes())==row['sha256'],'rpm_assembly_source_changed')


def _save(run,receipt):
    receipt['updated_at']=now();atomic_json(run.file('evidence/rpm-candidate-build.json'),receipt)


def mutation(run,receipt,args,**options):
    receipt['unknown_outcome']=True;_save(run,receipt)
    value=images.docker(args,**options)
    t.require(value['status']=='pass' and value['returncode']==0 and value['log_truncated'] is False,'rpm_build_request_incomplete')
    return value


def verify_builder(run,receipt,value,limits,*,stopped=False):
    host,cfg=value['HostConfig'],value['Config'];expected=limits['docker_create']
    t.require(value.get('Id')==receipt['builder_id'] and value.get('Image')==t.BASE_ID and
        value.get('Name')=='/wormhole-'+run.id+'-rpm-build' and cfg.get('Labels')==receipt['labels'] and cfg.get('User')=='0:0' and
        cfg.get('WorkingDir')=='/' and cfg.get('Entrypoint')==['/bin/sh'] and cfg.get('Cmd')==['-c',SELECT] and
        {item for item in cfg.get('Env',[]) if item.startswith('WORMHOLE_')}=={'WORMHOLE_ROLE=rpm-builder','WORMHOLE_RUN_ID='+run.id} and
        not cfg.get('Volumes') and not cfg.get('Tty') and not cfg.get('OpenStdin'),'rpm_builder_identity')
    t.require(host.get('Privileged') is False and host.get('ReadonlyRootfs') is False and host.get('NetworkMode')=='none' and
        images.capability_names(host.get('CapDrop'))=={'ALL'} and images.capability_names(host.get('CapAdd'))==set(images.BUILD_CAPS) and
        all(type(host.get(key)) is int and host[key]==expected[field] for key,field in
            (('Memory','memory_bytes'),('MemorySwap','memory_swap_bytes'),('NanoCpus','nano_cpus'),('PidsLimit','pids_limit'))) and
        host.get('LogConfig')=={'Type':expected['log_driver'],'Config':expected['log_opts']} and host.get('Tmpfs')==TMPFS and
        host.get('PidMode','')=='' and host.get('IpcMode') in ('','private') and host.get('UTSMode','')=='' and
        host.get('CgroupnsMode','private')=='private' and not host.get('PortBindings') and not host.get('PublishAllPorts') and
        not host.get('Devices') and not host.get('DeviceRequests') and not host.get('VolumesFrom') and
        host.get('AutoRemove',False) is False and host.get('RestartPolicy',{}).get('Name')=='no' and
        set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'},{'no-new-privileges=true'},{'no-new-privileges'}),'rpm_builder_limits')
    mounts=value.get('Mounts',[]);binds=[row for row in mounts if row.get('Type')=='bind']
    t.require(len(binds)==len(receipt['mounts']) and all(row.get('RW') is False and receipt['mounts'].get(row.get('Destination'))==row.get('Source') for row in binds) and
        all(row.get('Type')=='bind' or row.get('Type')=='tmpfs' and row.get('Destination') in TMPFS for row in mounts),'rpm_builder_mounts')
    _check_copies(run,receipt['source_bindings'])
    if stopped:t.require(value['State']['Status']=='created' and value['State']['Running'] is False and
        value['State']['StartedAt']=='0001-01-01T00:00:00Z','rpm_builder_started')


def installed_record(identifier):
    response=images.docker(('cp',identifier+':/opt/wormhole/rpm-installed.json','-'))
    t.require(not response['log_truncated'],'rpm_install_record_invalid')
    with tarfile.open(fileobj=io.BytesIO(response['log']),mode='r:*') as archive:
        records=archive.getmembers();t.require(len(records)==1 and records[0].name=='rpm-installed.json' and records[0].isfile() and
            records[0].size<=49152,'rpm_install_record_invalid')
        raw=archive.extractfile(records[0]).read(49153)
    t.require(len(raw)<=49152,'rpm_install_record_invalid')
    return sources.parse(raw)


def validate_installed(value,request,source_files):
    fields={'status','base_image_id','candidate_sha256','content_sha256','source_candidate_sha256','installed_packages','signature_results',
        'key_files','key_records','os_release','license_files','dependency_check','hostkeys_absent','runtime_sha256','sshd_config_sha256',
        'runtime_pipeline_complete','production_iso_eligible'}
    t.require(type(value) is dict and set(value)==fields and value['status']=='installed' and value['base_image_id']==t.BASE_ID and
        value['candidate_sha256']==request['candidate_sha256'] and value['content_sha256']==request['manifest']['content_sha256'] and
        value['source_candidate_sha256']==request['manifest']['source_candidate_sha256'] and value['hostkeys_absent'] is True and
        value['dependency_check']=='passed' and value['runtime_pipeline_complete'] is False and value['production_iso_eligible'] is False and
        value['runtime_sha256']==source_files['images/runtime.py'] and value['sshd_config_sha256']==source_files['images/sshd_config'] and
        value['os_release']['ID']=='rhel' and value['os_release']['VERSION_ID']=='9.8','rpm_install_record_invalid')
    packages=sources.validate_observation({'status':'observed','operation':'ubi-base-observation-v1','installed_packages':value['installed_packages']})
    for name,version in rc.PACKAGE_VERSIONS.items():
        selected=[row for row in packages if row['name']==name]
        t.require(len(selected)==1 and c.canonical({key:selected[0][key] for key in version})==c.canonical(version),'rpm_installed_package_mismatch')
    expected=[{'filename':Path(row['path']).name,'sha256':row['sha256']} for row in request['resolution']['packages']]
    signatures=value['signature_results']
    t.require(type(signatures) is list and len(signatures)==len(expected) and all(type(row) is dict and
        set(row)=={'filename','sha256','signature','verification_output_sha256'} and row['signature']=='verified' and
        type(row['verification_output_sha256']) is str and t.SHA.fullmatch(row['verification_output_sha256']) for row in signatures) and
        [{key:row[key] for key in ('filename','sha256')} for row in signatures]==expected,'rpm_signature_unverified')
    t.require(type(value['key_files']) is list and len(value['key_files'])==1 and value['key_files'][0]=={
        'path':t.KEY_PATHS[0],'sha256':KEY_SHA,'primary_fingerprints':KEY_FINGERPRINTS},'rpm_signature_unverified')
    for row in value['key_files']:
        t.require(type(row) is dict and set(row)=={'path','sha256','primary_fingerprints'} and
            row['path']==t.KEY_PATHS[0] and type(row['sha256']) is str and t.SHA.fullmatch(row['sha256']) and
            type(row['primary_fingerprints']) is list and row['primary_fingerprints'] and
            set(row['primary_fingerprints'])<=set(config()['trusted_primary_fingerprints']),'rpm_signature_unverified')
    eula={'path':'/licenses/ubi9-container/UBI-EULA-20190422.pdf','bytes':sources.EULA_BYTES,'sha256':sources.EULA_SHA256}
    t.require(type(value['license_files']) is list and 1<=len(value['license_files'])<=65 and eula in value['license_files'],'rpm_license_retention_unverified')
    for row in value['license_files']:
        t.require(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['path']) is str and
            (row==eula or row['path'] in ('/licenses/ubi9-container/LICENSE','/licenses/ubi9-container/LICENSE.txt','/licenses/ubi9-container/EULA') or
             row['path'].startswith(('/usr/share/doc/','/usr/share/licenses/')) and 'eula' in Path(row['path']).name.lower()) and
            '..' not in Path(row['path']).parts and type(row['bytes']) is int and 0<row['bytes']<=(sources.EULA_BYTES if row==eula else 65536) and
            type(row['sha256']) is str and t.SHA.fullmatch(row['sha256']),'rpm_license_retention_unverified')
    return value


def cleanup_builder(run,lease,receipt):
    t.require(receipt['unknown_outcome'] is False,'rpm_build_outcome_unknown')
    identifier=receipt['builder_id']
    if identifier is None:return
    entries=[row for row in lease.record['resources'] if row['kind']=='container' and row['id']==identifier]
    t.require(len(entries)==1 and entries[0]['outcome'] in ('pending','absent'),'rpm_build_cleanup_unverified')
    actual=images.inspect('container',identifier,missing=True)
    if actual is not None:
        t.require(entries[0]['outcome']=='pending','rpm_build_cleanup_unverified');verify_builder(run,receipt,actual,lease.plan['limits']['build'])
        if actual['State']['Running']:
            mutation(run,receipt,('stop','--time','2',identifier),timeout=10)
            t.require(images.inspect('container',identifier)['State']['Running'] is False,'rpm_build_cleanup_unverified')
            receipt['unknown_outcome']=False;_save(run,receipt)
        mutation(run,receipt,('rm',identifier));t.require(images.inspect('container',identifier,missing=True) is None,'rpm_build_cleanup_unverified')
        receipt.update(unknown_outcome=False,removal_confirmed=True);_save(run,receipt)
    else:t.require(entries[0]['outcome']=='absent' or receipt['removal_confirmed'] is True,'rpm_build_cleanup_unverified')
    if entries[0]['outcome']=='pending':lease.reconcile_resource('container',identifier)
    receipt['cleanup']='completed';_save(run,receipt)


def build(run,lease,*,base_run):
    from .rpm_resolution import resolve_packages
    t._scope(run,lease);t.require(os.getuid()==0,'rpm_assembly_host_owner')
    cfg=config();lock=t.load_lock();observed=t.read_base_observation(base_run)
    t.require(observed['os_release']['ID']=='rhel' and observed['os_release']['VERSION_ID']=='9.8' and len(observed['key_files'])==1 and
        observed['key_files'][0]['sha256']==KEY_SHA and observed['key_files'][0]['primary_fingerprints']==KEY_FINGERPRINTS,'rpm_base_observation_unsupported')
    t.require(not run.file('evidence/rpm-candidate-build.json').exists(),'rpm_candidate_reused')
    bundle=rc.prepare_manifest(run);recipe,files=rc.recipe_identity();manifest=bundle['manifest']
    resolution=resolve_packages(run,lease,base_run=base_run);packages=sources.prepare_packages(run,lock,resolution);eula=sources.prepare_eula(run)
    request={**common(run.manifest()),'operation':'ubi9-assembly-request-v1','base_image_id':t.BASE_ID,'candidate_sha256':bundle['candidate_sha256'],
        'manifest':manifest,'recipe_sha256':recipe,'source_files':files,'resolution':resolution,'key_file':observed['key_files'][0]}
    atomic_json(run.file('private/rpm-assembly-request.json'),request)
    copied={}
    for name,path in {'assemble.py':rc.CONTEXT/'assemble.py','assembly.json':rc.CONTEXT/'assembly.json','probe.py':rc.CONTEXT/'probe.py',
        'runtime.py':SOURCE_ROOT/'images/runtime.py','sshd_config':SOURCE_ROOT/'images/sshd_config','candidate-install.py':SOURCE_ROOT/'candidate/install.py'}.items():
        copied['/recipe/'+name]=_copy(run,name,path.read_bytes())
    copied['/request/assembly.json']=_copy(run,'request.json',c.canonical(request))
    copied['/license/UBI-EULA-20190422.pdf']=_copy(run,'UBI-EULA-20190422.pdf',sources.validate_eula(run).read_bytes())
    mounts={destination:row['path'] for destination,row in copied.items()}
    mounts.update({'/candidate-input':str(images.safe_bind(bundle['directory'])),'/packages':str(images.safe_bind(packages))})
    receipt={**common(run.manifest()),'operation':'ubi9-candidate-build','status':'pending','started_at':now(),'base_image_id':t.BASE_ID,
        'candidate_sha256':bundle['candidate_sha256'],'recipe_sha256':recipe,'source_files':files,'builder_id':None,'image_id':None,
        'source_bindings':copied,'mounts':mounts,'labels':{**lock['base']['labels'],images.LABEL+'.role':'rpm-builder',images.LABEL+'.run_id':run.id,
            images.LABEL+'.source_revision':run.manifest()['source_revision'],images.LABEL+'.rpm_recipe_sha256':recipe},
        'unknown_outcome':False,'primary_failure':None,'secondary_cleanup_failure':None,'cleanup':'pending','removal_confirmed':False,
        'daemon_materialization_cgroup_capped':False,'runtime_pipeline_complete':False,'production_iso_eligible':False}
    def check_source():
        t.require(source_identity()==(receipt['source_revision'],False) and rc.recipe_identity()==(recipe,files) and
            rc.validate_bundle(run)['candidate_sha256']==bundle['candidate_sha256'],'rpm_candidate_source_changed')
        _check_copies(run,copied);sources.validate_packages(run,lock,resolution)
        sources.validate_eula(run)
    _save(run,receipt)
    try:
        lease.set_phase('assembling');check_source();limits=lease.plan['limits']['build'];t.verify_base(images.inspect('image',t.BASE_ID),lock)
        args=['create','--name','wormhole-'+run.id+'-rpm-build','--network','none','--user','0:0','--workdir','/','--entrypoint','/bin/sh',*images.limits_arguments(limits)]
        for capability in images.BUILD_CAPS:args.extend(('--cap-add',capability))
        for key,value in TMPFS.items():args.extend(('--tmpfs',key+':'+value))
        for item in ('HOME=/tmp','PATH=/usr/sbin:/usr/bin:/sbin:/bin','LANG=C','WORMHOLE_ROLE=rpm-builder','WORMHOLE_RUN_ID='+run.id):args.extend(('--env',item))
        for key,value in receipt['labels'].items():args.extend(('--label',key+'='+value))
        for destination,path in mounts.items():args.extend(('--mount','type=bind,source='+path+',target='+destination+',readonly,bind-propagation=rprivate'))
        args.extend((t.BASE_ID,'-c',SELECT));created=mutation(run,receipt,tuple(args));identifier=created['log'].decode('ascii').strip()
        t.require(not created['log_truncated'] and t.ID.fullmatch(identifier),'rpm_builder_create_unknown')
        lease.register_resource('container',identifier);receipt.update(builder_id=identifier,unknown_outcome=False);_save(run,receipt)
        verify_builder(run,receipt,images.inspect('container',identifier),limits,stopped=True);check_source()
        root=images.docker(('info','--format','{{.DockerRootDir}}'));t.require(not root['log_truncated'],'rpm_storage_unverified')
        storage=Path(root['log'].decode().strip());t.require(storage.is_absolute() and storage.is_dir(),'rpm_storage_unverified')
        images.assembly_storage_guard(lease.plan,storage,images.inspect('container',identifier,size=True))
        mutation(run,receipt,('start',identifier));receipt['unknown_outcome']=False;_save(run,receipt)
        current=images.inspect('container',identifier);verify_builder(run,receipt,current,limits)
        t.require(current['State']['Running'] is True,'rpm_builder_start_failed')
        receipt['builder_cgroups']=images.cgroup_limits(current['State']['Pid'],limits['docker_create']);_save(run,receipt)
        mutation(run,receipt,('exec',identifier,'/bin/sh','-c',RELEASE),timeout=10);receipt['unknown_outcome']=False;_save(run,receipt)
        end=time.monotonic()+min(600,limits['timeout_seconds']);next_storage=0
        while True:
            t.require(time.monotonic()<end,'rpm_assembly_deadline')
            current=images.inspect('container',identifier,timeout=min(5,max(.01,end-time.monotonic())));verify_builder(run,receipt,current,limits)
            t.require(time.monotonic()<end,'rpm_assembly_deadline')
            if time.monotonic()>=next_storage:
                images.assembly_storage_guard(lease.plan,storage,images.inspect('container',identifier,size=True,timeout=min(5,max(.01,end-time.monotonic()))))
                next_storage=time.monotonic()+1
            if not current['State']['Running']:break
            time.sleep(min(.1,max(0,end-time.monotonic())))
        logs=images.docker(('logs','--tail','1000',identifier));atomic_bytes(run.file('private/rpm-assembly.log'),logs['log'],limit=65536)
        t.require(not logs['log_truncated'] and current['State']['Status']=='exited' and current['State']['ExitCode']==0,'rpm_install_failed')
        installed=validate_installed(installed_record(identifier),request,files);receipt['installed']=installed;_save(run,receipt)
        sized=images.inspect('container',identifier,size=True)
        images.assembly_storage_guard(lease.plan,storage,sized);check_source();lease.set_phase('materializing')
        tag='jake-wormhole-ubi-candidate:run-'+run.id;t.require(images.inspect('image',tag,missing=True) is None,'rpm_candidate_tag_exists')
        labels=rc.binding_labels(run,manifest,recipe);args=['commit','--no-pause']
        for change in ['USER 0:0','WORKDIR /home/wormhole','ENTRYPOINT ["/usr/bin/python3","/opt/wormhole/runtime.py","target"]','CMD []']+['LABEL '+key+'='+value for key,value in labels.items()]:args.extend(('--change',change))
        args.extend((identifier,tag));committed=mutation(run,receipt,tuple(args),timeout=lease.plan['materialization']['client_timeout_seconds'])
        t.require(not committed['log_truncated'],'rpm_candidate_commit_unknown');image=images.inspect('image',tag)
        binding={**common(run.manifest()),'operation':'ubi9-candidate-image-binding','status':'built','candidate_sha256':bundle['candidate_sha256'],
            'content_sha256':manifest['content_sha256'],'source_candidate_sha256':manifest['source_candidate_sha256'],'manifest':manifest,
            'base_image':t.BASE_ID,'image_id':image['Id'],'image_labels':labels,'recipe_sha256':recipe,'source_files':files,
            'test_contract_sha256':manifest['test_contract_sha256'],'runtime_pipeline_complete':False,'production_iso_eligible':False}
        rc.verify_image(image,binding);lease.register_resource('image',image['Id']);lease.reconcile_resource('image',image['Id'],outcome='retained',size_bytes=image['Size'])
        receipt.update(image_id=image['Id'],unknown_outcome=False,sampled_writable_layer_bytes=sized['SizeRw']);_save(run,receipt)
        cleanup_builder(run,lease,receipt);check_source();receipt['status']='built';_save(run,receipt)
        atomic_json(run.file('evidence/rpm-candidate-binding.json'),binding);return rc.validate_binding(run)
    except BaseException as error:
        receipt['status']='failed';receipt['primary_failure']={'code':getattr(error,'code','rpm_build_failed'),'recorded_at':now()};_save(run,receipt)
        if not receipt['unknown_outcome']:
            try:cleanup_builder(run,lease,receipt)
            except Exception as secondary:
                receipt['cleanup']='blocked';receipt['secondary_cleanup_failure']={'code':getattr(secondary,'code','rpm_cleanup_failed'),'recorded_at':now()};_save(run,receipt)
        raise
