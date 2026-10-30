"""Reconcile one stopped VM supervisor through the existing ownership journal."""
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import time
import xml.etree.ElementTree as ET

from . import vm_baseline as vm
from .admission import CANONICAL_INFRASTRUCTURE_ROOT
from .runs import atomic_json, read_json, run_id, workspace_path, now
from .vm_admission import VMLease, require
from .vm_inputs import sha256, terraform_config


def recover(identifier, terraform=None):
    require(os.geteuid()==0,'runtime_owner_required')
    identifier=run_id(identifier)
    run=workspace_path(vm.ROOT/'vm-runs'/identifier)
    result=read_json(run/'result.json')
    require(result['run_id']==identifier,'recovery_run_identity')
    provisioner=result.get('provisioner','terraform')
    require(provisioner=='terraform','recovery_provisioner_invalid')
    require(terraform is not None and sha256(terraform)==vm.TF_SHA,'runtime_owner_or_tool_mismatch')
    supervisor=result.get('supervisor')
    require(supervisor is not None,'supervisor_identity_missing')
    require(vm.process_identity(supervisor['pid'])!=supervisor,'supervisor_still_running')
    command=result.get('active_command')
    require(command is None or vm.process_identity(command['pid'])!=command,'operation_still_running')
    name='wormhole-vm-'+identifier.replace('-','')[:12]
    share=vm.SHARED/identifier
    pool=share/'disk'
    candidate,seed=share/'candidate.iso',share/'seed.iso'
    expected={('domain',name),('network',name),('pool',name),('disk',str(pool/(name+'.qcow2'))),
              ('installer_iso',str(candidate)),('seed_iso',str(seed)),('controller_container',name+'-controller')}
    sandbox=result.get('build',{}).get('sandbox') is True
    isolated=sandbox or result.get('network_isolated') is True
    if sandbox:expected.add(('support_container',name+'-services'))
    if isolated:expected.add(('network_filter',name+'-isolation'))
    def virsh(*args):
        return subprocess.check_output(['virsh','-c','qemu:///system',*args],timeout=10,text=True)
    with VMLease.resume(CANONICAL_INFRASTRUCTURE_ROOT,identifier,result['source_revision']) as lease:
        require({(x['kind'],x['identity']) for x in lease.record['resources']}<=expected,'recovery_ownership_mismatch')
        for helper in [name+'-controller']+([name+'-services'] if sandbox else []):
            inspected=subprocess.run(['docker','inspect',helper],capture_output=True,text=True,timeout=10)
            if inspected.returncode==0:
                item=json.loads(inspected.stdout)[0]
                require(item['Config']['Labels'].get('vm-run')==identifier and item['Config']['Image']==vm.HELPER,'controller_ownership_mismatch')
                subprocess.run(['docker','rm','-f',item['Id']],check=True,capture_output=True,timeout=20)
        domains=set(virsh('list','--all','--name').split())
        networks=set(virsh('net-list','--all','--name').split())
        pools=set(virsh('pool-list','--all','--name').split())
        resources_present=name in domains or name in networks or name in pools or (pool/(name+'.qcow2')).exists()
        if resources_present:
            qemu=pwd.getpwnam('libvirt-qemu')
            tfdir=run/'terraform'
            expected_config=terraform_config(name,pool,candidate,seed,vm.NETWORK,
                        '52:54:00:'+':'.join(identifier.replace('-','')[n:n+2] for n in (0,2,4)),qemu.pw_uid,qemu.pw_gid,
                        disk_bytes=(32 if result.get('distribution')=='rhel10' else 64)*1024**3)
            if isolated:
                from .ubuntu_sandbox import attach_filter
                expected_config=attach_filter(expected_config,name+'-isolation')
            require(sha256(tfdir/'main.tf.json')==result.get('terraform_configuration_sha256')
                    and read_json(tfdir/'main.tf.json')==expected_config,
                    'recovery_configuration_changed')
            state=read_json(tfdir/'terraform.tfstate')
            require(all(x['type'] in {'libvirt_pool','libvirt_network','libvirt_domain','libvirt_volume'}
                        and x['name'] in {'run','disk'} and x.get('mode','managed')=='managed'
                        for x in state['resources']),'recovery_state_mismatch')
            for resource in state['resources']:
                for instance in resource['instances']:
                    attributes=instance['attributes']
                    require(attributes['name']==(name+'.qcow2' if resource['type']=='libvirt_volume' else name),
                            'recovery_state_mismatch')
            if name in domains:
                domain=ET.fromstring(virsh('dumpxml',name))
                require(domain.findtext('description')=='jake-wormhole libvirt-iso '+name,'domain_ownership_mismatch')
                require({d.find('source').get('file') for d in domain.findall('devices/disk') if d.get('device')=='cdrom'}==
                        {str(candidate),str(seed)},'recovery_attached_media_mismatch')
            if name in pools:require(ET.fromstring(virsh('pool-dumpxml',name)).findtext('target/path')==str(pool),'pool_ownership_mismatch')
            if name in networks:
                network=ET.fromstring(virsh('net-dumpxml',name))
                require(network.find('forward') is None and network.find('ip').get('address')=='192.0.2.1','network_ownership_mismatch')
            with (run/'recovery-cleanup.log').open('xb') as log:
                subprocess.run([terraform,'-chdir='+str(tfdir),'destroy','-auto-approve','-input=false','-no-color'],
                               stdout=log,stderr=subprocess.STDOUT,check=True,timeout=90)
        for query in ('list','net-list','pool-list'):
            require(name not in virsh(query,'--all','--name').split(),'recovery_cleanup_incomplete')
        require(not (pool/(name+'.qcow2')).exists(),'recovery_disk_remains')
        console=result.get('console_process')
        if console and vm.process_identity(console['pid'])==console:
            require(os.getpgid(console['pid'])==console['pid'],'console_process_group_mismatch')
            os.killpg(console['pid'],signal.SIGTERM)
            end=time.monotonic()+5
            while vm.process_identity(console['pid'])==console and time.monotonic()<end:time.sleep(.1)
            if vm.process_identity(console['pid'])==console:os.killpg(console['pid'],signal.SIGKILL)
        if isolated:
            from .ubuntu_sandbox import remove_filter
            remove_filter(run,name+'-isolation')
        for item in list(lease.record['resources']):
            if item['outcome']=='pending':
                lease.reconciled(item['kind'],item['identity'],
                    retained_input=item['kind'] in {'installer_iso','seed_iso'} and Path(item['identity']).is_file())
        lease.finish()
        result['recovery']={'state':'stopped-and-cleaned','at':now(),'original_outcome':result['outcome']}
        if result['outcome']=='running':
            result.update(outcome='unknown',error_category='supervisor_interrupted_without_terminal_result')
            result.setdefault('first_failure',result['error_category'])
            if 'checks' in result:result['checks']={k:'blocked' if v=='pending' else v for k,v in result['checks'].items()}
        result['cleanup']='verified-absent-inputs-retained'
        result.setdefault('finished_at',now())
        atomic_json(run/'result.json',result)
        try:
            from .ubuntu_runtime import report
            from .storage import lifecycle
            if result.get('distribution')!='rhel10':report(run,result)
            result['storage_cleanup']=lifecycle(lease,identifier)
            if result['storage_cleanup']['retention_budget_exceeded']:
                result['storage_cleanup_error']='storage_retention_budget'
        except Exception as error:
            result['storage_cleanup_error']=getattr(error,'code',type(error).__name__)
        atomic_json(run/'result.json',result)
    return result
