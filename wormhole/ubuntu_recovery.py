"""Reconcile one stopped VM supervisor through the existing ownership journal."""
import json
import os
from pathlib import Path
import pwd
import subprocess
import xml.etree.ElementTree as ET

from . import vm_baseline as vm
from .admission import CANONICAL_INFRASTRUCTURE_ROOT
from .runs import atomic_json, read_json, run_id, workspace_path, now
from .vm_admission import VMLease, require
from .vm_inputs import sha256, terraform_config


def recover(identifier, terraform):
    require(os.geteuid()==0 and sha256(terraform)==vm.TF_SHA,'runtime_owner_or_tool_mismatch')
    identifier=run_id(identifier)
    run=workspace_path(vm.ROOT/'vm-runs'/identifier)
    result=read_json(run/'result.json')
    require(result['run_id']==identifier,'recovery_run_identity')
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
    def virsh(*args):
        return subprocess.check_output(['virsh','-c','qemu:///system',*args],timeout=10,text=True)
    with VMLease.resume(CANONICAL_INFRASTRUCTURE_ROOT,identifier,result['source_revision']) as lease:
        require({(x['kind'],x['identity']) for x in lease.record['resources']}<=expected,'recovery_ownership_mismatch')
        helper=name+'-controller'
        inspected=subprocess.run(['docker','inspect',helper],capture_output=True,text=True,timeout=10)
        if inspected.returncode==0:
            item=json.loads(inspected.stdout)[0]
            require(item['Config']['Labels'].get('vm-run')==identifier and item['Config']['Image']==vm.HELPER,'controller_ownership_mismatch')
            subprocess.run(['docker','rm','-f',item['Id']],check=True,capture_output=True,timeout=20)
        domains=set(virsh('list','--all','--name').split())
        networks=set(virsh('net-list','--all','--name').split())
        pools=set(virsh('pool-list','--all','--name').split())
        if name in domains or name in networks or name in pools or (pool/(name+'.qcow2')).exists():
            qemu=pwd.getpwnam('libvirt-qemu')
            tfdir=run/'terraform'
            require(sha256(tfdir/'main.tf.json')==result.get('terraform_configuration_sha256')
                    and read_json(tfdir/'main.tf.json')==terraform_config(name,pool,candidate,seed,vm.NETWORK,
                        '52:54:00:'+':'.join(identifier.replace('-','')[n:n+2] for n in (0,2,4)),qemu.pw_uid,qemu.pw_gid),
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
        for item in list(lease.record['resources']):
            if item['outcome']=='pending':
                lease.reconciled(item['kind'],item['identity'],
                    retained_input=item['kind'] in {'installer_iso','seed_iso'} and Path(item['identity']).is_file())
        lease.finish()
        result['recovery']={'state':'stopped-and-cleaned','at':now(),'original_outcome':result['outcome']}
        if result['outcome']=='running':
            result.update(outcome='unknown',error_category='supervisor_interrupted_without_terminal_result')
        result['cleanup']='verified-absent-inputs-retained'
        atomic_json(run/'result.json',result)
    return result
