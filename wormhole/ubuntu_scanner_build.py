"""Offline scanner dependency build using the existing shared admission lease."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from .admission import AdmissionLease,CANONICAL_INFRASTRUCTURE_ROOT
from .images import limits_arguments,BUILD_CAPS
from .runs import SOURCE_ROOT,source_identity,atomic_json,workspace_path
from .ubuntu_inputs import prepare
from .ubuntu_assessment import require
from .vm_inputs import sha256

SOURCE_SHA='7c6064ea52bc0002a21ba8d49e33bb25f55c388a06ba60b3c5ba02783b8acf8e'


def build(store,base):
    require(os.geteuid()==0,'runtime_owner_required')
    revision,dirty=source_identity();require(not dirty,'clean_scanner_source_required')
    store=workspace_path(store);prepare(store)
    require(sha256(store/'openscap-1.4.6.tar.gz')==SOURCE_SHA,'scanner_source_mismatch')
    require(re.fullmatch(r'docker[.]io/library/ubuntu@sha256:[a-f0-9]{64}',base),'scanner_base_unpinned')
    identifier=str(uuid.uuid4());run=workspace_path(CANONICAL_INFRASTRUCTURE_ROOT.parent/'scanner-builds'/identifier,create=True)
    work=run/'work';work.mkdir(mode=0o700)
    receipt={'source_revision':revision,'source_sha256':SOURCE_SHA,'base':base,'state':'running','production_iso_eligible':False}
    atomic_json(run/'result.json',receipt)
    def call(args,timeout=30):return subprocess.run(['docker',*args],capture_output=True,timeout=timeout,check=True)
    with AdmissionLease(CANONICAL_INFRASTRUCTURE_ROOT,identifier,revision,profile='smoke') as lease:
        container=None
        allocation_unknown=False
        try:
            lease.set_phase('assembling')
            present=subprocess.run(['docker','image','inspect',base],capture_output=True,timeout=20)
            if present.returncode:
                lease.set_phase('materializing')
                call(['pull','--platform','linux/amd64',base],timeout=120)
                image=json.loads(call(['image','inspect',base]).stdout)[0]
                lease.register_resource('image',image['Id'])
                lease.reconcile_resource('image',image['Id'],outcome='retained',size_bytes=image['Size'])
                lease.set_phase('assembling')
            base_info=json.loads(call(['image','inspect',base]).stdout)[0]
            require(base_info['Architecture']=='amd64' and base_info['Os']=='linux' and not base_info['Config'].get('Volumes'),'scanner_base_invalid')
            limits=lease.plan['limits']['build']
            name='wormhole-'+identifier+'-scanner-build'
            args=['create','--name',name,'--network','none','--entrypoint','/bin/bash',*limits_arguments(limits),
                  '--label','io.jake-wormhole.run_id='+identifier,'--label','application=jake-wormhole']
            for capability in BUILD_CAPS:args+=['--cap-add',capability]
            for source,target,read_only in [(store/'bundle','/inputs',True),(store,'/source',True),
                   (SOURCE_ROOT/'ubuntu/support','/recipe',True),(work,'/work',False)]:
                args+=['--mount','type=bind,src='+str(source)+',dst='+target+(',readonly' if read_only else '')]
            args+=[base,'/recipe/build-scanner.sh']
            allocation_unknown=True
            container=call(args).stdout.decode().strip()
            require(re.fullmatch('[a-f0-9]{64}',container),'scanner_create_unknown')
            lease.register_resource('container',container);allocation_unknown=False
            actual=json.loads(call(['inspect',container]).stdout)[0]
            require(actual['Config']['Labels'].get('io.jake-wormhole.run_id')==identifier and actual['HostConfig']['NetworkMode']=='none'
                    and actual['HostConfig']['Memory']==2*1024**3 and actual['HostConfig']['NanoCpus']==2_000_000_000,'scanner_limits_missing')
            started=time.monotonic();call(['start',container])
            while True:
                current=json.loads(call(['inspect','--size',container]).stdout)[0]
                size=0
                for file in work.rglob('*'):
                    try:
                        if file.is_file():size+=file.stat().st_size
                    except FileNotFoundError:pass
                require(current['SizeRw']+size<4*1024**3,'scanner_disk_budget')
                if not current['State']['Running']:break
                require(time.monotonic()-started<limits['timeout_seconds'],'scanner_build_deadline');time.sleep(3)
            logs=call(['logs',container]);(run/'build.log').write_bytes(logs.stdout+logs.stderr)
            require(current['State']['ExitCode']==0,'scanner_build_failed')
            receipt.update(state='complete',elapsed_seconds=round(time.monotonic()-started,3),
                artifact_sha256=sha256(work/'openscap-lab.tar.gz'),base_image_id=base_info['Id'])
        except BaseException as error:
            receipt.update(state='unknown' if allocation_unknown else 'failed',error_category=getattr(error,'code',type(error).__name__))
            raise
        finally:
            if allocation_unknown:
                atomic_json(run/'result.json',receipt)
                require(False,'scanner_allocation_requires_reconciliation')
            if container:
                actual=json.loads(call(['inspect',container]).stdout)[0]
                require(actual['Config']['Labels'].get('io.jake-wormhole.run_id')==identifier,'scanner_cleanup_ownership')
                call(['rm','-f',container]);lease.set_phase('reconciling');lease.reconcile_resource('container',container,outcome='absent')
            lease.finish(reconciliation_complete=True)
            atomic_json(run/'result.json',receipt)
            try:
                from .storage import lifecycle
                receipt['storage_cleanup']=lifecycle(lease)
            except Exception as error:
                receipt['storage_cleanup_error']=getattr(error,'code',type(error).__name__)
            atomic_json(run/'result.json',receipt)
    return {'build_directory':str(run),'state':receipt['state'],'elapsed_seconds':receipt.get('elapsed_seconds')}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--store',required=True);p.add_argument('--base',required=True)
    a=p.parse_args();print(json.dumps(build(a.store,a.base)))


if __name__=='__main__':main()
