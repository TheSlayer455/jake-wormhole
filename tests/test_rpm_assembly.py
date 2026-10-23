"""Original builder-policy fixtures. Every Docker/DNF/package result is mocked.

The process-bound tests run only authored local Python, never an upstream tool.
"""
from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from wormhole import admission,candidate as c,chunks,images,rpm_candidate as rc,rpm_assembly as a,rpm_target as t,rpm_source as sources,rpm_resolution
from wormhole.runs import create_run,read_json
from test_admission import observed

REVISION='a'*40
BUILDER='b'*64
DERIVED='sha256:'+'c'*64


class AssemblyPure(unittest.TestCase):
    def test_fixed_source_policy_has_only_observed_keys_and_unmodified_eula_identity(self):
        value=a.config()
        self.assertEqual(value['trusted_primary_fingerprints'],a.KEY_FINGERPRINTS)
        self.assertEqual(value['eula']['sha256'],sources.EULA_SHA256)
        self.assertFalse(value['production_iso_eligible'])
        self.assertNotIn('SYS_ADMIN',images.BUILD_CAPS)

    def test_digests_alone_missing_key_or_bad_signature_are_not_crypto_success(self):
        spec=importlib.util.spec_from_file_location('fixed_rpm_signature_fixture',rc.CONTEXT/'assemble.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        positive=b'/packages/synthetic.rpm:\n Header V4 RSA/SHA256 Signature, key ID fd431d51: OK\n Payload SHA256 digest: OK\n'
        self.assertEqual(module.signature_output(positive),c.sha(positive))
        for output in (b'Payload SHA256 digest: OK\n',positive+b'Header V6 Signature: NOKEY\n',positive.replace(b': OK',b': NOT OK'),b'x'*65537):
            with self.assertRaises(module.AssemblyError):module.signature_output(output)

    @unittest.skipUnless(os.name=='posix','POSIX process bound fixture')
    def test_actual_fixed_capture_kills_oversize_or_deadline_child(self):
        spec=importlib.util.spec_from_file_location('fixed_rpm_assemble_fixture',rc.CONTEXT/'assemble.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for program,seconds in (("import sys;sys.stdout.write('x'*70000);sys.stdout.flush()",2),('import time;time.sleep(10)',.1)):
            with self.assertRaises(module.AssemblyError):module.command([sys.executable,'-I','-B','-c',program],seconds)


@unittest.skipUnless(sys.platform.startswith('linux') and os.getuid()==0,'Root-owned synthetic Linux builder fixture; ALL Docker mocked')
class Builder(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='wormhole-rpm-assembly-synthetic-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.run=create_run(self.root/'runs',fixture=False,identity=(REVISION,False),kernel_lock=True)
        self.calls=[];self.args=[];self.started=False;self.running=False;self.released=False;self.polls=0;self.removed=False;self.committed=False
        self.unknown_commit=False;self.oversize_live=False;self.bad_signature=False;self.bad_licence=False
        for owner in (c,chunks,rc,t,a):
            item=patch.object(owner,'source_identity',return_value=(REVISION,False));item.start();self.addCleanup(item.stop)
        self.assertEqual(chunks.execute_fixture(self.run)['status'],'passed')
        with self.run.locked():c.prepare_candidate(self.run)
        self.packages=self.run.file('private/fake-public-package-cache');self.packages.mkdir(mode=0o700)
        self.eula=self.run.file('private/fake-public-eula.pdf');self.eula.write_bytes(b'Synthetic public EULA transport fixture, not the official PDF.')
        parent=self
        class Lease:
            root=images.INFRASTRUCTURE;run_id=parent.run.id;source_revision=REVISION;_reconciliation_only=False
            plan=admission.build_plan('smoke',observed());plan['synthetic']=False
            record={'resources':[{'kind':'image','id':t.BASE_ID,'outcome':'retained'}]}
            def _active(self):pass
            def set_phase(self,phase):parent.calls.append(('phase',phase))
            def register_resource(self,kind,identifier):self.record['resources'].append({'kind':kind,'id':identifier,'outcome':'pending'})
            def reconcile_resource(self,kind,identifier,**options):
                parent.calls.append(('reconcile',kind,identifier))
                for row in self.record['resources']:
                    if (row['kind'],row['id'])==(kind,identifier):row['outcome']=options.get('outcome','absent')
        self.lease=Lease()
        base={'os_release':{'ID':'rhel','VERSION_ID':'9.8'},'key_files':[{'path':t.KEY_PATHS[0],'sha256':a.KEY_SHA,
            'primary_fingerprints':a.KEY_FINGERPRINTS,'signature_verification':'not-performed','bytes':3682}]}
        for owner,name,value in ((images,'RUNS_ROOT',self.run.workspace),(t,'read_base_observation',lambda run:base),
            (rpm_resolution,'resolve_packages',lambda *args,**kwargs:{'packages':[]}),(sources,'prepare_packages',lambda *args:self.packages),
            (sources,'validate_packages',lambda *args:self.packages),(sources,'prepare_eula',lambda *args:self.eula),(sources,'validate_eula',lambda *args:self.eula),
            (images,'inspect',self.inspect),(images,'docker',self.docker),(images,'cgroup_limits',self.cgroups),
            (images,'assembly_storage_guard',self.storage),(a,'installed_record',self.record)):
            item=patch.object(owner,name,value);item.start();self.addCleanup(item.stop)

    def cgroups(self,pid,limits):
        self.calls.append(('cgroup',pid));self.assertTrue(self.running);self.assertFalse(self.released)
        return {'memory.max':str(limits['memory_bytes']),'pids.max':str(limits['pids_limit'])}

    def storage(self,plan,root,value):
        self.calls.append(('storage',self.running,self.released))
        if self.oversize_live and self.running and self.released:raise images.ImageError('writable_layer_too_large','Synthetic sampled layer overflow')

    def container(self):
        def values(flag):return [self.args[i+1] for i,x in enumerate(self.args) if x==flag]
        labels=dict(item.split('=',1) for item in values('--label'));expected=self.lease.plan['limits']['build']['docker_create']
        receipt=read_json(self.run.file('evidence/rpm-candidate-build.json'))
        return {'Id':BUILDER,'Image':t.BASE_ID,'Name':'/wormhole-'+self.run.id+'-rpm-build','Config':{'Labels':labels,'User':'0:0','WorkingDir':'/',
            'Entrypoint':['/bin/sh'],'Cmd':['-c',a.SELECT],'Env':values('--env'),'Tty':False,'OpenStdin':False},
            'HostConfig':{'Memory':expected['memory_bytes'],'MemorySwap':expected['memory_swap_bytes'],'NanoCpus':expected['nano_cpus'],
                'PidsLimit':expected['pids_limit'],'LogConfig':{'Type':expected['log_driver'],'Config':expected['log_opts']},'Tmpfs':a.TMPFS,
                'NetworkMode':'none','Privileged':False,'ReadonlyRootfs':False,'CapDrop':['ALL'],'CapAdd':list(images.BUILD_CAPS),
                'PidMode':'','IpcMode':'private','UTSMode':'','CgroupnsMode':'private','RestartPolicy':{'Name':'no'},'SecurityOpt':['no-new-privileges:true']},
            'Mounts':[{'Type':'bind','RW':False,'Destination':destination,'Source':source} for destination,source in receipt['mounts'].items()],
            'State':{'Running':self.running,'Pid':123 if self.running else 0,'Status':'running' if self.running else 'exited' if self.started else 'created',
                'StartedAt':'2026-10-23T18:00:00Z' if self.started else '0001-01-01T00:00:00Z','ExitCode':0},'SizeRw':10000000}

    def inspect(self,kind,identifier,**options):
        if kind=='container':
            if self.removed:return None
            if self.released and not options.get('size'):
                self.polls+=1
                if self.polls>1:self.running=False
            return self.container()
        if identifier==t.BASE_ID:
            return {'Id':t.BASE_ID,'Os':'linux','Architecture':'amd64','RepoDigests':[t.BASE],'Size':80416938,'Config':{'Labels':t.load_lock()['base']['labels']},
                'Descriptor':{'mediaType':'application/vnd.docker.distribution.manifest.v2+json','digest':t.BASE_ID,'size':429}}
        if not self.committed:return None
        binding=rc.validate_bundle(self.run);recipe,_=rc.recipe_identity()
        return {'Id':DERIVED,'Parent':t.BASE_ID,'Os':'linux','Architecture':'amd64','Size':250000000,'Config':{
            'Labels':rc.binding_labels(self.run,binding['manifest'],recipe),'User':'0:0','WorkingDir':'/home/wormhole',
            'Entrypoint':['/usr/bin/python3','/opt/wormhole/runtime.py','target'],'Cmd':[]}}

    def docker(self,args,**options):
        self.calls.append(('docker',*args));raw=b''
        if args[0]=='create':
            self.args=list(args);raw=BUILDER.encode()+b'\n';self.assertEqual(args[args.index('--network')+1],'none')
            self.assertNotIn('--privileged',args);self.assertFalse(any('docker.sock' in arg or 'credentials' in arg for arg in args))
        if args[0]=='start':self.started=True;self.running=True
        if args[0]=='exec':self.assertTrue(any(row[0]=='cgroup' for row in self.calls));self.released=True
        if args[0]=='info':raw=str(self.root).encode()
        if args[0]=='stop':self.running=False
        if args[0]=='rm':self.removed=True
        if args[0]=='commit':
            if self.unknown_commit:raise images.ImageError('docker_request_unknown','Synthetic timeout, no actual Docker')
            self.committed=True;raw=b'Docker diagnostic line\n'+DERIVED.encode()+b'\n'  # Do not parse the combined log as an ID.
        return {'log':raw,'log_truncated':False,'status':'pass','returncode':0}

    def record(self,identifier):
        self.assertEqual(identifier,BUILDER);bundle=rc.validate_bundle(self.run);_,files=rc.recipe_identity()
        result={'status':'installed','base_image_id':t.BASE_ID,'candidate_sha256':bundle['candidate_sha256'],'content_sha256':bundle['manifest']['content_sha256'],
            'source_candidate_sha256':bundle['manifest']['source_candidate_sha256'],'installed_packages':[{'name':name,**version} for name,version in rc.PACKAGE_VERSIONS.items()],
            'signature_results':[],'key_files':[{'path':t.KEY_PATHS[0],'sha256':a.KEY_SHA,'primary_fingerprints':a.KEY_FINGERPRINTS}],
            'key_records':[],'os_release':{'ID':'rhel','VERSION_ID':'9.8'},'license_files':[{'path':'/licenses/ubi9-container/UBI-EULA-20190422.pdf',
                'bytes':sources.EULA_BYTES,'sha256':sources.EULA_SHA256}],'dependency_check':'passed','hostkeys_absent':True,
            'runtime_sha256':files['images/runtime.py'],'sshd_config_sha256':files['images/sshd_config'],'runtime_pipeline_complete':False,'production_iso_eligible':False}
        if self.bad_signature:result['signature_results']=[{'signature':'unverified'}]
        if self.bad_licence:result['license_files']=[]
        return result

    def test_exact_capped_offline_builder_commits_by_owned_tag_then_reconciles(self):
        with self.run.locked():binding=rc.build_rpm_candidate(self.run,self.lease,base_run=self.run)
        self.assertEqual(binding['image_id'],DERIVED);self.assertEqual(binding['content_sha256'],rc.content_identity(c.validate_bundle(self.run)['manifest']))
        self.assertTrue(self.removed);self.assertTrue(self.committed)
        self.assertTrue(all(row['outcome']!='pending' for row in self.lease.record['resources']))
        self.assertTrue(any(row[:3]==('storage',True,True) for row in self.calls))
        self.assertFalse(read_json(self.run.file('evidence/rpm-candidate-build.json'))['daemon_materialization_cgroup_capped'])

    def test_unknown_commit_preserves_container_and_never_cleans_by_empty_sweep(self):
        self.unknown_commit=True
        with self.run.locked(),self.assertRaises(images.ImageError):rc.build_rpm_candidate(self.run,self.lease,base_run=self.run)
        receipt=read_json(self.run.file('evidence/rpm-candidate-build.json'));self.assertTrue(receipt['unknown_outcome']);self.assertFalse(self.removed)
        self.assertEqual(self.lease.record['resources'][-1]['outcome'],'pending')

    def test_live_sampled_disk_overflow_stops_only_known_builder_before_commit(self):
        self.oversize_live=True
        with self.run.locked(),self.assertRaises(images.ImageError):rc.build_rpm_candidate(self.run,self.lease,base_run=self.run)
        receipt=read_json(self.run.file('evidence/rpm-candidate-build.json'))
        self.assertEqual(receipt['primary_failure']['code'],'writable_layer_too_large');self.assertFalse(receipt['unknown_outcome'])
        self.assertTrue(self.removed);self.assertFalse(self.committed)

    def test_no_signature_or_license_claim_can_reach_image_commit(self):
        self.bad_signature=True
        with self.run.locked(),self.assertRaises(t.RpmError):rc.build_rpm_candidate(self.run,self.lease,base_run=self.run)
        self.assertFalse(self.committed);self.assertTrue(self.removed)

    def test_absent_or_substituted_eula_cannot_reach_image_commit(self):
        self.bad_licence=True
        with self.run.locked(),self.assertRaises(t.RpmError) as error:rc.build_rpm_candidate(self.run,self.lease,base_run=self.run)
        self.assertEqual(error.exception.code,'rpm_license_retention_unverified')
        self.assertFalse(self.committed);self.assertTrue(self.removed)

    def test_public_source_copy_is_rechecked_before_known_cleanup(self):
        with self.run.locked():rc.build_rpm_candidate(self.run,self.lease,base_run=self.run)
        receipt=read_json(self.run.file('evidence/rpm-candidate-build.json'))
        self.assertEqual(Path(receipt['source_bindings']['/recipe/assemble.py']['path']).stat().st_mode&0o777,0o444)
        value=self.container();value['Image']='sha256:'+'f'*64
        with self.assertRaises(t.RpmError):a.verify_builder(self.run,receipt,value,self.lease.plan['limits']['build'])


if __name__=='__main__':unittest.main()
