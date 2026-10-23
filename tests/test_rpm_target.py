"""Original synthetic UBI metadata/process fixtures; ALL Docker calls are mocked."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wormhole import admission, images, rpm_target as r
from wormhole.runs import atomic_json, create_run, read_json
from test_admission import observed

REVISION = 'a' * 40
CONTAINER = 'b' * 64


def observation(run):
    return {'schema_version':'1.0','operation':'ubi-base-observation-v1','status':'observed','run_id':run.id,
        'source_revision':REVISION,'probe_sha256':r.recipe_identity()[1]['probe.py'],
        'os_release':{'ID':'rhel','VERSION_ID':'9.8','NAME':'Synthetic UBI fixture'},
        'installed_packages':[{'name':'gpg-pubkey','epoch':0,'version':'fd431d51','release':'4ae0493b','arch':'(none)'},
            {'name':'python3','epoch':0,'version':'3.9.25','release':'7.el9_8.3','arch':'x86_64'}],
        'python':{'version':'3.9.25','executable':'/usr/bin/python3'},'rpm':{'version':'4.16.1.3'},
        'dnf':{'available':True,'version':'4.14.0','base_api':True,'repos_loaded':False,'transaction_run':False},
        'key_files':[],'license_files':[], 'executables':{key:False for key in r.EXECUTABLES},
        'execution':{'uid':0,'gid':0,'pid':1},'shared_kernel_release':'synthetic-shared-kernel',
        'packages_installed':False,'production_iso_eligible':False}


class Policy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='wormhole-rpm-policy-'); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.run = create_run(self.root/'runs',fixture=False,identity=(REVISION,False))

    def test_pinned_full_inherited_labels_and_original_ubuntu_recipe_are_independent(self):
        lock = r.load_lock(); image = {'Id':r.BASE_ID,'Os':'linux','Architecture':'amd64','RepoDigests':[r.BASE],
            'Config':{'Labels':deepcopy(lock['base']['labels'])},'Size':200000000}
        r.verify_base(image,lock)
        self.assertEqual(lock['base']['labels']['version'],'9.8')
        self.assertEqual(lock['base']['labels']['vendor'],'Red Hat, Inc.')
        image['Config']['Labels']['unexpected']='not trusted'
        with self.assertRaises(r.RpmError): r.verify_base(image,lock)
        image['Config']['Labels']=deepcopy(lock['base']['labels']); image['Id']='sha256:'+'c'*64
        with self.assertRaises(r.RpmError): r.verify_base(image,lock)
        self.assertNotIn('rpm',images.FILES)

    def test_complete_sorted_full_rpm_versions_and_honest_unavailable_dnf(self):
        value=observation(self.run)
        # JSON canonical ordering does not alter the executable mapping contract.
        value=json.loads(r.canonical(value)); r.validate_observation(self.run,value,value['probe_sha256'])
        value['dnf']={'available':False,'version':None,'base_api':False,'repos_loaded':False,'transaction_run':False}
        value['installed_packages'][0]['arch']=None  # Preserve a virtual RPM key header's absent architecture.
        r.validate_observation(self.run,value,value['probe_sha256'])
        for alter in (lambda x:x['installed_packages'].append(x['installed_packages'][0]),
            lambda x:x['installed_packages'][0].update(epoch=False),lambda x:x.update(production_iso_eligible=True),
            lambda x:x['dnf'].update(transaction_run=True),lambda x:x.update(run_id='wrong'),
            lambda x:x['executables'].update({'/private/credential':True}),lambda x:x['execution'].update(uid=False),
            lambda x:x['installed_packages'][0].update(version='bad\nvalue')):
            changed=deepcopy(value); alter(changed)
            with self.assertRaises(r.RpmError): r.validate_observation(self.run,changed,changed['probe_sha256'])

    def test_old_fixture_or_dirty_run_never_becomes_actual_base_provenance(self):
        fixture=create_run(self.root/'other-runs',fixture=True,identity=(REVISION,False))
        with self.assertRaises(r.RpmError): r.read_base_observation(fixture)
        manifest=self.run.manifest(); manifest['source_dirty']=True; self.run.save_manifest(manifest)
        with self.assertRaises(r.RpmError): r.read_base_observation(self.run)

    def test_package_probe_preserves_nullable_virtual_key_arch_only(self):
        spec=importlib.util.spec_from_file_location('fixed_rpm_package_probe',r.CONTEXT/'probe.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        headers=[{'name':'gpg-pubkey','epoch':None,'version':'fd431d51','release':'4ae0493b','arch':None}]
        class Transaction:
            def dbMatch(self): return headers
            def closeDB(self): pass
        class Rpm:
            def TransactionSet(self,root): return Transaction()
        self.assertIsNone(module.packages(Rpm())[0]['arch'])
        headers[0]['name']='python3'
        with self.assertRaises(ValueError): module.packages(Rpm())

    def test_duplicate_json_partial_output_and_oversized_body_refuse(self):
        for raw in (b'{"status":"observed","status":"observed"}\n',b'{"status":"observed"}',b'x'*(r.MAX_OUTPUT+2)):
            with self.assertRaises(r.RpmError): r._parse(raw)

    def test_v4_fingerprint_is_computed_but_not_claimed_signature_verification(self):
        spec=importlib.util.spec_from_file_location('fixed_rpm_probe',r.CONTEXT/'probe.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        packet=b'\x04\x00\x00\x00\x01\x01\x00\x01\x01'
        armored=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'+base64.b64encode(bytes([0xc6,len(packet)])+packet)+b'\n-----END PGP PUBLIC KEY BLOCK-----\n'
        expected=hashlib.sha1(b'\x99'+len(packet).to_bytes(2,'big')+packet).hexdigest().upper()
        self.assertEqual(module.fingerprints(armored),[expected])
        for raw in (b'not a key',armored.replace(b'BgAAAAE',b'invalid')):
            if raw != armored:
                with self.assertRaises((ValueError,TypeError)): module.fingerprints(raw)

    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux explicit PID1 deadline policy')
    def test_explicit_alarm_interrupts_blocked_probe_code_without_parent(self):
        code="import importlib.util,time\ns=importlib.util.spec_from_file_location('probe',"+repr(str(r.CONTEXT/'probe.py'))+")\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.deadline(1)\ntry: time.sleep(9)\nexcept TimeoutError: raise SystemExit(0)\nraise SystemExit(3)"
        result=subprocess.run([sys.executable,'-I','-B','-c',code],timeout=3,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(result.returncode,0)


@unittest.skipUnless(sys.platform.startswith('linux'),'Real Linux policy fixtures; every Docker operation mocked')
class Driver(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='wormhole-rpm-driver-'); self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name); self.run=create_run(self.root/'runs',fixture=False,identity=(REVISION,False),kernel_lock=True)
        self.calls=[]; self.created=False; self.running=False; self.removed=False; self.released=False; self.args=[]; self.cached=True
        self.bad_capture=False; self.start_unknown=False; self.empty_capture=False
        parent=self
        class Lease:
            root=images.INFRASTRUCTURE; run_id=parent.run.id; source_revision=REVISION; _reconciliation_only=False
            plan=admission.build_plan('smoke',observed()); plan['synthetic']=False
            record={'resources':[]}
            def _active(self): pass
            def set_phase(self,phase): parent.calls.append(('phase',phase))
            def register_resource(self,kind,identifier): self.record['resources'].append({'kind':kind,'id':identifier,'outcome':'pending'})
            def reconcile_resource(self,kind,identifier,**options):
                parent.calls.append(('reconcile',kind,identifier))
                for row in self.record['resources']:
                    if (row['kind'],row['id'])==(kind,identifier): row['outcome']=options.get('outcome','absent')
        self.lease=Lease()
        for owner,name,value in ((r,'source_identity',lambda:(REVISION,False)),(images,'RUNS_ROOT',self.run.workspace),
            (images,'docker',self.docker),(images,'inspect',self.inspect),(images,'cgroup_limits',self.cgroups)):
            item=patch.object(owner,name,value); item.start(); self.addCleanup(item.stop)

    def cgroups(self,pid,expected):
        self.calls.append(('cgroup',pid)); self.assertTrue(self.running); self.assertFalse(self.released)
        return {'memory.max':str(expected['memory_bytes']),'pids.max':str(expected['pids_limit'])}

    def container(self):
        args=self.args
        def values(flag): return [args[i+1] for i,x in enumerate(args) if x==flag]
        labels=dict(value.split('=',1) for value in values('--label')); e=self.lease.plan['limits']['build']['docker_create']
        return {'Id':CONTAINER,'Image':r.BASE_ID,'Name':'/wormhole-'+self.run.id+'-rpm-probe',
            'Config':{'Labels':labels,'User':'0:0','WorkingDir':'/','Entrypoint':['/bin/sh'],'Cmd':['-c',r.SELECT_PYTHON],
                'Env':values('--env'),'Tty':False,'OpenStdin':False},
            'HostConfig':{'Memory':e['memory_bytes'],'MemorySwap':e['memory_swap_bytes'],'NanoCpus':e['nano_cpus'],
                'PidsLimit':e['pids_limit'],'LogConfig':{'Type':e['log_driver'],'Config':e['log_opts']},'Tmpfs':r.TMPFS,
                'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':[],
                'PidMode':'','IpcMode':'private','UTSMode':'','RestartPolicy':{'Name':'no'},'SecurityOpt':['no-new-privileges:true']},
            'Mounts':[{'Type':'bind','RW':False,'Source':str(self.run.file('private/rpm-probe-source/probe.py')),
                'Destination':'/opt/wormhole-rpm/probe.py'}],
            'State':{'Running':self.running,'Pid':123 if self.running else 0,'Status':'running' if self.running else 'created',
                'StartedAt':'2026-10-23T18:00:00Z' if self.running else '0001-01-01T00:00:00Z'}}

    def inspect(self,kind,identifier,**options):
        self.calls.append(('inspect',kind,identifier))
        if kind=='image':
            if not self.cached: return None
            return {'Id':r.BASE_ID,'Os':'linux','Architecture':'amd64','RepoDigests':[r.BASE],
                'Config':{'Labels':r.load_lock()['base']['labels']},'Size':200000000}
        if self.removed: return None
        return self.container()

    def docker(self,args,**options):
        self.calls.append(('docker',*args)); raw=b''
        if args[0]=='pull': self.cached=True
        if args[0]=='create': self.args=list(args); self.created=True; raw=CONTAINER.encode()+b'\n'
        if args[0]=='start':
            if self.start_unknown: raise images.ImageError('docker_request_unknown','Synthetic timeout; no actual Docker.')
            self.running=True
        if args[0]=='exec':
            self.assertTrue(any(row[0]=='cgroup' for row in self.calls)); self.released=True
            self.assertEqual(args,('exec',CONTAINER,'/bin/sh','-c',r.RELEASE_COMMAND))
        if args[0]=='logs':
            self.assertTrue(self.released)
            raw=b'not-json\n' if self.bad_capture else r.canonical(observation(self.run))+b'\n'
        if args[0]=='stop': self.running=False
        if args[0]=='rm': self.removed=True
        return {'log':raw,'log_truncated':False,'status':'pass','returncode':0}

    def test_complete_probe_no_install_or_network_and_capture_replay_bound(self):
        with self.run.locked(): result=r.probe_base(self.run,self.lease)
        self.assertEqual(result['status'],'passed'); self.assertEqual(result['cleanup'],'completed')
        self.assertFalse(result['unknown_outcome']); self.assertFalse(result['daemon_pull_cgroup_capped'])
        self.assertEqual(r.read_base_observation(self.run),observation(self.run))
        with patch.object(r,'source_identity',return_value=('d'*40,False)):
            self.assertEqual(r.read_base_observation(self.run),observation(self.run))  # New clean source, unchanged exact recipe.
        self.assertTrue(all(row['outcome']!='pending' for row in self.lease.record['resources']))
        self.assertTrue(self.removed); self.assertIn('--read-only',self.args); self.assertNotIn('--cap-add',self.args)
        self.assertEqual(self.args[self.args.index('--network')+1],'none')
        self.assertFalse(any('socket' in arg or 'authorized_keys' in arg for arg in self.args))
        capture=self.run.file('private/rpm-base-probe.log'); capture.write_bytes(capture.read_bytes()+b' ')
        with self.assertRaises(r.RpmError): r.read_base_observation(self.run)

    def test_a_completed_logs_response_after_absolute_deadline_never_passes(self):
        original=self.docker; clock=[0.0]
        def docker(args,**options):
            value=original(args,**options)
            if args[0]=='logs': clock[0]=31.0
            return value
        with self.run.locked(),patch.object(images,'docker',docker),patch.object(r.time,'monotonic',side_effect=lambda:clock[0]),self.assertRaises(r.RpmError):
            r.probe_base(self.run,self.lease)
        receipt=read_json(self.run.file('evidence/rpm-base-probe.json'))
        self.assertEqual(receipt['primary_failure']['code'],'rpm_probe_deadline')
        self.assertEqual(receipt['cleanup'],'completed'); self.assertTrue(self.removed)

    def test_absent_base_pull_has_materialization_intent_then_exact_retained_image(self):
        self.cached=False
        with self.run.locked(): result=r.probe_base(self.run,self.lease)
        pull=next(i for i,row in enumerate(self.calls) if row[:2]==('docker','pull'))
        self.assertIn(('phase','materializing'),self.calls[:pull])
        self.assertEqual(self.lease.record['resources'][0],{'kind':'image','id':r.BASE_ID,'outcome':'retained'})
        self.assertEqual(result['base_image_id'],r.BASE_ID)

    def test_malformed_known_result_retains_primary_but_exact_known_cleanup_runs(self):
        self.bad_capture=True
        with self.run.locked(),self.assertRaises(r.RpmError): r.probe_base(self.run,self.lease)
        result=read_json(self.run.file('evidence/rpm-base-probe.json'))
        self.assertEqual(result['primary_failure']['code'],'rpm_observation_invalid')
        self.assertEqual(result['status'],'failed'); self.assertEqual(result['cleanup'],'completed'); self.assertTrue(self.removed)

    def test_unknown_start_never_stops_removes_or_finishes(self):
        self.start_unknown=True
        with self.run.locked(),self.assertRaises(images.ImageError): r.probe_base(self.run,self.lease)
        result=read_json(self.run.file('evidence/rpm-base-probe.json'))
        self.assertTrue(result['unknown_outcome']); self.assertEqual(result['cleanup'],'pending'); self.assertFalse(self.removed)
        self.assertFalse(any(row[:2] in (('docker','stop'),('docker','rm')) for row in self.calls))
        self.assertEqual(self.lease.record['resources'][-1]['outcome'],'pending')

    def test_identity_limit_mount_and_never_started_guards_precede_start(self):
        # First obtain the synthetic exact spec; no real resources exist in this test.
        with self.run.locked(): r.probe_base(self.run,self.lease)
        receipt=read_json(self.run.file('evidence/rpm-base-probe.json')); value=self.container()
        for alter in (lambda x:x.update(Image='sha256:'+'c'*64),lambda x:x['Config']['Labels'].update(extra='bad'),
            lambda x:x['HostConfig'].update(NetworkMode='bridge'),lambda x:x['HostConfig']['Tmpfs'].update({'/tmp':'size=1g'}),
            lambda x:x['Mounts'][0].update(RW=True),lambda x:x['State'].update(StartedAt='already-started')):
            changed=deepcopy(value); alter(changed)
            with self.assertRaises(r.RpmError): r.verify_probe(self.run,receipt,changed,self.lease.plan['limits']['build'],stopped=True)

    def test_wrong_run_or_synthetic_lease_refuses_before_any_docker(self):
        self.lease.plan['synthetic']=True
        with self.run.locked(),self.assertRaises(r.RpmError): r.probe_base(self.run,self.lease)
        self.assertEqual(self.calls,[])


if __name__=='__main__': unittest.main()
