"""Fixed resolver driver with disposable synthetic Docker/admission objects only."""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import admission, images, rpm_resolution as r, rpm_source as s
from wormhole.runs import atomic_json, create_run, read_json
from test_admission import observed
from test_rpm_source import fixtures

REVISION='a'*40
IDENTIFIER='b'*64


@unittest.skipUnless(os.name=='posix','Root-owned resolver bind and driver fixtures require POSIX')
class Driver(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.run=create_run(Path(temporary.name)/'runs',fixture=False,identity=(REVISION,False))
        self.lock,self.request,self.resolution,self.metadata=fixtures(self.run)
        self.request['lock_sha256']=s.sha(s.lock_bytes())
        self.resolution['request_sha256']=s.sha(s.canonical(self.request))
        atomic_json(self.run.file('private/rpm-sources/resolve-request.json'),self.request)
        self.running=False;self.released=False;self.removed=False;self.calls=[];self.args=None
        self.bad_capture=False;self.unknown_start=False;self.bad_pid=False;self.cgroup_fail=False;self.altered_source=False
        self.observation={'synthetic':True}
        parent=self
        class Lease:
            plan=admission.build_plan('smoke',observed());record={'resources':[]}
            def _active(self):pass
            def set_phase(self,phase):parent.calls.append(('phase',phase))
            def register_resource(self,kind,identifier):self.record['resources'].append({'kind':kind,'id':identifier,'outcome':'pending'})
            def reconcile_resource(self,kind,identifier,**options):
                parent.calls.append(('reconcile',kind,identifier))
                for row in self.record['resources']:
                    if (row['kind'],row['id'])==(kind,identifier):row['outcome']=options.get('outcome','absent')
        self.lease=Lease()
        def validated(_run,raw,request,lock):
            if self.bad_capture:raise s.SourceError('rpm_resolution_invalid','Synthetic malformed capture')
            self.assertEqual(raw,s.canonical(self.resolution)+b'\n');return deepcopy(self.resolution)
        for owner,name,value in ((r,'scope',lambda *_:None),(r,'source_identity',lambda:(REVISION,False)),
            (s,'prepare_metadata',lambda *_:self.metadata),(s,'resolve_request',lambda *_a,**_k:self.request),
            (s,'validate_metadata',lambda *_:self.metadata),(s,'validate_resolution',validated),
            (r.base,'read_base_observation',lambda *_:self.observation),(r,'revalidate',self.revalidate),
            (images,'docker',self.docker),(images,'inspect',self.inspect),(images,'cgroup_limits',self.cgroups)):
            item=patch.object(owner,name,value);item.start();self.addCleanup(item.stop)

    def revalidate(self,*_):
        self.calls.append(('revalidate',))
        if self.altered_source and self.args:raise r.ResolutionError('rpm_resolution_source_changed','Synthetic changed source')

    def cgroups(self,pid,expected):
        self.calls.append(('cgroups',pid));self.assertTrue(self.running);self.assertFalse(self.released)
        if self.cgroup_fail:raise images.ImageError('cgroup_unverified','Synthetic actual-limit failure')
        return {'memory.max':str(expected['memory_bytes']),'memory.swap.max':'0','pids.max':str(expected['pids_limit']),'cpu.max':'200000 100000'}

    def container(self):
        args=self.args
        def values(flag):return [args[i+1] for i,x in enumerate(args) if x==flag]
        labels=dict(x.split('=',1) for x in values('--label'));expected=self.lease.plan['limits']['build']['docker_create']
        mounts=[]
        for item in values('--mount'):
            mapping=dict(x.split('=',1) for x in item.split(',') if '=' in x)
            mounts.append({'Type':'bind','RW':False,'Source':mapping['source'],'Destination':mapping['target']})
        return {'Id':IDENTIFIER,'Image':s.BASE_IMAGE,'Name':'/wormhole-'+self.run.id+'-rpm-resolver',
            'Config':{'Labels':labels,'User':'0:0','WorkingDir':'/','Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B',r.DESTINATION],
                'Env':values('--env'),'Tty':False,'OpenStdin':False},
            'HostConfig':{'Memory':expected['memory_bytes'],'MemorySwap':expected['memory_swap_bytes'],'NanoCpus':expected['nano_cpus'],
                'PidsLimit':1 if self.bad_pid else expected['pids_limit'],'LogConfig':{'Type':expected['log_driver'],'Config':expected['log_opts']},
                'Tmpfs':r.TMPFS,'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':[],
                'PidMode':'','IpcMode':'private','UTSMode':'','RestartPolicy':{'Name':'no'},'SecurityOpt':['no-new-privileges:true']},
            'Mounts':mounts,'State':{'Running':self.running,'Status':'running' if self.running else 'exited' if self.released else 'created',
                'StartedAt':'2026-10-23T18:00:00Z' if self.running or self.released else '0001-01-01T00:00:00Z',
                'Pid':123 if self.running else 0,'ExitCode':0,'Paused':False,'Restarting':False,'OOMKilled':False}}

    def inspect(self,kind,identifier,**options):
        self.calls.append(('inspect',kind,identifier))
        if kind=='image':return {'Id':s.BASE_IMAGE,'Os':'linux','Architecture':'amd64','RepoDigests':[r.base.BASE],
            'Config':{'Labels':s.load_lock()['base']['labels']},'Size':80416938,
            'Descriptor':{'mediaType':'application/vnd.docker.distribution.manifest.v2+json','digest':s.BASE_IMAGE,'size':429}}
        if self.removed:return None
        if self.released:self.running=False
        return self.container()

    def docker(self,args,**options):
        self.calls.append(('docker',*args));raw=b''
        if args[0]=='create':self.args=list(args);raw=IDENTIFIER.encode()+b'\n'
        if args[0]=='start':
            if self.unknown_start:raise images.ImageError('docker_request_unknown','Synthetic timeout')
            self.running=True
        if args[0]=='exec':
            self.assertTrue(any(x[0]=='cgroups' for x in self.calls));self.released=True
            self.assertEqual(args,('exec',IDENTIFIER,'/usr/bin/python3','-I','-B','-c',r.RELEASE))
        if args[0]=='logs':raw=s.canonical(self.resolution)+b'\n'
        if args[0]=='stop':self.running=False
        if args[0]=='rm':self.removed=True
        return {'status':'pass','returncode':0,'log':raw,'log_truncated':False}

    def execute(self):
        with self.run.locked():return r.resolve_packages(self.run,self.lease,base_run=self.run)

    def test_stopped_bounds_then_live_cgroups_then_release_and_exact_cleanup(self):
        self.assertEqual(self.execute(),self.resolution)
        receipt=read_json(self.run.file(r.EVIDENCE));self.assertEqual(receipt['status'],'passed');self.assertEqual(receipt['cleanup'],'completed')
        self.assertFalse(receipt['unknown_outcome']);self.assertEqual(receipt['request'],self.request)
        self.assertEqual(receipt['capture_sha256'],s.sha(self.run.file('private/rpm-resolution.log').read_bytes()))
        self.assertTrue(self.removed);self.assertTrue(all(x['outcome']!='pending' for x in self.lease.record['resources']))
        self.assertNotIn('--cap-add',self.args);self.assertIn('--read-only',self.args)
        self.assertEqual(self.args[self.args.index('--network')+1],'none')
        self.assertFalse(any('docker.sock' in x or 'id_ed25519' in x for x in self.args))
        self.assertNotIn(('phase','reconciling'),self.calls)  # Caller may perform the subsequent assembly phase.
        with self.assertRaises(r.ResolutionError):self.execute()

    def test_invalid_stopped_limits_refuse_before_start_but_cleanup_stays_failclosed(self):
        self.bad_pid=True
        with self.assertRaises(r.ResolutionError):self.execute()
        self.assertFalse(any(x[:2]==('docker','start') for x in self.calls));self.assertFalse(self.removed)
        receipt=read_json(self.run.file(r.EVIDENCE));self.assertEqual(receipt['cleanup'],'blocked')

    def test_actual_cgroup_failure_never_releases_solver(self):
        self.cgroup_fail=True
        with self.assertRaises(images.ImageError):self.execute()
        self.assertFalse(self.released);self.assertTrue(self.removed)
        receipt=read_json(self.run.file(r.EVIDENCE));self.assertEqual(receipt['primary_failure']['code'],'cgroup_unverified')

    def test_unknown_start_retains_journal_without_cleanup_or_claimed_pass(self):
        self.unknown_start=True
        with self.assertRaises(images.ImageError):self.execute()
        receipt=read_json(self.run.file(r.EVIDENCE));self.assertTrue(receipt['unknown_outcome']);self.assertFalse(self.removed)
        self.assertEqual(receipt['status'],'failed');self.assertEqual(self.lease.record['resources'][-1]['outcome'],'pending')
        self.assertFalse(any(x[:2] in (('docker','stop'),('docker','rm')) for x in self.calls))

    def test_changed_source_after_create_stops_before_execution_and_cleans_only_known_id(self):
        self.altered_source=True
        with self.assertRaises(r.ResolutionError):self.execute()
        self.assertFalse(any(x[:2]==('docker','start') for x in self.calls));self.assertTrue(self.removed)

    def test_bad_complete_capture_is_not_a_resolution_and_known_cleanup_preserves_primary(self):
        self.bad_capture=True
        with self.assertRaises(s.SourceError):self.execute()
        receipt=read_json(self.run.file(r.EVIDENCE));self.assertEqual(receipt['status'],'failed');self.assertEqual(receipt['cleanup'],'completed')
        self.assertEqual(receipt['primary_failure']['code'],'rpm_resolution_invalid')

    def test_late_terminal_capture_cannot_pass(self):
        clock=[0.0];original=self.docker
        def docker(args,**options):
            result=original(args,**options)
            if args[0]=='logs':clock[0]=71
            return result
        with patch.object(r.time,'monotonic',side_effect=lambda:clock[0]),patch.object(images,'docker',docker),self.assertRaises(r.ResolutionError):self.execute()
        self.assertEqual(read_json(self.run.file(r.EVIDENCE))['primary_failure']['code'],'rpm_resolution_capture_bound');self.assertTrue(self.removed)

    def test_wrong_identity_network_mount_or_additional_capability_is_refused(self):
        self.execute();receipt=read_json(self.run.file(r.EVIDENCE));value=self.container()
        for alter in (lambda x:x.update(Image=s.BASE_CONFIG),lambda x:x['HostConfig'].update(NetworkMode='bridge'),
            lambda x:x['HostConfig'].update(CapAdd=['SYS_ADMIN']),lambda x:x['Config']['Env'].append('WORMHOLE_ROLE=other'),
            lambda x:x['Mounts'][0].update(RW=True),lambda x:x['Mounts'].append({'Type':'bind','RW':False,'Source':'/var/run/docker.sock','Destination':'/socket'})):
            changed=deepcopy(value);alter(changed)
            with self.assertRaises(r.ResolutionError):r.verify_container(self.run,receipt,changed,self.lease.plan['limits']['build'])


class Bindings(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','Private resolver binding fixture requires POSIX')
    def test_revalidation_binds_original_capture_request_types_and_exact_files(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(REVISION,False));_,request,_,cache=fixtures(run)
            observation={'synthetic':True};request['base_observation_sha256']=s.sha(s.canonical(observation))
            atomic_json(run.file('private/rpm-sources/resolve-request.json'),request)
            recipe,files=r.recipe_identity();receipt={**r.common(run.manifest()),'recipe_sha256':recipe,'source_files':files,'request':deepcopy(request)}
            receipt['bindings']={**r.public_sources(run,files),'/metadata':r.binding(cache,directory=True),
                '/request/resolve.json':r.binding(run.file('private/rpm-sources/resolve-request.json'))}
            with patch.object(r,'source_identity',return_value=(REVISION,False)),patch.object(s,'validate_metadata',return_value=cache),\
                 patch.object(r.base,'read_base_observation',return_value=observation):
                r.revalidate(run,receipt)
                request['source_dirty']=0;atomic_json(run.file('private/rpm-sources/resolve-request.json'),request)
                with self.assertRaises(r.ResolutionError):r.revalidate(run,receipt)

    @unittest.skipUnless(os.name=='posix','Public resolver source permissions require POSIX')
    def test_private_public_copy_does_not_change_original_and_refuses_modified_inode(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(REVISION,False));recipe,files=r.recipe_identity()
            before=(s.SOURCE_ROOT/'rpm/resolve.py').stat().st_mode
            result=r.public_sources(run,files);self.assertEqual(len(result),2)
            path=Path(result[r.DESTINATION]['path']);self.assertEqual(path.stat().st_mode&0o777,0o444)
            self.assertEqual(path.parent.stat().st_mode&0o777,0o700);self.assertEqual(before,(s.SOURCE_ROOT/'rpm/resolve.py').stat().st_mode)
            path.chmod(0o600);path.write_bytes(b'changed');path.chmod(0o444)
            with self.assertRaises(r.ResolutionError):r.public_sources(run,files)

    def test_release_is_fixed_atomic_python_source_and_no_data_arguments(self):
        compile(r.RELEASE,'fixed-release','exec')
        self.assertIn('os.O_EXCL|os.O_NOFOLLOW',r.RELEASE);self.assertIn('os.replace',r.RELEASE)
        self.assertNotIn('sys.argv',r.RELEASE)


if __name__=='__main__':unittest.main()
