"""Offline original-capture fixtures; every Docker/TF/SSH boundary is mocked."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from wormhole import candidate,images,pipeline_replay as replay,provisioning as p,readiness as r
from wormhole.runs import atomic_json,read_json,common
from scripts import qualify_images as qualification
import test_provisioning as tf
import test_readiness as ready


@unittest.skipUnless(os.name=='posix','POSIX retained original-capture fixtures, all Docker mocked')
class OfflineTerraform(unittest.TestCase):
    def setUp(self):
        self.fixture=tf.Controller('test_fixed_unavailable_apply_failure_needs_specific_proof_then_empty_saved_destroy')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.run=self.fixture.run;self.ps=self.fixture.session
        self.binding={'operation':'candidate-image-binding','image_id':p.TARGET_IMAGE,'image_labels':self.fixture.image_labels}
        self.ps.target_binding=self.binding;self.ps.receipt['target_binding']=deepcopy(self.binding)
        def capture(arguments,**options):
            name,attempt=arguments[-2],int(arguments[-1]);value=self.fixture.operation(name)
            from provisioning.runtime import JSON_OPERATIONS
            raw=json.dumps(value).encode() if name in JSON_OPERATIONS else b'Synthetic fixed Terraform output'
            folder=self.ps.state/'operations';folder.mkdir(mode=0o700,exist_ok=True);stem=folder/(name+'-'+str(attempt))
            stem.with_suffix('.out').write_bytes(raw);stem.with_suffix('.out').chmod(0o600)
            atomic_json(stem.with_suffix('.json'),{'operation':name,'attempt':attempt,'returncode':0,'duration_seconds':.001,
                'output_bytes':len(raw),'output_sha256':hashlib.sha256(raw).hexdigest(),'truncated':False,'timed_out':False,'passed':True})
            return {'status':'pass','returncode':0,'log':b'Synthetic runtime result','log_truncated':False}
        def cgroups(pid,limits):return {'memory.max':str(limits['memory_bytes']),'memory.swap.max':'0','pids.max':str(limits['pids_limit']),
            'cpu.max':str(limits['nano_cpus']//10000)+' 100000'}
        with self.fixture.patches(mock_operations=False),patch.object(p,'_run_process',side_effect=capture),\
            patch.object(images,'docker_configuration',return_value='/synthetic/config'),patch.object(images,'cgroup_limits',side_effect=cgroups):
            self.ps.create_stopped()
            stopped=self.fixture.container(tf.CID);network=self.fixture.inspect('network',tf.NET)
            self.ps.start_and_inventory();live=self.fixture.container(tf.CID);controller=self.fixture.container(tf.CONTROLLER)
            self.ps.destroy()
        atomic_json(self.run.file(replay.RUNTIME),{**common(self.run.manifest()),'operation':'reference-runtime-observations-v1',
            'image':{'Id':p.TARGET_IMAGE},'network':network,'target_stopped':stopped,'target_live':live,'provisioner':controller})
        self.archive={'plan':self.fixture.plan,'resources':[{'kind':item['kind'],'id':item['id'],'outcome':'absent'} for item in self.fixture.lease.record['resources']]}
        item=patch.object(replay,'source_identity',return_value=(tf.SHA,False));item.start();self.addCleanup(item.stop)

    def replay(self):
        # The image build/bytes guard is separately tested; this fixture isolates
        # the complete retained Terraform command/config/plan/state path.
        with patch.object(candidate,'verify_image'),patch.object(images,'inspect',side_effect=AssertionError('Offline replay contacted Docker')):
            return replay.report_provisioning(self.run,self.archive,self.binding)

    def test_original_saved_operations_and_runtime_config_replay_without_live_docker(self):
        value=self.replay();self.assertEqual(value['target']['resource_id'],tf.CID);self.assertEqual(value['receipt']['cleanup'],'completed')

    def test_changed_hcl_and_matching_input_hash_cannot_relabel_original_command_evidence(self):
        path=self.ps.state/'main.tf';raw=path.read_bytes()+b'\n# edited after original operation\n';path.write_bytes(raw)
        context=read_json(self.ps.state/'controller.json');context['inputs']['main.tf']=hashlib.sha256(raw).hexdigest();atomic_json(self.ps.state/'controller.json',context)
        with self.assertRaises(replay.ReplayError) as error:self.replay()
        self.assertEqual(error.exception.code,'pipeline_input_changed')

    def test_changed_output_or_incomplete_operation_pair_cannot_pass(self):
        path=self.ps.state/'operations/final-state-1.out';path.write_bytes(b'changed original output')
        with self.assertRaises(replay.ReplayError) as error:self.replay()
        self.assertEqual(error.exception.code,'pipeline_operation_changed')


@unittest.skipUnless(os.name=='posix','POSIX retained helper source/capture fixtures, no runtime operations')
class OfflineReadiness(unittest.TestCase):
    def setUp(self):
        self.fixture=ready.ReadinessPolicy('test_healthy_wait_requires_every_actual_helper_protocol_result_and_stays_partial')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);f=self.fixture
        self.run=f.run
        self.session=f.session=r.ReadinessSession(f.provisioning,validation=True)
        original=f.helper
        def helper():
            value=original();value['Mounts'].append({'Type':'bind','Source':str(f.run.file('private/helper-source/validation.py')),
                'Destination':r.VALIDATION_MOUNT,'RW':False});return value
        f.helper=helper;f.session.start_helper()
        for role,stage,raw in (('target','public-hostkey',(ready.HOST_KEY+'\n').encode()),('helper','auth-input',b'Synthetic receiver complete')):
            qualification.attempt_record(f.run,f.session.receipt,role,stage,{'status':'pass','returncode':0,'duration_seconds':.001,'log':raw,'log_truncated':False})
        target=f.target()
        with patch.object(f,'target',return_value=target),patch.object(r,'_run_process',side_effect=f.output):f.session.wait_ready()
        snapshot=f.helper();f.session.receipt['cleanup']='completed';f.session.save()
        self.provisioned={'target':{'resource_id':ready.TARGET},'runtime':{'network':{'Id':ready.NETWORK},'helper':snapshot}}
        self.archive={'plan':f.lease.plan,'resources':[{'kind':'container','id':ready.HELPER,'outcome':'absent'}]}
        item=patch.object(replay,'source_identity',return_value=(ready.SHA,False));item.start();self.addCleanup(item.stop)

    def test_replay_uses_original_protocol_observations_after_helper_deletion(self):
        with patch.object(images,'inspect',side_effect=AssertionError('Offline replay contacted Docker')):
            self.assertEqual(replay.report_readiness(self.run,self.archive,self.provisioned)['status'],'ready')

    def test_changed_protocol_observation_or_foreign_network_context_refuses(self):
        receipt=read_json(self.run.file('evidence/readiness.json'))
        tcp=next(item for item in receipt['attempts'] if item['stage']=='tcp');path=self.run.file(tcp['private_log'])
        value=json.loads(path.read_bytes());value['observation']['tcp_connected']=False;atomic_json(path,value)
        with self.assertRaises(replay.ReplayError):replay.report_readiness(self.run,self.archive,self.provisioned)


if __name__=='__main__':unittest.main()
