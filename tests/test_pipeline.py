"""Synthetic dependency orchestration; no Docker/SSH/TF/Ansible operations.

The chunk, candidate, assessment and inventory replayers use actual retained
authored fixture bytes. Provisioning/readiness are explicitly mocked here and
have their separate original-capture replay fixtures.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import sys
from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole import pipeline as w,pipeline_replay as replay,assessments as a,admission,images,rpm_validation,software_inventory as svd,validation as v
from wormhole.runs import atomic_json,common,now,read_json
from wormhole import rpm_target
import test_software_inventory as inventory_fixture
from test_software_inventory import TARGET,NETWORK,HELPER,PROVISIONER
from test_admission import observed
from test_candidate import SHA


class DomainReplay(unittest.TestCase):
    def setUp(self):
        self.fixture=inventory_fixture.SoftwareInventory('test_full_native_inventory_preserves_unrequired_packages_keys_and_replay_exports');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups);self.run=self.fixture.run;self.binding=self.fixture.binding
        for module in (w,replay,a):
            item=patch.object(module,'source_identity',return_value=(SHA,False));item.start();self.addCleanup(item.stop)
        session=svd.SoftwareInventorySession(self.fixture.ready,self.binding)
        with patch.object(v,'_run_process',side_effect=self.fixture.response):session.collect()
        a.assess_run(self.run,a.fixture('pass'),a.FIXTURE_EXPECTED)
        self.request=w.make_request(self.run,'ubi',base_run_id=str(uuid4()));atomic_json(self.run.file(w.REQUEST),self.request)
        self.plan=w.build_plan(self.run,self.request,w.prepared_manifest(self.run,'ubi'));atomic_json(self.run.file(w.PLAN),self.plan)
        self.context={**common(self.run.manifest()),'operation':'reference-pipeline-controller-v1','request_sha256':self.request['request_sha256'],
            'primary_failure':None,'secondary_failures':[],'unknown_outcome':False,'cleanup_status':'completed','pending_resources':0,'updated_at':now()}
        atomic_json(self.run.file(w.CONTEXT),self.context)
        root=Path(tempfile.mkdtemp(prefix='wormhole-pipeline-archive-synthetic-'));root.chmod(0o700)
        self.addCleanup(__import__('shutil').rmtree,root);(root/'history').mkdir(mode=0o700)
        item=patch.object(images,'INFRASTRUCTURE',root);item.start();self.addCleanup(item.stop)
        observations=observed();observations['synthetic']=False
        plan=admission.build_plan('smoke',observations)
        self.resources=[{'kind':kind,'id':identifier,'outcome':'absent','size_bytes':0} for kind,identifier in
            (('container',TARGET),('network',NETWORK),('container',HELPER),('container',PROVISIONER),('container','b'*64),('container','c'*64))]
        self.resources += [{'kind':'image','id':self.binding['image_id'],'outcome':'retained','size_bytes':1234},
            {'kind':'image','id':rpm_target.BASE_ID,'outcome':'retained','size_bytes':2000}]
        archive={'schema_version':'1.0','application':admission.PROJECT,'run_id':self.run.id,'source_revision':SHA,
            'boot_id':observations['boot_id'],'owner_pid':1234,'state':'finished','phase':'reconciling','created_at':now(),'updated_at':now(),
            'plan':plan,'resources':self.resources}
        self.archive=root/'history'/(self.run.id+'.json');atomic_json(self.archive,archive)
        cleanup={**common(self.run.manifest()),'operation':'scoped-cleanup','attempt_id':str(uuid4()),'reason':'success','status':'completed',
            'created_at':now(),'updated_at':now(),'primary_failure':None,'secondary_failures':[],
            'resources':[{'kind':item['kind'],'id':item['id'],'role':'retained-image' if item['kind']=='image' else 'other-owned','disposition':item['outcome']} for item in self.resources],
            'unknown_outcome':False,'terraform_state_retained':True,'private_state_removed':False,'runtime_pipeline_complete':False,'production_iso_eligible':False}
        atomic_json(self.run.file('evidence/cleanup.json'),cleanup)
        provision=read_json(self.run.file('evidence/provisioning.json'));provision['operations']=[];atomic_json(self.run.file('evidence/provisioning.json'),provision)
        atomic_json(self.run.file('evidence/readiness.json'),{'attempts':[]})
        expected=rpm_validation.expected_values(self.binding,'healthy')
        self.functional={'result':{'checks':[{'check_id':key,'observed':value,'status':'pass'} for key,value in expected.items()]}}
        atomic_json(self.run.file('evidence/rpm-validation.json'),{'attempts':[]})
        atomic_json(self.run.file('evidence/rpm-resolution.json'),{'container_id':'c'*64})
        self.provisioned={'target':{'target_id':'target-001','resource_id':TARGET,'image_digest':self.binding['image_id']},
            'runtime':{'network':{'Id':NETWORK},'image':{'Size':1234},'base_image':{'Size':2000}}}
        for module,name,value in ((replay,'report_candidate',self.binding),(replay,'report_provisioning',self.provisioned),
            (replay,'report_readiness',{}),(rpm_validation,'report_rpm_validation',self.functional),(rpm_target,'verify_base',None)):
            item=patch.object(module,name,return_value=value);item.start();self.addCleanup(item.stop)

    def export(self):
        value=w.assemble_record(self.run);atomic_json(self.run.file(w.RECORD),value)
        w._write_exports(self.run,w.export_files(self.run,value,self.plan))
        return value

    def test_complete_exact_grid_full_svd_and_deterministic_gate_bind_raw_archive_and_report_bytes(self):
        record=self.export();self.assertTrue(record['reference_eligible']);self.assertEqual(len(record['rows']),46)
        report=w.report_pipeline(self.run);self.assertEqual(report['record'],record);self.assertEqual(w.gate_pipeline(self.run),report['decision'])
        self.assertEqual(record['cleanup']['archive_sha256'],w.c.sha(self.archive.read_bytes()))
        self.assertEqual(report['decision']['record_sha256'],w.c.sha(report['json']))
        raw=self.run.file(w.EXPORT+'/targets/target-001/observed-svd.json').read_bytes()
        self.assertNotIn(b'private/',raw);self.assertIn(b'"bash"',raw);self.assertIn(b'"rpm_key_headers"',raw)

    def test_original_capture_tampering_or_missing_component_denies_gate_after_exports_were_written(self):
        self.export();self.run.file(svd.LOG).write_bytes(b'changed original')
        self.assertFalse(w.gate_pipeline(self.run)['reference_eligible'])

    def test_missing_supplied_functional_row_is_never_synthesized_as_a_pass(self):
        self.functional['result']['checks'].pop()
        with self.assertRaises(w.PipelineError) as error:w.assemble_record(self.run)
        self.assertEqual(error.exception.code,'pipeline_result_incomplete')

    def test_missing_builder_or_retained_image_never_shrinks_accounting_graph(self):
        original=read_json(self.archive)
        for identifier in ('b'*64,self.binding['image_id']):
            changed=deepcopy(original);changed['resources']=[item for item in changed['resources'] if item['id']!=identifier];atomic_json(self.archive,changed)
            with self.assertRaises(w.PipelineError) as error:w.assemble_record(self.run)
            self.assertEqual(error.exception.code,'pipeline_cleanup_graph_changed')
        atomic_json(self.archive,original)

    def test_unfinished_archive_and_missing_cleanup_never_reuse_global_journal_as_proof(self):
        self.export();self.archive.unlink()
        self.assertFalse(w.gate_pipeline(self.run)['reference_eligible'])
        with self.assertRaises(w.PipelineError):w.report_pipeline(self.run)

    def test_primary_failure_successful_cleanup_and_all_nonpass_missing_svd_rows_stay_in_grid(self):
        self.context['primary_failure']={'code':'candidate_required_check_mismatch','recorded_at':now()};atomic_json(self.run.file(w.CONTEXT),self.context)
        for path in (svd.RECORD,svd.JSON_EXPORT,svd.TEXT_EXPORT):self.run.file(path).unlink()
        self.functional['result']['checks'][9].update(status='fail',observed='controlled-version-mismatch')
        record=self.export();self.assertFalse(record['reference_eligible']);self.assertEqual(record['cleanup']['status'],'completed')
        self.assertTrue(all(row['status']=='blocked' for row in record['rows'] if row['component']=='svd'))
        self.assertEqual(record['primary_failure']['code'],'candidate_required_check_mismatch')

    def test_assessment_applicability_mutation_and_request_scope_change_refuse_original_replay(self):
        self.export();plan=read_json(self.run.file(a.PLAN));plan['expected_findings'][0]['applicable']=False;plan['expected_findings'][0]['reason']='edited'
        plan['plan_sha256']=a.digest({key:value for key,value in plan.items() if key!='plan_sha256'});atomic_json(self.run.file(a.PLAN),plan)
        self.assertFalse(w.gate_pipeline(self.run)['reference_eligible'])
        request=deepcopy(self.request);request['capabilities']=['powershell'];atomic_json(self.run.file(w.REQUEST),request)
        with self.assertRaises(w.PipelineError):w.validate_request(self.run,request)


class HistoricalAdmission(unittest.TestCase):
    def test_historical_replay_preserves_exact_bytes_and_live_build_still_refuses_old_measurements(self):
        value=observed();value['observed_at']='2026-01-01T00:00:00.000Z';before=deepcopy(value)
        replayed=admission.replay_plan('smoke',value);self.assertTrue(replayed['admitted']);self.assertEqual(value,before)
        self.assertEqual(replayed['observations'],before)
        with self.assertRaises(admission.AdmissionError) as error:admission.build_plan('smoke',value)
        self.assertEqual(error.exception.code,'stale_observation')
        for bad in ('bad-date','2026-01-01T00:00:00+05:00',None):
            changed=deepcopy(value);changed['observed_at']=bad
            with self.assertRaises(admission.AdmissionError):admission.replay_plan('smoke',changed)


class CoordinatorBoundaries(unittest.TestCase):
    def test_malformed_base_uuid_has_controlled_error_before_any_runtime_operation(self):
        run=SimpleNamespace(manifest=lambda:{},id='not-used')
        for value in ('not-a-uuid','../private',True,None):
            with self.assertRaises(w.PipelineError) as error:w.make_request(run,'ubi',base_run_id=value)
            self.assertEqual(error.exception.code,'pipeline_base_required')

    def test_lifetime_budget_refuses_slow_readiness_without_weakening_original_ttls(self):
        session=w.PipelineSession.__new__(w.PipelineSession);session.readiness=SimpleNamespace(helper=HELPER,target=TARGET)
        def inspect(kind,identifier):return {'State':{'StartedAt':(datetime.now(timezone.utc)-timedelta(seconds=50)).isoformat()}}
        with patch.object(images,'inspect',side_effect=inspect),self.assertRaises(w.PipelineError) as error:session._budget(140)
        self.assertEqual(error.exception.code,'pipeline_lifetime_budget')

    def test_stage_timing_failure_retains_the_original_operation_error(self):
        from wormhole.runs import create_run
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        session=w.PipelineSession.__new__(w.PipelineSession)
        session.run=create_run(Path(temporary.name)/'runs',fixture=False,identity=(SHA,False))
        session.timings={'stages':[]};session.context={'primary_failure':None,'secondary_failures':[]}
        original=w.PipelineError('controlled_primary_failure','Controlled operation failure')
        actual=w.atomic_json
        def persist(path,value):
            if path.name=='pipeline-timings.json' and value['stages'][0]['finished_at'] is not None:raise OSError('controlled disk error')
            actual(path,value)
        with patch.object(w,'atomic_json',side_effect=persist),self.assertRaises(w.PipelineError) as error:
            session.timed('functional-validation',lambda:(_ for _ in ()).throw(original))
        self.assertIs(error.exception,original)
        self.assertEqual(session.context['secondary_failures'][0]['code'],'pipeline_timing_write_failed')

    @unittest.skipUnless(sys.platform.startswith('linux'),'Real mode source/lock coordinator fixture, no Docker calls')
    def test_capacity_refusal_retains_complete_failed_grid_and_never_calls_old_unsupported_pipeline(self):
        from wormhole.runs import create_run
        from wormhole import candidate,chunks,assessments,stages
        with tempfile.TemporaryDirectory(prefix='wormhole-reference-capacity-synthetic-') as temporary:
            root=Path(temporary)/'runs';run=create_run(root,fixture=False,identity=(SHA,False),kernel_lock=True)
            patches=[patch.object(module,'source_identity',return_value=(SHA,False)) for module in (w,replay,candidate,chunks,assessments)]
            for item in patches:item.start();self.addCleanup(item.stop)
            with patch.object(images,'RUNS_ROOT',root),patch.object(images,'INFRASTRUCTURE',Path(temporary)/'infrastructure'),\
                patch.object(images,'create_auth'),patch.object(stages,'execute_run',side_effect=AssertionError('Old unsupported pipeline called')),\
                patch.object(w,'AdmissionLease',side_effect=admission.AdmissionError('capacity_refused','Synthetic measured refusal')):
                session=w.PipelineSession(run,w.make_request(run))
                with self.assertRaises(w.PipelineError) as error:session.execute()
                self.assertEqual(error.exception.code,'capacity_refused');self.assertEqual(error.exception.run_id,run.id)
                report=w.report_pipeline(run);self.assertEqual(len(report['record']['rows']),43);self.assertFalse(report['decision']['reference_eligible'])
                self.assertEqual(report['record']['primary_failure']['code'],'capacity_refused')
                self.assertTrue(all(item['status']=='blocked' for item in report['record']['rows'] if item['component'] in {'provisioning','readiness','functional','svd'}))
                self.assertEqual(run.manifest()['stages'],[]);self.assertFalse(run.manifest()['runtime_pipeline_complete'])


if __name__=='__main__':unittest.main()
