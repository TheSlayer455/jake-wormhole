"""Interrupted-intent proof and resumed adapter fixtures; Docker is mocked."""
from copy import deepcopy
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from wormhole import initialization as init,initialization_recovery as recovery,images,provisioning as p
from wormhole.runs import atomic_json,common,now,read_json,RunError
import test_initialization as fixture
from test_admission import observed
from wormhole.admission import build_plan


class InterruptedInitialization(unittest.TestCase):
    def setUp(self):
        self.f=fixture.InitializationTests('test_real_command_failure_exit_and_capture_are_preserved_before_readiness')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.run,self.ps=self.f.run,self.f.ps
        self.ps.receipt.update(**common(self.run.manifest()),operation='terraform-smoke',scenario='healthy',
            target_plan=self.ps.target_plan.record(),status='partially-started',primary_failure=None,secondary_failures=[],
            operations=[],resources=[{'address':self.ps.target_plan.address_for('target-001'),'id':'b'*64}],updated_at=now())
        self.value=self.f.observation('observer-lost')
        with self.assertRaises(RunError):self.f.execute(self.value,status='timeout')
        self.lease=SimpleNamespace(run_id=self.run.id,source_revision='a'*40,_reconciliation_only=True,
            _active=Mock(),plan=build_plan('smoke',observed()))
        self.lease.plan['synthetic']=False
        for owner,name,value in ((images,'RUNS_ROOT',self.run.workspace),
            (recovery,'source_identity',lambda:('a'*40,False))):
            item=patch.object(owner,name,value);item.start();self.addCleanup(item.stop)

    def test_original_known_receipt_precedes_the_exec_and_can_only_authorize_read_stop(self):
        proof=recovery.InitializationProof(self.run,self.lease)
        self.assertTrue(proof.validate(self.run,self.lease,self.ps.receipt))
        before=read_json(self.run.file(proof.record['attempts'][-1]['provider_before']))
        self.assertFalse(before['unknown_outcome']);self.assertTrue(self.ps.receipt['unknown_outcome'])
        self.ps.destroy_only=True
        with patch.object(p.ProvisioningSession,'_load_retained',return_value=self.ps),patch.object(images,'docker') as mutate:
            resumed=init.InitializationSession.resume(self.run,self.lease)
            with self.assertRaises(RunError) as error:resumed.observe('target-001')
        mutate.assert_not_called();self.assertEqual(error.exception.code,'initialization_recovery_observation_only')

    def test_new_terraform_operation_resource_or_input_never_inherits_initialization_proof(self):
        proof=recovery.InitializationProof(self.run,self.lease)
        for change in ('operations','resources','target_plan'):
            value=deepcopy(self.ps.receipt)
            if change=='target_plan':value[change]['profile']='five-targets'
            else:value[change].append({'operation':'unrelated-mutation'} if change=='operations' else {'address':'foreign','id':'c'*64})
            with self.subTest(change=change),self.assertRaises(RunError):proof.validate(self.run,self.lease,value)

    def test_changed_snapshot_missing_proof_and_nonrecovery_lease_refuse(self):
        record=read_json(self.run.file(init.RECORD));attempt=record['attempts'][-1]
        path=self.run.file(attempt['provider_before']);original=path.read_bytes();path.write_bytes(original+b' ')
        with self.assertRaises(RunError):recovery.InitializationProof(self.run,self.lease)
        path.write_bytes(original)
        self.lease._reconciliation_only=False
        with self.assertRaises(RunError):recovery.InitializationProof(self.run,self.lease)
        self.lease._reconciliation_only=True
        attempt.pop('provider_before');atomic_json(self.run.file(init.RECORD),record)
        with self.assertRaises(RunError):recovery.InitializationProof(self.run,self.lease)

    def test_resume_requires_exact_resource_start_and_retains_unknown_if_it_changed(self):
        self.ps.destroy_only=True
        with patch.object(p.ProvisioningSession,'_load_retained',return_value=self.ps):resumed=init.InitializationSession.resume(self.run,self.lease)
        with patch.object(images,'inspect',return_value={'State':{'Running':True,'StartedAt':'different'}}),\
            patch.object(init,'_run_process') as execute,self.assertRaises(RunError):resumed.reconcile('target-001')
        execute.assert_not_called();self.assertTrue(self.ps.receipt['unknown_outcome'])

    def test_durable_result_from_exact_original_start_resolves_the_contained_exec(self):
        self.ps.destroy_only=True
        with patch.object(p.ProvisioningSession,'_load_retained',return_value=self.ps):resumed=init.InitializationSession.resume(self.run,self.lease)
        response={'status':'pass','returncode':0,'log':json.dumps(self.value).encode(),'log_truncated':False}
        with patch.object(images,'inspect',return_value={'State':{'Running':True,'StartedAt':'2026-01-01T00:00:00Z'}}),\
            patch.object(images,'docker_configuration',return_value='private'),patch.object(init,'_run_process',return_value=response):
            self.assertEqual(resumed.reconcile('target-001'),self.value)
        self.assertFalse(self.ps.receipt['unknown_outcome'])
        self.assertFalse(resumed.record['unknown_outcome'])
        self.assertTrue(resumed.record['attempts'][-1]['terminal_marker_verified'])

    def test_known_failure_metadata_can_be_added_but_never_replaces_an_older_primary(self):
        proof=recovery.InitializationProof(self.run,self.lease)
        changed=deepcopy(self.ps.receipt);changed['status']='failed'
        changed['primary_failure']={'code':'coordinator_interrupted','recorded_at':now()}
        self.assertTrue(proof.validate(self.run,self.lease,changed))
        proof.before['primary_failure']={'code':'earlier_failure','recorded_at':now()}
        with self.assertRaises(RunError):proof.validate(self.run,self.lease,changed)


@unittest.skipUnless(os.name=='posix','Retained Linux provider fixtures; every Docker call is mocked')
class RetainedProviderIntegration(unittest.TestCase):
    def setUp(self):
        import test_provisioning as provider_fixture
        self.f=provider_fixture.Controller('test_actual_workflow_policy_orders_pid_and_inspection_before_start_then_provider_refresh_destroy')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.run,self.ps,self.lease=self.f.run,self.f.session,self.f.lease
        for owner,name,value in ((images,'RUNS_ROOT',self.run.workspace),(recovery,'source_identity',lambda:('a'*40,False))):
            item=patch.object(owner,name,value);item.start();self.addCleanup(item.stop)
        self.result={'schema_version':'1.0','operation':'container-initialization-v1','run_id':self.run.id,
            'scenario':'observer-lost','status':'passed','stage':'configuration','category':None,'command_returncode':None,
            'checks':dict.fromkeys(init.runtime.FIELDS,True),'events':['initialization-started','initialization-complete',
                'configuration-started','configuration-complete'],'simulated_installation':False,'production_iso_eligible':False}
        with self.f.patches(),patch.object(init.images,'docker_configuration',return_value='private'),\
            patch.object(init,'_run_process',return_value={'status':'timeout','returncode':-15,'log':b'','log_truncated':False}):
            self.ps.provision();self.initialization=init.InitializationSession(self.ps)
            with self.assertRaises(RunError):self.initialization.observe('target-001','observer-lost')
        (self.ps.state/'operations').mkdir(mode=0o700)
        self.lease._reconciliation_only=True;self.f.calls.clear()

    def test_same_loader_verifies_original_inputs_and_reconciles_without_starting_the_provisioner(self):
        import test_provisioning as provider_fixture
        self.f.running[provider_fixture.CONTROLLER]=False
        with self.f.patches(),patch.object(images,'docker_configuration',return_value='private'),\
            patch.object(init,'_run_process',return_value={'status':'pass','returncode':0,'log':json.dumps(self.result).encode(),'log_truncated':False}):
            resumed=init.InitializationSession.resume(self.run,self.lease)
            self.assertTrue(resumed.provisioning.destroy_only)
            self.assertTrue(resumed.provisioning.receipt['unknown_outcome'])
            resumed.reconcile('target-001')
        self.assertFalse(read_json(self.run.file('evidence/provisioning.json'))['unknown_outcome'])
        self.assertFalse(any(call[:2] in {('docker','create'),('docker','start')} for call in self.f.calls))
        self.assertFalse(any(call[0]=='operation' for call in self.f.calls))

    def test_unrelated_terraform_progress_is_refused_before_a_target_or_controller_is_touched(self):
        self.ps.receipt['operations'].append({'operation':'new-mutation'});self.ps.save()
        with self.f.patches(),patch.object(images,'inspect') as inspect,self.assertRaises(RunError) as error:
            init.InitializationSession.resume(self.run,self.lease)
        inspect.assert_not_called();self.assertEqual(error.exception.code,'initialization_provider_state_changed')


if __name__=='__main__':unittest.main()
