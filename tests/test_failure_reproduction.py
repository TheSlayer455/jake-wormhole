"""Source orchestration/CLI/report contracts; no Docker runtime claim."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

from wormhole import cli, failure_reproduction as f, failure_reports as reports
from wormhole.lifecycle import Lifecycle
from wormhole.runs import RunError,create_run


class FailureContracts(unittest.TestCase):
    def test_invalid_selection_and_nonlinux_refuse_before_creating_any_run(self):
        with patch.object(f,'create_run') as create:
            for profile,scenario,sentinel in (('twenty','healthy','b'*64),('smoke','arbitrary-code','b'*64),('smoke','healthy','foreign')):
                with self.assertRaises(RunError):f.reproduce(profile,scenario,sentinel)
            with patch.object(f.sys,'platform','win32'),self.assertRaises(RunError):f.reproduce('smoke','healthy','b'*64)
        create.assert_not_called()

    def test_expected_negative_cli_is_nonzero_and_unknown_stays_distinct(self):
        for outcome,expected in (('passed',0),('failed',1),('unknown',2)):
            value={'status':outcome,'scenario_expectation_met':True,'reference_eligible':False,'production_iso_eligible':False}
            with patch.object(f,'reproduce',return_value=value),redirect_stdout(io.StringIO()):
                status=cli.main(['reproduce','--scenario','initialization-command-fails','--sentinel-id','b'*64])
            self.assertEqual(status,expected)

    def test_twenty_target_report_counts_all_blocked_rows_and_keeps_original_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=('a'*40,False))
            ids=['target-'+str(index).zfill(3) for index in range(1,21)]
            lifecycle=Lifecycle(run,ids,candidate_identity={'kind':'stock-image'},checks=['required-function','inventory'])
            lifecycle.event(ids[0],'created',evidence='source-fixture',kind='source-fixture')
            lifecycle.event(ids[0],'failure',evidence='source-fixture',kind='source-fixture',category='initialization_command_failed')
            lifecycle.finalize()
            record={'run_id':run.id,'source_revision':'a'*40,'scenario':'initialization-command-fails','status':'failed',
                'primary_failure':{'code':'initialization_command_failed'},'secondary_failures':[],
                'stage_timings':dict.fromkeys(f.STAGES,None),'cleanup':{'status':'completed'},
                'remaining_owned_resources':[],'scenario_expectation_met':True}
            value=reports.write(run,record,lifecycle.record)
            self.assertEqual(value['summary']['targets_expected'],20)
            self.assertEqual(value['summary']['targets_created'],1)
            self.assertEqual(value['summary']['tests_blocked'],40)
            self.assertEqual(value['summary']['tests_passed'],0)
            self.assertEqual(len(list(run.file('evidence/targets').glob('*.txt'))),20)
            text=run.file('evidence/failure-report.txt').read_text()
            self.assertIn('initialization_command_failed',text)
            self.assertFalse(value['reference_eligible']);self.assertFalse(value['production_iso_eligible'])
            record['simulation']=True;record['identity_diagnostic']={'status':'fail','category':'ssh_user_rejected','returncode':255}
            reported=reports.report(record,lifecycle.record)
            self.assertTrue(reported['simulation']);self.assertEqual(reported['identity_diagnostic']['returncode'],255)

    def test_fixed_scenarios_cover_real_faults_and_labeled_simulations(self):
        self.assertEqual(len(f.SCENARIOS),19)
        self.assertIn('remote-unknown',f.SCENARIOS);self.assertIn('hardening-breaks-home',f.SCENARIOS)
        self.assertEqual(f.EXPECTED['initialization-command-fails'],'initialization_command_failed')
        self.assertEqual(f.EXPECTED['controller-deadline'],'validation_timeout')

    def test_report_keeps_observed_readiness_after_validation_failure_but_invalidates_restart(self):
        for restart in (False,True):
            with self.subTest(restart=restart),tempfile.TemporaryDirectory() as folder:
                run=create_run(Path(folder)/'runs',fixture=False,identity=('a'*40,False))
                lifecycle=Lifecycle(run,['target-001'],candidate_identity={'kind':'stock-image'},checks=['required-function'])
                for event in ('created','runtime-started','initialization-started','initialization-complete',
                        'configuration-started','configuration-complete','reachable','host-verified','authenticated',
                        'interpreter-verified','privilege-not-required','ansible-verified'):
                    lifecycle.event('target-001',event,evidence='source-fixture',kind='source-fixture')
                if restart:
                    lifecycle.event('target-001','restart-started',evidence='source-fixture',kind='source-fixture')
                    lifecycle.event('target-001','failure',evidence='source-fixture',kind='source-fixture',category='readiness_incomplete')
                else:
                    lifecycle.start_validation()
                    lifecycle.test_result('target-001','required-function','fail')
                lifecycle.finalize()
                record={'run_id':run.id,'source_revision':'a'*40,'scenario':'playbook-fails','status':'failed',
                    'primary_failure':lifecycle.record['first_failure'],'secondary_failures':[],
                    'stage_timings':dict.fromkeys(f.STAGES,None),'cleanup':{'status':'completed'},
                    'remaining_owned_resources':[],'scenario_expectation_met':True}
                value=reports.report(record,lifecycle.record)
                self.assertEqual(value['summary']['targets_ansible_ready'],0 if restart else 1)
                self.assertEqual(value['summary']['tests_failed'],0 if restart else 1)
                self.assertEqual(value['targets'][0]['terminal_outcome'],'failed')
                self.assertFalse(value['reference_eligible'])

    def test_negative_credit_requires_actual_declared_failure_known_state_and_complete_cleanup(self):
        record={'scenario':'never-ready','status':'failed','primary_failure':{'code':'target_not_started'},
            'unknown_outcome':False,'remaining_owned_resources':[],'cleanup':{'status':'completed'},'sentinel_unchanged':True,
            'full_catalog_started':False}
        self.assertTrue(f.expectation_met(record,'twenty-targets'))
        record['primary_failure']['code']='deadline_exhausted'
        self.assertTrue(f.expectation_met(record,'twenty-targets'))
        self.assertFalse(f.expectation_met(record,'smoke'))
        for field,value in (('unknown_outcome',True),('remaining_owned_resources',[{'outcome':'pending'}]),
            ('status','passed'),('cleanup',{'status':'blocked'}),('sentinel_unchanged',False),('full_catalog_started',True)):
            changed={**record,field:value}
            self.assertFalse(f.expectation_met(changed,'twenty-targets'))

    def test_absent_identity_experiment_requires_its_actual_rejected_ssh_diagnostic(self):
        record={'scenario':'account-missing','status':'failed','primary_failure':{'code':'final_account_missing'},
            'unknown_outcome':False,'remaining_owned_resources':[],'cleanup':{'status':'completed'},'sentinel_unchanged':True,
            'full_catalog_started':False,'identity_diagnostic':None}
        self.assertFalse(f.expectation_met(record,'smoke'))
        record['identity_diagnostic']={'status':'fail','category':'ssh_user_rejected','returncode':255}
        self.assertTrue(f.expectation_met(record,'smoke'))
        record['identity_diagnostic']={'status':'fail','category':'ssh_transport_pending','returncode':255}
        self.assertFalse(f.expectation_met(record,'smoke'))


if __name__=='__main__':unittest.main()
