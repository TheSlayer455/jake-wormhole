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

    def test_fixed_scenarios_cover_real_faults_and_labeled_simulations(self):
        self.assertEqual(len(f.SCENARIOS),19)
        self.assertIn('remote-unknown',f.SCENARIOS);self.assertIn('hardening-breaks-home',f.SCENARIOS)
        self.assertEqual(f.EXPECTED['initialization-command-fails'],'initialization_command_failed')
        self.assertEqual(f.EXPECTED['controller-deadline'],'validation_timeout')


if __name__=='__main__':unittest.main()
