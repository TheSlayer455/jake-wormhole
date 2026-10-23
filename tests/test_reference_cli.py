"""CLI boundaries use a controlled library adapter; these are not runtime proof."""
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from wormhole import cli
from wormhole.images import RUNS_ROOT
from wormhole.runs import RunError

RUN_ID = 'baf69558-c809-4ea5-b145-fc3659cc1331'


class LockedRun:
    held = False

    @contextmanager
    def locked(self):
        if self.held:
            raise AssertionError('Nested lock is not allowed')
        self.held = True
        try:
            yield
        finally:
            self.held = False


class ReferenceCLITests(unittest.TestCase):
    def setUp(self):
        self.run = LockedRun()
        self.pipeline = ModuleType('wormhole.pipeline')
        self.pipeline.make_request = Mock(return_value={'fixed': 'request'})
        self.execution = Mock()
        self.pipeline.PipelineSession = Mock(return_value=self.execution)
        self.pipeline.report_pipeline = Mock()
        self.pipeline.gate_pipeline = Mock()

    def invoke(self, *args):
        output = io.StringIO()
        with patch.dict(sys.modules, {'wormhole.pipeline': self.pipeline}), redirect_stdout(output):
            status = cli.main(list(args))
        return status, output.getvalue()

    def test_reference_run_uses_fixed_real_storage_and_never_credits_ineligible_record(self):
        self.execution.execute.return_value = {'reference_eligible': False}
        with patch.object(cli, 'create_run', return_value=self.run) as create:
            status, output = self.invoke('reference-run', '--platform', 'ubi', '--base-run', RUN_ID)
        create.assert_called_once_with(RUNS_ROOT, fixture=False, kernel_lock=True)
        self.pipeline.make_request.assert_called_once_with(self.run, platform='ubi', scenario='healthy', base_run_id=RUN_ID)
        self.assertEqual(status, 1)
        self.assertFalse(json.loads(output)['reference_eligible'])

    def test_actual_library_failure_is_nonzero_and_retains_the_exact_run_identity(self):
        error = RunError('candidate_required_check_mismatch', 'Required reference check failed.')
        error.run_id = RUN_ID
        self.execution.execute.side_effect = error
        with patch.object(cli, 'create_run', return_value=self.run):
            status, output = self.invoke('reference-run', '--scenario', 'version-expectation-mismatch')
        value = json.loads(output)
        self.assertEqual(status, 2)
        self.assertEqual(value['error']['code'], 'candidate_required_check_mismatch')
        self.assertEqual(value['run_id'], RUN_ID)

    def test_reports_preserve_each_library_format_and_hold_the_run_lock(self):
        record = {'reference_eligible': False, 'rows': [{'status': 'blocked'}]}
        report = {'record': record, 'json': json.dumps(record).encode() + b'\n',
                  'text': 'Required check: blocked\n', 'junit': '<testsuite errors="1"/>\n'}
        def replay(run):
            self.assertIs(run, self.run)
            self.assertTrue(run.held)
            return report
        self.pipeline.report_pipeline.side_effect = replay
        for name in ('json', 'text', 'junit'):
            with self.subTest(format=name), patch.object(cli, 'Run', return_value=self.run):
                status, output = self.invoke('reference-report', RUN_ID, '--format', name)
            expected = report[name].decode() if isinstance(report[name], bytes) else report[name]
            self.assertEqual(output, expected)
            self.assertEqual(status, 1)
            self.assertFalse(self.run.held)

    def test_gate_denial_remains_nonzero_even_after_successful_cleanup(self):
        decision = {'reference_eligible': False, 'cleanup': 'completed', 'reasons': ['missing_required_result']}
        def replay(run):
            self.assertTrue(run.held)
            return decision
        self.pipeline.gate_pipeline.side_effect = replay
        with patch.object(cli, 'Run', return_value=self.run):
            status, output = self.invoke('reference-gate', RUN_ID)
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output), decision)

    def test_unknown_scenario_is_rejected_before_run_creation(self):
        with patch.object(cli, 'create_run') as create, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            self.invoke('reference-run', '--scenario', 'execute-ticket-text')
        self.assertEqual(error.exception.code, 2)
        create.assert_not_called()


if __name__ == '__main__':
    unittest.main()
