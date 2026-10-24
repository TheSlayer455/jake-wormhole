"""CLI failure propagation; these fixtures do not claim actual host isolation."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from wormhole import cli
from wormhole.runs import RunError

SENTINEL = 'f' * 64


class IsolationCLITests(unittest.TestCase):
    def invoke(self, value=None, error=None, extra=()):
        module = ModuleType('wormhole.isolation_acceptance')
        module.acceptance = Mock(return_value=value, side_effect=error)
        output = io.StringIO()
        with patch.dict(sys.modules, {'wormhole.isolation_acceptance': module}), redirect_stdout(output):
            status = cli.main(['isolation-check', '--sentinel-id', SENTINEL, *extra])
        return status, json.loads(output.getvalue()), module.acceptance

    def test_fixed_library_dispatch(self):
        status, receipt, operation = self.invoke({'status': 'passed'})
        self.assertEqual((status, receipt), (0, {'status': 'passed'}))
        operation.assert_called_once_with(SENTINEL)

    def test_failed_or_incomplete_suite_stays_nonzero(self):
        for outcome in ('failed', 'incomplete', None):
            with self.subTest(outcome=outcome):
                status, receipt, _ = self.invoke({'status': outcome})
                self.assertEqual(status, 1)
                self.assertEqual(receipt['status'], outcome)

    def test_policy_refusal_is_not_success(self):
        status, receipt, _ = self.invoke(error=RunError('infrastructure_busy', 'The shared infrastructure is busy.'))
        self.assertEqual(status, 2)
        self.assertEqual(receipt['error']['code'], 'infrastructure_busy')

    def test_failed_suite_and_child_identities_survive_cli_error(self):
        error = RunError('controlled_interruption', 'Retain the original failure.')
        error.run_id = 'c18794ab-62af-47df-8129-dbd944ac3fe0'
        error.suite_run_id = '1cf70cee-d163-483f-aace-9dff39beef39'
        status, receipt, _ = self.invoke(error=error)
        self.assertEqual(status, 2)
        self.assertEqual(receipt['run_id'], error.run_id)
        self.assertEqual(receipt['suite_run_id'], error.suite_run_id)

    def test_no_operator_selected_profile_root_or_fault(self):
        for extra in (('--workspace', '/tmp/other'), ('--profile', 'twenty'), ('--fault', 'arbitrary')):
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.invoke({'status': 'passed'}, extra=extra)


if __name__ == '__main__':
    unittest.main()
