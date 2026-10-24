"""CLI dispatch fixtures; they do not execute Docker or prove real cleanup."""
from contextlib import redirect_stdout
import io
import json
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from wormhole import cli


class RecoveryCLI(unittest.TestCase):
    def setUp(self):
        self.run = Mock()
        self.run.manifest.return_value = {'mode': 'container-reference'}
        self.run.locked.side_effect = AssertionError('CLI must not acquire the coordinator lock')
        self.module = ModuleType('wormhole.recovery')
        self.module.request_cancel = Mock(return_value={'status': 'requested', 'acknowledged': False})
        self.module.inspect_recovery = Mock(return_value={'status': 'blocked', 'unknown_outcome': True})
        self.module.recover_run = Mock(return_value={'status': 'completed', 'primary_outcome': 'failed'})

    def invoke(self, command):
        output = io.StringIO()
        with patch.object(cli, 'Run', return_value=self.run), patch.dict(sys.modules, {'wormhole.recovery': self.module}), redirect_stdout(output):
            status = cli.main([command, '12345678-1234-4234-9234-123456789abc'])
        return status, json.loads(output.getvalue())

    def test_cancel_request_does_not_take_run_lock_or_claim_acknowledgement(self):
        status, value = self.invoke('cancel')
        self.assertEqual(status, 0)
        self.assertEqual(value, {'status': 'requested', 'acknowledged': False})
        self.module.request_cancel.assert_called_once_with(self.run)
        self.module.recover_run.assert_not_called()
        self.run.locked.assert_not_called()

    def test_real_cleanup_and_recover_delegate_locking_without_overwriting_primary_outcome(self):
        for command in ('cleanup', 'recover'):
            with self.subTest(command=command):
                self.module.recover_run.reset_mock()
                status, value = self.invoke(command)
                self.assertEqual(status, 0)
                self.assertEqual(value['primary_outcome'], 'failed')
                self.module.recover_run.assert_called_once_with(self.run)
                self.run.locked.assert_not_called()
        for terminal, expected in (('failed', 1), ('blocked', 2)):
            self.module.recover_run.return_value = {'status': terminal, 'primary_outcome': 'failed'}
            self.assertEqual(self.invoke('recover')[0], expected)

    def test_inspection_reports_uncertainty_without_mutating_or_attempting_cleanup(self):
        status, value = self.invoke('cleanup-status')
        self.assertEqual(status, 0)
        self.assertTrue(value['unknown_outcome'])
        self.module.inspect_recovery.assert_called_once_with(self.run)
        self.module.request_cancel.assert_not_called()
        self.module.recover_run.assert_not_called()
        self.run.locked.assert_not_called()

    def test_io_failure_does_not_falsely_assert_that_no_infrastructure_action_occurred(self):
        self.module.recover_run.side_effect = OSError('synthetic private diagnostic')
        status, value = self.invoke('recover')
        self.assertEqual(status, 2)
        self.assertEqual(value['error']['code'], 'local_io_error')
        self.assertNotIn('synthetic private diagnostic', json.dumps(value))
        self.assertIn('preserve the run', value['error']['message'])


if __name__ == '__main__':
    unittest.main()
