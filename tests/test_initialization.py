"""Fixed adapter fixtures. Docker is mocked; no initialization runtime proof."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import initialization as init
from wormhole.runs import RunError, create_run
from wormhole.targets import TargetPlan


class InitializationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.run = create_run(Path(temporary.name) / 'runs', fixture=False, identity=('a' * 40, False))
        self.ps = SimpleNamespace(run=self.run, held=Mock(), check_inputs=Mock(),
            target_plan=TargetPlan('smoke'), target_resources={'target-001': 'b' * 64},
            variables={'mutable_home': False}, receipt={'unknown_outcome': False}, save=Mock(), verify_target=Mock())
        self.session = init.InitializationSession(self.ps)

    def observation(self, scenario='healthy', status='passed', category=None):
        return {'schema_version': '1.0', 'operation': 'container-initialization-v1', 'run_id': self.run.id,
            'scenario': scenario, 'status': status, 'stage': 'initialization' if category else 'configuration',
            'category': category, 'command_returncode': 23 if scenario == 'initialization-command-fails' else None,
            'checks': dict.fromkeys(init.runtime.FIELDS, status == 'passed'),
            'events': ['initialization-started'] if status != 'passed' else ['initialization-started',
                'initialization-complete', 'configuration-started', 'configuration-complete'],
            'simulated_installation': scenario == 'installation-source-missing', 'production_iso_eligible': False}

    def execute(self, value, *, status=None):
        result = {'status': status or ('pass' if value['status'] != 'failed' else 'fail'),
            'returncode': 0 if value['status'] != 'failed' else value['command_returncode'] or 1,
            'log': json.dumps(value).encode(), 'log_truncated': False}
        actual = {'Id': 'b' * 64, 'State': {'Running': True, 'StartedAt': '2026-01-01T00:00:00Z'}}
        with patch.object(init.images, 'inspect', return_value=actual), \
            patch.object(init.images, 'docker_configuration', return_value='empty-private-config'), \
            patch.object(init, '_run_process', return_value=result) as command:
            observed = self.session.observe('target-001', value['scenario'])
        return observed, command

    def test_real_command_failure_exit_and_capture_are_preserved_before_readiness(self):
        value = self.observation('initialization-command-fails', 'failed', 'initialization_command_failed')
        observed, command = self.execute(value)
        self.assertEqual(observed['command_returncode'], 23)
        with self.assertRaises(RunError) as error: self.session.require_complete('target-001')
        self.assertEqual(error.exception.code, 'initialization_command_failed')
        self.assertFalse(self.ps.receipt['unknown_outcome'])
        self.assertEqual(init.report_initialization(self.run)['targets']['target-001']['observation'], value)
        self.assertEqual(command.call_args.args[0][-3:], ('initialization-command-fails', 'false', '0'))

    def test_account_home_key_and_simulated_install_failures_are_explicit_and_never_ready(self):
        for scenario, category in (('account-missing', 'final_account_missing'),
            ('home-inaccessible', 'final_home_inaccessible'), ('authorized-key-missing', 'authorized_key_missing'),
            ('installation-source-missing', 'simulated_installation_source_missing')):
            value = self.observation(scenario, 'failed', category); self.execute(value)
            with self.assertRaises(RunError) as error: self.session.require_complete('target-001')
            self.assertEqual(error.exception.code, category)
        with self.assertRaises(RunError): init.report_initialization(self.run, require_passed=True)

    def test_hardening_requires_observed_healthy_baseline_and_replay_rejects_changed_capture(self):
        with self.assertRaises(RunError) as error: self.session.observe('target-001', 'hardening-breaks-home')
        self.assertEqual(error.exception.code, 'hardening_baseline_required')
        self.execute(self.observation())
        self.execute(self.observation('hardening-breaks-home', 'failed', 'final_home_inaccessible'))
        capture = self.run.file(self.session.record['attempts'][-1]['capture']); capture.write_bytes(b'{}')
        with self.assertRaises(RunError): init.report_initialization(self.run)

    def test_foreign_ownership_blocks_before_exec_and_lost_exec_retains_unknown(self):
        with patch.object(init.images, 'inspect', return_value={}), \
            patch.object(self.ps, 'verify_target', side_effect=RunError('ownership_mismatch', 'Controlled mismatch')), \
            patch.object(init, '_run_process') as execute, self.assertRaises(RunError): self.session.observe('target-001')
        execute.assert_not_called()
        value = self.observation()
        with self.assertRaises(RunError) as error: self.execute(value, status='timeout')
        self.assertEqual(error.exception.code, 'initialization_outcome_unknown')
        self.assertTrue(self.ps.receipt['unknown_outcome'])

    def test_wrong_identity_duplicate_fields_and_fake_completion_refuse(self):
        value = self.observation()
        for changed in ({**value, 'run_id': 'foreign'}, {**value, 'checks': dict.fromkeys(init.runtime.FIELDS, False)},
                        {**value, 'production_iso_eligible': True}):
            with self.assertRaises(RunError): init.decode(json.dumps(changed).encode(), self.run.id, 'healthy')
        duplicate = json.dumps(value)[:-1] + ',"status":"passed"}'
        with self.assertRaises(RunError): init.decode(duplicate.encode(), self.run.id, 'healthy')

    def test_durable_terminal_result_resolves_only_the_exact_lost_execution(self):
        value=self.observation('observer-lost')
        with self.assertRaises(RunError):self.execute(value,status='timeout')
        actual={'State':{'Running':True,'StartedAt':'2026-01-01T00:00:00Z'}}
        response={'status':'pass','returncode':0,'log':json.dumps(value).encode(),'log_truncated':False}
        with patch.object(init.images,'inspect',return_value=actual),patch.object(init.images,'docker_configuration',return_value='private'),\
            patch.object(init,'_run_process',return_value=response):
            self.assertEqual(self.session.reconcile('target-001'),value)
        self.assertFalse(self.ps.receipt['unknown_outcome'])
        self.assertTrue(self.session.record['attempts'][-1]['terminal_marker_verified'])
        init.report_initialization(self.run,require_passed=True)

    def test_restarted_target_or_missing_terminal_does_not_clear_unknown(self):
        with self.assertRaises(RunError):self.execute(self.observation('observer-lost'),status='timeout')
        with patch.object(init.images,'inspect',return_value={'State':{'Running':True,'StartedAt':'different'}}),\
            patch.object(init,'_run_process') as execute,self.assertRaises(RunError):self.session.reconcile('target-001')
        execute.assert_not_called();self.assertTrue(self.ps.receipt['unknown_outcome'])

    def test_confirmed_stop_preserves_failure_and_does_not_adopt_older_healthy_result(self):
        self.execute(self.observation())
        with self.assertRaises(RunError):self.execute(self.observation('observer-lost'),status='timeout')
        self.ps.verify_owned=Mock();self.ps.verify_limits=Mock()
        before={'State':{'Running':True,'StartedAt':'2026-01-01T00:00:00Z'}}
        after={'State':{'Running':False,'Pid':0,'Status':'exited'}}
        with patch.object(init.images,'inspect',side_effect=[before,after]),patch.object(init.images,'docker') as stop:
            self.session.cancel_and_confirm('target-001')
        stop.assert_called_once_with(('stop','--time','2','b'*64),timeout=5)
        self.assertFalse(self.ps.receipt['unknown_outcome'])
        with self.assertRaises(RunError):self.session.require_complete('target-001')
        with self.assertRaises(RunError):init.report_initialization(self.run,require_passed=True)

    def test_command_failure_without_original_exit_is_not_valid_evidence(self):
        value=self.observation('initialization-command-fails','failed','initialization_command_failed')
        value['command_returncode']=None
        with self.assertRaises(RunError):init.decode(json.dumps(value).encode(),self.run.id,value['scenario'])


if __name__ == '__main__': unittest.main()
