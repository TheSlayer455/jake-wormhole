"""Deterministic source fixtures; these are not container or ISO executions."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from wormhole.lifecycle import Lifecycle, report_lifecycle
from wormhole.runs import RunError, atomic_json, create_run


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.run = create_run(Path(temporary.name) / 'runs', fixture=False, identity=('a' * 40, False))
        self.clock = [0.0]

    def journal(self, count=1):
        return Lifecycle(self.run, ['target-' + str(index).zfill(3) for index in range(1, count + 1)],
            candidate_identity={'image_id': 'sha256:' + 'b' * 64}, checks=['function', 'inventory'],
            budget_seconds=120, clock=lambda: self.clock[0])

    def event(self, journal, event, target='target-001', **options):
        journal.event(target, event, evidence='source-fixture/observation', kind='source-fixture', **options)

    def ready(self, journal, target='target-001'):
        for event in ('created', 'runtime-started', 'initialization-started', 'initialization-complete',
            'configuration-started', 'configuration-complete', 'reachable', 'host-verified', 'authenticated',
            'interpreter-verified', 'privilege-not-required', 'ansible-verified'):
            self.event(journal, event, target)

    def test_twenty_mixed_results_retain_every_declared_target_and_check(self):
        journal = self.journal(20)
        for target in journal.record['expected_targets']: self.ready(journal, target)
        journal.start_validation()
        for target in journal.record['expected_targets']:
            journal.test_result(target, 'function', 'fail' if target == 'target-020' else 'pass')
            journal.test_result(target, 'inventory', 'pass')
        result = journal.finalize()
        self.assertEqual(result['terminal_outcome'], 'failed')
        self.assertEqual(len(result['targets']), 20)
        self.assertEqual(sum(len(target['tests']) for target in result['targets'].values()), 40)
        self.assertEqual(sum(target['terminal_outcome'] == 'passed' for target in result['targets'].values()), 19)
        self.assertFalse(result['production_iso_eligible'])

    def test_port_and_authentication_cannot_skip_configuration_or_ansible_contract(self):
        journal = self.journal(); self.event(journal, 'created'); self.event(journal, 'reachable')
        with self.assertRaises(RunError): journal.start_validation()
        self.event(journal, 'host-verified')
        with self.assertRaises(RunError): self.event(journal, 'authenticated')
        with self.assertRaises(RunError): self.event(journal, 'ansible-verified')
        self.assertEqual(journal.record['targets']['target-001']['tests'], {'function': 'blocked', 'inventory': 'blocked'})

    def test_expected_restart_invalidates_readiness_without_resetting_absolute_deadline(self):
        journal = self.journal(); self.ready(journal); original = journal.deadline
        self.event(journal, 'restart-started'); self.assertFalse(journal.ready('target-001'))
        self.clock[0] = 5; self.event(journal, 'restart-complete')
        with self.assertRaises(RunError): journal.start_validation()
        for event in ('reachable', 'host-verified', 'authenticated', 'interpreter-verified', 'privilege-not-required', 'ansible-verified'):
            self.event(journal, event)
        self.assertTrue(journal.ready('target-001')); self.assertEqual(journal.deadline, original)

    def test_initialization_failure_has_priority_over_deadline_cleanup_and_heartbeat(self):
        journal = self.journal(); self.event(journal, 'initialization-started')
        self.event(journal, 'failure', category='initialization_command_failed')
        first = deepcopy(journal.record['first_failure'])
        last_progress = journal.target('target-001')['last_progress_at']
        self.clock[0] = 200; self.event(journal, 'heartbeat')
        self.event(journal, 'failure', category='cleanup_failed')
        result = journal.finalize()
        self.assertEqual(result['first_failure'], first)
        self.assertEqual(result['terminal_outcome'], 'failed')
        self.assertEqual(result['targets']['target-001']['tests']['function'], 'blocked')
        self.assertEqual(result['targets']['target-001']['last_progress_at'], last_progress)

    def test_hardening_and_unknown_remote_state_cannot_leave_an_old_ready_snapshot_usable(self):
        journal = self.journal(); self.ready(journal)
        self.event(journal, 'hardening-started'); self.assertFalse(journal.ready('target-001'))
        self.event(journal, 'failure', category='final_home_inaccessible')
        self.event(journal, 'remote-unknown'); self.event(journal, 'heartbeat')
        result = journal.finalize()
        self.assertEqual(result['terminal_outcome'], 'unknown')
        self.assertEqual(result['first_failure']['code'], 'final_home_inaccessible')

    def test_missing_result_deadline_and_reused_dispatch_are_failures(self):
        journal = self.journal(); self.ready(journal); journal.start_validation()
        with self.assertRaises(RunError): journal.start_validation()
        journal.test_result('target-001', 'function', 'pass')
        with self.assertRaises(RunError): journal.test_result('target-001', 'function', 'pass')
        self.clock[0] = 101
        with self.assertRaises(RunError): journal.test_result('target-001', 'inventory', 'pass')
        self.assertEqual(journal.finalize()['terminal_outcome'], 'failed')
        self.assertEqual(journal.record['targets']['target-001']['tests']['inventory'], 'missing')

    def test_complete_terminal_record_and_missing_evidence_refusal(self):
        journal = self.journal(); self.ready(journal); journal.start_validation()
        for check in ('function', 'inventory'): journal.test_result('target-001', check, 'pass')
        journal.finalize()
        self.assertEqual(report_lifecycle(self.run, require_passed=True)['terminal_outcome'], 'passed')
        value = deepcopy(journal.record); value['targets']['target-001']['tests'].pop('inventory')
        atomic_json(self.run.file('evidence/lifecycle.json'), value)
        with self.assertRaises(RunError): report_lifecycle(self.run, require_passed=True)


if __name__ == '__main__': unittest.main()
