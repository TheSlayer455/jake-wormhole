"""Observation contract regressions; no container execution is claimed here."""
from copy import deepcopy
import unittest

from wormhole import execution_state as state
from wormhole.runs import RunError


def fixture():
    plan = {'run_id': 'fixture-run', 'source_revision': 'a' * 40, 'plan_sha256': 'b' * 64,
        'target_plan': {'target_ids': ['target-001', 'target-002']},
        'target_image': 'sha256:' + 'c' * 64, 'candidate_binding': 'qualified-stock-only',
        'checks': [{'target_id': target, 'check_id': check} for target in ('target-001', 'target-002')
            for check in ('function', 'inventory')]}
    readiness = {'run_id': plan['run_id'], 'source_revision': plan['source_revision'],
        'unknown_outcome': False, 'targets': []}
    for target in plan['target_plan']['target_ids']:
        readiness['targets'].append({'target_id': target, 'status': 'ready', 'primary_failure': None,
            'unknown_outcome': False, 'ready_started_at': '2026-01-01T00:00:00Z',
            'transitions': [{'check_id': check, 'target_id': target, 'status': 'pass',
                'observed_at': '2026-01-01T00:00:01Z', 'elapsed_seconds': index}
                for index, check in enumerate(state.READINESS_CHECKS)]})
    return plan, readiness


class ExecutionStateTests(unittest.TestCase):
    def test_creation_port_and_authentication_prefixes_cannot_prove_readiness(self):
        _, readiness = fixture()
        for count in range(len(state.READINESS_CHECKS)):
            target = deepcopy(readiness['targets'][0]); target['transitions'] = target['transitions'][:count]
            self.assertFalse(state.readiness_complete(target))
        self.assertTrue(state.readiness_complete(readiness['targets'][0]))
        for key, value in (('unknown_outcome', True), ('primary_failure', {'code': 'configuration_failed'}),
                           ('ready_started_at', None), ('status', 'waiting')):
            target = deepcopy(readiness['targets'][0]); target[key] = value
            self.assertFalse(state.readiness_complete(target))

    def test_progress_retains_unknown_initialization_and_every_missing_result(self):
        plan, readiness = fixture(); report = state.project(plan, readiness)
        self.assertEqual(report['summary']['targets_created'], 2)
        self.assertIsNone(report['summary']['targets_initialized'])
        self.assertEqual(report['summary']['targets_ansible_ready'], 2)
        self.assertEqual(report['summary']['tests_missing'], 4)
        self.assertTrue(all(target['terminal_outcome'] == 'pending' for target in report['targets']))
        self.assertIn('not inferred', state.render_text(report))
        self.assertFalse(report['production_iso_eligible'])

    def test_initialization_failure_has_priority_over_downstream_blocked_results(self):
        plan, readiness = fixture(); target = readiness['targets'][0]
        target.update(status='failed', primary_failure={'code': 'target_initialization_failed'})
        target['transitions'] = target['transitions'][:1]
        validation = {key: plan[key] for key in ('run_id', 'source_revision', 'plan_sha256')}
        validation.update(status='failed', attempted_targets=[], checks=[{**item, 'status': 'unverified'}
            for item in plan['checks']])
        report = state.project(plan, readiness, validation)
        self.assertEqual(report['targets'][0]['first_failure']['code'], 'target_initialization_failed')
        self.assertEqual(report['targets'][0]['initialization_outcome'], 'failed')
        self.assertEqual(report['targets'][0]['terminal_outcome'], 'failed')
        self.assertEqual(report['summary']['tests_blocked'], 4)

    def test_foreign_identity_duplicate_target_and_missing_expected_target_are_refused(self):
        plan, readiness = fixture()
        for mutate in (lambda value: value.update(run_id='foreign'),
                       lambda value: value['targets'].pop(),
                       lambda value: value['targets'].__setitem__(1, deepcopy(value['targets'][0]))):
            changed = deepcopy(readiness); mutate(changed)
            with self.assertRaises(RunError): state.project(plan, changed)

    def test_failed_completed_checks_and_missing_checks_remain_distinct(self):
        plan, readiness = fixture()
        validation = {key: plan[key] for key in ('run_id', 'source_revision', 'plan_sha256')}
        validation.update(status='failed', attempted_targets=['target-001', 'target-002'],
            checks=[{**check, 'status': 'pass'} for check in plan['checks']])
        validation['checks'][0]['status'] = 'fail'
        report = state.project(plan, readiness, validation)
        self.assertEqual(report['summary']['targets_fully_tested'], 2)
        self.assertEqual(report['summary']['tests_failed'], 1)
        self.assertEqual(report['targets'][0]['terminal_outcome'], 'failed')
        validation['checks'].pop()
        report = state.project(plan, readiness, validation)
        self.assertEqual(report['summary']['tests_missing'], 1)
        self.assertEqual(report['summary']['targets_fully_tested'], 1)

    def test_heartbeat_does_not_establish_progress_or_timeout_imply_stopped(self):
        self.assertEqual(state.observer_state(remote_alive=True), 'running-progress-unobserved')
        self.assertEqual(state.observer_state(remote_alive=True, progress_age=90), 'running-without-progress')
        self.assertEqual(state.observer_state(remote_alive=True, progress_age=1), 'running-making-progress')
        self.assertEqual(state.observer_state(remote_alive=True, observation_lost=True), 'unknown')
        self.assertEqual(state.observer_state(terminal_outcome='cancelled'), 'unknown')
        self.assertEqual(state.observer_state(terminal_outcome='cancelled', stopped_confirmed=True), 'cancelled-confirmed-stopped')
        self.assertEqual(state.observer_state(terminal_outcome='failed', observation_lost=True), 'terminal-failed')


if __name__ == '__main__': unittest.main()
