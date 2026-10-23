"""Operator scope/source boundaries, with no Docker or homelab calls."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import validation_acceptance as operator
from wormhole.runs import RunError


class FunctionalOperatorBoundaries(unittest.TestCase):
    def test_pre_cleanup_scan_failure_retains_primary_and_still_uses_exact_cleanup_policy(self):
        error = RunError('controlled_scan_failure', 'Synthetic diagnostic refusal.')
        events = []
        session = SimpleNamespace(receipt={'primary_failure': None},
            failure=lambda value: events.append(('failure', value.code)))
        lease, readiness, run = object(), object(), object()
        cleanup = {'status': 'completed'}
        with patch.object(operator, 'scan_private_material', side_effect=error), \
                patch.object(operator, 'disk_sample') as sample, patch.object(operator, 'cleanup_session',
                    side_effect=lambda *args, **kwargs: events.append(('cleanup', args, kwargs)) or cleanup) as clean:
            receipt, primary = operator.cleanup_with_observations(run, {'checks': {}}, session, lease, readiness)
        self.assertIs(primary, error)
        self.assertIs(receipt, cleanup)
        self.assertEqual(events[0], ('failure', 'controlled_scan_failure'))
        clean.assert_called_once_with(session, lease, reason='failure', helper=readiness)
        sample.assert_not_called()

    def test_existing_same_primary_is_not_duplicated_as_a_cleanup_secondary(self):
        session = SimpleNamespace(receipt={'primary_failure': {'code': 'required_check_mismatch'}}, failure=Mock())
        operator.retain_failure(session, RunError('required_check_mismatch', 'Already recorded.'))
        session.failure.assert_not_called()

    def test_invalid_inputs_refuse_before_allocation_or_optional_module_import(self):
        with patch.object(operator, 'create_run') as allocate:
            for case, sentinel, expected in (('ticket-command', 'a' * 64, 'unsupported_acceptance_case'),
                    ('healthy', '../foreign', 'invalid_sentinel')):
                with self.subTest(case=case), self.assertRaises(RunError) as error:
                    operator.qualify_case(case, sentinel)
                self.assertEqual(error.exception.code, expected)
            allocate.assert_not_called()

    def test_unsupported_platform_cannot_allocate_a_runtime(self):
        with patch.object(operator.sys, 'platform', 'win32'), patch.object(operator, 'create_run') as allocate, \
                self.assertRaises(RunError) as error:
            operator.qualify_case('healthy', 'a' * 64)
        self.assertEqual(error.exception.code, 'linux_required')
        allocate.assert_not_called()

    def test_contradictory_case_revision_cannot_pass_a_suite(self):
        with patch.object(operator, 'source_identity', return_value=('a' * 40, False)), \
                patch.object(operator, 'qualify_case', return_value={'source_revision': 'b' * 40,
                    'source_dirty': False, 'status': 'pass', 'run_id': 'one'}), self.assertRaises(RunError) as error:
            operator.acceptance('c' * 64, ('healthy',))
        self.assertEqual(error.exception.code, 'source_changed')

    def test_changed_checkout_stops_before_the_next_case(self):
        with patch.object(operator, 'source_identity', side_effect=[('a' * 40, False), ('a' * 40, False),
                ('a' * 40, False), ('b' * 40, False)]), patch.object(operator, 'qualify_case',
                return_value={'source_revision': 'a' * 40, 'source_dirty': False, 'status': 'pass', 'run_id': 'one'}) as case, \
                self.assertRaises(RunError) as error:
            operator.acceptance('c' * 64, ('healthy', 'unreachable'))
        self.assertEqual(error.exception.code, 'source_changed')
        self.assertEqual(case.call_count, 1)

    def test_reused_run_identity_cannot_pass_two_fresh_cases(self):
        with patch.object(operator, 'source_identity', return_value=('a' * 40, False)), \
                patch.object(operator, 'qualify_case', return_value={'source_revision': 'a' * 40,
                    'source_dirty': False, 'status': 'pass', 'run_id': 'same'}), self.assertRaises(RunError) as error:
            operator.acceptance('c' * 64, ('healthy', 'unreachable'))
        self.assertEqual(error.exception.code, 'run_id_reused')

    def test_unreachable_injection_requires_exact_identity_before_stop(self):
        session = SimpleNamespace(held=Mock(), receipt={'unknown_outcome': False},
            owned={'docker_container.target': 'a' * 64}, verify_target=Mock(
                side_effect=RunError('ownership_mismatch', 'Wrong object.')), save=Mock())
        with patch.object(operator.images, 'inspect', return_value={}), patch.object(operator.images, 'docker') as docker, \
                self.assertRaises(RunError) as error:
            operator.stop_owned_target(session)
        self.assertEqual(error.exception.code, 'ownership_mismatch')
        docker.assert_not_called()
        session.save.assert_not_called()
        self.assertFalse(session.receipt['unknown_outcome'])

    def test_lost_stop_response_keeps_durable_unknown_intent(self):
        captures = []
        session = SimpleNamespace(held=Mock(), receipt={'unknown_outcome': False},
            owned={'docker_container.target': 'a' * 64}, verify_target=Mock())
        session.save = lambda: captures.append(deepcopy(session.receipt))
        with patch.object(operator.images, 'inspect', return_value={'State': {'Running': True, 'Pid': 10}}), \
                patch.object(operator.images, 'docker', side_effect=OSError('Lost response')), self.assertRaises(OSError):
            operator.stop_owned_target(session)
        self.assertTrue(session.receipt['unknown_outcome'])
        self.assertEqual(captures, [{'unknown_outcome': True}])


if __name__ == '__main__':
    unittest.main()
