"""Operator boundary fixtures; they perform no SSH, Ansible or Docker work."""
from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from wormhole import readiness_acceptance as operator
from wormhole.runs import RunError


class ReadinessOperatorBoundaries(unittest.TestCase):
    def test_rotated_hostkey_retries_only_pending_key_generation(self):
        pending = operator.images.ImageError('qualification_attempt_failed', 'Not generated yet.')
        observe = unittest.mock.Mock(side_effect=[pending,
            {'fingerprint': 'new', 'matches_original_pin': False}])
        readiness = SimpleNamespace(deadline=100, observe_hostkey=observe)
        with patch.object(operator.time, 'monotonic', return_value=1), patch.object(operator.time, 'sleep'):
            value = operator.observe_rotated_hostkey(readiness)
        self.assertEqual(value['fingerprint'], 'new')
        self.assertEqual(observe.call_count, 2)

    def test_rotated_hostkey_does_not_retry_ownership_failure(self):
        error = operator.images.ImageError('ownership_mismatch', 'Wrong object.')
        readiness = SimpleNamespace(deadline=100, observe_hostkey=unittest.mock.Mock(side_effect=error))
        with patch.object(operator.time, 'monotonic', return_value=1), self.assertRaises(operator.images.ImageError):
            operator.observe_rotated_hostkey(readiness)
        self.assertEqual(readiness.observe_hostkey.call_count, 1)

    def test_rotated_hostkey_stops_at_its_deadline(self):
        readiness = SimpleNamespace(deadline=2, observe_hostkey=unittest.mock.Mock(
            return_value={'fingerprint': 'old', 'matches_original_pin': True}))
        with patch.object(operator.time, 'monotonic', side_effect=[1, 1, 1.5, 2]), \
                patch.object(operator.time, 'sleep'), self.assertRaises(RunError) as error:
            operator.observe_rotated_hostkey(readiness)
        self.assertEqual(error.exception.code, 'rotated_hostkey_unavailable')
        self.assertEqual(readiness.observe_hostkey.call_count, 1)

    def test_invalid_case_and_sentinel_refuse_before_run_creation(self):
        with patch.object(operator, 'create_run') as allocate:
            for scenario, sentinel, code in (
                    ('imported-command', 'a' * 64, 'unsupported_acceptance_case'),
                    ('healthy', '../foreign', 'invalid_sentinel')):
                with self.subTest(scenario=scenario), self.assertRaises(RunError) as error:
                    operator.qualify_case(scenario, sentinel)
                self.assertEqual(error.exception.code, code)
            allocate.assert_not_called()

    def test_source_change_between_cases_stops_before_second_allocation(self):
        output = io.StringIO()
        with patch.object(operator, 'source_identity', side_effect=[('a' * 40, False),
                ('a' * 40, False), ('b' * 40, False)]), patch.object(operator, 'qualify_case',
                return_value={'source_revision': 'a' * 40, 'status': 'pass'}) as case, redirect_stdout(output):
            status = operator.main(['--scenario', 'all', '--sentinel-id', 'c' * 64])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())['error']['code'], 'source_changed')
        self.assertEqual(case.call_count, 1)

    def test_contradictory_case_source_cannot_be_reported_as_passing_suite(self):
        output = io.StringIO()
        with patch.object(operator, 'source_identity', return_value=('a' * 40, False)), \
                patch.object(operator, 'qualify_case', return_value={'source_revision': 'b' * 40,
                    'status': 'pass'}), redirect_stdout(output):
            status = operator.main(['--sentinel-id', 'c' * 64])
        value = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertEqual(value['status'], 'fail')
        self.assertEqual(value['error']['code'], 'source_changed')
        self.assertFalse(value['runtime_pipeline_complete'])


if __name__ == '__main__':
    unittest.main()
