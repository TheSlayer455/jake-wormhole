"""Acceptance operator guard fixtures; no host or container operations."""
from copy import deepcopy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import candidate as c, candidate_acceptance as a, images
from wormhole.runs import atomic_json, common, read_json, create_run
from test_candidate import CandidateFixture, BUILDER, DERIVED, SHA
from test_candidate_validation import binding_for


class CandidateOperator(CandidateFixture, unittest.TestCase):
    def setUp(self):
        super().setUp(); self.binding = binding_for(self)
        self.resources = [{'kind': 'container', 'id': BUILDER, 'outcome': 'absent'}, {'kind': 'image', 'id': DERIVED, 'outcome': 'retained'}]
        self.lease = SimpleNamespace(record={'resources': self.resources})
        item = patch.object(a, 'create_run', side_effect=lambda *_, **__: create_run(self.run.workspace, fixture=False, identity=(SHA, False)))
        item.start(); self.addCleanup(item.stop)

    def test_known_completed_image_phase_has_exact_absence_and_sweep_proof(self):
        image = {'Id': DERIVED, 'Parent': self.binding['base_image'], 'Os': 'linux', 'Architecture': 'amd64',
            'Config': {'Labels': self.binding['image_labels'], 'User': '0:0', 'Entrypoint': ['/usr/bin/python3', '/opt/wormhole/runtime.py', 'target'], 'Cmd': []}}
        with patch.object(images, 'inspect', side_effect=lambda kind, identity, **_: None if kind == 'container' else image), \
             patch.object(images, 'docker', return_value={'log': b'', 'log_truncated': False}) as docker:
            value = a.reconcile_image_phase(self.run, self.lease, self.binding)
        self.assertEqual(value['status'], 'completed'); self.assertFalse(value['terraform_or_helper_allocated'])
        self.assertEqual(docker.call_count, 2)

    def test_uncertain_or_pending_image_phase_refuses_before_any_runtime_request(self):
        built = read_json(self.run.file('evidence/candidate-build.json')); built['unknown_outcome'] = True
        atomic_json(self.run.file('evidence/candidate-build.json'), built)
        with patch.object(images, 'inspect') as inspect, self.assertRaises(c.CandidateError):
            a.reconcile_image_phase(self.run, self.lease, self.binding)
        inspect.assert_not_called()
        built['unknown_outcome'] = False; atomic_json(self.run.file('evidence/candidate-build.json'), built)
        self.resources[0]['outcome'] = 'pending'
        with patch.object(images, 'inspect') as inspect, self.assertRaises(c.CandidateError):
            a.reconcile_image_phase(self.run, self.lease, self.binding)
        inspect.assert_not_called()

    def test_suite_rejects_changed_source_contradictory_case_and_reused_run_identity(self):
        def result(scenario, sentinel):
            number = a.CASES.index(scenario)
            return {'status': 'passed', 'source_revision': SHA, 'source_dirty': False, 'scenario': scenario,
                'run_id': f'{number:08x}-0000-4000-8000-000000000001', 'derived_image': 'sha256:' + str(number) * 64}
        with patch.object(a, 'source_identity', return_value=(SHA, False)), patch.object(a, 'qualify_case', side_effect=result):
            self.assertEqual(a.acceptance('f' * 64)['status'], 'passed')
        def wrong(scenario, sentinel): value = result(scenario, sentinel); value['source_revision'] = 'b' * 40; return value
        with patch.object(a, 'source_identity', return_value=(SHA, False)), patch.object(a, 'qualify_case', side_effect=wrong), self.assertRaises(c.CandidateError):
            a.acceptance('f' * 64)
        def reused(scenario, sentinel): value = result(scenario, sentinel); value['run_id'] = '00000000-0000-4000-8000-000000000001'; return value
        with patch.object(a, 'source_identity', return_value=(SHA, False)), patch.object(a, 'qualify_case', side_effect=reused) as qualify, self.assertRaises(c.CandidateError):
            a.acceptance('f' * 64)
        self.assertEqual(qualify.call_count, 2)

    def test_failed_child_and_suite_identifiers_remain_available_without_outputting_exception_text(self):
        error = c.CandidateError('candidate_install_failed', 'Synthetic failure text stays private')
        error.run_id = self.run.id
        with patch.object(a, 'source_identity', return_value=(SHA, False)), patch.object(a, 'qualify_case', side_effect=error):
            with self.assertRaises(c.CandidateError) as result: a.acceptance('f' * 64)
        self.assertEqual(result.exception.run_id, self.run.id)
        suite = result.exception.suite_run_id
        receipt = read_json(self.run.workspace / suite / 'evidence/candidate-acceptance-suite.json')
        self.assertEqual(receipt['failed_child_run_id'], self.run.id); self.assertEqual(receipt['status'], 'failed')
        self.assertNotIn('Synthetic failure text', json.dumps(receipt))

    def test_source_change_before_second_child_does_not_attribute_failure_to_first_healthy_run(self):
        result = {'status': 'passed', 'source_revision': SHA, 'source_dirty': False, 'scenario': 'healthy',
            'run_id': self.run.id, 'derived_image': DERIVED}
        identities = [(SHA, False), (SHA, False), (SHA, False), ('b' * 40, False)]
        with patch.object(a, 'source_identity', side_effect=identities), patch.object(a, 'qualify_case', return_value=result) as qualify:
            with self.assertRaises(c.CandidateError) as error: a.acceptance('f' * 64)
        self.assertEqual(qualify.call_count, 1)
        receipt = read_json(self.run.workspace / error.exception.suite_run_id / 'evidence/candidate-acceptance-suite.json')
        self.assertIsNone(receipt['failed_child_run_id']); self.assertEqual(receipt['cases'][0]['run_id'], self.run.id)


if __name__ == '__main__': unittest.main()
