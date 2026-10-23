"""Synthetic protocol/transport fixtures; no Docker, SSH or Ansible execution."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wormhole import candidate as c, candidate_validation as cv, validation as v, images, provisioning as p
from wormhole.runs import atomic_json, common, read_json
from validation import runtime
from test_candidate import CandidateFixture, DERIVED, BUILDER, SHA

TARGET, NETWORK, HELPER = 'd' * 64, 'e' * 64, 'f' * 64


def binding_for(fixture):
    value = {**common(fixture.run.manifest()), 'operation': 'candidate-image-binding', 'status': 'built',
        'candidate_sha256': fixture.bundle['candidate_sha256'], 'manifest': fixture.bundle['manifest'],
        'base_image': p.TARGET_IMAGE, 'image_id': DERIVED,
        'image_labels': c.binding_labels(fixture.run, fixture.bundle['candidate_sha256'], c.qualified_base_labels()),
        'installer_sha256': c.sha((c.CONTEXT / 'install.py').read_bytes()), 'test_contract_sha256': fixture.bundle['manifest']['test_contract_sha256'],
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    atomic_json(fixture.run.file('evidence/candidate-binding.json'), value)
    atomic_json(fixture.run.file('evidence/candidate-build.json'), {**common(fixture.run.manifest()), 'status': 'built',
        'builder_id': BUILDER, 'image_id': DERIVED, 'unknown_outcome': False, 'candidate_sha256': value['candidate_sha256']})
    return c.validate_binding(fixture.run)


def observed(binding):
    manifest = binding['manifest']
    return {'schema_version': '1.0', 'os': {'id': 'ubuntu', 'version_id': '24.04'},
        'candidate_sha256': binding['candidate_sha256'], 'source_sha256': manifest['source_sha256'],
        'payload_sha256': next(item['sha256'] for item in manifest['files'] if item['path'] == 'payload.py'),
        'version': c.VERSION, 'configuration': c.CONFIG,
        'function': {'status': 'observed', 'value': {'version': c.VERSION, 'message': c.CONFIG['greeting'], 'source_sha256': manifest['source_sha256']}}}


class CandidateValidation(CandidateFixture, unittest.TestCase):
    def setUp(self):
        super().setUp(); self.binding = binding_for(self)
        self.lease = SimpleNamespace(_reconciliation_only=False)
        self.ps = SimpleNamespace(run=self.run, lease=self.lease, target_binding=self.binding, target_image_id=DERIVED,
            receipt={'primary_failure': None}, held=Mock(), target_inventory=Mock(return_value={
                'resource_id': TARGET, 'host': '172.31.77.2', 'image_digest': DERIVED}))
        def failure(error):
            if self.ps.receipt['primary_failure'] is None:
                self.ps.receipt['primary_failure'] = {'code': error.code, 'recorded_at': datetime.now(timezone.utc).isoformat()}
        self.ps.failure = failure
        self.ready = SimpleNamespace(run=self.run, lease=self.lease, provisioning=self.ps, scenario='healthy',
            target=TARGET, network=NETWORK, helper=HELPER, validation_enabled=True, validation_source_sha256=v.runtime_hash(),
            held=Mock(), require_ready=Mock(), verify_helper=Mock(), save=Mock(), trust_address='172.31.77.2',
            last_started_at=datetime.now(timezone.utc).isoformat(), receipt={'unknown_outcome': False})
        atomic_json(self.run.file('evidence/provisioning.json'), {**common(self.run.manifest()), 'target_binding': self.binding,
            'target_image': DERIVED, 'resources': [{'address': 'docker_container.target["target-001"]', 'id': TARGET},
                                                {'address': 'docker_network.run', 'id': NETWORK}]})
        item = patch.object(cv, 'source_identity', return_value=(SHA, False)); item.start(); self.addCleanup(item.stop)
        item = patch.object(images, 'docker_configuration', return_value='/synthetic-empty-docker-config'); item.start(); self.addCleanup(item.stop)
        item = patch.object(images, 'inspect', return_value={'State': {'StartedAt': datetime.now(timezone.utc).isoformat()}}); item.start(); self.addCleanup(item.stop)

    def response(self, argv, **options):
        import base64
        request = runtime.decode(base64.b64decode(argv[-1]))
        self.assertEqual(request['operation'], 'candidate-functional-v1'); self.assertIn(v.VALIDATION_MOUNT, argv)
        self.assertNotIn('private/credentials', ' '.join(argv))
        value = {**{key: request[key] for key in ('schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256')},
            'status': 'pass', 'category': None, 'returncode': 0, 'timed_out': False, 'truncated': False,
            'duration_seconds': .01, 'observation': observed(self.binding), 'private_diagnostic': ''}
        return {'status': 'pass', 'returncode': 0, 'duration_seconds': .02, 'log_truncated': False, 'log': c.canonical(value)}

    def test_capture_backed_candidate_checks_and_report_agree(self):
        session = cv.CandidateValidationSession(self.ready, self.binding)
        with patch.object(v, '_run_process', side_effect=self.response): result = session.validate()
        self.assertEqual(result['status'], 'passed'); self.assertEqual(len(result['checks']), len(c.CHECKS))
        self.assertTrue(all(item['status'] == 'pass' for item in result['checks']))
        report = cv.report_candidate_validation(self.run)
        self.assertEqual(report['result'], result); self.assertIn('ISO processing: none', report['text'])
        self.assertIsNone(self.ps.receipt['primary_failure'])
        changed = read_json(self.run.file('evidence/candidate-validation.json')); changed['checks'].pop()
        atomic_json(self.run.file('evidence/candidate-validation.json'), changed)
        with self.assertRaises(Exception): cv.report_candidate_validation(self.run)

    def test_payload_version_mismatch_fails_criterion_and_overall_without_hiding_actual_observations(self):
        session = cv.CandidateValidationSession(self.ready, self.binding, scenario='version-expectation-mismatch')
        with patch.object(v, '_run_process', side_effect=self.response), self.assertRaises(c.CandidateError) as error: session.validate()
        self.assertEqual(error.exception.code, 'candidate_required_check_mismatch')
        result = cv.report_candidate_validation(self.run)['result']
        failed = [item['check_id'] for item in result['checks'] if item['status'] != 'pass']
        self.assertEqual(failed, ['candidate-version']); self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.ps.receipt['primary_failure']['code'], error.exception.code)
        self.assertFalse(self.ready.receipt['unknown_outcome'])

    def test_wrong_candidate_wrong_image_or_changed_capture_refuses(self):
        wrong = deepcopy(self.binding); wrong['candidate_sha256'] = '0' * 64
        with self.assertRaises(c.CandidateError): cv.CandidateValidationSession(self.ready, wrong)
        self.ps.target_image_id = p.TARGET_IMAGE
        with self.assertRaises(c.CandidateError): cv.CandidateValidationSession(self.ready, self.binding)
        self.ps.target_image_id = DERIVED
        session = cv.CandidateValidationSession(self.ready, self.binding)
        with patch.object(v, '_run_process', side_effect=self.response): session.validate()
        self.run.file(cv.LOG).write_bytes(b'changed captured response')
        with self.assertRaises(c.CandidateError): cv.report_candidate_validation(self.run)

    def test_outer_exec_timeout_remains_unknown_and_preserves_primary(self):
        session = cv.CandidateValidationSession(self.ready, self.binding)
        failed = {'status': 'timeout', 'returncode': -9, 'duration_seconds': .02, 'log_truncated': False, 'log': b''}
        with patch.object(v, '_run_process', return_value=failed), self.assertRaises(c.CandidateError): session.validate()
        self.assertTrue(session.receipt['unknown_outcome']); self.assertTrue(self.ready.receipt['unknown_outcome'])
        self.assertEqual(cv.report_candidate_validation(self.run)['result']['status'], 'failed')

    def test_actual_authored_collector_observes_only_fixed_reference_files(self):
        # Execute original authored code with its two fixed absolute roots replaced
        # by this labeled local filesystem fixture; no target, SSH or downloaded code.
        release = self.root / 'os-release'; release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        program = runtime.CANDIDATE_PROGRAM.replace("Path('/opt/wormhole/reference')", 'Path(' + repr(str(self.bundle['directory'])) + ')')
        program = program.replace("Path('/usr/lib/os-release')", 'Path(' + repr(str(release)) + ')')
        expected = next(item['sha256'] for item in self.binding['manifest']['files'] if item['path'] == 'payload.py')
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program, expected], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(runtime.candidate_observation(json.loads(result.stdout)), observed(self.binding))
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program, '0' * 64], capture_output=True, timeout=3)
        unverified = json.loads(result.stdout)
        self.assertEqual(unverified['function'], {'status': 'unverified', 'value': None})
        plan = cv.make_plan(self.run, self.binding, TARGET, NETWORK, 'healthy')
        self.assertEqual(next(item['status'] for item in cv.rows(plan, unverified) if item['check_id'] == 'candidate-function'), 'unverified')

    def test_typed_common_and_bounded_attempt_metadata_cannot_be_rewritten(self):
        session = cv.CandidateValidationSession(self.ready, self.binding)
        with patch.object(v, '_run_process', side_effect=self.response): session.validate()
        original = read_json(self.run.file('evidence/candidate-validation.json'))
        for mutate in (lambda x: x.update(source_dirty=0), lambda x: x['attempts'][0].update(stage='different-execution'),
            lambda x: x['attempts'][0].update(duration_seconds=True), lambda x: x['attempts'][0].update(private_log='private/credentials/key')):
            value = deepcopy(original); mutate(value)
            atomic_json(self.run.file('evidence/candidate-validation.json'), value)
            with self.assertRaises(Exception): cv.report_candidate_validation(self.run)


if __name__ == '__main__': unittest.main()
