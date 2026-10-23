"""Disposable real-flock/zero-resource recovery fixtures; every Docker call mocked."""
from copy import deepcopy
import os
import unittest
from unittest.mock import patch

from wormhole import admission as a, candidate as c, candidate_recovery as r, images
from wormhole.runs import atomic_json, common, now, read_json, create_run
from test_admission import observed
from test_candidate import CandidateFixture, SHA, BUILDER, DERIVED


@unittest.skipUnless(os.name == 'posix', 'Linux private-file/flock recovery; no Docker operations')
class EmptyRecovery(CandidateFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.infrastructure = self.root / 'infrastructure'
        for module, name, value in ((images, 'RUNS_ROOT', self.run.workspace), (images, 'INFRASTRUCTURE', self.infrastructure),
            (a, 'CANONICAL_INFRASTRUCTURE_ROOT', self.infrastructure)):
            item = patch.object(module, name, value); item.start(); self.addCleanup(item.stop)
        item = patch.object(r, 'source_identity', return_value=(SHA, False)); item.start(); self.addCleanup(item.stop)
        observations = observed(); observations['synthetic'] = False  # Measured-shape fixture, never actual Docker authority.
        with a.AdmissionLease(self.infrastructure, self.run.id, SHA, collector=lambda _: observations): pass
        self.built = {**common(self.run.manifest()), 'operation': 'candidate-image-build', 'status': 'failed',
            'candidate_sha256': self.bundle['candidate_sha256'], 'builder_id': None, 'image_id': None,
            'unknown_outcome': False, 'primary_failure': {'code': 'candidate_base_invalid', 'recorded_at': now()},
            'daemon_materialization_cgroup_capped': False, 'runtime_pipeline_complete': False,
            'production_iso_eligible': False, 'updated_at': now()}
        atomic_json(self.run.file('evidence/candidate-build.json'), self.built)

    def test_public_exact_source_resume_finishes_empty_phase_idempotently_preserving_failure(self):
        before = self.run.file('evidence/candidate-build.json').read_bytes()
        with patch.object(images, 'docker', return_value={'log': b'', 'log_truncated': False}) as docker:
            first = r.recover_preallocation(self.run); second = r.recover_preallocation(self.run)
        self.assertEqual(first['status'], 'completed'); self.assertEqual(second['status'], 'completed')
        self.assertEqual(first['primary_failure'], self.built['primary_failure'])
        self.assertNotEqual(first['attempt_id'], second['attempt_id'])
        self.assertEqual(before, self.run.file('evidence/candidate-build.json').read_bytes())
        self.assertEqual(read_json(self.infrastructure / 'admission.json')['state'], 'finished')
        self.assertEqual(read_json(self.infrastructure / 'admission.json'), read_json(self.infrastructure / 'history' / (self.run.id + '.json')))
        self.assertEqual(docker.call_count, 8)
        commands = [call.args[0] for call in docker.call_args_list]
        self.assertTrue(all(command[:2] in {('ps', '-a'), ('network', 'ls'), ('image', 'ls'), ('volume', 'ls')} for command in commands))
        self.assertIn(('image', 'ls', '--all', '--no-trunc'), [command[:4] for command in commands])

    def test_unknown_ids_changed_authority_fields_or_nonempty_state_refuse_before_docker(self):
        for field, value in (('unknown_outcome', True), ('builder_id', BUILDER), ('image_id', DERIVED),
            ('source_dirty', 0), ('status', 'built'), ('primary_failure', None), ('operation', 'other')):
            changed = deepcopy(self.built); changed[field] = value
            atomic_json(self.run.file('evidence/candidate-build.json'), changed)
            with patch.object(images, 'docker') as docker, self.assertRaises(Exception): r.recover_preallocation(self.run)
            docker.assert_not_called()
        atomic_json(self.run.file('evidence/candidate-build.json'), self.built)
        atomic_json(self.run.file('private/terraform/controller.json'), {'synthetic_fixture': True})
        with patch.object(images, 'docker') as docker, self.assertRaises(c.CandidateError): r.recover_preallocation(self.run)
        docker.assert_not_called()

    def test_any_actual_owned_resource_or_incomplete_sweep_refuses_without_finishing(self):
        for kind in ('ps', 'network', 'image', 'volume', 'truncated'):
            def result(args):
                present = args[0] == kind
                return {'log': (BUILDER + '\n').encode() if present else b'', 'log_truncated': kind == 'truncated'}
            with self.subTest(kind=kind), patch.object(images, 'docker', side_effect=result), self.assertRaises(c.CandidateError):
                r.recover_preallocation(self.run)
            self.assertEqual(read_json(self.infrastructure / 'admission.json')['state'], 'active')
            self.assertFalse((self.infrastructure / 'history' / (self.run.id + '.json')).exists())

    def test_archive_first_interruption_can_retry_without_journal_edit_or_failure_loss(self):
        original = a._sync_json
        def fail_current(path, value):
            if path.name == 'admission.json' and value['state'] == 'finished': raise OSError('Synthetic interrupted final write')
            original(path, value)
        with patch.object(images, 'docker', return_value={'log': b'', 'log_truncated': False}), patch.object(a, '_sync_json', side_effect=fail_current), self.assertRaises(OSError):
            r.recover_preallocation(self.run)
        self.assertEqual(read_json(self.infrastructure / 'admission.json')['state'], 'active')
        self.assertTrue((self.infrastructure / 'history' / (self.run.id + '.json')).exists())
        with patch.object(images, 'docker', return_value={'log': b'', 'log_truncated': False}): result = r.recover_preallocation(self.run)
        self.assertEqual(result['status'], 'completed'); self.assertEqual(result['primary_failure'], self.built['primary_failure'])

    def test_wrong_workspace_source_or_live_locks_cannot_recover_or_create_config(self):
        foreign = create_run(self.root / 'foreign', fixture=False, identity=(SHA, False))
        with patch.object(images, 'docker') as docker, self.assertRaises(c.CandidateError): r.recover_preallocation(foreign)
        docker.assert_not_called(); self.assertFalse(foreign.file('private/docker-config').exists())
        with patch.object(r, 'source_identity', return_value=('b' * 40, False)), patch.object(images, 'docker') as docker, self.assertRaises(c.CandidateError):
            r.recover_preallocation(self.run)
        docker.assert_not_called()
        with self.run.locked(), patch.object(images, 'docker') as docker, self.assertRaises(Exception): r.recover_preallocation(self.run)
        docker.assert_not_called()
        with a.AdmissionLease.resume(self.infrastructure, self.run.id, SHA), patch.object(images, 'docker') as docker, self.assertRaises(a.AdmissionError):
            r.recover_preallocation(self.run)
        docker.assert_not_called()

    def test_recorded_nonreserved_phase_or_pending_resource_never_becomes_empty_proof(self):
        original = read_json(self.infrastructure / 'admission.json')
        for phase, resources in (('assembling', []), ('provisioning', [{'kind': 'container', 'id': BUILDER, 'outcome': 'pending', 'size_bytes': 0}])):
            # Disposable corruption/leftover fixture, never an operator recovery edit.
            changed = deepcopy(original); changed.update(phase=phase, resources=resources)
            atomic_json(self.infrastructure / 'admission.json', changed)
            with patch.object(images, 'docker') as docker, self.assertRaises(c.CandidateError): r.recover_preallocation(self.run)
            docker.assert_not_called()
            self.assertFalse((self.infrastructure / 'history' / (self.run.id + '.json')).exists())


if __name__ == '__main__': unittest.main()
