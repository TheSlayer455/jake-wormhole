"""Synthetic pure records only; these fixtures establish no publication or privacy."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from wormhole import publication_records as p


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(platform='ubuntu'):
    common = {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc',
        'source_revision': 'a' * 40, 'source_dirty': False, 'mode': 'container-reference'}
    originals = {name: ('Synthetic unexecuted record: ' + name + '\n').encode() for name in p.copied_paths(platform)}
    originals['REFERENCE.txt'] = p.REFERENCE_BYTES
    files = {name: {'sha256': sha(raw), 'size_bytes': len(raw)} for name, raw in sorted(originals.items())}
    if platform == 'ubi':
        # The pure fixture pins metadata only; it does not pretend to own the PDF.
        files[p.EULA_PATH] = {'sha256': p.EULA_SHA256, 'size_bytes': p.EULA_BYTES}
    checksums = {**common, 'operation': p.CHECKSUMS_OPERATION, 'platform': platform, 'files': files}
    candidate = {'manifest_sha256': files['candidate/manifest.json']['sha256'],
        'source_candidate_sha256': files['candidate/manifest.json']['sha256'] if platform == 'ubuntu' else 'b' * 64,
        'source_sha256': files['candidate/source.synthetic.bin']['sha256'], 'image_digest': 'sha256:' + 'c' * 64,
        'content_sha256': p.digest({'files': [{'path': name, 'sha256': files['candidate/' + name]['sha256'],
            'size': files['candidate/' + name]['size_bytes']} for name in p.CANDIDATE_NAMES]})}
    complete = {**common, 'operation': p.COMPLETE_OPERATION, 'artifact_kind': p.ARTIFACT_KIND, 'label': p.LABEL,
        'simulation': True, 'production_eligible': False, 'production_iso_eligible': False,
        'image_published': False, 'remote_release': False, 'synthetic_assessment': True,
        'platform': platform, 'profile': 'smoke', 'release_id': 'reference-' + common['run_id'], 'candidate': candidate,
        'gate': {'plan_sha256': 'd' * 64, 'record_sha256': files['evidence/report.json']['sha256'],
            'decision_sha256': files['evidence/decision.json']['sha256'],
            'final_decision_sha256': files['evidence/decision.json']['sha256'], 'archive_sha256': 'e' * 64},
        'files': files, 'checksums_sha256': sha(p.render_checksums(checksums)),
        'visibility': {'kind': 'private-posix', 'owner_uid': 0, 'owner_gid': 0, 'directory_mode': '0700',
            'file_mode': '0600', 'owner_readable': True, 'unprivileged_denied': True, 'probe_uid': 65534, 'probe_gid': 65534},
        'created_at': '2026-10-24T16:30:00.000Z'}
    return complete, checksums


def receipt(status='completed'):
    complete, _ = fixture()
    result = {**{key: complete[key] for key in p.COMMON_KEYS},
        **{key: complete[key] for key in p.FLAGS}, 'operation': p.RECEIPT_OPERATION,
        'attempt_id': '22345678-1234-4234-9234-123456789abc', 'release_id': complete['release_id'],
        'platform': complete['platform'], 'status': status, 'logical_complete': status == 'completed',
        'durability_acknowledged': status == 'completed', 'completion_sha256': sha(p.render_completion(complete)) if status == 'completed' else None,
        'error_code': 'publication_refused' if status in ('failed', 'refused') else None,
        'created_at': complete['created_at'], 'updated_at': '2026-10-24T16:30:01.000Z'}
    return result


class PublicationRecords(unittest.TestCase):
    def test_published_schemas_match_exact_definitions(self):
        root = Path(__file__).resolve().parents[1] / 'schemas'
        for name, definition in (('publication-complete-v1.schema.json', p.schema()),
                                 ('publication-checksums-v1.schema.json', p.checksums_schema()),
                                 ('publication-receipt-v1.schema.json', p.receipt_schema())):
            with self.subTest(name=name):
                self.assertEqual(json.loads((root / name).read_bytes()), definition)

    def test_exact_paths_and_original_dependency_pins_are_not_a_recursive_export(self):
        from wormhole import candidate, pipeline_records, rpm_source
        self.assertEqual(p.CANDIDATE_NAMES, candidate.NAMES)
        self.assertEqual(p.EVIDENCE_PATHS, pipeline_records.EXPORT_PATHS)
        self.assertEqual((p.EULA_BYTES, p.EULA_SHA256), (rpm_source.EULA_BYTES, rpm_source.EULA_SHA256))
        self.assertEqual(len(p.copied_paths('ubuntu')), 21)
        self.assertEqual(len(p.copied_paths('ubi')), 22)
        for platform, count in (('ubuntu', 24), ('ubi', 25)):
            self.assertEqual(len(p.publication_paths(platform)), count)
            self.assertEqual(len(set(p.publication_paths(platform))), count)
            self.assertNotIn('checksums.json', p.artifact_paths(platform))
            self.assertNotIn('COMPLETE.json', p.artifact_paths(platform))
        for platform in ('windows', '', None, True, []):
            with self.subTest(platform=platform), self.assertRaises(p.PublicationRecordError):
                p.copied_paths(platform)

    def test_both_platforms_validate_and_render_deterministically_without_mutating_input(self):
        for platform in ('ubuntu', 'ubi'):
            value, checksums = fixture(platform); before = deepcopy((value, checksums))
            self.assertEqual(p.validate_completion(value), value)
            validated = p.validate_completion(value, checksums)
            self.assertEqual(json.loads(p.render_completion(value, checksums)), value)
            self.assertEqual(p.render_completion(value, checksums), p.canonical(value) + b'\n')
            self.assertEqual(sha(p.render_checksums(checksums)), value['checksums_sha256'])
            validated['candidate']['source_sha256'] = 'f' * 64
            copied = p.validate_checksums(checksums); copied['files']['REFERENCE.txt']['size_bytes'] = 1
            self.assertEqual((value, checksums), before)

    def test_reference_only_flags_are_required_exactly_typed_and_cannot_claim_other_publication(self):
        mutations = {'production_eligible': True, 'production_iso_eligible': True, 'image_published': True,
            'remote_release': True, 'simulation': False, 'synthetic_assessment': False, 'source_dirty': True,
            'mode': 'fixture', 'profile': 'five-targets', 'artifact_kind': 'container-image', 'label': 'Production artifact'}
        for field, value in mutations.items():
            complete, _ = fixture(); complete[field] = value
            with self.subTest(field=field), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(complete)
        for field in ('source_dirty', 'production_eligible', 'simulation'):
            complete, _ = fixture(); complete[field] = int(complete[field])
            with self.subTest(integer_boolean=field), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(complete)

    def test_candidate_and_two_gate_decisions_must_bind_copied_hashes(self):
        for section, fields in (('candidate', ('manifest_sha256', 'source_candidate_sha256', 'content_sha256', 'source_sha256')),
                                ('gate', ('record_sha256', 'decision_sha256', 'final_decision_sha256'))):
            for field in fields:
                complete, _ = fixture(); complete[section][field] = 'f' * 64
                with self.subTest(section=section, field=field), self.assertRaises(p.PublicationRecordError):
                    p.validate_completion(complete)
        complete, _ = fixture(); complete['candidate']['image_digest'] = 'sha256:not-an-image'
        with self.assertRaises(p.PublicationRecordError):
            p.validate_completion(complete)

    def test_wrong_run_source_platform_or_copied_checksums_never_match_the_completion(self):
        for field, wrong in (('run_id', '22345678-1234-4234-9234-123456789abc'), ('source_revision', 'b' * 40), ('platform', 'ubi')):
            complete, checksums = fixture(); checksums[field] = wrong
            with self.subTest(field=field), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(complete, checksums)
        complete, _ = fixture(); complete['checksums_sha256'] = 'f' * 64
        with self.assertRaises(p.PublicationRecordError):
            p.validate_completion(complete)
        complete, checksums = fixture(); checksums['files']['candidate/payload.py']['sha256'] = 'f' * 64
        with self.assertRaises(p.PublicationRecordError):
            p.validate_completion(complete, checksums)

    def test_missing_extra_duplicate_alias_or_private_paths_are_refused(self):
        for path in ('../private/id_ed25519', 'candidate/../manifest.json', 'candidate\\payload.py',
                     '/tmp/file', 'https://example.invalid/file', 'COMPLETE.json', 'checksums.json', 'private/state.json'):
            complete, _ = fixture(); complete['files'][path] = {'sha256': 'f' * 64, 'size_bytes': 1}
            with self.subTest(path=path), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(complete)
        for path in p.artifact_paths('ubuntu'):
            complete, _ = fixture(); del complete['files'][path]
            with self.subTest(missing=path), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(complete)

    def test_platform_license_and_reference_label_bytes_have_fixed_hashes_and_sizes(self):
        for path, platform in (('REFERENCE.txt', 'ubuntu'), (p.EULA_PATH, 'ubi')):
            for field, wrong in (('sha256', 'f' * 64), ('size_bytes', 1)):
                complete, _ = fixture(platform); complete['files'][path][field] = wrong
                with self.subTest(path=path, field=field), self.assertRaises(p.PublicationRecordError):
                    p.validate_completion(complete)
        complete, _ = fixture('ubuntu'); complete['files'][p.EULA_PATH] = {'sha256': p.EULA_SHA256, 'size_bytes': p.EULA_BYTES}
        with self.assertRaises(p.PublicationRecordError):
            p.validate_completion(complete)

    def test_existing_candidate_and_evidence_byte_bounds_are_not_relaxed(self):
        for path, size, code in (('candidate/source.synthetic.bin', 8 * 1024 * 1024 + 1, 'publication_candidate_bound'),
                                 ('candidate/manifest.json', 16385, 'publication_candidate_bound'),
                                 ('evidence/report.json', 1024 * 1024 + 1, 'publication_evidence_bound')):
            complete, _ = fixture(); complete['files'][path]['size_bytes'] = size
            with self.subTest(path=path), self.assertRaises(p.PublicationRecordError) as failure:
                p.validate_completion(complete)
            self.assertEqual(failure.exception.code, code)
        for value in (True, -1, 0, 1.5):
            complete, _ = fixture(); complete['files']['candidate/payload.py']['size_bytes'] = value
            with self.subTest(size=value), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(complete)

    def test_privacy_requires_different_identity_and_exact_private_modes_not_a_durability_claim(self):
        for field, wrong in (('probe_uid', 0), ('owner_uid', 65534), ('directory_mode', '0755'), ('file_mode', '0644'),
                             ('unprivileged_denied', False), ('owner_readable', False), ('probe_gid', True)):
            complete, _ = fixture(); complete['visibility'][field] = wrong
            with self.subTest(field=field), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(complete)
        complete, _ = fixture(); complete['durability_acknowledged'] = True
        with self.assertRaises(p.PublicationRecordError):
            p.validate_completion(complete)

    def test_completed_receipt_requires_all_producer_acknowledgements(self):
        good = receipt(); before = deepcopy(good)
        self.assertEqual(json.loads(p.render_receipt(good)), good)
        self.assertEqual(p.validate_receipt(good), good)
        for field, wrong in (('logical_complete', False), ('durability_acknowledged', False), ('completion_sha256', None),
                             ('error_code', 'publication_io_error'), ('platform', None), ('status', 'passed')):
            value = deepcopy(good); value[field] = wrong
            with self.subTest(field=field), self.assertRaises(p.PublicationRecordError):
                p.validate_receipt(value)
        self.assertEqual(good, before)

    def test_interrupted_failed_refused_and_completed_before_ack_outcomes_stay_distinct(self):
        for status in ('running', 'failed', 'refused'):
            value = receipt(status); value['platform'] = None
            self.assertEqual(p.validate_receipt(value), value)
        value = receipt('failed'); value.update(logical_complete=True, completion_sha256='f' * 64)
        self.assertEqual(p.validate_receipt(value), value)
        for field, wrong in (('durability_acknowledged', True), ('completion_sha256', None), ('error_code', None), ('platform', None)):
            changed = deepcopy(value); changed[field] = wrong
            with self.subTest(field=field), self.assertRaises(p.PublicationRecordError):
                p.validate_receipt(changed)
        for status in ('running', 'refused'):
            changed = receipt(status); changed.update(logical_complete=True, completion_sha256='f' * 64)
            with self.subTest(status=status), self.assertRaises(p.PublicationRecordError):
                p.validate_receipt(changed)

    def test_release_identity_timestamp_unknown_fields_and_malformed_values_refuse_safely(self):
        for field, wrong in (('release_id', 'reference-22345678-1234-4234-9234-123456789abc'),
                             ('updated_at', '2026-10-24T16:29:59.000Z'), ('created_at', '2026-02-30T00:00:00Z'),
                             ('attempt_id', 'not-a-uuid'), ('error_code', 'untrusted; raw sensitive text')):
            value = receipt('failed'); value[field] = wrong
            with self.subTest(field=field), self.assertRaises(p.PublicationRecordError) as failure:
                p.validate_receipt(value)
            self.assertNotIn(str(wrong), str(failure.exception))
        for value in ([], None, {'private_path': '/untrusted/raw/value'}, {'platform': []}):
            with self.subTest(value=value), self.assertRaises(p.PublicationRecordError):
                p.validate_completion(value)
        complete, _ = fixture(); complete['visibility']['secret'] = 'untrusted-private-value'
        with self.assertRaises(p.PublicationRecordError) as failure:
            p.validate_completion(complete)
        self.assertNotIn('untrusted-private-value', str(failure.exception))
        recursive = {}; recursive['platform'] = 'ubuntu'; recursive['cycle'] = recursive
        with self.assertRaises(p.PublicationRecordError):
            p.validate_completion(recursive)

    def test_validation_and_rendering_do_not_read_execute_or_contact_anything(self):
        complete, checksums = fixture('ubi'); value = receipt()
        with patch('builtins.open', side_effect=AssertionError('Unexpected file read')), \
             patch('os.open', side_effect=AssertionError('Unexpected file descriptor')), \
             patch('subprocess.Popen', side_effect=AssertionError('Unexpected process')), \
             patch('socket.socket', side_effect=AssertionError('Unexpected socket')):
            self.assertEqual(p.validate_completion(complete, checksums), complete)
            self.assertEqual(json.loads(p.render_checksums(checksums)), checksums)
            self.assertEqual(json.loads(p.render_receipt(value)), value)


if __name__ == '__main__':
    unittest.main()
