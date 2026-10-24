"""Synthetic native records only; no package tools, network or target execution."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from wormhole import observed_svd as s
from wormhole.contracts import ContractError, validate_artifact


def fixture(family='dpkg'):
    files = [{'path': name, 'bytes': index + 1, 'sha256': str(index + 1) * 64} for index, name in enumerate(s.FILES)]
    content = hashlib.sha256(s.canonical({'files': [{'path': f['path'], 'size': f['bytes'], 'sha256': f['sha256']} for f in files]})).hexdigest()
    packages = ([{'name': 'libexample', 'version': '1:2.3-0ubuntu1.2', 'architecture': 'amd64'},
                 {'name': 'libexample', 'version': '1:2.3-0ubuntu1.2', 'architecture': 'i386'}] if family == 'dpkg' else
                [{'name': 'example', 'epoch': 2, 'version': '4.9', 'release': '16.el9', 'arch': 'x86_64'},
                 {'name': 'example', 'epoch': 2, 'version': '4.10', 'release': '1.el9', 'arch': 'x86_64'}])
    if family == 'rpm': packages.sort(key=lambda p: (p['name'], p['epoch'], p['version'], p['release'], p['arch']))
    observation = {'schema_version': '1.0', 'os': {'id': 'ubuntu' if family == 'dpkg' else 'rhel',
        'version_id': '24.04' if family == 'dpkg' else '9.8', 'name': 'Synthetic userland', 'architecture': 'x86_64'},
        'package_manager': family, 'packages': packages, 'rpm_key_headers': [] if family == 'dpkg' else
        [{'name': 'gpg-pubkey', 'epoch': 0, 'version': 'fd431d51', 'release': '4ae0493b', 'arch': None}],
        'payload': {'version': '1.0.0-reference', 'sha256': files[1]['sha256'], 'manifest_sha256': 'a' * 64,
            'content_sha256': content, 'source_sha256': files[0]['sha256'], 'files': files},
        'shared_kernel': {'scope': 'host-shared', 'release': 'synthetic-host-kernel'}}
    raw = s.canonical(observation)
    return {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc',
        'source_revision': 'b' * 40, 'source_dirty': False, 'mode': 'container-reference',
        'operation': 'observed-software-description-v1', 'status': 'passed', 'plan_sha256': 'c' * 64,
        'collector': {'version': '1.0', 'sha256': 'd' * 64, 'helper_source_sha256': 'e' * 64, 'readiness_source_sha256': 'f' * 64},
        'target': {'target_id': 'target-001', 'resource_id': '1' * 64, 'image_digest': 'sha256:' + '2' * 64,
            'candidate_sha256': 'a' * 64, 'source_candidate_sha256': '3' * 64, 'content_sha256': content},
        'observation': observation, 'execution_provenance': {
            'helper': {'image_digest': 'sha256:' + '4' * 64, 'python_version': '3.12.3', 'ansible_core_version': '2.21.5'},
            'provisioner': {'image_digest': 'sha256:' + '5' * 64, 'terraform_version': '1.17.0', 'provider_version': '4.6.0'}},
        'checks': [{'check_id': key, 'target_id': 'target-001', 'required': True, 'expected': 'synthetic-observed',
            'observed': 'synthetic-observed', 'status': 'pass', 'evidence': ['evidence/software-inventory.json']} for key in s.CORE_CHECKS],
        'capture': {'path': s.LOG, 'sha256': '6' * 64, 'size_bytes': len(raw) + 100, 'budget_seconds': 10., 'complete': True,
            'collector_sha256': hashlib.sha256(raw).hexdigest(), 'collector_bytes': len(raw)},
        'primary_failure': None, 'unknown_outcome': False, 'updated_at': '2026-10-23T19:00:00.000Z',
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}


def rebind_capture(record):
    raw = s.canonical(record['observation'])
    record['capture'].update(collector_sha256=hashlib.sha256(raw).hexdigest(), collector_bytes=len(raw), size_bytes=len(raw) + 100)


class ObservedSVD(unittest.TestCase):
    def test_same_frozen_records_generate_json_and_complete_text_without_mutation(self):
        for family in ('dpkg', 'rpm'):
            with self.subTest(family=family):
                record = fixture(family); before = deepcopy(record)
                parsed = json.loads(s.render_json(record)); text = s.render_text(record)
                self.assertEqual(parsed, record)
                self.assertEqual(s.render_json(record), s.canonical(record) + b'\n')
                for row in record['checks']:
                    self.assertIn(row['check_id'] + ': pass', text)
                for field in ('run_id', 'source_revision', 'plan_sha256'):
                    self.assertIn(record[field], text)
                self.assertEqual(record, before)
                copy = s.validate_record(record); copy['checks'][0]['status'] = 'fail'
                self.assertEqual(record, before)

    def test_full_dpkg_epoch_revision_and_multiarch_are_preserved(self):
        value = fixture(); text = s.render_text(value)
        self.assertEqual(text.count('version=1:2.3-0ubuntu1.2'), 2)
        self.assertIn('architecture=amd64', text); self.assertIn('architecture=i386', text)
        self.assertEqual(json.loads(s.render_json(value))['observation']['packages'], value['observation']['packages'])

    def test_full_rpm_nevra_parallel_versions_and_key_null_arch_are_preserved(self):
        value = fixture('rpm'); text = s.render_text(value)
        self.assertEqual(text.count('epoch=2'), 2)
        self.assertIn('release=16.el9', text); self.assertIn('version=4.10', text)
        self.assertIn('arch=null (reported absent)', text)
        self.assertIn('Installed target packages: 2', text)
        self.assertIn('RPM virtual key headers (not application packages): 1', text)

    def test_helper_tools_and_shared_kernel_are_separate_from_packages(self):
        text = s.render_text(fixture())
        package_section = text.split('Installed target packages:', 1)[1].split('RPM virtual key headers', 1)[0]
        self.assertNotIn('2.21.5', package_section); self.assertNotIn('1.17.0', package_section)
        self.assertIn('Execution provenance (separate from installed target packages)', text)
        self.assertIn('Shared host kernel release (not target package inventory)', text)
        self.assertIn('No VM installation', text)

    def test_failed_collector_renders_unverified_not_empty_success(self):
        value = fixture(); value.update(status='failed', observation=None, target=None, execution_provenance=None, capture=None,
            primary_failure={'code': 'configured_interpreter_unavailable', 'recorded_at': value['updated_at']})
        for row in value['checks']: row.update(status='unverified', observed='not observed')
        value['checks'][0]['status'] = 'error'
        text = s.render_text(value)
        self.assertIn('Target identity: unverified', text)
        self.assertIn('Target software: unverified; no complete observation.', text)
        self.assertNotIn('Installed target packages: 0', text)
        self.assertEqual(json.loads(s.render_json(value))['observation'], None)
        value['checks'][1]['status'] = 'pass'
        with self.assertRaises(s.ObservedSVDError): s.validate_record(value)

    def test_known_target_identity_failure_preserves_actual_observation_and_failed_row(self):
        value = fixture(); value['status'] = 'failed'; value['primary_failure'] = {'code': 'svd_target_identity_mismatch', 'recorded_at': value['updated_at']}
        value['checks'][0].update(status='fail', expected='wrong expectation', observed='actual resource')
        self.assertIn('target-identity: fail', s.render_text(value))
        self.assertEqual(s.validate_record(value)['target']['resource_id'], '1' * 64)

    def test_missing_duplicate_foreign_and_out_of_order_checks_refuse(self):
        for change in ('missing', 'duplicate', 'foreign', 'order', 'extra'):
            with self.subTest(change=change):
                value = fixture()
                if change == 'missing': value['checks'].pop()
                elif change == 'duplicate': value['checks'][-1] = deepcopy(value['checks'][0])
                elif change == 'foreign': value['checks'][0]['target_id'] = 'target-002'
                elif change == 'order': value['checks'][0], value['checks'][1] = value['checks'][1], value['checks'][0]
                else: value['checks'].append({**value['checks'][0], 'check_id': 'unknown-component'})
                with self.assertRaises(s.ObservedSVDError): s.validate_record(value)

    def test_boolean_numeric_aliases_are_rejected(self):
        paths = [('source_dirty',), ('unknown_outcome',), ('capture', 'collector_bytes'), ('capture', 'size_bytes'),
            ('capture', 'budget_seconds'), ('observation', 'packages', 0, 'epoch'), ('observation', 'payload', 'files', 0, 'bytes')]
        for path in paths:
            with self.subTest(path=path):
                value = fixture('rpm'); node = value
                for part in path[:-1]: node = node[part]
                node[path[-1]] = 0 if path[-1] in ('source_dirty', 'unknown_outcome') else True
                with self.assertRaises(s.ObservedSVDError): s.validate_record(value)

    def test_capture_candidate_content_and_file_identity_tampering_refuse(self):
        changes = [('capture', 'collector_sha256'), ('target', 'candidate_sha256'), ('target', 'content_sha256'),
            ('observation', 'payload', 'sha256'), ('observation', 'payload', 'source_sha256')]
        for path in changes:
            value = fixture(); node = value
            for part in path[:-1]: node = node[part]
            node[path[-1]] = '0' * 64
            with self.subTest(path=path), self.assertRaises(s.ObservedSVDError): s.validate_record(value)
        value = fixture(); value['observation']['payload']['files'].reverse(); rebind_capture(value)
        with self.assertRaises(s.ObservedSVDError): s.validate_record(value)

    def test_native_rows_require_canonical_order_uniqueness_and_no_key_as_package(self):
        for family in ('dpkg', 'rpm'):
            for change in ('order', 'duplicate'):
                value = fixture(family)
                if change == 'order': value['observation']['packages'].reverse()
                else: value['observation']['packages'].append(deepcopy(value['observation']['packages'][0]))
                rebind_capture(value)
                with self.subTest(family=family, change=change), self.assertRaises(s.ObservedSVDError): s.validate_record(value)
        value = fixture('rpm'); value['observation']['packages'][0]['name'] = 'gpg-pubkey'; rebind_capture(value)
        with self.assertRaises(s.ObservedSVDError): s.validate_record(value)

    def test_required_nonpass_unknown_primary_and_incomplete_capture_cannot_pass(self):
        for change in ('fail', 'error', 'unverified', 'unknown', 'primary', 'capture', 'empty-capture'):
            value = fixture()
            if change in ('fail', 'error', 'unverified'): value['checks'][1]['status'] = change
            elif change == 'unknown': value['unknown_outcome'] = True
            elif change == 'primary': value['primary_failure'] = {'code': 'svd_error', 'recorded_at': value['updated_at']}
            elif change == 'empty-capture': value['capture']['size_bytes'] = 0
            else: value['capture']['complete'] = False
            with self.subTest(change=change), self.assertRaises(s.ObservedSVDError): s.validate_record(value)
        value = fixture(); value['checks'][0]['observed'] = 'different'
        with self.assertRaises(s.ObservedSVDError): s.validate_record(value)

    def test_bounds_control_text_paths_unknown_fields_and_nonfinite_values_refuse(self):
        changes = [('observation', 'os', 'name', 'line\nspoof'), ('checks', 0, 'expected', 'tab\tspoof'),
            ('capture', 'budget_seconds', float('nan')), ('checks', 0, 'evidence', ['../private/key']),
            ('observation', 'packages', 0, 'name', 'x' * 241)]
        for change in changes:
            value = fixture(); node = value
            for part in change[:-2]: node = node[part]
            node[change[-2]] = change[-1]
            with self.subTest(change=change), self.assertRaises(s.ObservedSVDError): s.validate_record(value)
        value = fixture(); value['environment'] = {'unexpected': 'not collected'}
        with self.assertRaises(s.ObservedSVDError): s.validate_record(value)
        value = fixture(); value['observation']['packages'] = [{'name': 'package-' + str(i).zfill(4), 'version': 'v' * 200, 'architecture': 'amd64'} for i in range(200)]
        with self.assertRaises(s.ObservedSVDError): s.validate_record(value)

    def test_schema_generated_parity_and_legacy_contract_remains_distinct(self):
        path = Path(__file__).resolve().parents[1] / 'schemas/observed-svd-v1.schema.json'
        self.assertEqual(json.loads(path.read_text()), s.schema())
        with self.assertRaises(ContractError): validate_artifact('svd', fixture())


if __name__ == '__main__': unittest.main()
