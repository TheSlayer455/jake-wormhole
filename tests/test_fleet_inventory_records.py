"""Synthetic pure inventory contracts; no SSH, Docker or runtime qualification."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import UUID

from wormhole import fleet_inventory_records as f


def observation():
    versions = {'ca-certificates': '20260816ubuntu0.24.04.1', 'python3': '3.12.3-0ubuntu2.1',
        'python3.12': '3.12.3-1ubuntu0.17', 'openssh-client': '1:9.6p1-3ubuntu13.20',
        'openssh-server': '1:9.6p1-3ubuntu13.20', 'openssh-sftp-server': '1:9.6p1-3ubuntu13.20'}
    packages = [{'name': name, 'version': version, 'architecture': 'all' if name == 'ca-certificates' else 'amd64'}
        for name, version in versions.items()]
    packages.extend({'name': 'libc6:' + arch, 'version': '2:2.39-0ubuntu8.9~synthetic', 'architecture': arch}
        for arch in ('amd64', 'i386'))
    return {'schema_version': '1.0', 'os': {'id': 'ubuntu', 'version_id': '24.04',
        'name': 'Ubuntu 24.04.3 LTS', 'architecture': 'amd64'}, 'package_manager': 'dpkg',
        'packages': sorted(packages, key=lambda package: (package['name'], package['architecture'])),
        'runtime_sha256': 'c' * 64, 'shared_kernel': {'scope': 'host-shared', 'release': '6.8.0-synthetic-shared'}}


def record(target_id='target-001'):
    observed = observation(); raw = f.canonical(observed)
    value = {'schema_version': '1.0', 'run_id': str(UUID(int=1)), 'source_revision': 'a' * 40,
        'source_dirty': False, 'mode': 'container-reference', 'operation': f.OPERATION, 'profile': 'twenty-targets',
        'status': 'passed', 'plan_sha256': 'b' * 64, 'target_id': target_id,
        'target': {'target_id': target_id, 'resource_id': str(f.TARGET_IDS.index(target_id) + 1).zfill(64), 'image_digest': f.STOCK_IMAGE},
        'stock_build': {'run_id': f.STOCK_BUILD_RUN, 'source_revision': f.STOCK_BUILD_SOURCE,
            'recipe_sha256': 'd' * 64, 'runtime_sha256': 'c' * 64},
        'collector': {'version': '1.0', 'sha256': 'e' * 64, 'helper_source_sha256': 'f' * 64, 'readiness_source_sha256': '1' * 64},
        'observation': observed, 'execution_provenance': {
            'helper': {'image_digest': 'sha256:' + '2' * 64, 'python_version': '3.12.3', 'ansible_core_version': '2.21.5'},
            'provisioner': {'image_digest': f.STOCK_IMAGE, 'terraform_version': '1.17.0', 'provider_version': '4.6.0'}},
        'checks': [], 'capture': {'batch_id': f.batch_for(target_id), 'path': f.evidence_for(target_id)[1],
            'sha256': '3' * 64, 'size_bytes': len(raw) + 1000, 'complete': True,
            'collector_sha256': hashlib.sha256(raw).hexdigest(), 'collector_bytes': len(raw)},
        'primary_failure': None, 'unknown_outcome': False, 'updated_at': '2026-10-24T17:00:00.000Z',
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    rows = f.observed_values(value)
    value['checks'] = [{'check_id': check, 'target_id': target_id, 'required': True,
        'expected': rows[check], 'observed': rows[check], 'status': 'pass', 'evidence': f.evidence_for(target_id)} for check in f.CHECK_IDS]
    return value


def rebind(value):
    """Fixture-only complete-packet/hash rebinding; never a domain proof."""
    raw = f.canonical(value['observation'])
    value['capture'].update(collector_sha256=hashlib.sha256(raw).hexdigest(), collector_bytes=len(raw), size_bytes=len(raw) + 1000)
    rows = f.observed_values(value)
    for row in value['checks']:
        row.update(expected=rows[row['check_id']], observed=rows[row['check_id']])


def index():
    value = record()
    keys = ('schema_version', 'run_id', 'source_revision', 'source_dirty', 'mode', 'profile', 'plan_sha256', 'primary_failure',
        'unknown_outcome', 'updated_at', 'runtime_pipeline_complete', 'production_iso_eligible')
    result = {**{key: value[key] for key in keys}, 'operation': f.INDEX_OPERATION,
        'status': 'passed', 'target_count': 20, 'controller_concurrency': 4, 'targets': []}
    for target_id in f.TARGET_IDS:
        target = record(target_id); raw, text = f.render_json(target), f.render_text(target).encode()
        prefix = 'evidence/fleet-inventory/targets/' + target_id + '/svd.'
        result['targets'].append({'target_id': target_id, 'status': 'passed',
            'record': {'path': prefix + 'json', 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)},
            'text': {'path': prefix + 'txt', 'sha256': hashlib.sha256(text).hexdigest(), 'size_bytes': len(text)},
            'checks': [{'check_id': check, 'status': 'pass'} for check in f.CHECK_IDS]})
    return result


class FleetInventoryContracts(unittest.TestCase):
    def rejects(self, value, validator=f.validate_record):
        with self.assertRaises(f.FleetInventoryRecordError) as caught:
            validator(value)
        self.assertNotIn('SYNTHETIC-SENSITIVE', str(caught.exception))

    def test_generated_schemas_match_fixed_definitions(self):
        root = Path(__file__).resolve().parents[1] / 'schemas'
        for name, function in (('fleet-software-inventory-v1.schema.json', f.schema),
                ('fleet-software-observation-v1.schema.json', f.observation_schema),
                ('fleet-software-inventory-index-v1.schema.json', f.index_schema)):
            self.assertEqual(json.loads((root / name).read_bytes()), function())

    def test_json_and_text_preserve_same_complete_native_records_and_provenance_without_io(self):
        value = record(); before = deepcopy(value)
        with patch('builtins.open', side_effect=AssertionError('Pure report cannot read original evidence')):
            validated = f.validate_record(value); raw, text = f.render_json(value), f.render_text(value)
        self.assertEqual(json.loads(raw), value); self.assertEqual(raw, f.canonical(value) + b'\n')
        for package in value['observation']['packages']:
            self.assertIn(package['name'] + ' | version=' + package['version'] + ' | architecture=' + package['architecture'], text)
        self.assertIn('1:9.6p1-3ubuntu13.20', text); self.assertIn('2:2.39-0ubuntu8.9~synthetic', text)
        self.assertIn('Shared host kernel release (separate from target packages)', text)
        self.assertIn('Execution provenance (separate from installed target packages)', text)
        self.assertNotIn('private/', text); self.assertNotIn('candidate_sha256', raw.decode())
        validated['observation']['packages'].clear(); self.assertEqual(value, before)

    def test_package_names_multiarch_full_versions_and_sorted_unique_database(self):
        value = observation(); self.assertEqual(f.validate_observation(value), value)
        for mutation in ('reverse', 'duplicate', 'missing-version', 'control', 'rpm', 'extra'):
            bad = deepcopy(value)
            if mutation == 'reverse':bad['packages'].reverse()
            elif mutation == 'duplicate':bad['packages'].append(deepcopy(bad['packages'][-1]))
            elif mutation == 'missing-version':del bad['packages'][0]['version']
            elif mutation == 'control':bad['packages'][0]['version'] = 'SYNTHETIC-SENSITIVE\n'
            elif mutation == 'rpm':bad['package_manager'] = 'rpm'
            else:bad['packages'][0]['rpm_epoch'] = 1
            with self.subTest(mutation=mutation):self.rejects(bad, f.validate_observation)

    def test_missing_ambiguous_package_wrong_userland_or_runtime_cannot_be_passed_even_with_rebound_rows(self):
        for mutation in ('missing', 'ambiguous', 'os', 'arch', 'runtime'):
            value = record()
            if mutation == 'missing':value['observation']['packages'] = [p for p in value['observation']['packages'] if p['name'] != 'python3']
            elif mutation == 'ambiguous':
                value['observation']['packages'].append({'name': 'python3', 'version': '3.12.3-0ubuntu2.1', 'architecture': 'i386'})
                value['observation']['packages'].sort(key=lambda p: (p['name'], p['architecture']))
            elif mutation == 'os':value['observation']['os']['id'] = 'debian'
            elif mutation == 'arch':value['observation']['os']['architecture'] = 'arm64'
            else:value['observation']['runtime_sha256'] = '4' * 64
            rebind(value)
            with self.subTest(mutation=mutation):self.rejects(value)

    def test_wrong_version_is_an_explicit_failed_check_not_lost_inventory(self):
        value = record(); value['observation']['packages'][-1]['version'] += '-changed'; rebind(value)
        changed = next(row for row in value['checks'] if row['check_id'] == 'package-python3-12')
        changed.update(status='fail', expected='3.12.3-1ubuntu0.17')
        value.update(status='failed', primary_failure={'code': 'stock_package_mismatch', 'recorded_at': value['updated_at']})
        self.assertEqual(f.validate_record(value), value)
        self.assertIn('package-python3-12: fail', f.render_text(value))
        self.assertIn('-changed', f.render_text(value))

    def test_collector_failure_keeps_every_required_row_explicitly_unverified(self):
        value = record(); value.update(status='failed', observation=None,
            primary_failure={'code': 'collector_unavailable', 'recorded_at': value['updated_at']})
        value['capture'].update(complete=False, collector_sha256=None, collector_bytes=0)
        for row in value['checks'][1:]:row.update(status='unverified', observed='')
        self.assertEqual(f.validate_record(value), value)
        text = f.render_text(value); self.assertIn('no complete observation', text)
        self.assertEqual(sum(line.startswith('target-001 / ') and line.endswith(': unverified') for line in text.splitlines()), 9)
        for check in f.CHECK_IDS[1:]:
            bad = deepcopy(value); next(row for row in bad['checks'] if row['check_id'] == check)['status'] = 'pass'
            self.rejects(bad)

    def test_no_target_metadata_means_identity_cannot_pass_and_no_observation_can_exist(self):
        value = record(); value.update(status='failed', target=None, observation=None, capture=None, execution_provenance=None,
            primary_failure={'code': 'target_unverified', 'recorded_at': value['updated_at']})
        for row in value['checks']:row.update(status='unverified', observed='')
        self.assertEqual(f.validate_record(value), value)
        bad = deepcopy(value); bad['checks'][0].update(status='pass', expected=''); self.rejects(bad)
        bad = record(); bad['target'] = None; self.rejects(bad)

    def test_capture_bytes_hash_completeness_and_batch_namespace_are_bound(self):
        for key, wrong in (('collector_sha256', '4' * 64), ('collector_bytes', 1), ('complete', False),
                ('size_bytes', 0), ('size_bytes', True), ('batch_id', 'batch-002'),
                ('path', 'captures/stock-inventory/batch-002'), ('path', 'private/key')):
            value = record(); value['capture'][key] = wrong
            with self.subTest(key=key, wrong=wrong):self.rejects(value)
        value = record(); value['observation']['packages'][0]['version'] += '-changed'; self.rejects(value)

    def test_every_fixed_check_and_observed_summary_matches_the_native_packet(self):
        for mutation in ('missing', 'duplicate', 'reordered', 'wrong-observed', 'other-target', 'private-evidence', 'empty-evidence'):
            value = record()
            if mutation == 'missing':value['checks'].pop()
            elif mutation == 'duplicate':value['checks'][1] = deepcopy(value['checks'][0])
            elif mutation == 'reordered':value['checks'].reverse()
            elif mutation == 'wrong-observed':value['checks'][1].update(expected='edited', observed='edited')
            elif mutation == 'other-target':value['checks'][1]['target_id'] = 'target-002'
            elif mutation == 'private-evidence':value['checks'][1]['evidence'] = ['private/key']
            else:value['checks'][1]['evidence'] = []
            with self.subTest(mutation=mutation):self.rejects(value)

    def test_stock_identity_and_no_candidate_or_production_claim(self):
        for section, key, wrong in (('root', 'operation', 'observed-software-description-v1'),
                ('root', 'runtime_pipeline_complete', True), ('root', 'production_iso_eligible', True),
                ('root', 'profile', 'five-targets'), ('root', 'candidate_sha256', 'SYNTHETIC-SENSITIVE'),
                ('stock_build', 'run_id', str(UUID(int=2))), ('stock_build', 'source_revision', 'f' * 40),
                ('target', 'image_digest', 'sha256:' + '4' * 64), ('root', 'target_id', 'target-021')):
            value = record(); target = value if section == 'root' else value[section]; target[key] = wrong
            with self.subTest(section=section, key=key):self.rejects(value)

    def test_boolean_integer_aliases_dates_and_primary_failure_cannot_float(self):
        for key, wrong in (('source_dirty', 0), ('unknown_outcome', 0), ('production_iso_eligible', 0),
                ('runtime_pipeline_complete', 0), ('updated_at', '2026-02-30T00:00:00Z')):
            value = record(); value[key] = wrong; self.rejects(value)
        value = record(); value['checks'][0]['required'] = 1; self.rejects(value)
        value = record(); value['unknown_outcome'] = True; self.rejects(value)
        value = record(); value.update(status='failed', primary_failure=None); self.rejects(value)
        value['primary_failure'] = {'code': 'late_error', 'recorded_at': '2026-10-24T17:00:01Z'}; self.rejects(value)

    def test_packet_and_record_bounds_reject_before_rendering_without_truncation(self):
        value = observation(); value['packages'] = [{'name': 'package-' + str(n).zfill(4), 'version': 'x' * 100,
            'architecture': 'amd64'} for n in range(2048)]
        self.rejects(value, f.validate_observation)
        for value in (None, [], {'bad': float('nan')}, {'bad': object()}):self.rejects(value)
        cycle = record(); cycle['bad'] = cycle; self.rejects(cycle)
        value = record(); value['bad'] = 'SYNTHETIC-SENSITIVE' * f.MAX_RECORD_BYTES; self.rejects(value)

    def test_index_is_exactly_twenty_namespaces_with_concurrency_distinct_from_target_count(self):
        value = index(); copy = f.validate_index(value); self.assertEqual(copy, value)
        self.assertEqual(value['target_count'], 20); self.assertEqual(value['controller_concurrency'], 4)
        self.assertEqual(sum(len(row['checks']) for row in value['targets']), 200)
        copy['targets'].clear(); self.assertEqual(len(value['targets']), 20)
        for key, wrong in (('target_count', 4), ('target_count', True), ('controller_concurrency', 20),
                ('controller_concurrency', True), ('production_iso_eligible', 0)):
            bad = deepcopy(value); bad[key] = wrong; self.rejects(bad, f.validate_index)

    def test_index_missing_duplicate_target_checks_paths_and_hash_types_refuse(self):
        value = index()
        for mutation in ('missing', 'duplicate', 'order', 'check', 'namespace', 'private-path', 'hash', 'size'):
            bad = deepcopy(value)
            if mutation == 'missing':bad['targets'].pop()
            elif mutation == 'duplicate':bad['targets'][-1] = deepcopy(bad['targets'][0])
            elif mutation == 'order':bad['targets'].reverse()
            elif mutation == 'check':bad['targets'][0]['checks'].pop()
            elif mutation == 'namespace':bad['targets'][1]['record']['path'] = bad['targets'][0]['record']['path']
            elif mutation == 'private-path':bad['targets'][0]['text']['path'] = 'private/key'
            elif mutation == 'hash':bad['targets'][0]['record']['sha256'] = 'SYNTHETIC-SENSITIVE'
            else:bad['targets'][0]['record']['size_bytes'] = True
            with self.subTest(mutation=mutation):self.rejects(bad, f.validate_index)

    def test_index_failed_target_and_unverified_grid_cannot_be_a_zero_failure_pass(self):
        value = index(); target = value['targets'][7]; target['status'] = 'failed'; target['checks'][1]['status'] = 'unverified'
        self.rejects(value, f.validate_index)
        value.update(status='failed', primary_failure={'code': 'inventory_incomplete', 'recorded_at': value['updated_at']})
        self.assertEqual(f.validate_index(value), value)
        target['status'] = 'passed'; self.rejects(value, f.validate_index)

    def test_batch_mapping_and_observed_value_helper_fail_safely(self):
        self.assertEqual([f.batch_for(target) for target in f.TARGET_IDS], [batch for batch in f.BATCH_IDS for _ in range(4)])
        for value in ('target-000', 'target-021', True, [], None):
            with self.subTest(value=value), self.assertRaises(f.FleetInventoryRecordError):f.batch_for(value)
        with self.assertRaises(f.FleetInventoryRecordError):f.observed_values(None)
        with self.assertRaises(f.FleetInventoryRecordError):f.observed_values({'target': {'SYNTHETIC-SENSITIVE': True}})


if __name__ == '__main__':
    unittest.main()
