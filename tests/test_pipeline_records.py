"""Pure synthetic pipeline records; no infrastructure or runtime observation."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from wormhole import pipeline_records as p


def fixture(platform='ubuntu'):
    common = {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc',
        'source_revision': 'a' * 40, 'source_dirty': False, 'mode': 'container-reference'}
    candidate = {'manifest_sha256': 'b' * 64, 'source_candidate_sha256': ('b' if platform == 'ubuntu' else 'c') * 64,
        'content_sha256': 'd' * 64, 'source_sha256': 'e' * 64}
    plan = {**common, 'operation': p.PLAN_OPERATION, 'policy': p.POLICY, 'platform': platform, 'profile': 'smoke',
        'targets': ['target-001'], 'capabilities': [], 'candidate': candidate,
        'expected_rows': [{**row, 'expected': 'synthetic-observed'} for row in p.grid(platform)]}
    next(row for row in plan['expected_rows'] if row['component'] == 'svd' and row['check_id'] == 'target-identity')['expected'] = 'exact-owned-target-001'
    plan['plan_sha256'] = p.digest(plan)
    record = {**common, 'operation': p.OPERATION, 'policy': p.POLICY, 'plan_sha256': plan['plan_sha256'], 'status': 'passed',
        'candidate': {**candidate, 'image_digest': 'sha256:' + 'f' * 64},
        'targets': [{'target_id': 'target-001', 'resource_id': '1' * 64, 'image_digest': 'sha256:' + 'f' * 64}],
        'rows': [{**row, 'observed': row['expected'], 'status': 'pass', 'reason_code': 'observed',
            'message': 'Synthetic complete observation.', 'evidence': ['fixture-capture']} for row in plan['expected_rows']],
        'artifacts': [{'artifact_id': 'fixture-capture', 'kind': 'log-capture', 'sha256': '2' * 64, 'size_bytes': 123}],
        'primary_failure': None, 'secondary_failures': [], 'cleanup': {'status': 'completed', 'admission_finished': True,
            'archive_sha256': '3' * 64, 'pending_resources': 0}, 'unknown_outcome': False,
        'reference_scope_complete': True, 'reference_eligible': True, 'production_iso_eligible': False,
        'updated_at': '2026-10-23T19:55:00.000Z'}
    return plan, record


def rehash(plan, record=None):
    plan['plan_sha256'] = p.digest({key: value for key, value in plan.items() if key != 'plan_sha256'})
    if record is not None:
        record['plan_sha256'] = plan['plan_sha256']


def fail(record, row=0, status='fail', code='synthetic_failure'):
    record.update(status='failed', reference_scope_complete=False, reference_eligible=False,
        primary_failure={'code': code, 'recorded_at': record['updated_at']})
    record['rows'][row].update(status=status, observed='not observed', reason_code=code, message='Synthetic negative.')
    return record


def key(row):
    return '/'.join((row['component'], row['target_id'] or 'run', row['check_id']))


def svd_fixture(plan, record):
    from tests.test_observed_svd import fixture as native_fixture
    source = native_fixture('dpkg' if plan['platform'] == 'ubuntu' else 'rpm')
    for name in p.COMMON_KEYS:
        source[name] = record[name]
    for candidate in (plan['candidate'], record['candidate']):
        candidate['content_sha256'] = source['observation']['payload']['content_sha256']
        candidate['source_sha256'] = source['observation']['payload']['source_sha256']
    rehash(plan, record)
    source['target'] = {'target_id': 'target-001', 'resource_id': record['targets'][0]['resource_id'],
        'image_digest': record['candidate']['image_digest'], 'candidate_sha256': record['candidate']['manifest_sha256'],
        'source_candidate_sha256': record['candidate']['source_candidate_sha256'], 'content_sha256': record['candidate']['content_sha256']}
    source['observation']['payload']['manifest_sha256'] = record['candidate']['manifest_sha256']
    from tests.test_observed_svd import rebind_capture
    rebind_capture(source)
    source['checks'] = [{key: row[key] for key in ('check_id', 'target_id', 'required', 'expected', 'observed', 'status')}
        | {'evidence': ['evidence/software-inventory.json']} for row in record['rows'] if row['component'] == 'svd']
    source['checks'][0].update(expected=record['targets'][0]['resource_id'], observed=record['targets'][0]['resource_id'])
    return source


class PipelineRecords(unittest.TestCase):
    def test_published_schemas_are_generated_exactly(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(json.loads((root / 'schemas/pipeline-v1.schema.json').read_bytes()), p.schema())
        self.assertEqual(json.loads((root / 'schemas/pipeline-plan-v1.schema.json').read_bytes()), p.plan_schema())

    def test_fixed_grids_match_existing_platform_contracts_without_stock_substitution(self):
        from wormhole import candidate, readiness, rpm_candidate, software_inventory
        for platform, count in (('ubuntu', 43), ('ubi', 46)):
            with self.subTest(platform=platform):
                rows = p.grid(platform)
                self.assertEqual(len(rows), count)
                self.assertEqual([r['check_id'] for r in rows if r['component'] == 'readiness'], list(readiness.EXPECTED))
                self.assertEqual([r['check_id'] for r in rows if r['component'] == 'functional'],
                    list(candidate.CHECKS if platform == 'ubuntu' else rpm_candidate.CHECKS))
                self.assertEqual([r['check_id'] for r in rows if r['component'] == 'svd'], software_inventory.check_ids(platform))
                self.assertTrue(all(r['target_id'] is None for r in rows if r['scope'] == 'run'))
                self.assertTrue(all(r['target_id'] == 'target-001' for r in rows if r['scope'] == 'target'))
        self.assertEqual(p.expected_grid('ubuntu'), p.grid('ubuntu'))

    def test_exact_shared_json_text_and_junit_grid_without_mutation(self):
        for platform in ('ubuntu', 'ubi'):
            plan, record = fixture(platform); before = deepcopy((plan, record))
            parsed = json.loads(p.render_json(record, plan)); text = p.render_text(record, plan)
            xml = ET.fromstring(p.render_junit(record, plan)); cases = xml.findall('testcase')
            self.assertEqual(parsed, record)
            self.assertEqual([case.attrib['name'] for case in cases], [key(row) for row in record['rows']])
            self.assertEqual(xml.attrib, {'name': p.POLICY, 'tests': str(len(cases)), 'failures': '0', 'errors': '0', 'skipped': '0'})
            for row, case in zip(record['rows'], cases):
                self.assertIn(key(row) + ': ' + row['status'], text)
                values = {item.attrib['name']: item.attrib['value'] for item in case.findall('./properties/property')}
                for field in ('status', 'expected', 'observed', 'reason_code', 'message'):
                    self.assertEqual(values[field], row[field])
                self.assertEqual(json.loads(values['evidence']), row['evidence'])
            self.assertEqual((plan, record), before)
            copy = p.validate_record(record, plan); copy['rows'][0]['observed'] = 'changed'
            self.assertEqual((plan, record), before)
            self.assertIn('Synthetic assessment', text); self.assertIn('kernel is shared', text)
            self.assertIn('Production ISO eligible: false', text)

    def test_every_required_nonpass_is_visible_in_junit_and_exact_counts(self):
        for status in p.STATUSES[1:]:
            with self.subTest(status=status):
                plan, record = fixture(); fail(record, 4, status)
                xml = ET.fromstring(p.render_junit(record, plan))
                cases = xml.findall('testcase'); failed = cases[4].find('failure' if status == 'fail' else 'error')
                self.assertEqual(failed.attrib['type'], status)
                self.assertEqual(len(cases), len(record['rows']))
                self.assertEqual(xml.attrib['failures'], str(int(status == 'fail')))
                self.assertEqual(xml.attrib['errors'], '0' if status == 'fail' else '1')
                self.assertEqual(xml.attrib['skipped'], '0')
                self.assertIn('required_' + status, [r['code'] for r in p.decision(record, plan)['reasons']])

    def test_xml_escaping_roundtrips_exact_values_and_control_characters_refuse(self):
        plan, record = fixture()
        for row in plan['expected_rows']:
            if not (row['component'] == 'svd' and row['check_id'] == 'target-identity'):
                row['expected'] = '<expected attr="value"> & safe'
        rehash(plan, record)
        for planned, row in zip(plan['expected_rows'], record['rows']):
            row.update(expected=planned['expected'], observed=planned['expected'], message='"quoted" <tag> & content')
        xml = p.render_junit(record, plan); parsed = ET.fromstring(xml)
        values = {prop.attrib['name']: prop.attrib['value'] for prop in parsed.findall('./testcase/properties/property')}
        self.assertEqual(values['expected'], '<expected attr="value"> & safe')
        self.assertIn('&lt;expected', xml)
        for unsafe in ('bad\x00value', 'bad\x1fvalue', 'bad\nvalue', 'bad\rvalue', 'bad\tvalue', '\ud800', 'bad\x7fvalue'):
            bad = deepcopy(record); bad['rows'][0]['message'] = unsafe
            with self.subTest(unsafe=repr(unsafe)), self.assertRaises(p.PipelineRecordError): p.render_junit(bad, plan)

    def test_plan_cannot_remove_required_rows_change_scopes_or_enable_capabilities(self):
        for change in ('empty', 'missing', 'duplicate', 'foreign', 'order', 'optional', 'scope', 'target', 'powershell', 'five'):
            plan, _ = fixture()
            if change == 'empty': plan['expected_rows'] = []
            elif change == 'missing': plan['expected_rows'].pop()
            elif change == 'duplicate': plan['expected_rows'][1] = deepcopy(plan['expected_rows'][0])
            elif change == 'foreign': plan['expected_rows'][1]['check_id'] = 'foreign'
            elif change == 'order': plan['expected_rows'][1:3] = reversed(plan['expected_rows'][1:3])
            elif change == 'optional': plan['expected_rows'][0]['required'] = False
            elif change == 'scope': plan['expected_rows'][0]['scope'] = 'target'
            elif change == 'target': plan['targets'] = ['target-002']
            elif change == 'powershell': plan['capabilities'] = ['powershell']
            elif change == 'five': plan['profile'] = 'five'
            rehash(plan)
            with self.subTest(change=change), self.assertRaises(p.PipelineRecordError): p.validate_plan(plan)

    def test_exact_result_grid_refuses_missing_extra_foreign_duplicate_and_reordered_rows(self):
        for change in ('empty', 'missing', 'extra', 'duplicate', 'foreign', 'order', 'expected'):
            plan, record = fixture()
            if change == 'empty': record['rows'] = []
            elif change == 'missing': record['rows'].pop()
            elif change == 'extra': record['rows'].append(deepcopy(record['rows'][0]))
            elif change == 'duplicate': record['rows'][1] = deepcopy(record['rows'][0])
            elif change == 'foreign': record['rows'][0]['target_id'] = 'target-001'
            elif change == 'order': record['rows'][1:3] = reversed(record['rows'][1:3])
            elif change == 'expected': record['rows'][0]['expected'] = 'edited expectation'
            with self.subTest(change=change), self.assertRaises(p.PipelineRecordError): p.validate_record(record, plan)

    def test_identity_candidate_and_plan_hash_changes_refuse(self):
        for path in ('run_id', 'source_revision', 'mode', 'source_dirty', 'plan_sha256', 'candidate', 'image', 'resource', 'plan'):
            plan, record = fixture()
            if path == 'run_id': record[path] = '22345678-1234-4234-9234-123456789abc'
            elif path == 'source_revision': record[path] = '9' * 40
            elif path == 'mode': record[path] = 'fixture'
            elif path == 'source_dirty': record[path] = True
            elif path == 'plan_sha256': record[path] = '9' * 64
            elif path == 'candidate': record[path]['content_sha256'] = '9' * 64
            elif path == 'image': record['targets'][0]['image_digest'] = 'sha256:' + '9' * 64
            elif path == 'resource': record['targets'][0]['resource_id'] = 'not-an-id'
            elif path == 'plan': plan['expected_rows'][0]['expected'] = 'edited without rehash'
            with self.subTest(path=path), self.assertRaises(p.PipelineRecordError): p.validate_record(record, plan)

    def test_typed_aliases_unbounded_nonfinite_and_unknown_fields_refuse(self):
        for kind in ('pending-bool', 'bytes-bool', 'eligible-int', 'dirty-int', 'required-int', 'production-int',
                     'archive-int', 'nan', 'large', 'extra', 'cycle'):
            plan, record = fixture()
            if kind == 'pending-bool': record['cleanup']['pending_resources'] = False
            elif kind == 'bytes-bool': record['artifacts'][0]['size_bytes'] = True
            elif kind == 'eligible-int': record['reference_eligible'] = 1
            elif kind == 'dirty-int': record['source_dirty'] = 0
            elif kind == 'required-int': record['rows'][0]['required'] = 1
            elif kind == 'production-int': record['production_iso_eligible'] = 0
            elif kind == 'archive-int': record['cleanup']['admission_finished'] = 1
            elif kind == 'nan': record['artifacts'][0]['size_bytes'] = float('nan')
            elif kind == 'large': record['rows'][0]['message'] = 'x' * 1001
            elif kind == 'extra': record['environment'] = {'TOKEN': 'unexportable'}
            elif kind == 'cycle': record['rows'].append(record)
            with self.subTest(kind=kind), self.assertRaises(p.PipelineRecordError): p.validate_record(record, plan)

    def test_evidence_requires_existing_unique_metadata_and_pass_value_match(self):
        for kind in ('missing', 'duplicate-ref', 'duplicate-id', 'empty-pass', 'mismatch', 'path-id', 'raw'):
            plan, record = fixture()
            if kind == 'missing': record['rows'][0]['evidence'] = ['missing-capture']
            elif kind == 'duplicate-ref': record['rows'][0]['evidence'] *= 2
            elif kind == 'duplicate-id': record['artifacts'] *= 2
            elif kind == 'empty-pass': record['rows'][0]['evidence'] = []
            elif kind == 'mismatch': record['rows'][0]['observed'] = 'wrong'
            elif kind == 'path-id': record['artifacts'][0]['artifact_id'] = 'private/state'
            elif kind == 'raw': record['artifacts'][0]['raw_capture'] = 'arbitrary raw output'
            with self.subTest(kind=kind), self.assertRaises(p.PipelineRecordError): p.validate_record(record, plan)

    def test_early_failure_keeps_every_planned_row_and_no_invented_identity(self):
        plan, record = fixture(); plan['candidate'] = None; rehash(plan, record)
        record.update(candidate=None, targets=[], status='failed', reference_scope_complete=False, reference_eligible=False,
            primary_failure={'code': 'source_integrity_failed', 'recorded_at': record['updated_at']},
            cleanup={'status': 'not-started', 'admission_finished': False, 'archive_sha256': None, 'pending_resources': 0})
        for row in record['rows']:
            row.update(status='blocked', observed='not attempted', reason_code='prerequisite_failed', evidence=[])
        record['rows'][1].update(status='fail', reason_code='source_integrity_failed')
        self.assertEqual(len(p.validate_record(record, plan)['rows']), 43)
        xml = ET.fromstring(p.render_junit(record, plan))
        self.assertEqual(xml.attrib['tests'], '43'); self.assertEqual(xml.attrib['failures'], '1'); self.assertEqual(xml.attrib['errors'], '42')
        self.assertIn('candidate_missing', [r['code'] for r in p.decision(record, plan)['reasons']])
        files = p.safe_export(record, plan)
        self.assertIsNone(json.loads(files['targets/target-001/observed-svd.json'])['record'])
        self.assertIn(b'Unverified', files['targets/target-001/observed-svd.txt'])
        record['reference_eligible'] = True
        with self.assertRaises(p.PipelineRecordError): p.validate_record(record, plan)

    def test_primary_failure_survives_successful_cleanup_and_secondary_diagnostic(self):
        plan, record = fixture(); index = next(i for i, row in enumerate(record['rows']) if row['check_id'] == 'candidate-version')
        fail(record, index, 'fail', 'candidate_version_mismatch')
        record['secondary_failures'] = [{'code': 'diagnostic_unavailable', 'recorded_at': record['updated_at']}]
        value = p.validate_record(record, plan); decision = p.decision(value, plan)
        self.assertFalse(decision['reference_eligible']); self.assertEqual(value['cleanup']['status'], 'completed')
        self.assertEqual(value['primary_failure']['code'], 'candidate_version_mismatch')
        self.assertIn('diagnostic_unavailable', p.render_text(value, plan))

    def test_unfinished_archive_unknown_and_pending_cleanup_cannot_pass(self):
        for kind in ('unfinished', 'missing-hash', 'orphan-hash', 'pending', 'unknown', 'row-hidden-primary'):
            plan, record = fixture()
            if kind == 'unfinished': record['cleanup'].update(admission_finished=False, archive_sha256=None)
            elif kind == 'missing-hash': record['cleanup']['archive_sha256'] = None
            elif kind == 'orphan-hash': record['cleanup']['admission_finished'] = False
            elif kind == 'pending': record['cleanup']['pending_resources'] = 1
            elif kind == 'unknown': record['unknown_outcome'] = True
            elif kind == 'row-hidden-primary':
                record.update(status='failed', reference_scope_complete=False, reference_eligible=False,
                    primary_failure={'code': 'late_failure', 'recorded_at': record['updated_at']})
            with self.subTest(kind=kind), self.assertRaises(p.PipelineRecordError): p.validate_record(record, plan)
        plan, record = fixture(); fail(record, len(record['rows']) - 1, 'blocked', 'admission_unfinished')
        record.update(status='blocked'); record['cleanup'].update(status='blocked', admission_finished=False, archive_sha256=None)
        record['rows'][-2].update(status='unverified', observed='not reconciled', reason_code='cleanup_incomplete')
        self.assertFalse(p.validate_record(record, plan)['reference_eligible'])

    def test_safe_export_exact_allowlist_checksums_and_no_circular_self_hash(self):
        plan, record = fixture('ubi'); source = svd_fixture(plan, record); files = p.safe_export(record, plan, svd_record=source)
        self.assertEqual(tuple(files), p.EXPORT_PATHS)
        self.assertTrue(all(type(raw) is bytes for raw in files.values()))
        checksum = json.loads(files['checksums.json']); listed = {row['path']: row for row in checksum['files']}
        self.assertEqual(set(listed), set(files) - {'checksums.json', 'decision.json'})
        for path, row in listed.items():
            self.assertEqual(row['sha256'], hashlib.sha256(files[path]).hexdigest()); self.assertEqual(row['size_bytes'], len(files[path]))
        decision = json.loads(files['decision.json'])
        self.assertEqual(decision['checksums_sha256'], hashlib.sha256(files['checksums.json']).hexdigest())
        self.assertEqual(decision['record_sha256'], hashlib.sha256(files['report.json']).hexdigest())
        self.assertEqual(json.loads(files['report.json']), record)
        logs = json.loads(files['targets/target-001/logs.json'])
        self.assertFalse(logs['raw_captures_exported']); self.assertEqual(logs['captures'], record['artifacts'])
        for path in p.EXPORT_PATHS:
            self.assertFalse(path.startswith('private/')); self.assertNotIn('tfstate', path); self.assertNotIn('known_hosts', path)
        self.assertEqual(json.loads(files['targets/target-001/svd.json'])['projection'], 'normalized-result-rows-only')

    def test_full_native_svd_projection_retains_inventory_and_removes_private_paths(self):
        for platform in ('ubuntu', 'ubi'):
            plan, record = fixture(platform); source = svd_fixture(plan, record); before = deepcopy(source)
            files = p.safe_export(record, plan, svd_record=source)
            projection = json.loads(files['targets/target-001/observed-svd.json'])
            observed = projection['record']; text = files['targets/target-001/observed-svd.txt'].decode()
            for field in ('collector', 'target', 'observation', 'execution_provenance'):
                self.assertEqual(observed[field], source[field])
            self.assertEqual(projection['source_record_sha256'], hashlib.sha256(p.observed_svd.render_json(source)).hexdigest())
            self.assertNotIn('path', observed['capture']); self.assertEqual(observed['capture']['artifact_id'], 'observed-svd-private-capture')
            self.assertTrue(all(row['evidence'] == ['observed-svd-original-record'] for row in observed['checks']))
            self.assertNotIn('private/', text); self.assertNotIn('evidence/software-inventory.json', text)
            for native in source['observation']['packages']:
                for field in ('name', 'version'):
                    self.assertIn(native[field], text)
            self.assertIn('Safe JSON projection SHA256: ' + hashlib.sha256(files['targets/target-001/observed-svd.json']).hexdigest(), text)
            self.assertIn(json.dumps(projection, sort_keys=True, ensure_ascii=True, indent=2), text)
            self.assertEqual(source, before)

    def test_full_svd_missing_wrong_identity_grid_capture_and_raw_path_refuse(self):
        plan, record = fixture()
        with self.assertRaisesRegex(p.PipelineRecordError, 'record refused'):
            p.safe_export(record, plan)
        for change in ('run', 'candidate', 'target', 'row', 'capture', 'private-value'):
            plan, record = fixture(); source = svd_fixture(plan, record)
            if change == 'run': source['run_id'] = '22345678-1234-4234-9234-123456789abc'
            elif change == 'candidate': source['target']['source_candidate_sha256'] = '9' * 64
            elif change == 'target': source['target']['resource_id'] = '9' * 64
            elif change == 'row': source['checks'][0]['expected'] = source['checks'][0]['observed'] = 'edited'
            elif change == 'capture': source['capture']['collector_sha256'] = '9' * 64
            elif change == 'private-value':
                source['observation']['shared_kernel']['release'] = '/srv/private-state'
                from tests.test_observed_svd import rebind_capture
                rebind_capture(source)
            with self.subTest(change=change), self.assertRaises(p.RunError): p.safe_export(record, plan, svd_record=source)

    def test_safe_export_rejects_secret_dumps_and_absolute_private_paths(self):
        for leak in ('/srv/homelab/state', 'C:\\Users\\example\\state', '/home/example/state', 'private/terraform/state',
            'terraform.tfstate', 'saved.tfplan', 'https://user:password@example.test/file',
            '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----', '{"environment":{"TOKEN":"value"}}',
            '{"password":"value"}', 'github_pat_' + 'a' * 65):
            plan, record = fixture(); source = svd_fixture(plan, record); record['rows'][0]['message'] = leak
            with self.subTest(leak=leak), self.assertRaises(p.PipelineRecordError): p.safe_export(record, plan, svd_record=source)

    def test_pure_functions_perform_no_io_or_adapter_calls(self):
        plan, record = fixture(); source = svd_fixture(plan, record)
        with patch('builtins.open', side_effect=AssertionError('unexpected file read')), \
             patch('subprocess.run', side_effect=AssertionError('unexpected process')):
            p.validate_plan(plan); p.validate_record(record, plan); p.render_text(record, plan)
            p.render_json(record, plan); p.render_junit(record, plan); p.safe_export(record, plan, svd_record=source)


if __name__ == '__main__':
    unittest.main()
