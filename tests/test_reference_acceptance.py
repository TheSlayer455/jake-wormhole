"""Synthetic guards for the actual-acceptance wrapper; no allocation is performed."""
from copy import deepcopy
import json
import unittest
from xml.etree import ElementTree as ET

from wormhole import reference_acceptance as a
from wormhole.runs import RunError


def reports(platform='ubuntu', negative=False):
    # These declarations deliberately test the wrapper, not domain authenticity.
    # The actual operator supplies pipeline_records.grid(platform), and domain
    # replay validates the real original plan and every component observation.
    declarations = []
    for component, ids in [('functional', ('userland', 'source', 'manifest', 'payload', 'candidate-version', 'config', 'function')),
                           ('svd', tuple('svd-' + str(i) for i in range(14 if platform == 'ubuntu' else 12)))]:
        declarations.extend({'component': component, 'scope': 'target', 'target_id': 'target-001', 'check_id': key, 'required': True} for key in ids)
    size = 43 if platform == 'ubuntu' else 46
    declarations.extend({'component': 'other', 'scope': 'run', 'target_id': None, 'check_id': 'required-' + str(i), 'required': True}
                        for i in range(size - len(declarations)))
    rows = [{**row, 'expected': 'expected', 'observed': 'expected', 'status': 'pass', 'reason_code': 'observed',
             'message': 'Controlled fixture', 'evidence': ['capture']} for row in declarations]
    if negative:
        rows[4].update(status='fail', observed='different', reason_code='version_mismatch')
        for row in rows:
            if row['component'] == 'svd':
                row.update(status='blocked', observed='not-observed', reason_code='not_executed')
    record = {'rows': rows, 'status': 'failed' if negative else 'passed', 'reference_eligible': not negative,
              'reference_scope_complete': not negative, 'production_iso_eligible': False, 'unknown_outcome': False,
              'primary_failure': {'code': a.NEGATIVE} if negative else None,
              'cleanup': {'status': 'completed', 'admission_finished': True, 'pending_resources': 0, 'archive_sha256': 'a' * 64}}
    suite = ET.Element('testsuite', {'tests': str(size), 'failures': str(int(negative)),
                                   'errors': str(sum(row['status'] == 'blocked' for row in rows)), 'skipped': '0'})
    for row in rows:
        case = ET.SubElement(suite, 'testcase', {'name': a.row_key(row), 'classname': 'wormhole.reference-smoke-v1'})
        props = ET.SubElement(case, 'properties')
        for key in ('status', 'required', 'expected', 'observed', 'reason_code', 'message', 'evidence'):
            value = json.dumps(row[key]) if key == 'evidence' else str(row[key]).lower() if key == 'required' else row[key]
            ET.SubElement(props, 'property', {'name': key, 'value': value})
        if row['status'] != 'pass':
            ET.SubElement(case, 'failure' if row['status'] == 'fail' else 'error')
    report = {'record': record, 'json': json.dumps(record).encode(),
              'text': '\n'.join(a.row_key(row) + ': ' + row['status'] for row in rows),
              'junit': ET.tostring(suite, encoding='unicode'),
              'decision': {'reference_eligible': not negative, 'production_iso_eligible': False,
                           'reasons': [{'code': a.NEGATIVE}] if negative else []}}
    return report, declarations


class ReferenceAcceptanceGuards(unittest.TestCase):
    def test_complete_controlled_healthy_grids_and_negative_remain_distinct(self):
        for platform in ('ubuntu', 'ubi'):
            report, declarations = reports(platform)
            result = a.checked_reports(platform, 'healthy', report, declarations)
            self.assertTrue(result['reference_eligible'])
            self.assertIsNot(result, report['record'])
        report, declarations = reports(negative=True)
        result = a.checked_reports('ubuntu', 'version-expectation-mismatch', report, declarations)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['reference_eligible'])

    def test_json_and_text_disagreement_are_rejected(self):
        for kind in ('json', 'text'):
            report, declarations = reports()
            report[kind] = b'{}' if kind == 'json' else ''
            with self.assertRaises(RunError):
                a.checked_reports('ubuntu', 'healthy', report, declarations)

    def test_junit_cannot_hide_a_required_failure_as_skipped(self):
        report, declarations = reports(negative=True)
        xml = ET.fromstring(report['junit'])
        case = xml.findall('testcase')[4]
        case.remove(case.find('failure')); ET.SubElement(case, 'skipped')
        report['junit'] = ET.tostring(xml, encoding='unicode')
        with self.assertRaises(RunError):
            a.checked_reports('ubuntu', 'version-expectation-mismatch', report, declarations)

    def test_missing_duplicate_or_foreign_declaration_cannot_complete_grid(self):
        for mode in ('missing', 'duplicate', 'foreign'):
            report, declarations = reports()
            if mode == 'missing':
                declarations.pop()
            elif mode == 'duplicate':
                declarations[-1] = deepcopy(declarations[0])
            else:
                declarations[0]['target_id'] = 'target-999'
            with self.assertRaises(RunError):
                a.checked_reports('ubuntu', 'healthy', report, declarations)

    def test_successful_rows_cannot_replace_finished_cleanup_archive(self):
        report, declarations = reports()
        report['record']['cleanup']['admission_finished'] = False
        report['json'] = json.dumps(report['record']).encode()
        with self.assertRaises(RunError):
            a.checked_reports('ubuntu', 'healthy', report, declarations)

    def test_negative_cannot_claim_svd_execution_or_empty_refusal_reasons(self):
        for mode in ('svd', 'reasons'):
            report, declarations = reports(negative=True)
            if mode == 'svd':
                report['record']['rows'][7]['status'] = 'pass'
            else:
                report['decision']['reasons'] = []
            report['json'] = json.dumps(report['record']).encode()
            with self.assertRaises(RunError):
                a.checked_reports('ubuntu', 'version-expectation-mismatch', report, declarations)


if __name__ == '__main__':
    unittest.main()
