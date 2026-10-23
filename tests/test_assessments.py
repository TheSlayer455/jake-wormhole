"""Disposable synthetic files and exact component failures, no scanner or infrastructure."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import assessments as a
from wormhole.contracts import ContractError, validate_artifact
from wormhole.runs import RunError, atomic_bytes, atomic_json, create_run, read_json
from wormhole.stages import execute_run, verify_run

SHA = 'a' * 40


class ChecklistParsing(unittest.TestCase):
    def parse(self, value):
        return a.parse_checklist(a.canonical(value), a.FIXTURE_EXPECTED)

    def test_four_categories_and_policy_rejection_do_not_become_empty_success(self):
        raw = a.fixture('reject')
        result = a.parse_checklist(raw, a.FIXTURE_EXPECTED)
        self.assertEqual(result['counts'], {status: 1 for status in a.STATUSES})
        self.assertEqual(result['policy_verdict'], 'reject')
        self.assertEqual(len(result['policy_reasons']), 2)
        self.assertEqual(raw, a.fixture('reject'))

    def test_complete_reference_pass_requires_declared_applicability(self):
        value = json.loads(a.fixture('pass'))
        result = self.parse(value)
        self.assertEqual(result['policy_verdict'], 'pass')
        self.assertEqual(result['counts']['Not a Finding'], 3)
        for position, reason in [(0, 'invented exemption'), (3, '')]:
            wrong = deepcopy(value)
            wrong['findings'][position].update(status='Not Applicable', reason=reason)
            self.assertEqual(self.parse(wrong)['policy_verdict'], 'reject')
        wrong = deepcopy(value)
        wrong['findings'][3]['status'] = 'Not a Finding'
        self.assertEqual(self.parse(wrong)['policy_verdict'], 'reject')

    def test_malformed_unsupported_and_nonfinite_input_fail_explicitly(self):
        for raw, code in [(a.fixture('malformed'), 'malformed_assessment'),
                          (a.fixture('unsupported'), 'unsupported_assessment_format'),
                          (b'{"format":NaN}', 'malformed_assessment'),
                          (b'{"format":"x","format":"y"}', 'duplicate_json_member'),
                          (b'\xff', 'malformed_assessment')]:
            with self.subTest(code=code), self.assertRaises(a.AssessmentError) as caught:
                a.parse_checklist(raw, a.FIXTURE_EXPECTED)
            self.assertEqual(caught.exception.code, code)

    def test_missing_duplicate_unknown_and_empty_findings_are_rejected(self):
        base = json.loads(a.fixture('pass'))
        for modify in (lambda x: x['findings'].pop(), lambda x: x.update(findings=[]),
                       lambda x: x['findings'].append(deepcopy(x['findings'][0])),
                       lambda x: x['findings'][0].update(finding_id='unplanned-finding')):
            value = deepcopy(base)
            modify(value)
            with self.assertRaises(a.AssessmentError):
                self.parse(value)

    def test_unknown_fields_types_and_unsafe_text_cannot_reach_reports(self):
        base = json.loads(a.fixture('pass'))
        for modify in (lambda x: x.update(production_iso_eligible=True),
                       lambda x: x.update(synthetic=1),
                       lambda x: x['findings'][0].update(status='Passed'),
                       lambda x: x['findings'][0].update(summary='\x1b[31m'),
                       lambda x: x['findings'][0].update(summary='\ud800'),
                       lambda x: x['findings'][0].update(summary=''),
                       lambda x: x['findings'][0].update(reason={})):
            value = deepcopy(base)
            modify(value)
            with self.assertRaises(a.AssessmentError):
                self.parse(value)

    def test_expected_set_is_nonempty_unique_and_predeclares_applicability(self):
        for expected in ([], a.FIXTURE_EXPECTED * 2, [{'finding_id': 'x', 'applicable': False, 'reason': ''}],
                         [{'finding_id': 'x', 'applicable': 1, 'reason': ''}]):
            with self.assertRaises(a.AssessmentError):
                a.parse_checklist(a.fixture('pass'), expected)

    def test_input_and_finding_bounds_are_enforced_before_acceptance(self):
        for raw in (b'', b' ' * (a.MAX_INPUT + 1), '[' * 2000 + ']' * 2000):
            if isinstance(raw, str):
                raw = raw.encode()
            with self.assertRaises(a.AssessmentError):
                a.parse_checklist(raw, a.FIXTURE_EXPECTED)
        value = json.loads(a.fixture('pass'))
        value['findings'] *= a.MAX_FINDINGS
        with self.assertRaises(a.AssessmentError):
            self.parse(value)


class RetainedAssessment(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='wormhole-synthetic-assessment-')
        self.addCleanup(folder.cleanup)
        self.run = create_run(Path(folder.name) / 'runs', fixture=True, identity=(SHA, False))
        self.identity = patch.object(a, 'source_identity', return_value=(SHA, False))
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def assess(self, case='pass'):
        return a.assess_run(self.run, a.fixture(case), a.FIXTURE_EXPECTED)

    def test_original_bytes_persist_and_report_replays_same_normalized_records(self):
        saved = self.assess()
        raw = self.run.file(a.ORIGINAL).read_bytes()
        self.assertEqual(raw, a.fixture('pass'))
        self.assertEqual(saved['original_sha256'], hashlib.sha256(raw).hexdigest())
        report = a.report_assessment(self.run)
        self.assertEqual(report['result'], saved)
        self.assertIn('Not a Finding: 3', report['text'])
        for row in saved['result']['findings']:
            self.assertIn(row['finding_id'] + ': ' + row['status'], report['text'])
        validate_artifact('assessment', saved['assessment_artifact'])

    def test_pass_and_reject_are_both_ineligible_for_release_and_main_fixture_unchanged(self):
        with self.run.locked():
            execute_run(self.run)
        before = {kind: self.run.artifact(kind) for kind in ('assessment', 'release-decision')}
        saved = self.assess('reject')
        self.assertEqual(saved['status'], 'rejected')
        self.assertEqual(saved['result']['policy_verdict'], 'reject')
        self.assertTrue(verify_run(self.run)['fixture_subset_passed'])
        self.assertEqual(before, {kind: self.run.artifact(kind) for kind in before})
        for field in ('runtime_pipeline_complete', 'reference_eligible', 'production_iso_eligible'):
            self.assertIs(saved[field], False)
        for flag in ('reference_eligible', 'production_iso_eligible'):
            record = deepcopy(before['release-decision'])
            record[flag] = True
            with self.assertRaises(ContractError):
                validate_artifact('release-decision', record)

    def test_failed_input_retains_original_and_failure_not_zero_findings(self):
        with self.assertRaises(a.AssessmentError) as caught:
            self.assess('malformed')
        self.assertEqual(caught.exception.code, 'malformed_assessment')
        self.assertEqual(self.run.file(a.ORIGINAL).read_bytes(), a.fixture('malformed'))
        report = a.report_assessment(self.run)
        self.assertEqual(report['result']['status'], 'failed')
        self.assertIsNone(report['result']['result'])
        self.assertIn('malformed_assessment', report['text'])
        with self.assertRaises(a.AssessmentError) as retried:
            self.assess('pass')
        self.assertEqual(retried.exception.code, 'assessment_attempt_reused')

    def test_editing_counts_findings_outcomes_or_eligibility_is_rejected(self):
        original = self.assess()
        for modify in (lambda x: x['result']['counts'].update(Open=0, **{'Not a Finding': 0}),
                       lambda x: x['result']['findings'].pop(),
                       lambda x: x.update(status='rejected'),
                       lambda x: x.update(reference_eligible=True),
                       lambda x: x.update(production_iso_eligible=True),
                       lambda x: x.update(duration_seconds=True),
                       lambda x: x.update(created_at='not-a-timestamp')):
            value = deepcopy(original)
            modify(value)
            atomic_json(self.run.file(a.RECEIPT), value)
            with self.assertRaises(a.AssessmentError):
                a.report_assessment(self.run)
        atomic_json(self.run.file(a.RECEIPT), original)
        self.assertEqual(a.report_assessment(self.run)['result'], original)

    def test_original_hash_and_frozen_plan_are_required_to_report(self):
        self.assess()
        raw = self.run.file(a.ORIGINAL).read_bytes()
        atomic_bytes(self.run.file(a.ORIGINAL), a.fixture('reject'))
        with self.assertRaises(a.AssessmentError):
            a.report_assessment(self.run)
        atomic_bytes(self.run.file(a.ORIGINAL), raw)
        plan = read_json(self.run.file(a.PLAN))
        plan['expected_findings'][0]['applicable'] = False
        atomic_json(self.run.file(a.PLAN), plan)
        with self.assertRaises(a.AssessmentError):
            a.report_assessment(self.run)

    def test_stale_source_interrupted_plan_and_competing_lock_cannot_overwrite(self):
        with patch.object(a, 'source_identity', return_value=(SHA, True)):
            with self.assertRaises(a.AssessmentError):
                self.assess()
        self.assertFalse(self.run.file(a.PLAN).exists())
        with self.run.locked():
            with self.assertRaises(RunError):
                self.assess()
        atomic_json(self.run.file(a.PLAN), a.make_plan(self.run, a.FIXTURE_EXPECTED))
        with self.assertRaises(a.AssessmentError) as caught:
            self.assess()
        self.assertEqual(caught.exception.code, 'assessment_attempt_reused')
        self.assertFalse(self.run.file(a.ORIGINAL).exists())

    def test_hardlinked_original_is_not_accepted_as_owned_evidence(self):
        self.assess()
        alias = self.run.path / 'private' / 'linked-original.json'
        os.link(self.run.file(a.ORIGINAL), alias)
        with self.assertRaises(RunError):
            a.report_assessment(self.run)

    @unittest.skipUnless(os.name == 'posix', 'POSIX private-file permissions')
    def test_world_readable_original_cannot_be_used_for_a_pass(self):
        self.assess()
        self.run.file(a.ORIGINAL).chmod(0o644)
        with self.assertRaises(RunError):
            a.report_assessment(self.run)
