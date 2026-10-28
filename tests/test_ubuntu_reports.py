"""Synthetic report and installed-input dependency regressions; no VM claims."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import ubuntu_inputs as inputs, ubuntu_reports as reports
from wormhole.ubuntu_assessment import POLICY


class Reports(unittest.TestCase):
    def test_absent_results_are_blocked_and_junit_retains_each_expected_check(self):
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            result={'run_id':'fixture', 'source_revision':'fixture', 'outcome':'failed','cleanup':'unreconciled',
                    'error_category':'initialization_failed'}
            report=reports.generate(root,result)
            self.assertEqual(report['functional_counts'],{'blocked':14})
            self.assertFalse(report['lab_iso_qualified'])
            self.assertFalse(report['production_iso_eligible'])
            self.assertEqual(len(ET.parse(root/'junit.xml').findall('./testcase')),14)
            self.assertIn('cleanup-not-verified',report['qualification_reasons'])

    def test_clean_fixture_does_not_satisfy_missing_fips_or_repeatability(self):
        policy=json.loads(POLICY.read_text())
        with tempfile.TemporaryDirectory() as value:
            result={'run_id':'fixture','source_revision':'fixture','outcome':'assessment-complete',
                    'cleanup':'verified-absent-inputs-retained','final_authentication':True,'ansible_ready':True}
            report=reports.generate(Path(value),result,
                observations={'checks':{x:True for x in policy['functional_checks']},'packages':[],'kernel':'fixture'},
                findings={'scanner_execution_completed':True,'coverage_complete':True,
                          'all_selected_automated_clean':True,'rules':[]})
            self.assertFalse(report['lab_iso_qualified'])
            self.assertEqual(report['functional_counts'],{'pass':14})
            self.assertIn('authorized-guest-procedure-for-usg-and-fips-updates',report['qualification_reasons'])

    def test_controller_change_reuses_inputs_but_installed_change_invalidates(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);(root/'bundle').mkdir();(root/'bundle/manifest.json').write_text('{}')
            def identity(path):return 'a' * 64
            with patch.object(inputs,'sha256',side_effect=identity):
                original,_=inputs.input_identity(root,'stock-audit')
            def changed(path):
                return 'b'*64 if str(path).endswith('finalize.sh') else 'a'*64
            with patch.object(inputs,'sha256',side_effect=changed):
                installed,_=inputs.input_identity(root,'stock-audit')
            def controller(path):
                return 'c'*64 if str(path).endswith('vm_baseline.py') else 'a'*64
            with patch.object(inputs,'sha256',side_effect=controller):
                unchanged,_=inputs.input_identity(root,'stock-audit')
            self.assertNotEqual(original,installed)
            self.assertEqual(original,unchanged)
