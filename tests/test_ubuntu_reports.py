"""Synthetic report and installed-input dependency regressions; no VM claims."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import ubuntu_inputs as inputs, ubuntu_reports as reports
from wormhole.ubuntu_assessment import POLICY


class Reports(unittest.TestCase):
    def test_guest_hashing_does_not_require_python_311_file_digest(self):
        import importlib.util
        import hashlib
        from wormhole.runs import SOURCE_ROOT
        spec=importlib.util.spec_from_file_location('guest_observe',SOURCE_ROOT/'ubuntu/guest/observe.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as value:
            file=Path(value)/'fixture';file.write_bytes(b'0123456789'*200000)
            with patch.object(module.hashlib,'file_digest',None):
                self.assertEqual(module.file_sha256(file),hashlib.sha256(file.read_bytes()).hexdigest())

    def test_pending_policy_refuses_publication_before_creating_release(self):
        from wormhole.ubuntu_release import publish
        from wormhole.runs import RunError
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            with self.assertRaises(RunError) as failure:
                publish(root/'run-a',root/'run-b',candidate=root/'not-created.iso',dependency_store=root,
                        destination=root,name='Jake-Ubuntu-22.04-LAB-QUALIFIED-fixture')
            self.assertEqual(failure.exception.code,'lab_policy_dependencies_pending')
            self.assertEqual(list(root.iterdir()),[])
            (root/'Jake-Ubuntu-22.04-LAB-QUALIFIED-fixture').mkdir()
            with self.assertRaises(RunError) as duplicate:
                publish(root/'run-a',root/'run-b',candidate=root/'not-created.iso',dependency_store=root,
                        destination=root,name='Jake-Ubuntu-22.04-LAB-QUALIFIED-fixture')
            self.assertEqual(duplicate.exception.code,'duplicate_publication')

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
