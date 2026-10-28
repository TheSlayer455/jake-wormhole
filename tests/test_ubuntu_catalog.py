"""Synthetic comparisons and HTML escaping, separate from real VM evidence."""
import json
from pathlib import Path
import tempfile
import unittest

from wormhole.runs import atomic_json
from wormhole.ubuntu_catalog import catalog,compare


class Catalog(unittest.TestCase):
    def run_record(self,root,identifier,*,status='fail',content='a',mode='hardened'):
        path=root/identifier;path.mkdir();(path/'assessment').mkdir()
        result={'run_id':identifier,'source_revision':'fixture','outcome':'assessment-complete',
                'installed':True,'cleanup':'verified-absent-inputs-retained',
                'build':{'candidate_sha256':'c','installed_input_fingerprint':'inputs'}}
        atomic_json(path/'result.json',result)
        atomic_json(path/'qualification.json',{'run_id':identifier,'source_revision':'fixture','candidate_sha256':'c',
            'policy_sha256':'policy','mode':mode,'outcome':'assessment-complete','lab_status':'LAB QUALIFICATION PENDING',
            'cleanup':result['cleanup'],'functional_counts':{'pass':1},'assessment':{},
            'functional_results':[{'id':'fixture-check','status':'pass'}]})
        (path/'assessment/findings.json').write_text(json.dumps({'content_sha256':content,'profile_id':'fixture',
            'rules':[{'rule_id':'fixture-rule','native_status':status}]}))
        (path/'installed-svd.json').write_text(json.dumps({'kernel':'fixture','inventory_complete':True,'snaps':[],
            'packages':[{'name':'fixture','version':'1','architecture':'amd64'}]}))
        return path

    def test_incompatible_benchmarks_do_not_report_security_improvement(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            a=self.run_record(root,'previous')
            b=self.run_record(root,'current',status='pass',content='other')
            delta=compare(a,b)
            self.assertFalse(delta['assessment_comparable'])
            self.assertFalse(delta['equivalent_fresh_installations'])
            self.assertNotIn('resolved',delta['findings_trends'])

    def test_matching_failed_installs_can_be_repeatable_without_qualifying(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            a=self.run_record(root,'previous');b=self.run_record(root,'current')
            delta=compare(a,b)
            self.assertTrue(delta['equivalent_fresh_installations'])
            self.assertEqual(delta['findings_trends']['persistent'],['fixture-rule'])
            self.assertFalse(delta['lab_iso_qualified'])
            self.assertIsNone(delta['findings_trends']['reopened'])

    def test_catalog_escapes_content_and_has_no_external_assets(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            self.run_record(root,'fixture',mode='<img src=x onerror=alert(1)>')
            self.assertEqual(len(catalog(root)),1)
            page=(root/'catalog.html').read_text()
            self.assertNotIn('<img',page)
            self.assertIn('&lt;img',page)
            self.assertNotIn('https://',page)
            self.assertNotIn('<script',page)

    def test_reopened_findings_need_three_compatible_observations(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            first=self.run_record(root,'first',status='fail')
            middle=self.run_record(root,'middle',status='pass')
            last=self.run_record(root,'last',status='fail')
            self.assertEqual(compare(middle,last,earlier=first)['findings_trends']['reopened'],['fixture-rule'])
