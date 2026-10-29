"""Synthetic comparisons and HTML escaping, separate from real VM evidence."""
import json
import hashlib
import base64
from pathlib import Path
import tempfile
import unittest
from uuid import uuid5,NAMESPACE_URL

from wormhole.runs import atomic_json
from wormhole.ubuntu_catalog import catalog,compare


class Catalog(unittest.TestCase):
    def run_record(self,root,identifier,*,status='fail',content='a',mode='hardened'):
        identifier=str(uuid5(NAMESPACE_URL,'wormhole-synthetic-'+identifier))
        path=root/identifier;path.mkdir(mode=0o700);(path/'assessment').mkdir(mode=0o700)
        result={'run_id':identifier,'source_revision':'fixture','outcome':'assessment-complete',
                'installed':True,'cleanup':'verified-absent-inputs-retained',
                'build':{'candidate_sha256':'c','installed_input_fingerprint':'inputs',
                         'seed_sha256':hashlib.sha256(identifier.encode()).hexdigest()}}
        atomic_json(path/'result.json',result)
        atomic_json(path/'assessment/scanner-receipt.json',{'run_id':identifier,'target':'vm-'+identifier[:8],
            'firstboot_id':str(uuid5(NAMESPACE_URL,identifier+'-first')),'boot_id':str(uuid5(NAMESPACE_URL,identifier+'-final'))})
        (path/'console.log').write_text('WORMHOLE_FINAL_HOST_KEY_BEGIN\nssh-rsa '+
            base64.b64encode(('SYNTHETIC-KEY-'+identifier).encode()).decode()+'\nWORMHOLE_FINAL_HOST_KEY_END\n')
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
            self.assertTrue(delta['independent_installation_identities'])
            self.assertEqual(delta['findings_trends']['persistent'],['fixture-rule'])
            self.assertFalse(delta['lab_iso_qualified'])
            self.assertIsNone(delta['findings_trends']['reopened'])
            unavailable=self.run_record(root,'not-applicable',status='notapplicable')
            changed=compare(a,unavailable)['findings_trends']
            self.assertEqual(changed['resolved'],[])
            self.assertEqual(len(changed['applicability_changes']),1)

    def test_relabelled_installation_cannot_establish_independence(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);a=self.run_record(root,'previous')
            for identity in ('seed','boot','host-key'):
                with self.subTest(identity=identity):
                    b=self.run_record(root,identity)
                    if identity=='seed':
                        record=json.loads((b/'result.json').read_text())
                        record['build']['seed_sha256']=json.loads((a/'result.json').read_text())['build']['seed_sha256']
                        atomic_json(b/'result.json',record)
                    elif identity=='boot':
                        record=json.loads((b/'assessment/scanner-receipt.json').read_text())
                        record['firstboot_id']=json.loads((a/'assessment/scanner-receipt.json').read_text())['boot_id']
                        atomic_json(b/'assessment/scanner-receipt.json',record)
                    else:(b/'console.log').write_bytes((a/'console.log').read_bytes())
                    delta=compare(a,b)
                    self.assertFalse(delta['independent_installation_identities'])
                    self.assertFalse(delta['equivalent_fresh_installations'])

    def test_missing_identity_evidence_preserves_comparison_without_freshness_claim(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);a=self.run_record(root,'previous');b=self.run_record(root,'current')
            (b/'assessment/scanner-receipt.json').unlink()
            delta=compare(a,b)
            self.assertFalse(delta['equivalent_fresh_installations'])
            self.assertEqual(delta['findings_trends']['persistent'],['fixture-rule'])

    def test_cross_run_receipt_cannot_establish_independence(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);a=self.run_record(root,'previous');b=self.run_record(root,'current')
            path=b/'assessment/scanner-receipt.json';record=json.loads(path.read_text())
            record['run_id']=json.loads((a/'result.json').read_text())['run_id']
            atomic_json(path,record)
            self.assertFalse(compare(a,b)['equivalent_fresh_installations'])

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
