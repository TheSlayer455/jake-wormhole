"""Synthetic parser negatives; live scans are recorded separately."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from wormhole import ubuntu_assessment as a
from wormhole.runs import RunError

class Assessment(unittest.TestCase):
    def test_prospective_lab_scope_preserves_native_controls_and_historical_policy(self):
        previous=a.POLICY.with_name('ubuntu-lab-policy-v1.json')
        self.assertEqual(a.digest(previous),'246d12d3537ad69c57d5aa40ac8c57796fc568b693fc8c31a68b1d7288dddcb4')
        old=json.loads(previous.read_text());current=json.loads(a.POLICY.read_text())
        self.assertEqual(current['supersedes'],old['policy_id'])
        self.assertNotEqual(a.digest(a.POLICY),a.digest(previous))
        self.assertFalse(current['lab_scope']['physical_token_required'])
        self.assertEqual(current['lab_scope']['physical_token_assurance'],'unverified')
        self.assertNotIn('physical-token-authentication-assurance',current['unresolved_requirements'])
        self.assertIn('delegated-lab-trust-anchor-review',current['unresolved_requirements'])
        self.assertIn('authorized-guest-procedure-for-usg-and-fips-updates',current['unresolved_requirements'])
        self.assertFalse(current['lab_scope']['historical_results_requalified'])
        self.assertFalse(current['production_iso_eligible'])
        for key in ('content','tailoring','requirements','functional_checks'):
            self.assertEqual(current[key],old[key])

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        x=a.X
        content=ET.Element('datastream')
        profile=ET.SubElement(content,x+'Profile',id='profile')
        ET.SubElement(profile,x+'select',idref='rule-a',selected='true')
        for name in ['rule-a','rule-b']:
            r=ET.SubElement(content,x+'Rule',id=name,severity='high')
            ET.SubElement(r,x+'title').text=name
        self.content=self.root/'content.xml'
        ET.ElementTree(content).write(self.content)
        self.policy={'content':{'datastream_sha256':a.digest(self.content),'profile_id':'profile'},
                     'unresolved_requirements':['fips-pending']}
        self.result=self.root/'result.xml'
        self.write('fail')

    def tearDown(self):self.tmp.cleanup()

    def write(self,status,*,target='vm-fixture',second=True):
        x=a.X;r=ET.Element(x+'Benchmark')
        t=ET.SubElement(r,x+'TestResult')
        ET.SubElement(t,x+'profile',idref='profile')
        ET.SubElement(t,x+'target').text=target
        for name,state in [('rule-a',status)]+([('rule-b','notselected')] if second else []):
            q=ET.SubElement(t,x+'rule-result',idref=name)
            ET.SubElement(q,x+'result').text=state
        ET.ElementTree(r).write(self.result)

    def read(self,rc=2):
        return a.read_results(self.content,self.result,expected_target='vm-fixture',scanner_exit=rc,policy=self.policy)

    def test_full_inventory_retains_failure_and_upstream_notselected(self):
        r=self.read()
        self.assertTrue(r['scanner_execution_completed'])
        self.assertEqual(r['native_counts'],{'fail':1,'notselected':1})
        self.assertTrue(r['coverage_complete'])
        self.assertFalse(r['all_selected_automated_clean'])
        self.assertFalse(r['lab_iso_qualified'])

    def test_missing_and_wrong_target_never_become_zero_findings(self):
        self.write('pass',second=False)
        self.assertFalse(self.read()['coverage_complete'])
        self.assertEqual(self.read()['native_counts']['missing'],1)
        self.write('pass',target='other-vm')
        with self.assertRaises(RunError):self.read()

    def test_error_unknown_unchecked_are_not_passes(self):
        for status in ['error','unknown','notchecked','fixed','informational']:
            self.write(status)
            self.assertFalse(self.read()['all_selected_automated_clean'])
        self.write('pass')
        self.assertFalse(self.read(1)['scanner_execution_completed'])
        self.assertFalse(self.read(1)['lab_iso_qualified'])
        with self.assertRaises(RunError):self.read(False)
        self.content.write_text('changed')
        with self.assertRaises(RunError):self.read()

    def test_known_manual_rule_remains_notchecked_and_requires_separate_evidence(self):
        self.write('pass')
        identifier='xccdf_org.ssgproject.content_rule_only_allow_dod_certs'
        tree=ET.parse(self.content);root=tree.getroot()
        ET.SubElement(root.find(a.X+'Profile'),a.X+'select',idref=identifier,selected='true')
        ET.SubElement(root,a.X+'Rule',id=identifier,severity='high')
        tree.write(self.content);self.policy['content']['datastream_sha256']=a.digest(self.content)
        tree=ET.parse(self.result);test=tree.getroot().find(a.X+'TestResult')
        row=ET.SubElement(test,a.X+'rule-result',idref=identifier)
        ET.SubElement(row,a.X+'result').text='notchecked';tree.write(self.result)
        observed=self.read()
        self.assertTrue(observed['all_selected_automated_clean'])
        self.assertEqual(observed['native_counts']['notchecked'],1)
        self.assertEqual(observed['selected_manual_rule_count'],1)
        self.assertFalse(observed['lab_iso_qualified'])

    def test_upstream_group_deselection_is_not_a_missing_rule(self):
        tree=ET.parse(self.content);root=tree.getroot()
        profile=next(root.iter(a.X+'Profile'))
        ET.SubElement(profile,a.X+'select',idref='group-unused',selected='false')
        group=ET.SubElement(root,a.X+'Group',id='group-unused')
        rule=ET.SubElement(group,a.X+'Rule',id='rule-c',selected='true',severity='low')
        ET.SubElement(rule,a.X+'title').text='Unused group rule'
        tree.write(self.content)
        self.policy['content']['datastream_sha256']=a.digest(self.content)
        plan=a.inventory(self.content,self.policy)
        self.assertFalse(plan['rule-c']['selected'])
        self.assertEqual(len(plan),3)

    def test_unimplemented_tailoring_cannot_hide_a_selected_rule(self):
        self.policy['tailoring']={'excluded_rules':['rule-a'],'parameters':{},'owner_approved_exceptions':[]}
        with self.assertRaises(RunError) as refused:self.read()
        self.assertEqual(refused.exception.code,'unsupported_assessment_tailoring')

    def test_lab_value_tailoring_preserves_parent_and_cannot_weaken_other_controls(self):
        from wormhole.ubuntu_tailoring import document,VALUES,PROFILE
        self.policy['tailoring']={'excluded_rules':[],'parameters':dict(VALUES),'owner_approved_exceptions':[]}
        tree=ET.fromstring(document(self.policy));profile=tree.find(a.X+'Profile')
        self.assertEqual(profile.get('extends'),'profile')
        self.assertEqual(profile.get('id'),PROFILE)
        self.assertEqual(list(profile.iter(a.X+'select')),[])
        self.assertEqual(len(profile.findall(a.X+'set-value')),2)
        self.policy['tailoring']['parameters']['remote_login_banner_text']='.*'
        with self.assertRaises(RunError):document(self.policy)
        self.policy['tailoring']['parameters']={'is_fips_mode_enabled':'false'}
        with self.assertRaises(RunError):document(self.policy)

    def test_manual_revision_mapping_does_not_claim_scanner_equivalence(self):
        from wormhole.ubuntu_coverage import reconcile
        def manual(path,release,checks):
            root=ET.Element(a.X+'Benchmark')
            ET.SubElement(root,a.X+'version').text='2'
            ET.SubElement(root,a.X+'plain-text',id='release-info').text=release
            for key,text in checks.items():
                rule=ET.SubElement(root,a.X+'Rule',id=key,severity='high')
                ET.SubElement(rule,a.X+'version').text=key
                check=ET.SubElement(rule,a.X+'check')
                ET.SubElement(check,a.X+'check-content').text=text
            ET.ElementTree(root).write(path)
        old=self.root/'old.xml';new=self.root/'new.xml'
        manual(old,'Release: 7',{'UBTU-22-123456':'original check'})
        manual(new,'Release: 8',{'UBTU-22-123456':'changed check','UBTU-22-123457':'new check'})
        rows=[{'rule_id':'synthetic','selected':True,'native_status':'pass','references':[{'value':'UBTU-22-123456'}]}]
        report=reconcile(rows,old,new)
        self.assertFalse(report['manual_revision_mapping_complete'])
        self.assertFalse(report['scanner_logic_equivalence_established'])
        self.assertEqual(report['unmapped_controls'],['UBTU-22-123457'])
        self.assertEqual(report['changed_controls'][0]['changed_fields'],['check'])

    def test_secret_identity_is_not_in_installer_command_arguments(self):
        from wormhole.ubuntu_inputs import seed_config,grub_password_hash
        from uuid import uuid4
        value=seed_config(str(uuid4()),'ssh-rsa '+'A'*500,'192.0.2.10/24','52:54:00:11:22:33','$6$private$hash')
        self.assertNotIn('$6$private$hash',value)
        self.assertIn('CIDATA',value)
        self.assertIn('lab.service ALL=(ALL) ALL',value)
        self.assertNotIn('NOPASSWD',value)
        boot=grub_password_hash('synthetic-boot-credential',b'a'*64)
        value=seed_config(str(uuid4()),'ssh-rsa '+'A'*500,'192.0.2.10/24','52:54:00:11:22:33','$6$private$hash',boot)
        self.assertNotIn(boot,value)
        self.assertNotIn('synthetic-boot-credential',value)
        self.assertIn('boot-password-hash',value)
