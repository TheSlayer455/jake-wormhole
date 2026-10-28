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
