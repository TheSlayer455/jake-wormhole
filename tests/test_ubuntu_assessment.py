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
        for status in ['error','unknown','notchecked','fixed']:
            self.write(status)
            self.assertFalse(self.read()['all_selected_automated_clean'])
        self.write('pass')
        self.assertFalse(self.read(1)['scanner_execution_completed'])
        self.assertFalse(self.read(1)['lab_iso_qualified'])
        self.content.write_text('changed')
        with self.assertRaises(RunError):self.read()
