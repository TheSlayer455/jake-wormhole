"""Tiny synthetic consumer bundles test integrity, never real qualification."""
import json
from pathlib import Path
import tempfile
import unittest

from wormhole.ubuntu_release import verify
from wormhole.vm_inputs import sha256
from wormhole.runs import atomic_json,RunError


class Readback(unittest.TestCase):
    def fixture(self,root):
        iso=root/'synthetic.iso';iso.write_bytes(b'SYNTHETIC-NOT-INSTALLABLE')
        manifest={'capability':'lab-qualified-ubuntu-iso','lab_iso_qualified':True,'production_iso_eligible':False,
            'candidate_sha256':sha256(iso),'files':[{'path':iso.name,'bytes':iso.stat().st_size,'sha256':sha256(iso)}]}
        atomic_json(root/'manifest.json',manifest)
        atomic_json(root/'complete.json',{'manifest_sha256':sha256(root/'manifest.json')})
        return iso

    def test_modified_contents_and_unlisted_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);iso=self.fixture(root)
            self.assertEqual(verify(root)['files_verified'],1)
            (root/'extra').write_text('unexpected')
            with self.assertRaises(RunError):verify(root)
            (root/'extra').unlink();iso.write_bytes(b'TAMPERED')
            with self.assertRaises(RunError):verify(root)

    def test_no_completion_marker_is_never_a_release(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);self.fixture(root);(root/'complete.json').unlink()
            with self.assertRaises(RunError) as error:verify(root)
            self.assertEqual(error.exception.code,'publication_incomplete')
