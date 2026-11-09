"""Synthetic contract/console regressions, not encrypted VM acceptance."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import shutil
import subprocess
from unittest.mock import patch

from wormhole.ubuntu_encryption import ConsoleUnlock,WRONG_KEY,configure,storage,read_region
from wormhole.runs import RunError


class Encryption(unittest.TestCase):
    def test_controller_reader_changes_reuse_but_installer_changes_invalidate(self):
        from wormhole.ubuntu_inputs import input_identity
        from wormhole import ubuntu_encryption
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'bundle').mkdir();(root/'bundle/manifest.json').write_text('{}')
            first,_=input_identity(root,'hardened',sandbox=True)
            with patch.object(ubuntu_encryption,'read_region',side_effect=RuntimeError('controller-only fixture')):
                second,_=input_identity(root,'hardened',sandbox=True)
            self.assertEqual(first,second)
            with patch.object(ubuntu_encryption,'EARLY',ubuntu_encryption.EARLY+'\n# changed installed input\n'):
                third,_=input_identity(root,'hardened',sandbox=True)
            self.assertNotEqual(first,third)
    @unittest.skipUnless(shutil.which('qemu-img'),'actual qemu-img required for this small real-tool regression')
    def test_actual_qcow2_skip_reads_the_requested_nonzero_region(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);data=bytearray(32768);data[4096:4112]=b'WORMHOLE-REGION!!'
            (root/'raw').write_bytes(data)
            subprocess.run(['qemu-img','convert','-f','raw','-O','qcow2',str(root/'raw'),str(root/'disk')],check=True,capture_output=True)
            read_region(root/'disk',root/'sample',8,2)
            self.assertEqual((root/'sample').stat().st_size,1024)
            self.assertTrue((root/'sample').read_bytes().startswith(b'WORMHOLE-REGION!!'))
    def test_installer_contract_uses_file_not_embedded_secret(self):
        value=configure({'autoinstall':{'late-commands':[],'network':{'version':2}}})
        crypt=next(x for x in storage()['config'] if x['type']=='dm_crypt')
        self.assertEqual(crypt['keyfile'],'/run/wormhole-unlock')
        self.assertNotIn('key',crypt)
        self.assertEqual(value['autoinstall']['late-commands'][0],['bash','/cdrom/wormhole/encryption-late.sh'])
        self.assertEqual(value['autoinstall']['storage']['swap'],{'size':0})

    @unittest.skipIf(os.name=='nt','POSIX owner permissions required')
    def test_missing_secret_and_repeated_prompt_do_not_succeed(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'unlock';unlock=ConsoleUnlock(key);stream=io.BytesIO()
            self.assertFalse(unlock.observe('kernel still booting',stream))
            with self.assertRaises(RunError):unlock.observe('WORMHOLE_INSTALL_UNLOCK_REQUEST',stream)
            key.write_text('A'*64);key.chmod(0o600)
            self.assertFalse(unlock.observe("log: os.write(fd,b'WORMHOLE_INSTALL_UNLOCK_REQUEST')",stream))
            self.assertTrue(unlock.observe('WORMHOLE_INSTALL_UNLOCK_REQUEST',stream))
            self.assertFalse(unlock.observe('WORMHOLE_INSTALL_UNLOCK_REQUEST',stream))
            self.assertTrue(unlock.observe('Please unlock disk wormhole-root:',stream))
            self.assertFalse(unlock.observe('Please unlock disk wormhole-root:',stream))
            self.assertEqual(len(unlock.events),2)
            self.assertNotIn('A'*64,json.dumps(unlock.events))
            log=Path(directory)/'console';log.write_text('A'*64)
            with self.assertRaises(RunError):unlock.check_capture(log)

    @unittest.skipIf(os.name=='nt','POSIX owner permissions required')
    def test_systemd_prompt_requires_real_rejection_before_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'unlock';key.write_text('A'*64);key.chmod(0o600)
            unlock=ConsoleUnlock(key,probes=True,systemd=True);stream=io.BytesIO()
            prompt='Please enter passphrase for disk lab (luks-test):'
            with patch('time.monotonic',return_value=1):self.assertFalse(unlock.observe(prompt,stream))
            with patch('time.monotonic',return_value=12):self.assertTrue(unlock.observe(prompt,stream))
            self.assertNotIn(b'A'*64,stream.getvalue())
            with self.assertRaises(RunError):unlock.observe(prompt+'\n'+prompt,stream)
            rejected=prompt+'\nFailed to activate with specified passphrase. (Passphrase incorrect?)\n'+prompt
            self.assertTrue(unlock.observe(rejected,stream))
            self.assertFalse(unlock.observe(rejected,stream))
            self.assertEqual(unlock.events[-2]['kind'],'wrong-secret-refused')

    @unittest.skipIf(os.name=='nt','POSIX owner permissions required')
    def test_systemd_masked_submission_allows_retry_without_claiming_cryptographic_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'unlock';key.write_text('A'*64);key.chmod(0o600)
            unlock=ConsoleUnlock(key,probes=True,systemd=True);stream=io.BytesIO()
            prompt='Please enter passphrase for disk lab (luks-test):'
            with patch('time.monotonic',return_value=1):self.assertFalse(unlock.observe(prompt,stream))
            with patch('time.monotonic',return_value=12):self.assertTrue(unlock.observe(prompt,stream))
            submitted=prompt+' (press TAB for no echo) \n'+'•'*len(WRONG_KEY)+'\n'
            with self.assertRaises(RunError):
                unlock.observe(submitted+'Please enter passphrase for disk unrelated:',stream)
            self.assertTrue(unlock.observe(submitted+prompt,stream))
            self.assertEqual(unlock.events[-2]['kind'],'wrong-secret-reprompted')
            self.assertTrue(stream.getvalue().endswith(b'A'*64+b'\n'))

    @unittest.skipIf(os.name=='nt','POSIX owner permissions required')
    def test_broad_secret_permissions_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'unlock';key.write_text('A'*64);key.chmod(0o644)
            with self.assertRaises(RunError):ConsoleUnlock(key).observe('WORMHOLE_INSTALL_UNLOCK_REQUEST',io.BytesIO())
