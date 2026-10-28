"""Synthetic contract/console regressions, not encrypted VM acceptance."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from wormhole.ubuntu_encryption import ConsoleUnlock,configure,storage
from wormhole.runs import RunError


class Encryption(unittest.TestCase):
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
    def test_broad_secret_permissions_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'unlock';key.write_text('A'*64);key.chmod(0o644)
            with self.assertRaises(RunError):ConsoleUnlock(key).observe('WORMHOLE_INSTALL_UNLOCK_REQUEST',io.BytesIO())
