"""Synthetic service-isolation/provider negatives; real integrations are separate."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
import importlib.util
from unittest.mock import patch
from types import SimpleNamespace

from wormhole.ubuntu_sandbox import network_filter,BIND,GUEST
from wormhole.ubuntu_secrets import status,put,read
from wormhole.runs import RunError


class Sandbox(unittest.TestCase):
    @unittest.skipIf(os.name=='nt','POSIX private delivery modes required')
    def test_private_guest_config_is_ephemeral_and_vendor_output_is_not_returned(self):
        source=Path(__file__).resolve().parents[1]/'ubuntu/guest/entitlement.py'
        spec=importlib.util.spec_from_file_location('entitlement_fixture',source)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        calls=[]
        token='SYNTHETIC-NOT-A-VENDOR-TOKEN'
        def runner(args,**kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0 if '--help' in args else 1,stdout=b'--attach-config '+token.encode(),stderr=token.encode())
        original=tempfile.TemporaryDirectory
        with original() as directory:
            def temporary(**kwargs):return original(prefix=kwargs['prefix'],dir=directory)
            with patch.object(module.tempfile,'TemporaryDirectory',side_effect=temporary):
                probe=module.execute({'operation':'probe','token':token},runner)
                self.assertTrue(probe['ephemeral_config_removed'])
                self.assertFalse(probe['vendor_contacted'])
                self.assertEqual(calls,[])
                refused=module.execute({'operation':'enroll','token':token},runner)
                self.assertEqual(refused['attach_returncode'],1)
                self.assertTrue(refused['ephemeral_config_removed'])
                self.assertNotIn(token,json.dumps(refused)+json.dumps(calls))
            self.assertEqual(list(Path(directory).iterdir()),[])
    def test_only_declared_new_connections_precede_default_deny(self):
        root=ET.fromstring(network_filter('wormhole-test'))
        rules=root.findall('rule')
        new=[r for r in rules if r[0].get('state')=='NEW']
        self.assertEqual({(r.get('direction'),r[0].tag,r[0].get('dstportstart')) for r in new},
                         {('in','tcp','22'),('out','tcp','6514'),('out','tcp','6000'),('out','udp','12345')})
        self.assertTrue(all(r[0].get('dstipaddr')==BIND for r in new if r.get('direction')=='out'))
        self.assertEqual(rules[-1].get('action'),'drop')
        self.assertEqual(rules[-1][0].tag,'mac')
        self.assertTrue(any(r[0].tag=='mac' and r.get('action')=='accept' and r[0].get('protocolid')=='0x0800' for r in rules))
        self.assertNotEqual(BIND,GUEST)

    @unittest.skipIf(os.name=='nt','POSIX ownership required')
    def test_provider_explicit_slot_absence_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            self.assertFalse(status(root)['ubuntu_pro_present'])
            with self.assertRaises(RunError):read(root,'ubuntu-pro')
            with self.assertRaises(RunError):read(root,'another-secret')
            source=root/'owner-input';source.write_text('SYNTHETIC-NOT-A-REAL-ENTITLEMENT');source.chmod(0o600)
            result=put(root,'ubuntu-pro',source)
            self.assertTrue(result['ubuntu_pro_present'])
            self.assertNotIn('SYNTHETIC',json.dumps(result))
            self.assertFalse(result['vendor_entitlement_verified'])
            with self.assertRaises(FileExistsError):put(root,'ubuntu-pro',source)
            (root/'ubuntu-pro').chmod(0o644)
            with self.assertRaises(RunError):status(root)
