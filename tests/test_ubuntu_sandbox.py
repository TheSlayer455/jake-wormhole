"""Synthetic service-isolation/provider negatives; real integrations are separate."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
import importlib.util
import base64
import hashlib
import shutil
import subprocess
import zlib
from unittest.mock import patch
from types import SimpleNamespace

from wormhole.ubuntu_sandbox import network_filter,BIND,GUEST,canonical_rules,verify_audit_archive,certificates
from wormhole.ubuntu_secrets import status,put,read
from wormhole.runs import RunError


class Sandbox(unittest.TestCase):
    def test_durable_archive_ack_is_bound_to_the_transfer_and_run(self):
        source=Path(__file__).resolve().parents[1]/'ubuntu/guest/audit-offload.py'
        spec=importlib.util.spec_from_file_location('audit_fixture',source)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.confirm_ack(b'{"run_id":"fixture-run","archive_saved":"fixture-transfer"}\n','fixture-run','fixture-transfer')
        for raw in (b'{}',b'{"run_id":"other","archive_saved":"fixture-transfer"}',b''):
            with self.assertRaises((RuntimeError,ValueError)):module.confirm_ack(raw,'fixture-run','fixture-transfer')
    def test_audit_archive_readback_rejects_missing_chunks_and_changed_bytes(self):
        content=b'SYNTHETIC audit event\n'*100
        rows=[{'kind':'chunk','file':'audit.log','index':0,'data':base64.b64encode(zlib.compress(content)).decode()},
              {'kind':'complete','files':[{'file':'audit.log','bytes':len(content),'sha256':hashlib.sha256(content).hexdigest(),'chunks':1}]}]
        self.assertTrue(verify_audit_archive(rows))
        with self.assertRaises(RunError):verify_audit_archive(rows[1:])
        rows[1]['files'][0]['sha256']='0'*64
        with self.assertRaises(RunError):verify_audit_archive(rows)

    @unittest.skipUnless(shutil.which('openssl'),'real OpenSSL executable required')
    def test_disposable_ca_actually_accepts_valid_and_refuses_revoked_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            private=certificates(directory)
            args=['openssl','verify','-CAfile',str(private/'ca.crt'),'-CRLfile',str(private/'ca.crl'),'-crl_check']
            self.assertEqual(subprocess.run(args+[str(private/'active.crt')],capture_output=True,timeout=10).returncode,0)
            revoked=subprocess.run(args+[str(private/'revoked.crt')],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(revoked.returncode,0)
            self.assertIn('certificate revoked',revoked.stderr)
            request=private/'request.der';response=private/'response.der'
            for name,status in (('active','good'),('revoked','revoked')):
                client=['openssl','ocsp','-issuer',str(private/'ca.crt'),'-cert',str(private/(name+'.crt'))]
                subprocess.run(client+['-reqout',str(request)],check=True,capture_output=True,timeout=10)
                subprocess.run(['openssl','ocsp','-index',str(private/'index'),'-CA',str(private/'ca.crt'),
                    '-rsigner',str(private/'responder.crt'),'-rkey',str(private/'responder.key'),'-reqin',str(request),
                    '-respout',str(response),'-rmd','sha256','-nmin','1'],check=True,capture_output=True,timeout=10)
                verified=subprocess.run(['openssl','ocsp','-reqin',str(request),'-respin',str(response),'-CAfile',str(private/'ca.crt')],
                    capture_output=True,text=True,timeout=10)
                self.assertEqual(verified.returncode,0)
                self.assertIn('Response verify OK',verified.stderr)
    def test_libvirt_canonical_xml_is_equivalent_but_changed_policy_is_not(self):
        original=network_filter('wormhole-test')
        actual=original.replace('0x0800','ipv4')
        self.assertEqual(canonical_rules(ET.fromstring(original)),canonical_rules(ET.fromstring(actual)))
        changed=actual.replace('dstportstart="6514"','dstportstart="22"')
        self.assertNotEqual(canonical_rules(ET.fromstring(original)),canonical_rules(ET.fromstring(changed)))
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
                detached=module.execute({'operation':'detach'},runner)
                self.assertEqual(detached['returncode'],1)
                self.assertFalse(detached['vendor_cleanup_verified'])
            self.assertEqual(list(Path(directory).iterdir()),[])
    def test_only_declared_new_connections_precede_default_deny(self):
        root=ET.fromstring(network_filter('wormhole-test'))
        rules=root.findall('rule')
        new=[r for r in rules if r[0].get('state')=='NEW']
        self.assertEqual({(r.get('direction'),r[0].tag,r[0].get('dstportstart')) for r in new},
                         {('in','tcp','22'),('out','tcp','6514'),('out','tcp','6000'),('out','tcp','8080'),('out','udp','12345')})
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
