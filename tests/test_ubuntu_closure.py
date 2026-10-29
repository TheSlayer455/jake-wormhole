"""Content/probe source regressions. Container and VM results are separate."""
import ctypes
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from wormhole import ubuntu_content_erratum as content
from wormhole.runs import RunError
from wormhole.vm_inputs import sha256


def probe_module():
    path=Path(__file__).resolve().parents[1]/'ubuntu/guest/pkcs11-probe.py'
    spec=importlib.util.spec_from_file_location('pkcs11_probe_fixture',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class Closure(unittest.TestCase):
    def test_native_repair_requires_exact_accessors_and_retains_crl_ownership(self):
        path=Path(__file__).resolve().parents[1]/'ubuntu/support/patch-pam-crl.py'
        spec=importlib.util.spec_from_file_location('pam_repair',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        source='\n'.join(['      rv = X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_get_issuer_name(x509), &obj);',
            'issuer_cert = X509_OBJECT_get0_X509((&obj));',
            'crl = X509_OBJECT_get0_X509_CRL((&obj));',
            'x509_ca = X509_OBJECT_get0_X509((&obj));',
            '  rv = verify_crl(crl, ctx);',
            '  } else if (rv == 0) {\n    return 0;\n  }\n  DBG("checking revocation");'])
        repaired=module.repair(source)
        self.assertIn('X509_CRL_up_ref(crl)',repaired)
        self.assertIn('if (crl == NULL)',repaired)
        self.assertIn('X509_CRL_free(crl);\n    return 0;',repaired)
        self.assertNotIn('((&obj))',repaired)
        self.assertIn('X509_get_issuer_name(x509), obj);',repaired)
        with self.assertRaises(ValueError):module.repair(repaired)
        with self.assertRaises(ValueError):module.repair(source.replace('issuer_cert =','changed =',1))

    def test_corrected_check_accepts_vendor_grammar_and_refuses_wrong_missing_commented_values(self):
        for line in ('  use_mappers = pwent;','\tuse_mappers\t=\tpwent ;  '):
            self.assertIsNotNone(re.fullmatch(content.PATTERN,line))
        for line in ('# use_mappers = pwent;','use_mappers = digest;','use_mappers = pwent','use_mappers = pwent, digest;'):
            self.assertIsNone(re.fullmatch(content.PATTERN,line))

    def test_derivation_preserves_all_other_bytes_and_requires_the_pinned_source(self):
        raw=(b'<root xmlns:o="urn:oval"><profile selected="true"/>'
             b'<o:textfilecontent54_object id="'+content.OBJECT.encode()+b'">'
             b'<o:pattern operation="pattern match">^use_mappers = pwent$</o:pattern>'
             b'</o:textfilecontent54_object><rule severity="low"/></root>')
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);source=root/'original.xml';source.write_bytes(raw)
            with self.assertRaises(RunError):content.derive(source,root/'untrusted.xml')
            with patch.object(content,'UPSTREAM_SHA',sha256(source)):
                receipt=content.derive(source,root/'derived.xml')
                self.assertEqual((root/'derived.xml').read_bytes(),raw.replace(b'^use_mappers = pwent$',content.PATTERN.encode()))
                self.assertTrue(receipt['rule_selection_unchanged'])
                self.assertTrue(receipt['upstream_native_assessment_required'])
                with self.assertRaises(RunError):content.derive(source,root/'derived.xml')

    def test_ambiguous_or_missing_objects_do_not_create_an_output(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);source=root/'original.xml';source.write_text('<root/>')
            with patch.object(content,'UPSTREAM_SHA',sha256(source)):
                with self.assertRaises(RunError):content.derive(source,root/'derived.xml')
            self.assertFalse((root/'derived.xml').exists())

    def test_key_decoder_rejects_truncated_wrong_type_and_multiprime_material(self):
        module=probe_module()
        good=b'\x30\x1b'+b'\x02\x01\0'+b'\x02\x01\1'*8
        self.assertEqual(len(module.der_integers(good)),8)
        for raw in (good[:-1],good.replace(b'\x02\x01\0',b'\x02\x01\1',1),b'\x31'+good[1:]):
            with self.assertRaises((ValueError,IndexError)):module.der_integers(raw)

    def test_pkcs11_attribute_abi_uses_native_ulong_and_pointer_alignment(self):
        module=probe_module()
        self.assertEqual(module.Attribute.value.offset,ctypes.sizeof(ctypes.c_void_p))
        self.assertEqual(ctypes.sizeof(module.Attribute),3*ctypes.sizeof(ctypes.c_void_p))

    def test_supplement_is_not_a_native_pass_or_physical_assurance_claim(self):
        module=probe_module()
        self.assertIn('never physical-token assurance',module.__doc__)
        source=Path(module.__file__).read_text()
        self.assertNotIn('--pin',source)
        self.assertNotIn('--so-pin',source)
