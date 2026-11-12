"""Focused RHEL release-gate fixtures; synthetic bytes make no runtime claim."""
from collections import Counter
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole import rhel_hardening as hardening
from wormhole import rhel_release as release
from wormhole.rhel_assessment import HARDENED_CHECKS
from wormhole.rhel_manual import MANUAL_RULES
from wormhole.runs import RunError, atomic_json
from wormhole.vm_inputs import sha256
class RHELRelease(unittest.TestCase):
    def policy(self,root,*,resolved=False):
        policy=json.loads(hardening.POLICY.read_text())
        if resolved:policy['unresolved_requirements']=[]
        path=root/'policy.json';path.write_text(json.dumps(policy));return path
    def oe(self,root,*,verified=False):
        value=json.loads(release.OE_REFERENCE.read_text())
        value['cryptographic_module_operational_environment_verified']=verified
        value['decision']='verified' if verified else 'blocked'
        if verified:
            value['modules']={module:{'status':'validated','certificate':'fixture-'+module,
                'package_name':package,'allowed_nevras':[package+'-1-1.el10.x86_64'],
                'operating_environments':[value['declared_environment']]}
                for module,package in release.MODULE_PACKAGE_NAMES.items()}
        path=root/'oe.json';path.write_text(json.dumps(value));return path
    def parser(self):
        return patch('wormhole.rhel_assessment.read_results',return_value={
            'rules':self.native_rules,'native_counts':dict(Counter(row['native_status'] for row in self.native_rules))})

    def fixture(self,root,candidate,marker):
        run=root/str(uuid4());run.mkdir(mode=0o700);(run/'assessment').mkdir(mode=0o700);(run/'inputs').mkdir(mode=0o700)
        identifier=run.name;install_boot,final_boot=str(uuid4()),str(uuid4())
        contract=hardening.installation_contract();candidate_hash=sha256(candidate)
        build={'capability':hardening.CAPABILITY,'mode':'hardened','candidate_sha256':candidate_hash,
            'seed_sha256':marker*64,'assessment_content':dict(hardening.CONTENT),
            'policy_sha256':sha256(hardening.POLICY),'installation_contract':contract,
            'installed_input_fingerprint':hardening.fingerprint(contract)}
        from wormhole.vm_baseline import controller_checks
        result={'schema_version':'1.0','capability':'real-iso-installation-baseline','run_id':identifier,
            'source_revision':'f'*40,'distribution':'rhel10','provisioner':'terraform','scenario':'healthy',
            'outcome':'baseline-passed','installed':True,'final_authentication':True,'ansible_ready':True,
            'cold_start_verified':True,'cleanup':'verified-absent-inputs-retained','build':build,
            'checks':dict.fromkeys(controller_checks([],assessment=True),'pass'),
            'hardened_checks':dict.fromkeys(HARDENED_CHECKS,'pass'),
            'offline_encryption':{'powered_off_logical_read':True,'luks_magic_verified':True,
                'correct_key_accepted':True,'wrong_key_refused':True,'missing_key_refused':True,
                'disk_modified':False,'swap':'encrypted-lvm'},
            'lab_iso_qualified':False,'production_iso_eligible':False}
        atomic_json(run/'result.json',result);atomic_json(run/'inputs/build-manifest.json',build)
        rules=[{'rule_id':rule,'native_status':'notchecked'} for rule in MANUAL_RULES]
        rules.append({'rule_id':hardening.SSSD_CERTMAP_RULE,'native_status':'notselected'})
        rules += [{'rule_id':f'pass-{n}','native_status':'pass'} for n in range(433)]
        rules += [{'rule_id':f'na-{n}','native_status':'notapplicable'} for n in range(29)]
        rules += [{'rule_id':f'ns-{n}','native_status':'notselected'} for n in range(600)]
        self.native_rules=rules
        runtime={name:{'status':'observed','returncode':0,'stdout':'observed','stderr':'',
            'truncated':False,'error':None} for name in ('openssl_providers','kernel_release','virtualization')}
        assessment={'schema_version':'1.0','run_id':identifier,'boot_id':final_boot,
            'content_sha256':hardening.CONTENT['sha256'],'profile_id':hardening.LAB_PROFILE,
            'scanner_execution_completed':True,'coverage_complete':True,'upstream_rule_count':1073,
            'native_counts':dict(Counter(row['native_status'] for row in rules)),'rules':rules,
            'all_functional_checks_pass':True,
            'functional_results':[{'id':name,'status':'pass'} for name in HARDENED_CHECKS],
            'crypto_runtime':runtime,'lab_iso_qualified':False,'production_iso_eligible':False}
        atomic_json(run/'assessment.json',assessment);(run/'assessment.txt').write_text('synthetic\n')
        receipt={'run_id':identifier,'target':'vm-'+identifier[:8],'content_sha256':hardening.CONTENT['sha256'],
            'profile_id':hardening.LAB_PROFILE,'tailoring_sha256':contract['tailoring_sha256'],
            'remediation_during_assessment':False,'installation_boot_id':install_boot,
            'boot_id':final_boot,'kernel':'6.12.0-fixture','scanner_exit':0}
        for name in release.NATIVE_FILES:
            if name=='receipt.json':atomic_json(run/'assessment'/name,receipt)
            else:(run/'assessment'/name).write_text('synthetic '+name+'\n')
        assessment['native_hashes']={name:sha256(run/'assessment'/name) for name in release.NATIVE_FILES}
        atomic_json(run/'assessment.json',assessment)
        objective={rule:{'disposition':'not-applicable' if rule.endswith(('libreswan_approved_tunnels',
            'ssh_keys_passphrase_protected','sssd_has_trust_anchor')) else 'satisfied',
            'observed_satisfied':True,'reason':'synthetic fixture'} for rule in MANUAL_RULES}
        manual={'schema_version':'1.0','run_id':identifier,'candidate_sha256':candidate_hash,
            'policy_sha256':sha256(hardening.POLICY),'content_sha256':hardening.CONTENT['sha256'],
            'tailoring_sha256':contract['tailoring_sha256'],
            'native_statuses':{rule:'notchecked' for rule in MANUAL_RULES},
            'native_notchecked_statuses_preserved':True,'objective_results':objective,
            'all_required_manual_evidence_complete':True,'exception_approved':False}
        atomic_json(run/'manual-evidence.json',manual)
        packages=[{'name':name,'epoch':'0','version':'1','release':'1.el10','architecture':'x86_64'}
            for name in release.MODULE_PACKAGES]
        svd={'schema_version':'1.0','run_id':identifier,'source_revision':'f'*40,
            'candidate_sha256':candidate_hash,'boot_id':final_boot,'kernel':'6.12.0-fixture',
            'package_manager':'rpm','packages':packages,'rpm_key_headers':[],
            'inventory_complete':True,'production_iso_eligible':False}
        atomic_json(run/'installed-svd.json',svd);(run/'installed-svd.txt').write_text('synthetic\n')
        (run/'console.log').write_text('WORMHOLE_FINAL_HOST_KEY_BEGIN\nssh-rsa '+marker*64+' fixture\nWORMHOLE_FINAL_HOST_KEY_END\n')
        release.crypto_evidence(run)
        return run

    def test_pending_real_policy_refuses_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            with self.assertRaises(RunError) as failure:
                release.publish(root/'current',root/'previous',candidate=root/'candidate.iso',
                    destination=root,name='Jake-RHEL-10-LAB-QUALIFIED-fixture')
            self.assertEqual(failure.exception.code,'lab_policy_dependencies_pending')
            self.assertEqual(list(root.iterdir()),[])

    def test_evaluator_preserves_native_manual_status_and_rejects_cross_identity(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);candidate=root/'candidate.iso';candidate.write_bytes(b'synthetic')
            run=self.fixture(root,candidate,'a')
            with self.parser():report=release.evaluate(run)
            self.assertEqual(report['native_counts'],{'notchecked':10,'notselected':601,'pass':433,'notapplicable':29})
            self.assertIn('cryptographic-module-operational-environment-unverified',report['qualification_reasons'])
            self.assertFalse(report['lab_iso_qualified'])
            with self.parser():self.assertEqual(release.evaluate(run),report)
            crypto=json.loads((run/'crypto-operating-environment.json').read_text())
            crypto['observed']['module_packages']['nss']['version']='changed'
            atomic_json(run/'crypto-operating-environment.json',crypto)
            with self.parser(),self.assertRaises(RunError) as failure:release._load(run)
            self.assertEqual(failure.exception.code,'release_crypto_evidence_invalid')
            (run/'crypto-operating-environment.json').unlink();release.crypto_evidence(run)
            native=run/'assessment/xccdf.xml';original=native.read_bytes();native.write_bytes(b'changed')
            with self.parser(),self.assertRaises(RunError) as failure:release.evaluate(run)
            self.assertEqual(failure.exception.code,'release_native_assessment_missing')
            native.write_bytes(original)
            manifest=json.loads((run/'inputs/build-manifest.json').read_text());manifest['candidate_sha256']='0'*64
            atomic_json(run/'inputs/build-manifest.json',manifest)
            with self.parser(),self.assertRaises(RunError) as failure:release.evaluate(run)
            self.assertEqual(failure.exception.code,'release_build_manifest_mismatch')
            atomic_json(run/'inputs/build-manifest.json',json.loads((run/'result.json').read_text())['build'])
            manual=json.loads((run/'manual-evidence.json').read_text());manual['candidate_sha256']='0'*64
            atomic_json(run/'manual-evidence.json',manual)
            with self.parser(),self.assertRaises(RunError) as failure:release.evaluate(run)
            self.assertEqual(failure.exception.code,'release_manual_requirements_pending')

    def test_resolved_synthetic_pair_publishes_and_reads_exact_bytes(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);candidate=root/'candidate.iso';candidate.write_bytes(b'SYNTHETIC-NOT-INSTALLABLE')
            policy=self.policy(root,resolved=True);oe=self.oe(root,verified=True)
            with ExitStack() as stack:
                stack.enter_context(patch.object(hardening,'POLICY',policy));stack.enter_context(patch.object(release,'POLICY',policy))
                stack.enter_context(patch.object(release,'OE_REFERENCE',oe))
                previous=self.fixture(root,candidate,'a');current=self.fixture(root,candidate,'b')
                stack.enter_context(self.parser())
                release.evaluate(previous);release.evaluate(current)
                manifest=release._publish(current,previous,candidate=candidate,destination=root,
                    name='Jake-RHEL-10-LAB-QUALIFIED-fixture')
            output=root/'Jake-RHEL-10-LAB-QUALIFIED-fixture'
            self.assertEqual(manifest['candidate_sha256'],sha256(candidate))
            self.assertEqual(release.verify(output)['candidate_sha256'],sha256(candidate))
            self.assertEqual((output/'Jake-RHEL-10-LAB-QUALIFIED-fixture.iso').read_bytes(),candidate.read_bytes())
            self.assertFalse(json.loads((output/'release-decision.json').read_text())['production_iso_eligible'])

    def publication(self,root):
        candidate=root/'candidate.iso';candidate.write_bytes(b'SYNTHETIC-NOT-INSTALLABLE')
        policy=self.policy(root,resolved=True);oe=self.oe(root,verified=True)
        with ExitStack() as stack:
            stack.enter_context(patch.object(hardening,'POLICY',policy));stack.enter_context(patch.object(release,'POLICY',policy))
            stack.enter_context(patch.object(release,'OE_REFERENCE',oe))
            previous=self.fixture(root,candidate,'a');current=self.fixture(root,candidate,'b');stack.enter_context(self.parser())
            release.evaluate(previous);release.evaluate(current)
            release._publish(current,previous,candidate=candidate,destination=root,
                name='Jake-RHEL-10-LAB-QUALIFIED-fixture')
        return root/'Jake-RHEL-10-LAB-QUALIFIED-fixture'

    def test_consumer_rejects_incomplete_tampered_extra_and_unsafe_files(self):
        for action,code in (('incomplete','publication_incomplete'),('tampered','publication_file_changed'),
                ('extra','publication_file_set_changed'),('traversal','publication_path_invalid'),
                ('symlink','publication_file_invalid'),('inconsistent','publication_installation_evidence_invalid')):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as value:
                output=self.publication(Path(value))
                if action=='incomplete':(output/'complete.json').unlink()
                elif action=='tampered':next(output.glob('*.iso')).write_bytes(b'CHANGED')
                elif action=='extra':(output/'extra').write_text('unexpected')
                elif action in {'traversal','symlink'}:
                    manifest=json.loads((output/'manifest.json').read_text())
                    if action=='traversal':manifest['files'][0]['path']='../escape'
                    else:
                        target=output/'SHA256SUMS';target.unlink();target.symlink_to('policy.json')
                        row=next(row for row in manifest['files'] if row['path']=='SHA256SUMS')
                        row.update(bytes=(output/'policy.json').stat().st_size,sha256=sha256(output/'policy.json'))
                    atomic_json(output/'manifest.json',manifest)
                    atomic_json(output/'complete.json',{'manifest_sha256':sha256(output/'manifest.json')})
                else:
                    path=output/'installation-1/qualification.json';qualification=json.loads(path.read_text())
                    qualification['policy_sha256']='0'*64;atomic_json(path,qualification)
                    manifest=json.loads((output/'manifest.json').read_text())
                    row=next(row for row in manifest['files'] if row['path']=='installation-1/qualification.json')
                    row.update(bytes=path.stat().st_size,sha256=sha256(path));atomic_json(output/'manifest.json',manifest)
                    atomic_json(output/'complete.json',{'manifest_sha256':sha256(output/'manifest.json')})
                with self.assertRaises(RunError) as failure:release.verify(output)
                self.assertEqual(failure.exception.code,code)


if __name__=='__main__':unittest.main()
