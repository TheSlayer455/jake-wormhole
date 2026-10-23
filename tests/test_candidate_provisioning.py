"""Candidate target/stock controller separation; all Docker/Terraform mocked."""
from copy import deepcopy
import json
import os
import unittest
from unittest.mock import patch

import test_provisioning as base
from test_candidate import DERIVED
from wormhole import candidate as c, rpm_candidate as rc, rpm_assembly as assembly, rpm_target, provisioning as p, images
from wormhole.runs import read_json,atomic_json,atomic_bytes


class RuntimeCapabilityPlans(unittest.TestCase):
    def test_only_explicit_typed_session_policy_can_authorize_ubi_audit_write(self):
        standard=list(images.TARGET_CAPS)
        self.assertEqual(set(standard),{'SETUID','SETGID','SYS_CHROOT'})
        stock=base.inputs();stock['target_capabilities']=standard
        p.validate_plan(base.plan(stock),stock)
        ubi=deepcopy(stock);ubi['target_capabilities']=standard+['AUDIT_WRITE']
        with self.assertRaises(p.ProvisioningError):p.validate_plan(base.plan(ubi),ubi)
        p.validate_plan(base.plan(ubi),ubi,runtime_policy=p.TargetRuntimePolicy.UBI9_AUDIT_WRITE)
        for bad in ('ubi9-ssh-audit-write-v1',True,{'id':'ubi9-ssh-audit-write-v1'}):
            with self.subTest(bad=bad),self.assertRaises(p.ProvisioningError):
                p.validate_plan(base.plan(ubi),ubi,runtime_policy=bad)
        for caps in (standard,standard+['AUDIT_CONTROL'],standard+['AUDIT_READ'],standard+['KILL'],
            standard+['AUDIT_WRITE','AUDIT_CONTROL'],standard+['AUDIT_WRITE','AUDIT_WRITE']):
            value=deepcopy(ubi);value['target_capabilities']=caps
            with self.subTest(caps=caps),self.assertRaises(p.ProvisioningError):
                p.validate_plan(base.plan(value),value,runtime_policy=p.TargetRuntimePolicy.UBI9_AUDIT_WRITE)
        # A valid input record cannot hide extra capabilities in either saved
        # plan representation, even when both representations agree.
        value=base.plan(ubi)
        value['planned_values']['root_module']['resources'][1]['values']['capabilities'][0]['add'].append('KILL')
        value['resource_changes'][1]['change']['after']['capabilities'][0]['add'].append('KILL')
        with self.assertRaises(p.ProvisioningError):p.validate_plan(value,ubi,runtime_policy=p.TargetRuntimePolicy.UBI9_AUDIT_WRITE)


@unittest.skipUnless(os.name == 'posix', 'Linux provisioning policy fixture; Docker/Terraform mocked')
class CandidateProvisioning(unittest.TestCase):
    policy = c
    operation_name = 'candidate-image-binding'
    expected_binding_version = 1

    def setUp(self):
        base.Controller.setUp(self)
        self.binding = {'operation': self.operation_name, 'image_id': DERIVED, 'image_labels': {**self.image_labels, images.LABEL + '.candidate_sha256': 'e' * 64}}
        self.lease.record['resources'].append({'kind': 'image', 'id': DERIVED, 'outcome': 'retained'})
        with patch.object(self.policy, 'validate_binding', return_value=deepcopy(self.binding)), patch.object(self.policy, 'verify_image'), patch.object(images, 'inspect'):
            self.session = p.ProvisioningSession(self.run, self.lease, toolchain=self.tools, target_binding=self.binding)

    def container(self, identity):
        value = base.Controller.container(self, identity)
        if identity == base.CID:
            value['Image'] = DERIVED
            value['Config']['Labels'] = {**self.binding['image_labels'], **self.session.labels('target')}
        return value

    def inspect(self, *args, **options): return base.Controller.inspect(self, *args, **options)
    def docker(self, *args, **options): return base.Controller.docker(self, *args, **options)
    def patches(self): return base.Controller.patches(self)
    def operation(self, name):
        value = base.Controller.operation(self, name)
        if name == 'output': value['run']['value']['targets']['target-001']['image'] = DERIVED
        return value

    def test_only_target_uses_derived_image_and_retained_controller_context_is_explicit(self):
        with self.patches():
            inventory = self.session.provision()
            controller = self.container(base.CONTROLLER); target = self.container(base.CID)
            self.assertEqual(controller['Image'], p.TARGET_IMAGE); self.assertEqual(target['Image'], DERIVED)
            self.assertEqual(self.session.variables['image'], DERIVED)
            self.assertEqual(inventory['targets'][0]['image_digest'], DERIVED)
            context = read_json(self.run.file('private/terraform/controller.json'))
            self.assertEqual(context['target_binding_version'], self.expected_binding_version); self.assertEqual(context['target_binding'], self.binding)
            self.assertEqual(context['target_runtime_policy'],self.session.target_runtime_policy.record())
            wrong = deepcopy(target); wrong['Image'] = p.TARGET_IMAGE
            with self.assertRaises(p.ProvisioningError): self.session.verify_target(wrong)
            result = self.session.destroy()
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(self.lease.record['resources'][0]['outcome'], 'retained')

    def test_retained_candidate_cleanup_revalidates_explicit_binding_without_candidate_data_execution(self):
        with self.patches():
            self.session.provision(); self.running[base.CONTROLLER] = False
            self.lease._reconciliation_only = True
            (self.session.state / 'operations').mkdir(mode=0o700)
            with patch.object(self.policy, 'validate_binding', return_value=deepcopy(self.binding)) as validation:
                resumed = p.ProvisioningSession.resume_destroy(self.run, self.lease)
            validation.assert_called_once_with(self.run, self.binding, artifacts=False)
            self.assertEqual(resumed.target_image_id, DERIVED); self.assertTrue(resumed.destroy_only)
            self.assertEqual(resumed.target_runtime_policy,self.session.target_runtime_policy)
            with patch.object(resumed, 'operation', side_effect=self.operation): result = resumed.destroy()
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(result['target_binding'], self.binding)
        self.assertEqual(self.lease.record['resources'][0]['outcome'], 'retained')


class RpmCandidateProvisioning(CandidateProvisioning):
    policy = rc
    operation_name = 'ubi9-candidate-image-binding'
    expected_binding_version = 2

    def test_ubi_caps_are_exact_before_start_and_never_expand_stock_defaults(self):
        self.assertIs(self.session.target_runtime_policy,p.TargetRuntimePolicy.UBI9_AUDIT_WRITE)
        self.assertEqual(set(self.session.variables['target_capabilities']),set(images.TARGET_CAPS)|{'AUDIT_WRITE'})
        self.assertNotIn('AUDIT_WRITE',images.TARGET_CAPS)
        with self.patches():
            self.session.create_stopped();target=self.container(base.CID)
            self.session.verify_target(target,stopped=True)
            for capabilities in (list(images.TARGET_CAPS),list(self.session.target_runtime_policy.capabilities)+['AUDIT_CONTROL'],
                list(self.session.target_runtime_policy.capabilities)+['AUDIT_READ'],list(self.session.target_runtime_policy.capabilities)+['KILL'],
                list(self.session.target_runtime_policy.capabilities)+['AUDIT_WRITE']):
                changed=deepcopy(target);changed['HostConfig']['CapAdd']=capabilities
                with self.subTest(capabilities=capabilities),self.assertRaises(p.ProvisioningError) as error:
                    self.session.verify_target(changed,stopped=True)
                self.assertEqual(error.exception.code,'unsafe_target')
            self.assertFalse(self.running[base.CID])
            self.session.destroy()

    def test_resume_refuses_policy_context_receipt_or_input_tamper_before_restart(self):
        with self.patches():
            self.session.provision();self.running[base.CONTROLLER]=False;self.lease._reconciliation_only=True
            (self.session.state/'operations').mkdir(mode=0o700)
            context_path=self.session.state/'controller.json';receipt_path=self.run.file('evidence/provisioning.json')
            variables_path=self.session.state/'terraform.tfvars.json'
            originals={path:read_json(path) for path in (context_path,receipt_path,variables_path)}
            original_bytes={path:path.read_bytes() for path in originals}
            for path in originals:
                changed=deepcopy(originals[path])
                if path==variables_path:changed['target_capabilities']=list(images.TARGET_CAPS)
                else:changed['target_runtime_policy']=p.TargetRuntimePolicy.QUALIFIED_SSH.record()
                atomic_json(path,changed);before=len(self.calls)
                with patch.object(rc,'validate_binding',return_value=deepcopy(self.binding)),self.assertRaises(p.ProvisioningError) as error:
                    p.ProvisioningSession.resume_destroy(self.run,self.lease)
                self.assertEqual(error.exception.code,'recovery_scope')
                self.assertFalse(any(call[:2]==('docker','start') for call in self.calls[before:]))
                self.assertFalse(any(call[0]=='operation' for call in self.calls[before:]))
                atomic_bytes(path,original_bytes[path])
            with patch.object(rc,'validate_binding',return_value=deepcopy(self.binding)):
                resumed=p.ProvisioningSession.resume_destroy(self.run,self.lease)
            self.assertIs(resumed.target_runtime_policy,p.TargetRuntimePolicy.UBI9_AUDIT_WRITE)
            with patch.object(resumed,'operation',side_effect=self.operation):resumed.destroy()

    def test_real_commit_layout_matches_unchanged_strict_provisioning_guard(self):
        # Parse the authored Dockerfile change instructions, rather than giving
        # the RPM image and Terraform container unrelated hardcoded mock layouts.
        labels=rc.binding_labels(self.run,{'content_sha256':'f'*64},'e'*64)
        changes=assembly.commit_changes(labels)
        runtime={name:json.loads(next(value[len(prefix):] for value in changes if value.startswith(prefix)))
            for name,prefix in (('Entrypoint','ENTRYPOINT '),('Cmd','CMD '))}
        with self.patches():
            self.session.provision()
            target=self.container(base.CID);target['Config'].update(runtime)
            # Docker inherits image environment in addition to Terraform's two
            # explicit runtime variables. Neither layer may smuggle builder role.
            target['Config']['Env']=list(rc.IMAGE_ENV)+target['Config']['Env']
            image={'Id':DERIVED,'Parent':rpm_target.BASE_ID,'Os':'linux','Architecture':'amd64',
                'Config':{**target['Config'],'Labels':self.binding['image_labels'],'WorkingDir':'/home/wormhole','Env':list(rc.IMAGE_ENV)}}
            rc.verify_image(image,self.binding)
            self.session.verify_target(target)
            old=deepcopy(target);old['Config'].update(Entrypoint=['/usr/bin/python3','/opt/wormhole/runtime.py','target'],Cmd=[])
            with self.assertRaises(p.ProvisioningError) as error:self.session.verify_target(old)
            self.assertEqual(error.exception.code,'unsafe_target')
            old_image=deepcopy(image);old_image['Config'].update(Entrypoint=old['Config']['Entrypoint'],Cmd=[])
            with self.assertRaises(rpm_target.RpmError):rc.verify_image(old_image,self.binding)
            leaked=deepcopy(target);leaked['Config']['Env'].append('WORMHOLE_ROLE=rpm-builder')
            with self.assertRaises(p.ProvisioningError) as error:self.session.verify_target(leaked)
            self.assertEqual(error.exception.code,'unsafe_target')
            leaked_image=deepcopy(image);leaked_image['Config']['Env'].append('WORMHOLE_ROLE=rpm-builder')
            with self.assertRaises(rpm_target.RpmError):rc.verify_image(leaked_image,self.binding)
            self.session.destroy()


if __name__ == '__main__': unittest.main()
