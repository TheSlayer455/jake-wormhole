"""Candidate target/stock controller separation; all Docker/Terraform mocked."""
from copy import deepcopy
import json
import os
import unittest
from unittest.mock import patch

import test_provisioning as base
from test_candidate import DERIVED
from wormhole import candidate as c, rpm_candidate as rc, rpm_assembly as assembly, rpm_target, provisioning as p, images
from wormhole.runs import read_json


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
            with patch.object(resumed, 'operation', side_effect=self.operation): result = resumed.destroy()
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(result['target_binding'], self.binding)
        self.assertEqual(self.lease.record['resources'][0]['outcome'], 'retained')


class RpmCandidateProvisioning(CandidateProvisioning):
    policy = rc
    operation_name = 'ubi9-candidate-image-binding'
    expected_binding_version = 2

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
