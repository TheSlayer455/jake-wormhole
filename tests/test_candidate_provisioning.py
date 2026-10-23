"""Candidate target/stock controller separation; all Docker/Terraform mocked."""
from copy import deepcopy
import os
import unittest
from unittest.mock import patch

import test_provisioning as base
from test_candidate import DERIVED
from wormhole import candidate as c, provisioning as p, images
from wormhole.runs import read_json


@unittest.skipUnless(os.name == 'posix', 'Linux provisioning policy fixture; Docker/Terraform mocked')
class CandidateProvisioning(unittest.TestCase):
    def setUp(self):
        base.Controller.setUp(self)
        self.binding = {'image_id': DERIVED, 'image_labels': {**self.image_labels, images.LABEL + '.candidate_sha256': 'e' * 64}}
        self.lease.record['resources'].append({'kind': 'image', 'id': DERIVED, 'outcome': 'retained'})
        with patch.object(c, 'validate_binding', return_value=deepcopy(self.binding)), patch.object(c, 'verify_image'), patch.object(images, 'inspect'):
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
            self.assertEqual(context['target_binding_version'], 1); self.assertEqual(context['target_binding'], self.binding)
            wrong = deepcopy(target); wrong['Image'] = p.TARGET_IMAGE
            with self.assertRaises(p.ProvisioningError): self.session.verify_target(wrong)
            result = self.session.destroy()
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(self.lease.record['resources'][0]['outcome'], 'retained')


if __name__ == '__main__': unittest.main()
