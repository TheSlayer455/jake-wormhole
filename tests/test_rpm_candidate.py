"""Synthetic original-byte/platform fixtures; all image operations are mocked."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from wormhole import candidate as c, rpm_candidate as rc, rpm_target as t, provisioning as p
from wormhole.runs import atomic_json,common,read_json
from test_candidate import CandidateFixture,SHA,DERIVED,BUILDER


def binding_for(fixture):
    manifest=fixture.rpm_bundle['manifest'];recipe,files=rc.recipe_identity()
    value={**common(fixture.run.manifest()),'operation':'ubi9-candidate-image-binding','status':'built',
        'candidate_sha256':fixture.rpm_bundle['candidate_sha256'],'content_sha256':manifest['content_sha256'],
        'source_candidate_sha256':manifest['source_candidate_sha256'],'manifest':manifest,'base_image':t.BASE_ID,'image_id':DERIVED,
        'image_labels':rc.binding_labels(fixture.run,manifest,recipe),'recipe_sha256':recipe,'source_files':files,
        'test_contract_sha256':manifest['test_contract_sha256'],'runtime_pipeline_complete':False,'production_iso_eligible':False}
    atomic_json(fixture.run.file('evidence/rpm-candidate-binding.json'),value)
    atomic_json(fixture.run.file('evidence/rpm-candidate-build.json'),{**common(fixture.run.manifest()),'operation':'ubi9-candidate-build',
        'status':'built','builder_id':BUILDER,'image_id':DERIVED,'unknown_outcome':False,'primary_failure':None,
        'candidate_sha256':value['candidate_sha256'],'recipe_sha256':recipe,'source_files':files,
        'installed':{'installed_packages':[{'name':name,**version} for name,version in rc.PACKAGE_VERSIONS.items()]}})
    return rc.validate_binding(fixture.run)


class RpmFixture(CandidateFixture):
    def setUp(self):
        super().setUp()
        item=patch.object(rc,'source_identity',return_value=(SHA,False));item.start();self.addCleanup(item.stop)
        with self.run.locked():self.rpm_bundle=rc.prepare_manifest(self.run)


class RpmCandidate(RpmFixture,unittest.TestCase):
    def test_same_four_exact_bytes_have_shared_content_and_separate_platform_manifest(self):
        original=c.validate_bundle(self.run);rpm=rc.validate_bundle(self.run)
        self.assertNotEqual(original['candidate_sha256'],rpm['candidate_sha256'])
        self.assertEqual(rc.content_identity(original['manifest']),rpm['manifest']['content_sha256'])
        self.assertEqual(rpm['manifest']['source_candidate_sha256'],original['candidate_sha256'])
        self.assertEqual(original['manifest']['applicability']['os_id'],'ubuntu')
        self.assertEqual(rpm['manifest']['applicability']['os_id'],'rhel')
        for name in c.NAMES:self.assertEqual((original['directory']/name).read_bytes(),(rpm['directory']/name).read_bytes())
        with self.assertRaises(c.CandidateError):c.validate_manifest(rpm['manifest'])

    def test_generated_schema_and_nested_manifest_unsupported_versions_or_types(self):
        self.assertEqual(json.loads((rc.SOURCE_ROOT/'schemas/ubi-candidate-manifest-v1.schema.json').read_text()),rc.schema())
        for alter in (lambda x:x.update(schema_version='2.0'),lambda x:x.update(content_sha256='0'*64),
            lambda x:x['applicability'].update(os_id='ubuntu'),lambda x:x['source_candidate_manifest'].update(source_dirty=0),
            lambda x:x['files'][0].update(path='../secrets'),lambda x:x['packages']['shadow-utils'].update(epoch=True),
            lambda x:x.update(production_iso_eligible=True)):
            value=deepcopy(self.rpm_bundle['manifest']);alter(value)
            with self.assertRaises(Exception):rc.validate_manifest(value)

    def test_exact_image_binding_and_explicit_policy_version_do_not_replace_stock(self):
        binding=binding_for(self)
        image={'Id':DERIVED,'Parent':t.BASE_ID,'Os':'linux','Architecture':'amd64','Config':{'Labels':binding['image_labels'],
            'User':'0:0','WorkingDir':'/home/wormhole','Entrypoint':['/usr/bin/python3','/opt/wormhole/runtime.py'],'Cmd':['target'],'Env':list(rc.IMAGE_ENV)}}
        rc.verify_image(image,binding)
        self.assertEqual(p.target_binding_policy(binding)[1],2)
        self.assertEqual(p.target_binding_policy({'operation':'candidate-image-binding'})[1],1)
        for version in (1,True,'2'):
            with self.assertRaises(p.ProvisioningError):p.target_binding_policy(binding,version=version)
        for alter in (lambda x:x.update(Id=p.TARGET_IMAGE),lambda x:x.update(Parent=p.TARGET_IMAGE),
            lambda x:x['Config']['Labels'].update(extra='foreign'),lambda x:x['Config'].update(Volumes={'/state':{}}),
            lambda x:x['Config']['Env'].append('WORMHOLE_ROLE=rpm-builder'),lambda x:x['Config']['Env'].append('WORMHOLE_ROLE='),
            lambda x:x['Config']['Env'].append('WORMHOLE_RUN_ID='+self.run.id),lambda x:x['Config']['Env'].append('WORMHOLE_RUN_ID='),
            lambda x:x['Config'].update(Entrypoint=['/usr/bin/python3','/opt/wormhole/runtime.py','target'],Cmd=[])):
            changed=deepcopy(image);alter(changed)
            with self.assertRaises(t.RpmError):rc.verify_image(changed,binding)
        self.assertNotEqual(p.TARGET_IMAGE,t.BASE_ID)

    def test_forged_binding_fields_unfinished_build_and_changed_bytes_cannot_pass(self):
        binding=binding_for(self)
        for alter in (lambda x:x.update(source_candidate_sha256='0'*64),lambda x:x.update(content_sha256='0'*64),
            lambda x:x['image_labels'].update(extra='unapproved'),lambda x:x.update(source_dirty=0),
            lambda x:x.update(target_capabilities=['AUDIT_CONTROL']),lambda x:x.update(target_runtime_policy='arbitrary')):
            changed=deepcopy(binding);alter(changed)
            with self.assertRaises(Exception):rc.validate_binding(self.run,changed)
        receipt=read_json(self.run.file('evidence/rpm-candidate-build.json'));receipt['unknown_outcome']=True
        atomic_json(self.run.file('evidence/rpm-candidate-build.json'),receipt)
        with self.assertRaises(t.RpmError):rc.validate_binding(self.run,artifacts=False)
        receipt['unknown_outcome']=False;atomic_json(self.run.file('evidence/rpm-candidate-build.json'),receipt)
        (self.rpm_bundle['directory']/'version.txt').write_bytes(b'changed')
        with self.assertRaises(t.RpmError):rc.validate_binding(self.run)
        self.assertEqual(rc.validate_binding(self.run,artifacts=False),binding)  # Original-source cleanup needs no candidate byte execution.


if __name__=='__main__':unittest.main()
