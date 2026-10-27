"""Original generated bundles; Docker image observations are mocked."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest
import sys

from wormhole import candidate as c, candidate_cache as cache, chunks, images
from wormhole.runs import atomic_json, common, create_run, read_json
from test_candidate import CandidateFixture, SHA, BUILDER, DERIVED


class Cache(CandidateFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.original=self.run
        self.binding={**common(self.run.manifest()),'operation':'candidate-image-binding','status':'built',
            'candidate_sha256':self.bundle['candidate_sha256'],'manifest':self.bundle['manifest'],
            'base_image':c.input_identity(self.bundle['manifest']['source_sha256'])['build_inputs']['base_image'],
            'image_id':DERIVED,'image_labels':c.binding_labels(self.run,self.bundle['candidate_sha256'],c.qualified_base_labels()),
            'installer_sha256':c.sha((c.CONTEXT/'install.py').read_bytes()),
            'test_contract_sha256':self.bundle['manifest']['test_contract_sha256'],
            'runtime_pipeline_complete':False,'production_iso_eligible':False}
        atomic_json(self.run.file('evidence/candidate-binding.json'),self.binding)
        atomic_json(self.run.file('evidence/candidate-build.json'),{**common(self.run.manifest()),
            'operation':'candidate-image-build','status':'built','unknown_outcome':False,
            'candidate_sha256':self.binding['candidate_sha256'],'image_id':DERIVED,'builder_id':BUILDER,'primary_failure':None})
        self.lease=self.lease_for(self.run)
        self.lease.record['resources'].append({'kind':'image','id':DERIVED,'outcome':'retained'})
        self.infra=self.root/'infra';self.infra.mkdir(mode=0o700)
        for name,value in (('INFRASTRUCTURE',self.infra),('RUNS_ROOT',self.run.workspace)):
            item=patch.object(images,name,value);item.start();self.addCleanup(item.stop)
        cache.publish(self.run,self.lease,self.binding)
        self.current=create_run(self.run.workspace,fixture=False,identity=(SHA,False))
        chunks.execute_fixture(self.current)
        with self.current.locked():c.prepare_candidate(self.current)

    def lease_for(self,run):
        lease=SimpleNamespace(run_id=run.id,source_revision=SHA,_reconciliation_only=False,
            _active=Mock(),set_phase=Mock(),record={'resources':[]})
        lease.register_resource=lambda kind,identifier:lease.record['resources'].append({'kind':kind,'id':identifier,'outcome':'pending'})
        def reconcile(kind,identifier,**options):
            item=next(item for item in lease.record['resources'] if (item['kind'],item['id'])==(kind,identifier))
            item.update(options)
        lease.reconcile_resource=reconcile
        return lease

    def image(self):
        return {'Id':DERIVED,'Parent':self.binding['base_image'],'Os':'linux','Architecture':'amd64','Size':12345,
            'Config':{'Labels':self.binding['image_labels'],'User':'0:0',
                'Entrypoint':['/usr/bin/python3','/opt/wormhole/runtime.py','target'],'Cmd':[]}}

    def test_actual_reuse_preserves_embedded_origin_manifest_and_starts_no_builder(self):
        self.assertEqual(cache.select(self.current),self.binding['manifest'])
        lease=self.lease_for(self.current)
        with patch.object(images,'inspect',return_value=self.image()) as inspect,patch.object(images,'docker') as mutate:
            binding=cache.reuse(self.current,lease)
        mutate.assert_not_called();inspect.assert_called_once_with('image',DERIVED)
        self.assertEqual(binding['run_id'],self.current.id)
        self.assertEqual(binding['manifest']['run_id'],self.original.id)
        self.assertEqual(binding['candidate_sha256'],self.binding['candidate_sha256'])
        self.assertEqual(binding['image_labels'],self.binding['image_labels'])
        self.assertEqual(c.validate_binding(self.current),binding)
        self.assertIsNone(read_json(self.current.file('evidence/candidate-build.json'))['builder_id'])
        self.assertFalse(binding['runtime_pipeline_complete']);self.assertFalse(binding['production_iso_eligible'])
        self.assertEqual(lease.record['resources'][0]['outcome'],'retained')

    def test_postbuild_image_mutation_refuses_before_adoption_and_preserves_failure(self):
        cache.select(self.current);lease=self.lease_for(self.current)
        image=self.image();image['Config']['Labels']={}
        with patch.object(images,'inspect',return_value=image),self.assertRaises(c.CandidateError):cache.reuse(self.current,lease)
        self.assertEqual(lease.record['resources'],[])
        built=read_json(self.current.file('evidence/candidate-build.json'))
        self.assertEqual(built['status'],'failed');self.assertFalse(built['unknown_outcome'])
        self.assertFalse(self.current.file('evidence/candidate-binding.json').exists())

    @unittest.skipUnless(sys.platform.startswith('linux'),'Canonical flock admission requires Linux.')
    def test_reuse_registers_retained_image_through_real_admission_phase_guards(self):
        from wormhole.admission import AdmissionLease
        from test_admission import observed
        cache.select(self.current)
        with AdmissionLease(self.root/'enforced-infrastructure',self.current.id,SHA,
                collector=lambda _:observed(),allow_synthetic=True) as lease:
            with patch.object(images,'inspect',return_value=self.image()),patch.object(images,'docker') as mutate:
                binding=cache.reuse(self.current,lease)
            mutate.assert_not_called()
            self.assertEqual(lease.record['phase'],'materializing')
            self.assertEqual(lease.record['resources'],[{'kind':'image','id':DERIVED,
                'outcome':'retained','size_bytes':12345}])
            self.assertEqual(binding['image_id'],DERIVED)
            lease.finish(reconciliation_complete=True)

    def test_changed_content_misses_cache_and_controller_revision_does_not_change_key(self):
        before=cache.key(self.current)
        with patch.object(c,'source_identity',return_value=('f'*40,False)):
            self.assertEqual(cache.key(self.current),before)
        with patch.object(c,'VERSION','different'):
            with self.assertRaises(c.CandidateError):cache.key(self.current)
        # A valid new content generation has its own key, not an old cache hit.
        path=cache.index_path(self.current);path.unlink()
        self.assertIsNone(cache.select(self.current))
        self.assertFalse(self.current.file(cache.SELECTION).exists())

    def test_new_controller_revision_reuses_old_bytes_with_separate_source_attribution(self):
        revision='f'*40
        newer=create_run(self.run.workspace,fixture=False,identity=(revision,False))
        with patch.object(c,'source_identity',return_value=(revision,False)),patch.object(chunks,'source_identity',return_value=(revision,False)):
            chunks.execute_fixture(newer)
            with newer.locked():c.prepare_candidate(newer)
            cache.select(newer);lease=self.lease_for(newer);lease.source_revision=revision
            with patch.object(images,'inspect',return_value=self.image()),patch.object(images,'docker') as docker:
                binding=cache.reuse(newer,lease)
        docker.assert_not_called()
        self.assertEqual(binding['source_revision'],revision)
        self.assertEqual(binding['manifest']['source_revision'],SHA)
        self.assertEqual(binding['image_id'],DERIVED)

    def test_test_only_contract_change_reuses_bytes_but_binds_the_new_execution_contract(self):
        from wormhole import candidate_validation
        old_key=cache.key(self.current)
        old_plan=candidate_validation.make_plan(self.current,self.binding,'d'*64,'e'*64,'healthy')
        changed={**c.test_contract(),'collector':'fixed-ssh-ansible-candidate-v2'}
        with patch.object(c,'test_contract',return_value=changed):
            self.assertEqual(cache.key(self.current),old_key)
            self.assertEqual(cache.select(self.current),self.binding['manifest'])
            plan=candidate_validation.make_plan(self.current,self.binding,'d'*64,'e'*64,'healthy')
        self.assertEqual(plan['candidate_sha256'],old_plan['candidate_sha256'])
        self.assertNotEqual(plan['execution_contract_sha256'],old_plan['execution_contract_sha256'])
        self.assertEqual(plan['test_contract_sha256'],old_plan['test_contract_sha256'])

    def test_stale_index_changed_capture_and_origin_reuse_chains_are_refused(self):
        path=cache.index_path(self.current);saved=read_json(path)
        altered=deepcopy(saved);altered['input_sha256']='0'*64;atomic_json(path,altered)
        with self.assertRaises(c.CandidateError):cache.select(self.current)
        atomic_json(path,saved)
        raw=self.original.file('private/candidate/payload.py');raw.write_bytes(b'changed source')
        with self.assertRaises(c.CandidateError):cache.select(self.current)

    def test_forged_current_binding_and_missing_original_receipt_refuse(self):
        cache.select(self.current);lease=self.lease_for(self.current)
        with patch.object(images,'inspect',return_value=self.image()):binding=cache.reuse(self.current,lease)
        changed=deepcopy(binding);changed['manifest']['run_id']=self.current.id
        atomic_json(self.current.file('evidence/candidate-binding.json'),changed)
        with self.assertRaises(c.CandidateError):c.validate_binding(self.current)
        atomic_json(self.current.file('evidence/candidate-binding.json'),binding)
        self.original.file('evidence/candidate-build.json').unlink()
        with self.assertRaises(OSError):c.validate_binding(self.current)


if __name__=='__main__':unittest.main()
