"""Real bundles/index decisions; Docker and package replay are isolated fixtures.

The original package/crypto validators retain their separate authored-capture
tests. These cases do not execute Docker, DNF, SSH or prove runtime reuse.
"""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from wormhole import candidate as c,candidate_cache as cache,chunks,images,pipeline_replay as replay
from wormhole import rpm_candidate as rc,rpm_target as rt
from wormhole.runs import atomic_bytes,atomic_json,create_run,read_json,common,RunError
from test_candidate import SHA,DERIVED
from test_rpm_candidate import RpmFixture,binding_for
REPLAY_BUILD=replay.replay_rpm_build


class RpmCache(RpmFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.original=self.run;self.binding=binding_for(self)
        self.infra=self.root/'infra';self.infra.mkdir(mode=0o700)
        self.replay=Mock(side_effect=lambda run,binding:binding)
        for owner,name,value in ((images,'RUNS_ROOT',self.run.workspace),(images,'INFRASTRUCTURE',self.infra),
            (replay,'replay_rpm_build',self.replay)):
            item=patch.object(owner,name,value);item.start();self.addCleanup(item.stop)
        lease=self.lease_for(self.run)
        lease.record['resources']=[{'kind':'image','id':DERIVED,'outcome':'retained'}]
        cache.publish(self.run,lease,self.binding)
        self.current=create_run(self.run.workspace,fixture=False,identity=(SHA,False))
        chunks.execute_fixture(self.current)
        with self.current.locked():c.prepare_candidate(self.current)

    def lease_for(self,run):
        lease=SimpleNamespace(run_id=run.id,source_revision=run.manifest()['source_revision'],
            _reconciliation_only=False,_active=Mock(),record={'resources':[]})
        lease.register_resource=lambda kind,identifier:lease.record['resources'].append({'kind':kind,'id':identifier,'outcome':'pending'})
        def reconcile(kind,identifier,**options):
            item=next(item for item in lease.record['resources'] if (item['kind'],item['id'])==(kind,identifier));item.update(options)
        lease.reconcile_resource=reconcile;return lease

    def inspect(self,kind,identifier):
        if identifier==rt.BASE_ID:
            return {'Id':rt.BASE_ID,'Os':'linux','Architecture':'amd64','RepoDigests':[rt.BASE],'Size':80416938,
                'Config':{'Labels':rt.load_lock()['base']['labels']},
                'Descriptor':{'mediaType':'application/vnd.docker.distribution.manifest.v2+json','digest':rt.BASE_ID,'size':429}}
        return {'Id':DERIVED,'Parent':rt.BASE_ID,'Os':'linux','Architecture':'amd64','Size':90000000,
            'Config':{'Labels':self.binding['image_labels'],'User':'0:0','WorkingDir':'/home/wormhole',
                'Entrypoint':['/usr/bin/python3','/opt/wormhole/runtime.py'],'Cmd':['target'],'Env':list(rc.IMAGE_ENV)}}

    def test_reuses_original_ubi_and_parent_without_new_builder_or_resolution(self):
        manifest=cache.select(self.current,'ubi');self.assertEqual(manifest,self.binding['manifest'])
        lease=self.lease_for(self.current)
        with patch.object(images,'inspect',side_effect=self.inspect),patch.object(images,'docker') as allocate:
            binding=cache.reuse(self.current,lease)
        allocate.assert_not_called()
        self.assertEqual(rc.validate_binding(self.current),binding)
        self.assertEqual(binding['run_id'],self.current.id);self.assertEqual(binding['manifest']['run_id'],self.original.id)
        self.assertFalse(self.current.file('evidence/rpm-resolution.json').exists())
        self.assertFalse(self.current.file('private/rpm-candidate').exists())
        self.assertIsNone(read_json(self.current.file('evidence/rpm-candidate-build.json'))['builder_id'])
        self.assertEqual({row['id'] for row in lease.record['resources']},{DERIVED,rt.BASE_ID})
        self.assertTrue(all(row['outcome']=='retained' for row in lease.record['resources']))
        self.assertFalse(binding['production_iso_eligible'])

    def test_controller_revision_is_separate_and_original_source_recipe_stays_required(self):
        revision='f'*40;newer=create_run(self.run.workspace,fixture=False,identity=(revision,False))
        with patch.object(c,'source_identity',return_value=(revision,False)),patch.object(chunks,'source_identity',return_value=(revision,False)):
            chunks.execute_fixture(newer)
            with newer.locked():c.prepare_candidate(newer)
            cache.select(newer,'ubi')
            with patch.object(images,'inspect',side_effect=self.inspect):binding=cache.reuse(newer,self.lease_for(newer))
        self.assertEqual(binding['source_revision'],revision);self.assertEqual(binding['manifest']['source_revision'],SHA)
        self.replay.side_effect=RunError('pipeline_resolution_changed','Controlled original-resolution mismatch')
        with self.assertRaises(RunError):rc.validate_binding(newer)

    def test_installed_package_change_misses_both_platform_cache_keys(self):
        old=cache.key(self.current,'ubi')
        changed=deepcopy(rc.PACKAGE_VERSIONS);changed['python3']['release']='changed'
        with patch.object(rc,'PACKAGE_VERSIONS',changed):
            self.assertNotEqual(cache.key(self.current,'ubi'),old)
            self.assertIsNone(cache.select(self.current,'ubi'))
        self.assertNotEqual(cache.key(self.current,'ubi'),cache.key(self.current,'ubuntu'))

    def test_collector_only_change_reuses_image_and_freezes_the_new_run_contract(self):
        from validation import runtime
        from wormhole import rpm_validation
        old_key=cache.key(self.current,'ubi')
        before=rpm_validation.make_plan(self.current,self.binding,'d'*64,'e'*64,'healthy')
        with patch.object(runtime,'RPM_PROGRAM',runtime.RPM_PROGRAM+'\n# authored changed test collector\n'):
            self.assertEqual(cache.key(self.current,'ubi'),old_key)
            self.assertEqual(cache.select(self.current,'ubi'),self.binding['manifest'])
            after=rpm_validation.make_plan(self.current,self.binding,'d'*64,'e'*64,'healthy')
        self.assertEqual(before['candidate_sha256'],after['candidate_sha256'])
        self.assertNotEqual(before['collector_sha256'],after['collector_sha256'])
        self.assertNotEqual(before['execution_contract_sha256'],after['execution_contract_sha256'])
        self.assertEqual(before['test_contract_sha256'],after['test_contract_sha256'])

    def test_missing_resolution_proof_and_tampered_input_receipt_refuse_before_inspection(self):
        self.replay.side_effect=FileNotFoundError('Controlled missing resolution')
        with patch.object(images,'inspect') as inspect,self.assertRaises(OSError):cache.select(self.current,'ubi')
        inspect.assert_not_called()
        self.replay.side_effect=lambda run,binding:binding
        path=self.original.file('evidence/rpm-candidate-inputs.json');value=read_json(path);value['input_sha256']='0'*64;atomic_json(path,value)
        with self.assertRaises(RunError):cache.select(self.current,'ubi')

    def test_platform_substitution_and_unverified_requested_base_are_refused(self):
        cache.select(self.current,'ubi')
        with self.assertRaises(RunError):cache.selected_manifest(self.current,'ubuntu')
        old_request=self.original.file('private/rpm-sources');old_request.mkdir(mode=0o700)
        atomic_json(old_request/'resolve-request.json',{'base_packages_sha256':'0'*64})
        from wormhole import rpm_source
        with patch.object(rt,'read_base_observation',return_value={}),patch.object(rpm_source,'validate_observation',return_value=[]),\
            self.assertRaises(RunError) as error:cache.verify_base_request(self.current,self.original.id)
        self.assertEqual(error.exception.code,'candidate_base_changed')

    def test_original_build_replay_requires_resolution_capture_and_all_component_verifiers(self):
        from wormhole import rpm_source,rpm_resolution,rpm_assembly
        run=self.original;resolution={'packages':[],'status':'passed'};observation={'synthetic':'base'};packages=[]
        folder=run.file('private/rpm-sources');folder.mkdir(mode=0o700)
        atomic_json(folder/'resolve-request.json',{'base_probe':{'run_id':run.id},
            'base_observation_sha256':c.sha(c.canonical(observation)),'base_packages_sha256':c.sha(c.canonical(packages))})
        atomic_json(run.file('private/rpm-assembly-request.json'),{**common(run.manifest()),'operation':'ubi9-assembly-request-v1',
            'manifest':self.binding['manifest'],'candidate_sha256':self.binding['candidate_sha256'],
            'source_files':self.binding['source_files'],'recipe_sha256':self.binding['recipe_sha256'],'resolution':resolution})
        raw=c.canonical(resolution)+b'\n';atomic_bytes(run.file('private/rpm-resolution.log'),raw)
        recipe,files=rpm_resolution.recipe_identity()
        receipt={**common(run.manifest()),'operation':'ubi-offline-resolution','status':'passed','unknown_outcome':False,
            'primary_failure':None,'cleanup':'completed','recipe_sha256':recipe,'source_files':files,
            'capture_bytes':len(raw),'capture_sha256':c.sha(raw),'resolution':resolution}
        atomic_json(run.file(rpm_resolution.EVIDENCE),receipt)
        with patch.object(rpm_assembly,'validate_installed') as installed,patch.object(rpm_source,'validate_eula') as license,\
            patch.object(rpm_source,'validate_resolution',return_value=resolution) as resolved,\
            patch.object(rt,'read_base_observation',return_value=observation),\
            patch.object(rpm_source,'validate_observation',return_value=packages),patch.object(rpm_source,'validate_packages') as checked:
            self.assertEqual(REPLAY_BUILD(run,self.binding),self.binding)
            installed.assert_called_once();license.assert_called_once();resolved.assert_called_once();checked.assert_called_once()
            run.file('private/rpm-resolution.log').write_bytes(raw+b'changed')
            with self.assertRaises(RunError) as error:REPLAY_BUILD(run,self.binding)
            self.assertEqual(error.exception.code,'pipeline_resolution_changed')


if __name__=='__main__':unittest.main()
