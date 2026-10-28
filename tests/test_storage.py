"""Disposable filesystem proofs; never evidence of ISO qualification."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole import storage as s
from wormhole.runs import RunError, atomic_json, read_json, now
from wormhole.vm_inputs import sha256


class Capacity(unittest.TestCase):
    def test_projected_critical_and_exact_threshold(self):
        with patch.object(s,'filesystem',return_value={'used_bytes':80,'available_bytes':20,'usage_percent':80}):
            self.assertTrue(s.admission('.',10)['warning'])
            with self.assertRaises(RunError) as error:s.admission('.',11)
            self.assertEqual(error.exception.code,'storage_projected_critical')
            with self.assertRaises(RunError):s.admission('.',0,candidate_bytes=s.CANDIDATE_BUDGET+1)
            with self.assertRaises(RunError):s.admission('.',0,managed_bytes=s.ARTIFACT_BUDGET+1)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux allocated-block filesystem tests')
class Cleanup(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.root=self.base/'project/runtime';self.root.mkdir(parents=True,mode=0o700)
        self.shared=self.base/'project-vm';self.shared.mkdir(mode=0o700)
        self.store=s.Store(self.root,self.shared);self.store.live={}
        self.store.qemu_uid=os.geteuid
        self.store.infrastructure.mkdir(mode=0o700)
        atomic_json(self.store.infrastructure/'owner.json',{
            'application':'jake-wormhole','schema_version':'1.0','kind':'shared-infrastructure-root'})
        (self.store.infrastructure/'vm-history').mkdir(mode=0o700)
        self.store.runs.mkdir(mode=0o700)

    def fixture(self, *, outcome='failed', content=b'candidate'*4096):
        identifier=str(uuid4());run=self.store.runs/identifier;run.mkdir(mode=0o700)
        inputs=run/'inputs';inputs.mkdir(mode=0o700)
        payload=inputs/'payload';payload.mkdir(mode=0o700)
        repository=payload/'repository';repository.mkdir(mode=0o700)
        package=repository/'example.deb';package.write_bytes(b'disposable fixture'*4096)
        atomic_json(payload/'manifest.json',{'files':[{'path':'repository/example.deb','bytes':package.stat().st_size,'sha256':sha256(package)}]})
        share=self.shared/identifier;share.mkdir(mode=0o700)
        candidate=share/'candidate.iso';candidate.write_bytes(content)
        seed=share/'seed.iso';seed.write_bytes(b'PRIVATE SEED FIXTURE')
        build={'candidate_sha256':sha256(candidate),'seed_sha256':sha256(seed),'dependency_manifest_sha256':sha256(payload/'manifest.json')}
        atomic_json(inputs/'build-manifest.json',build)
        value={'run_id':identifier,'source_revision':'a'*40,'outcome':outcome,'build':build,'finished_at':now(),
               'cleanup':'verified-absent-inputs-retained','error_category':'original-failure' if outcome=='failed' else None}
        atomic_json(run/'result.json',value)
        atomic_json(run/'diagnostic.json',{'original_evidence':True})
        journal={'schema_version':'1.0','backend':'libvirt-iso','run_id':identifier,'source_revision':'a'*40,
                 'state':'finished','created_at':now(),'updated_at':now(),'production_iso_eligible':False,
                 'resources':[{'kind':'installer_iso','identity':str(candidate),'outcome':'retained-input'},
                              {'kind':'seed_iso','identity':str(seed),'outcome':'retained-input'}]}
        atomic_json(self.store.infrastructure/'vm-history'/(identifier+'.json'),journal)
        return run,candidate,package

    def clean(self,references=()):
        with self.store.locked(),patch.object(self.store,'observe',return_value=references):return self.store.clean_held()

    def test_failed_and_successful_evidence_and_releases_survive_duplicate_cleanup(self):
        first, candidate, package=self.fixture(outcome='assessment-complete')
        second, duplicate, package2=self.fixture()
        release=self.root/'ubuntu-releases';release.mkdir(mode=0o700)
        qualified=release/'qualified.iso';qualified.write_bytes(b'NEVER DELETE')
        originals={p:p.read_bytes() for p in (first/'result.json',second/'result.json',second/'diagnostic.json',qualified)}
        receipt=self.clean()
        self.assertGreater(receipt['unlinked_allocated_bytes'],0)
        self.assertEqual(sum(p.exists() for p in (candidate,duplicate)),1)
        self.assertFalse(package.exists());self.assertFalse(package2.exists())
        for p,content in originals.items():self.assertEqual(p.read_bytes(),content)
        self.assertEqual(sha256(self.store.resolve(first.name)),sha256(self.store.resolve(second.name)))
        self.assertEqual(self.clean()['unlinked_allocated_bytes'],0)

    def test_active_resource_and_hardlinks_symlinks_are_protected(self):
        run,candidate,package=self.fixture()
        self.assertEqual(self.clean([str(candidate)])['unlinked_allocated_bytes'],0)
        self.assertTrue(package.exists())
        other=self.base/'unrelated';other.write_bytes(b'UNRELATED')
        package.unlink();package.symlink_to(other)
        receipt=self.clean()
        self.assertTrue(package.is_symlink());self.assertEqual(other.read_bytes(),b'UNRELATED')
        self.assertTrue(receipt['blocked'])
        package.unlink();os.link(other,package)
        self.clean();self.assertTrue(package.exists());self.assertEqual(other.stat().st_nlink,2)

    def test_unknown_and_running_runs_without_finished_archive_cannot_authorize_cleanup(self):
        for outcome in ('running','unknown'):
            run,candidate,package=self.fixture(outcome=outcome)
            (self.store.infrastructure/'vm-history'/(run.name+'.json')).unlink()
            self.clean()
            self.assertTrue(candidate.exists());self.assertTrue(package.exists())

    def test_finished_archive_and_live_domain_mismatch_is_refused(self):
        run,candidate,package=self.fixture()
        path=self.store.infrastructure/'vm-history'/(run.name+'.json')
        journal=read_json(path);journal['resources'].append({'kind':'domain','identity':'owned-live','outcome':'absent'})
        atomic_json(path,journal);self.store.live={'domain':{'owned-live'}}
        self.assertTrue(self.clean()['blocked']);self.assertTrue(package.exists())

    def test_corrupt_manifest_or_modified_candidate_cannot_authorize_deletion(self):
        run,candidate,package=self.fixture()
        candidate.write_bytes(b'TAMPERED')
        self.assertTrue(self.clean()['blocked']);self.assertTrue(package.exists())

    def test_sparse_files_report_blocks_not_apparent_bytes_and_do_not_double_count_hardlinks(self):
        file=self.root/'sparse';file.touch();file.chmod(0o600)
        with file.open('r+b') as stream:stream.truncate(2*s.GIB)
        os.link(file,self.root/'hardlink')
        status=self.store.status()
        self.assertLess(status['total_allocated_bytes'],s.GIB)
        self.assertEqual(sum(status['allocated_bytes'].values()),status['total_allocated_bytes'])

    def test_alias_cycle_and_changed_canonical_are_refused(self):
        first,candidate,_=self.fixture();second,duplicate,_=self.fixture()
        candidate.unlink();duplicate.unlink()
        for run,target in ((first,second),(second,first)):
            atomic_json(run/'storage-candidate.json',{'sha256':read_json(run/'inputs/build-manifest.json')['candidate_sha256'],'canonical_run':target.name})
        with self.assertRaises(RunError):self.store.resolve(first.name)

    def test_interrupted_unlink_recovers_with_durable_alias_and_idempotent_retry(self):
        first,candidate,_=self.fixture();second,duplicate,_=self.fixture()
        original=Path.unlink;calls=[0]
        def interrupted(path,*args,**kwargs):
            # Simulate loss after alias intent but before candidate removal.
            if path.name=='candidate.iso':raise OSError('controlled interruption')
            return original(path,*args,**kwargs)
        with patch.object(Path,'unlink',interrupted):
            with self.assertRaises(OSError):self.clean()
        self.assertTrue(candidate.exists() and duplicate.exists())
        self.clean()
        self.assertEqual(sha256(self.store.resolve(first.name)),sha256(self.store.resolve(second.name)))

    def test_journal_active_refusal_precedes_observation_commands(self):
        run,candidate,package=self.fixture()
        journal=read_json(self.store.infrastructure/'vm-history'/(run.name+'.json'))
        journal['state']='active'
        atomic_json(self.store.infrastructure/'vm-admission.json',journal)
        # Install a valid finished Docker journal by using its fixture lease.
        from test_admission import observed
        from wormhole.admission import AdmissionLease
        (self.store.infrastructure/'vm-admission.json').unlink()
        with AdmissionLease(self.store.infrastructure,str(uuid4()),'b'*40,collector=lambda _:observed(),allow_synthetic=True) as lease:
            lease.finish(reconciliation_complete=True)
        atomic_json(self.store.infrastructure/'vm-admission.json',journal)
        with patch.object(s.subprocess,'check_output') as command:
            with self.assertRaises(RunError) as error:self.store.observe()
            self.assertEqual(error.exception.code,'storage_active_run');command.assert_not_called()
        self.assertTrue(package.exists())

    def test_source_proven_stale_eviction_keeps_manifest_and_refuses_reuse(self):
        run,candidate,package=self.fixture()
        with patch.object(self.store,'invalidated',return_value=['ubuntu/guest/finalize.sh']):
            receipt=self.clean()
        self.assertFalse(candidate.exists());self.assertTrue((run/'inputs/build-manifest.json').exists())
        self.assertTrue(any(a.get('reason')=='obsolete-installed-inputs'
                            for p in (self.store.infrastructure/'storage-operations').glob('*-batch-*.json')
                            for a in read_json(p)['actions']))
        with self.assertRaises(RunError) as error:self.store.resolve(run.name)
        self.assertEqual(error.exception.code,'stale_candidate')

    def test_qualified_candidate_is_pinned_even_if_source_changes(self):
        run,candidate,package=self.fixture()
        manifest=read_json(run/'inputs/build-manifest.json');manifest['lab_iso_qualified']=True
        atomic_json(run/'inputs/build-manifest.json',manifest)
        result=read_json(run/'result.json');result['build']=manifest;atomic_json(run/'result.json',result)
        with patch.object(self.store,'invalidated',return_value=['ubuntu/guest/finalize.sh']):self.clean()
        self.assertTrue(candidate.exists())

    def test_partial_build_requires_preallocation_intent_and_finished_input_only_journal(self):
        run,candidate,package=self.fixture()
        result=read_json(run/'result.json');result.pop('build');atomic_json(run/'result.json',result)
        (run/'inputs/build-manifest.json').unlink()
        self.clean();self.assertTrue(candidate.exists())
        atomic_json(run/'storage-build-intent.json',{'schema_version':'1.0','run_id':run.name,
            'source_revision':result['source_revision'],'candidate':str(candidate),'seed':str(candidate.with_name('seed.iso'))})
        self.clean();self.assertFalse(candidate.exists());self.assertTrue((run/'diagnostic.json').exists())

    def test_changed_inode_or_mount_reference_cannot_be_unlinked(self):
        run,candidate,package=self.fixture()
        with self.assertRaises(RunError):self.store.checked(package,[str(package.parent)])
        plan=self.store.preview([])
        package.write_bytes(b'changed after preview')
        with self.store.locked(),patch.object(self.store,'observe',return_value=[]),patch.object(self.store,'preview',return_value=plan):
            with self.assertRaises(RunError) as error:self.store.clean_held()
        self.assertEqual(error.exception.code,'storage_file_changed');self.assertTrue(package.exists())

    def test_private_digest_receipt_invalidates_after_content_change(self):
        run,candidate,package=self.fixture()
        first=self.store.digest(candidate)
        candidate.write_bytes(b'changed bytes')
        self.assertNotEqual(self.store.digest(candidate),first)

    def test_preview_does_not_write_receipts_or_mutate_artifacts(self):
        run,candidate,package=self.fixture()
        paths={p:signature for p in self.root.rglob('*') if p.is_file() for signature in [s.signature(p)]}
        self.store.preview([])
        self.assertEqual(paths,{p:s.signature(p) for p in paths})
        self.assertFalse((self.store.infrastructure/'storage-operations').exists())

    def test_unheld_or_changed_admission_lock_cannot_delete(self):
        run,candidate,package=self.fixture()
        with self.assertRaises(RunError) as error:self.store.clean_held()
        self.assertEqual(error.exception.code,'storage_lock_required')
        with self.store.locked():
            lock=self.store.infrastructure/'infrastructure.lock'
            lock.rename(lock.with_suffix('.old'));lock.touch(mode=0o600)
            with self.assertRaises(RunError) as error:self.store.clean_held()
            self.assertEqual(error.exception.code,'storage_lock_changed')
        self.assertTrue(package.exists())
