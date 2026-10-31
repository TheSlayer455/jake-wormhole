"""Selective retention regressions; real remote round trips are separate evidence."""
import io
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import test_storage
from wormhole import storage_archive as a
from wormhole.runs import RunError, atomic_json, read_json
from wormhole.storage import signature
from wormhole.vm_inputs import sha256


@unittest.skipUnless(os.name=='posix','Linux archive ownership')
class Archive(unittest.TestCase):
    def setUp(self):
        self.fixture=test_storage.Cleanup();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.store=self.fixture.store
        self.patch=patch.object(self.store,'observe',return_value=[])
        self.patch.start();self.addCleanup(self.patch.stop)
        self.config={'schema_version':'1.0','archive_id':str(uuid4()),'keep_local_digests':[]}
        atomic_json(self.store.infrastructure/'archive-config.json',self.config)

    def queued(self):
        run,path,_=self.fixture.fixture();digest=sha256(path)
        with self.store.locked():a.queue(self.store,[])
        return run,path,digest

    def receipt(self,digest):
        v=a.record(self.store,digest)
        return {'archive_id':self.config['archive_id'],'sha256':digest,'bytes':v['bytes'],
            'ciphertext_sha256':'c'*64,'ciphertext_bytes':v['bytes']+100,'verified':True}

    def test_verified_commit_reclaims_once_and_restore_preserves_bytes_and_aliases(self):
        with patch.object(test_storage,'uuid4',return_value='ffffffff-ffff-4fff-8fff-ffffffffffff'):
            run,path,digest=self.queued()
        original=path.read_bytes();mode=path.stat().st_mode&0o777
        with patch.object(test_storage,'uuid4',return_value='00000000-0000-4000-8000-000000000001'):
            other,duplicate,_=self.fixture.fixture()
        # Existing dedupe aliases remain valid after the canonical object returns.
        with self.store.locked():self.store.clean_held()
        canonical=self.store.resolve(run.name);identifier=canonical.parent.name
        result=a.commit(self.store,digest,self.receipt(digest))
        self.assertGreater(result['cleanup']['unlinked_allocated_bytes'],0)
        self.assertFalse(canonical.exists())
        with self.assertRaises(RunError) as error:self.store.resolve(other.name)
        self.assertEqual(error.exception.code,'archive_restore_required')
        with patch.object(a.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(original))):a.restore(self.store,digest)
        self.assertEqual(self.store.resolve(run.name).read_bytes(),original)
        self.assertEqual(sha256(self.store.resolve(other.name)),digest)
        self.assertEqual(self.store.resolve(identifier).stat().st_mode&0o777,mode)
        a.commit(self.store,digest,self.receipt(digest))
        self.assertEqual(a.commit(self.store,digest,self.receipt(digest))['cleanup']['unlinked_allocated_bytes'],0)

    def test_pending_offline_and_wrong_destination_cannot_authorize_cleanup(self):
        _,path,digest=self.queued()
        _,different,_=self.fixture.fixture(content=b'different bytes with the same candidate filename')
        with self.store.locked():a.queue(self.store,[])
        self.assertNotEqual(digest,sha256(different))
        self.assertEqual(len(list(a.directory(self.store).glob('*.json'))),2)
        with self.store.locked():self.store.clean_held()
        self.assertTrue(path.exists());self.assertEqual(a.status(self.store)['verified_archived_bytes'],0)
        with self.assertRaises(RunError):a.commit(self.store,digest,{**self.receipt(digest),'archive_id':str(uuid4())})
        self.assertTrue(path.exists())
        atomic_json(self.store.infrastructure/'archive-config.json',{**self.config,'archive_id':str(uuid4())})
        with self.assertRaises(RunError):a.record(self.store,digest)

    def test_active_unknown_and_current_candidate_remain_protected(self):
        run,path,digest=self.queued()
        with self.store.locked():
            self.assertFalse(a.preview(self.store,[str(path)])['objects'])
        value=read_json(run/'result.json');atomic_json(run/'result.json',{**value,'outcome':'unknown'})
        with self.store.locked():self.assertFalse(a.preview(self.store,[])['objects'])
        with self.assertRaises(RunError):a.commit(self.store,digest,self.receipt(digest))
        self.assertTrue(path.exists())
        atomic_json(run/'result.json',value)
        atomic_json(self.store.infrastructure/'archive-config.json',{**self.config,'keep_local_digests':[digest]})
        a.commit(self.store,digest,self.receipt(digest));self.assertTrue(path.exists())
        atomic_json(self.store.infrastructure/'archive-config.json',self.config)
        alias,_,_=self.fixture.fixture()
        (self.store.infrastructure/'vm-history'/(alias.name+'.json')).unlink()
        a.commit(self.store,digest,self.receipt(digest));self.assertTrue(path.exists())

    def test_changed_source_and_failed_destination_receipt_retain_local_data(self):
        _,path,digest=self.queued();path.write_bytes(b'changed source')
        with self.assertRaises(RunError):a.commit(self.store,digest,self.receipt(digest))
        self.assertEqual(path.read_bytes(),b'changed source')
        value=a.record(self.store,digest);atomic_json(a.directory(self.store)/(digest+'.json'),{**value,'state':'failed'})
        with self.assertRaises(RunError):a.cleanup_actions(self.store,[],{digest})

    def test_truncated_or_corrupt_restore_never_exposes_partial_plaintext(self):
        _,path,digest=self.queued();original=path.read_bytes()
        a.commit(self.store,digest,self.receipt(digest))
        for content in (original[:-1],b'X'*len(original)):
            with patch.object(a.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(content))):
                with self.assertRaises(RunError):a.restore(self.store,digest)
            self.assertFalse(path.exists());self.assertFalse(path.with_name('candidate.iso.archive-part').exists())
        self.assertEqual(a.record(self.store,digest)['state'],'committed')

    def test_export_releases_host_lock_and_exact_stream_is_attributable(self):
        _,path,digest=self.queued();sink=io.BytesIO();store=self.store
        class Output:
            def write(self,data):
                self.assert_unlocked();return sink.write(data)
            def assert_unlocked(self):
                with store.locked():pass
            def flush(self):pass
        with patch.object(a.sys,'stdout',SimpleNamespace(buffer=Output())):a.export(self.store,digest)
        self.assertEqual(sink.getvalue(),path.read_bytes())
        self.assertEqual(a.record(self.store,digest)['state'],'transfer-started')


if __name__=='__main__':unittest.main()
