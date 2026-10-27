"""Small synthetic ISO-shaped bytes exercise streaming failure contracts only."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from wormhole import media_store as m
from wormhole.runs import RunError,atomic_json


@unittest.skipUnless(sys.platform.startswith('linux'),'Private media storage requires Linux ownership and flock.')
class StreamingMedia(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        raw=bytearray((bytes(range(256))*900));raw[32769:32774]=b'CD001'
        self.raw=bytes(raw);self.source=self.root/'fixture.iso';self.source.write_bytes(self.raw)
        self.sha=hashlib.sha256(self.raw).hexdigest();self.store=self.root/'store'

    def imported(self):
        result=m.split(self.source,self.store,self.sha,chunk_bytes=65536)
        return Path(result['manifest']),m.load(result['manifest'])

    def test_roundtrip_streams_exact_bytes_and_refuses_duplicate_destination(self):
        manifest,value=self.imported();destination=self.root/'restored.iso'
        result=m.assemble(manifest,self.store,destination)
        self.assertEqual(destination.read_bytes(),self.raw)
        self.assertEqual(result['sha256'],self.sha);self.assertEqual(result['resumed_chunks'],0)
        self.assertFalse(result['lab_iso_qualified']);self.assertFalse(result['production_iso_eligible'])
        with self.assertRaises(RunError):m.assemble(manifest,self.store,destination)

    def test_interrupted_output_rechecks_prefix_and_discards_uncheckpointed_tail(self):
        manifest,value=self.imported();destination=self.root/'resumed.iso'
        partial=destination.with_name(destination.name+'.partial');partial.write_bytes(self.raw[:65536]+b'interrupted')
        partial.chmod(0o600)
        atomic_json(destination.with_name(destination.name+'.reconstruction.json'),{
            'operation':'iso-reconstruction-v1','manifest_sha256':m.fingerprint(value),'bytes':len(self.raw),'completed_chunks':1})
        result=m.assemble(manifest,self.store,destination)
        self.assertEqual(result['resumed_chunks'],1);self.assertEqual(destination.read_bytes(),self.raw)

    def test_corrupt_missing_and_misordered_chunks_never_publish_iso(self):
        for kind in ('corrupt','missing','order'):
            with self.subTest(kind=kind):
                store=self.root/('store-'+kind)
                manifest=Path(m.split(self.source,store,self.sha,chunk_bytes=65536)['manifest'])
                value=m.load(manifest);chunk=store/value['chunks'][1]['object']
                if kind=='corrupt':chunk.write_bytes(b'x'*chunk.stat().st_size)
                elif kind=='missing':chunk.unlink()
                else:
                    value['chunks'][0],value['chunks'][1]=value['chunks'][1],value['chunks'][0]
                    atomic_json(manifest,value)
                destination=self.root/(kind+'.iso')
                with self.assertRaises((RunError,OSError)):m.assemble(manifest,store,destination)
                self.assertFalse(destination.exists())

    def test_wrong_whole_hash_never_publishes_manifest(self):
        with self.assertRaises(RunError) as error:m.split(self.source,self.store,'a'*64,chunk_bytes=65536)
        self.assertEqual(error.exception.code,'media_source_hash')
        self.assertFalse(any((self.store/'manifests').iterdir()))

    def test_foreign_store_and_changed_checkpoint_refuse(self):
        foreign=self.root/'foreign';foreign.mkdir(mode=0o700);(foreign/'unrelated').write_text('preserve')
        with self.assertRaises(RunError):m.split(self.source,foreign,self.sha)
        self.assertEqual((foreign/'unrelated').read_text(),'preserve')
        manifest,value=self.imported();destination=self.root/'wrong.iso'
        partial=destination.with_name(destination.name+'.partial');partial.write_bytes(b'');partial.chmod(0o600)
        atomic_json(destination.with_name(destination.name+'.reconstruction.json'),{
            'operation':'iso-reconstruction-v1','manifest_sha256':'b'*64,'bytes':len(self.raw),'completed_chunks':0})
        with self.assertRaises(RunError):m.assemble(manifest,self.store,destination)


class MediaManifest(unittest.TestCase):
    def test_false_qualification_boolean_sizes_and_unordered_offsets_refuse(self):
        value={'schema_version':'2.0','capability':'iso-source-chunks','source_name':'input.iso',
            'bytes':65536,'sha256':'a'*64,'chunk_bytes':65536,
            'chunks':[{'index':0,'offset':0,'bytes':65536,'sha256':'b'*64,'object':'objects/'+'b'*64+'.chunk'}],
            'lab_iso_qualified':False,'production_iso_eligible':False}
        self.assertIs(m.validate(value),value)
        for field,changed in (('lab_iso_qualified',True),('production_iso_eligible',True),('bytes',True),('source_name','../escape.iso')):
            bad=deepcopy(value);bad[field]=changed
            with self.assertRaises(RunError):m.validate(bad)


if __name__=='__main__':unittest.main()
