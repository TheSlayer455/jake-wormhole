"""Real age streaming with a local subprocess transport; not SSH/runtime proof."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4
from wormhole import archive_client as a

SERVER = '''import hashlib,json,pathlib,sys,time
op,sha,base=sys.argv[1:]; p=pathlib.Path(base)
if (p/'offline').exists(): sys.exit(1)
if (p/'stall').exists(): time.sleep(5)
value=json.loads((p/'listing').read_text())
if op=='archive-list': print(json.dumps(value))
elif op=='archive-export':
 with (p/'exports').open('a') as f: f.write('export\\n')
 sys.stdout.buffer.write((p/'source').read_bytes())
 if (p/'interrupt').exists(): sys.exit(2)
elif op=='archive-import':
 data=sys.stdin.buffer.read(); assert hashlib.sha256(data).hexdigest()==sha
 (p/'restored').write_bytes(data); print('{}')
elif op=='archive-commit':
 data=json.load(sys.stdin); assert data['sha256']==sha and data['verified']
 (p/'commit').write_text(json.dumps(data)); print('{}')
elif op=='archive-failed': (p/'failed').write_bytes(sys.stdin.buffer.read()); print('{}')
'''

@unittest.skipUnless(os.name == 'posix' and shutil.which('age'), 'Linux with age is required')
class ArchiveClient(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.base=Path(temp.name)
        self.root=self.base/'archive'; self.root.mkdir(); self.owner=str(uuid4())
        a.durable(self.root/'owner.json',{'schema_version':'1.0','archive_id':self.owner})
        key=self.base/'identity'; key.write_bytes(subprocess.check_output(['age-keygen'],stderr=subprocess.DEVNULL)); key.chmod(0o600)
        recipient=subprocess.check_output(['age-keygen','-y',str(key)],text=True).strip()
        self.config=self.base/'config'; a.durable(self.config,{'archive_id':self.owner,'root':str(self.root),
            'identity':str(key),'recipient':recipient,'ssh':['ssh','fixture'],'command':'fixture','reserve_bytes':0,'timeout_seconds':20})
        self.data=b'actual age archive\0'*100000; self.sha=hashlib.sha256(self.data).hexdigest()
        (self.base/'source').write_bytes(self.data)
        a.durable(self.base/'listing',{'archive_id':self.owner,'objects':[{'sha256':self.sha,'bytes':len(self.data),'state':'pending'}]})
        transport=patch.object(a.Client,'remote',lambda client,operation,digest=None:[sys.executable,'-c',SERVER,operation,digest or '',str(self.base)])
        transport.start(); self.addCleanup(transport.stop)

    def call(self, operation, digest=None): return a.run(operation,self.config,digest)

    def test_real_encryption_readback_duplicate_and_restore(self):
        self.assertEqual(self.call('sync')['outcome'],'complete')
        self.assertNotIn(self.data[:64],(self.root/'objects'/f'{self.sha}.age').read_bytes())
        (self.root/'objects'/f'{self.sha}.json').unlink()  # Crash after final ciphertext rename.
        self.call('sync'); self.assertEqual((self.base/'exports').read_text(),'export\n')
        self.call('verify'); self.call('restore',self.sha)
        self.assertEqual((self.base/'restored').read_bytes(),self.data)
        receipt=json.loads((self.base/'commit').read_text()); self.assertEqual(receipt['bytes'],len(self.data))

    def test_corruption_never_imports_and_notifies_server(self):
        self.call('sync'); path=self.root/'objects'/f'{self.sha}.age'
        path.write_bytes(path.read_bytes()[:-5]+b'wrong')
        with self.assertRaises(a.ArchiveError): self.call('restore',self.sha)
        self.assertTrue((self.base/'failed').exists()); self.assertFalse((self.base/'restored').exists())
        self.assertEqual(json.loads((self.root/'status.json').read_text())['outcome'],'failed')

    def test_failed_export_retains_partial_without_ack_and_retry_recovers(self):
        (self.base/'interrupt').touch()
        with self.assertRaises(a.ArchiveError): self.call('sync')
        self.assertFalse((self.base/'commit').exists())
        self.assertFalse((self.root/'objects'/f'{self.sha}.age').exists())
        self.assertTrue((self.root/'objects'/f'{self.sha}.age.part').exists())
        (self.base/'interrupt').unlink(); self.call('sync')
        self.assertTrue((self.base/'commit').exists())

    def test_owner_lock_offline_and_deadline_refuse_without_ack(self):
        client=a.Client(self.config)
        with a.lock(self.root/'archive.lock'):
            with self.assertRaises(a.ArchiveError): self.call('sync')
        (self.base/'offline').touch()
        with self.assertRaises(a.ArchiveError): self.call('sync')
        (self.base/'offline').unlink(); (self.base/'stall').touch()
        config=a.read_json(self.config); config['timeout_seconds']=1; a.durable(self.config,config)
        with self.assertRaises(a.ArchiveError) as error: self.call('sync')
        self.assertEqual(error.exception.code,'archive_timeout'); self.assertFalse((self.base/'commit').exists())
        a.durable(self.root/'owner.json',{'schema_version':'1.0','archive_id':str(uuid4())})
        with self.assertRaises(a.ArchiveError): client.guard()
        (self.root/'owner.json').unlink(); (self.root/'owner.json').symlink_to(self.config)
        with self.assertRaises(a.RunError): self.call('sync')
