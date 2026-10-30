"""Real local files/locks; subprocess fixtures are not VM acceptance evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import intake as i, rhel_inputs as r
from wormhole.media_store import fingerprint
from wormhole.runs import RunError, atomic_json, read_json
from wormhole.storage import Store
from wormhole.vm_inputs import sha256


@unittest.skipUnless(os.name=='posix','Linux private intake and VM controller')
class Intake(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.inbox=self.base/'inbox';self.inbox.mkdir(mode=0o700)
        self.root=self.base/'project/runtime';self.root.mkdir(parents=True,mode=0o700)
        self.store=Store(self.root,self.base/'shared');self.store.infrastructure.mkdir(mode=0o700)
        atomic_json(self.store.infrastructure/'owner.json',{'application':'jake-wormhole',
            'schema_version':'1.0','kind':'shared-infrastructure-root'})
        previous=os.umask(0o077);self.addCleanup(os.umask,previous)
        self.observe=patch.object(self.store,'observe',return_value=[]);self.observe.start();self.addCleanup(self.observe.stop)
        self.iso=self.inbox/'delivered.iso';self.iso.write_bytes(b'A'*65536)
        self.marker=self.inbox/'delivery.ready.json'

    def complete(self):
        value={'schema_version':'1.0','iso':self.iso.name,'bytes':self.iso.stat().st_size,
            'sha256':sha256(self.iso),'contract_sha256':fingerprint(r.installation_contract())}
        atomic_json(self.marker,value);return value

    def fake_execution(self,source,terraform,**kwargs):
        self.assertEqual(sha256(source),kwargs['delivery']['sha256'])
        self.assertEqual(kwargs['distribution'],'rhel10')
        run=self.store.runs/kwargs['request_run'];run.mkdir(parents=True,mode=0o700)
        result={'run_id':kwargs['request_run'],'delivery':kwargs['delivery'],
            'outcome':'baseline-passed','cleanup':'verified-absent-inputs-retained','checks':{'fixture':'pass'}}
        atomic_json(run/'result.json',result);return result

    def test_completed_manual_and_scan_share_dispatch_with_independent_staging(self):
        delivered=self.complete();request=i.register(self.marker,store=self.store)
        staged=self.root/'intake/candidates'/(delivered['sha256']+'.iso')
        self.assertNotEqual(self.iso.stat().st_ino,staged.stat().st_ino)
        self.assertEqual(staged.stat().st_mode & 0o777,0o400)
        self.iso.write_bytes(b'B'*65536)
        self.assertEqual(sha256(staged),delivered['sha256'])
        from wormhole import vm_baseline as vm
        with patch.object(vm,'execute',side_effect=self.fake_execution) as execute:
            self.assertEqual(i.submit(request['request_id'],'fixture',store=self.store)['outcome'],'baseline-passed')
            repeated=i.scan(self.inbox,execute=True,terraform='fixture',store=self.store)
            self.assertEqual(repeated[0]['run_id'],request['run_id']);self.assertEqual(execute.call_count,1)
        self.assertFalse(repeated[0]['lab_iso_qualified'])

    def test_unfinished_corrupt_or_unsupported_delivery_never_submits(self):
        with self.assertRaises(RunError):i.scan(self.base/'missing-inbox',store=self.store)
        self.assertEqual(i.scan(self.inbox,store=self.store),[])
        delivered=self.complete();self.iso.write_bytes(b'incomplete')
        with self.assertRaises(RunError):i.register(self.marker,store=self.store)
        self.iso.write_bytes(b'B'*delivered['bytes'])
        with self.assertRaises(RunError):i.register(self.marker,store=self.store)
        atomic_json(self.marker,{**delivered,'contract_sha256':'0'*64})
        with self.assertRaises(RunError):i.register(self.marker,store=self.store)
        self.assertEqual(list((self.root/'intake/candidates').glob('*')),[])
        self.assertFalse(self.store.runs.exists())

    def test_real_admission_contention_does_not_create_a_phantom_running_attempt(self):
        from wormhole import vm_baseline as vm, admission
        self.complete();request=i.register(self.marker,store=self.store)
        record=self.root/'intake/requests'/(request['request_id']+'.json')
        with patch.object(vm,'ROOT',self.root),patch.object(vm,'source_identity',return_value=('a'*40,False)),\
             patch.object(vm,'TF_SHA',sha256(self.iso)),\
             patch.object(vm,'CANONICAL_INFRASTRUCTURE_ROOT',self.store.infrastructure),\
             patch.object(admission,'CANONICAL_INFRASTRUCTURE_ROOT',self.store.infrastructure):
            with self.store.locked():
                with self.assertRaises(RunError) as error:i.submit(request['request_id'],str(self.iso),store=self.store)
            self.assertEqual(error.exception.code,'media_store_busy')
            self.assertEqual(read_json(record)['state'],'registered')
            self.assertFalse((self.store.runs/request['run_id']).exists())
            with patch.object(vm,'TF_SHA','0'*64):
                with self.assertRaises(RunError):i.submit(request['request_id'],str(self.iso),store=self.store)
            self.assertEqual(read_json(record)['last_prelaunch_refusal'],'unverified_execution_inputs')

    def test_interrupted_dispatch_reconciles_failure_without_relaunch(self):
        self.complete();request=i.register(self.marker,store=self.store)
        record=self.root/'intake/requests'/(request['request_id']+'.json')
        atomic_json(record,{**request,'state':'submitted'})
        from wormhole import vm_baseline as vm
        with patch.object(vm,'execute',side_effect=AssertionError('must not launch')):
            self.assertEqual(i.submit(request['request_id'],'fixture',store=self.store)['observation'],'launch-outcome-unknown')
            run=self.store.runs/request['run_id'];run.mkdir(parents=True,mode=0o700)
            atomic_json(run/'result.json',{'run_id':request['run_id'],'delivery':request['delivery'],
                'outcome':'failed','cleanup':'verified-absent-inputs-retained','error_category':'readiness-failed',
                'checks':{'readiness':'fail','validation':'blocked'}})
            result=i.scan(self.inbox,execute=True,terraform='fixture',store=self.store)[0]
            self.assertEqual(result['outcome'],'failed');self.assertEqual(result['error_category'],'readiness-failed')
            self.assertEqual(result['checks']['validation'],'blocked');self.assertFalse(result['lab_iso_qualified'])
        again=i.register(self.marker,generation='requalification-2',store=self.store)
        self.assertNotEqual(again['run_id'],request['run_id'])
        self.assertEqual(read_json(record)['outcome'],'failed')

    def test_same_filename_new_bytes_and_new_assessment_each_get_a_new_request(self):
        self.complete();first=i.register(self.marker,store=self.store)
        self.iso.write_bytes(b'B'*65536);self.complete();second=i.register(self.marker,store=self.store)
        self.assertNotEqual(first['request_id'],second['request_id'])
        context=i.acceptance_context()
        with patch.object(i,'acceptance_context',return_value={**context,'assessment_content_sha256':'b'*64}):
            third=i.register(self.marker,store=self.store)
        self.assertNotEqual(second['request_id'],third['request_id'])
        self.assertEqual(second['delivery'],third['delivery'])
        self.assertEqual(len(list((self.root/'intake/candidates').glob('*.iso'))),2)

    def test_preparation_only_copies_iso_and_makes_a_fresh_declared_seed(self):
        delivery=self.complete();calls=[]
        boot='set default="0"\n linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL='+r.LABEL+' inst.ks=hd:LABEL=WORMHOLEKS:/ks.cfg console=ttyS0,115200n8\n'
        def command(args,**kwargs):
            calls.append(args)
            if '-extract' in args:Path(args[-1]).write_text(boot)
            else:
                self.assertEqual(args[:3],['xorriso','-as','mkisofs'])
                self.assertEqual(args[args.index('-V')+1],r.SEED_LABEL)
                Path(args[args.index('-o')+1]).write_bytes(Path(args[-1]).read_bytes())
        from uuid import uuid4
        with patch.object(r.subprocess,'run',side_effect=command),patch.object(r,'build_rhel',side_effect=AssertionError('no builder')):
            manifests=[]
            for _ in range(2):
                identifier=str(uuid4());target=self.base/identifier;target.mkdir()
                manifests.append(r.prepare_delivered(self.iso,target/'candidate.iso',target/'inputs',identifier,
                    'ssh-ed25519 '+'A'*68,'192.0.2.10/24','52:54:00:11:22:33',
                    password_hash='$6$synthetic$'+'A'*86,delivery=delivery))
            self.assertEqual(manifests[0]['candidate_sha256'],manifests[1]['candidate_sha256'])
            self.assertNotEqual(manifests[0]['seed_sha256'],manifests[1]['seed_sha256'])
            self.assertFalse(any('-outdev' in c or c[0]=='implantisomd5' for c in calls))
            boot=boot.replace('inst.ks=hd:LABEL=WORMHOLEKS:/ks.cfg','inst.ks=hd:LABEL=WORMHOLEKS:/ks.cfg.bad')
            with self.assertRaises(RunError):
                r.prepare_delivered(self.iso,self.base/'bad.iso',self.base/'bad-inputs',str(uuid4()),
                    'ssh-ed25519 '+'A'*68,'192.0.2.10/24','52:54:00:11:22:33',
                    password_hash='$6$synthetic$'+'A'*86,delivery=delivery)
            self.assertFalse((self.base/'bad.iso').exists())
