"""Real local files/locks; subprocess fixtures are not VM acceptance evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import intake as i, rhel_inputs as r, ubuntu_intake as u
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

    def complete_ubuntu(self):
        dependencies=self.base/'dependencies';(dependencies/'bundle').mkdir(parents=True)
        atomic_json(dependencies/'bundle/manifest.json',{'files':[]})
        identity,inputs=u.input_identity(dependencies,'hardened',sandbox=True)
        build={'capability':'ubuntu-assessment-candidate-iso','source':u.UBUNTU,
            'mode':'hardened','sandbox':True,'candidate_sha256':sha256(self.iso),
            'installed_input_fingerprint':identity,'installed_inputs':inputs,
            'policy_sha256':sha256(u.POLICY),'dependency_manifest_sha256':sha256(dependencies/'bundle/manifest.json')}
        sidecar=self.inbox/'build.json';atomic_json(sidecar,build)
        marker={'schema_version':'2.0','iso':self.iso.name,'bytes':self.iso.stat().st_size,
            'sha256':sha256(self.iso),'contract_sha256':fingerprint(u.installation_contract()),
            'build_manifest':sidecar.name,'build_manifest_sha256':sha256(sidecar)}
        atomic_json(self.marker,marker)
        return dependencies,{**marker,'build':build}

    def test_ubuntu_bound_sidecar_uses_same_dispatch_and_preserves_password_required_contract(self):
        from wormhole import vm_baseline as vm
        dependencies,delivery=self.complete_ubuntu();request=i.register(self.marker,store=self.store)
        self.assertEqual(request['delivery'],delivery)
        record=self.root/'intake/requests'/(request['request_id']+'.json')
        with self.assertRaises(RunError) as missing:i.submit(request['request_id'],'fixture',store=self.store)
        self.assertEqual(missing.exception.code,'ubuntu_intake_store_required')
        self.assertEqual(read_json(record)['state'],'registered')
        def execute(source,terraform,**arguments):
            self.assertEqual(arguments['distribution'],'ubuntu');self.assertEqual(arguments['ubuntu_mode'],'hardened')
            self.assertTrue(arguments['sandbox']);self.assertEqual(arguments['dependency_store'],dependencies)
            self.assertEqual(sha256(source),delivery['sha256'])
            return {'run_id':arguments['request_run'],'delivery':delivery,'outcome':'assessment-complete',
                'cleanup':'verified-absent-inputs-retained','checks':{'fixture':'pass'}}
        with patch.object(vm,'execute',side_effect=execute) as dispatch:
            results=i.scan(self.inbox,execute=True,terraform='fixture',store=self.store,dependency_store=dependencies)
            self.assertEqual(results[0]['outcome'],'assessment-complete')
            self.assertFalse(results[0]['lab_iso_qualified'])
            i.scan(self.inbox,execute=True,terraform='fixture',store=self.store,dependency_store=dependencies)
            self.assertEqual(dispatch.call_count,1)
        (self.inbox/'build.json').write_text('{}')
        with self.assertRaises(RunError) as changed:i.completed_delivery(self.marker)
        self.assertEqual(changed.exception.code,'delivery_build_manifest_mismatch')

    def test_ubuntu_stale_inputs_and_oversized_or_unbound_sidecars_refuse_before_dispatch(self):
        dependencies,delivery=self.complete_ubuntu();request=i.register(self.marker,store=self.store)
        atomic_json(dependencies/'bundle/manifest.json',{'files':[],'changed_installed_input':True})
        with self.assertRaises(RunError) as changed:
            i.submit(request['request_id'],'fixture',store=self.store,dependency_store=dependencies)
        self.assertEqual(changed.exception.code,'stale_candidate')
        self.assertFalse((self.store.runs/request['run_id']).exists())
        (self.inbox/'build.json').write_bytes(b' '*65537)
        with self.assertRaises(RunError) as bounded:i.completed_delivery(self.marker)
        self.assertEqual(bounded.exception.code,'delivery_manifest_bound')
        legacy={k:v for k,v in delivery.items() if k not in {'build','build_manifest','build_manifest_sha256'}}
        atomic_json(self.marker,{**legacy,'schema_version':'1.0'})
        with self.assertRaises(RunError):i.completed_delivery(self.marker)

    def test_ubuntu_unchanged_media_fresh_private_seed_and_actual_payload_refusals(self):
        from uuid import uuid4
        from wormhole import ubuntu_inputs, ubuntu_hardening
        dependencies,delivery=self.complete_ubuntu();payload=b'fixture installed input\n'
        import hashlib
        files={'finalize.sh':(len(payload),hashlib.sha256(payload).hexdigest())}
        boot='linux /casper/vmlinuz autoinstall console=ttyS0,115200n8 ---\n'
        extra=False;corrupt=False;calls=[]
        def command(args,**kwargs):
            calls.append(args)
            if '-find' in args:
                names=[] if args.count('-not')==2 else ['/wormhole/finalize.sh']+(['/wormhole/extra'] if extra else [])
                kwargs['stdout'].write(''.join(repr(p)+'\n' for p in names).encode())
            elif '-extract_cut' in args:
                for at,token in enumerate(args):
                    if token!='-extract_cut':continue
                    source=args[at+1];target=Path(args[at+4]);count=int(args[at+3])
                    if source.startswith('/boot/'):raw=boot.encode()
                    elif source.startswith('/wormhole/'):raw=payload+(b'bad' if corrupt else b'')
                    else:raw=(target.parent.parent/'wormhole-identity'/target.name).read_bytes()
                    target.write_bytes(raw[:count])
            else:
                self.assertEqual(args[:3],['xorriso','-as','mkisofs'])
                identity=Path(args[-1].split('=',1)[1])
                Path(args[args.index('-o')+1]).write_bytes(b''.join(p.read_bytes() for p in sorted(identity.iterdir())))
        def prepare():
            identifier=str(uuid4());target=self.base/identifier;target.mkdir(mode=0o700)
            support=target/'support-private';support.mkdir(mode=0o700)
            for name in ('ca.crt','ca.crl','active.crt','revoked.crt'):(support/name).write_text('synthetic public certificate')
            result=u.prepare_delivered(self.iso,target/'candidate.iso',target/'inputs',identifier,
                'ssh-rsa '+'A'*400,'192.0.2.10/24','52:54:00:11:22:33',store=dependencies,
                password_hash='$6$synthetic$'+'A'*86,
                boot_hash='grub.pbkdf2.sha512.100000.'+'A'*128+'.'+'B'*128,delivery=delivery)
            config=(target/'inputs/user-data').read_text()
            self.assertIn('lab.service ALL=(ALL) ALL',config);self.assertNotIn('NOPASSWD',config)
            self.assertNotIn('$6$synthetic',config)
            self.assertEqual((target/'inputs/wormhole-identity/password').stat().st_mode & 0o777,0o600)
            self.assertNotIn('build',result['delivery'])
            return result
        with patch.object(u,'expected_payload',return_value=files),patch.object(u.subprocess,'run',side_effect=command),\
             patch.object(ubuntu_inputs,'build',side_effect=AssertionError('no builder')),\
             patch.object(ubuntu_hardening,'generate',side_effect=AssertionError('no remediation generator')):
            first=prepare();second=prepare()
            self.assertEqual(first['candidate_sha256'],delivery['sha256'])
            self.assertEqual(first['candidate_sha256'],second['candidate_sha256'])
            self.assertNotEqual(first['seed_sha256'],second['seed_sha256'])
            self.assertFalse(any('-outdev' in c or '-map' in c for c in calls))
            corrupt=True
            with self.assertRaises(RunError) as changed:prepare()
            self.assertEqual(changed.exception.code,'delivered_payload_mismatch')
            corrupt=False;extra=True
            with self.assertRaises(RunError) as undeclared:prepare()
            self.assertEqual(undeclared.exception.code,'delivered_payload_mismatch')
            extra=False;boot=boot.replace('autoinstall','autoinstall ds=nocloud-net;s=https://example.invalid/')
            with self.assertRaises(RunError) as injected:prepare()
            self.assertEqual(injected.exception.code,'unsupported_installation_contract')

    def test_ubuntu_expected_payload_hashes_pinned_files_without_creating_remediation(self):
        from wormhole import ubuntu_tailoring
        import hashlib
        source=self.base/'source';guest=source/'ubuntu/guest';guest.mkdir(parents=True)
        names={'finalize.sh','audit.sh','observe.py','remediate.py','encryption-late.sh','sandbox.sh',
            'entitlement.py','audit-offload.py','secret-audit.py','pkcs11-probe.py'}
        for name in names:(guest/name).write_text('fixture '+name)
        dependencies=self.base/'dependencies';bundle=dependencies/'bundle';bundle.mkdir(parents=True)
        atomic_json(bundle/'manifest.json',{'files':[{'path':'repository/pinned.deb','bytes':4,'sha256':'a'*64}]})
        raw="# BEGIN fix (1 / 1) for 'xccdf_org.ssgproject.content_rule_sample'\necho fixture\n# END fix for 'xccdf_org.ssgproject.content_rule_sample'"
        upstream=dependencies/'ubuntu2204-script-stig.sh';upstream.write_text(raw)
        atomic_json(source/'ubuntu/remediation-plan-v1.json',{'upstream_script_sha256':sha256(upstream),
            'remediation_rules':['sample']})
        before=set(self.base.rglob('*'))
        with patch.object(u,'SOURCE_ROOT',source),patch.object(ubuntu_tailoring,'document',return_value=None):
            result=u.expected_payload(dependencies)
            self.assertEqual(set(result),names | {'repository/pinned.deb','manifest.json','policy.json',
                'remediation/sample.sh','remediation-plan.json','offline-apt.conf','install-contract.json',
                'wormhole-finalize.service'})
            block=b'\necho fixture\n'
            self.assertEqual(result['remediation/sample.sh'],(len(block),hashlib.sha256(block).hexdigest()))
            self.assertEqual(before,set(self.base.rglob('*')))
            upstream.write_text(raw+'changed')
            with self.assertRaises(RunError) as stale:u.expected_payload(dependencies)
            self.assertEqual(stale.exception.code,'remediation_content_mismatch')

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

    def test_existing_protected_candidate_reuses_verified_store_proof_not_inbox_links(self):
        from test_storage import Cleanup
        from wormhole import vm_baseline as vm
        self.shared=self.store.shared;self.shared.mkdir(mode=0o700)
        self.store.runs.mkdir(mode=0o700);self.store.live={};self.store.qemu_uid=os.geteuid
        (self.store.infrastructure/'vm-history').mkdir(mode=0o700)
        origin,candidate,_=Cleanup.fixture(self,content=self.iso.read_bytes())
        candidate.chmod(0o640) # The existing QEMU read-only group contract.
        self.complete();request=i.register(self.marker,store=self.store)
        self.assertEqual(request['candidate_origin_run'],origin.name)
        self.assertEqual(list((self.root/'intake/candidates').glob('*.iso')),[])
        self.assertNotEqual(candidate.stat().st_ino,self.iso.stat().st_ino)
        with patch.object(vm,'execute',side_effect=self.fake_execution) as execute:
            i.submit(request['request_id'],'fixture',store=self.store)
        self.assertEqual(execute.call_args.args[0],candidate)

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
