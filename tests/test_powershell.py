"""Synthetic public bytes/protocol checks, no PowerShell or host/container installs."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.request
from unittest.mock import Mock, patch

from wormhole import images, powershell as p
from wormhole.runs import atomic_json, create_run, read_json

SPEC = importlib.util.spec_from_file_location('fixed_optional_powershell_runtime', p.CONTEXT / 'runtime.py')
runtime = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runtime)
SHA = 'a' * 40


class Response:
    def __init__(self, raw, url=p.PS_URL): self.raw,self.url=raw,url
    def __enter__(self): return self
    def __exit__(self,*_): pass
    def geturl(self): return self.url
    def read1(self, size): value,self.raw=self.raw[:size],self.raw[size:];return value


class OptionalPolicy(unittest.TestCase):
    def test_separate_source_pins_leave_original_image_policy_unchanged(self):
        lock=p.load_lock();recipe,files=images.recipe_identity()
        self.assertEqual(lock['base_recipe_sha256'],recipe);self.assertEqual(lock['base_source_files'],files)
        self.assertEqual(images.MAX_DOWNLOAD,16*1024*1024)
        self.assertEqual(len(images.FILES),7);self.assertEqual(p.MAX_FILE,64*1024*1024)
        self.assertEqual(sum(x['bytes'] for x in lock['artifacts']),66269596)
        self.assertEqual(lock['installed_files']['pwsh'],'873de21f04b6a0269c220f9c8396ff5cd639e8deb058a32cc26df54b69bbff8d')

    def test_exact_single_github_release_redirect_drops_credentials_and_rejects_fallbacks(self):
        request=urllib.request.Request(p.PS_URL,headers={'Authorization':'synthetic-never-forward','Cookie':'synthetic-never-forward'})
        policy=p.RedirectPolicy(p.PS_URL)
        target='https://release-assets.githubusercontent.com/public-fixture?signature=temporary-not-persisted'
        redirected=policy.redirect_request(request,None,302,'',{},target)
        self.assertEqual(redirected.header_items(),[])
        for value in (target,'https://example.invalid/file','http://release-assets.githubusercontent.com/file'):
            with self.assertRaises(p.CapabilityError):policy.redirect_request(request,None,302,'',{},value)
        with self.assertRaises(p.CapabilityError):p.RedirectPolicy(p.ICU_URL).redirect_request(urllib.request.Request(p.ICU_URL),None,302,'',{},target)

    def test_streamed_exact_size_hash_download_and_failed_partial_are_not_accepted(self):
        for fault in ('healthy','hash','short','long','redirect'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='wormhole-ps-synthetic-') as folder:
                destination=Path(folder)/'powershell.deb';raw=b'public synthetic bytes'
                item={'url':p.PS_URL,'filename':'powershell.deb','bytes':len(raw),'sha256':p.sha(raw)}
                body=raw[:-1] if fault=='short' else raw+b'x' if fault=='long' else b'x'*len(raw) if fault=='hash' else raw
                opener=lambda *_args,**_kwargs:Response(body,'https://example.invalid/file' if fault=='redirect' else p.PS_URL)
                if fault=='healthy':
                    p.fetch(item,destination,opener=opener);self.assertEqual(p.hash_file(destination,item),len(raw))
                else:
                    with self.assertRaises(p.CapabilityError):p.fetch(item,destination,opener=opener)
                    self.assertFalse(destination.exists())

    def test_oversized_download_configuration_never_opens_a_source(self):
        item={'url':p.PS_URL,'filename':'powershell.deb','bytes':p.MAX_FILE+1,'sha256':'a'*64}
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(p.CapabilityError):
            p.fetch(item,Path(folder)/'powershell.deb',opener=Mock(side_effect=AssertionError('No request')))

    def test_worker_timeout_and_incomplete_cache_never_authorize_allocation(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-ps-synthetic-') as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False))
            result={'status':'timeout','log':b'','log_truncated':False}
            with patch.object(p,'_run_process',return_value=result),patch.object(images,'docker',side_effect=AssertionError('No Docker')):
                with self.assertRaises(p.CapabilityError) as error:p.prepare(run,p.load_lock())
            self.assertEqual(error.exception.code,'capability_preparation_timeout')
            run.file('private/powershell-artifacts').mkdir(mode=0o700)
            with self.assertRaises(p.CapabilityError):p.validate_cache(run,p.load_lock())

    def test_explicit_selection_platform_and_unknown_recovery_fail_before_docker(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-ps-synthetic-') as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False))
            with patch.object(images,'docker',side_effect=AssertionError('No Docker')):
                for selection in ('','auto','ordinary-helper','missing-package-fixture'):
                    with self.assertRaises(p.CapabilityError):p.execute(run,selection=selection)
                with patch.object(p,'source_identity',return_value=(SHA,False)),patch.object(images,'RUNS_ROOT',run.workspace),patch.object(p.sys,'platform','linux'):
                    recipe,files=p.recipe_identity()
                    receipt={**p.common(run.manifest()),'component':'optional-powershell','operation':'probe',
                        'selection':'missing-package-fixture','unknown_outcome':True,'resources_reconciled':False,
                        'recipe_sha256':recipe,'source_files':files,'container_id':'c'*64}
                    atomic_json(run.file('evidence/powershell-capability.json'),receipt)
                    with self.assertRaises(p.CapabilityError):p.recover(run)

    def test_mutating_requests_are_durably_unknown_before_call_and_allocations_wait_for_identity(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-ps-synthetic-') as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));receipt={'unknown_outcome':False}
            def operation(*_args,**_kwargs):
                self.assertIs(read_json(run.file('evidence/powershell-capability.json'))['unknown_outcome'],True)
                return {'log':b'c'*64,'status':'pass'}
            with patch.object(images,'docker',side_effect=operation):p.mutation(run,receipt,['create'],keep_unknown=True)
            self.assertIs(receipt['unknown_outcome'],True)
            with patch.object(images,'docker',side_effect=images.ImageError('docker_request_unknown','synthetic')):
                with self.assertRaises(images.ImageError):p.mutation(run,receipt,['start'])
            self.assertIs(read_json(run.file('evidence/powershell-capability.json'))['unknown_outcome'],True)

    @unittest.skipUnless(os.name=='posix','Public single-file bind identities require POSIX')
    def test_public_source_inodes_hashes_modes_and_private_parents_are_bound(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-ps-synthetic-') as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));mounts=p.binding_files(run)
            records={destination:p.binding_identity(path) for destination,path in mounts.items()}
            p.verify_bindings(run,mounts,False,records)
            path=Path(next(iter(mounts.values())));raw=path.read_bytes();previous=path.stat().st_ino
            path.rename(path.with_name('retained-old-inode.py'))
            path.write_bytes(raw);path.chmod(0o444)
            self.assertNotEqual(path.stat().st_ino,previous,'Keep the old inode allocated so this actually tests substitution')
            with self.assertRaises(p.CapabilityError):p.verify_bindings(run,mounts,False,records)
            self.assertEqual(path.parent.stat().st_mode&0o777,0o700)


class FixedRuntime(unittest.TestCase):
    def test_smoke_uses_fixed_noninteractive_no_profile_script_and_separate_actual_versions(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-ps-runtime-synthetic-') as folder:
            root=Path(folder);lock={'dependency_packages':['libicu74'],'icu_version':'synthetic-icu',
                'package_version':'7.6.8-1.deb','installed_files':{}}
            (root/'lock.json').write_text(json.dumps(lock))
            observed={'version':'7.6.8','edition':'Core','platform':'Unix','dotnet':'10.0.synthetic','result':2}
            def capture(argv,timeout):
                self.assertEqual(argv,['/opt/microsoft/powershell/7/pwsh','-NoLogo','-NoProfile','-NonInteractive','-Command',runtime.SCRIPT])
                self.assertEqual(timeout,20);return 0,json.dumps(observed).encode()
            base=Mock();base.doctor.return_value={'passed':True}
            with patch.object(runtime,'ROOT',root),patch.object(runtime,'base_runtime',return_value=base),\
                 patch.object(runtime,'query',side_effect=lambda name:'synthetic-icu' if name=='libicu74' else '7.6.8-1.deb'),\
                 patch.object(runtime,'capture',side_effect=capture):
                value=runtime.doctor();self.assertEqual(value['powershell'],observed)
                self.assertEqual(value['scanner_compatibility'],'unavailable-no-authorized-package-or-documented-method')
                observed['version']='unverified'
                with self.assertRaises(ValueError):runtime.doctor()

    def test_missing_package_empty_source_status_location_and_ordinary_diagnostics_are_independent(self):
        for success in (True,False):
            with tempfile.TemporaryDirectory(prefix='wormhole-ps-empty-source-synthetic-') as folder:
                root=Path(folder)/'isolated-empty';original=Path
                def mapped(value):return root if str(value)=='/tmp/wormhole-empty-package-source' else original(value)
                def capture(argv,timeout):
                    self.assertEqual(argv[0:2],['/usr/bin/apt-get','-s']);self.assertEqual(argv[-2:],['install',runtime.PACKAGE])
                    self.assertIn('Dir::State::status='+str(root/'status'),argv)
                    self.assertIn('Dir::Etc::sourcelist='+str(root/'sources.list'),argv)
                    self.assertFalse(any('https://' in x or '--fix-broken' in x for x in argv))
                    return (100,b'E: Unable to locate package powershell\n') if success else (0,b'Unexpected available package')
                base=Mock();base.doctor.return_value={'passed':True,'checks':{'ansible-core':{'passed':True}}}
                with patch.object(runtime,'Path',side_effect=mapped),patch.object(runtime,'base_runtime',return_value=base),patch.object(runtime,'capture',side_effect=capture):
                    if success:
                        value=runtime.missing_package();self.assertEqual(value['status'],'failed')
                        self.assertEqual(value['failure']['execution_location'],'optional-helper-package-source-fixture')
                        self.assertEqual(value['failure']['package'],'powershell');self.assertTrue(value['ordinary_helper_doctor']['passed'])
                    else:
                        with self.assertRaises(ValueError):runtime.missing_package()
                self.assertEqual((root/'status').read_bytes(),b'')

    def test_telemetry_opt_out_precedes_process_and_no_scanner_or_provider_is_invoked(self):
        environment=runtime.environment()
        self.assertEqual(environment['POWERSHELL_TELEMETRY_OPTOUT'],'1')
        self.assertNotIn('Evaluate-STIG',runtime.SCRIPT)
        self.assertNotIn('PSModulePath',environment)
        self.assertNotIn('Authorization',environment)

    @unittest.skipUnless(os.name=='posix','Actual owned-process deadline fixture requires Linux')
    def test_actual_fixed_capture_deadline_and_output_bound_terminate_children(self):
        began=__import__('time').monotonic()
        with self.assertRaises(ValueError):runtime.capture([sys.executable,'-c','import time;time.sleep(5)'],.15)
        self.assertLess(__import__('time').monotonic()-began,2)
        with self.assertRaises(ValueError):runtime.capture([sys.executable,'-c',"print('x'*20000)"],2)


if __name__=='__main__':unittest.main()
