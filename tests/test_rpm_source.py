"""Synthetic source bytes and offline protocol only; no DNF/RPM installation."""
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from wormhole import rpm_source as s
from wormhole.runs import create_run, common, atomic_json

SPEC=importlib.util.spec_from_file_location('fixed_offline_rpm_resolver',s.SOURCE_ROOT/'rpm/resolve.py')
resolver=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(resolver)
SHA='a'*40


class Response:
    def __init__(self,raw,url):self.raw,self.url=raw,url
    def __enter__(self):return self
    def __exit__(self,*_):pass
    def geturl(self):return self.url
    def read1(self,size):part,self.raw=self.raw[:size],self.raw[size:];return part


def fixtures(run):
    folder=run.file('private/rpm-sources/metadata');folder.mkdir(parents=True,mode=0o700);(folder/'repodata').mkdir(mode=0o700)
    packages=[];xml=[]
    for record in s.REQUESTED:
        row={**record,'path':'Packages/'+record['name'][0]+'/'+record['name']+'.rpm','bytes':3,'sha256':s.sha(b'rpm'),'repo_id':'wormhole-ubi9-baseos'}
        packages.append(row)
        xml.append('<package><name>'+row['name']+'</name><arch>'+row['arch']+'</arch><version epoch="'+str(row['epoch'])+'" ver="'+row['version']+'" rel="'+row['release']+'"/><checksum type="sha256">'+row['sha256']+'</checksum><size package="3"/><location href="'+row['path']+'"/></package>')
    raw=('<metadata xmlns="http://linux.duke.edu/metadata/common">'+''.join(xml)+'</metadata>').encode();compressed=gzip.compress(raw,mtime=0)
    item={'kind':'primary','path':'repodata/primary.xml.gz','bytes':len(compressed),'sha256':s.sha(compressed),'open_bytes':len(raw),'open_sha256':s.sha(raw)}
    repomd=('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">'+item['sha256']+'</checksum><open-checksum type="sha256">'+item['open_sha256']+'</open-checksum><location href="'+item['path']+'"/><size>'+str(item['bytes'])+'</size><open-size>'+str(item['open_bytes'])+'</open-size></data></repomd>').encode()
    (folder/'repodata/primary.xml.gz').write_bytes(compressed);(folder/'repodata/repomd.xml').write_bytes(repomd)
    if os.name=='posix':
        run.file('private/rpm-sources').chmod(0o700)
        for p in (folder/'repodata').iterdir():p.chmod(0o600)
    lock={'sources':{'metadata':[item],'repomd':{'path':'repodata/repomd.xml','bytes':len(repomd),'sha256':s.sha(repomd)},
        'base_url':s.URL,'repository_id':'wormhole-ubi9-baseos','requested_packages':deepcopy(s.REQUESTED),'policy':s.POLICY}}
    request={**common(run.manifest()),'operation':'ubi-offline-resolution-request-v1','base_image_id':s.BASE_IMAGE,
        'lock_sha256':s.sha(s.LOCK.read_bytes()),'base_packages_sha256':s.sha(s.canonical([])),'installed_packages':[],
        'base_observation_sha256':'a'*64,'base_probe':{'run_id':run.id,'source_revision':SHA,'recipe_sha256':'b'*64,'capture_sha256':'c'*64},
        'sources_sha256':s.sha(s.canonical(lock['sources'])),'requested_packages':deepcopy(s.REQUESTED)}
    result={'operation':'ubi-offline-resolution-v1','status':'passed','base_image_id':s.BASE_IMAGE,'request_sha256':s.sha(s.canonical(request)),
        'base_packages_sha256':request['base_packages_sha256'],'sources_sha256':request['sources_sha256'],
        'requested_packages':deepcopy(s.REQUESTED),'packages':sorted(packages,key=s.canonical),'remove_packages':[]}
    return lock,request,result,folder


class PublicSources(unittest.TestCase):
    def test_fixed_eula_artifact_never_expands_url_or_accepts_changed_bytes(self):
        raw=b'%PDF-synthetic exact license bytes'
        with patch.object(s,'EULA_BYTES',len(raw)),patch.object(s,'EULA_SHA256',s.sha(raw)):
            for fault in ('good','short','long','hash','redirect'):
                with self.subTest(fault=fault),tempfile.TemporaryDirectory() as folder:
                    path=Path(folder)/s.EULA_NAME
                    body=raw[:-1] if fault=='short' else raw+b'!' if fault=='long' else b'x'*len(raw) if fault=='hash' else raw
                    url='https://example.invalid/' if fault=='redirect' else s.EULA_URL
                    opener=Mock(return_value=Response(body,url))
                    if fault=='good':s.fetch_eula(path,opener=opener);self.assertEqual(path.read_bytes(),raw)
                    else:
                        with self.assertRaises(s.SourceError):s.fetch_eula(path,opener=opener)
                        self.assertFalse(path.exists())
                    opener.assert_called_once_with(s.EULA_URL,timeout=20)

    def test_eula_replay_is_hash_bound_and_uses_supervised_fixed_operation(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));root=run.file('private/rpm-sources');root.mkdir(mode=0o700)
            raw=b'%PDF-synthetic';path=root/s.EULA_NAME
            def fixed_worker(current,operation):
                self.assertEqual(current,run);self.assertEqual(operation,'eula');path.write_bytes(raw);path.chmod(0o600)
            with patch.object(s,'guard'),patch.object(s,'supervised',side_effect=fixed_worker) as worker,\
                 patch.object(s,'EULA_BYTES',len(raw)),patch.object(s,'EULA_SHA256',s.sha(raw)):
                self.assertEqual(s.prepare_eula(run),path);self.assertEqual(s.prepare_eula(run),path);worker.assert_called_once()
                path.write_bytes(b'changed')
                with self.assertRaises(s.SourceError):s.prepare_eula(run)

    def test_new_request_retains_old_probe_provenance_and_rejects_supplied_body_edits(self):
        from wormhole import rpm_target
        with tempfile.TemporaryDirectory() as folder:
            workspace=Path(folder)/'runs';run=create_run(workspace,fixture=False,identity=(SHA,False));old=create_run(workspace,fixture=False,identity=('b'*40,False))
            lock,_,_,_=fixtures(run)
            observed={'status':'observed','operation':'ubi-base-observation-v1','run_id':old.id,'source_revision':'b'*40,
                'installed_packages':[{'name':'base','epoch':0,'version':'1','release':'1','arch':'x86_64'}],
                'dnf':{'available':True,'base_api':True,'version':'4.14.0'}}
            original={'run_id':old.id,'source_revision':'b'*40,'recipe_sha256':'c'*64,'capture_sha256':'d'*64}
            atomic_json(old.file('evidence/rpm-base-probe.json'),original)
            with patch.object(s,'source_identity',return_value=(SHA,False)),patch.object(s,'load_lock',return_value=lock),\
                 patch.object(rpm_target,'read_base_observation',return_value=observed):
                value=s.resolve_request(run,lock,observed,base_run=old)
                self.assertEqual(value['source_revision'],SHA);self.assertEqual(value['base_probe'],original)
                self.assertEqual(value['base_observation_sha256'],s.sha(s.canonical(observed)))
                changed=deepcopy(observed);changed['installed_packages'][0]['version']='invented'
                with self.assertRaises(s.SourceError):s.resolve_request(run,lock,changed,base_run=old)
                observed['dnf']['available']=False
                with self.assertRaises(s.SourceError):s.resolve_request(run,lock,observed,base_run=old)

    def test_virtual_key_architecture_is_preserved_only_for_actual_key_records(self):
        key={'name':'gpg-pubkey','epoch':0,'version':'abcdef01','release':'12345678','arch':None}
        value={'status':'observed','operation':'ubi-base-observation-v1','installed_packages':[key]}
        self.assertEqual(s.validate_observation(value),[key])
        value['installed_packages'][0]['name']='ordinary-package'
        with self.assertRaises(s.SourceError):s.validate_observation(value)

    def test_source_lock_preserves_fixed_baseos_only_policy_and_rejects_typed_aliases(self):
        lock=s.load_lock();self.assertEqual(lock['sources']['base_url'],s.URL)
        self.assertEqual(len(lock['sources']['metadata']),8)
        self.assertEqual(lock['base']['image_id'],s.BASE_IMAGE);self.assertEqual(lock['base']['config_digest'],s.BASE_CONFIG)
        for field,bad in (('worker_seconds',True),('allow_erasing',0),('plugins',0)):
            changed=deepcopy(lock);changed['sources']['policy'][field]=bad
            with self.assertRaises(s.SourceError):s.load_lock(changed)
        changed=deepcopy(lock);changed['sources']['base_url']='https://example.invalid/'
        with self.assertRaises(s.SourceError):s.load_lock(changed)

    def test_lock_and_retained_resolution_reads_have_preparse_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'lock.json';path.write_bytes(b' '*65537)
            with patch.object(s,'LOCK',path),self.assertRaises(s.SourceError) as caught:s.load_lock()
            self.assertEqual(caught.exception.code,'rpm_lock_bound')
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));root=run.file('private/rpm-sources');root.mkdir(mode=0o700)
            resolution=root/'resolution.json';resolution.write_bytes(b' '*(s.POLICY['resolution_bytes']+1));resolution.chmod(0o600)
            atomic_json(root/'resolve-request.json',{})
            with patch.object(s,'guard'),patch.object(s,'validate_metadata'),patch.object(s,'validate_resolution',side_effect=lambda _r,raw,*_a: s.parse(raw)),\
                 self.assertRaises(s.SourceError) as caught:s._worker(run,'packages')
            self.assertEqual(caught.exception.code,'rpm_resolution_bound')

    def test_linked_retained_resolution_is_refused_before_fetch(self):
        for kind in ('hardlink','symlink') if os.name=='posix' else ('hardlink',):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));root=run.file('private/rpm-sources');root.mkdir(mode=0o700)
                original=Path(folder)/'original.json';original.write_bytes(b'{}');original.chmod(0o600)
                destination=root/'resolution.json'
                if kind=='hardlink':os.link(original,destination)
                else:destination.symlink_to(original)
                atomic_json(root/'resolve-request.json',{})
                with patch.object(s,'guard'),patch.object(s,'fetch',side_effect=AssertionError('No fetch')),\
                     self.assertRaises(s.RunError) as caught:s._worker(run,'packages')
                self.assertEqual(caught.exception.code,'unsafe_path')

    def test_fixed_https_has_no_redirect_proxy_or_partial_acceptance(self):
        raw=b'synthetic public bytes';item={'path':'Packages/p/python.rpm','bytes':len(raw),'sha256':s.sha(raw)}
        for fault in ('good','short','long','hash','redirect'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as folder:
                destination=Path(folder)/'python.rpm';body=raw[:-1] if fault=='short' else raw+b'!' if fault=='long' else b'x'*len(raw) if fault=='hash' else raw
                url='https://example.invalid/foreign' if fault=='redirect' else s.URL+item['path']
                opener=lambda *_a,**_kw:Response(body,url)
                if fault=='good':s.fetch(item,destination,opener=opener);self.assertEqual(destination.read_bytes(),raw)
                else:
                    with self.assertRaises(s.SourceError):s.fetch(item,destination,opener=opener)
                    self.assertFalse(destination.exists())
        with self.assertRaises(s.SourceError):s.NoRedirect().redirect_request(None,None,302,'',{},s.URL+'elsewhere')

    def test_path_traversal_and_oversized_configuration_never_open_url(self):
        for path,size in (('../escape.rpm',1),('Packages/p/a.rpm',s.POLICY['rpm_file_bytes']+1),('https://elsewhere/file',1)):
            with tempfile.TemporaryDirectory() as folder,patch.object(s.urllib.request,'build_opener',side_effect=AssertionError('No network')):
                with self.assertRaises(s.SourceError):s.fetch({'path':path,'bytes':size,'sha256':'a'*64},Path(folder)/'a')

    def test_decompression_is_stream_bounded_and_open_hash_is_required(self):
        with tempfile.TemporaryDirectory() as folder:
            raw=b'a'*200000;p=Path(folder)/'data.gz';p.write_bytes(gzip.compress(raw))
            item={'path':'repodata/data.gz','open_bytes':100,'open_sha256':s.sha(raw)}
            with self.assertRaises(s.SourceError) as caught:s.expanded(p,item)
            self.assertEqual(caught.exception.code,'rpm_metadata_expansion_bound')
            item['open_bytes']=len(raw);s.expanded(p,item);item['open_sha256']='0'*64
            with self.assertRaises(s.SourceError):s.expanded(p,item)

    def test_exact_metadata_hashes_repomd_contract_catalog_and_no_extra_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));lock,request,result,cache=fixtures(run)
            with patch.object(s,'load_lock',return_value=lock):
                self.assertEqual(s.validate_metadata(run,lock),cache);catalog=s.package_catalog(run,lock);self.assertEqual(len(catalog),3)
                (cache/'extra').mkdir(mode=0o700)
                with self.assertRaises(s.SourceError):s.validate_metadata(run,lock)
                (cache/'extra').rmdir();p=cache/'repodata/primary.xml.gz';p.write_bytes(p.read_bytes()+b'x')
                with self.assertRaises(s.SourceError):s.validate_metadata(run,lock)

    def test_xml_entities_and_duplicate_json_members_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'data.xml';p.write_bytes(b'<!DOCTYPE x [<!ENTITY x "bad">]><x/>')
            with self.assertRaises(s.SourceError):s.xml_bytes(p,1000)
        with self.assertRaises(s.SourceError):s.parse(b'{"status":"passed","status":"failed"}')

    def test_resolution_binds_request_and_exact_package_set_no_missing_or_removed_requests(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));lock,request,result,_=fixtures(run)
            with patch.object(s,'load_lock',return_value=lock):
                self.assertEqual(s.validate_resolution(run,s.canonical(result),request,lock),result)
                for fault in ('source','hash','missing','duplicate','foreign','remove','epoch-type'):
                    bad=deepcopy(result)
                    if fault=='source':bad['request_sha256']='0'*64
                    if fault=='hash':bad['packages'][0]['sha256']='0'*64
                    if fault=='missing':bad['packages']=[]
                    if fault=='duplicate':bad['packages'].append(deepcopy(bad['packages'][0]))
                    if fault=='foreign':bad['packages'][0]['repo_id']='subscription-repository'
                    if fault=='remove':bad['remove_packages']=[s.REQUESTED[0]]
                    if fault=='epoch-type':bad['packages'][0]['epoch']=False
                    with self.subTest(fault=fault),self.assertRaises(s.SourceError):s.validate_resolution(run,s.canonical(bad),request,lock)

    def test_worker_failure_never_accepts_a_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False))
            with patch.object(s,'source_identity',return_value=(SHA,False)),patch.object(s,'_run_process',return_value={'status':'timeout','log':b'synthetic','log_truncated':False}):
                with self.assertRaises(s.SourceError) as caught:s.prepare_metadata(run,s.load_lock())
            self.assertEqual(caught.exception.code,'rpm_source_timeout');self.assertFalse(run.file('private/rpm-sources/metadata').exists())

    @unittest.skipUnless(os.name=='posix','Owned worker deadline fixture requires POSIX')
    def test_actual_worker_whole_deadline_terminates_slow_progress(self):
        with tempfile.TemporaryDirectory() as folder:
            run=create_run(Path(folder)/'runs',fixture=False,identity=(SHA,False));began=time.monotonic()
            worker="import time;print('synthetic worker entered',flush=True);time.sleep(5)"
            with patch.object(s,'source_identity',return_value=(SHA,False)),patch.object(s,'WORKER',worker),patch.object(s,'TIMEOUT',.2):
                with self.assertRaises(s.SourceError) as caught:s.prepare_metadata(run,s.load_lock())
            self.assertEqual(caught.exception.code,'rpm_source_timeout');self.assertLess(time.monotonic()-began,2)
            self.assertIn(b'synthetic worker entered',run.file('private/rpm-metadata-preparation.log').read_bytes())


class OfflineResolution(unittest.TestCase):
    def setUp(self):
        # Protocol-only fixtures never create runtime paths on this host.
        item=patch.object(resolver,'working_directories',return_value={name:'/synthetic/'+name for name in ('cache','persist','log')})
        self.mock_directories=item.start();self.addCleanup(item.stop)

    @unittest.skipUnless(os.name=='posix','Real private DNF working-directory fixture requires POSIX')
    def test_sack_log_parent_exists_before_real_fopen_style_operation(self):
        # Reach the unpatched fixed implementation without executing DNF.
        module=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder,patch.object(module,'WORK_ROOT',Path(folder)/'fixed'):
            with self.assertRaises(FileNotFoundError):(module.WORK_ROOT/'log/hawkey.log').open('a')
            result=module.working_directories()
            for path in result.values():self.assertEqual(Path(path).stat().st_mode&0o777,0o700)
            with (Path(result['log'])/'hawkey.log').open('a') as stream:stream.write('synthetic bounded log')
            with self.assertRaises(ValueError):module.working_directories()  # No retained-cache retry.

    def test_oserror_diagnostic_preserves_numeric_errno_but_no_filename_or_message(self):
        try:raise OSError(13,'Synthetic secret message','/private/credential/location')
        except OSError as error:value=resolver.failure(error)
        self.assertEqual(value['errno'],13);self.assertEqual(value['sites'],[])
        self.assertNotIn('private',s.canonical(value).decode());self.assertNotIn('secret',s.canonical(value).decode())

    @unittest.skipUnless(os.name=='posix','Isolated solver exception fixture requires POSIX')
    def test_failed_solver_records_only_fixed_phase_and_exception_class(self):
        def child():
            resolver.phase('sack-load');raise RuntimeError('Synthetic credential-like text must not escape')
        with patch.object(resolver,'emit_output') as emit:code=resolver.supervise(child,1)
        self.assertEqual(code,2);value=s.parse(emit.call_args.args[0])
        self.assertEqual(value,{'operation':'ubi-offline-resolution-v1','status':'failed','code':'rpm_resolution_refused',
            'phase':'sack-load','exception_class':'RuntimeError','errno':None,'sites':[]})
        self.assertNotIn(b'credential',emit.call_args.args[0])

    @unittest.skipUnless(os.name=='posix','Resolver release marker permission fixture requires POSIX')
    def test_fixed_release_marker_is_exact_private_bounded_and_required(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'marker'
            with patch.object(resolver,'START_MARKER',path):
                with self.assertRaises(ValueError):resolver.wait_for_start(.03)
                path.write_bytes(b'1\n');path.chmod(0o600);resolver.wait_for_start(.1)
                for fault in (b'2\n',b'1\nextra'):
                    path.write_bytes(fault)
                    with self.assertRaises(ValueError):resolver.wait_for_start(.1)
                path.write_bytes(b'1\n');path.chmod(0o644)
                with self.assertRaises(ValueError):resolver.wait_for_start(.1)
                path.unlink();path.symlink_to(Path(folder)/'missing')
                with self.assertRaises(ValueError):resolver.wait_for_start(.1)

    @unittest.skipUnless(os.name=='posix','Finite resolver supervisor requires POSIX')
    def test_actual_fixed_resolver_child_has_finite_lifetime_and_is_reaped(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'child.pid'
            def fixed_child():
                path.write_text(str(os.getpid()));time.sleep(5);return 0
            with patch.object(resolver,'emit_output') as emit:
                began=time.monotonic();code=resolver.supervise(fixed_child,.15,grace_seconds=.05)
            self.assertEqual(code,124);self.assertLess(time.monotonic()-began,2)
            self.assertLess(len(emit.call_args.args[0]),200)
            child=int(path.read_text())
            with self.assertRaises(ChildProcessError):os.waitpid(child,os.WNOHANG)

    @unittest.skipUnless(os.name=='posix','Bounded resolver output fixture requires POSIX')
    def test_fixed_resolver_output_overflow_is_terminated_and_never_forwarded(self):
        def noisy_child():
            while True:os.write(1,b'x'*65536)
        with patch.object(resolver,'emit_output') as emit:
            began=time.monotonic();code=resolver.supervise(noisy_child,1,grace_seconds=.05)
        self.assertEqual(code,2);self.assertLess(time.monotonic()-began,2)
        self.assertLess(len(emit.call_args.args[0]),200);self.assertNotIn(b'xxxxx',emit.call_args.args[0])

    @unittest.skipUnless(os.name=='posix','Resolver output drain fixture requires POSIX')
    def test_fixed_resolver_complete_bounded_output_is_preserved(self):
        def child():os.write(1,b'{"status":"passed"}\n');return 0
        with patch.object(resolver,'emit_output') as emit:code=resolver.supervise(child,1)
        self.assertEqual(code,0);emit.assert_called_once_with(b'{"status":"passed"}\n')

    def test_rpm_snapshot_retains_virtual_key_null_architecture(self):
        rpm=Mock();rpm.TransactionSet.return_value.dbMatch.return_value=[{'name':'gpg-pubkey','epoch':None,'version':'abcdef01','release':'12345678','arch':None}]
        self.assertEqual(resolver.installed_packages(rpm),[{'name':'gpg-pubkey','epoch':0,'version':'abcdef01','release':'12345678','arch':None}])
        rpm.TransactionSet.return_value.closeDB.assert_called_once()

    def setup_protocol(self):
        packages=[SimpleNamespace(**x,installed=False,reponame='wormhole-ubi9-baseos',downloadsize=3) for x in s.REQUESTED]
        class Query:
            def filter(self,**kwargs):return [p for p in packages if p.name==kwargs['name']]
        base=MagicMock();base.__enter__.return_value=base;base.conf.substitutions={};base.repos.iter_enabled.return_value=[]
        base.sack.query.return_value=Query();base.transaction.install_set=packages;base.transaction.remove_set=[]
        dnf=SimpleNamespace(Base=Mock(return_value=base));rpm=Mock();rpm.TransactionSet.return_value.dbMatch.return_value=[{'name':'base','epoch':0,'version':'1','release':'1','arch':'x86_64'}]
        installed=resolver.installed_packages(rpm)
        request={'operation':'ubi-offline-resolution-request-v1','base_image_id':s.BASE_IMAGE,'installed_packages':installed,
            'base_packages_sha256':s.sha(s.canonical(installed)),'sources_sha256':None,'requested_packages':deepcopy(s.REQUESTED)}
        lock={'sources':{'base_url':s.URL,'repository_id':'wormhole-ubi9-baseos','requested_packages':deepcopy(s.REQUESTED),'policy':s.POLICY}}
        request['sources_sha256']=s.sha(s.canonical(lock['sources']))
        catalog={s.canonical(x):{**x,'repo_id':'wormhole-ubi9-baseos','bytes':3,'sha256':s.sha(b'rpm'),'path':'Packages/'+x['name'][0]+'/'+x['name']+'.rpm'} for x in s.REQUESTED}
        return base,dnf,rpm,request,lock,catalog

    def test_fixed_offline_dnf_api_resolves_without_download_install_plugins_or_ambient_repos(self):
        base,dnf,rpm,request,lock,catalog=self.setup_protocol()
        with patch.object(resolver,'metadata',return_value=catalog):result=resolver.resolve(request,lock,dnf,rpm)
        self.assertEqual(result['status'],'passed');self.assertEqual(len(result['packages']),3)
        base.fill_sack.assert_called_once_with(load_system_repo=True,load_available_repos=True)
        base.resolve.assert_called_once_with(allow_erasing=False)
        for method in ('read_all_repos','download_packages','do_transaction','init_plugins'):getattr(base,method).assert_not_called()
        self.assertIs(base.conf.plugins,False);self.assertIs(base.conf.install_weak_deps,False)
        self.assertEqual(base.repos.add_new_repo.call_args.kwargs,{'baseurl':['file:///metadata']})

    def test_changed_base_ambient_repo_or_removal_refuses_no_transaction(self):
        for fault in ('base','repo','remove','foreign'):
            base,dnf,rpm,request,lock,catalog=self.setup_protocol()
            if fault=='base':request['base_packages_sha256']='0'*64
            if fault=='repo':base.repos.iter_enabled.return_value=['ambient']
            if fault=='remove':base.transaction.remove_set=[object()]
            if fault=='foreign':base.transaction.install_set[0].reponame='foreign'
            with self.subTest(fault=fault),patch.object(resolver,'metadata',return_value=catalog),self.assertRaises(ValueError):resolver.resolve(request,lock,dnf,rpm)
            base.do_transaction.assert_not_called();base.download_packages.assert_not_called()


if __name__=='__main__':unittest.main()
