"""Synthetic helper transport and actual authored-collector local fixtures."""
import base64
from copy import deepcopy
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from validation import runtime
from wormhole import candidate as c,rpm_candidate as rc,rpm_validation as rv,rpm_target as t,validation as v,images
from wormhole.runs import atomic_json,common,read_json
from test_rpm_candidate import RpmFixture,binding_for
from test_candidate import SHA,DERIVED

TARGET,NETWORK,HELPER='d'*64,'e'*64,'f'*64


def observed(binding):
    manifest=binding['manifest']
    return {'schema_version':'1.0','os':{'id':'rhel','version_id':'9.8'},'candidate_sha256':binding['candidate_sha256'],
        'content_sha256':binding['content_sha256'],'source_sha256':manifest['source_sha256'],
        'payload_sha256':next(row['sha256'] for row in manifest['files'] if row['path']=='payload.py'),
        'version':c.VERSION,'configuration':c.CONFIG,'function':{'status':'observed','value':{'version':c.VERSION,
            'message':c.CONFIG['greeting'],'source_sha256':manifest['source_sha256']}},
        'packages':{**deepcopy(rc.PACKAGE_VERSIONS),'openssh-clients':None},'shared_kernel_release':'synthetic-shared-kernel'}


class RpmValidation(RpmFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.binding=binding_for(self);self.lease=SimpleNamespace(_reconciliation_only=False)
        self.ps=SimpleNamespace(run=self.run,lease=self.lease,target_binding=self.binding,target_image_id=DERIVED,
            receipt={'primary_failure':None},held=Mock(),target_inventory=Mock(return_value={'resource_id':TARGET,'host':'172.31.77.2','image_digest':DERIVED}))
        def failure(error):
            if self.ps.receipt['primary_failure'] is None:self.ps.receipt['primary_failure']={'code':error.code,'recorded_at':datetime.now(timezone.utc).isoformat()}
        self.ps.failure=failure
        self.ready=SimpleNamespace(run=self.run,lease=self.lease,provisioning=self.ps,scenario='healthy',target=TARGET,network=NETWORK,helper=HELPER,
            validation_enabled=True,validation_source_sha256=v.runtime_hash(),held=Mock(),require_ready=Mock(),verify_helper=Mock(),save=Mock(),
            trust_address='172.31.77.2',last_started_at=datetime.now(timezone.utc).isoformat(),receipt={'unknown_outcome':False})
        atomic_json(self.run.file('evidence/provisioning.json'),{**common(self.run.manifest()),'target_binding':self.binding,'target_image':DERIVED,
            'resources':[{'address':'docker_container.target["target-001"]','id':TARGET},{'address':'docker_network.run','id':NETWORK}]})
        for owner,name,value in ((rv,'source_identity',lambda:(SHA,False)),(images,'docker_configuration',lambda:'/synthetic-empty-config'),
            (images,'inspect',lambda *a,**k:{'State':{'StartedAt':datetime.now(timezone.utc).isoformat()}})):
            item=patch.object(owner,name,value);item.start();self.addCleanup(item.stop)

    def response(self,argv,**options):
        request=runtime.decode(base64.b64decode(argv[-1]));self.assertEqual(request['operation'],'rpm-functional-v1')
        self.assertNotIn('credentials',' '.join(argv));self.assertIn(v.VALIDATION_MOUNT,argv)
        value={**{key:request[key] for key in ('schema_version','run_id','source_revision','target_id','plan_sha256')},'status':'pass',
            'category':None,'returncode':0,'timed_out':False,'truncated':False,'duration_seconds':.01,
            'observation':observed(self.binding),'private_diagnostic':''}
        return {'status':'pass','returncode':0,'duration_seconds':.02,'log_truncated':False,'log':c.canonical(value)}

    def test_all_twelve_checks_capture_backed_report_and_full_nevra(self):
        session=rv.RPMValidationSession(self.ready,self.binding)
        with patch.object(v,'_run_process',side_effect=self.response):result=session.validate()
        self.assertEqual(len(result['checks']),12);self.assertTrue(all(row['status']=='pass' for row in result['checks']))
        report=rv.report_rpm_validation(self.run);self.assertEqual(report['result'],result)
        self.assertIn('UBI9-derived container',report['text']);self.assertIn('Shared host kernel',report['text'])
        package=next(row for row in result['checks'] if row['check_id']=='rpm-shadow-utils')
        self.assertEqual(json.loads(package['observed']),{'status':'installed','epoch':2,'version':'4.9','release':'16.el9','arch':'x86_64'})

    def test_missing_optional_is_actual_absence_and_not_a_removed_package(self):
        session=rv.RPMValidationSession(self.ready,self.binding,scenario='missing-optional-package')
        with patch.object(v,'_run_process',side_effect=self.response),self.assertRaises(t.RpmError) as error:session.validate()
        self.assertEqual(error.exception.code,'rpm_missing_package');report=rv.report_rpm_validation(self.run)
        rows=report['result']['checks'];self.assertEqual(len(rows),13)
        self.assertEqual([(row['check_id'],row['status']) for row in rows if row['status']!='pass'],[(rc.OPTIONAL,'fail')])
        self.assertEqual(json.loads(rows[-1]['observed']),{'status':'missing'})
        self.assertEqual(self.ps.receipt['primary_failure']['code'],'rpm_missing_package')

    def test_wrong_version_is_frozen_expectation_only_retaining_observed_package(self):
        session=rv.RPMValidationSession(self.ready,self.binding,scenario='version-expectation-mismatch')
        with patch.object(v,'_run_process',side_effect=self.response),self.assertRaises(t.RpmError) as error:session.validate()
        self.assertEqual(error.exception.code,'rpm_version_mismatch');rows=rv.report_rpm_validation(self.run)['result']['checks']
        wrong=next(row for row in rows if row['check_id']=='rpm-openssh-server')
        self.assertEqual(json.loads(wrong['observed'])['version'],'9.9p1');self.assertIn('controlled-mismatch',wrong['expected'])
        self.assertEqual(sum(row['status']=='pass' for row in rows),11)

    def test_unsupported_os_fails_userland_and_keeps_package_observations_unverified(self):
        session=rv.RPMValidationSession(self.ready,self.binding,scenario='unsupported-os')
        with patch.object(v,'_run_process',side_effect=self.response),self.assertRaises(t.RpmError) as error:session.validate()
        self.assertEqual(error.exception.code,'rpm_applicability_mismatch');rows=rv.report_rpm_validation(self.run)['result']['checks']
        self.assertEqual(sum(row['status']=='unverified' for row in rows),4);self.assertEqual(sum(row['status']=='pass' for row in rows),7)
        self.assertEqual(rows[0]['status'],'fail');self.assertIn('rhel',rows[0]['observed'])

    def test_incomplete_exec_or_unexecuted_function_never_passes_or_clears_unknown(self):
        session=rv.RPMValidationSession(self.ready,self.binding)
        result={'status':'timeout','returncode':-9,'duration_seconds':.02,'log_truncated':False,'log':b''}
        with patch.object(v,'_run_process',return_value=result),self.assertRaises(t.RpmError):session.validate()
        self.assertTrue(self.ready.receipt['unknown_outcome']);self.assertTrue(session.receipt['unknown_outcome'])
        self.assertEqual(rv.report_rpm_validation(self.run)['result']['status'],'failed')
        value=observed(self.binding);value['function']={'status':'unverified','value':None}
        self.assertEqual(next(row['status'] for row in rv.rows(session.plan,value) if row['check_id']=='candidate-function'),'unverified')

    def test_capture_rows_typed_metadata_and_applicability_cannot_be_rewritten(self):
        session=rv.RPMValidationSession(self.ready,self.binding)
        with patch.object(v,'_run_process',side_effect=self.response):session.validate()
        path=self.run.file('evidence/rpm-validation.json');original=read_json(path)
        for change in (lambda x:x['checks'].pop(),lambda x:x.update(source_dirty=0),lambda x:x['attempts'][0].update(returncode=False),
            lambda x:x['attempts'][0].update(private_log='private/credentials/key')):
            value=deepcopy(original);change(value);atomic_json(path,value)
            with self.assertRaises(Exception):rv.report_rpm_validation(self.run)
        atomic_json(path,original);self.run.file(rv.LOG).write_bytes(b'changed')
        with self.assertRaises(t.RpmError):rv.report_rpm_validation(self.run)

    def test_missing_fixture_is_refused_if_optional_package_was_actually_installed(self):
        build=read_json(self.run.file('evidence/rpm-candidate-build.json'));build['installed']['installed_packages'].append({'name':'openssh-clients',**rc.PACKAGE_VERSIONS['openssh']})
        atomic_json(self.run.file('evidence/rpm-candidate-build.json'),build)
        with self.assertRaises(t.RpmError):rv.RPMValidationSession(self.ready,self.binding,scenario='missing-optional-package')

    def structured_failure(self,status,category,returncode):
        session=rv.RPMValidationSession(self.ready,self.binding)
        def failure(argv,**options):
            result=self.response(argv,**options);value=json.loads(result['log'])
            value.update(status=status,category=category,returncode=returncode,observation=None)
            result['log']=c.canonical(value);return result
        with patch.object(v,'_run_process',side_effect=failure),self.assertRaises(t.RpmError) as error:session.validate()
        self.assertEqual(error.exception.code,category)
        self.assertFalse(session.receipt['unknown_outcome']);self.assertFalse(self.ready.receipt['unknown_outcome'])
        self.assertTrue(all(row['status']==status and row['observed']==category for row in session.receipt['checks']))
        self.assertEqual(rv.report_rpm_validation(self.run)['result']['primary_failure']['code'],category)

    def test_complete_unreachable_is_not_mislabeled_as_an_observed_os_mismatch(self):
        self.structured_failure('unreachable','ansible_unreachable',4)

    def test_complete_skip_preserves_its_real_category_without_fabricated_observations(self):
        self.structured_failure('skipped','unexpected_skip',0)

    @unittest.skipUnless(os.name=='posix','Authored local collector uses POSIX userland; no SSH/Ansible/runtime operation')
    def test_authored_fixed_collector_observes_actual_four_bytes_and_full_rpm_tuple(self):
        release=self.root/'rpm-os-release';release.write_text('ID="rhel"\nVERSION_ID="9.8"\n')
        # Replace only fixed absolute data roots and the RPM library with labeled
        # local fixtures. No downloaded code or package manager is executed.
        fake="""
class Transaction:
 def dbMatch(self,key,name):
  value=VERSIONS.get(name)
  return [dict(value)] if value else []
 def closeDB(self): pass
rpm=types.SimpleNamespace(TransactionSet=lambda root:Transaction())
""".replace('VERSIONS',repr(rc.PACKAGE_VERSIONS))
        program=runtime.RPM_PROGRAM.replace('import hashlib,json,os,stat,sys,types,rpm','import hashlib,json,os,stat,sys,types')
        program=program.replace('from pathlib import Path','from pathlib import Path\n'+fake)
        program=program.replace("Path('/opt/wormhole/reference')",'Path('+repr(str(self.rpm_bundle['directory']))+')')
        program=program.replace("Path('/usr/lib/os-release')",'Path('+repr(str(release))+')')
        program=program.replace('os.uname().release',repr('synthetic-shared-kernel'))
        expected=observed(self.binding)['payload_sha256']
        result=subprocess.run([sys.executable,'-I','-B','-c',program,expected],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(runtime.rpm_observation(json.loads(result.stdout)),observed(self.binding))
        path=self.rpm_bundle['directory']/'version.txt';path.write_bytes(path.read_bytes()+b'\n')
        result=subprocess.run([sys.executable,'-I','-B','-c',program,expected],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr.decode());value=json.loads(result.stdout)
        rows=rv.rows(rv.make_plan(self.run,self.binding,TARGET,NETWORK,'healthy'),value)
        self.assertEqual(next(row['status'] for row in rows if row['check_id']=='candidate-version'),'pass')
        self.assertEqual(next(row['status'] for row in rows if row['check_id']=='candidate-content-sha256'),'fail')


if __name__=='__main__':unittest.main()
