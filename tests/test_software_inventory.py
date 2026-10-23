"""Synthetic inventory domain/transport fixtures; every Docker/SSH call mocked."""
import base64
from copy import deepcopy
from datetime import datetime,timezone
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from validation import runtime
from wormhole import candidate as c,images,provisioning as p,software_inventory as s,validation as v
from wormhole.runs import atomic_json,common,read_json
from wormhole.readiness import HELPER_IMAGE
from test_rpm_candidate import RpmFixture,binding_for
from test_candidate import SHA,DERIVED

TARGET,NETWORK,HELPER,PROVISIONER='d'*64,'e'*64,'f'*64,'a'*64
TOOLS={'terraform_version':'1.17.0','provider_version':'4.6.0','platform':'linux_amd64',
    'provider_schema_observed':True,'offline_readonly_lock_h1_confirmed':p.H1}


def observation(binding):
    manifest=binding['manifest'];files=[{'path':row['path'],'bytes':row['size'],'sha256':row['sha256']} for row in manifest['files']]
    packages=list(s.package_expectations('ubi','healthy').values())+[{'name':'bash','epoch':0,'version':'5.1','release':'1.el9','arch':'x86_64'}]
    return {'schema_version':'1.0','os':{'id':'rhel','version_id':'9.8','name':'Synthetic UBI-derived fixture','architecture':'x86_64'},
        'package_manager':'rpm','packages':sorted(packages,key=lambda x:(x['name'],x['epoch'],x['version'],x['release'],x['arch'])),
        'rpm_key_headers':[{'name':'gpg-pubkey','epoch':0,'version':'fd431d51','release':'4ae0493b','arch':None}],
        'payload':{'version':manifest['version'],'sha256':files[1]['sha256'],'manifest_sha256':binding['candidate_sha256'],
            'content_sha256':binding['content_sha256'],'source_sha256':manifest['source_sha256'],'files':files},
        'shared_kernel':{'scope':'host-shared','release':'synthetic-host-shared-kernel'}}


class SoftwareInventory(RpmFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.binding=binding_for(self);self.lease=SimpleNamespace(_reconciliation_only=False)
        self.ps=SimpleNamespace(run=self.run,lease=self.lease,target_binding=self.binding,target_image_id=DERIVED,provisioner=PROVISIONER,
            receipt={'primary_failure':None,'actual_tools':deepcopy(TOOLS)},
            held=Mock(),verify_target=Mock(),verify_provisioner=Mock(),
            target_inventory=Mock(return_value={'resource_id':TARGET,'host':'172.31.77.2','image_digest':DERIVED}))
        def failure(error):
            if self.ps.receipt['primary_failure'] is None:self.ps.receipt['primary_failure']={'code':error.code,'recorded_at':__import__('wormhole.runs',fromlist=['now']).now()}
        self.ps.failure=failure
        self.ready=SimpleNamespace(run=self.run,lease=self.lease,provisioning=self.ps,scenario='healthy',target=TARGET,network=NETWORK,helper=HELPER,
            validation_enabled=True,validation_source_sha256=v.runtime_hash(),held=Mock(),require_ready=Mock(),verify_helper=Mock(),save=Mock(),
            trust_address='172.31.77.2',receipt={'unknown_outcome':False})
        atomic_json(self.run.file('evidence/provisioning.json'),{**common(self.run.manifest()),'target_binding':self.binding,'target_image':DERIVED,'actual_tools':deepcopy(TOOLS),
            'resources':[{'address':'docker_container.target["target-001"]','id':TARGET},{'address':'docker_network.run','id':NETWORK}]})
        atomic_json(self.run.file('private/readiness-controller.json'),{**common(self.run.manifest()),'operation':'readiness-helper',
            'helper_id':HELPER,'helper_image':HELPER_IMAGE,'target_resource_id':TARGET,'network_id':NETWORK,'validation_enabled':True,
            'source_sha256':c.sha((s.SOURCE_ROOT/'readiness/runtime.py').read_bytes()),'validation_source_sha256':v.runtime_hash()})
        atomic_json(self.run.file('private/terraform/controller.json'),{'schema_version':'1.0','run_id':self.run.id,'source_revision':SHA,
            'id':PROVISIONER,'target_binding':self.binding})
        for owner,name,value in ((s,'source_identity',lambda:(SHA,False)),(images,'docker_configuration',lambda:'/synthetic-config'),
            (images,'inspect',self.inspect)):
            item=patch.object(owner,name,value);item.start();self.addCleanup(item.stop)

    def inspect(self,kind,identifier,**options):
        return {'Id':identifier,'Image':DERIVED if identifier==TARGET else HELPER_IMAGE if identifier==HELPER else p.TARGET_IMAGE,
            'State':{'StartedAt':datetime.now(timezone.utc).isoformat()}}

    def response(self,argv,**options):
        request=runtime.decode_software_inventory(base64.b64decode(argv[-1]));self.assertEqual(request['operation'],'software-inventory-v1')
        self.assertNotIn('credentials',' '.join(argv));self.assertIn(v.VALIDATION_MOUNT,argv)
        value={**{key:request[key] for key in ('schema_version','run_id','source_revision','target_id','plan_sha256')},'status':'pass','category':None,
            'returncode':0,'timed_out':False,'truncated':False,'duration_seconds':.01,
            'collector_base64':base64.b64encode(c.canonical(observation(self.binding))).decode(),
            'helper_provenance':{'python_version':'3.12.3','ansible_core_version':'2.21.5'},'private_diagnostic':'Synthetic original transport.'}
        if request['scenario']=='collector-unavailable':
            value.update(status='error',category='configured_interpreter_unavailable',returncode=2,collector_base64=None)
        return {'status':'pass','returncode':0,'duration_seconds':.02,'log_truncated':False,'log':c.canonical(value)}

    def test_full_native_inventory_preserves_unrequired_packages_keys_and_replay_exports(self):
        session=s.SoftwareInventorySession(self.ready,self.binding)
        with patch.object(v,'_run_process',side_effect=self.response):result=session.collect()
        self.assertEqual(len(result['checks']),12);self.assertTrue(all(row['status']=='pass' for row in result['checks']))
        self.assertEqual(len(result['observation']['packages']),5)
        self.assertTrue(any(row['name']=='bash' for row in result['observation']['packages']))
        self.assertEqual(result['observation']['rpm_key_headers'][0]['arch'],None)
        report=s.report_software_inventory(self.run);self.assertEqual(report['record'],result)
        self.assertEqual(json.loads(self.run.file(s.JSON_EXPORT).read_bytes()),result)
        self.assertEqual(self.run.file(s.TEXT_EXPORT).read_text(),report['text'])
        self.assertIn('Shared host kernel',report['text']);self.assertIn('Installed target packages: 5',report['text'])
        self.assertEqual(result['execution_provenance']['helper']['python_version'],'3.12.3')

    def test_missing_package_and_wrong_version_keep_actual_inventory_and_only_one_failed_row(self):
        for scenario,code,key in (('missing-package','svd_missing_package','package-openssh-clients'),
            ('wrong-version','svd_version_mismatch','package-openssh-server')):
            # Each subcase is a fresh isolated Run, not a second write to one attempt.
            if scenario=='wrong-version':self.doCleanups();self.setUp()
            session=s.SoftwareInventorySession(self.ready,self.binding,scenario)
            with patch.object(v,'_run_process',side_effect=self.response),self.assertRaises(s.InventoryError) as error:session.collect()
            self.assertEqual(error.exception.code,code);record=s.report_software_inventory(self.run)['record']
            self.assertEqual([(row['check_id'],row['status']) for row in record['checks'] if row['status']!='pass'],[(key,'fail')])
            self.assertEqual(record['observation']['packages'],observation(self.binding)['packages'])
            self.assertEqual(self.ps.receipt['primary_failure']['code'],code)

    def test_collector_unavailable_has_complete_failed_capture_and_dependent_unverified_rows(self):
        session=s.SoftwareInventorySession(self.ready,self.binding,'collector-unavailable')
        with patch.object(v,'_run_process',side_effect=self.response),self.assertRaises(s.InventoryError) as error:session.collect()
        self.assertEqual(error.exception.code,'configured_interpreter_unavailable')
        result=s.report_software_inventory(self.run)['record'];self.assertEqual(result['checks'][0]['status'],'pass')
        self.assertTrue(all(row['status']=='unverified' for row in result['checks'][1:]));self.assertIsNone(result['observation'])
        self.assertTrue(result['capture']['complete']);self.assertFalse(result['unknown_outcome'])

    def test_wrong_expected_identity_never_calls_collector_or_adopts_foreign_target(self):
        session=s.SoftwareInventorySession(self.ready,self.binding,'wrong-identity')
        with patch.object(v,'_run_process') as execute,self.assertRaises(s.InventoryError) as error:session.collect()
        execute.assert_not_called();self.assertEqual(error.exception.code,'svd_target_identity_mismatch')
        result=s.report_software_inventory(self.run)['record'];self.assertEqual(result['target']['resource_id'],TARGET)
        self.assertEqual(result['checks'][0]['status'],'fail');self.assertTrue(all(row['status']=='unverified' for row in result['checks'][1:]))
        self.assertIsNone(result['capture']);self.assertEqual(self.ready.target,TARGET)

    def test_unknown_outer_exec_blocks_helper_cleanup_and_retains_failed_original_capture(self):
        session=s.SoftwareInventorySession(self.ready,self.binding)
        failed={'status':'timeout','returncode':-9,'duration_seconds':.02,'log_truncated':False,'log':b''}
        with patch.object(v,'_run_process',return_value=failed),self.assertRaises(s.InventoryError):session.collect()
        self.assertTrue(session.receipt['unknown_outcome']);self.assertTrue(self.ready.receipt['unknown_outcome'])
        self.assertEqual(s.report_software_inventory(self.run)['record']['status'],'failed')

    def test_changed_capture_plan_rows_exports_or_scalar_metadata_never_replay_as_success(self):
        session=s.SoftwareInventorySession(self.ready,self.binding)
        with patch.object(v,'_run_process',side_effect=self.response):session.collect()
        path=self.run.file(s.RECORD);original=read_json(path)
        for alter in (lambda x:x['checks'].pop(),lambda x:x.update(source_dirty=0),lambda x:x['capture'].update(size_bytes=False),
            lambda x:x['target'].update(resource_id='1'*64),lambda x:x['observation']['packages'].pop()):
            value=deepcopy(original);alter(value);atomic_json(path,value)
            with self.assertRaises(Exception):s.report_software_inventory(self.run)
        atomic_json(path,original)
        self.run.file(s.LOG).write_bytes(b'changed original capture')
        with self.assertRaises(s.InventoryError):s.report_software_inventory(self.run)

    def test_complete_malformed_response_is_failed_not_empty_inventory_success(self):
        session=s.SoftwareInventorySession(self.ready,self.binding)
        value={'status':'pass','returncode':0,'duration_seconds':.02,'log_truncated':False,'log':b'{}'}
        with patch.object(v,'_run_process',return_value=value),self.assertRaises(s.InventoryError) as error:session.collect()
        self.assertEqual(error.exception.code,'svd_capture_invalid')
        record=s.report_software_inventory(self.run)['record'];self.assertIsNone(record['observation'])
        self.assertTrue(all(row['status']=='unverified' for row in record['checks'][1:]))

    def test_changed_controller_and_matching_exports_cannot_relabel_original_capture_provenance(self):
        session=s.SoftwareInventorySession(self.ready,self.binding)
        with patch.object(v,'_run_process',side_effect=self.response):session.collect()
        controller=read_json(self.run.file(s.CONTROLLER));record=read_json(self.run.file(s.RECORD));raw=self.run.file(s.LOG).read_bytes()
        pure=s.records_module()
        for key,value in (('helper_image','sha256:'+'1'*64),('image_digest','sha256:'+'2'*64),('terraform_version','1.99.0'),('provider_version','9.9.9')):
            metadata=deepcopy(controller);changed=deepcopy(record)
            if key=='helper_image':metadata[key]=value;changed['execution_provenance']['helper']['image_digest']=value
            else:metadata['provisioner'][key]=value;changed['execution_provenance']['provisioner'][key]=value
            atomic_json(self.run.file(s.CONTROLLER),metadata);atomic_json(self.run.file(s.RECORD),changed)
            self.run.file(s.JSON_EXPORT).write_bytes(pure.render_json(changed));self.run.file(s.TEXT_EXPORT).write_text(pure.render_text(changed),encoding='utf-8')
            with self.assertRaises(s.InventoryError) as error:s.report_software_inventory(self.run)
            self.assertEqual(error.exception.code,'svd_provenance_invalid');self.assertEqual(self.run.file(s.LOG).read_bytes(),raw)

    def test_delayed_final_report_cannot_return_pass_after_absolute_deadline(self):
        session=s.SoftwareInventorySession(self.ready,self.binding);original=session.require_passed;clock=[0]
        def delayed():
            value=original();clock[0]=61;return value
        with patch.object(v,'_run_process',side_effect=self.response),patch.object(s.time,'monotonic',side_effect=lambda:clock[0]),\
            patch.object(session,'require_passed',side_effect=delayed),self.assertRaises(s.InventoryError) as error:session.collect()
        self.assertEqual(error.exception.code,'svd_timeout');self.assertEqual(session.receipt['status'],'failed')
        self.assertEqual(s.report_software_inventory(self.run)['record']['status'],'failed')


if __name__=='__main__':unittest.main()
