"""Synthetic orchestration guards only; no Docker, RPM or host operations."""
from copy import deepcopy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wormhole import rpm_acceptance as a
from wormhole.runs import create_run, read_json

SHA = 'a' * 40
BASE_RUN = '11111111-1111-4111-8111-111111111111'


class AcceptanceGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='worm-rpm-operator-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        p = patch.object(a,'create_run',side_effect=lambda *_,**__:create_run(self.root,fixture=False,identity=(SHA,False)))
        p.start();self.addCleanup(p.stop)

    def rows(self,scenario):
        ids = list(a.rpm.CHECKS) + ([a.rpm.OPTIONAL] if scenario=='missing-optional-package' else [])
        rows = [{'check_id':key,'target_id':'target-001','required':True,'status':'pass'} for key in ids]
        if scenario=='missing-optional-package': rows[-1]['status']='fail'
        if scenario=='version-expectation-mismatch':
            next(x for x in rows if x['check_id']=='rpm-openssh-server')['status']='fail'
        if scenario=='unsupported-os':
            rows[0]['status']='fail'
            for row in rows[1:5]: row['status']='unverified'
        return rows

    def case(self,scenario,*_):
        number = a.CASES.index(scenario)+1
        return {'scenario':scenario,'status':'passed','operation_status':'passed' if scenario=='healthy' else 'failed',
            'failure_code':a.EXPECTED.get(scenario),'source_revision':SHA,'source_dirty':False,
            'run_id':f'{number:08x}-0000-4000-8000-000000000001','derived_image':'sha256:'+str(number)*64,
            'content_sha256':'b'*64,'source_sha256':'c'*64}

    def test_rows_preserve_negative_meanings_and_refuse_missing_duplicate_or_foreign_checks(self):
        for scenario in a.CASES:
            rows=self.rows(scenario)
            self.assertEqual(a.checked_rows(scenario,rows),rows)
            for altered in (rows[:-1],rows+[deepcopy(rows[0])]):
                with self.assertRaises(a.rpm_target.RpmError):a.checked_rows(scenario,altered)
            altered=deepcopy(rows);altered[0]['target_id']='target-002'
            with self.assertRaises(a.rpm_target.RpmError):a.checked_rows(scenario,altered)
            altered=deepcopy(rows);altered[0]['required']=False
            with self.assertRaises(a.rpm_target.RpmError):a.checked_rows(scenario,altered)

    def test_wrong_negative_status_cannot_be_replaced_by_a_green_count(self):
        for scenario in a.CASES[1:]:
            rows=self.rows(scenario)
            for row in rows:row['status']='pass'
            with self.assertRaises(a.rpm_target.RpmError):a.checked_rows(scenario,rows)
        rows=self.rows('healthy');rows[-1]['status']='unverified'
        with self.assertRaises(a.rpm_target.RpmError):a.checked_rows('healthy',rows)

    def test_fresh_cases_share_content_but_never_run_or_image_identity(self):
        with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=self.case):
            value=a.acceptance('f'*64,BASE_RUN)
        self.assertEqual(value['status'],'passed');self.assertEqual(len(value['cases']),4)
        self.assertFalse(value['production_iso_eligible']);self.assertFalse(value['runtime_pipeline_complete'])
        for field in ('run_id','derived_image'):
            def reused(scenario,*args):
                item=self.case(scenario);item[field]=self.case('healthy')[field];return item
            with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=reused) as call:
                with self.assertRaises(a.rpm_target.RpmError):a.acceptance('f'*64,BASE_RUN)
            self.assertEqual(call.call_count,2)

    def test_contradictory_source_or_negative_outcome_cannot_pass_suite(self):
        for field,value in [('source_dirty',True),('source_revision','d'*40),('failure_code','wrong_failure')]:
            def wrong(scenario,*args):item=self.case(scenario);item[field]=value;return item
            with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=wrong):
                with self.assertRaises(a.rpm_target.RpmError):a.acceptance('f'*64,BASE_RUN)

    def test_source_refusal_before_next_child_does_not_blame_previous_child(self):
        identities=[(SHA,False),(SHA,False),(SHA,False),('d'*40,False)]
        with patch.object(a,'source_identity',side_effect=identities),patch.object(a,'qualify_case',side_effect=self.case) as call:
            with self.assertRaises(a.rpm_target.RpmError) as error:a.acceptance('f'*64,BASE_RUN)
        self.assertEqual(call.call_count,1)
        receipt=read_json(self.root/error.exception.suite_run_id/'evidence/rpm-acceptance-suite.json')
        self.assertIsNone(receipt['failed_child_run_id']);self.assertEqual(len(receipt['cases']),1)
        self.assertEqual(receipt['status'],'failed')

    def test_child_failure_keeps_both_ids_without_exporting_exception_text(self):
        failure=a.rpm_target.RpmError('rpm_example_failure','PRIVATE ERROR TEXT')
        failure.run_id=BASE_RUN
        with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=failure):
            with self.assertRaises(a.rpm_target.RpmError) as error:a.acceptance('f'*64,BASE_RUN)
        receipt=read_json(self.root/error.exception.suite_run_id/'evidence/rpm-acceptance-suite.json')
        self.assertEqual(receipt['failed_child_run_id'],BASE_RUN);self.assertEqual(receipt['error_code'],'rpm_example_failure')
        self.assertNotIn('PRIVATE ERROR TEXT',str(receipt))

    def test_failure_diagnostic_requires_exact_target_guard_and_retains_only_private_bytes(self):
        run=create_run(self.root,fixture=False,identity=(SHA,False));result={}
        session=SimpleNamespace(target_resources={'target-001':'f'*64},verify_target=lambda *args,**kwargs:None)
        capture={'status':'pass','returncode':0,'log':b'controlled server diagnostic\n','log_truncated':False}
        with patch.object(a.images,'inspect',return_value={'Id':'f'*64}),patch.object(a.images,'docker_configuration',return_value='/fixed/private/config'),\
            patch.object(a,'_run_process',return_value=capture) as call:
            a.retain_readiness_failure(run,result,session)
        self.assertEqual(call.call_args.args[0][-4:],('logs','--tail','200','f'*64))
        self.assertEqual(call.call_args.kwargs['timeout'],5);self.assertEqual(call.call_args.kwargs['log_limit'],65536)
        self.assertEqual(run.file(result['failure_diagnostic']['private_log']).read_bytes(),capture['log'])
        self.assertEqual(result['failure_diagnostic']['sha256'],a.hashlib.sha256(capture['log']).hexdigest())
        self.assertNotIn('controlled server diagnostic',str(result))
        def refused(*args,**kwargs):raise a.rpm_target.RpmError('rpm_owned_target_refused','private guard detail')
        session.verify_target=refused;result={}
        with patch.object(a.images,'inspect',return_value={'Id':'f'*64}),patch.object(a,'_run_process') as call:
            a.retain_readiness_failure(run,result,session)
        call.assert_not_called();self.assertEqual(result['failure_diagnostic'],{'status':'unavailable','code':'rpm_owned_target_refused'})


if __name__=='__main__':unittest.main()
