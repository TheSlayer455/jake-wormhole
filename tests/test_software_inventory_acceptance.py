"""Synthetic acceptance guards; no target, package, Docker or SSH execution."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import software_inventory_acceptance as a
from wormhole.runs import create_run, read_json

SHA='a'*40
BASE='11111111-1111-4111-8111-111111111111'


class InventoryAcceptanceGuards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='worm-svd-guards-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        p=patch.object(a,'create_run',side_effect=lambda *args,**kwargs:create_run(self.root,fixture=False,identity=(SHA,False)))
        p.start();self.addCleanup(p.stop)

    def grid(self,platform,scenario):
        names=(['ca-certificates','openssh-client','openssh-server','openssh-sftp-server','python3','python3-12'] if platform=='ubuntu'
            else ['openssh','openssh-server','python3','shadow-utils'])
        if scenario=='missing-package':names=sorted(names+['openssh-clients'])
        ids=list(a.BASE_CHECKS)+['package-'+name for name in names]
        rows=[{'check_id':key,'target_id':'target-001','required':True,'status':'pass','expected':'actual','observed':'actual'} for key in ids]
        if scenario in ('missing-package','wrong-version'):
            key='package-openssh-clients' if scenario=='missing-package' else 'package-openssh-server'
            row=next(row for row in rows if row['check_id']==key);row.update(status='fail',observed='different')
        if scenario in ('collector-unavailable','wrong-identity'):
            for row in rows:row.update(status='unverified',observed='not-observed')
            rows[0].update(status='fail' if scenario=='wrong-identity' else 'pass',observed='different' if scenario=='wrong-identity' else 'actual')
        return ids,rows

    def case(self,platform,scenario,*args):
        number=a.CASES.index((platform,scenario))+1
        return {'platform':platform,'scenario':scenario,'status':'passed','source_revision':SHA,'source_dirty':False,
            'operation_status':'passed' if scenario=='healthy' else 'failed','failure_code':a.EXPECTED.get(scenario),
            'run_id':f'{number:08x}-0000-4000-8000-000000000001','derived_image':'sha256:'+str(number)*64,
            'candidate_files_sha256':'b'*64,'source_sha256':'c'*64}

    def test_all_six_grids_and_negative_meanings_require_complete_owned_rows(self):
        for platform,scenario in a.CASES:
            ids,rows=self.grid(platform,scenario)
            self.assertEqual(a.checked_rows(platform,scenario,rows,ids),rows)
            for changed in (rows[:-1],rows+[deepcopy(rows[0])]):
                with self.assertRaises(a.rpm_target.RpmError):a.checked_rows(platform,scenario,changed,ids)
            for field,value in [('target_id','target-002'),('required',False)]:
                changed=deepcopy(rows);changed[0][field]=value
                with self.assertRaises(a.rpm_target.RpmError):a.checked_rows(platform,scenario,changed,ids)

    def test_green_negative_and_unequal_passing_values_are_rejected(self):
        for platform,scenario in a.CASES[2:]:
            ids,rows=self.grid(platform,scenario)
            for row in rows:row.update(status='pass',observed=row['expected'])
            with self.assertRaises(a.rpm_target.RpmError):a.checked_rows(platform,scenario,rows,ids)
        ids,rows=self.grid('ubuntu','healthy');rows[-1]['observed']='wrong'
        with self.assertRaises(a.rpm_target.RpmError):a.checked_rows('ubuntu','healthy',rows,ids)

    def test_suite_requires_six_unique_runs_images_and_shared_file_bytes(self):
        with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=self.case):
            result=a.acceptance('f'*64,BASE)
        self.assertEqual(len(result['cases']),6);self.assertEqual(result['status'],'passed')
        self.assertFalse(result['production_iso_eligible']);self.assertFalse(result['runtime_pipeline_complete'])
        for field in ('run_id','derived_image','candidate_files_sha256','source_sha256'):
            def changed(platform,scenario,*args):
                result=self.case(platform,scenario)
                if (platform,scenario)!=a.CASES[0]:
                    result[field]=(self.case(*a.CASES[0])[field] if field in ('run_id','derived_image') else 'd'*64)
                return result
            with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=changed):
                with self.assertRaises(a.rpm_target.RpmError):a.acceptance('f'*64,BASE)

    def test_underlying_failure_and_source_cannot_be_promoted_to_healthy(self):
        for field,value in [('source_dirty',True),('source_revision','d'*40),('failure_code','wrong_failure')]:
            def changed(platform,scenario,*args):result=self.case(platform,scenario);result[field]=value;return result
            with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=changed):
                with self.assertRaises(a.rpm_target.RpmError):a.acceptance('f'*64,BASE)

    def test_source_refusal_before_next_child_does_not_blame_the_previous_child(self):
        with patch.object(a,'source_identity',side_effect=[(SHA,False),(SHA,False),(SHA,False),('d'*40,False)]),\
            patch.object(a,'qualify_case',side_effect=self.case) as call:
            with self.assertRaises(a.rpm_target.RpmError) as error:a.acceptance('f'*64,BASE)
        receipt=read_json(self.root/error.exception.suite_run_id/'evidence/svd-acceptance-suite.json')
        self.assertEqual(call.call_count,1);self.assertEqual(len(receipt['cases']),1)
        self.assertIsNone(receipt['failed_child_run_id'])

    def test_child_error_keeps_both_ids_and_hides_private_exception_text(self):
        failure=a.rpm_target.RpmError('svd_example_failure','PRIVATE DETAILS');failure.run_id=BASE
        with patch.object(a,'source_identity',return_value=(SHA,False)),patch.object(a,'qualify_case',side_effect=failure):
            with self.assertRaises(a.rpm_target.RpmError) as error:a.acceptance('f'*64,BASE)
        receipt=read_json(self.root/error.exception.suite_run_id/'evidence/svd-acceptance-suite.json')
        self.assertEqual(receipt['failed_child_run_id'],BASE);self.assertEqual(receipt['error_code'],'svd_example_failure')
        self.assertNotIn('PRIVATE DETAILS',str(receipt))


if __name__=='__main__':unittest.main()
