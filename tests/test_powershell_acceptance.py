"""Operator boundary fixtures; no Docker, package execution or host mutation."""
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wormhole import powershell_acceptance as a
from wormhole.runs import RunError, common, create_run, read_json

SHA='a'*40
SENTINEL='b'*64


class OperatorBoundaries(unittest.TestCase):
    def test_wrong_platform_or_sentinel_cannot_create_runs_or_call_docker(self):
        with patch.object(a,'new_run',side_effect=AssertionError('No allocation')):
            with self.assertRaises(RunError):a.acceptance('not-an-ID')
            with patch.object(a.sys,'platform','win32'),self.assertRaises(RunError):a.acceptance(SENTINEL)

    def exercise(self, fault=None):
        temporary=tempfile.TemporaryDirectory(prefix='wormhole-ps-operator-synthetic-');self.addCleanup(temporary.cleanup)
        folder=Path(temporary.name);runs=[];calls=[]
        def new():
            run=create_run(folder/'runs',fixture=False,identity=(SHA,False));runs.append(run);return run
        def execute(run,selection,build_run=None):
            calls.append(selection)
            value={**common(run.manifest()),'status':'completed','resources_reconciled':True,'unknown_outcome':False,'primary_failure':None}
            if selection=='missing-package-fixture':
                value.update(status='failed',primary_failure={'code':'package_unavailable'},observation={'failure':{'code':'package_unavailable','package':'powershell','expected_version':'7.6.8-1.deb','execution_location':'optional-helper-package-source-fixture','returncode':100}})
                if fault=='unknown':value['unknown_outcome']=True
            elif build_run is None:
                value.update(image_id='sha256:'+'c'*64,base_reference={'image_id':a.capability.BASE,'source_revision':a.capability.BASE_SOURCE},installed={'powershell':{'version':'7.6.8'}})
            else:value.update(image='sha256:'+'c'*64,observation={'powershell':{'version':'7.6.8','edition':'Core','platform':'Unix','result':2},'ordinary_helper_doctor':{'passed':True}})
            if fault=='wrong-source':value['source_revision']='d'*40
            return value
        def normal(_):
            if fault=='normal-failure':raise RunError('synthetic_normal_failure','Fixture')
            value={**common(new().manifest()),'status':'pass'}
            if fault=='reuse':value['run_id']=runs[1].id
            return value
        contexts=[patch.object(a.sys,'platform','linux'),patch.object(a,'source_identity',return_value=(SHA,False)),
            patch.object(a,'new_run',side_effect=new),patch.object(a.images,'docker_scope',side_effect=lambda _:nullcontext()),
            patch.object(a,'snapshot',return_value='stable-synthetic-sentinel'),patch.object(a.capability,'execute',side_effect=execute),
            patch.object(a,'ordinary_diagnostics',side_effect=normal)]
        for context in contexts:context.start();self.addCleanup(context.stop)
        if fault:
            with self.assertRaises(RunError):a.acceptance(SENTINEL)
            self.assertEqual(read_json(runs[0].file('evidence/powershell-acceptance.json'))['status'],'failed')
        else:
            result=a.acceptance(SENTINEL);self.assertEqual(len(result['stages']),4)
            self.assertEqual(len({item['run_id'] for item in result['stages']}),4)
            self.assertFalse(result['production_iso_eligible']);self.assertFalse(result['runtime_pipeline_complete'])
            self.assertEqual(result['stages'][0]['operation_status'],'failed')
        return calls

    def test_four_fresh_serial_cases_preserve_failed_negative_and_false_eligibility(self):self.exercise()
    def test_unknown_missing_outcome_stops_before_normal_diagnostics_or_build(self):self.assertEqual(self.exercise('unknown'),['missing-package-fixture'])
    def test_wrong_source_stops_before_next_allocation(self):self.assertEqual(self.exercise('wrong-source'),['missing-package-fixture'])
    def test_reused_run_id_or_independent_diagnostic_failure_cannot_start_build(self):
        for fault in ('reuse','normal-failure'):
            with self.subTest(fault=fault):self.assertEqual(self.exercise(fault),['missing-package-fixture'])


if __name__=='__main__':unittest.main()
