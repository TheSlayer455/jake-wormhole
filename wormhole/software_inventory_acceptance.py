"""Six fresh observed-inventory cases; failed target operations stay failed."""
import argparse
from copy import deepcopy
import json
import sys
from uuid import UUID

from . import candidate, chunks, images, rpm_candidate, rpm_target
from .admission import AdmissionLease
from .provisioning import ProvisioningSession
from .provisioning_acceptance import snapshot, scan_private_material, disk_sample, error_code
from .readiness import ReadinessSession
from .recovery import cleanup_session
from .rpm_acceptance import retain_readiness_failure, sweep
from .runs import Run, atomic_json, common, create_run, now, read_json, source_identity

CASES = (('ubuntu','healthy'),('ubi','healthy'),('ubi','missing-package'),
    ('ubi','wrong-version'),('ubuntu','collector-unavailable'),('ubuntu','wrong-identity'))
EXPECTED = {'missing-package':'svd_missing_package','wrong-version':'svd_version_mismatch',
    'collector-unavailable':'configured_interpreter_unavailable','wrong-identity':'svd_target_identity_mismatch'}
BASE_CHECKS = ('target-identity','userland','package-inventory','payload-version','payload-sha256',
    'candidate-manifest-sha256','candidate-content-sha256','candidate-source-sha256')


def require(value, code='svd_acceptance_invalid'):
    rpm_target.require(value,code)


def checked_rows(platform, scenario, rows, expected_ids):
    """Assert the complete grid and the meaning of each controlled negative."""
    require((platform,scenario) in CASES and type(expected_ids) is list and expected_ids[:8]==list(BASE_CHECKS) and
        len(set(expected_ids))==len(expected_ids) and len(expected_ids)==(14 if platform=='ubuntu' else 13 if scenario=='missing-package' else 12),
        'svd_acceptance_grid')
    require(type(rows) is list and [row['check_id'] for row in rows]==expected_ids and
        all(row['target_id']=='target-001' and row['required'] is True for row in rows),'svd_acceptance_grid')
    outcomes={key:'pass' for key in expected_ids}
    if scenario=='missing-package':outcomes['package-openssh-clients']='fail'
    elif scenario=='wrong-version':outcomes['package-openssh-server']='fail'
    elif scenario in ('collector-unavailable','wrong-identity'):
        outcomes={key:'unverified' for key in expected_ids}
        outcomes['target-identity']='fail' if scenario=='wrong-identity' else 'pass'
    require(all(row['status']==outcomes[row['check_id']] for row in rows),'svd_negative_not_observed')
    require(all(row['expected']==row['observed'] for row in rows if row['status']=='pass'),'svd_pass_values_disagree')
    return deepcopy(rows)


def qualify_case(platform, scenario, sentinel, base_run_id):
    from .software_inventory import SoftwareInventorySession, report_software_inventory, check_ids
    require((platform,scenario) in CASES and type(sentinel) is str and candidate.IDENTIFIER.fullmatch(sentinel),'svd_acceptance_input')
    require(type(base_run_id) is str and str(UUID(base_run_id))==base_run_id,'rpm_base_probe_required')
    revision,dirty=source_identity();require(sys.platform.startswith('linux') and dirty is False,'svd_acceptance_source')
    base_run=Run(images.RUNS_ROOT,base_run_id)
    if platform=='ubi':rpm_target.read_base_observation(base_run)
    run=create_run(images.RUNS_ROOT,fixture=False,kernel_lock=True)
    result={**common(run.manifest()),'operation':'real-software-inventory-acceptance','platform':platform,'scenario':scenario,
        'status':'running','phase':'source','created_at':now(),'iso_processing':'none',
        'runtime_pipeline_complete':False,'production_iso_eligible':False}
    def save():atomic_json(run.file('evidence/svd-acceptance.json'),result)
    save();session=readiness=None
    try:
        # This independent component does not execute the unsupported v1 pipeline.
        source=chunks.execute_fixture(run,transport='local',scenario='healthy')
        require(source['status']=='passed','svd_source_unverified');images.create_auth(run)
        with run.locked(),images.docker_scope(run),AdmissionLease(images.INFRASTRUCTURE,run.id,revision,'smoke') as lease:
            before=snapshot('container',sentinel,unrelated=True)
            bundle=candidate.prepare_candidate(run);result['phase']='derive-image';save()
            binding=(candidate.build_candidate(run,lease,bundle) if platform=='ubuntu' else
                rpm_candidate.build_rpm_candidate(run,lease,base_run=base_run))
            result.update(derived_image=binding['image_id'],candidate_sha256=binding['candidate_sha256'],
                candidate_files_sha256=candidate.sha(candidate.canonical(binding['manifest']['files'])),
                source_sha256=binding['manifest']['source_sha256'])
            result['phase']='provision';save()
            session=ProvisioningSession(run,lease,target_binding=binding);session.provision()
            require(sentinel not in {session.provisioner,*session.owned.values()},'svd_sentinel_is_owned')
            readiness=ReadinessSession(session,validation=True);readiness.start_helper()
            try:readiness.wait_ready();readiness.require_ready()
            except BaseException:
                retain_readiness_failure(run,result,session)
                try:save()
                except Exception:pass
                raise
            result['phase']='collect';save()
            collector=SoftwareInventorySession(readiness,binding,scenario=scenario);observed=None
            try:collector.collect();collector.require_passed()
            except Exception as error:observed=error_code(error)
            result['collector_failure_code']=observed
            require(observed==EXPECTED.get(scenario),'svd_unexpected_outcome')
            report=report_software_inventory(run);record=report['record']
            require(record==collector.receipt and record['status']==('passed' if observed is None else 'failed'),'svd_report_mismatch')
            rows=checked_rows(platform,scenario,record['checks'],list(check_ids(platform,scenario)))
            require(read_json(run.file('evidence/svd.json'))==record and
                run.file('evidence/svd.txt').read_text(encoding='utf-8')==report['text'],'svd_export_disagreement')
            observation=record['observation']
            if scenario in ('collector-unavailable','wrong-identity'):
                require(observation is None,'svd_unobserved_inventory_invented')
            else:
                require(type(observation) is dict and observation['package_manager']==('dpkg' if platform=='ubuntu' else 'rpm') and
                    type(observation['packages']) is list and len(observation['packages'])>len(rows)-8,'svd_full_inventory_missing')
                require(not any(row['name'] in ('ansible','ansible-core') for row in observation['packages']),'svd_helper_software_leaked')
            primary=session.receipt['primary_failure']
            require(primary is None if observed is None else primary is not None and primary['code']==observed,'svd_primary_failure_changed')
            result.update(target_resource_id=session.target_resources['target-001'],network_id=session.network_id,
                plan_sha256=record['plan_sha256'],record=record,checks=rows,
                text_sha256=candidate.sha(report['text'].encode('utf-8')),json_sha256=candidate.sha(run.file('evidence/svd.json').read_bytes()))
            cleanup=cleanup_session(session,lease,helper=readiness,reason='failure' if observed else 'success')
            require(cleanup['status']=='completed' and cleanup['unknown_outcome'] is False and
                (cleanup['primary_failure'] is None if observed is None else cleanup['primary_failure']['code']==observed),'svd_cleanup_incomplete')
            sweep(run)
            require(all(row['outcome']=='absent' or row['kind']=='image' and row['outcome']=='retained' for row in lease.record['resources']),
                'svd_resources_unreconciled')
            require(snapshot('container',sentinel,unrelated=True)==before,'svd_sentinel_changed')
            result.update(credential_scan=scan_private_material(run),disk_sample=disk_sample(run,'svd-cleaned'))
            require(source_identity()==(revision,False),'svd_acceptance_source')
            result.update(status='passed',phase='completed',operation_status='failed' if observed else 'passed',failure_code=observed,
                cleanup=cleanup,unrelated_sentinel_unchanged=True,finished_at=now());save()
            lease.finish(reconciliation_complete=True)
        return result
    except BaseException as error:
        result.update(status='failed',error_code=error_code(error),finished_at=now())
        if session is not None:
            try:
                from .recovery import recover_run
                result['failure_cleanup']=recover_run(run)
            except Exception:pass
        save();error.run_id=run.id;raise


def acceptance(sentinel,base_run_id):
    require(type(sentinel) is str and candidate.IDENTIFIER.fullmatch(sentinel),'svd_acceptance_input')
    require(type(base_run_id) is str and str(UUID(base_run_id))==base_run_id,'rpm_base_probe_required')
    revision=source_identity();require(revision[1] is False,'svd_acceptance_source')
    suite=create_run(images.RUNS_ROOT,fixture=False,kernel_lock=True)
    result={**common(suite.manifest()),'operation':'real-software-inventory-acceptance-suite','status':'running',
        'suite_run_id':suite.id,'base_probe_run_id':base_run_id,'cases':[],'pending_case':None,
        'runtime_pipeline_complete':False,'production_iso_eligible':False}
    def save():atomic_json(suite.file('evidence/svd-acceptance-suite.json'),result)
    with suite.locked():
        save()
        try:
            require(suite.manifest()['source_revision']==revision[0] and suite.manifest()['source_dirty'] is False,'svd_acceptance_source')
            for platform,scenario in CASES:
                require(source_identity()==revision,'svd_acceptance_source');result['pending_case']=[platform,scenario];save()
                value=qualify_case(platform,scenario,sentinel,base_run_id)
                require(value['status']=='passed' and value['source_revision']==revision[0] and value['source_dirty'] is False and
                    value['platform']==platform and value['scenario']==scenario and str(UUID(value['run_id']))==value['run_id'] and
                    value['operation_status']==('passed' if scenario=='healthy' else 'failed') and
                    value['failure_code']==EXPECTED.get(scenario) and candidate.IMAGE.fullmatch(value['derived_image']) and
                    source_identity()==revision,'svd_acceptance_source')
                require(value['run_id']!=suite.id and value['run_id'] not in {row['run_id'] for row in result['cases']} and
                    value['derived_image'] not in {row['derived_image'] for row in result['cases']},'svd_runs_not_isolated')
                result['cases'].append(value);result['pending_case']=None;save()
            require(len({row['candidate_files_sha256'] for row in result['cases']})==1 and
                len({row['source_sha256'] for row in result['cases']})==1,'svd_candidate_content_changed')
            result['status']='passed';save();return result
        except BaseException as error:
            result.update(status='failed',failed_child_run_id=getattr(error,'run_id',None),error_code=error_code(error));save()
            error.suite_run_id=suite.id;raise


def main(arguments=None):
    parser=argparse.ArgumentParser(description='Actual bounded Ubuntu/UBI inventory qualification; no VM or ISO acceptance.')
    parser.add_argument('--base-run',required=True);parser.add_argument('--sentinel-id',required=True)
    parser.add_argument('--platform',choices=('ubuntu','ubi'),default='ubuntu')
    parser.add_argument('--case',choices=('healthy',*EXPECTED),default='healthy');parser.add_argument('--all',action='store_true')
    options=parser.parse_args(arguments)
    try:
        value=(acceptance(options.sentinel_id,options.base_run) if options.all else
            qualify_case(options.platform,options.case,options.sentinel_id,options.base_run))
        print(json.dumps(value,sort_keys=True));return 0
    except Exception as error:
        print(json.dumps({'error':{'code':error_code(error)},'run_id':getattr(error,'run_id',None),
            'suite_run_id':getattr(error,'suite_run_id',None),'private_evidence_retained':True}));return 1


if __name__=='__main__':raise SystemExit(main())
