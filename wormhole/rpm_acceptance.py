"""Explicit four-case UBI container qualification, with fresh attributable Runs.

No operation runs on import. Negative harness success preserves failed target
operations. This is not a scanner, RHEL VM, ISO or complete-pipeline result.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import sys
from uuid import UUID

from . import candidate, chunks, images, rpm_candidate as rpm, rpm_target
from .admission import AdmissionLease
from .provisioning import ProvisioningSession
from .provisioning_acceptance import snapshot, scan_private_material, disk_sample, error_code
from .readiness import ReadinessSession
from .recovery import cleanup_session
from .runs import Run, SOURCE_ROOT, atomic_bytes, atomic_json, common, create_run, now, source_identity
from .stages import _run_process, execute_run

CASES = ('healthy', 'missing-optional-package', 'version-expectation-mismatch', 'unsupported-os')
EXPECTED = {'missing-optional-package':'rpm_missing_package', 'version-expectation-mismatch':'rpm_version_mismatch',
            'unsupported-os':'rpm_applicability_mismatch'}


def require(value, code='rpm_acceptance_invalid'):
    rpm_target.require(value, code)


def sweep(run):
    for args in (('ps','-a','--no-trunc'), ('network','ls','--no-trunc')):
        result = images.docker((*args,'--filter','label='+images.LABEL+'.run_id='+run.id,'--format','{{.ID}}'))
        require(not result['log_truncated'] and not result['log'].strip(), 'rpm_resources_remain')


def checked_rows(scenario, rows):
    """Freeze required identities and negative meanings; never trust a pass count."""
    ids = list(rpm.CHECKS) + ([rpm.OPTIONAL] if scenario == 'missing-optional-package' else [])
    require(type(rows) is list and [x['check_id'] for x in rows] == ids and
            all(x['target_id']=='target-001' and x['required'] is True for x in rows), 'rpm_required_rows_missing')
    expected = {key:'pass' for key in ids}
    if scenario == 'missing-optional-package': expected[rpm.OPTIONAL] = 'fail'
    elif scenario == 'version-expectation-mismatch': expected['rpm-openssh-server'] = 'fail'
    elif scenario == 'unsupported-os':
        expected['rpm-userland'] = 'fail'
        for package in rpm.PACKAGES: expected['rpm-'+package] = 'unverified'
    require(all(x['status']==expected[x['check_id']] for x in rows), 'rpm_negative_not_observed')
    return deepcopy(rows)


def retain_readiness_failure(run, result, session):
    """Read only exact-owned target logs before normal cleanup; never mask failure."""
    try:
        identifier = session.target_resources['target-001']
        actual = images.inspect('container', identifier)
        session.verify_target(actual, target_id='target-001')
        value = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
            'logs', '--tail', '200', identifier), cwd=SOURCE_ROOT, timeout=5, log_limit=65536)
        raw = value['log']
        relative = 'private/rpm-target-readiness-failure.log'
        atomic_bytes(run.file(relative), raw, limit=65536)
        result['failure_diagnostic'] = {'status': value['status'], 'returncode': value.get('returncode'),
            'log_truncated': value['log_truncated'], 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(), 'private_log': relative}
    except Exception as error:
        result['failure_diagnostic'] = {'status': 'unavailable', 'code': error_code(error)}


def qualify_case(scenario, sentinel, base_run_id):
    from .rpm_validation import RPMValidationSession, report_rpm_validation
    require(scenario in CASES and type(sentinel) is str and candidate.IDENTIFIER.fullmatch(sentinel), 'rpm_acceptance_input')
    require(type(base_run_id) is str and str(UUID(base_run_id)) == base_run_id, 'rpm_base_probe_required')
    revision,dirty = source_identity(); require(sys.platform.startswith('linux') and dirty is False, 'rpm_acceptance_source')
    base_run = Run(images.RUNS_ROOT,base_run_id)
    rpm_target.read_base_observation(base_run)
    run = create_run(images.RUNS_ROOT,fixture=False,kernel_lock=True)
    result = {**common(run.manifest()),'operation':'real-rpm-acceptance','scenario':scenario,'status':'running',
        'phase':'source','created_at':now(),'base_probe_run_id':base_run_id,'iso_processing':'none',
        'runtime_pipeline_complete':False,'production_iso_eligible':False}
    def save(): atomic_json(run.file('evidence/rpm-acceptance.json'),result)
    save(); session = readiness = None
    try:
        with run.locked(): execute_run(run)  # The full v1 runtime pipeline is still unsupported.
        source = chunks.execute_fixture(run,transport='local',scenario='healthy')
        require(source['status']=='passed','rpm_source_unverified'); images.create_auth(run)
        with run.locked(),images.docker_scope(run),AdmissionLease(images.INFRASTRUCTURE,run.id,revision,'smoke') as lease:
            before = snapshot('container',sentinel,unrelated=True)
            candidate.prepare_candidate(run)
            result['phase']='derive-image'; save()
            binding = rpm.build_rpm_candidate(run,lease,base_run=base_run)
            rpm.validate_binding(run,binding); rpm.verify_image(images.inspect('image',binding['image_id']),binding)
            result.update(derived_image=binding['image_id'],base_image=binding['base_image'],
                candidate_sha256=binding['candidate_sha256'],content_sha256=binding['content_sha256'],
                source_candidate_sha256=binding['source_candidate_sha256'],source_sha256=binding['manifest']['source_sha256'],
                test_contract_sha256=binding['test_contract_sha256'])
            result['phase']='provision'; save()
            session = ProvisioningSession(run,lease,target_binding=binding); session.provision()
            require(sentinel not in {session.provisioner,*session.owned.values()},'rpm_sentinel_is_owned')
            readiness = ReadinessSession(session,validation=True)
            readiness.start_helper()
            try:
                readiness.wait_ready(); readiness.require_ready()
            except BaseException:
                retain_readiness_failure(run,result,session)
                save()
                raise
            result['phase']='ssh-ansible'; save()
            validator = RPMValidationSession(readiness,binding,scenario=scenario)
            observed = None
            try: validator.validate()
            except rpm_target.RpmError as error: observed = error.code
            require(observed==EXPECTED.get(scenario),'rpm_unexpected_outcome')
            report = report_rpm_validation(run)
            require(report['result']==validator.receipt and report['result']['status']==('passed' if observed is None else 'failed'),
                    'rpm_report_mismatch')
            rows = checked_rows(scenario,report['result']['checks'])
            primary = session.receipt['primary_failure']
            require(primary is None if observed is None else primary is not None and primary['code']==observed,
                    'rpm_primary_failure_changed')
            result.update(target_resource_id=session.target_resources['target-001'],network_id=session.network_id,
                validation_plan_sha256=validator.plan['plan_sha256'],checks=rows)
            cleanup = cleanup_session(session,lease,helper=readiness,reason='failure' if observed else 'success')
            require(cleanup['status']=='completed' and cleanup['unknown_outcome'] is False and
                (cleanup['primary_failure'] is None if observed is None else cleanup['primary_failure']['code']==observed),
                'rpm_cleanup_incomplete')
            sweep(run)
            require(all(x['outcome']=='absent' or x['kind']=='image' and x['outcome']=='retained' for x in lease.record['resources']),
                    'rpm_resources_unreconciled')
            require(snapshot('container',sentinel,unrelated=True)==before,'rpm_sentinel_changed')
            result.update(credential_scan=scan_private_material(run),disk_sample=disk_sample(run,'rpm-cleaned'))
            require(source_identity()==(revision,False),'rpm_acceptance_source')
            result.update(status='passed',phase='completed',operation_status='failed' if observed else 'passed',failure_code=observed,
                cleanup=cleanup,unrelated_sentinel_unchanged=True,finished_at=now()); save()
            lease.finish(reconciliation_complete=True)
        return result
    except BaseException as error:
        result.update(status='failed',error_code=error_code(error),finished_at=now())
        # Original-source normal recovery only; an uncertain builder/resolver
        # remains blocked rather than being adopted, pruned or silently retried.
        if session is not None:
            try:
                from .recovery import recover_run
                result['failure_cleanup']=recover_run(run)
            except Exception: pass
        save(); error.run_id=run.id; raise


def acceptance(sentinel,base_run_id):
    require(type(sentinel) is str and candidate.IDENTIFIER.fullmatch(sentinel),'rpm_acceptance_input')
    require(type(base_run_id) is str and str(UUID(base_run_id))==base_run_id,'rpm_base_probe_required')
    revision = source_identity(); require(revision[1] is False,'rpm_acceptance_source')
    suite = create_run(images.RUNS_ROOT,fixture=False,kernel_lock=True)
    result = {**common(suite.manifest()),'operation':'real-rpm-acceptance-suite','suite_run_id':suite.id,'status':'running',
        'base_probe_run_id':base_run_id,'cases':[],'pending_scenario':None,'iso_processing':'none',
        'runtime_pipeline_complete':False,'production_iso_eligible':False}
    def save(): atomic_json(suite.file('evidence/rpm-acceptance-suite.json'),result)
    with suite.locked():
        save()
        try:
            require(suite.manifest()['source_revision']==revision[0] and suite.manifest()['source_dirty'] is False,'rpm_acceptance_source')
            for scenario in CASES:
                require(source_identity()==revision,'rpm_acceptance_source')
                result['pending_scenario']=scenario; save()
                value = qualify_case(scenario,sentinel,base_run_id)
                require(value['status']=='passed' and value['source_revision']==revision[0] and value['source_dirty'] is False and
                    value['scenario']==scenario and str(UUID(value['run_id']))==value['run_id'] and
                    value['operation_status']==('passed' if scenario=='healthy' else 'failed') and value['failure_code']==EXPECTED.get(scenario) and
                    candidate.IMAGE.fullmatch(value['derived_image']) and source_identity()==revision,'rpm_acceptance_source')
                require(value['run_id']!=suite.id and value['run_id'] not in {x['run_id'] for x in result['cases']} and
                    value['derived_image'] not in {x['derived_image'] for x in result['cases']},'rpm_runs_not_isolated')
                result['cases'].append(value); result['pending_scenario']=None; save()
            require(len({x['run_id'] for x in result['cases']})==4 and len({x['derived_image'] for x in result['cases']})==4 and
                len({x['content_sha256'] for x in result['cases']})==1 and len({x['source_sha256'] for x in result['cases']})==1,
                'rpm_runs_not_isolated')
            result['status']='passed'; save(); return result
        except BaseException as error:
            result.update(status='failed',failed_child_run_id=getattr(error,'run_id',None),error_code=error_code(error)); save()
            error.suite_run_id=suite.id; raise


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Four fresh owned UBI reference cases; no VM, ISO, scanner or production acceptance.')
    parser.add_argument('--base-run',required=True); parser.add_argument('--sentinel-id',required=True)
    parser.add_argument('--case',choices=CASES,default='healthy'); parser.add_argument('--all',action='store_true')
    options = parser.parse_args(arguments)
    try:
        value = acceptance(options.sentinel_id,options.base_run) if options.all else qualify_case(options.case,options.sentinel_id,options.base_run)
        print(json.dumps(value,sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({'error':{'code':error_code(error)},'run_id':getattr(error,'run_id',None),
            'suite_run_id':getattr(error,'suite_run_id',None),'private_evidence_retained':True})); return 1


if __name__=='__main__': raise SystemExit(main())
