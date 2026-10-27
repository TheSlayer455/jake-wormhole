"""Fixed focused/fleet fault operations using the existing execution adapters.

These are stock-container acceptance experiments, not candidate fleet or ISO
qualification. An expected negative keeps its underlying nonzero CLI outcome.
"""
from copy import deepcopy
import hashlib
import re
import sys
import time

from . import candidate, chunks, images
from .admission import AdmissionLease
from .fleet_acceptance import restart_owned_target
from .fleet_readiness import BatchReadinessSession
from .fleet_validation import BatchValidationSession, report_batch_validation
from .initialization import InitializationSession
from .lifecycle import Lifecycle, initialization_events, readiness_events
from .provisioning import ProvisioningSession, TARGET_IMAGE
from .provisioning_acceptance import snapshot
from .recovery import cleanup_session, safe_code
from .runs import RunError, atomic_json, common, create_run, now, source_identity
from .targets import TargetPlan
from .validation import CHECKS
from .failure_scenarios import SCENARIOS

EXPECTED={'initialization-command-fails':'initialization_command_failed','account-missing':'final_account_missing',
    'home-inaccessible':'final_home_inaccessible','authorized-key-missing':'authorized_key_missing',
    'hardening-breaks-home':'final_home_inaccessible','wrong-key':'ssh_key_rejected','never-ready':'target_not_started',
    'interpreter-unavailable':'configured_interpreter_unavailable','playbook-fails':'required_batch_check_failed',
    'controller-deadline':'validation_timeout','remote-unknown':'initialization_outcome_unknown',
    'candidate-stale':'candidate_stale','source-chunk-corrupted':'source_integrity_failed',
    'required-evidence-missing':'required_evidence_missing','cleanup-error':'controlled_cleanup_error'}
STAGES=('preflight','source','candidate-integrity','provisioning','initialization','readiness',
    'functional','assessment','evidence','cleanup','publication')


def require(value,code):
    if not value: raise RunError(code,'The declared fault experiment did not satisfy its bounded execution contract.')


def expectation_met(record,profile):
    expected=EXPECTED.get(record['scenario']);codes={expected}
    if record['scenario']=='never-ready' and profile=='twenty-targets':codes.add('deadline_exhausted')
    observed=(record['status']=='passed' and expected is None and record['primary_failure'] is None) or (
        record['status']=='failed' and expected is not None and (record['primary_failure'] or {}).get('code') in codes)
    return (observed and record['unknown_outcome'] is False and not record['remaining_owned_resources'] and
        record['cleanup'] is not None and record['cleanup']['status']=='completed' and record.get('sentinel_unchanged') is True)


def reproduce(profile,scenario,sentinel_id):
    require(profile in {'smoke','five-targets','twenty-targets'} and scenario in SCENARIOS,'reproduction_selection')
    require(type(sentinel_id) is str and re.fullmatch('[a-f0-9]{64}',sentinel_id),'invalid_sentinel')
    require(sys.platform.startswith('linux'),'linux_required')
    revision,dirty=source_identity();require(not dirty,'source_changed')
    plan=TargetPlan(profile);selected=plan.target_ids[-1]
    run=create_run(images.RUNS_ROOT,fixture=False,kernel_lock=True,profile=profile)
    record={**common(run.manifest()),'operation':'owned-container-failure-reproduction-v1','scenario':scenario,
        'target_plan':plan.record(),'status':'running','primary_failure':None,'secondary_failures':[],
        'unknown_outcome':False,'scenario_expectation_met':False,'full_catalog_started':False,
        'stage_timings':dict.fromkeys(STAGES,None),'cleanup':None,'remaining_owned_resources':[],
        'reference_eligible':False,'production_iso_eligible':False,'simulation':scenario in {'candidate-stale','cleanup-error'},
        'candidate_binding':'qualified stock image; candidate-bound fleet not established'}
    journal=None;ps=ready=initialization=validation=None;failure=None
    def save():
        record['updated_at']=now();atomic_json(run.file('evidence/failure-reproduction.json'),record)
    def stage(name,action):
        began=time.monotonic();timing={'started_at':now(),'finished_at':None,'elapsed_seconds':None,'outcome':'running'}
        record['stage_timings'][name]=timing;save()
        try:
            value=action()
            timing['outcome']='failed' if type(value) is dict and value.get('status') in {'failed','blocked','pending'} else 'passed'
            return value
        except BaseException:
            timing['outcome']='failed';raise
        finally:
            timing.update(finished_at=now(),elapsed_seconds=time.monotonic()-began);save()
    def retain(error):
        nonlocal failure
        if failure is None:
            failure=error;record['primary_failure']={'code':safe_code(error),'recorded_at':now()}
        else:record['secondary_failures'].append({'code':safe_code(error),'recorded_at':now()})
        if ps is not None: ps.failure(error)
    with run.locked(): save()
    try:
        images.create_auth(run)
        with run.locked() as guard,images.docker_scope(run):
            baseline=stage('preflight',lambda:snapshot('container',sentinel_id,unrelated=True))
            journal=Lifecycle(run,plan.target_ids,candidate_identity={'image_id':TARGET_IMAGE,'kind':'stock-image'},
                checks=CHECKS,budget_seconds=240 if profile=='twenty-targets' else 180)
            if scenario=='candidate-stale':
                expected=candidate.input_identity('a'*64)
                stale=deepcopy(expected);stale['build_inputs']['configuration']={'stale':True}
                stale['input_sha256']=candidate.sha(candidate.canonical(stale['build_inputs']))
                require(candidate.compare_inputs(stale,expected)['content_reusable'] is False,'fault_not_observed')
                record['cleanup']={'status':'completed','resources_allocated':0}
                record['sentinel_unchanged']=snapshot('container',sentinel_id,unrelated=True)==baseline
                raise RunError('candidate_stale','Controlled stale construction inputs were refused before provisioning.')
            if scenario=='source-chunk-corrupted':
                def corrupt():
                    try:result=chunks.execute_fixture_held(run,guard,transport='local',scenario='corrupted')
                    except RunError:
                        record['cleanup']={'status':'completed','resources_allocated':0}
                        record['sentinel_unchanged']=snapshot('container',sentinel_id,unrelated=True)==baseline
                        raise RunError('source_integrity_failed','Corrupted source refused before provisioning.') from None
                    if result['status']!='passed':
                        record['cleanup']={'status':'completed','resources_allocated':0}
                        record['sentinel_unchanged']=snapshot('container',sentinel_id,unrelated=True)==baseline
                        raise RunError('source_integrity_failed','Corrupted source refused before provisioning.')
                stage('source',corrupt)
            with AdmissionLease(images.INFRASTRUCTURE,run.id,revision,profile) as lease:
                try:
                    ps=ProvisioningSession(run,lease,mutable_home=True)
                    stage('provisioning',ps.create_stopped)
                    for target in plan.target_ids:journal.event(target,'created',evidence='evidence/provisioning.json',persist=False)
                    delayed=scenario in {'never-ready','ready-late'}
                    initial=[target for target in plan.target_ids if not delayed or target!=selected]
                    if initial:ps.start_and_inventory(initial)
                    for target in initial:journal.event(target,'runtime-started',evidence='evidence/provisioning.json',persist=False)
                    journal.save()
                    initialization=InitializationSession(ps,absolute_deadline=journal.deadline-20)
                    configured={selected:'wrong-key'} if scenario=='wrong-key' else {selected:'configured-interpreter-unavailable'} if scenario=='interpreter-unavailable' else {}
                    ready=BatchReadinessSession(ps,scenarios=configured,initialization=initialization)
                    ready.deadline=min(ready.deadline,journal.deadline-20)
                    ready.start_helper()
                    early_port=scenario in {'port-briefly-opens','restart-during-readiness'}
                    if early_port:
                        with ready.selected(selected):
                            address=ready.endpoint();until=time.monotonic()+5
                            while True:
                                probe=ready.probe('tcp',address)
                                if probe['status']=='pass' or time.monotonic()>=until:break
                                time.sleep(.1)
                            require(probe['status']=='pass','early_port_not_observed')
                        journal.event(selected,'reachable',evidence='evidence/readiness.json')
                        require(not journal.ready(selected),'premature_readiness')
                        ready.invalidate(selected,expected_restart=True)
                        journal.event(selected,'restart-started',evidence='evidence/provisioning.json')
                        restart_owned_target(ps,selected)
                        journal.event(selected,'restart-complete',evidence='evidence/provisioning.json')
                    def initialize():
                        for target in initial:
                            chosen=scenario if target==selected and scenario in {
                                'initialization-command-fails','account-missing','home-inaccessible','authorized-key-missing'} else 'healthy'
                            observation=initialization.wait_result(target,chosen)
                            initialization_events(journal,target,observation,'evidence/initialization.json')
                        return {'status':'failed' if any(item['observation']['status']!='passed'
                            for item in initialization.record['targets'].values()) else 'passed'}
                    stage('initialization',initialize)
                    deferred={'started':False,'deadline_shortened':False}
                    def poll(elapsed):
                        if scenario=='ready-late' and elapsed>=2 and not deferred['started']:
                            ps.start_and_inventory([selected]);deferred['started']=True
                            journal.event(selected,'runtime-started',evidence='evidence/provisioning.json')
                            observation=initialization.wait_result(selected)
                            initialization_events(journal,selected,observation,'evidence/initialization.json')
                        if scenario=='never-ready' and len(ready.ready_target_ids)==len(plan.target_ids)-1 and not deferred['deadline_shortened']:
                            ready.deadline=min(ready.deadline,time.monotonic()+2);deferred['deadline_shortened']=True
                    try:stage('readiness',lambda:ready.wait_ready(on_poll=poll))
                    except RunError as error:retain(error)
                    for target in plan.target_ids:
                        child=ready.target_state(target)
                        if child['status']=='ready':readiness_events(journal,target,child)
                        elif journal.target(target)['first_failure'] is None:
                            journal.event(target,'failure',evidence='evidence/readiness.json',
                                category=(child['primary_failure'] or {}).get('code','readiness_incomplete'))
                    validation=BatchValidationSession(ready,scenarios={selected:'configured-interpreter-unavailable'} if scenario=='playbook-fails' else {})
                    if failure is None and scenario=='hardening-breaks-home':
                        initialization.begin_phase()
                        observation=initialization.observe(selected,'hardening-breaks-home')
                        initialization_events(journal,selected,observation,'evidence/initialization.json')
                        ready.invalidate(selected)
                        try:ready.require_ready(selected)
                        except RunError as error:retain(error)
                    if failure is None and scenario=='remote-unknown':
                        initialization.begin_phase()
                        try:initialization.observe(selected,'observer-lost')
                        except RunError as error:
                            retain(error);journal.event(selected,'failure',evidence='evidence/initialization.json',category=safe_code(error))
                            journal.event(selected,'remote-unknown',evidence='evidence/initialization.json')
                    if failure is None:journal.start_validation()
                    try:
                        result=stage('functional',lambda:validation.validate(absolute_deadline=
                            time.monotonic()-1 if scenario=='controller-deadline' else journal.deadline-20))
                    except RunError as error:
                        retain(error);result=validation.receipt
                    record['full_catalog_started']=bool(result['attempts'])
                    for row in result['checks']:
                        if journal.target(row['target_id'])['current_phase']=='validating':
                            journal.test_result(row['target_id'],row['check_id'],row['status'] if row['status'] in {'pass','fail','error','unreachable'} else 'blocked',persist=False)
                    journal.save();journal.finalize()
                    record['functional_grid']=deepcopy(result['checks'])
                    if scenario=='required-evidence-missing' and failure is None:
                        run.file('evidence/batch-validation-observations.json').unlink()
                        try:report_batch_validation(run)
                        except OSError:raise RunError('required_evidence_missing','Disposable negative evidence was absent and acceptance refused.') from None
                    if scenario=='cleanup-error':retain(RunError('controlled_cleanup_error','Controlled pre-cleanup diagnostic failure; normal cleanup must still execute.'))
                except BaseException as error:retain(error)
                finally:
                    if initialization is not None and initialization.record['unknown_outcome']:
                        try:
                            until=time.monotonic()+5
                            while True:
                                try:initialization.reconcile(selected,absolute_deadline=until);break
                                except RunError:
                                    if time.monotonic()>=until:raise
                                    time.sleep(.2)
                            journal.event(selected,'remote-reconciled',evidence='evidence/initialization.json')
                            record['remote_resolution']='durable-terminal-result'
                        except Exception:
                            try:
                                initialization.cancel_and_confirm(selected)
                                journal.event(selected,'cancel-confirmed',evidence='evidence/initialization.json')
                                record['remote_resolution']='cancelled-confirmed-stopped'
                            except Exception as error:retain(error)
                    if ps is not None:
                        try:
                            cleaned=stage('cleanup',lambda:cleanup_session(ps,lease,helper=ready,reason='failure' if failure else 'success'))
                            record['cleanup']=cleaned
                            if cleaned['status']=='completed':lease.finish(reconciliation_complete=True)
                        except BaseException as error:retain(error)
                    elif lease.record['phase']=='reserved' and not lease.record['resources']:
                        try:
                            lease.finish(reconciliation_complete=True)
                            record['cleanup']={'status':'completed','resources_allocated':0}
                        except BaseException as error:retain(error)
                    record['unknown_outcome']=ps is not None and ps.receipt['unknown_outcome'] is True
                    record['remaining_owned_resources']=[deepcopy(item) for item in lease.record['resources'] if item['outcome']=='pending']
            require(snapshot('container',sentinel_id,unrelated=True)==baseline,'sentinel_changed')
            record['sentinel_unchanged']=True
    except BaseException as error:retain(error)
    finally:
        with run.locked():
            if journal is not None:
                if failure is not None and journal.record['terminal_outcome']!='passed':
                    for target in plan.target_ids:
                        if journal.target(target)['terminal_outcome']=='pending':
                            journal.event(target,'failure',evidence='lifecycle/controller',category=safe_code(failure))
                journal.finalize();record['lifecycle_outcome']=journal.record['terminal_outcome']
            record['status']='unknown' if record['unknown_outcome'] else 'failed' if failure else 'passed'
            record['scenario_expectation_met']=expectation_met(record,profile)
            save()
            if journal is not None:
                from .failure_reports import write
                write(run,record,journal.record)
    return record
