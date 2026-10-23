"""Explicit bounded WORM-008 acceptance; only the operator invokes real cases.

Interruption kills this harness's own coordinator child only after independently
verified terminal Terraform teardown. Cancellation is a cooperative CLI request.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from . import images
from .admission import AdmissionLease, infrastructure_status
from .provisioning import ADDRESSES, ID, ProvisioningSession, bounded_json, file_digest, resources, layout_addresses
from .provisioning_acceptance import disk_sample, scan_private_material, snapshot
from .recovery import RecoveryError, cancellation_requested, cleanup_session, recover_run, safe_code
from .targets import TargetPlan
from .runs import Run, RunError, SOURCE_ROOT, atomic_bytes, atomic_json, common, create_run, now, read_json, source_identity
from .stages import _run_process, execute_run

CASES = ('normal', 'functional-failure', 'cancelled', 'interrupted-cleanup')
CHECKPOINT = 'private/recovery-interruption-checkpoint.json'
CONTROL = 'private/recovery-acceptance-control.json'
CHILD_LOG = 'private/logs/recovery-interruption-child.log'
EXPECTED_CHECK = b'WORM-008 controlled functional check failure\n'
WORKER_OBSERVATION_SECONDS = 600


def require(value, code):
    if not value: raise RecoveryError(code, 'Recovery acceptance refused; retain private evidence and exact resource accounting.')


def _fresh(scenario):
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    with run.locked(): execute_run(run)  # Never claim the unfinished full pipeline passed.
    images.create_auth(run)
    return run


def _record(run, scenario):
    return {**common(run.manifest()), 'operation': 'real-recovery-acceptance', 'scenario': scenario,
        'status': 'running', 'checks': {}, 'created_at': now(), 'runtime_pipeline_complete': False,
        'production_iso_eligible': False}


def _persist(run, value):
    value['updated_at'] = now()
    with run.locked(): atomic_json(run.file('evidence/recovery-acceptance.json'), value)


def _finished(run):
    journal = infrastructure_status(images.INFRASTRUCTURE)['admission']
    require(journal['run_id'] == run.id and journal['source_revision'] == run.manifest()['source_revision'] and
            journal['state'] == 'finished' and all(x['outcome'] in {'absent', 'retained'} for x in journal['resources']),
            'admission_not_finished')
    return {'status': 'pass', 'finished_current_exact_run': True, 'pending_resources': 0}


def _functional_failure(session):
    target = session.target_resources['target-001']
    session.verify_target(images.inspect('container', target))
    result = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
        'exec', target, '/usr/bin/python3', '-c',
        'import sys;print("WORM-008 controlled functional check failure");sys.exit(17)'), cwd=SOURCE_ROOT, timeout=5)
    atomic_bytes(session.run.file('private/logs/recovery-functional-check.log'), result['log'], limit=65536)
    if result['status'] not in {'pass', 'fail'} or result['log_truncated']:
        session.receipt['unknown_outcome'] = True; session.save()
        raise RecoveryError('functional_check_unknown', 'The controlled check did not produce a complete terminal result.')
    require(result['status'] == 'fail' and result['returncode'] == 17 and result['log'] == EXPECTED_CHECK,
            'functional_failure_not_observed')
    session.failure(RecoveryError('controlled_functional_failure', 'The fixed negative check returned its expected failure.'))
    return {'status': 'pass', 'controlled_fixture': True, 'actual_container_exit': 17,
        'output_sha256': hashlib.sha256(result['log']).hexdigest()}


def _cancel_at_boundary(session, lease):
    from .readiness import ReadinessSession
    # The real target stays created/PID-capped; the real helper safely polls for
    # startup. The separate CLI can publish without acquiring this held run lock.
    helper = ReadinessSession(session)
    helper.start_helper()
    helper.deadline = min(helper.deadline, time.monotonic() + 10)
    observed = {'request_seen': False}
    def on_poll(_elapsed):
        if cancellation_requested(session.run):
            observed['request_seen'] = True
            raise RecoveryError('cancelled', 'The coordinator acknowledged its scoped cancellation request.')
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_run_process, (sys.executable, '-B', '-m', 'wormhole', 'cancel', session.run.id,
            '--workspace', str(images.RUNS_ROOT)), cwd=SOURCE_ROOT, timeout=5)
        caught = None
        try: helper.wait_ready(on_poll=on_poll)
        except RunError as error: caught = safe_code(error)
        result = future.result(timeout=6)
    atomic_bytes(session.run.file('private/logs/recovery-cancel-request.log'), result['log'], limit=65536)
    require(result['status'] == 'pass' and not result['log_truncated'] and caught == 'cancelled' and
            observed['request_seen'] and cancellation_requested(session.run), 'cooperative_cancel_not_observed')
    return helper, {'status': 'pass', 'separate_cli_completed_while_run_locked': True,
        'coordinator_safe_poll_acknowledged': True, 'docker_cli_killed': False}


def _case(scenario, sentinel):
    run = _fresh(scenario)
    value = _record(run, scenario)
    try:
        with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE, run.id,
                run.manifest()['source_revision'], 'smoke') as lease:
            baseline = snapshot('container', sentinel, unrelated=True)
            session = ProvisioningSession(run, lease)
            helper = None
            if scenario == 'cancelled':
                session.create_stopped()
                helper, value['checks']['cancellation'] = _cancel_at_boundary(session, lease)
            else:
                session.provision()
            value['checks']['scan_before_cleanup'] = scan_private_material(run)
            value['disk_before_cleanup'] = disk_sample(run, 'before-cleanup')
            if scenario == 'functional-failure':
                value['checks']['controlled_functional_failure'] = _functional_failure(session)
                original = lease.reconcile_resource
                injected = False
                def fail_ack(kind, identifier, **kwargs):
                    nonlocal injected
                    if not injected:
                        injected = True
                        raise RecoveryError('controlled_cleanup_failure', 'Controlled acknowledgement failure after exact positive absence.')
                    return original(kind, identifier, **kwargs)
                lease.reconcile_resource = fail_ack
                try: failed = cleanup_session(session, lease, reason='failure')
                finally: lease.reconcile_resource = original
                require(injected and failed['status'] == 'failed' and failed['unknown_outcome'] is False and
                        failed['primary_failure']['code'] == 'controlled_functional_failure' and
                        any(x['code'] == 'controlled_cleanup_failure' for x in failed['secondary_failures']), 'primary_or_secondary_failure_lost')
                value['checks']['secondary_cleanup_failure'] = {'status': 'pass', 'attempt_id': failed['attempt_id'],
                    'original_primary_retained': True, 'fault': 'owned-controller acknowledgement exception'}
            reason = 'cancelled' if scenario == 'cancelled' else 'failure' if scenario == 'functional-failure' else 'success'
            receipt = cleanup_session(session, lease, reason=reason, helper=helper)
            expected = {'normal': None, 'functional-failure': 'controlled_functional_failure', 'cancelled': 'cancelled'}[scenario]
            require(receipt['status'] == 'completed' and receipt['unknown_outcome'] is False and
                    (receipt['primary_failure'] or {}).get('code') == expected and
                    all(x['disposition'] in {'absent', 'retained'} for x in receipt['resources']), 'cleanup_or_primary_incorrect')
            require(snapshot('container', sentinel, unrelated=True) == baseline, 'sentinel_changed')
            value['checks']['cleanup'] = {'status': 'pass', 'primary_failure': expected,
                'terraform_state_retained': receipt['terraform_state_retained'], 'unrelated_sentinel_unchanged': True}
            value['checks']['scan_after_cleanup'] = scan_private_material(run)
            lease.finish(reconciliation_complete=True)
            value['checks']['admission_finished'] = _finished(run)
            value['status'] = 'pass'
    except BaseException as error:
        value.update(status='fail', error={'code': safe_code(error)}, cleanup_claimed=False)
        error.run_id = run.id
        raise
    finally:
        try: _persist(run, value)
        except Exception:
            if value['status'] == 'pass': raise
    return value


def _worker(run):
    control = read_json(run.file(CONTROL))
    revision, dirty = source_identity()
    require(control == {**common(run.manifest()), 'operation': 'owned-teardown-interruption'} and
            revision == control['source_revision'] and not dirty, 'worker_scope')
    with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE, run.id, revision, 'smoke') as lease:
        session = ProvisioningSession(run, lease)
        session.provision()
        session.failure(RecoveryError('controlled_teardown_interruption', 'Declared coordinator-termination acceptance fault.'))
        def pause_ack(_kind, _identifier, **_kwargs):
            require(session.receipt['unknown_outcome'] is False and
                    session.receipt.get('cleanup_progress', {}).get('terraform_final_state_empty') is True,
                    'checkpoint_not_terminal')
            require(all(images.inspect('container' if address.startswith('docker_container.') else 'network', identifier,
                    missing=True) is None for address, identifier in session.owned.items()), 'checkpoint_resources_remain')
            atomic_json(run.file(CHECKPOINT), {**common(run.manifest()), 'operation': 'known-terminal-destroy-before-journal',
                'worker_pid': os.getpid(), 'provisioner_id': session.provisioner, 'owned': deepcopy(session.owned), 'created_at': now()})
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline: time.sleep(.05)
            raise RecoveryError('parent_did_not_interrupt', 'The controlled coordinator termination was not observed.')
        lease.reconcile_resource = pause_ack
        result = cleanup_session(session, lease, reason='failure')
        require(False, 'interruption_not_observed')  # Never finalize this admission in the child.


def _checkpoint_proof(run, worker_pid):
    checkpoint = read_json(run.file(CHECKPOINT))
    context = read_json(run.file('private/terraform/controller.json'))
    target_plan = TargetPlan.from_record(context['target_plan']) if context.get('resource_layout') == 'indexed-targets-v1' else None
    require(target_plan is None or target_plan.profile == run.manifest()['profile'], 'checkpoint_identity')
    require(common(checkpoint) == common(run.manifest()) and checkpoint.get('operation') == 'known-terminal-destroy-before-journal' and
            type(checkpoint.get('worker_pid')) is int and checkpoint['worker_pid'] == worker_pid and
            type(checkpoint.get('owned')) is dict and set(checkpoint['owned']) == layout_addresses(target_plan),
            'invalid_interruption_checkpoint')
    receipt = read_json(run.file('evidence/provisioning.json'))
    require(common(receipt) == common(run.manifest()) and receipt['unknown_outcome'] is False and
            receipt.get('cleanup_progress', {}).get('terraform_final_state_empty') is True and
            {x['address']: x['id'] for x in receipt['resources']} == checkpoint['owned'] and
            receipt.get('provisioner_id') == checkpoint['provisioner_id'], 'checkpoint_receipt_mismatch')
    mutations = [x for x in receipt['operations'] if x['operation'] in {'apply', 'refresh-apply', 'destroy'}]
    finals = [x for x in receipt['operations'] if x['operation'] == 'final-state']
    require(mutations and mutations[-1]['operation'] == 'destroy' and finals, 'checkpoint_not_terminal')
    for record in (mutations[-1], finals[-1]):
        require(record['passed'] is True and record['returncode'] == 0 and record.get('client_status') == 'pass' and
                record.get('client_returncode') == 0 and record.get('client_log_truncated') is False and
                record['timed_out'] is False and record['truncated'] is False, 'checkpoint_result_incomplete')
        stem = run.file('private/terraform/operations/' + record['operation'] + '-' + str(record['attempt']))
        digest, size = file_digest(stem.with_suffix('.out'))
        require(digest == record['output_sha256'] and size == record['output_bytes'] and
                read_json(stem.with_suffix('.json')) == {key: item for key, item in record.items()
                    if key not in {'client_status', 'client_returncode', 'client_log_truncated', 'evidence'}}, 'checkpoint_capture_changed')
    require(not resources(bounded_json(stem.with_suffix('.out')), target_plan), 'checkpoint_state_not_empty')
    for address, identifier in checkpoint['owned'].items():
        require(type(identifier) is str and ID.fullmatch(identifier) and images.inspect(
            'container' if address.startswith('docker_container.') else 'network', identifier, missing=True) is None,
            'checkpoint_resources_remain')
    journal = infrastructure_status(images.INFRASTRUCTURE)['admission']
    expected = {('container', checkpoint['provisioner_id'])} | {
        ('container' if address.startswith('docker_container.') else 'network', identifier)
        for address, identifier in checkpoint['owned'].items()}
    require(journal['run_id'] == run.id and journal['source_revision'] == checkpoint['source_revision'] and
            {(x['kind'], x['id']) for x in journal['resources'] if x['outcome'] == 'pending'} == expected,
            'checkpoint_journal_mismatch')
    return {'status': 'pass', 'known_successful_saved_destroy': True, 'empty_bound_final_state': True,
        'exact_resources_absent_before_journal_ack': True, 'checkpoint_sha256': file_digest(run.file(CHECKPOINT))[0]}


def _interrupt_owned_worker(process, run):
    require(process.poll() is None, 'worker_exited_before_interruption')
    require(run.file(CHILD_LOG).stat().st_size <= 65536, 'worker_output_bound')
    proof = _checkpoint_proof(run, process.pid)
    process.kill()  # This Popen handle was created here; never construct a handle from a stored PID.
    require(process.wait(timeout=5) == -signal.SIGKILL, 'owned_worker_not_terminated')
    return {**proof, 'owned_coordinator_terminated': True, 'docker_cli_killed': False}


def _interrupted_case(sentinel):
    run = _fresh('interrupted-cleanup'); value = _record(run, 'interrupted-cleanup')
    process = None
    try:
        with run.locked(): atomic_json(run.file(CONTROL), {**common(run.manifest()), 'operation': 'owned-teardown-interruption'})
        with images.docker_scope(run):
            baseline = snapshot('container', sentinel, unrelated=True)
            descriptor = os.open(run.file(CHILD_LOG), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                process = subprocess.Popen((sys.executable, '-B', '-m', 'wormhole.recovery_acceptance', '--worker-run', run.id),
                    cwd=SOURCE_ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                    env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
                         'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}, close_fds=True)
            deadline = time.monotonic() + WORKER_OBSERVATION_SECONDS
            while not run.file(CHECKPOINT).exists():
                require(process.poll() is None, 'worker_failed_before_checkpoint')
                require(time.monotonic() < deadline and run.file(CHILD_LOG).stat().st_size <= 65536, 'worker_observation_bound')
                time.sleep(.05)
            value['checks']['interruption'] = _interrupt_owned_worker(process, run)
            receipt = recover_run(run)
            require(receipt['status'] == 'completed' and receipt['unknown_outcome'] is False and
                    receipt['primary_failure']['code'] == 'controlled_teardown_interruption', 'normal_recovery_failed')
            require(snapshot('container', sentinel, unrelated=True) == baseline, 'sentinel_changed')
            value['checks']['cleanup'] = {'status': 'pass', 'normal_exact_source_recovery': True,
                'unrelated_sentinel_unchanged': True, 'original_primary_retained': True}
            value['checks']['credential_scan'] = scan_private_material(run)
            value['checks']['admission_finished'] = _finished(run)
            value['status'] = 'pass'
    except BaseException as error:
        value.update(status='fail', error={'code': safe_code(error)}, cleanup_claimed=False)
        # Never kill an uncheckpointed child and call remote Terraform stopped.
        # Its existing finite adapters/TTLs and durable journal remain authoritative.
        if process is not None: value['owned_worker_still_running'] = process.poll() is None
        error.run_id = run.id
        raise
    finally:
        try: _persist(run, value)
        except Exception:
            if value['status'] == 'pass': raise
    return value


def qualify_case(scenario, sentinel):
    require(sys.platform.startswith('linux') and scenario in CASES, 'unsupported_acceptance_case')
    require(type(sentinel) is str and ID.fullmatch(sentinel), 'invalid_sentinel_id')
    require(source_identity()[1] is False, 'source_dirty')
    return _interrupted_case(sentinel) if scenario == 'interrupted-cleanup' else _case(scenario, sentinel)


def acceptance(sentinel):
    revision, dirty = source_identity(); require(not dirty, 'source_dirty')
    cases = []
    for scenario in CASES:
        require(source_identity() == (revision, False), 'source_changed')
        case = qualify_case(scenario, sentinel)
        require(case['source_revision'] == revision and case['source_dirty'] is False and case['status'] == 'pass' and
                source_identity() == (revision, False), 'source_changed')
        cases.append(case)
    require(len({x['run_id'] for x in cases}) == len(CASES), 'run_id_reused')
    return {'schema_version': '1.0', 'operation': 'recovery-acceptance-suite', 'source_revision': revision,
        'status': 'pass', 'cases': cases, 'existing_sentinel_modified': False,
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Explicit real scoped recovery acceptance; no production qualification.')
    parser.add_argument('--sentinel-id')
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--worker-run', help=argparse.SUPPRESS)
    options = parser.parse_args(arguments)
    try:
        if options.worker_run is not None:
            require(sys.platform.startswith('linux') and options.sentinel_id is None and options.case is None, 'worker_scope')
            _worker(Run(images.RUNS_ROOT, options.worker_run))
            return 2
        value = qualify_case(options.case, options.sentinel_id) if options.case else acceptance(options.sentinel_id)
        print(json.dumps(value, sort_keys=True, indent=2)); return 0
    except Exception as error:
        print(json.dumps({'status': 'fail', 'error': {'code': safe_code(error), 'run_id': getattr(error, 'run_id', options.worker_run)},
            'message': 'Acceptance stopped; preserve private state, active admission and unresolved owned resources.',
            'runtime_pipeline_complete': False, 'production_iso_eligible': False})); return 2


if __name__ == '__main__': raise SystemExit(main())
