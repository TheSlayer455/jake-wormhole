"""Explicit fresh smoke/five-target qualification; never a full-pipeline gate."""
import argparse
from copy import deepcopy
import hashlib
import json
import re
import sys
import time

from . import images
from .admission import AdmissionLease
from .fleet_readiness import BatchReadinessSession
from .fleet_validation import BatchValidationSession, report_batch_validation
from .provisioning import ID, ProvisioningSession
from .provisioning_acceptance import disk_sample, scan_private_material, snapshot
from .readiness import ReadinessError
from .recovery import cleanup_session
from .runs import RunError, atomic_json, common, create_run, now, read_json, source_identity
from .stages import execute_run
from .validation import ValidationError

CASES = ('healthy', 'delayed-start', 'never-starts', 'wrong-key', 'wrong-user',
    'configured-interpreter-unavailable', 'wrong-endpoint', 'wrong-network', 'changed-host-key',
    'validation-interpreter-unavailable')
READINESS_FAILURES = {'never-starts': 'target_not_started', 'wrong-key': 'ssh_key_rejected',
    'wrong-user': 'ssh_user_rejected', 'configured-interpreter-unavailable': 'configured_interpreter_unavailable',
    'wrong-endpoint': 'inventory_endpoint_mismatch', 'wrong-network': 'inventory_network_mismatch',
    'changed-host-key': 'ssh_host_key_mismatch'}
PROFILES = ('smoke', 'five-targets')


def require(value, code):
    if not value:
        raise RunError(code, 'Fleet acceptance failed; retain bounded private evidence and exact resource accounting.')


def safe_code(error):
    code = getattr(error, 'code', 'fleet_acceptance_failed')
    return code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', code) else 'fleet_acceptance_failed'


def retain_failure(session, error):
    previous = session.receipt.get('primary_failure')
    if previous is None or previous.get('code') != safe_code(error):
        session.failure(error)


def restart_owned_target(session, target_id):
    """One fixed fixture restart; no replacement, new endpoint or trust update."""
    session.held(allocating=True)
    target_id = session.target_plan.resolve(target_id)
    target = session.target_resources[target_id]
    require(session.receipt['unknown_outcome'] is False, 'daemon_outcome_unknown')
    before = images.inspect('container', target, timeout=10)
    session.verify_target(before, target_id=target_id, inspection_timeout=10)
    require(before['State']['Running'] is True and before['State']['Pid'] > 0, 'target_not_running')
    session.receipt['unknown_outcome'] = True; session.save()
    images.docker(('stop', '--time', '2', target), timeout=10)
    stopped = images.inspect('container', target, timeout=10)
    session.verify_owned(stopped, 'target', target, target_id=target_id)
    session.verify_limits(stopped, 'target', stopped=True)
    require(stopped['State']['Running'] is False and stopped['State']['Pid'] == 0 and
        stopped['State']['Status'] == 'exited' and not stopped['State'].get('Paused', False) and
        not stopped['State'].get('Restarting', False), 'restart_stop_unverified')
    session.receipt['unknown_outcome'] = False; session.save()
    session.lease.refresh()
    session.receipt['unknown_outcome'] = True; session.save()
    images.docker(('start', target), timeout=10)
    live = images.inspect('container', target, timeout=10)
    session.verify_target(live, target_id=target_id, inspection_timeout=10)
    require(live['State']['Running'] is True and live['State']['Pid'] > 0 and
        live['State']['StartedAt'] != before['State']['StartedAt'], 'restart_start_unverified')
    session.receipt['targets_started'][target_id] = {'started_at': live['State']['StartedAt'],
        'cgroups': images.cgroup_limits(live['State']['Pid'], session.lease.plan['limits']['target']['docker_create'])}
    session.receipt['unknown_outcome'] = False; session.save()
    session.refresh_inventory()
    return {'target_id': target_id, 'resource_id': target, 'actual_stopped_pid_zero': True,
        'actual_started_at_changed': True, 'original_pin_retained': True}


def rotate_hostkey(session, readiness, target_id):
    original_deadline = readiness.deadline
    readiness.deadline = deadline = min(original_deadline, time.monotonic() + 20)
    try:
        while not readiness.pin_trust(target_id):
            require(time.monotonic() < deadline, 'original_hostkey_unavailable')
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
        original_pin = readiness.target_state(target_id)['hostkey_fingerprint']
        restart = restart_owned_target(session, target_id)
        while time.monotonic() < deadline:
            try:
                observed = readiness.observe_hostkey(target_id)
            except images.ImageError as error:
                if error.code != 'qualification_attempt_failed': raise
            else:
                if observed['matches_original_pin'] is False:
                    require(observed['fingerprint'] != original_pin and
                        readiness.target_state(target_id)['hostkey_fingerprint'] == original_pin, 'hostkey_did_not_change')
                    return {**restart, 'new_public_identity_observed': True}
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
    finally:
        readiness.deadline = original_deadline
    raise RunError('rotated_hostkey_unavailable', 'The exact owned target did not produce its new public key within the window.')


def wait_case(session, readiness, scenario, selected):
    """Controlled expected-input negatives never modify networking or TF state."""
    original_inventory = deepcopy(session.receipt['inventory'])
    view = readiness._states[selected]['provisioning']
    original_expected_network = view.expected_network_id
    delay = {'invoked': False, 'elapsed_seconds': None}
    if scenario == 'wrong-endpoint':
        row = next(item for item in session.receipt['inventory']['targets'] if item['target_id'] == selected)
        row['host'] = '127.0.0.1'  # Rejected against the exact endpoint before any foreign contact.
    elif scenario == 'wrong-network':
        wrong = hashlib.sha256(('WORM-010 expected network:' + session.run.id).encode()).hexdigest()
        require(wrong != original_expected_network, 'negative_identity_collision')
        view.expected_network_id = wrong  # Expected identity only; no network attachment/change.

    def on_poll(elapsed):
        if scenario == 'delayed-start' and elapsed >= 2 and not delay['invoked']:
            delay.update(invoked=True, elapsed_seconds=elapsed)
            session.start_and_inventory([selected])

    observed = None
    try:
        readiness.wait_ready(on_poll=on_poll)
    except ReadinessError as error:
        observed = error.code
    finally:
        if scenario in {'wrong-endpoint', 'wrong-network'}:
            session.receipt['inventory'] = original_inventory
            view.expected_network_id = original_expected_network
            session.save(); readiness.save()  # Restore expected metadata only; retain the failed observation.
    require(observed == READINESS_FAILURES.get(scenario), 'unexpected_readiness_outcome')
    return observed, delay


def check_grid(run, validation, planned, profile, scenario, selected, readiness):
    require(validation.plan == planned and read_json(run.file('evidence/batch-validation-plan.json')) == planned,
        'functional_plan_changed')
    result = validation.receipt
    declared = {(item['target_id'], item['check_id']) for item in planned['checks']}
    actual = {(item['target_id'], item['check_id']) for item in result['checks']}
    require(actual == declared and len(result['checks']) == len(declared) == (10 if profile == 'smoke' else 50),
        'functional_result_incomplete')
    report = report_batch_validation(run)
    require(report['result'] == result and all(item['target_id'] + ' / ' + item['check_id'] + ': ' + item['status'] in
        report['text'] for item in result['checks']), 'functional_report_disagrees')
    if scenario == 'validation-interpreter-unavailable':
        observations = read_json(run.file('evidence/batch-validation-observations.json'))
        negative = next(item for item in observations['targets'] if item['target_id'] == selected)
        require(negative['source'] == 'ansible' and negative['status'] == 'fail' and
            negative['category'] == 'configured_interpreter_unavailable' and negative['observation'] is None,
            'mixed_ansible_fault_not_observed')
    by_target = {}
    for target in planned['target_plan']['target_ids']:
        rows = [item for item in result['checks'] if item['target_id'] == target]
        state = readiness.target_state(target)
        require(len(rows) == 10 and all(item['required'] is True for item in rows), 'functional_result_incomplete')
        bad = scenario in READINESS_FAILURES or scenario == 'validation-interpreter-unavailable'
        expect_pass = not bad or target != selected
        require(all(item['status'] == 'pass' for item in rows) if expect_pass else all(item['status'] != 'pass' for item in rows),
            'target_result_disagrees')
        if scenario in READINESS_FAILURES and target == selected:
            require(state['primary_failure']['code'] == READINESS_FAILURES[scenario] and
                result['blocked_targets'] == {selected: READINESS_FAILURES[scenario]} and
                target not in result['attempted_targets'] and all(item['status'] == 'unverified' for item in rows), 'readiness_block_not_retained')
        else:
            require(state['status'] == 'ready' and state['primary_failure'] is None and
                target in result['attempted_targets'], 'ready_target_not_measured')
        by_target[target] = {'resource_id': planned['target_resource_ids'][target], 'readiness': state['status'],
            'readiness_failure': deepcopy(state['primary_failure']), 'passed_rows': sum(item['status'] == 'pass' for item in rows),
            'required_rows': len(rows), 'transition_ids': [item['check_id'] for item in state['transitions']],
            'probe_results': [{'operation': item['operation'], 'status': item['status'], 'category': item['category']} for item in state['probes']],
            'private_attempt_logs': [item['private_log'] for item in state['attempts']]}
    return {'status': 'pass', 'underlying_status': result['status'], 'required_rows': len(result['checks']),
        'expected_targets': planned['target_plan']['target_count'], 'configured_ansible_forks': planned['controller_concurrency'],
        'attempted_targets': deepcopy(result['attempted_targets']), 'blocked_targets': deepcopy(result['blocked_targets']),
        'plan_sha256': planned['plan_sha256'], 'targets': by_target, 'readable_structured_agreement': True,
        'row_evidence': 'evidence/batch-validation.json', 'capture_bound': result['capture'] is not None and result['capture']['complete']}


def cleanup_case(run, value, session, lease, readiness, unexpected, expected_failure):
    try:
        value['checks']['credential_scan_before_cleanup'] = scan_private_material(run)
        value['disk_samples'].append(disk_sample(run, 'before-fleet-cleanup'))
    except BaseException as error:
        retain_failure(session, error)
        value['checks']['pre_cleanup_observation_error'] = {'code': safe_code(error)}
        if unexpected is None: unexpected = error
    cleanup = cleanup_session(session, lease, reason='failure' if unexpected is not None or expected_failure else 'success', helper=readiness)
    value['checks']['cleanup'] = {'status': cleanup['status'], 'primary_failure': deepcopy(cleanup['primary_failure']),
        'secondary_failures': deepcopy(cleanup['secondary_failures']), 'unknown_outcome': cleanup['unknown_outcome'],
        'terraform_state_retained': cleanup['terraform_state_retained']}
    return cleanup, unexpected


def qualify_case(profile, scenario, sentinel):
    require(profile in PROFILES, 'unsupported_acceptance_profile')
    require(scenario in CASES and (profile != 'smoke' or scenario == 'healthy'), 'unsupported_acceptance_case')
    require(type(sentinel) is str and ID.fullmatch(sentinel) is not None, 'invalid_sentinel')
    require(sys.platform.startswith('linux'), 'linux_required')
    revision, dirty = source_identity(); require(not dirty, 'source_dirty')
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True, profile=profile)
    value = {**common(run.manifest()), 'operation': 'real-fleet-acceptance', 'profile': profile, 'scenario': scenario,
        'status': 'running', 'checks': {}, 'disk_samples': [], 'created_at': now(), 'cleanup_claimed': False,
        'negative_kind': 'configured validation interpreter path; actual Ansible attempt' if scenario == 'validation-interpreter-unavailable' else
            'configured readiness interpreter path; not package removal' if scenario == 'configured-interpreter-unavailable' else
            'expected inventory/network input; no foreign contact' if scenario in {'wrong-endpoint', 'wrong-network'} else scenario,
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    try:
        with run.locked(): execute_run(run)  # Unsupported whole-pipeline outcome remains separate.
        images.create_auth(run)
        with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE, run.id, revision, profile) as lease:
            baseline = snapshot('container', sentinel, unrelated=True)
            session = ProvisioningSession(run, lease)
            readiness, validation, unexpected = None, None, None
            expected_primary = READINESS_FAILURES.get(scenario)
            if scenario == 'validation-interpreter-unavailable': expected_primary = 'required_batch_check_failed'
            try:
                session.create_stopped()
                selected = session.target_plan.target_ids[-1]
                initial = [target for target in session.target_plan.target_ids if target != selected] if scenario in {'delayed-start', 'never-starts'} else list(session.target_plan.target_ids)
                session.start_and_inventory(initial)
                if scenario in {'delayed-start', 'never-starts'}:
                    require(session.target_inventory(selected) is None and session.receipt['inventory']['status'] == 'unverified', 'pending_endpoint_fabricated')
                    value['checks']['pending_endpoint'] = {'status': 'pass', 'target_id': selected, 'provider_endpoint_absent': True}
                configured = {selected: scenario} if scenario in {'wrong-key', 'wrong-user', 'configured-interpreter-unavailable'} else {}
                readiness = BatchReadinessSession(session, scenarios=configured)
                readiness.start_helper()
                validation = BatchValidationSession(readiness, scenarios={selected: 'configured-interpreter-unavailable'} if
                    scenario == 'validation-interpreter-unavailable' else {})
                planned = deepcopy(validation.plan)
                require(planned['controller_concurrency'] == (1 if profile == 'smoke' else 2), 'concurrency_plan_changed')
                value['owned_resource_ids'] = sorted([*session.target_resources.values(), session.network_id, session.provisioner, readiness.helper])
                require(sentinel not in value['owned_resource_ids'] and len(set(value['owned_resource_ids'])) == len(value['owned_resource_ids']), 'sentinel_is_owned')
                value['disk_samples'].append(disk_sample(run, 'after-fleet-provision'))
                if scenario == 'changed-host-key': value['checks']['hostkey_rotation'] = {'status': 'pass', **rotate_hostkey(session, readiness, selected)}
                observed, delay = wait_case(session, readiness, scenario, selected)
                if observed is not None:
                    retain_failure(session, ReadinessError(observed, 'Controlled exact-target readiness negative.'))
                    blocked = False
                    try: readiness.require_ready(selected)
                    except ReadinessError: blocked = True
                    require(blocked, 'dependent_check_not_blocked')
                if scenario == 'delayed-start':
                    require(delay['invoked'] and delay['elapsed_seconds'] >= 2, 'delay_not_exercised')
                    value['checks']['delayed_start'] = {'status': 'pass', **delay}
                validation_error = None
                try: validation.validate(diagnostic_subset=scenario in READINESS_FAILURES)
                except ValidationError as error: validation_error = error.code
                expected_validation = 'required_batch_check_failed' if expected_primary else None
                require(validation_error == expected_validation, 'unexpected_validation_outcome')
                if expected_validation is None: validation.require_passed()
                else:
                    blocked = False
                    try: validation.require_passed()
                    except ValidationError: blocked = True
                    require(blocked and validation.receipt['status'] == 'failed', 'failed_functional_check_accepted')
                value['checks']['functional'] = check_grid(run, validation, planned, profile, scenario, selected, readiness)
                if scenario == 'validation-interpreter-unavailable':
                    require(not validation.receipt['blocked_targets'] and len(validation.receipt['attempted_targets']) == 5,
                        'mixed_ansible_attempt_incomplete')
                require(not readiness.receipt['unknown_outcome'] and not session.receipt['unknown_outcome'], 'unresolved_operation')
            except BaseException as error:
                unexpected = error; retain_failure(session, error)
            cleanup, unexpected = cleanup_case(run, value, session, lease, readiness, unexpected, expected_primary)
            if cleanup['status'] == 'completed':
                unchanged = snapshot('container', sentinel, unrelated=True) == baseline
                lease.finish(reconciliation_complete=True)
                value['cleanup_claimed'] = True
                value['checks']['cleanup']['unrelated_sentinel_unchanged'] = unchanged
                value['checks']['credential_scan_after_cleanup'] = scan_private_material(run)
                value['disk_samples'].append(disk_sample(run, 'after-fleet-cleanup'))
                require(unchanged, 'sentinel_changed')
            if unexpected is not None: raise unexpected
            require(cleanup['status'] == 'completed' and not cleanup['unknown_outcome'] and
                (cleanup['primary_failure'] or {}).get('code') == expected_primary, 'cleanup_or_primary_changed')
            value['status'] = 'pass'
    except BaseException as error:
        value.update(status='fail', error={'code': safe_code(error)})
        error.run_id = run.id
        raise
    finally:
        value['updated_at'] = now()
        try:
            with run.locked(): atomic_json(run.file('evidence/fleet-acceptance.json'), value)
        except Exception:
            if value['status'] == 'pass': raise
    return value


def acceptance(profile, sentinel, scenarios=('healthy',)):
    require(profile in PROFILES, 'unsupported_acceptance_profile')
    require(type(sentinel) is str and ID.fullmatch(sentinel) is not None, 'invalid_sentinel')
    require(type(scenarios) is tuple and 1 <= len(scenarios) <= len(CASES) and len(set(scenarios)) == len(scenarios) and
        all(case in CASES for case in scenarios) and (profile != 'smoke' or scenarios == ('healthy',)), 'unsupported_acceptance_case')
    revision, dirty = source_identity(); require(not dirty, 'source_dirty')
    cases, run_ids, runtime_ids = [], set(), set()
    for scenario in scenarios:
        require(source_identity() == (revision, False), 'source_changed')
        case = qualify_case(profile, scenario, sentinel)
        require(case['source_revision'] == revision and case['source_dirty'] is False and case['status'] == 'pass' and
            source_identity() == (revision, False), 'source_changed')
        require(case['run_id'] not in run_ids and not set(case['owned_resource_ids']) & runtime_ids, 'run_identity_reused')
        run_ids.add(case['run_id']); runtime_ids.update(case['owned_resource_ids']); cases.append(case)
    return {'schema_version': '1.0', 'operation': 'fleet-acceptance-suite', 'profile': profile, 'source_revision': revision,
        'status': 'pass', 'cases': cases, 'existing_sentinel_modified': False,
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Real smoke/five-target SSH/Ansible acceptance, not a full-pipeline gate.')
    parser.add_argument('--profile', choices=PROFILES, default='smoke')
    parser.add_argument('--scenario', choices=(*CASES, 'all'), default='healthy')
    parser.add_argument('--sentinel-id', required=True)
    options = parser.parse_args(arguments)
    try:
        value = acceptance(options.profile, options.sentinel_id, CASES if options.scenario == 'all' else (options.scenario,))
        print(json.dumps(value, sort_keys=True, indent=2)); return 0
    except Exception as error:
        print(json.dumps({'status': 'fail', 'error': {'code': safe_code(error), 'run_id': getattr(error, 'run_id', None)},
            'runtime_pipeline_complete': False, 'production_iso_eligible': False})); return 2


if __name__ == '__main__': raise SystemExit(main())
