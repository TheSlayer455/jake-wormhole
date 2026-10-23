"""Explicit real one-target functional qualification; the full pipeline is unfinished."""
import argparse
from copy import deepcopy
import json
import sys

from . import images
from .admission import AdmissionLease
from .provisioning import ID, ProvisioningSession
from .provisioning_acceptance import disk_sample, scan_private_material, snapshot
from .recovery import cleanup_session
from .runs import RunError, atomic_json, common, create_run, now, read_json, source_identity
from .stages import execute_run

CASES = ('healthy', 'version-expectation-mismatch', 'functional-expectation-mismatch',
         'configured-interpreter-unavailable', 'unexpected-skip', 'unreachable')
EXPECTED_FAILURE = {'version-expectation-mismatch': 'required_check_mismatch',
    'functional-expectation-mismatch': 'required_check_mismatch',
    'configured-interpreter-unavailable': 'configured_interpreter_unavailable',
    'unexpected-skip': 'unexpected_skip', 'unreachable': 'ansible_unreachable'}


def require(value, code):
    if not value:
        raise RunError(code, 'Functional acceptance failed; retain primary evidence and resource accounting.')


def retain_failure(session, error):
    prior = session.receipt.get('primary_failure')
    if prior is None or prior.get('code') != getattr(error, 'code', None):
        session.failure(error)


def cleanup_with_observations(run, value, session, lease, readiness, *, prior_error=None, failed=False):
    """A known diagnostic failure cannot skip the normal scoped cleanup policy."""
    try:
        value['checks']['credential_scan_before_cleanup'] = scan_private_material(run)
        value['disk_sample'] = disk_sample(run, 'before-functional-cleanup')
    except BaseException as error:
        retain_failure(session, error)
        value['checks']['pre_cleanup_observation_error'] = {'code': getattr(error, 'code', 'diagnostic_failed')}
        if prior_error is None:
            prior_error = error
    receipt = cleanup_session(session, lease,
        reason='failure' if prior_error is not None or failed else 'success', helper=readiness)
    return receipt, prior_error


def stop_owned_target(session):
    """One fixed owned-target stop after successful readiness, before SSH validation."""
    session.held()
    require(session.receipt['unknown_outcome'] is False, 'daemon_outcome_unknown')
    targets = session.target_resources
    require(type(targets) is dict and set(targets) == {'target-001'}, 'single_target_required')
    target = targets['target-001']
    before = images.inspect('container', target)
    session.verify_target(before)
    require(before['State']['Running'] is True and before['State']['Pid'] > 0, 'target_not_running')
    session.receipt['unknown_outcome'] = True
    session.save()
    images.docker(('stop', '--time', '2', target), timeout=10)
    stopped = images.inspect('container', target, timeout=10)
    session.verify_owned(stopped, 'target', target)
    session.verify_limits(stopped, 'target', stopped=True)
    require(stopped['State']['Running'] is False and stopped['State']['Pid'] == 0 and
            stopped['State']['Status'] == 'exited' and not stopped['State'].get('Paused', False) and
            not stopped['State'].get('Restarting', False), 'target_stop_unverified')
    session.receipt['unknown_outcome'] = False
    session.save()
    return {'status': 'pass', 'exact_target_resource_id': target, 'stopped_pid_zero': True,
            'previous_provider_endpoint_retained': True, 'new_endpoint_selected': False}


def qualify_case(scenario, sentinel):
    require(scenario in CASES, 'unsupported_acceptance_case')
    require(type(sentinel) is str and ID.fullmatch(sentinel) is not None, 'invalid_sentinel')
    require(sys.platform.startswith('linux'), 'linux_required')
    from .readiness import ReadinessSession
    from .validation import ValidationError, ValidationSession, report_validation
    revision, dirty = source_identity()
    require(not dirty, 'source_dirty')
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    value = {**common(run.manifest()), 'operation': 'real-functional-acceptance', 'scenario': scenario,
        'status': 'running', 'checks': {}, 'created_at': now(), 'runtime_pipeline_complete': False,
        'production_iso_eligible': False}
    try:
        with run.locked():
            execute_run(run)  # Keep the unsupported whole-pipeline outcome separate.
        images.create_auth(run)
        with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE, run.id,
                revision, 'smoke') as lease:
            baseline = snapshot('container', sentinel, unrelated=True)
            provisioning = ProvisioningSession(run, lease)
            readiness, validation, unexpected = None, None, None
            observed = None
            try:
                provisioning.provision()
                readiness = ReadinessSession(provisioning, validation=True)
                readiness.start_helper()
                # Freeze every expected check before any validation probe runs.
                validation = ValidationSession(readiness, scenario=scenario)
                planned = deepcopy(validation.plan)
                require(len(planned['checks']) == 10 and all(x['required'] for x in planned['checks']),
                        'functional_plan_incomplete')
                readiness.wait_ready()
                value['checks']['actual_readiness'] = {'status': 'pass',
                    'transitions': deepcopy(readiness.receipt['transitions'])}

                def before_probe():
                    value['checks']['unreachable_injection'] = stop_owned_target(provisioning)

                try:
                    validation.validate(before_probe=before_probe if scenario == 'unreachable' else None)
                except ValidationError as error:
                    observed = error.code
                expected = EXPECTED_FAILURE.get(scenario)
                require(observed == expected, 'unexpected_validation_outcome')
                require(validation.plan == planned and read_json(run.file('evidence/validation-plan.json')) == planned,
                        'functional_plan_changed')
                receipt = validation.receipt
                actual = {(x['target_id'], x['check_id']) for x in receipt['checks']}
                declared = {(x['target_id'], x['check_id']) for x in planned['checks']}
                require(actual == declared and len(receipt['checks']) == len(declared), 'functional_result_incomplete')
                report = report_validation(run)
                require(report['result'] == receipt and all(x['check_id'] in report['text'] for x in receipt['checks']),
                        'functional_report_disagrees')
                if expected is None:
                    validation.require_passed()
                    require(receipt['status'] == 'passed' and receipt['primary_failure'] is None and
                        all(x['status'] == 'pass' for x in receipt['checks']), 'functional_checks_not_passed')
                else:
                    blocked = False
                    try:
                        validation.require_passed()
                    except ValidationError:
                        blocked = True
                    require(blocked and receipt['status'] == 'failed' and
                        receipt['primary_failure']['code'] == expected and
                        any(x['status'] != 'pass' for x in receipt['checks']), 'failed_functional_check_accepted')
                    if provisioning.receipt['primary_failure'] is None:
                        provisioning.failure(ValidationError(expected, 'Controlled actual validation negative.'))
                # Functional failure must not rewrite earlier successful readiness.
                require(readiness.receipt['status'] == 'ready' and readiness.receipt['primary_failure'] is None,
                        'readiness_history_changed')
                value['checks']['functional'] = {'status': 'pass', 'underlying_status': receipt['status'],
                    'expected_failure': expected, 'observed_failure': observed, 'required_rows': len(receipt['checks']),
                    'plan_sha256': planned['plan_sha256'], 'candidate_binding': planned['candidate_binding'],
                    'negative_kind': planned['negative_kind'], 'records': deepcopy(receipt['checks']),
                    'readable_structured_agreement': True, 'attempts': deepcopy(receipt['attempts'])}
            except BaseException as error:
                unexpected = error
                retain_failure(provisioning, error)

            cleanup, unexpected = cleanup_with_observations(run, value, provisioning, lease, readiness,
                prior_error=unexpected, failed=observed is not None)
            value['checks']['cleanup'] = {'status': cleanup['status'],
                'primary_failure': deepcopy(cleanup['primary_failure']),
                'secondary_failures': deepcopy(cleanup['secondary_failures']),
                'terraform_state_retained': cleanup['terraform_state_retained']}
            if cleanup['status'] == 'completed':
                unchanged = snapshot('container', sentinel, unrelated=True) == baseline
                lease.finish(reconciliation_complete=True)
                value['checks']['cleanup']['unrelated_sentinel_unchanged'] = unchanged
                value['checks']['credential_scan_after_cleanup'] = scan_private_material(run)
                require(unchanged, 'sentinel_changed')
            if unexpected is not None:
                raise unexpected
            require(cleanup['status'] == 'completed' and not cleanup['unknown_outcome'] and
                (cleanup['primary_failure'] or {}).get('code') == EXPECTED_FAILURE.get(scenario), 'cleanup_or_primary_changed')
            value['status'] = 'pass'
    except BaseException as error:
        value.update(status='fail', error={'code': getattr(error, 'code', 'functional_acceptance_failed')})
        error.run_id = run.id
        raise
    finally:
        value['updated_at'] = now()
        try:
            with run.locked():
                atomic_json(run.file('evidence/validation-acceptance.json'), value)
        except Exception:
            if value['status'] == 'pass':
                raise
    return value


def acceptance(sentinel, scenarios=CASES):
    require(type(scenarios) is tuple and 1 <= len(scenarios) <= len(CASES) and
            len(set(scenarios)) == len(scenarios) and all(x in CASES for x in scenarios), 'unsupported_acceptance_case')
    revision, dirty = source_identity()
    require(not dirty, 'source_dirty')
    cases = []
    for scenario in scenarios:
        require(source_identity() == (revision, False), 'source_changed')
        case = qualify_case(scenario, sentinel)
        require(case['source_revision'] == revision and case['source_dirty'] is False and
                case['status'] == 'pass' and source_identity() == (revision, False), 'source_changed')
        cases.append(case)
    require(len({x['run_id'] for x in cases}) == len(cases), 'run_id_reused')
    return {'schema_version': '1.0', 'operation': 'functional-acceptance-suite', 'source_revision': revision,
        'status': 'pass', 'cases': cases, 'existing_sentinel_modified': False,
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Actual one-target SSH/Ansible functional qualification, not a complete pipeline.')
    parser.add_argument('--scenario', choices=(*CASES, 'all'), default='healthy')
    parser.add_argument('--sentinel-id', required=True)
    options = parser.parse_args(arguments)
    try:
        scenarios = CASES if options.scenario == 'all' else (options.scenario,)
        result = acceptance(options.sentinel_id, scenarios)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'fail', 'error': {'code': getattr(error, 'code', 'functional_acceptance_failed'),
            'run_id': getattr(error, 'run_id', None)}, 'runtime_pipeline_complete': False,
            'production_iso_eligible': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
