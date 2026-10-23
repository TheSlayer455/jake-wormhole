"""Explicit real readiness cases; no candidate gate or production qualification."""
import argparse
from copy import deepcopy
import hashlib
import json
import time

from . import images
from .admission import AdmissionLease
from .provisioning import ID, ProvisioningSession, file_digest, validate_plan
from .provisioning_acceptance import disk_sample, scan_private_material, snapshot
from .runs import RunError, atomic_json, common, create_run, now, source_identity
from .stages import execute_run

CASES = ('healthy', 'delayed-start', 'never-starts', 'wrong-key', 'wrong-user',
         'configured-interpreter-unavailable', 'wrong-endpoint', 'wrong-network', 'changed-host-key')
EXPECTED_FAILURE = {'never-starts': 'target_not_started', 'wrong-key': 'ssh_key_rejected',
    'wrong-user': 'ssh_user_rejected', 'configured-interpreter-unavailable': 'configured_interpreter_unavailable',
    'wrong-endpoint': 'inventory_endpoint_mismatch', 'wrong-network': 'inventory_endpoint_mismatch',
    'changed-host-key': 'ssh_host_key_mismatch'}


def require(value, code):
    if not value:
        raise RunError(code, 'Readiness acceptance failed; retain private evidence and resource accounting.')


def refresh_inventory(session):
    """Only fixed refresh operations; never select an endpoint from a guess."""
    session.held()
    session.operation('refresh-plan')
    validate_plan(session.operation('show-refresh-plan'), session.variables,
                  operation='refresh', owned=session.owned)
    saved = file_digest(session.state / 'refresh.tfplan')[0]
    session.check_inputs()
    require(file_digest(session.state / 'refresh.tfplan')[0] == saved, 'refresh_plan_changed')
    session.operation('refresh-apply')
    inventory = session.inventory(session.operation('output'))
    session.receipt['inventory'] = inventory
    session.run.save_artifact('inventory', inventory)
    session.save()
    return inventory


def restart_for_hostkey_case(session):
    """Fixed owned-fixture restart, preserving the original trusted host-key pin."""
    session.held(allocating=True)
    target = session.owned['docker_container.target']
    before = images.inspect('container', target)
    session.verify_target(before)
    require(session.receipt['unknown_outcome'] is False, 'daemon_outcome_unknown')
    session.receipt['unknown_outcome'] = True
    session.save()
    images.docker(('stop', '--time', '2', target))
    stopped = images.inspect('container', target)
    session.verify_owned(stopped, 'target', target)
    session.verify_limits(stopped, 'target', stopped=True)
    require(stopped['State']['Running'] is False and stopped['State']['Pid'] == 0, 'restart_stop_unverified')
    session.receipt['unknown_outcome'] = False
    session.save()
    session.lease.refresh()
    session.receipt['unknown_outcome'] = True
    session.save()
    images.docker(('start', target))
    live = images.inspect('container', target)
    session.verify_target(live)
    require(live['State']['Running'] is True and live['State']['Pid'] > 0, 'restart_start_unverified')
    session.receipt['target_cgroups'] = images.cgroup_limits(live['State']['Pid'],
        session.lease.plan['limits']['target']['docker_create'])
    session.receipt['target_started_at'] = live['State']['StartedAt']
    session.receipt['unknown_outcome'] = False
    session.save()
    refresh_inventory(session)
    return {'target_resource_id': target, 'before_started_at': before['State']['StartedAt'],
        'after_started_at': live['State']['StartedAt'], 'actual_stop_pid_zero': True,
        'purpose': 'controlled host-key rotation; original trusted pin retained'}


def observe_rotated_hostkey(readiness):
    """Wait only for key generation after the single controlled owned restart."""
    deadline = min(readiness.deadline, time.monotonic() + 20)
    while time.monotonic() < deadline:
        try:
            observation = readiness.observe_hostkey()
        except images.ImageError as error:
            if error.code != 'qualification_attempt_failed':
                raise
        else:
            if observation['matches_original_pin'] is False:
                return observation
        time.sleep(min(.1, max(0, deadline - time.monotonic())))
    raise RunError('rotated_hostkey_unavailable', 'The new public identity was not observed within the bounded window.')


def qualify_case(scenario, sentinel):
    # Import only when actually requested; ordinary CLI discovery remains local.
    require(scenario in CASES, 'unsupported_acceptance_case')
    require(type(sentinel) is str and ID.fullmatch(sentinel) is not None, 'invalid_sentinel')
    from .readiness import ReadinessError, ReadinessSession
    revision, dirty = source_identity()
    require(not dirty, 'source_dirty')
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    result = {**common(run.manifest()), 'operation': 'real-readiness-acceptance',
        'scenario': scenario, 'status': 'running', 'checks': {}, 'created_at': now(),
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    provisioning, readiness = None, None
    try:
        with run.locked():
            execute_run(run)  # This partial operation cannot qualify the whole pipeline.
        images.create_auth(run)
        with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE,
                run.id, revision, 'smoke') as lease:
            baseline = snapshot('container', sentinel, unrelated=True)
            provisioning = ProvisioningSession(run, lease)
            provisioning.create_stopped()
            adapter_scenario = scenario if scenario in {'wrong-key', 'wrong-user',
                'configured-interpreter-unavailable'} else 'healthy'
            if scenario not in {'delayed-start', 'never-starts'}:
                provisioning.start_and_inventory()
            readiness = ReadinessSession(provisioning, scenario=adapter_scenario)
            readiness.start_helper()
            if scenario == 'never-starts':
                # A finite five-second negative window within the normal90s cap.
                readiness.deadline = min(readiness.deadline, time.monotonic() + 5)
                result['negative_window_seconds'] = 5
            if scenario == 'changed-host-key':
                pin_deadline = min(readiness.deadline, time.monotonic() + 20)
                while not readiness.pin_trust():
                    require(time.monotonic() < pin_deadline, 'original_hostkey_unavailable')
                    time.sleep(.1)
                original_pin = readiness.receipt['hostkey_fingerprint']
                restart = restart_for_hostkey_case(provisioning)
                observation = observe_rotated_hostkey(readiness)
                require(observation['fingerprint'] != original_pin and
                        observation['matches_original_pin'] is False and
                        readiness.receipt['hostkey_fingerprint'] == original_pin, 'hostkey_did_not_change')
                result['checks']['actual_hostkey_rotation'] = {'status': 'pass', **restart,
                    'original_pin_retained': True, 'new_public_identity_observed': True}

            original_inventory = deepcopy(provisioning.receipt['inventory'])
            original_network = readiness.network
            if scenario == 'wrong-endpoint':
                provisioning.receipt['inventory']['targets'][0]['host'] = '127.0.0.1'
            elif scenario == 'wrong-network':
                wrong = hashlib.sha256(('WORM-007 expected network:' + run.id).encode()).hexdigest()
                require(wrong != original_network, 'negative_identity_collision')
                readiness.network = wrong
            delayed_start = {'invoked': False, 'elapsed_seconds': None}

            def on_poll(elapsed):
                if scenario == 'delayed-start' and elapsed >= 2 and not delayed_start['invoked']:
                    provisioning.start_and_inventory()
                    delayed_start.update(invoked=True, elapsed_seconds=elapsed)

            observed = None
            try:
                readiness.wait_ready(on_poll=on_poll)
            except ReadinessError as error:
                observed = error.code
            finally:
                if scenario in {'wrong-endpoint', 'wrong-network'}:
                    provisioning.receipt['inventory'] = original_inventory
                    readiness.network = original_network
                    provisioning.save()
                    readiness.save()  # Restore expected metadata; never edit Terraform state.
            expected = EXPECTED_FAILURE.get(scenario)
            require(observed == expected, 'unexpected_readiness_outcome')
            if expected is None:
                readiness.require_ready()
                require(readiness.receipt['status'] == 'ready' and
                        readiness.receipt['primary_failure'] is None, 'readiness_not_complete')
                result['checks']['real_ssh_ansible_readiness'] = {'status': 'pass',
                    'observed_transitions': deepcopy(readiness.receipt['transitions']),
                    'genuine_remote_probes': True}
                if scenario == 'delayed-start':
                    require(delayed_start['invoked'] and delayed_start['elapsed_seconds'] >= 2,
                            'delay_not_exercised')
                    result['checks']['delayed_start'] = {'status': 'pass', **delayed_start}
            else:
                require(readiness.receipt['status'] == 'failed' and
                        readiness.receipt['primary_failure']['code'] == expected, 'failure_not_preserved')
                blocked = False
                try:
                    readiness.require_ready()
                except ReadinessError:
                    blocked = True
                require(blocked, 'dependent_check_not_blocked')
                provisioning.failure(ReadinessError(expected, 'Controlled readiness negative; retain its failure.'))
                result['checks']['expected_failure'] = {'status': 'pass', 'observed_error': observed,
                    'dependent_check_blocked': True, 'reference_eligible': False,
                    'configured_interpreter_absence_is_package_absence': False,
                    'mismatch_kind': 'expected inventory/network input' if scenario in
                        {'wrong-endpoint', 'wrong-network'} else scenario}
            require(not readiness.receipt['unknown_outcome'] and
                    not provisioning.receipt['unknown_outcome'], 'unresolved_operation')
            result['checks']['credential_scan'] = scan_private_material(run)
            result['disk_sample'] = disk_sample(run, 'after-readiness')
            helper_receipt = readiness.cleanup()
            require(helper_receipt['cleanup'] == 'completed', 'helper_cleanup_incomplete')
            core_receipt = provisioning.destroy()
            require(core_receipt['cleanup'] == 'completed' and
                    (core_receipt['primary_failure'] or {}).get('code') == expected, 'primary_or_cleanup_changed')
            require(snapshot('container', sentinel, unrelated=True) == baseline, 'sentinel_changed')
            lease.finish(reconciliation_complete=True)
            result['checks']['cleanup'] = {'status': 'pass', 'helper': 'completed',
                'terraform': 'completed', 'unrelated_sentinel_unchanged': True,
                'underlying_partial_outcome': core_receipt['status']}
            result['status'] = 'pass'
    except BaseException as error:
        result['status'] = 'fail'
        result['error'] = {'code': getattr(error, 'code', 'readiness_acceptance_failed')}
        result['cleanup_claimed'] = False
        error.run_id = run.id
        raise
    finally:
        result['updated_at'] = now()
        try:
            with run.locked():
                atomic_json(run.file('evidence/readiness-acceptance.json'), result)
        except Exception:
            if result['status'] == 'pass':
                raise
    return result


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Actual scoped SSH/Ansible readiness acceptance; no full-pipeline claim.')
    parser.add_argument('--scenario', choices=(*CASES, 'all'), default='healthy')
    parser.add_argument('--sentinel-id', required=True)
    options = parser.parse_args(arguments)
    try:
        require(ID.fullmatch(options.sentinel_id) is not None, 'invalid_sentinel')
        cases = CASES if options.scenario == 'all' else (options.scenario,)
        revision, dirty = source_identity()
        require(not dirty, 'source_dirty')
        values = []
        for case in cases:
            require(source_identity() == (revision, False), 'source_changed')
            value = qualify_case(case, options.sentinel_id)
            require(value['source_revision'] == revision, 'source_changed')
            values.append(value)
        print(json.dumps({'operation': 'real-readiness-acceptance', 'status': 'pass', 'cases': values,
            'runtime_pipeline_complete': False, 'production_iso_eligible': False}, sort_keys=True, indent=2))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'fail', 'error': {'code': getattr(error, 'code', 'readiness_acceptance_failed'),
            'run_id': getattr(error, 'run_id', None)}, 'runtime_pipeline_complete': False,
            'production_iso_eligible': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
