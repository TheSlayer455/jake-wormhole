"""Shared observation projections for readiness admission and engineering reports.

These records describe container observations. They never infer installation or
configuration completion from creation, a port, or an SSH connection. The
original component replay remains the authority for qualification.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime
import math
import re

from .runs import RunError, common, read_json

READINESS_CHECKS = ('created', 'started', 'endpoint-discovered', 'tcp-reachable',
    'ssh-identity-accepted', 'python-usable', 'ansible-usable', 'required-test-complete')
PHASES = dict(zip(READINESS_CHECKS, ('created', 'initializing', 'initializing',
    'reachable', 'authentication-ready', 'authentication-ready', 'ansible-probing', 'ansible-ready')))


def require(value):
    if not value:
        raise RunError('progress_record_invalid', 'Progress must retain exact target identities and observed states.')


def children(receipt):
    require(type(receipt) is dict)
    values = receipt.get('targets', [receipt])
    require(type(values) is list and 1 <= len(values) <= 20)
    return values


def readiness_complete(receipt):
    """One contract for admission and reports; a TCP/SSH prefix cannot pass."""
    return (type(receipt) is dict and receipt.get('status') == 'ready' and
        receipt.get('primary_failure') is None and receipt.get('unknown_outcome') is False and
        type(receipt.get('transitions')) is list and
        [item.get('check_id') for item in receipt['transitions']] == list(READINESS_CHECKS) and
        all(item.get('status') == 'pass' for item in receipt['transitions']) and
        type(receipt.get('ready_started_at')) is str and bool(receipt['ready_started_at']))


def observer_state(*, terminal_outcome=None, remote_alive=None, progress_age=None,
                   stall_seconds=30, observation_lost=False, stopped_confirmed=False):
    """A lost observer cannot invent remote termination; liveness is not progress."""
    require(terminal_outcome in {None, 'passed', 'failed', 'cancelled', 'unknown'} and
        type(stall_seconds) in (int, float) and math.isfinite(stall_seconds) and stall_seconds > 0 and
        (remote_alive is None or type(remote_alive) is bool) and
        all(type(value) is bool for value in (observation_lost, stopped_confirmed)) and
        (progress_age is None or type(progress_age) in (int, float) and
         math.isfinite(progress_age) and progress_age >= 0))
    if terminal_outcome in {'passed', 'failed'}:
        return 'terminal-' + terminal_outcome
    if terminal_outcome == 'cancelled' and stopped_confirmed:
        return 'cancelled-confirmed-stopped'
    if observation_lost or terminal_outcome in {'unknown', 'cancelled'} or remote_alive is not True:
        return 'unknown'
    if progress_age is None:
        return 'running-progress-unobserved'
    return 'running-without-progress' if progress_age >= stall_seconds else 'running-making-progress'


def project(plan, readiness, validation=None):
    """Project one attributable atomic snapshot. This is not a qualification gate.

    Callers that publish acceptance must first replay the component originals.
    Pending/missing results remain visible; unobserved initialization stays null.
    """
    require(type(plan) is dict and type(plan.get('checks')) is list and
        type(readiness) is dict and plan.get('run_id') == readiness.get('run_id') and
        plan.get('source_revision') == readiness.get('source_revision'))
    ids = plan.get('target_plan', {}).get('target_ids', [plan.get('target_id', 'target-001')])
    require(type(ids) is list and 1 <= len(ids) <= 20 and len(ids) == len(set(ids)))
    require(all(type(identifier) is str and re.fullmatch('target-0(?:0[1-9]|1[0-9]|20)', identifier) for identifier in ids))
    observed = children(readiness)
    require(len(observed) == len(ids) and
        [item.get('target_id', 'target-001') for item in observed] == ids)
    checks = plan['checks']
    expected = [(item['target_id'], item['check_id']) for item in checks]
    require(len(expected) == len(set(expected)) and all(target in ids for target, _ in expected))
    result_rows = [] if validation is None else validation.get('checks', [])
    if validation is not None:
        require(validation.get('run_id') == plan.get('run_id') and
            validation.get('source_revision') == plan.get('source_revision') and
            validation.get('plan_sha256') == plan.get('plan_sha256'))
    require(type(result_rows) is list)
    result_keys = [(item['target_id'], item['check_id']) for item in result_rows]
    require(len(result_keys) == len(set(result_keys)) and set(result_keys) <= set(expected))
    results = dict(zip(result_keys, result_rows))
    targets = []
    for identifier, child in zip(ids, observed):
        transitions = child.get('transitions', [])
        require(type(transitions) is list and
            [item.get('check_id') for item in transitions] == list(READINESS_CHECKS[:len(transitions)]) and
            all(item.get('status') == 'pass' and item.get('target_id') == identifier for item in transitions))
        seen = {item['check_id'] for item in transitions}
        previous = 0
        stage_seconds = {}
        for item in transitions:
            elapsed = item.get('elapsed_seconds')
            require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= previous)
            try:
                stamp = item['observed_at']
                require(type(stamp) is str and len(stamp) <= 40 and datetime.fromisoformat(stamp.replace('Z', '+00:00')).tzinfo is not None)
            except (TypeError, ValueError, KeyError):
                raise RunError('progress_record_invalid', 'Observed progress requires an attributable timestamp.') from None
            stage_seconds[item['check_id']] = elapsed - previous
            previous = elapsed
        last = deepcopy(transitions[-1]) if transitions else None
        first = deepcopy(child.get('primary_failure'))
        require(first is None or type(first) is dict and type(first.get('code')) is str and
            re.fullmatch('[a-z][a-z0-9_]{0,79}', first['code']))
        unknown = child.get('unknown_outcome') is True or readiness.get('unknown_outcome') is True
        planned = [check for target, check in expected if target == identifier]
        counts = Counter()
        for check in planned:
            item = results.get((identifier, check))
            counts['missing' if item is None else item['status']] += 1
        require(set(counts) <= {'pass', 'fail', 'error', 'unreachable', 'skipped', 'blocked', 'unverified', 'missing'})
        passed = bool(planned) and counts['pass'] == len(planned)
        complete = bool(planned) and counts['pass'] + counts['fail'] == len(planned)
        terminal = 'unknown' if unknown else 'failed' if first else 'passed' if passed else 'pending'
        phase = PHASES[last['check_id']] if last else 'pending'
        if phase == 'ansible-ready' and not readiness_complete(child): phase = 'ansible-probing'
        if first: phase = 'failed'
        elif passed: phase = 'complete'
        elif validation and validation.get('attempted_targets') and identifier in validation['attempted_targets']:
            phase = 'validating' if validation.get('status') == 'pending' else 'validation-failed'
            if phase == 'validation-failed': terminal = 'failed'
        elif validation and validation.get('status') == 'failed':
            phase, terminal = 'blocked', 'failed'
        failures = [item for item in result_rows if item['target_id'] == identifier and item['status'] != 'pass']
        if first is None and failures:
            observed_category = failures[0].get('observed')
            first = {'code': failures[0].get('reason_code') or (observed_category if
                type(observed_category) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', observed_category)
                else 'functional_' + failures[0]['status'])}
        targets.append({'target_id': identifier,
            'resource_identity': plan.get('target_resource_ids', {}).get(identifier, plan.get('target_resource_id')),
            'candidate_identity': plan.get('candidate_binding'), 'image_identity': plan.get('target_image'),
            'current_phase': phase, 'terminal_outcome': terminal,
            'last_successful_transition': last, 'last_progress_at': None if last is None else last.get('observed_at'),
            'initialization_outcome': 'failed' if first and first['code'] == 'target_initialization_failed' else 'not-separately-observed',
            'configuration_outcome': 'not-separately-observed',
            'authentication_verified': 'ssh-identity-accepted' in seen,
            'ansible_ready': readiness_complete(child), 'first_failure': first,
            'tests_expected': len(planned), 'tests_passed': counts['pass'],
            'tests_failed': sum(counts[name] for name in ('fail', 'error', 'unreachable')),
            'tests_blocked': sum(counts[name] for name in ('blocked', 'unverified', 'skipped')),
            'tests_missing': counts['missing'], 'test_completion': 'complete' if complete else 'incomplete',
            'transition_elapsed_seconds': stage_seconds,
            'evidence_references': sorted({reference for item in result_rows if item['target_id'] == identifier
                for reference in item.get('evidence', [])})})
    summary = {'targets_expected': len(ids),
        'targets_created': sum(bool(item.get('transitions')) for item in observed),
        'targets_initialized': None,
        'targets_authenticated': sum(item['authentication_verified'] for item in targets),
        'targets_ansible_ready': sum(item['ansible_ready'] for item in targets),
        'targets_fully_tested': sum(item['test_completion'] == 'complete' for item in targets)}
    for field in ('expected', 'passed', 'failed', 'blocked', 'missing'):
        summary['tests_' + field] = sum(item['tests_' + field] for item in targets)
    return {'operation': 'container-execution-progress-v1', 'run_id': plan.get('run_id'),
        'source_revision': plan.get('source_revision'), 'targets': targets, 'summary': summary,
        'test_plan_observed': bool(checks),
        'qualification_authority': 'original component replay; progress is not qualification',
        'production_iso_eligible': False}


def report_progress(run):
    """Read atomic live snapshots without taking the active coordinator's lock."""
    path = run.file('evidence/readiness.json')
    if not path.exists():
        raise RunError('progress_unavailable', 'This run has no readiness observations; counts are unknown.')
    receipt = read_json(path)
    require(common(receipt) == common(run.manifest()))
    batch_path = run.file('evidence/batch-validation-plan.json')
    single_path = run.file('evidence/validation-plan.json')
    result = None
    if batch_path.exists():
        from .fleet_validation import validate_plan, report_batch_validation
        plan = read_json(batch_path); validate_plan(run, plan)
        result_path = run.file('evidence/batch-validation.json')
        result = read_json(result_path) if result_path.exists() else None
        if result and result.get('status') in {'passed', 'failed'}:
            return report_batch_validation(run)['progress']
    elif single_path.exists():
        from .validation import validate_plan, report_validation
        plan = read_json(single_path); validate_plan(run, plan)
        result_path = run.file('evidence/validation.json')
        result = read_json(result_path) if result_path.exists() else None
        if result and result.get('status') in {'passed', 'failed'}:
            result = report_validation(run)['result']
    else:
        plan = {**common(run.manifest()), 'target_plan': {'target_ids': [
            item.get('target_id', 'target-001') for item in children(receipt)]}, 'checks': []}
    return project(plan, receipt, result)


def render_text(record):
    lines = ['Container execution progress', 'Initialization and final configuration are not inferred from access.']
    if not record['test_plan_observed']:
        lines.append('Expected functional test plan not observed; completion cannot be established.')
    summary = record['summary']
    lines.append('Targets expected/created/authenticated/Ansible-ready/fully-tested: ' + '/'.join(
        str(summary['targets_' + key]) for key in ('expected', 'created', 'authenticated', 'ansible_ready', 'fully_tested')))
    for target in record['targets']:
        lines.extend([target['target_id'] + ': ' + target['current_phase'] + ' / ' + target['terminal_outcome'],
            '  resource: ' + str(target['resource_identity']) + '; image: ' + str(target['image_identity']),
            '  candidate: ' + str(target['candidate_identity']),
            '  initialization: ' + target['initialization_outcome'] + '; configuration: ' + target['configuration_outcome'],
            '  authentication: ' + str(target['authentication_verified']) + '; Ansible ready: ' + str(target['ansible_ready']),
            '  expected/passed/failed/blocked/missing: ' + '/'.join(str(target['tests_' + key])
                for key in ('expected', 'passed', 'failed', 'blocked', 'missing')),
            '  first failure: ' + str(target['first_failure']),
            '  evidence: ' + ', '.join(target['evidence_references'])])
    return '\n'.join(lines) + '\n'
