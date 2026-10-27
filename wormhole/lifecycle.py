"""Observed execution state shared by initialization, admission and reports.

The journal is data, not an executor. Callers retain the existing Run/admission
locks and bounded process adapters. Installation simulations stay labeled.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
import re
import time

from .runs import RunError, atomic_json, common, now, read_json

PATH = 'evidence/lifecycle.json'
CONDITIONS = ('initialization', 'configuration', 'network', 'host_identity',
              'final_identity', 'interpreter', 'privilege', 'ansible')
EVENTS = {
    'provisioning': ('provisioning', None), 'created': ('created', None),
    'runtime-started': ('initializing', None), 'initialization-started': ('initializing', None),
    'initialization-complete': ('initializing', 'initialization'),
    'configuration-started': ('configuration-running', None),
    'configuration-complete': ('configuration-complete', 'configuration'),
    'hardening-started': ('hardening', None),
    'reachable': ('reachable', 'network'), 'host-verified': ('reachable', 'host_identity'),
    'authenticated': ('authentication-ready', 'final_identity'),
    'interpreter-verified': ('authentication-ready', 'interpreter'),
    'privilege-verified': ('authentication-ready', 'privilege'),
    'privilege-not-required': ('authentication-ready', 'privilege'),
    'ansible-verified': ('ansible-ready', 'ansible'),
}
KINDS = ('container-observation', 'simulated-installation', 'source-fixture')


def require(value, code='lifecycle_invalid'):
    if not value: raise RunError(code, 'Execution observation violates the declared lifecycle contract.')


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


class Lifecycle:
    def __init__(self, run, target_ids, *, candidate_identity, checks, budget_seconds=120,
                 cleanup_reserve=20, clock=time.monotonic, absolute_deadline=None, requires_privilege=False):
        require(type(target_ids) in (list, tuple) and 1 <= len(target_ids) <= 20 and
            len(set(target_ids)) == len(target_ids) and all(type(identifier) is str and
            re.fullmatch('target-0(?:0[1-9]|1[0-9]|20)', identifier) for identifier in target_ids))
        require(type(checks) in (list, tuple) and 1 <= len(checks) <= 128 and len(set(checks)) == len(checks) and
            all(type(check) is str and re.fullmatch('[a-z][a-z0-9-]{0,79}', check) for check in checks))
        require(type(candidate_identity) is dict and number(budget_seconds) and 1 <= budget_seconds <= 600 and
            number(cleanup_reserve) and 0 <= cleanup_reserve < budget_seconds)
        self.run, self.clock, self.began = run, clock, clock()
        require(type(requires_privilege) is bool and (absolute_deadline is None or number(absolute_deadline)))
        self.deadline = min(self.began + budget_seconds, absolute_deadline) if absolute_deadline is not None else self.began + budget_seconds
        require(self.deadline - self.began > cleanup_reserve, 'execution_deadline_exhausted')
        self.record = {**common(run.manifest()), 'operation': 'observed-container-lifecycle-v1',
            'started_at': now(), 'deadline_at': (datetime.now(timezone.utc) + timedelta(seconds=self.deadline - self.began)).isoformat(),
            'budget_seconds': self.deadline - self.began, 'cleanup_reserve_seconds': cleanup_reserve,
            'requires_privilege': requires_privilege,
            'candidate_identity': deepcopy(candidate_identity), 'expected_targets': list(target_ids),
            'expected_checks': list(checks), 'terminal_outcome': 'pending', 'first_failure': None,
            'secondary_failures': [], 'remote_state': 'running', 'events': [], 'targets': {},
            'production_iso_eligible': False}
        for identifier in target_ids:
            self.record['targets'][identifier] = {'target_id': identifier, 'current_phase': 'pending',
                'last_successful_transition': None, 'last_progress_at': None, 'last_observed_at': None,
                'latest_failure_category': None, 'first_failure': None, 'terminal_outcome': 'pending',
                'generation': 0, 'restart_pending': False, 'conditions': dict.fromkeys(CONDITIONS, False),
                'tests': dict.fromkeys(checks, 'blocked')}
        self.save()

    def save(self):
        atomic_json(self.run.file(PATH), self.record)

    def target(self, identifier):
        require(identifier in self.record['targets'])
        return self.record['targets'][identifier]

    def remaining(self, maximum=60, *, reserve=True):
        require(number(maximum) and maximum > 0)
        value = self.deadline - self.clock() - (self.record['cleanup_reserve_seconds'] if reserve else 0)
        require(value > 0, 'execution_deadline_exhausted')
        return min(maximum, value)

    def ready(self, identifier):
        target = self.target(identifier)
        return (target['terminal_outcome'] == 'pending' and not target['restart_pending'] and
            all(target['conditions'].values()) and self.record['remote_state'] == 'running')

    def event(self, identifier, event, *, evidence, kind='container-observation', category=None, persist=True):
        target = self.target(identifier)
        require(kind in KINDS and type(evidence) is str and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9/_.-]{0,159}', evidence) and
            '..' not in evidence.split('/') and event in {*EVENTS, 'restart-started', 'restart-complete',
                'unavailable', 'heartbeat', 'failure', 'remote-unknown', 'remote-reconciled', 'cancel-confirmed'})
        require(len(self.record['events']) < 512, 'lifecycle_event_bound')
        failure = event == 'failure'
        require(category is None or type(category) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', category))
        require((category is not None) == failure)
        if event not in {'failure', 'remote-unknown', 'remote-reconciled', 'cancel-confirmed', 'heartbeat'}:
            self.remaining()
            require(target['terminal_outcome'] == 'pending', 'terminal_target_cannot_resume')
        if event == 'configuration-complete': require(target['conditions']['initialization'])
        if event == 'authenticated': require(target['conditions']['configuration'] and target['conditions']['host_identity'])
        if event == 'ansible-verified': require(all(target['conditions'][key] for key in CONDITIONS if key != 'ansible'))
        if event == 'privilege-not-required': require(self.record['requires_privilege'] is False)
        stamp = now()
        observation = {'target_id': identifier, 'event': event, 'evidence_kind': kind,
            'evidence': evidence, 'elapsed_seconds': max(0, self.clock() - self.began), 'observed_at': stamp,
            'category': category, 'generation': target['generation']}
        self.record['events'].append(observation); target['last_observed_at'] = stamp
        if event == 'heartbeat':
            if persist: self.save()
            return
        if event in EVENTS:
            phase, condition = EVENTS[event]; target['current_phase'] = phase
            if event in {'configuration-started', 'hardening-started'}:
                for name in CONDITIONS[1:]: target['conditions'][name] = False
            if condition: target['conditions'][condition] = True
            target['last_successful_transition'] = event; target['last_progress_at'] = stamp
        elif event in {'restart-started', 'unavailable'}:
            target['current_phase'] = 'restarting' if event == 'restart-started' else 'unavailable'
            target['restart_pending'] = event == 'restart-started'; target['generation'] += 1
            for condition in CONDITIONS[2:]: target['conditions'][condition] = False
            target['last_progress_at'] = stamp
        elif event == 'restart-complete':
            require(target['restart_pending']); target['restart_pending'] = False
            target['current_phase'] = 'configuration-complete' if target['conditions']['configuration'] else 'initializing'
            target['last_progress_at'] = stamp
        elif failure:
            issue = {'target_id': identifier, 'stage': target['current_phase'], 'code': category, 'observed_at': stamp}
            target['latest_failure_category'] = category
            if target['first_failure'] is None: target['first_failure'] = deepcopy(issue)
            if self.record['first_failure'] is None: self.record['first_failure'] = deepcopy(issue)
            else: self.record['secondary_failures'].append(deepcopy(issue))
            target['terminal_outcome'], target['current_phase'] = 'failed', 'failed'
        elif event == 'remote-unknown':
            self.record['remote_state'] = 'unknown'; target['terminal_outcome'] = 'unknown'
        elif event == 'remote-reconciled':
            require(target['terminal_outcome']=='unknown' and target['first_failure'] is not None)
            target['terminal_outcome'],target['current_phase']='failed','failed'
            self.record['remote_state']='running'
        elif event == 'cancel-confirmed':
            target['terminal_outcome'] = 'cancelled'; target['current_phase'] = 'cancelled'
        if persist: self.save()

    def start_validation(self):
        self.remaining()
        require(all(self.ready(identifier) and self.target(identifier)['current_phase'] == 'ansible-ready'
            for identifier in self.record['expected_targets']), 'fleet_readiness_incomplete')
        for target in self.record['targets'].values():
            target['current_phase'] = 'validating'; target['tests'] = dict.fromkeys(self.record['expected_checks'], 'missing')
        self.save()

    def test_result(self, identifier, check, status, *, persist=True):
        self.remaining(); target = self.target(identifier)
        require(target['current_phase'] == 'validating' and check in target['tests'] and
            target['tests'][check] == 'missing' and status in {'pass', 'fail', 'error', 'unreachable', 'blocked'}, 'test_result_invalid')
        target['tests'][check] = status; target['last_progress_at'] = now()
        if status in {'fail', 'error', 'unreachable'} and target['first_failure'] is None:
            issue = {'target_id': identifier, 'stage': 'validating', 'check_id': check,
                'code': 'required_test_failed', 'observed_at': now()}
            target['first_failure'] = issue; target['latest_failure_category'] = issue['code']
            if self.record['first_failure'] is None: self.record['first_failure'] = deepcopy(issue)
        if persist: self.save()

    def finalize(self):
        for identifier, target in self.record['targets'].items():
            if target['terminal_outcome'] == 'pending':
                passing = target['current_phase'] == 'validating' and all(value == 'pass' for value in target['tests'].values())
                if passing: target['terminal_outcome'], target['current_phase'] = 'passed', 'complete'
                elif target['first_failure'] is not None:
                    target['terminal_outcome'], target['current_phase'] = 'failed', 'failed'
                else:
                    category = 'execution_deadline_exhausted' if self.clock() >= self.deadline - self.record['cleanup_reserve_seconds'] else 'required_results_incomplete'
                    self.event(identifier, 'failure', evidence='lifecycle/terminal-accounting', category=category)
        outcomes = {target['terminal_outcome'] for target in self.record['targets'].values()}
        self.record['terminal_outcome'] = ('unknown' if 'unknown' in outcomes else 'passed' if outcomes == {'passed'}
            else 'cancelled' if outcomes == {'cancelled'} and self.record['first_failure'] is None else 'failed')
        self.record['remote_state'] = 'unknown' if 'unknown' in outcomes else 'stopped' if outcomes == {'cancelled'} else 'terminal'
        self.save(); return deepcopy(self.record)

    def render_text(self):
        lines = ['Container lifecycle: ' + self.record['terminal_outcome'],
            'Production ISO eligibility: false; installation simulations retain their evidence kind.']
        for target in self.record['targets'].values():
            counts = {status: list(target['tests'].values()).count(status) for status in ('pass', 'fail', 'error', 'unreachable', 'blocked', 'missing')}
            lines.extend([target['target_id'] + ': ' + target['current_phase'] + ' / ' + target['terminal_outcome'],
                '  first failure: ' + str(target['first_failure']), '  tests: ' + str(counts),
                '  readiness conditions: ' + str(target['conditions'])])
        return '\n'.join(lines) + '\n'


def initialization_events(journal, target, observation, reference):
    kind = 'simulated-installation' if observation['simulated_installation'] else 'container-observation'
    for event in observation['events']:
        journal.event(target, 'hardening-started' if event == 'hardening-applied' else event,
            evidence=reference, kind=kind, persist=False)
    if observation['status'] == 'failed':
        journal.event(target, 'failure', evidence=reference, kind=kind, category=observation['category'])
    else: journal.save()


def readiness_events(journal, target, receipt):
    from .execution_state import readiness_complete
    require(readiness_complete(receipt), 'fleet_readiness_incomplete')
    for event in ('reachable', 'host-verified', 'authenticated', 'interpreter-verified',
                  'privilege-not-required', 'ansible-verified'):
        journal.event(target, event, evidence='evidence/readiness.json',persist=False)
    journal.save()


def report_lifecycle(run, *, expected_targets=None, expected_checks=None, require_passed=False):
    value = read_json(run.file(PATH))
    require(type(value) is dict and common(value) == common(run.manifest()) and
        value.get('operation') == 'observed-container-lifecycle-v1' and value.get('production_iso_eligible') is False and
        type(value.get('targets')) is dict and type(value.get('expected_targets')) is list and
        set(value['targets']) == set(value['expected_targets']) and type(value.get('expected_checks')) is list and
        number(value.get('budget_seconds')) and 0 < value['budget_seconds'] <= 600)
    require(expected_targets is None or value['expected_targets'] == list(expected_targets))
    require(expected_checks is None or value['expected_checks'] == list(expected_checks))
    for target, record in value['targets'].items():
        require(record['target_id'] == target and set(record['tests']) == set(value['expected_checks']) and
            set(record['conditions']) == set(CONDITIONS) and all(type(flag) is bool for flag in record['conditions'].values()))
        if require_passed:
            require(record['terminal_outcome'] == 'passed' and record['current_phase'] == 'complete' and
                record['first_failure'] is None and not record['restart_pending'] and all(record['conditions'].values()) and
                all(status == 'pass' for status in record['tests'].values()), 'lifecycle_incomplete')
    if require_passed:
        require(value['terminal_outcome'] == 'passed' and value['remote_state'] == 'terminal' and
            value['first_failure'] is None, 'lifecycle_incomplete')
    return value
