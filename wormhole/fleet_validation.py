"""Complete target/check grids from one bounded, genuine Ansible batch."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import time

from . import images, validation as v
from .contracts import validate_artifact
from .runs import SOURCE_ROOT, _owned, atomic_json, common, now, read_json, source_identity
from .stages import _run_process
from .targets import TargetPlan, LAYOUT
from validation import runtime

TIMEOUT = 60
EVIDENCE = ['evidence/batch-validation-plan.json', 'evidence/batch-validation-observations.json']
LOG = 'private/qualification-helper-batch-functional-validation-0.log'


def make_plan(run, target_plan, targets, network, concurrency, scenarios):
    v.require(target_plan.profile in {'smoke', 'five-targets'} and type(concurrency) is int and
        1 <= concurrency <= min(2, len(target_plan.target_ids)) and set(targets) == set(target_plan.target_ids), 'validation_scope')
    recipe, files = images.recipe_identity()
    checks = []
    for target in target_plan.target_ids:
        expected = v.expectations(scenarios[target], files)
        checks.extend({'target_id': target, 'check_id': check, 'required': True, 'expected': expected[check]} for check in v.CHECKS)
    value = {**common(run.manifest()), 'operation': 'batch-functional-validation-plan', 'resource_layout': LAYOUT,
        'target_plan': target_plan.record(), 'target_resource_ids': dict(targets), 'network_id': network,
        'controller_concurrency': concurrency, 'target_image': v.TARGET_IMAGE, 'target_build_run': v.TARGET_BUILD,
        'target_build_source_revision': v.TARGET_BUILD_SOURCE, 'recipe_sha256': recipe, 'recipe_files': files,
        'validation_source_sha256': v.runtime_hash(), 'readiness_source_sha256': hashlib.sha256((SOURCE_ROOT / 'readiness/runtime.py').read_bytes()).hexdigest(),
        'collector_sha256': hashlib.sha256(runtime.TARGET_PROGRAM.encode()).hexdigest(), 'scenarios': dict(scenarios),
        'applicability': {'os_id': 'ubuntu', 'os_version': '24.04', 'platform': 'linux/amd64'},
        'candidate_binding': 'not-implemented; qualified stock reference image only', 'checks': checks}
    return {**value, 'plan_sha256': v.digest(value)}


def validate_plan(run, value):
    v.require(type(value) is dict and common(value) == common(run.manifest()) and
        value.get('source_dirty') is False and value.get('mode') == 'container-reference', 'validation_plan_changed')
    target_plan = TargetPlan.from_record(value['target_plan'])
    targets = value['target_resource_ids']; scenarios = value['scenarios']
    v.require(type(targets) is dict and set(targets) == set(target_plan.target_ids) and len(set(targets.values())) == len(targets) and
        all(type(x) is str and re.fullmatch('[a-f0-9]{64}', x) for x in targets.values()) and
        type(value['network_id']) is str and re.fullmatch('[a-f0-9]{64}', value['network_id']) and
        type(scenarios) is dict and set(scenarios) == set(target_plan.target_ids) and all(x in runtime.SCENARIOS for x in scenarios.values()), 'validation_plan_changed')
    v.require(value == make_plan(run, target_plan, targets, value['network_id'], value['controller_concurrency'], scenarios), 'validation_plan_changed')
    return target_plan


def rows(plan, records):
    result = []
    for target in plan['target_plan']['target_ids']:
        record = records[target]
        partial = {'checks': [item for item in plan['checks'] if item['target_id'] == target]}
        values = v.rows(partial, record['observation'], status=record['status'], category=record['category'] or 'observed')
        result.extend({**item, 'evidence': list(EVIDENCE)} for item in values)
    return result


def blocked_record(target_id, code):
    return {'target_id': target_id, 'source': 'readiness', 'status': 'unverified', 'category': code,
            'module_returncode': None, 'observation': None}


def parse_response(raw, plan, attempted, budget):
    try:
        v.require(type(raw) is bytes and 1 <= len(raw) <= 65536, 'validation_probe_invalid')
        value = json.loads(raw, object_pairs_hook=runtime.unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        fields = {'schema_version', 'run_id', 'source_revision', 'resource_layout', 'plan_sha256', 'status', 'returncode',
                  'timed_out', 'truncated', 'duration_seconds', 'targets', 'private_diagnostic'}
        v.require(type(value) is dict and set(value) == fields and all(value[key] == plan[key] for key in
            ('schema_version', 'run_id', 'source_revision', 'resource_layout', 'plan_sha256')) and value['status'] in {'pass', 'fail'} and
            type(value['returncode']) is int and -(2**31) <= value['returncode'] < 2**31 and
            type(value['timed_out']) is bool and type(value['truncated']) is bool and
            type(value['duration_seconds']) in (int, float) and math.isfinite(value['duration_seconds']) and
            0 <= value['duration_seconds'] <= budget and type(value['private_diagnostic']) is str and
            len(value['private_diagnostic'].encode()) <= 32768 and type(value['targets']) is list and
            [item.get('target_id') for item in value['targets']] == list(attempted), 'validation_probe_invalid')
        for target in value['targets']:
            v.require(type(target) is dict and set(target) == {'target_id', 'status', 'category', 'module_returncode', 'observation'} and
                target['status'] in {'pass', 'fail', 'error', 'unreachable', 'skipped'} and
                (target['module_returncode'] is None or type(target['module_returncode']) is int) and
                (target['category'] is None or type(target['category']) is str and target['category'] in v.CATEGORIES) and
                (target['status'] == 'pass' or target['category'] is not None) and
                (target['status'] == 'pass') == (target['category'] is None and target['module_returncode'] == 0 and target['observation'] is not None),
                'validation_probe_invalid')
            if target['observation'] is not None:
                v.require(target['status'] == 'pass' and not value['timed_out'] and not value['truncated'], 'validation_probe_invalid')
                runtime.observation(target['observation'])
        v.require((value['status'] == 'pass') == (value['returncode'] == 0 and not value['timed_out'] and not value['truncated'] and
            all(target['status'] == 'pass' for target in value['targets'])), 'validation_probe_invalid')
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError, AttributeError):
        raise v.ValidationError('validation_probe_invalid', 'A complete expected target result set is required.') from None


def validate_result(run, plan, result, observed):
    from .recovery import valid_failure, _timestamp
    target_plan = validate_plan(run, plan)
    fields = set(common(run.manifest())) | {'operation', 'resource_layout', 'plan_sha256', 'status', 'attempted_targets',
        'blocked_targets', 'checks', 'attempts', 'capture', 'primary_failure', 'unknown_outcome', 'updated_at',
        'runtime_pipeline_complete', 'production_iso_eligible', 'candidate_binding'}
    v.require(type(result) is dict and set(result) == fields and common(result) == common(run.manifest()) and
        result['operation'] == 'batch-ssh-ansible-functional-validation' and result['resource_layout'] == LAYOUT and
        result['plan_sha256'] == plan['plan_sha256'] and result['status'] in {'passed', 'failed'} and
        result['runtime_pipeline_complete'] is False and result['production_iso_eligible'] is False and
        result['candidate_binding'] == plan['candidate_binding'] and _timestamp(result['updated_at']) and type(result['unknown_outcome']) is bool and
        type(result['attempted_targets']) is list and result['attempted_targets'] == sorted(set(result['attempted_targets'])) and
        set(result['attempted_targets']) <= set(target_plan.target_ids) and type(result['blocked_targets']) is dict and
        set(result['blocked_targets']) == set(target_plan.target_ids) - set(result['attempted_targets']) and
        all(type(x) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', x) for x in result['blocked_targets'].values()), 'validation_result_invalid')
    failure = result['primary_failure']
    v.require((result['status'] == 'failed') == (failure is not None) and valid_failure(failure), 'validation_result_invalid')
    obs_fields = set(common(run.manifest())) | {'operation', 'plan_sha256', 'targets'}
    v.require(type(observed) is dict and set(observed) == obs_fields and common(observed) == common(run.manifest()) and
        observed['operation'] == 'batch-functional-observations' and observed['plan_sha256'] == plan['plan_sha256'] and
        type(observed['targets']) is list and [x.get('target_id') for x in observed['targets']] == list(target_plan.target_ids), 'validation_result_invalid')
    records = {item['target_id']: item for item in observed['targets']}
    for target, item in records.items():
        v.require(type(item) is dict and set(item) == {'target_id', 'source', 'status', 'category', 'module_returncode', 'observation'} and
            item['source'] in {'readiness', 'ansible'} and item['status'] in {'pass', 'fail', 'error', 'unreachable', 'skipped', 'unverified'}, 'validation_result_invalid')
        if target in result['blocked_targets']:
            v.require(item == blocked_record(target, result['blocked_targets'][target]), 'validation_result_invalid')
        else:
            v.require(item['source'] == 'ansible' and (item['category'] is None or type(item['category']) is str and
                re.fullmatch('[a-z][a-z0-9_]{0,79}', item['category'])), 'validation_result_invalid')
    capture = result['capture']; v.require(type(result['attempts']) is list and len(result['attempts']) <= 1, 'validation_result_invalid')
    if capture is None:
        v.require(not result['attempted_targets'] and not result['attempts'], 'validation_capture_invalid')
    else:
        v.require(type(capture) is dict and set(capture) == {'private_log', 'sha256', 'size_bytes', 'budget_seconds', 'complete'} and
            capture['private_log'] == LOG and type(capture['sha256']) is str and re.fullmatch('[a-f0-9]{64}', capture['sha256']) and
            type(capture['size_bytes']) is int and 0 <= capture['size_bytes'] <= 65536 and type(capture['complete']) is bool and
            type(capture['budget_seconds']) in (int, float) and .1 <= capture['budget_seconds'] <= 45 and len(result['attempts']) == 1,
            'validation_capture_invalid')
        attempt = result['attempts'][0]
        v.require(type(attempt) is dict and set(attempt) == {'role', 'stage', 'status', 'returncode', 'duration_seconds', 'log_truncated', 'private_log'} and
            attempt['role'] == 'helper' and attempt['stage'] == 'batch-functional-validation' and attempt['private_log'] == LOG and
            attempt['status'] in {'pass', 'fail', 'error', 'timeout', 'unsupported'} and type(attempt['log_truncated']) is bool and
            (attempt['returncode'] is None or type(attempt['returncode']) is int) and
            type(attempt['duration_seconds']) in (int, float) and math.isfinite(attempt['duration_seconds']) and
            0 <= attempt['duration_seconds'] <= TIMEOUT + 2, 'validation_capture_invalid')
        path = run.file(LOG); _owned(path)
        with path.open('rb') as stream: raw = stream.read(65537)
        v.require(len(raw) == capture['size_bytes'] and hashlib.sha256(raw).hexdigest() == capture['sha256'], 'validation_capture_invalid')
        if capture['complete']:
            v.require(attempt['status'] == 'pass' and attempt['returncode'] == 0 and not attempt['log_truncated'], 'validation_capture_invalid')
            reply = parse_response(raw, plan, result['attempted_targets'], capture['budget_seconds'])
            for item in reply['targets']:
                v.require(records[item['target_id']] == {**item, 'source': 'ansible'}, 'validation_capture_invalid')
        else:
            v.require(result['status'] == 'failed' and all(records[target]['status'] == 'error' and records[target]['observation'] is None
                for target in result['attempted_targets']), 'validation_capture_invalid')
    expected = rows(plan, records); v.require(result['checks'] == expected, 'validation_result_invalid')
    validate_artifact('test-results', {**common(result), 'status': 'pass' if result['status'] == 'passed' else 'fail', 'checks': result['checks']})
    passing = (len(result['attempted_targets']) == len(target_plan.target_ids) and not result['unknown_outcome'] and failure is None and
        capture is not None and capture['complete'] and all(item['status'] == 'pass' for item in result['checks']))
    if passing:
        passing = parse_response(raw, plan, result['attempted_targets'], capture['budget_seconds'])['status'] == 'pass'
    v.require((result['status'] == 'passed') == passing, 'validation_result_invalid')
    return result


def report_batch_validation(run):
    plan = read_json(run.file('evidence/batch-validation-plan.json'))
    result = read_json(run.file('evidence/batch-validation.json'))
    observed = read_json(run.file('evidence/batch-validation-observations.json'))
    validate_result(run, plan, result, observed)
    lines = [f"Run {run.id}: batch functional validation {result['status']}",
        f"Targets {plan['target_plan']['target_count']}; configured Ansible forks {plan['controller_concurrency']} (separate quantities).",
        'Qualified stock reference image; complete pipeline, candidate binding and production eligibility remain unimplemented.']
    for item in result['checks']:
        lines.extend([item['target_id'] + ' / ' + item['check_id'] + ': ' + item['status'],
            '  expected: ' + item['expected'], '  observed: ' + item['observed'], '  evidence: ' + ', '.join(item['evidence'])])
    return {'result': deepcopy(result), 'text': '\n'.join(lines) + '\n'}


class BatchValidationSession:
    def __init__(self, readiness, *, scenarios=None):
        self.readiness, self.run, self.lease = readiness, readiness.run, readiness.lease
        readiness.held(); revision, dirty = source_identity()
        self.target_plan = TargetPlan.from_lease(self.lease)
        v.require(readiness.target_plan == self.target_plan and readiness.validation_enabled is True and
            readiness.validation_source_sha256 == v.runtime_hash() and revision == self.run.manifest()['source_revision'] and
            dirty is False and not self.lease._reconciliation_only and self.target_plan.profile in {'smoke', 'five-targets'}, 'validation_scope')
        scenarios = {} if scenarios is None else scenarios
        v.require(type(scenarios) is dict and set(scenarios) <= set(self.target_plan.target_ids) and
            all(x in runtime.SCENARIOS for x in scenarios.values()), 'unsupported_validation_scenario')
        self.scenarios = {target: scenarios.get(target, 'healthy') for target in self.target_plan.target_ids}
        build = v.qualification.build_reference(v.TARGET_BUILD, 'target')
        v.require(build['image_id'] == v.TARGET_IMAGE and build['source_revision'] == v.TARGET_BUILD_SOURCE, 'validation_image_mismatch')
        self.plan = make_plan(self.run, self.target_plan, readiness.target_resources, readiness.network,
                              self.lease.plan['controller_concurrency'], self.scenarios)
        v.require(not self.run.file('evidence/batch-validation-plan.json').exists(), 'validation_attempt_reused')
        atomic_json(self.run.file('evidence/batch-validation-plan.json'), self.plan)
        self.records = {target: blocked_record(target, 'not_attempted') for target in self.target_plan.target_ids}
        self.receipt = {**common(self.run.manifest()), 'operation': 'batch-ssh-ansible-functional-validation', 'resource_layout': LAYOUT,
            'plan_sha256': self.plan['plan_sha256'], 'status': 'pending', 'attempted_targets': [],
            'blocked_targets': {target: 'not_attempted' for target in self.target_plan.target_ids}, 'checks': rows(self.plan, self.records),
            'attempts': [], 'capture': None, 'primary_failure': None, 'unknown_outcome': False,
            'runtime_pipeline_complete': False, 'production_iso_eligible': False, 'candidate_binding': self.plan['candidate_binding']}
        self.started = False; self.save()

    def save(self):
        self.receipt.update(checks=rows(self.plan, self.records), updated_at=now())
        atomic_json(self.run.file('evidence/batch-validation-observations.json'), {**common(self.run.manifest()),
            'operation': 'batch-functional-observations', 'plan_sha256': self.plan['plan_sha256'],
            'targets': [self.records[target] for target in self.target_plan.target_ids]})
        atomic_json(self.run.file('evidence/batch-validation.json'), self.receipt)

    def remaining(self, deadline, maximum=20):
        value = deadline - time.monotonic(); v.require(value > .1, 'validation_timeout')
        return min(maximum, value)

    def failure(self, error):
        code = getattr(error, 'code', 'validation_failed')
        code = code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', code) else 'validation_failed'
        self.readiness.held(); ps = self.readiness.parent_provisioning
        v.require(ps.run.id == self.run.id and ps.run.path == self.run.path and ps.lease is self.lease, 'validation_scope')
        ps.held()
        if ps.receipt['primary_failure'] is None or ps.receipt['primary_failure']['code'] != code:
            ps.failure(v.ValidationError(code, 'A required planned target/check failed.'))
        if self.receipt['primary_failure'] is None: self.receipt['primary_failure'] = {'code': code, 'recorded_at': now()}
        self.receipt['status'] = 'failed'; self.save()

    def validate(self, *, before_probe=None):
        v.require(not self.started, 'validation_attempt_reused'); self.started = True
        deadline = time.monotonic() + TIMEOUT
        try:
            v.require(before_probe is None or callable(before_probe), 'invalid_validation_coordinator')
            self.readiness.held(); validate_plan(self.run, self.plan)
            v.require(read_json(self.run.file('evidence/batch-validation-plan.json')) == self.plan, 'validation_plan_changed')
            v.require(not self.readiness.receipt['unknown_outcome'], 'helper_outcome_unknown')
            targets = []
            for target in self.target_plan.target_ids:
                try:
                    self.readiness.require_ready(target, inspection_timeout=self.remaining(deadline))
                    state = self.readiness._states[target]
                    started = datetime.fromisoformat(state['last_started_at'].replace('Z', '+00:00'))
                    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                    v.require(started.tzinfo is not None and 0 <= elapsed and 300 - elapsed >= TIMEOUT + 20, 'validation_lifetime_budget_insufficient')
                    targets.append({'target_id': target, 'address': state['trust_address'], 'scenario': self.scenarios[target]})
                except Exception as error:
                    code = getattr(error, 'code', 'readiness_required')
                    failure = self.readiness.target_state(target).get('primary_failure')
                    code = failure['code'] if failure is not None else code
                    self.records[target] = blocked_record(target, code); self.receipt['blocked_targets'][target] = code
            self.remaining(deadline)
            if not targets:
                raise v.ValidationError('readiness_required', 'No planned target has a valid ready snapshot.')
            attempted = [target['target_id'] for target in targets]
            for target in attempted:
                self.receipt['blocked_targets'].pop(target, None)
                self.records[target] = {'target_id': target, 'source': 'ansible', 'status': 'error',
                    'category': 'not_observed', 'module_returncode': None, 'observation': None}
            self.receipt['attempted_targets'] = attempted
            helper = images.inspect('container', self.readiness.helper, timeout=self.remaining(deadline))
            self.readiness.verify_helper(helper)
            started = datetime.fromisoformat(helper['State']['StartedAt'].replace('Z', '+00:00'))
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            v.require(started.tzinfo is not None and 0 <= elapsed and 180 - elapsed >= TIMEOUT + 20, 'validation_lifetime_budget_insufficient')
            if before_probe is not None: before_probe(); self.remaining(deadline)
            budget = self.remaining(deadline, 45); v.require(budget > 3, 'validation_timeout')
            request = {'schema_version': '1.0', 'run_id': self.run.id, 'source_revision': self.run.manifest()['source_revision'],
                'resource_layout': LAYOUT, 'plan_sha256': self.plan['plan_sha256'], 'target_plan': self.target_plan.record(),
                'targets': targets, 'controller_concurrency': self.plan['controller_concurrency'],
                'expected_payload_sha256': self.plan['recipe_files']['runtime.py'], 'readiness_source_sha256': self.plan['readiness_source_sha256'],
                'timeout_seconds': budget - 2}
            runtime.decode_batch(v.canonical(request).encode())
            encoded = base64.b64encode(v.canonical(request).encode()).decode()
            result = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
                'exec', '--user', '10001:10001', self.readiness.helper, '/opt/wormhole/venv/bin/python', '-I', '-B',
                v.VALIDATION_MOUNT, encoded), cwd=SOURCE_ROOT, timeout=budget)
            if result['status'] == 'timeout':
                self.receipt['unknown_outcome'] = True; self.readiness.receipt['unknown_outcome'] = True; self.readiness.save()
            v.qualification.attempt_record(self.run, self.receipt, 'helper', 'batch-functional-validation', result)
            v.require(len(self.receipt['attempts']) == 1 and not self.receipt['attempts'][0].get('diagnostic_write_failed'), 'validation_diagnostic_unavailable')
            raw = result['log']; v.require(type(raw) is bytes and len(raw) <= 65536, 'validation_probe_invalid')
            self.receipt['capture'] = {'private_log': LOG, 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw), 'budget_seconds': budget, 'complete': False}
            self.save(); v.require(result['status'] == 'pass' and not result['log_truncated'], 'validation_probe_incomplete')
            self.remaining(deadline); value = parse_response(raw, self.plan, attempted, budget)
            self.receipt['capture']['complete'] = True
            for record in value['targets']: self.records[record['target_id']] = {**record, 'source': 'ansible'}
            self.remaining(deadline)
            passed = not self.receipt['blocked_targets'] and value['status'] == 'pass' and all(row['status'] == 'pass' for row in rows(self.plan, self.records))
            if not passed:
                raise v.ValidationError('required_batch_check_failed', 'The complete target/check grid did not pass.')
            self.receipt['status'] = 'passed'; self.save(); self.require_passed(); self.remaining(deadline)
            return deepcopy(self.receipt)
        except BaseException as error:
            if self.receipt['capture'] is None and not self.receipt['attempts']:
                code = getattr(error, 'code', 'validation_failed')
                code = code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', code) else 'validation_failed'
                for target in self.receipt['attempted_targets']:
                    self.records[target] = blocked_record(target, code)
                    self.receipt['blocked_targets'][target] = code
                self.receipt['attempted_targets'] = []
            if self.receipt['primary_failure'] is None: self.failure(error)
            raise

    def require_passed(self):
        observed = {**common(self.run.manifest()), 'operation': 'batch-functional-observations', 'plan_sha256': self.plan['plan_sha256'],
                    'targets': [self.records[target] for target in self.target_plan.target_ids]}
        validate_result(self.run, self.plan, self.receipt, observed)
        v.require(self.receipt['status'] == 'passed', 'functional_validation_required')
        return True
