"""One-target candidate checks through the existing fixed SSH/Ansible helper."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import time

from validation import runtime
from scripts import qualify_images as qualification
from . import candidate as c, images, validation as v
from .contracts import validate_artifact
from .runs import SOURCE_ROOT, _owned, atomic_json, common, now, read_json, source_identity

SCENARIOS = ('healthy', 'version-expectation-mismatch')
TIMEOUT = 60
LOG = 'private/qualification-helper-candidate-validation-0.log'
EVIDENCE = ['evidence/candidate-validation-plan.json', 'evidence/candidate-observations.json']


def expected_values(binding, scenario):
    c.require(scenario in SCENARIOS, 'candidate_scenario_invalid')
    manifest = binding['manifest']; files = {item['path']: item for item in manifest['files']}
    return {'candidate-userland': v.canonical({'id': manifest['applicability']['os_id'], 'version_id': manifest['applicability']['os_version']}),
        'candidate-source-sha256': manifest['source_sha256'], 'candidate-manifest-sha256': binding['candidate_sha256'],
        'candidate-payload-sha256': files['payload.py']['sha256'],
        'candidate-version': manifest['version'] + ('-controlled-mismatch' if scenario == 'version-expectation-mismatch' else ''),
        'candidate-configuration': v.canonical(manifest['configuration']),
        'candidate-function': v.canonical({'status': 'observed', 'value': {'version': manifest['version'],
            'message': manifest['configuration']['greeting'], 'source_sha256': manifest['source_sha256']}})}


def make_plan(run, binding, target, network, scenario):
    values = expected_values(binding, scenario)
    value = {**common(run.manifest()), 'operation': 'candidate-validation-plan', 'scenario': scenario,
        'target_id': 'target-001', 'target_resource_id': target, 'network_id': network, 'target_image': binding['image_id'],
        'candidate_sha256': binding['candidate_sha256'], 'source_integrity': {'chunk_plan_sha256': binding['manifest']['chunk_plan_sha256'],
            'chunk_manifest_sha256': binding['manifest']['chunk_manifest_sha256'], 'source_sha256': binding['manifest']['source_sha256']},
        'test_contract_sha256': binding['test_contract_sha256'],
        'execution_contract_sha256':c.sha(c.canonical(c.test_contract())), 'validation_source_sha256': v.runtime_hash(),
        'readiness_source_sha256': hashlib.sha256((SOURCE_ROOT / 'readiness/runtime.py').read_bytes()).hexdigest(),
        'collector_sha256': hashlib.sha256(runtime.CANDIDATE_PROGRAM.encode()).hexdigest(),
        'checks': [{'target_id': 'target-001', 'check_id': check, 'required': True, 'expected': values[check]} for check in c.CHECKS],
        'iso_processing': 'none', 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    return {**value, 'plan_sha256': v.digest(value)}


def validate_plan(run, plan):
    binding = c.validate_binding(run)
    c.require(type(plan) is dict and c.bound_common(plan, run.manifest()) and
        type(plan.get('target_resource_id')) is str and c.IDENTIFIER.fullmatch(plan['target_resource_id']) and
        type(plan.get('network_id')) is str and c.IDENTIFIER.fullmatch(plan['network_id']) and
        plan == make_plan(run, binding, plan['target_resource_id'], plan['network_id'], plan.get('scenario')), 'candidate_plan_changed')
    provisioning = read_json(run.file('evidence/provisioning.json'))
    owned = {item['address']: item['id'] for item in provisioning['resources']}
    c.require(c.bound_common(provisioning, run.manifest()) and provisioning.get('target_binding') == binding and
        provisioning.get('target_image') == binding['image_id'] and owned.get('docker_container.target["target-001"]') == plan['target_resource_id'] and
        owned.get('docker_network.run') == plan['network_id'], 'candidate_plan_changed')
    return binding


def rows(plan, observed=None, *, status='unverified', category='not-attempted'):
    values = {}
    if observed is not None:
        runtime.candidate_observation(observed)
        values = {'candidate-userland': v.canonical(observed['os']), 'candidate-source-sha256': observed['source_sha256'],
            'candidate-manifest-sha256': observed['candidate_sha256'], 'candidate-payload-sha256': observed['payload_sha256'],
            'candidate-version': observed['version'], 'candidate-configuration': v.canonical(observed['configuration']),
            'candidate-function': v.canonical(observed['function'])}
    return [{**item, 'status': ('unverified' if item['check_id'] == 'candidate-function' and observed['function']['status'] == 'unverified'
        else 'pass' if values[item['check_id']] == item['expected'] else 'fail') if observed is not None else status,
        'observed': values[item['check_id']] if observed is not None else category, 'evidence': list(EVIDENCE)} for item in plan['checks']]


def parse_response(raw, plan, budget):
    try:
        c.require(type(raw) is bytes and 1 <= len(raw) <= 65536, 'candidate_capture_invalid')
        value = json.loads(raw, object_pairs_hook=runtime.unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        fields = {'schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256', 'status', 'category',
            'returncode', 'timed_out', 'truncated', 'duration_seconds', 'observation', 'private_diagnostic'}
        c.require(type(value) is dict and set(value) == fields and all(value[key] == plan[key] for key in
            ('schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256')) and
            value['status'] in {'pass', 'fail', 'error', 'unreachable', 'skipped'} and
            type(value['returncode']) is int and -(2**31) <= value['returncode'] < 2**31 and
            type(value['timed_out']) is bool and type(value['truncated']) is bool and
            type(value['duration_seconds']) in (int, float) and math.isfinite(value['duration_seconds']) and
            0 <= value['duration_seconds'] <= budget and type(value['private_diagnostic']) is str and
            len(value['private_diagnostic'].encode()) <= 8192 and
            (value['category'] is None or value['category'] in v.CATEGORIES) and
            (value['status'] == 'pass') == (value['returncode'] == 0 and value['category'] is None and
                value['timed_out'] is False and value['truncated'] is False and value['observation'] is not None) and
            (value['observation'] is None or value['status'] == 'pass'), 'candidate_capture_invalid')
        if value['observation'] is not None: runtime.candidate_observation(value['observation'])
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise c.CandidateError('candidate_capture_invalid', 'A complete bound candidate helper response is required.') from None


def report_candidate_validation(run):
    from .recovery import valid_failure, _timestamp
    plan, result = read_json(run.file('evidence/candidate-validation-plan.json')), read_json(run.file('evidence/candidate-validation.json'))
    validate_plan(run, plan)
    fields = set(common(run.manifest())) | {'operation', 'plan_sha256', 'status', 'checks', 'capture', 'attempts',
        'primary_failure', 'unknown_outcome', 'updated_at', 'runtime_pipeline_complete', 'production_iso_eligible'}
    c.require(type(result) is dict and set(result) == fields and c.bound_common(result, run.manifest()) and
        result['operation'] == 'candidate-validation' and result['plan_sha256'] == plan['plan_sha256'] and
        result['status'] in {'passed', 'failed'} and type(result['unknown_outcome']) is bool and
        result['runtime_pipeline_complete'] is False and result['production_iso_eligible'] is False and
        valid_failure(result['primary_failure']) and (result['status'] == 'failed') == (result['primary_failure'] is not None) and
        _timestamp(result['updated_at']) and type(result['attempts']) is list and len(result['attempts']) <= 1, 'candidate_result_invalid')
    for attempt in result['attempts']:
        c.require(type(attempt) is dict and set(attempt) == {'role', 'stage', 'status', 'returncode', 'duration_seconds', 'log_truncated', 'private_log'} and
            attempt['role'] == 'helper' and attempt['stage'] == 'candidate-validation' and
            attempt['status'] in {'pass', 'fail', 'error', 'timeout', 'unsupported'} and
            (attempt['returncode'] is None or type(attempt['returncode']) is int) and type(attempt['log_truncated']) is bool and
            type(attempt['duration_seconds']) in (int, float) and math.isfinite(attempt['duration_seconds']) and
            0 <= attempt['duration_seconds'] <= TIMEOUT + 2 and attempt['private_log'] == LOG, 'candidate_result_invalid')
    observation = read_json(run.file('evidence/candidate-observations.json'))
    c.require(type(observation) is dict and set(observation) == set(common(run.manifest())) | {'operation', 'plan_sha256', 'response'} and
        c.bound_common(observation, run.manifest()) and observation['operation'] == 'candidate-observations' and
        observation['plan_sha256'] == plan['plan_sha256'], 'candidate_result_invalid')
    response = observation['response']; capture = result['capture']
    if capture is None:
        c.require(response is None and not result['attempts'] and result['status'] == 'failed', 'candidate_capture_invalid')
    else:
        c.require(type(capture) is dict and set(capture) == {'path', 'sha256', 'size_bytes', 'budget_seconds', 'complete'} and
            capture['path'] == LOG and type(capture['size_bytes']) is int and 0 <= capture['size_bytes'] <= 65536 and
            type(capture['budget_seconds']) in (int, float) and .1 <= capture['budget_seconds'] <= 35 and
            type(capture['complete']) is bool and len(result['attempts']) == 1, 'candidate_capture_invalid')
        _owned(run.file(LOG))
        with run.file(LOG).open('rb') as stream: raw = stream.read(65537)
        c.require((len(raw), c.sha(raw)) == (capture['size_bytes'], capture['sha256']), 'candidate_capture_invalid')
        if capture['complete']:
            c.require(response == parse_response(raw, plan, capture['budget_seconds']) and result['attempts'][0]['status'] == 'pass' and
                result['attempts'][0]['returncode'] == 0 and result['attempts'][0]['log_truncated'] is False, 'candidate_capture_invalid')
        else: c.require(response is None and result['status'] == 'failed', 'candidate_capture_invalid')
    actual = None if response is None else response['observation']
    expected_rows = rows(plan, actual, status='error' if response is None else response['status'],
        category=result['primary_failure']['code'] if response is None else response['category'] or 'observed')
    c.require(result['checks'] == expected_rows and (result['status'] == 'passed') ==
        (actual is not None and all(item['status'] == 'pass' for item in expected_rows) and not result['unknown_outcome'] and result['primary_failure'] is None),
        'candidate_result_invalid')
    validate_artifact('test-results', {**common(run.manifest()), 'status': 'pass' if result['status'] == 'passed' else 'fail', 'checks': result['checks']})
    lines = [f"Run {run.id}: candidate validation {result['status']}", 'Synthetic source and derived Ubuntu payload; ISO processing: none.']
    lines += [f"{item['check_id']}: {item['status']} expected={item['expected']} observed={item['observed']}" for item in result['checks']]
    return {'plan': plan, 'result': result, 'text': '\n'.join(lines) + '\n'}


class CandidateValidationSession:
    def __init__(self, readiness, binding, *, scenario='healthy'):
        self.readiness, self.run, self.lease = readiness, readiness.run, readiness.lease
        readiness.held(); provisioning = readiness.provisioning
        self.binding = c.validate_binding(self.run, binding)
        c.require(source_identity() == (self.run.manifest()['source_revision'], False) and self.run.manifest()['profile'] == 'smoke' and
            readiness.scenario == 'healthy' and readiness.validation_enabled is True and not self.lease._reconciliation_only and
            provisioning.target_binding == self.binding and provisioning.target_image_id == self.binding['image_id'] and
            readiness.validation_source_sha256 == v.runtime_hash(), 'candidate_validation_scope')
        c.require(not self.run.file('evidence/candidate-validation-plan.json').exists(), 'candidate_validation_reused')
        self.plan = make_plan(self.run, self.binding, readiness.target, readiness.network, scenario)
        atomic_json(self.run.file('evidence/candidate-validation-plan.json'), self.plan)
        self.receipt = {**common(self.run.manifest()), 'operation': 'candidate-validation', 'plan_sha256': self.plan['plan_sha256'],
            'status': 'pending', 'checks': rows(self.plan), 'capture': None, 'attempts': [], 'primary_failure': None,
            'unknown_outcome': False, 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
        self.response, self.started = None, False; self.save()

    def save(self):
        self.receipt['updated_at'] = now()
        atomic_json(self.run.file('evidence/candidate-observations.json'), {**common(self.run.manifest()),
            'operation': 'candidate-observations', 'plan_sha256': self.plan['plan_sha256'], 'response': self.response})
        atomic_json(self.run.file('evidence/candidate-validation.json'), self.receipt)

    def failure(self, error):
        code = getattr(error, 'code', 'candidate_validation_failed')
        if type(code) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,79}', code): code = 'candidate_validation_failed'
        provisioning = self.readiness.provisioning
        c.require(provisioning.run.id == self.run.id and provisioning.lease is self.lease, 'candidate_validation_scope')
        provisioning.held(); provisioning.failure(c.CandidateError(code, 'Candidate validation failed.'))
        if self.receipt['primary_failure'] is None: self.receipt['primary_failure'] = {'code': code, 'recorded_at': now()}
        self.receipt['status'] = 'failed'
        if self.response is None: self.receipt['checks'] = rows(self.plan, status='error', category=code)
        self.save()

    remaining = v.ValidationSession.remaining

    def validate(self):
        c.require(not self.started, 'candidate_validation_reused'); self.started = True
        deadline = time.monotonic() + TIMEOUT
        try:
            self.readiness.held(); validate_plan(self.run, self.plan)
            c.require(read_json(self.run.file('evidence/candidate-validation-plan.json')) == self.plan, 'candidate_plan_changed')
            self.readiness.require_ready(inspection_timeout=self.remaining(deadline))
            helper = images.inspect('container', self.readiness.helper, timeout=self.remaining(deadline))
            self.readiness.verify_helper(helper)
            for stamp, lifetime in ((helper['State']['StartedAt'], 180), (self.readiness.last_started_at, 300)):
                began = datetime.fromisoformat(stamp.replace('Z', '+00:00')); elapsed = (datetime.now(timezone.utc) - began).total_seconds()
                c.require(began.tzinfo is not None and 0 <= elapsed and lifetime - elapsed >= TIMEOUT + 20, 'candidate_lifetime_budget')
            inventory = self.readiness.provisioning.target_inventory('target-001')
            c.require(inventory is not None and inventory['resource_id'] == self.plan['target_resource_id'] and
                inventory['image_digest'] == self.binding['image_id'] and inventory['host'] == self.readiness.trust_address, 'candidate_endpoint_mismatch')
            budget = self.remaining(deadline, 35)
            request = {key: self.plan[key] for key in ('schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256', 'readiness_source_sha256')}
            request.update(operation='candidate-functional-v1', address=inventory['host'], scenario='healthy',
                expected_payload_sha256=next(item['sha256'] for item in self.binding['manifest']['files'] if item['path'] == 'payload.py'), timeout_seconds=budget - 2)
            runtime.decode(c.canonical(request)); encoded = base64.b64encode(c.canonical(request)).decode()
            result = v._run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
                'exec', '--user', '10001:10001', self.readiness.helper, '/opt/wormhole/venv/bin/python',
                '-I', '-B', v.VALIDATION_MOUNT, encoded), cwd=SOURCE_ROOT, timeout=budget)
            if result['status'] != 'pass' or result['log_truncated']:
                self.receipt['unknown_outcome'] = True; self.readiness.receipt['unknown_outcome'] = True; self.readiness.save()
            qualification.attempt_record(self.run, self.receipt, 'helper', 'candidate-validation', result)
            c.require(len(self.receipt['attempts']) == 1 and not self.receipt['attempts'][0].get('diagnostic_write_failed'), 'candidate_diagnostic_unavailable')
            raw = result['log']; c.require(type(raw) is bytes and len(raw) <= 65536, 'candidate_capture_invalid')
            self.receipt['capture'] = {'path': LOG, 'sha256': c.sha(raw), 'size_bytes': len(raw), 'budget_seconds': budget, 'complete': False}; self.save()
            c.require(result['status'] == 'pass' and result['log_truncated'] is False, 'candidate_probe_incomplete')
            self.remaining(deadline); self.response = parse_response(raw, self.plan, budget); self.receipt['capture']['complete'] = True
            self.receipt['checks'] = rows(self.plan, self.response['observation'], status=self.response['status'], category=self.response['category'] or 'observed')
            self.remaining(deadline)
            c.require(all(item['status'] == 'pass' for item in self.receipt['checks']), 'candidate_required_check_mismatch')
            self.receipt['status'] = 'passed'; self.save(); self.require_passed(); self.remaining(deadline)
            return deepcopy(self.receipt)
        except BaseException as error:
            if self.receipt['primary_failure'] is None: self.failure(error)
            raise

    def require_passed(self):
        report = report_candidate_validation(self.run)
        c.require(report['result']['status'] == 'passed', 'candidate_validation_required')
        return True
