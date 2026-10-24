"""One frozen one-target plan and genuine SSH/Ansible functional observations.

Caller holds the existing Run lock, Docker scope and admission lease. This is
partial reference validation, not candidate-derived validation or publication.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import time

from scripts import qualify_images as qualification
from validation import runtime
from . import images
from .contracts import validate_artifact
from .provisioning import TARGET_IMAGE
from .runs import RunError, SOURCE_ROOT, atomic_json, common, now, read_json, source_identity, _owned
from .stages import _run_process

RUNTIME = SOURCE_ROOT / 'validation/runtime.py'
VALIDATION_MOUNT = '/opt/validation/runtime.py'
TARGET_BUILD = '759b5541-a077-46ca-97a1-1cdfb782ba15'
TARGET_BUILD_SOURCE = '5c4656c683f02b4dca51ee6e24bd9b476a6c781a'
TIMEOUT = 60
SCENARIOS = runtime.SCENARIOS
CHECKS = ('os-applicability', 'package-ca-certificates', 'package-python3', 'package-python3-12',
    'package-openssh-client', 'package-openssh-server', 'package-openssh-sftp-server',
    'sshd-config-sha256', 'payload-sha256', 'payload-public-key-function')
EVIDENCE = ['evidence/validation-plan.json', 'evidence/validation-observations.json']
CATEGORIES = {'validation_timeout', 'output_bound', 'ansible_result_invalid', 'ansible_unreachable',
              'unexpected_skip', 'ansible_failed', 'configured_interpreter_unavailable'}


class ValidationError(RunError):
    pass


def require(value, code='validation_invalid'):
    if not value:
        raise ValidationError(code, 'Functional validation refused; retain bounded private diagnostics and exact accounting.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def runtime_hash():
    require(RUNTIME.is_file() and not RUNTIME.is_symlink() and RUNTIME.stat().st_nlink == 1 and
            RUNTIME.stat().st_size <= 65536, 'validation_source_changed')
    with RUNTIME.open('rb') as stream:
        raw = stream.read(65537)
    require(1 <= len(raw) <= 65536, 'validation_source_changed')
    return hashlib.sha256(raw).hexdigest()


def expectations(scenario, files):
    require(scenario in SCENARIOS, 'unsupported_validation_scenario')
    lock = images.load_lock()
    packages = {**lock['apt']['packages']['common'], **lock['apt']['packages']['target']}
    require(set(packages) == set(runtime.PACKAGES), 'validation_plan_changed')
    expected = {'os-applicability': canonical({'id': 'ubuntu', 'version_id': '24.04'})}
    expected.update({'package-' + name.replace('.', '-'): packages[name] for name in runtime.PACKAGES})
    expected.update({'sshd-config-sha256': files['sshd_config'], 'payload-sha256': files['runtime.py'],
        'payload-public-key-function': canonical({'status': 'observed', 'valid_normalized': True, 'invalid_rejected': True})})
    if scenario == 'version-expectation-mismatch':
        expected['package-python3'] += '-controlled-expectation-mismatch'
    if scenario == 'functional-expectation-mismatch':
        expected['payload-public-key-function'] = canonical({'status': 'observed', 'valid_normalized': False, 'invalid_rejected': True})
    return expected


def make_plan(run, scenario, target, network, build):
    require(build['source_revision'] == TARGET_BUILD_SOURCE, 'validation_image_mismatch')
    recipe, files = images.recipe_identity()
    expected = expectations(scenario, files)
    value = {**common(run.manifest()), 'operation': 'functional-validation-plan', 'scenario': scenario,
        'target_id': 'target-001', 'target_resource_id': target, 'network_id': network, 'target_image': TARGET_IMAGE,
        'target_build_run': TARGET_BUILD, 'target_build_source_revision': build['source_revision'],
        'recipe_sha256': recipe, 'recipe_files': files, 'validation_source_sha256': runtime_hash(),
        'collector_sha256': hashlib.sha256(runtime.TARGET_PROGRAM.encode()).hexdigest(),
        'readiness_source_sha256': hashlib.sha256((SOURCE_ROOT / 'readiness/runtime.py').read_bytes()).hexdigest(),
        'applicability': {'os_id': 'ubuntu', 'os_version': '24.04', 'platform': 'linux/amd64'},
        'negative_kind': 'controlled-expectation' if scenario.endswith('expectation-mismatch') else
            'controlled-input' if scenario != 'healthy' else None,
        'candidate_binding': 'not-implemented; qualified stock reference image only',
        'checks': [{'check_id': check, 'target_id': 'target-001', 'required': True, 'expected': expected[check]} for check in CHECKS]}
    return {**value, 'plan_sha256': digest(value)}


def validate_plan(run, plan):
    require(type(plan) is dict and plan.get('scenario') in SCENARIOS and common(plan) == common(run.manifest()) and
        plan.get('mode') == 'container-reference' and plan.get('source_dirty') is False and
        type(plan.get('target_resource_id')) is str and re.fullmatch('[a-f0-9]{64}', plan['target_resource_id']) and
        type(plan.get('network_id')) is str and re.fullmatch('[a-f0-9]{64}', plan['network_id']) and
        type(plan.get('target_build_source_revision')) is str and re.fullmatch('[a-f0-9]{40}', plan['target_build_source_revision']),
        'validation_plan_changed')
    expected = make_plan(run, plan['scenario'], plan['target_resource_id'], plan['network_id'],
                         {'source_revision': plan['target_build_source_revision']})
    require(plan == expected, 'validation_plan_changed')
    return plan


def rows(plan, observed=None, *, status='error', category='not-observed'):
    actual = {}
    if observed is not None:
        runtime.observation(observed)
        actual = {'os-applicability': canonical(observed['os']), 'sshd-config-sha256': observed['sshd_config_sha256'],
                  'payload-sha256': observed['payload_sha256'], 'payload-public-key-function': canonical(observed['function'])}
        actual.update({'package-' + name.replace('.', '-'): version if version is not None else 'MISSING'
                       for name, version in observed['packages'].items()})
    return [{**check, 'status': ('unverified' if check['check_id'] == 'payload-public-key-function' and
        observed['function']['status'] == 'unverified' else 'pass' if actual[check['check_id']] == check['expected'] else 'fail') if observed is not None else status,
        'observed': actual[check['check_id']] if observed is not None else category,
        'evidence': list(EVIDENCE)} for check in plan['checks']]


def parse_response(raw, plan, budget):
    try:
        require(type(raw) is bytes and 1 <= len(raw) <= 65536, 'validation_probe_invalid')
        value = json.loads(raw, object_pairs_hook=runtime.unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        fields = {'schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256', 'status', 'category',
            'returncode', 'timed_out', 'truncated', 'duration_seconds', 'observation', 'private_diagnostic'}
        require(type(value) is dict and set(value) == fields and all(value[key] == plan[key] for key in
            ('schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256')) and
            value['status'] in {'pass', 'fail', 'error', 'unreachable', 'skipped'} and
            type(value['returncode']) is int and -(2**31) <= value['returncode'] < 2**31 and
            type(value['timed_out']) is bool and type(value['truncated']) is bool and
            type(value['duration_seconds']) in (int, float) and math.isfinite(value['duration_seconds']) and
            0 <= value['duration_seconds'] <= budget and type(value['private_diagnostic']) is str and
            len(value['private_diagnostic'].encode()) <= 8192 and
            (value['category'] is None or type(value['category']) is str and value['category'] in CATEGORIES) and
            (value['status'] == 'pass') == (value['category'] is None and value['returncode'] == 0 and
                not value['timed_out'] and not value['truncated'] and value['observation'] is not None), 'validation_probe_invalid')
        require(value['observation'] is None or value['status'] == 'pass', 'validation_probe_invalid')
        if value['observation'] is not None:
            runtime.observation(value['observation'])
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise ValidationError('validation_probe_invalid', 'Expected a complete fixed helper result.') from None


def validate_result(run, plan, result, observation_record):
    validate_plan(run, plan)
    result_fields = set(common(run.manifest())) | {'operation', 'scenario', 'plan_sha256', 'status', 'target_id',
        'target_resource_id', 'target_image', 'checks', 'attempts', 'primary_failure', 'unknown_outcome',
        'runtime_pipeline_complete', 'production_iso_eligible', 'candidate_binding', 'updated_at', 'capture'}
    require(type(result) is dict and set(result) == result_fields and common(result) == common(run.manifest()) and
        result.get('operation') == 'ssh-ansible-functional-validation' and result.get('plan_sha256') == plan['plan_sha256'] and
        result.get('scenario') == plan['scenario'] and result.get('target_id') == 'target-001' and
        result.get('target_resource_id') == plan['target_resource_id'] and result.get('target_image') == TARGET_IMAGE and
        result.get('status') in {'passed', 'failed'} and result.get('runtime_pipeline_complete') is False and
        result.get('production_iso_eligible') is False and type(result.get('unknown_outcome')) is bool and
        type(result.get('checks')) is list and result['candidate_binding'] == plan['candidate_binding'] and
        type(result['updated_at']) is str and len(result['updated_at']) <= 40 and
        type(result['attempts']) is list and len(result['attempts']) <= 1, 'validation_result_invalid')
    failure = result['primary_failure']
    require(failure is None or type(failure) is dict and set(failure) == {'code', 'recorded_at'} and
        type(failure['code']) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', failure['code']) and
        type(failure['recorded_at']) is str and len(failure['recorded_at']) <= 40, 'validation_result_invalid')
    require((result['status'] == 'failed') == (failure is not None), 'validation_result_invalid')
    for item in result['attempts']:
        require(type(item) is dict and set(item) == {'role', 'stage', 'status', 'returncode', 'duration_seconds',
            'log_truncated', 'private_log'} and item['role'] == 'helper' and item['stage'] == 'functional-validation' and
            item['status'] in {'pass', 'fail', 'error', 'timeout', 'unsupported'} and
            (item['returncode'] is None or type(item['returncode']) is int) and type(item['log_truncated']) is bool and
            type(item['duration_seconds']) in (int, float) and math.isfinite(item['duration_seconds']) and
            0 <= item['duration_seconds'] <= TIMEOUT + 2 and
            item['private_log'] == 'private/qualification-helper-functional-validation-0.log', 'validation_result_invalid')
    require(type(observation_record) is dict and set(observation_record) == set(common(run.manifest())) | {
        'operation', 'plan_sha256', 'status', 'category', 'observation'} and
        common(observation_record) == common(run.manifest()) and observation_record['operation'] == 'functional-observations' and
        observation_record['plan_sha256'] == plan['plan_sha256'] and
        observation_record['status'] in {'pass', 'fail', 'error', 'unreachable', 'skipped', 'unverified'} and
        type(observation_record['category']) is str and len(observation_record['category']) <= 80 and
        (observation_record['status'] == 'pass') == (observation_record['observation'] is not None) and
        (observation_record['status'] != 'pass' or observation_record['category'] == 'observed'),
        'validation_result_invalid')
    observed = observation_record['observation']
    capture = result['capture']
    if capture is not None:
        require(type(capture) is dict and set(capture) == {'private_log', 'sha256', 'size_bytes', 'budget_seconds', 'complete'} and
            len(result['attempts']) == 1 and capture['private_log'] == result['attempts'][0]['private_log'] and
            type(capture['sha256']) is str and re.fullmatch('[a-f0-9]{64}', capture['sha256']) and
            type(capture['size_bytes']) is int and 0 <= capture['size_bytes'] <= 65536 and
            type(capture['complete']) is bool and type(capture['budget_seconds']) in (int, float) and
            .1 <= capture['budget_seconds'] <= 35, 'validation_capture_invalid')
        path = run.file(capture['private_log']); _owned(path)
        with path.open('rb') as stream:
            raw = stream.read(65537)
        require(len(raw) == capture['size_bytes'] and hashlib.sha256(raw).hexdigest() == capture['sha256'], 'validation_capture_invalid')
        if capture['complete']:
            value = parse_response(raw, plan, capture['budget_seconds'])
            require(result['attempts'][0]['status'] == 'pass' and result['attempts'][0]['returncode'] == 0 and
                not result['attempts'][0]['log_truncated'] and
                observation_record['observation'] == value['observation'] and observation_record['status'] == value['status'] and
                observation_record['category'] == (value['category'] or 'observed'), 'validation_capture_invalid')
        else:
            require(observed is None and result['status'] == 'failed', 'validation_capture_invalid')
    else:
        require(observed is None and result['status'] == 'failed' and not result['attempts'], 'validation_capture_invalid')
    expected_rows = rows(plan, observed, status=observation_record['status'], category=observation_record['category'])
    require(result['checks'] == expected_rows and (observed is None or observation_record['status'] == 'pass'), 'validation_result_invalid')
    validate_artifact('test-results', {**common(result), 'status': 'pass' if result['status'] == 'passed' else 'fail', 'checks': result['checks']})
    passing = observed is not None and all(item['status'] == 'pass' for item in result['checks']) and \
        result.get('primary_failure') is None and not result['unknown_outcome']
    require((result['status'] == 'passed') == passing, 'validation_result_invalid')
    return result


def report_validation(run):
    plan = read_json(run.file('evidence/validation-plan.json'))
    result = read_json(run.file('evidence/validation.json'))
    observed = read_json(run.file('evidence/validation-observations.json'))
    validate_result(run, plan, result, observed)
    lines = [f"Run {run.id}: functional validation {result['status']}",
        'Qualified stock reference image; candidate binding and complete pipeline remain unimplemented.']
    for item in result['checks']:
        lines.extend([f"{item['target_id']} / {item['check_id']}: {item['status']}",
            '  expected: ' + item['expected'], '  observed: ' + item['observed'],
            '  evidence: ' + ', '.join(item['evidence'])])
    return {'result': deepcopy(result), 'text': '\n'.join(lines) + '\n'}


class ValidationSession:
    """One attempt; fixed scenarios only; no target repair or new allocation.

    before_probe is trusted in-process acceptance orchestration, never CLI,
    ticket text or serialized input. Only the unreachable scenario accepts it.
    """
    def __init__(self, readiness, *, scenario='healthy'):
        self.readiness, self.run, self.lease = readiness, readiness.run, readiness.lease
        readiness.held()
        require(scenario in SCENARIOS and getattr(readiness, 'validation_enabled', False) is True and
            readiness.scenario == 'healthy' and not self.lease._reconciliation_only, 'validation_scope')
        revision, dirty = source_identity()
        manifest = self.run.manifest()
        require(revision == manifest['source_revision'] and dirty is False and manifest['source_dirty'] is False and
            readiness.validation_source_sha256 == runtime_hash() and readiness.validation_bind_path ==
            self.run.file('private/helper-source/validation.py'), 'validation_source_changed')
        require(not self.run.file('evidence/validation-plan.json').exists() and
                not self.run.file('evidence/validation.json').exists(), 'validation_attempt_reused')
        # Original build provenance is not overwritten with this controller SHA.
        build = qualification.build_reference(TARGET_BUILD, 'target')
        require(build['image_id'] == TARGET_IMAGE and build['source_revision'] == TARGET_BUILD_SOURCE, 'validation_image_mismatch')
        self.scenario = scenario
        self.plan = make_plan(self.run, scenario, readiness.target, readiness.network, build)
        atomic_json(self.run.file('evidence/validation-plan.json'), self.plan)
        self.receipt = {**common(manifest), 'operation': 'ssh-ansible-functional-validation', 'scenario': scenario,
            'plan_sha256': self.plan['plan_sha256'], 'status': 'pending', 'target_id': 'target-001',
            'target_resource_id': readiness.target, 'target_image': TARGET_IMAGE,
            'checks': rows(self.plan, status='unverified', category='not-attempted'), 'attempts': [],
            'primary_failure': None, 'unknown_outcome': False, 'runtime_pipeline_complete': False,
            'production_iso_eligible': False, 'candidate_binding': self.plan['candidate_binding'], 'capture': None}
        self.observed = self.observation_record('unverified', 'not-attempted', None)
        self.started = False
        self.save()

    def observation_record(self, status, category, observed):
        return {**common(self.run.manifest()), 'operation': 'functional-observations', 'plan_sha256': self.plan['plan_sha256'],
                'status': status, 'category': category, 'observation': observed}

    def save(self):
        self.receipt['updated_at'] = now()
        atomic_json(self.run.file('evidence/validation-observations.json'), self.observed)
        atomic_json(self.run.file('evidence/validation.json'), self.receipt)

    def failure(self, error, *, status='error'):
        code = getattr(error, 'code', 'validation_failed')
        code = code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', code) else 'validation_failed'
        # Durable overall failure precedes the terminal component write. A crash
        # cannot leave a terminal validation failure hidden from WORM008 recovery.
        self.readiness.held()
        provisioning = self.readiness.provisioning
        require(provisioning.run.id == self.run.id and provisioning.run.path == self.run.path and
                provisioning.lease is self.lease, 'validation_scope')
        provisioning.held()
        prior = provisioning.receipt['primary_failure']
        if prior is None or prior.get('code') != code:
            provisioning.failure(ValidationError(code, 'Dependent functional validation failed.'))
        if self.receipt['primary_failure'] is None:
            self.receipt['primary_failure'] = {'code': code, 'recorded_at': now()}
        self.receipt['status'] = 'failed'
        if self.observed['observation'] is None:
            self.observed = self.observation_record(status, code, None)
            self.receipt['checks'] = rows(self.plan, status=status, category=code)
        self.save()
        # Established readiness remains its own historical fact. Unknown outer
        # helper exec is separately propagated to its cleanup safety guard.

    def remaining(self, deadline, maximum=20):
        left = deadline - time.monotonic()
        require(left > .1, 'validation_timeout')
        return min(left, maximum)

    def validate(self, *, before_probe=None):
        require(not self.started, 'validation_attempt_reused')
        self.started = True
        deadline = time.monotonic() + TIMEOUT
        try:
            require((self.scenario == 'unreachable' and callable(before_probe)) or
                (self.scenario != 'unreachable' and before_probe is None), 'invalid_validation_coordinator')
            self.readiness.held()
            validate_plan(self.run, self.plan)
            require(read_json(self.run.file('evidence/validation-plan.json')) == self.plan, 'validation_plan_changed')
            self.readiness.require_ready()
            self.remaining(deadline)
            helper = images.inspect('container', self.readiness.helper, timeout=self.remaining(deadline))
            self.readiness.verify_helper(helper)
            for stamp, lifetime in ((helper['State']['StartedAt'], 180), (self.readiness.last_started_at, 300)):
                started = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
                elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                require(started.tzinfo is not None and 0 <= elapsed and lifetime - elapsed >= TIMEOUT + 20,
                        'validation_lifetime_budget_insufficient')
            address = self.readiness.trust_address
            inventory = self.readiness.provisioning.receipt['inventory']
            require(common(inventory) == common(self.run.manifest()) and len(inventory['targets']) == 1 and
                inventory['targets'][0]['resource_id'] == self.plan['target_resource_id'] and
                inventory['targets'][0]['host'] == address, 'validation_endpoint_mismatch')
            # The source-only negative callback stops the exact owned target after
            # a successful snapshot, retaining that frozen provider endpoint.
            if before_probe is not None:
                before_probe()
                self.remaining(deadline)
            self.readiness.verify_helper(images.inspect('container', self.readiness.helper,
                                                       timeout=self.remaining(deadline)))
            budget = self.remaining(deadline, 35)
            require(budget > 3, 'validation_timeout')
            request = {'schema_version': '1.0', 'run_id': self.run.id, 'source_revision': self.run.manifest()['source_revision'],
                'target_id': 'target-001', 'address': address, 'scenario': self.scenario,
                'plan_sha256': self.plan['plan_sha256'], 'expected_payload_sha256': self.plan['recipe_files']['runtime.py'],
                'readiness_source_sha256': self.plan['readiness_source_sha256'], 'timeout_seconds': budget - 2}
            runtime.decode(canonical(request).encode())
            encoded = base64.b64encode(canonical(request).encode()).decode()
            result = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
                'exec', '--user', '10001:10001', self.readiness.helper, '/opt/wormhole/venv/bin/python',
                '-I', '-B', VALIDATION_MOUNT, encoded), cwd=SOURCE_ROOT, timeout=budget)
            if result['status'] == 'timeout':
                self.receipt['unknown_outcome'] = True
                self.readiness.receipt['unknown_outcome'] = True
                self.readiness.save()
            qualification.attempt_record(self.run, self.receipt, 'helper', 'functional-validation', result)
            require(self.receipt['attempts'] and not self.receipt['attempts'][-1].get('diagnostic_write_failed'), 'validation_diagnostic_unavailable')
            raw = result['log']
            require(type(raw) is bytes and len(raw) <= 65536, 'validation_probe_invalid')
            self.receipt['capture'] = {'private_log': self.receipt['attempts'][-1]['private_log'],
                'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw), 'budget_seconds': budget, 'complete': False}
            self.save()
            require(result['status'] == 'pass' and not result['log_truncated'], 'validation_probe_incomplete')
            self.remaining(deadline)
            value = parse_response(raw, self.plan, budget)
            self.receipt['capture']['complete'] = True
            category = value['category'] or 'observed'
            self.observed = self.observation_record(value['status'], category, value['observation'])
            self.receipt['checks'] = rows(self.plan, value['observation'], status=value['status'], category=category)
            self.remaining(deadline)  # A late parse/row derivation cannot establish success.
            self.receipt['status'] = 'passed' if all(x['status'] == 'pass' for x in self.receipt['checks']) else 'failed'
            if self.receipt['status'] != 'passed':
                error = ValidationError(value['category'] or 'required_check_mismatch', 'Required functional checks did not all pass.')
                self.failure(error, status=value['status'] if value['status'] != 'pass' else 'fail')
                raise error
            self.save()
            self.require_passed()
            self.remaining(deadline)
            return deepcopy(self.receipt)
        except BaseException as error:
            if self.receipt['primary_failure'] is None:
                self.failure(error)
            raise

    def require_passed(self):
        validate_result(self.run, self.plan, self.receipt, self.observed)
        require(self.receipt['status'] == 'passed', 'functional_validation_required')
        return True
