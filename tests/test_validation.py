"""No Docker/SSH/Ansible allocation: fixed protocol/policy and read-only collector fixtures."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from validation import runtime
from readiness import runtime as rr
from wormhole import validation as v
from wormhole.runs import atomic_json, common, create_run, read_json

SHA, TARGET, NETWORK, HELPER = 'a' * 40, 'b' * 64, 'c' * 64, 'e' * 64


def observed():
    lock = v.images.load_lock()
    return {'schema_version': '1.0', 'os': {'id': 'ubuntu', 'version_id': '24.04'},
        'packages': {**lock['apt']['packages']['common'], **lock['apt']['packages']['target']},
        'sshd_config_sha256': hashlib.sha256((v.SOURCE_ROOT / 'images/sshd_config').read_bytes()).hexdigest(),
        'payload_sha256': hashlib.sha256((v.SOURCE_ROOT / 'images/runtime.py').read_bytes()).hexdigest(),
        'function': {'status': 'observed', 'valid_normalized': True, 'invalid_rejected': True}}


class ValidationPolicy(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='wormhole-validation-synthetic-')
        self.addCleanup(folder.cleanup)
        self.run = create_run(Path(folder.name) / 'runs', fixture=False, identity=(SHA, False))
        self.lease = SimpleNamespace(_reconciliation_only=False)
        self.ready = SimpleNamespace(run=self.run, lease=self.lease, target=TARGET, network=NETWORK, helper=HELPER,
            scenario='healthy', validation_enabled=True, validation_source_sha256=v.runtime_hash(),
            validation_bind_path=self.run.file('private/helper-source/validation.py'),
            held=Mock(), require_ready=Mock(return_value=True), verify_helper=Mock(),
            trust_address='172.31.77.2', last_started_at=datetime.now(timezone.utc).isoformat(),
            receipt={'status': 'ready', 'primary_failure': None, 'unknown_outcome': False}, save=Mock())
        self.ready.provisioning = SimpleNamespace(run=self.run, lease=self.lease, held=Mock(),
            receipt={'primary_failure': None, 'secondary_failures': [], 'inventory': {**common(self.run.manifest()), 'targets': [
            {'resource_id': TARGET, 'target_id': 'target-001', 'host': self.ready.trust_address}]}})
        def overall_failure(error):
            receipt = self.ready.provisioning.receipt
            value = {'code': error.code}
            if receipt['primary_failure'] is None: receipt['primary_failure'] = value
            else: receipt['secondary_failures'].append(value)
            atomic_json(self.run.file('private/overall-failure-fixture.json'), receipt)
        self.ready.provisioning.failure = overall_failure
        def failure(error):
            self.ready.receipt['status'] = 'failed'
            self.ready.receipt['primary_failure'] = {'code': error.code}
        self.ready.failure = failure
        self.patches = [patch.object(v, 'source_identity', return_value=(SHA, False)),
            patch.object(v.qualification, 'build_reference', return_value={'image_id': v.TARGET_IMAGE, 'source_revision': v.TARGET_BUILD_SOURCE}),
            patch.object(v.images, 'inspect', return_value={'State': {'StartedAt': datetime.now(timezone.utc).isoformat()}}),
            patch.object(v.images, 'docker_configuration', return_value='/synthetic/empty-config')]
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)

    def response(self, arguments, **options):
        self.assertEqual(arguments[0], 'docker')
        self.assertEqual(arguments[arguments.index('exec') + 3], HELPER)
        self.assertIn('/opt/validation/runtime.py', arguments)
        self.assertNotIn('shell', arguments)
        request = runtime.decode(base64.b64decode(arguments[-1]))
        value = {**{key: request[key] for key in ('schema_version', 'run_id', 'source_revision', 'target_id', 'plan_sha256')},
            'status': 'pass', 'category': None, 'returncode': 0, 'timed_out': False, 'truncated': False,
            'duration_seconds': .01, 'observation': observed(), 'private_diagnostic': 'synthetic private diagnostic'}
        return {'status': 'pass', 'returncode': 0, 'duration_seconds': .02, 'log_truncated': False, 'log': json.dumps(value).encode()}

    def test_complete_plan_actual_protocol_and_readable_json_parity_remain_partial(self):
        session = v.ValidationSession(self.ready)
        self.assertEqual([item['check_id'] for item in read_json(self.run.file('evidence/validation-plan.json'))['checks']], list(v.CHECKS))
        with patch.object(v, '_run_process', side_effect=self.response):
            result = session.validate()
        self.assertTrue(session.require_passed()); self.assertEqual(result['status'], 'passed')
        self.assertFalse(result['runtime_pipeline_complete']); self.assertFalse(result['production_iso_eligible'])
        report = v.report_validation(self.run)
        self.assertEqual(report['result']['checks'], result['checks'])
        for item in result['checks']:
            self.assertIn(item['check_id'] + ': ' + item['status'], report['text'])
            self.assertIn('expected: ' + item['expected'], report['text'])
            self.assertIn('observed: ' + item['observed'], report['text'])
        self.assertNotIn('synthetic private diagnostic', json.dumps(report))
        self.assertEqual(len(result['checks']), 10)
        with self.assertRaises(v.ValidationError): session.validate()
        with self.assertRaises(v.ValidationError): v.ValidationSession(self.ready)

    def test_controlled_expectation_mismatch_retains_observed_healthy_payload_without_repair(self):
        for scenario, check in (('version-expectation-mismatch', 'package-python3'),
                                ('functional-expectation-mismatch', 'payload-public-key-function')):
            with self.subTest(scenario=scenario):
                # Independent attempt/run and target context, no retesting a repaired target.
                self.run = create_run(self.run.path.parent, fixture=False, identity=(SHA, False))
                self.ready.run = self.run
                self.ready.provisioning.run = self.run
                self.ready.validation_bind_path = self.run.file('private/helper-source/validation.py')
                self.ready.provisioning.receipt['inventory'].update(common(self.run.manifest()))
                self.ready.receipt.update(status='ready', primary_failure=None)
                session = v.ValidationSession(self.ready, scenario=scenario)
                with patch.object(v, '_run_process', side_effect=self.response), self.assertRaises(v.ValidationError): session.validate()
                report = v.report_validation(self.run)
                self.assertEqual(session.plan['negative_kind'], 'controlled-expectation')
                self.assertEqual([x['check_id'] for x in report['result']['checks'] if x['status'] == 'fail'], [check])
                self.assertEqual(len(report['result']['checks']), 10)
                self.assertEqual(session.observed['observation']['function'], observed()['function'])

    def test_unreachable_skip_and_interpreter_failure_are_complete_nonpassing_rows(self):
        for status, category, scenario in (('unreachable', 'ansible_unreachable', 'unreachable'),
            ('skipped', 'unexpected_skip', 'unexpected-skip'), ('fail', 'configured_interpreter_unavailable', 'configured-interpreter-unavailable')):
            with self.subTest(category=category):
                self.run = create_run(self.run.path.parent, fixture=False, identity=(SHA, False)); self.ready.run = self.run
                self.ready.provisioning.run = self.run
                self.ready.validation_bind_path = self.run.file('private/helper-source/validation.py')
                self.ready.provisioning.receipt['inventory'].update(common(self.run.manifest()))
                self.ready.receipt.update(status='ready', primary_failure=None)
                session = v.ValidationSession(self.ready, scenario=scenario)
                def failed(*args, **kwargs):
                    response = self.response(*args, **kwargs); value = json.loads(response['log'])
                    value.update(status=status, category=category, returncode=2, observation=None)
                    response['log'] = json.dumps(value).encode(); return response
                callback = Mock() if scenario == 'unreachable' else None
                with patch.object(v, '_run_process', side_effect=failed), self.assertRaises(v.ValidationError): session.validate(before_probe=callback)
                if callback is not None: callback.assert_called_once_with()
                self.assertEqual({x['status'] for x in v.report_validation(self.run)['result']['checks']}, {status})
                self.assertIsNone(self.ready.receipt['primary_failure'])
                self.assertEqual(session.receipt['primary_failure']['code'], category)

    def test_readiness_refusal_and_changed_plan_block_before_transport_with_all_rows(self):
        session = v.ValidationSession(self.ready)
        self.ready.require_ready.side_effect = v.ValidationError('readiness_required', 'synthetic known refusal')
        with patch.object(v, '_run_process', side_effect=AssertionError('No transport when readiness blocked')), self.assertRaises(v.ValidationError): session.validate()
        self.assertEqual({x['observed'] for x in session.receipt['checks']}, {'readiness_required'})
        self.assertIsNone(session.receipt['capture']); self.assertEqual(v.report_validation(self.run)['result']['status'], 'failed')
        self.ready.require_ready.reset_mock(side_effect=True)

    def test_stale_plan_wrong_run_and_incomplete_or_malformed_response_cannot_pass(self):
        for mutation in ('plan', 'wrong-run', 'missing', 'duplicate', 'truncated', 'timeout'):
            with self.subTest(mutation=mutation):
                self.run = create_run(self.run.path.parent, fixture=False, identity=(SHA, False)); self.ready.run = self.run
                self.ready.provisioning.run = self.run
                self.ready.validation_bind_path = self.run.file('private/helper-source/validation.py')
                self.ready.provisioning.receipt['inventory'].update(common(self.run.manifest()))
                self.ready.receipt.update(status='ready', primary_failure=None, unknown_outcome=False)
                session = v.ValidationSession(self.ready)
                if mutation == 'plan':
                    plan = deepcopy(session.plan); plan['checks'][0]['required'] = False
                    atomic_json(self.run.file('evidence/validation-plan.json'), plan)
                def malformed(*args, **kwargs):
                    self.assertNotEqual(mutation, 'plan', 'Changed contract must refuse before transport')
                    result = self.response(*args, **kwargs)
                    if mutation == 'wrong-run':
                        value = json.loads(result['log']); value['run_id'] = '12345678-1234-4234-9234-123456789abc'; result['log'] = json.dumps(value).encode()
                    elif mutation == 'missing': result['log'] = b'{}'
                    elif mutation == 'duplicate': result['log'] = b'{"status":"pass","status":"pass"}'
                    elif mutation == 'truncated': result['log_truncated'] = True
                    elif mutation == 'timeout': result['status'] = 'timeout'; result['returncode'] = None
                    return result
                with patch.object(v, '_run_process', side_effect=malformed), self.assertRaises(v.ValidationError): session.validate()
                self.assertEqual(len(session.receipt['checks']), 10)
                self.assertNotIn('pass', {x['status'] for x in session.receipt['checks']})
                self.assertEqual(session.receipt['unknown_outcome'], mutation == 'timeout')

    def test_saved_report_requires_original_capture_and_rejects_edited_summary_rows_and_fields(self):
        session = v.ValidationSession(self.ready)
        with patch.object(v, '_run_process', side_effect=self.response): session.validate()
        original = deepcopy(session.receipt)
        for change in (lambda result: result.update(extra='forbidden'), lambda result: result['checks'].pop(),
                       lambda result: result['checks'][0].update(required=False)):
            result = deepcopy(original); change(result); atomic_json(self.run.file('evidence/validation.json'), result)
            with self.assertRaises(v.ValidationError): v.report_validation(self.run)
        atomic_json(self.run.file('evidence/validation.json'), original)
        actual = deepcopy(session.observed)
        actual['observation']['sshd_config_sha256'] = 'f' * 64
        forged = deepcopy(original); forged['checks'] = v.rows(session.plan, actual['observation'])
        forged['status'] = 'failed'; forged['primary_failure'] = {'code': 'required_check_mismatch', 'recorded_at': original['updated_at']}
        atomic_json(self.run.file('evidence/validation-observations.json'), actual)
        atomic_json(self.run.file('evidence/validation.json'), forged)
        with self.assertRaises(v.ValidationError): v.report_validation(self.run)
        atomic_json(self.run.file('evidence/validation-observations.json'), session.observed)
        atomic_json(self.run.file('evidence/validation.json'), original)
        log = self.run.file(original['capture']['private_log'])
        log.write_bytes(b'{}')
        with self.assertRaises(v.ValidationError): v.report_validation(self.run)
        log.unlink()
        with self.assertRaises((v.ValidationError, FileNotFoundError)): v.report_validation(self.run)

    def test_payload_hash_mismatch_keeps_function_unexecuted_unverified(self):
        session = v.ValidationSession(self.ready)
        def changed(*args, **kwargs):
            response = self.response(*args, **kwargs); value = json.loads(response['log'])
            value['observation']['payload_sha256'] = 'f' * 64
            value['observation']['function'] = {'status': 'unverified', 'valid_normalized': None, 'invalid_rejected': None}
            response['log'] = json.dumps(value).encode(); return response
        with patch.object(v, '_run_process', side_effect=changed), self.assertRaises(v.ValidationError): session.validate()
        by_id = {x['check_id']: x for x in v.report_validation(self.run)['result']['checks']}
        self.assertEqual(by_id['payload-sha256']['status'], 'fail')
        self.assertEqual(by_id['payload-public-key-function']['status'], 'unverified')

    def test_lifetime_budget_and_late_trusted_callback_refuse_before_transport(self):
        session = v.ValidationSession(self.ready, scenario='unreachable')
        with patch.object(v, 'TIMEOUT', .1), patch.object(v, '_run_process', side_effect=AssertionError('No late probe')):
            import time
            with self.assertRaises(v.ValidationError): session.validate(before_probe=lambda: time.sleep(.12))
        self.assertEqual(session.receipt['primary_failure']['code'], 'validation_timeout')
        self.assertEqual(len(session.receipt['checks']), 10)
        self.assertIsNone(self.ready.receipt['primary_failure'])

    def test_overall_primary_is_durable_before_component_terminal_write_and_survives_its_failure(self):
        session = v.ValidationSession(self.ready)
        def interrupted_save():
            persisted = read_json(self.run.file('private/overall-failure-fixture.json'))
            self.assertEqual(persisted['primary_failure']['code'], 'required_check_mismatch')
            raise OSError('synthetic component save interruption')
        with patch.object(session, 'save', side_effect=interrupted_save), self.assertRaises(OSError):
            session.failure(v.ValidationError('required_check_mismatch', 'synthetic'))
        self.assertEqual(self.ready.provisioning.receipt['primary_failure']['code'], 'required_check_mismatch')
        self.assertIsNone(self.ready.receipt['primary_failure']); self.assertEqual(self.ready.receipt['status'], 'ready')
        self.assertEqual(read_json(self.run.file('evidence/validation.json'))['status'], 'pending')

    def test_late_response_parser_cannot_declare_pass_after_absolute_deadline(self):
        session = v.ValidationSession(self.ready)
        clock = [0.]
        parser = v.parse_response
        def delayed_parser(*args, **kwargs):
            value = parser(*args, **kwargs)
            clock[0] = v.TIMEOUT + 1
            return value
        with patch.object(v.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(v, 'parse_response', side_effect=delayed_parser), \
             patch.object(v, '_run_process', side_effect=self.response), self.assertRaises(v.ValidationError):
            session.validate()
        self.assertEqual(session.receipt['status'], 'failed')
        self.assertEqual(self.ready.provisioning.receipt['primary_failure']['code'], 'validation_timeout')


class RuntimeProtocol(unittest.TestCase):
    def request(self, scenario='healthy'):
        return {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc', 'source_revision': SHA,
            'target_id': 'target-001', 'address': '172.31.77.2', 'scenario': scenario, 'plan_sha256': 'a' * 64,
            'expected_payload_sha256': observed()['payload_sha256'], 'readiness_source_sha256': 'b' * 64, 'timeout_seconds': 20}

    def test_only_fixed_bounded_requests_and_observations_are_accepted(self):
        value = self.request(); self.assertEqual(runtime.decode(json.dumps(value).encode()), value)
        for change in (lambda x: x.update(command='arbitrary'), lambda x: x.update(address='127.0.0.1'),
            lambda x: x.update(scenario='repair'), lambda x: x.update(timeout_seconds=float('nan')), lambda x: x.update(target_id='foreign')):
            bad = deepcopy(value); change(bad)
            with self.assertRaises(ValueError): runtime.decode(json.dumps(bad).encode())
        bad = observed(); bad['packages']['unknown'] = 'invented'
        with self.assertRaises(ValueError): runtime.observation(bad)
        with self.assertRaises(ValueError): runtime.decode(b'{"schema_version":"1.0","schema_version":"1.0"}')

    def test_fixed_ansible_argv_ssh_options_and_terminal_flags(self):
        for scenario, kind in (('healthy', 'pass'), ('unexpected-skip', 'skipped'), ('unreachable', 'unreachable'),
                               ('healthy', 'missing'), ('healthy', 'nonzero'), ('healthy', 'truncated')):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='wormhole-validation-helper-synthetic-') as temporary:
                root = Path(temporary)
                fake = SimpleNamespace(ROOT=root, qualified_runtime=lambda: SimpleNamespace(identity=lambda: self.request()['run_id']),
                    prepare_auth=Mock(), ssh_options=rr.ssh_options, environment=rr.environment)
                def capture(argv, *_):
                    self.assertEqual(argv[argv.index('-m') + 1], 'ansible.builtin.command')
                    args = json.loads(argv[argv.index('-a') + 1]); command = args['argv']
                    self.assertIs(args['expand_argument_vars'], False)
                    self.assertEqual(command[:4], ['/usr/bin/python3', '-I', '-B', '-c'])
                    self.assertEqual(command[4], runtime.TARGET_PROGRAM)
                    inventory = json.loads(Path(argv[argv.index('-i') + 1]).read_text())['all']['hosts']['target-001']
                    self.assertFalse(inventory['ansible_ssh_use_tty']); self.assertEqual(inventory['ansible_ssh_transfer_method'], 'piped')
                    self.assertIn('StrictHostKeyChecking=yes', inventory['ansible_ssh_args'])
                    self.assertNotIn('ansible_password', inventory)
                    if scenario == 'unexpected-skip': self.assertIn('--check', argv)
                    results = root / 'functional-validation/results'; results.mkdir()
                    tree = {'cmd': command, 'rc': 0, 'stdout': json.dumps(observed()), 'stderr': '', 'msg': '', 'changed': True}
                    if kind == 'skipped': tree.update(skipped=True)
                    if kind == 'unreachable': tree = {'unreachable': True, 'msg': 'Connection refused'}
                    if kind != 'missing': (results / 'target-001').write_text(json.dumps(tree))
                    return {'returncode': 2 if kind in ('unreachable', 'nonzero') else 0, 'timed_out': False,
                        'truncated': kind == 'truncated', 'log': '', 'duration_seconds': .01}
                fake.capture = capture
                result = runtime.collect(self.request(scenario), fake)
                self.assertEqual(result['status'], kind if kind in ('pass', 'skipped', 'unreachable') else 'fail' if kind == 'nonzero' else 'error')
                self.assertEqual(result['observation'] is not None, kind == 'pass')


@unittest.skipUnless(os.name == 'posix', 'Real read-only dpkg collector fixture requires Linux')
class TargetCollector(unittest.TestCase):
    def test_actual_fixed_collector_hashes_imported_payload_and_blocks_changed_bytes(self):
        import contextlib
        import pathlib
        with tempfile.TemporaryDirectory(prefix='wormhole-target-collector-synthetic-') as temporary:
            root = Path(temporary)
            mapping = {'/usr/lib/os-release': root / 'os-release', '/etc/ssh/sshd_config': root / 'sshd_config',
                       '/opt/wormhole/runtime.py': root / 'runtime.py'}
            mapping['/usr/lib/os-release'].write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            mapping['/etc/ssh/sshd_config'].write_bytes((v.SOURCE_ROOT / 'images/sshd_config').read_bytes())
            payload = (v.SOURCE_ROOT / 'images/runtime.py').read_bytes(); mapping['/opt/wormhole/runtime.py'].write_bytes(payload)
            original_spec = importlib.util.spec_from_file_location
            def spec(name, location): return original_spec(name, mapping.get(str(location), location))
            for match in (True, False):
                expected = hashlib.sha256(payload).hexdigest() if match else 'f' * 64
                output = io.StringIO()
                with patch.object(pathlib, 'Path', side_effect=lambda path: mapping.get(str(path), Path(path))), \
                     patch.object(importlib.util, 'spec_from_file_location', side_effect=spec), \
                     patch('sys.argv', ['fixed-collector', expected]), contextlib.redirect_stdout(output):
                    exec(compile(runtime.TARGET_PROGRAM, '<fixed-target-collector>', 'exec'), {})
                result = json.loads(output.getvalue())
                self.assertEqual(result['payload_sha256'], hashlib.sha256(payload).hexdigest())
                self.assertEqual(set(result['packages']), set(runtime.PACKAGES))
                self.assertEqual(result['function']['status'], 'observed' if match else 'unverified')
                if match:
                    self.assertTrue(result['function']['valid_normalized']); self.assertTrue(result['function']['invalid_rejected'])


if __name__ == '__main__':
    unittest.main()
