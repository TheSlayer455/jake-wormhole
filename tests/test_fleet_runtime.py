"""Fixed batch callback/argv fixtures. No Docker/SSH/Ansible installation or target."""
import importlib.metadata
import json
import os
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from readiness import runtime as rr
from validation import runtime
from wormhole.targets import TargetPlan
from test_validation import observed, callback_event


def callback(results):
    class Base:
        def _dump_results(self, value): return json.dumps(value)
    modules = {name: ModuleType(name) for name in ('ansible', 'ansible.plugins', 'ansible.plugins.callback')}
    modules['ansible'].__path__ = []; modules['ansible.plugins'].__path__ = []
    modules['ansible.plugins.callback'].CallbackBase = Base
    namespace = {'__name__': 'fixed_batch_callback_fixture'}
    with patch.dict('sys.modules', modules): exec(compile(runtime.BATCH_CALLBACK_SOURCE, '<batch-callback>', 'exec'), namespace)
    namespace['RESULTS'] = results
    with patch.object(importlib.metadata, 'version', return_value='2.21.5'): return namespace['CallbackModule']()


class BatchProtocol(unittest.TestCase):
    def value(self):
        plan = TargetPlan('five-targets')
        return {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc', 'source_revision': 'a' * 40,
            'resource_layout': 'indexed-targets-v1', 'plan_sha256': 'a' * 64, 'target_plan': plan.record(),
            'targets': [{'target_id': target, 'address': '172.31.77.' + str(index), 'scenario': 'healthy'} for index, target in enumerate(plan.target_ids, 2)],
            'controller_concurrency': 2, 'expected_payload_sha256': observed()['payload_sha256'],
            'readiness_source_sha256': 'b' * 64, 'timeout_seconds': 40}

    def test_count_concurrency_target_identity_and_endpoint_are_separately_bounded(self):
        value = self.value(); runtime.decode_batch(json.dumps(value).encode())
        for mutate in (lambda x: x.update(controller_concurrency=5), lambda x: x['targets'].reverse(),
            lambda x: x['targets'][0].update(target_id='target-020'), lambda x: x['targets'][0].update(address='127.0.0.1'),
            lambda x: x['target_plan'].update(target_count=4), lambda x: x.update(command='untrusted')):
            import copy
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises((ValueError, TypeError)): runtime.decode_batch(json.dumps(invalid).encode())
        partial = self.value(); partial['targets'] = partial['targets'][1:]
        self.assertEqual(len(runtime.decode_batch(json.dumps(partial).encode())['targets']), 4)


@unittest.skipUnless(os.name == 'posix', 'Owned private callback/filesystem fixtures require Linux')
class BatchExecution(unittest.TestCase):
    value = BatchProtocol.value
    def test_actual_embedded_callback_mixed_exit_preserves_per_target_success_and_forks_two(self):
        for fault in ('healthy', 'one-interpreter', 'missing', 'duplicate', 'foreign'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='wormhole-fleet-runtime-synthetic-') as temporary:
                root = Path(temporary); root.chmod(0o700); value = self.value()
                def write(path, raw): path.write_bytes(raw); path.chmod(0o600)
                def bounded(path, **_):
                    self.assertIn(path.parent.name, TargetPlan('five-targets').target_ids)
                    self.assertIn(path.name, {'id_ed25519', 'known_hosts'})
                    return b'synthetic private input'
                module = SimpleNamespace(identity=lambda: value['run_id'], write_private=write, bounded_input=bounded)
                helper = SimpleNamespace(ROOT=root, qualified_runtime=lambda: module, ssh_options=rr.ssh_options,
                    environment=rr.environment, MAX_LOG=8192)
                def capture(argv, _, environment):
                    config = Path(environment['ANSIBLE_CONFIG'])
                    self.assertEqual(config, root / 'ansible.cfg')
                    self.assertEqual(config.read_bytes(), b'[defaults]\nhost_key_checking = True\nretry_files_enabled = False\ninterpreter_python = /usr/bin/python3\n')
                    self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(argv[argv.index('--forks') + 1], '2')
                    self.assertEqual(environment['ANSIBLE_CALLBACKS_ENABLED'], 'wormhole_validation_batch')
                    self.assertEqual(environment['ANSIBLE_LOAD_CALLBACK_PLUGINS'], '1')
                    self.assertEqual(environment['PYTHONDONTWRITEBYTECODE'], '1')
                    command = json.loads(argv[argv.index('-a') + 1])['argv']
                    self.assertEqual(command[4], runtime.TARGET_PROGRAM)
                    hosts = json.loads(Path(argv[argv.index('-i') + 1]).read_text())['all']['hosts']
                    self.assertEqual(set(hosts), set(TargetPlan('five-targets').target_ids))
                    for target, variables in hosts.items():
                        self.assertIn(str(root / target / 'known_hosts'), variables['ansible_ssh_args'])
                        self.assertFalse(variables['ansible_ssh_use_tty'])
                    recorder = callback(root / 'functional-batch/results')
                    for index, target in enumerate(hosts):
                        if fault == 'missing' and index == 4: continue
                        tree = {'cmd': command, 'rc': 0, 'stdout': json.dumps(observed()), 'stderr': '', 'msg': '', 'changed': True}
                        event = callback_event(tree, host=target)
                        if fault == 'one-interpreter' and index == 2:
                            tree.update(rc=127, msg='/run/wormhole/no-such-python not found')
                            recorder.v2_runner_on_failed(event)
                        else: recorder.v2_runner_on_ok(event)
                        if fault == 'duplicate' and index == 0: recorder.v2_runner_on_ok(event)
                    if fault == 'foreign': recorder.v2_runner_on_ok(callback_event({}, host='target-020'))
                    recorder.v2_playbook_on_stats(None)
                    return {'returncode': 2 if fault == 'one-interpreter' else 0, 'timed_out': False, 'truncated': False,
                        'duration_seconds': .01, 'log': 'target-005 | SKIPPED (synthetic console text ignored)'}
                helper.capture = capture
                if fault == 'one-interpreter': value['targets'][2]['scenario'] = 'configured-interpreter-unavailable'
                result = runtime.collect_batch(value, helper)
                passed = sum(target['status'] == 'pass' for target in result['targets'])
                self.assertEqual(passed, 5 if fault == 'healthy' else 4 if fault == 'one-interpreter' else 0)
                self.assertEqual(result['status'], 'pass' if fault == 'healthy' else 'fail')
                if fault == 'one-interpreter': self.assertEqual(result['targets'][2]['category'], 'configured_interpreter_unavailable')
                self.assertEqual(helper.MAX_LOG, 32768)


if __name__ == '__main__': unittest.main()
