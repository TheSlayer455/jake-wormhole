"""Synthetic packets/events and real local pipe bounds, never SSH or Docker."""
import ast
import base64
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.metadata
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from fleet_inventory import runtime as r
from wormhole import fleet_inventory_capture as capture
from tests.test_fleet_inventory_records import observation


def request(batch='batch-001', forks=4):
    return {'schema_version': '1.0', 'operation': 'stock-fleet-inventory-batch-v1',
        'run_id': '12345678-1234-4234-9234-123456789abc', 'source_revision': 'a' * 40,
        'plan_sha256': 'b' * 64, 'batch_id': batch,
        'targets': [{'target_id': target, 'address': '10.88.0.' + str(int(target[-3:]) + 1)} for target in r.BATCHES[batch]],
        'controller_concurrency': forks, 'readiness_source_sha256': 'c' * 64, 'timeout_seconds': 20}


def native_functions():
    tree = ast.parse(r.STOCK_PROGRAM)
    body = [item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
    scope = {}; exec(compile(ast.Module(body=body, type_ignores=[]), 'fixed-stock-native-functions', 'exec'), scope)
    return scope


class RuntimeBounds(unittest.TestCase):
    def test_five_exact_batches_twenty_targets_and_explicit_one_to_four_forks(self):
        self.assertEqual(tuple(target for ids in r.BATCHES.values() for target in ids), r.TARGET_IDS)
        for batch in r.BATCHES:
            for forks in range(1, 5):
                value = request(batch, forks)
                self.assertEqual(r.decode(r.canonical(value)), value)
        for field, wrong in (('controller_concurrency', True), ('controller_concurrency', 5),
                ('timeout_seconds', float('inf')), ('batch_id', 'batch-006')):
            value = request(); value[field] = wrong
            with self.subTest(field=field), self.assertRaises(Exception): r.decode(r.canonical(value))

    def test_missing_duplicate_cross_batch_target_or_endpoint_is_not_a_smaller_success(self):
        for action in ('missing', 'duplicate', 'foreign', 'endpoint', 'extra-command'):
            value = request()
            if action == 'missing': value['targets'].pop()
            elif action == 'duplicate': value['targets'][1] = deepcopy(value['targets'][0])
            elif action == 'foreign': value['targets'][3]['target_id'] = 'target-020'
            elif action == 'endpoint': value['targets'][0]['address'] = '127.0.0.1'
            else: value['argv'] = ['arbitrary']
            with self.subTest(action=action), self.assertRaises(Exception): r.decode(r.canonical(value))

    def test_native_dpkg_preserves_epoch_revision_architecture_and_excludes_uninstalled(self):
        parser = native_functions()['dpkg_rows']
        raw = b'libc6\t2:2.39-0ubuntu8.9~synthetic\ti386\tinstalled\tok\nlibc6\t2:2.39-0ubuntu8.9~synthetic\tamd64\tinstalled\tok\nold\t1\tall\tconfig-files\tok\n'
        rows = parser(raw)
        self.assertEqual([item['architecture'] for item in rows], ['amd64', 'i386'])
        self.assertTrue(all(item['version'] == '2:2.39-0ubuntu8.9~synthetic' for item in rows))
        for bad in (raw + raw, b'bad\t1\tamd64\thalf-installed\tok\n',
                b'bad\t1\tamd64\tinstalled\treinstreq\n', b'bad\t1\n', b''):
            with self.subTest(bad=bad), self.assertRaises(Exception): parser(bad)

    def test_capture_public_boundary_never_accepts_commands_other_endpoints_or_unbounded_time(self):
        encoded = base64.b64encode(r.canonical(request())).decode()
        for helper, value, timeout in (('bad', encoded, 20), ('a' * 64, 'arbitrary', 20),
                ('a' * 64, encoded, 28), ('a' * 64, encoded, True)):
            with patch.object(capture.subprocess, 'Popen') as popen, self.assertRaises(Exception):
                capture.capture_inventory(helper, value, timeout=timeout)
            popen.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux'), 'Actual local POSIX pipes and private callback filesystem')
class NativeRuntime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='worm-stock-runtime-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)

    def test_real_bounded_capture_flood_timeout_and_descendant_pipe_hold(self):
        flood = capture._capture((sys.executable, '-I', '-B', '-c', 'import sys;sys.stdout.buffer.write(b"x"*400000)'), timeout=2)
        self.assertEqual(flood['status'], 'pass'); self.assertTrue(flood['log_truncated'])
        self.assertEqual(len(flood['log']), capture.LIMIT)
        began = time.monotonic()
        timeout = capture._capture((sys.executable, '-I', '-B', '-c', 'import time;time.sleep(10)'), timeout=.1)
        self.assertEqual(timeout['status'], 'timeout'); self.assertLess(time.monotonic() - began, 2)
        descendant = capture._capture((sys.executable, '-I', '-B', '-c',
            'import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(10)"])'), timeout=.15)
        self.assertEqual(descendant['status'], 'timeout')

    def collect(self, action='healthy'):
        outer = self
        image = SimpleNamespace(identity=lambda: request()['run_id'])
        def write(path, raw):
            with path.open('xb') as stream: stream.write(raw)
            path.chmod(0o600)
        image.write_private = write
        image.bounded_input = lambda path, **kwargs: path.read_bytes()
        for target in r.BATCHES['batch-001']:
            folder = self.root / target; folder.mkdir(mode=0o700)
            write(folder / 'id_ed25519', b'SYNTHETIC NONCREDENTIAL')
            write(folder / 'known_hosts', b'SYNTHETIC PUBLIC TRUST')
        helper = SimpleNamespace(ROOT=self.root, qualified_runtime=lambda: image,
            environment=lambda: {}, ssh_options=lambda *args, **kwargs: ['-o', 'StrictHostKeyChecking=yes'])
        def invoke(argv, timeout, env):
            outer.assertIn('--forks', argv); outer.assertEqual(argv[argv.index('--forks') + 1], '4')
            outer.assertEqual(Path(env['ANSIBLE_CONFIG']).read_bytes().splitlines()[1], b'host_key_checking = True')
            outer.assertEqual(env['ANSIBLE_STDOUT_CALLBACK'], 'wormhole_stock_inventory_quiet')
            outer.assertEqual(env['ANSIBLE_CALLBACKS_ENABLED'], 'wormhole_stock_inventory')
            outer.assertEqual(env['ANSIBLE_LOAD_CALLBACK_PLUGINS'], '1')
            outer.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')
            callbacks = Path(env['ANSIBLE_CALLBACK_PLUGINS'])
            outer.assertEqual({p.name for p in callbacks.iterdir()}, {'wormhole_stock_inventory.py', 'wormhole_stock_inventory_quiet.py'})
            outer.assertEqual((callbacks / 'wormhole_stock_inventory_quiet.py').read_bytes(), r.QUIET_CALLBACK_SOURCE.encode())
            outer.assertEqual((callbacks / 'wormhole_stock_inventory.py').read_bytes(), r.CALLBACK.encode())
            outer.assertEqual(helper.MAX_LOG, 4096)
            # CallbackBase supplies no-op event methods in pinned Ansible. The
            # authored stdout subclass must not emit packet/error contents.
            methods = {'__init__': lambda self, *a, **k: None}
            methods.update({name: lambda self, *a, **k: None for name in (
                'v2_runner_on_ok', 'v2_runner_on_failed', 'v2_runner_on_unreachable', 'v2_runner_on_skipped', 'v2_playbook_on_stats')})
            module = ModuleType('ansible.plugins.callback'); module.CallbackBase = type('CallbackBase', (), methods)
            modules = {'ansible': ModuleType('ansible'), 'ansible.plugins': ModuleType('ansible.plugins'), 'ansible.plugins.callback': module}
            namespace, quiet_namespace = {}, {}
            with patch.dict(sys.modules, modules), patch.dict(os.environ, env), patch.object(importlib.metadata, 'version', return_value='2.21.5'):
                exec(r.CALLBACK, namespace)
                exec(r.QUIET_CALLBACK_SOURCE, quiet_namespace)
                quiet = quiet_namespace['CallbackModule']()
                outer.assertEqual((quiet.CALLBACK_TYPE, quiet.CALLBACK_NAME), ('stdout', env['ANSIBLE_STDOUT_CALLBACK']))
                namespace['ROOT'] = self.root / 'stock-inventory'
                callback = namespace['CallbackModule']()
                command = json.loads(argv[argv.index('-a') + 1])['argv']
                native = observation()
                native['packages'].extend({'name': 'synthetic-package-' + str(i).zfill(3), 'version': '1:2.3-4',
                    'architecture': 'amd64'} for i in range(150))
                native['packages'].sort(key=lambda item: (item['name'], item['architecture']))
                packet_raw = r.canonical(native)
                outer.assertLess(len(packet_raw), r.MAX_PACKET)
                packet = base64.b64encode(packet_raw).decode()
                outer.assertGreater(len(packet), helper.MAX_LOG)
                targets = list(r.BATCHES['batch-001'])
                console, errors = io.StringIO(), io.StringIO()
                for index, target in enumerate(targets):
                    if action == 'missing' and index == 3: continue
                    result = SimpleNamespace(host=SimpleNamespace(get_name=lambda target=target: target),
                        task=SimpleNamespace(action='ansible.builtin.command', no_log=False),
                        result={'rc': 0, 'stdout': packet, 'stderr': '', 'cmd': command})
                    event = action if action in ('failed', 'skipped', 'unreachable') and index == 3 else 'ok'
                    if event == 'failed': result.result.update(rc=2, stdout='', stderr='SYNTHETIC MODULE FAILURE', failed=True)
                    with redirect_stdout(console), redirect_stderr(errors):
                        getattr(quiet, 'v2_runner_on_' + event)(result)
                    getattr(callback, 'v2_runner_on_' + event)(result)
                    if action == 'duplicate' and index == 0: callback.v2_runner_on_ok(result)
                callback.v2_playbook_on_stats(None)
                with redirect_stdout(console), redirect_stderr(errors): quiet.v2_playbook_on_stats(None)
                outer.assertEqual(console.getvalue(), ''); outer.assertEqual(errors.getvalue(), '')
            if action in ('console-flood', 'nonzero'):
                from readiness import runtime as rr
                # Real bounded local child/pipe behavior, not an Ansible or SSH
                # claim. Even valid aggregate files cannot hide these failures.
                program = ('import sys,time;sys.stdout.write("x"*20000);sys.stdout.flush();time.sleep(10)' if action == 'console-flood'
                    else 'import sys;sys.stdout.write("SYNTHETIC TERMINAL FAILURE\\n");sys.exit(3)')
                with patch.object(rr, 'ROOT', self.root), patch.object(rr, 'MAX_LOG', helper.MAX_LOG):
                    return rr.capture([sys.executable, '-I', '-B', '-c', program], 1, {'PATH': os.environ.get('PATH', '')})
            return {'returncode': 2 if action in ('failed', 'unreachable') else 0, 'timed_out': False, 'truncated': False, 'log': ''}
        helper.capture = invoke
        with patch.object(importlib.metadata, 'version', return_value='2.21.5'):
            return r.collect(request(), helper)

    def test_actual_embedded_callback_collects_each_complete_packet_once(self):
        value = self.collect()
        self.assertEqual(value['status'], 'pass')
        self.assertEqual([item['target_id'] for item in value['targets']], list(r.BATCHES['batch-001']))
        self.assertTrue(all(item['collector_base64'] is not None for item in value['targets']))
        self.assertLess(len(r.canonical(value)), r.MAX_RESPONSE)

    def test_missing_duplicate_failed_skipped_or_unreachable_events_cannot_be_a_pass(self):
        # Each iteration has its own actual private event directory, as real
        # attempts never reuse a completed helper batch.
        for action in ('missing', 'duplicate', 'failed', 'skipped', 'unreachable'):
            with self.subTest(action=action), tempfile.TemporaryDirectory(dir=self.root) as folder:
                previous = self.root; self.root = Path(folder); self.root.chmod(0o700)
                try:
                    value = self.collect(action)
                    self.assertEqual(value['status'], 'fail')
                    self.assertTrue(any(item['status'] != 'pass' for item in value['targets']))
                finally: self.root = previous

    def test_real_console_flood_and_nonzero_exit_stay_failed_with_complete_aggregate(self):
        for action in ('console-flood', 'nonzero'):
            with self.subTest(action=action), tempfile.TemporaryDirectory(dir=self.root) as folder:
                previous = self.root; self.root = Path(folder); self.root.chmod(0o700)
                try:
                    value = self.collect(action)
                    self.assertEqual(value['status'], 'fail'); self.assertFalse(value['timed_out'])
                    self.assertTrue(all(item['status'] == 'pass' and item['collector_base64'] is not None for item in value['targets']))
                    self.assertNotEqual(value['returncode'], 0)
                    self.assertEqual(value['diagnostic_truncated'], action == 'console-flood')
                    self.assertEqual(value['diagnostic_bytes'], 4096 if action == 'console-flood' else 27)
                finally: self.root = previous

    def test_twenty_functional_uses_fixed_quiet_stdout_and_original_complete_aggregate(self):
        from validation import runtime as functional
        from wormhole.targets import TargetPlan
        from test_fleet_runtime import callback
        from test_validation import observed, callback_event
        plan = TargetPlan('twenty-targets'); value = {'schema_version': '1.0', 'run_id': request()['run_id'],
            'source_revision': 'a' * 40, 'resource_layout': 'indexed-targets-v1', 'plan_sha256': 'b' * 64,
            'target_plan': plan.record(), 'targets': [{'target_id': target, 'address': '10.88.0.' + str(i),
                'scenario': 'healthy'} for i, target in enumerate(plan.target_ids, 2)], 'controller_concurrency': 4,
            'expected_payload_sha256': observed()['payload_sha256'], 'readiness_source_sha256': 'c' * 64, 'timeout_seconds': 40}
        def write(path, raw): path.write_bytes(raw); path.chmod(0o600)
        image = SimpleNamespace(identity=lambda: value['run_id'], write_private=write,
            bounded_input=lambda *args, **kwargs: b'SYNTHETIC NONCREDENTIAL')
        helper = SimpleNamespace(ROOT=self.root, qualified_runtime=lambda: image, environment=lambda: {},
            ssh_options=lambda *args, **kwargs: ['-o', 'StrictHostKeyChecking=yes'], MAX_LOG=8192)
        def invoke(argv, timeout, env):
            self.assertEqual(argv[argv.index('--forks') + 1], '4')
            self.assertEqual(env['ANSIBLE_STDOUT_CALLBACK'], 'wormhole_validation_quiet')
            callbacks = Path(env['ANSIBLE_CALLBACK_PLUGINS'])
            self.assertEqual((callbacks / 'wormhole_validation_quiet.py').read_bytes(), functional.QUIET_CALLBACK_SOURCE.encode())
            self.assertEqual((callbacks / 'wormhole_validation_batch.py').read_bytes(), functional.BATCH_CALLBACK_SOURCE.encode())
            self.assertEqual(env['ANSIBLE_CALLBACKS_ENABLED'], 'wormhole_validation_batch')
            self.assertEqual(env['ANSIBLE_LOAD_CALLBACK_PLUGINS'], '1')
            self.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')
            command = json.loads(argv[argv.index('-a') + 1])['argv']
            recorder = callback(self.root / 'functional-batch/results')
            for target in plan.target_ids:
                recorder.v2_runner_on_ok(callback_event({'cmd': command, 'rc': 0, 'stdout': json.dumps(observed()),
                    'stderr': '', 'msg': '', 'changed': True}, host=target))
            recorder.v2_playbook_on_stats(None)
            return {'returncode': 0, 'timed_out': False, 'truncated': False, 'duration_seconds': .1, 'log': ''}
        helper.capture = invoke
        result = functional.collect_batch(value, helper)
        self.assertEqual(result['status'], 'pass'); self.assertEqual(len(result['targets']), 20)
        self.assertTrue(all(row['status'] == 'pass' for row in result['targets']))
        self.assertLess(len(r.canonical(result)), 65536)
        self.assertEqual(helper.MAX_LOG, 32768)


if __name__ == '__main__':
    unittest.main()
