"""Original-capture twenty replay. All Docker/Terraform/SSH calls are mocked."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

# Existing shared fixtures import one another by discovery-relative names.
# Keep those legacy fixtures available for both named and discovery invocation.
if str(Path(__file__).parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent))
from tests import test_provisioning as tf
from tests import test_provisioning_fleet as fleet_tf
from tests import test_twenty_infrastructure as helper_fixture
from scripts import qualify_images as qualification
from wormhole import images, provisioning as p, readiness as r, twenty_replay as replay
from wormhole.runs import atomic_json, common, read_json


def cgroups(_pid, limits):
    return {'memory.max': str(limits['memory_bytes']), 'memory.swap.max': '0', 'pids.max': str(limits['pids_limit']),
        'cpu.max': str(limits['nano_cpus'] // 10000) + ' 100000'}


def archive(run, lease):
    plan = deepcopy(lease.plan)
    # This entire fixture is synthetic. Serialize the internally consistent
    # production record shape so historical recomputation itself remains tested.
    plan['observations']['synthetic'] = False
    return {'run_id': run.id, 'source_revision': run.manifest()['source_revision'], 'state': 'finished', 'phase': 'reconciling',
        'plan': plan, 'resources': [dict(item, outcome='absent') for item in lease.record['resources']]}


@unittest.skipUnless(os.name == 'posix', 'POSIX original-state fixtures; no Docker or target execution')
class OfflineTwentyTerraform(unittest.TestCase):
    def setUp(self):
        self.fixture = fleet_tf.TwentyLifecycle('test_retained_five_target_recovery_uses_exact_layout_and_terraform_destroy')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.run, self.ps = self.fixture.run, self.fixture.session
        def capture(arguments, **_):
            name, attempt = arguments[-2], int(arguments[-1]); value = self.fixture.operation(name)
            from provisioning.runtime import JSON_OPERATIONS
            raw = json.dumps(value).encode() if name in JSON_OPERATIONS else b'Synthetic fixed Terraform output'
            folder = self.ps.state / 'operations'; folder.mkdir(mode=0o700, exist_ok=True); stem = folder / (name + '-' + str(attempt))
            stem.with_suffix('.out').write_bytes(raw); stem.with_suffix('.out').chmod(0o600)
            atomic_json(stem.with_suffix('.json'), {'operation': name, 'attempt': attempt, 'returncode': 0, 'duration_seconds': .001,
                'output_bytes': len(raw), 'output_sha256': hashlib.sha256(raw).hexdigest(), 'truncated': False, 'timed_out': False, 'passed': True})
            return {'status': 'pass', 'returncode': 0, 'log': b'Synthetic runtime result', 'log_truncated': False}
        with tf.Controller.patches(self.fixture, mock_operations=False), patch.object(p, '_run_process', side_effect=capture), \
            patch.object(images, 'docker_configuration', return_value='/synthetic/config'), patch.object(images, 'cgroup_limits', side_effect=cgroups):
            self.ps.create_stopped()
            stopped = {target: self.fixture.container(identifier) for target, identifier in self.ps.target_resources.items()}
            network = self.fixture.inspect('network', tf.NET)
            self.ps.start_and_inventory()
            live = {target: self.fixture.container(identifier) for target, identifier in self.ps.target_resources.items()}
            controller = self.fixture.container(tf.CONTROLLER)
            self.ps.destroy()
        atomic_json(self.run.file(replay.RUNTIME), {**common(self.run.manifest()), 'operation': 'twenty-runtime-observations-v1',
            'network': network, 'targets_stopped': stopped, 'targets_live': live, 'provisioner': controller, 'helper': {'Id': '9' * 64}})
        self.archive = archive(self.run, self.fixture.lease)
        self.archive['resources'].append({'kind': 'container', 'id': '9' * 64, 'outcome': 'absent'})
        for module, name, value in [(replay, 'source_identity', (tf.SHA, False)), (images, 'RUNS_ROOT', self.run.workspace)]:
            setting = patch.object(module, name, return_value=value) if name == 'source_identity' else patch.object(module, name, value)
            setting.start(); self.addCleanup(setting.stop)

    def report(self):
        with tf.Controller.patches(self.fixture, mock_operations=False), \
            patch.object(images, 'inspect', side_effect=AssertionError('Offline replay contacted Docker')):
            return replay.report_provisioning(self.run, self.archive)

    def test_all_original_saved_operations_and_twenty_configs_replay_without_docker(self):
        value = self.report()
        self.assertEqual(len(value['targets']), 20)
        self.assertEqual(value['targets'], self.fixture.identities)
        self.assertEqual(value['proof']['terraform_resources'], 21)
        self.assertEqual(value['proof']['terminal_operations'], 16)

    def test_changed_hcl_even_with_changed_context_hash_cannot_relabel_original_plan(self):
        path = self.ps.state / 'main.tf'; raw = path.read_bytes() + b'\n# changed after original saved plan\n'; path.write_bytes(raw)
        context = read_json(self.ps.state / 'controller.json'); context['inputs']['main.tf'] = hashlib.sha256(raw).hexdigest()
        atomic_json(self.ps.state / 'controller.json', context)
        with self.assertRaises(replay.TwentyReplayError): self.report()

    def test_missing_target020_or_changed_runtime_pid_policy_refuses(self):
        path = self.run.file(replay.RUNTIME); original = read_json(path)
        for mutate in (lambda value: value['targets_live'].pop('target-020'),
            lambda value: value['targets_stopped']['target-020']['HostConfig'].update(PidsLimit=0),
            lambda value: value['targets_live']['target-020']['NetworkSettings']['Networks'].clear()):
            value = deepcopy(original); mutate(value); atomic_json(path, value)
            with self.assertRaises(Exception): self.report()

    def test_changed_final_capture_or_missing_archive_target_refuses(self):
        self.archive['resources'].pop()
        with self.assertRaises(replay.TwentyReplayError): self.report()
        self.archive['resources'].append({'kind': 'container', 'id': '9' * 64, 'outcome': 'absent'})
        (self.ps.state / 'operations/final-state-1.out').write_bytes(b'changed original capture')
        with self.assertRaises(replay.TwentyReplayError): self.report()

    def test_changed_saved_apply_bytes_cannot_retain_validated_plan_credit(self):
        (self.ps.state / 'apply.tfplan').write_bytes(b'changed saved apply plan after execution')
        with self.assertRaises(replay.TwentyReplayError) as error: self.report()
        self.assertEqual(error.exception.code, 'twenty_original_plan_changed')


@unittest.skipUnless(os.name == 'posix', 'POSIX original helper source/capture fixtures; no Docker or SSH')
class OfflineTwentyReadiness(unittest.TestCase):
    def setUp(self):
        self.fixture = helper_fixture.TwentyHelper('test_twenty_ready_has_exact_160_pairs_one_bounded_helper_and_three_public_sources')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        f = self.fixture; self.run, self.session = f.run, f.session
        with patch.object(images, 'cgroup_limits', side_effect=cgroups): self.session.start_helper()
        for target in self.session.target_plan.target_ids:
            with self.session.selected(target):
                for role, stage, raw in [('target', 'public-hostkey', (helper_fixture.fixture.HOST_KEY + '\n').encode()),
                    ('helper', 'auth-input', b'Synthetic fixed receiver complete')]:
                    qualification.attempt_record(self.run, self.session.receipt, role, self.session.stage_name(stage),
                        {'status': 'pass', 'returncode': 0, 'duration_seconds': .001, 'log': raw, 'log_truncated': False})
        with patch.object(r, '_run_process', side_effect=f.probe): self.session.wait_ready()
        helper = f.helper(); self.session.cleanup()
        self.provisioned = {'targets': dict(f.target_resources), 'network_id': helper_fixture.fixture.NETWORK,
            'runtime': {'helper': helper, 'targets_live': {target: f.target(target) for target in f.target_plan.target_ids}}}
        self.archive = archive(self.run, f.lease)
        for module, name, value in [(replay, 'source_identity', (helper_fixture.fixture.SHA, False)), (images, 'RUNS_ROOT', self.run.workspace)]:
            setting = patch.object(module, name, return_value=value) if name == 'source_identity' else patch.object(module, name, value)
            setting.start(); self.addCleanup(setting.stop)

    def report(self):
        with patch.object(images, 'inspect', side_effect=AssertionError('Offline replay contacted Docker')):
            return replay.report_readiness(self.run, self.archive, self.provisioned)

    def test_all160_pairs_replay_from_original_captures_after_helper_is_gone(self):
        value = self.report()
        self.assertEqual(value['passed_pairs'], 160)
        self.assertTrue(self.fixture.removed)

    def test_original_packet_mutation_rejects_even_when_retained_transition_grid_says_pass(self):
        value = read_json(self.run.file('evidence/readiness.json'))
        child = value['targets'][-1]; item = next(item for item in child['attempts'] if item['stage'] == 'target-020-ssh')
        path = self.run.file(item['private_log']); packet = json.loads(path.read_bytes()); packet['observation']['uid'] = 0
        atomic_json(path, packet)
        with self.assertRaises(replay.TwentyReplayError): self.report()

    def test_foreign_target_capture_and_changed_context_network_or_policy_refuse(self):
        path = self.run.file('private/readiness-controller.json'); original = read_json(path)
        for mutate in (lambda value: value.update(network_id='f' * 64), lambda value: value['helper_policy'].update(wait_seconds=180)):
            value = deepcopy(original); mutate(value); atomic_json(path, value)
            with self.assertRaises(replay.TwentyReplayError): self.report()
        atomic_json(path, original)
        receipt = read_json(self.run.file('evidence/readiness.json'))
        item = next(item for item in receipt['targets'][-1]['attempts'] if item['stage'] == 'target-020-tcp')
        path = self.run.file(item['private_log']); packet = json.loads(path.read_bytes()); packet['target_id'] = 'target-019'
        atomic_json(path, packet)
        with self.assertRaises(replay.TwentyReplayError): self.report()


if __name__ == '__main__': unittest.main()
