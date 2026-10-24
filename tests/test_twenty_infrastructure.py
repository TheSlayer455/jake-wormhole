"""Twenty-target policy fixtures. All Docker/SSH/Terraform operations are mocked."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import test_fleet_helper as fixture
from readiness import runtime
from wormhole import fleet_readiness as f, images, readiness as r
from wormhole.runs import atomic_json, common, read_json
from wormhole.targets import TargetPlan


class TwentyProtocol(unittest.TestCase):
    def request(self):
        return {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc',
            'source_revision': 'a' * 40, 'resource_layout': 'indexed-targets-v1',
            'target_plan': TargetPlan('twenty-targets').record(), 'target_id': 'target-020',
            'address': '172.31.77.21', 'operation': 'ssh', 'attempt': 1, 'scenario': 'healthy', 'timeout_seconds': 3}

    def test_twenty_request_requires_full_exact_plan_and_old_five_bound_stays_closed(self):
        request = self.request()
        self.assertEqual(runtime.request(json.dumps(request).encode()), request)
        mutations = [lambda x: x.update(target_id='target-000'), lambda x: x.update(target_id='target-021'),
            lambda x: x['target_plan']['target_ids'].pop(), lambda x: x['target_plan']['target_ids'].reverse(),
            lambda x: x['target_plan']['target_ids'].__setitem__(19, 'target-019'),
            lambda x: x['target_plan'].update(target_count=True), lambda x: x['target_plan'].update(profile='five-targets'),
            lambda x: x.pop('target_plan')]
        for mutate in mutations:
            value = deepcopy(request); mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError): runtime.request(json.dumps(value).encode())
        old = deepcopy(request); old.pop('target_plan'); old['target_id'] = 'target-005'
        self.assertEqual(runtime.request(json.dumps(old).encode()), old)

    def test_fixed_receiver_binds_profile_before_any_input_directory_or_files(self):
        # Execute the actual fixed receiver suffix; no real /run path is reached.
        suffix = f.RECEIVER[len(r.qualification.INPUT_RECEIVER):]
        touched = []
        class PathRefused:
            def __init__(self, _): touched.append('path'); raise RuntimeError('fixture stops before filesystem')
        for target, profile, accepted in [('target-020', 'twenty-targets', True), ('target-005', 'five-targets', True),
            ('target-020', 'five-targets', False), ('target-000', 'twenty-targets', False),
            ('target-021', 'twenty-targets', False), ('target-001', 'untrusted', False)]:
            import sys
            touched.clear()
            with patch.object(sys, 'argv', ['fixed', target, profile]), patch.object(sys, 'stderr'), self.assertRaises(SystemExit):
                exec(compile(suffix, '<actual-fixed-receiver>', 'exec'), {'sys': sys, 'Path': PathRefused})
            self.assertEqual(bool(touched), accepted)


class TwentyHelper(unittest.TestCase):
    fixture_profile, fixture_inventory = 'twenty-targets', True
    verify_target = fixture.FleetHelper.verify_target
    target = fixture.FleetHelper.target
    inspect = fixture.FleetHelper.inspect
    docker = fixture.FleetHelper.docker
    make_ready = fixture.FleetHelper.make_ready

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='wormhole-inventory-code-synthetic-')
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / 'runtime.py'; source.write_bytes(b'# Explicit synthetic inventory source fixture\n')
        setting = patch.object(r, 'FLEET_INVENTORY_RUNTIME', source); setting.start(); self.addCleanup(setting.stop)
        fixture.FleetHelper.setUp(self)

    def helper(self):
        value = fixture.FleetHelper.helper(self)
        value['Config']['Cmd'] = ['wait', '300']
        value['HostConfig']['Tmpfs']['/run/input'] = 'rw,nosuid,nodev,noexec,size=512k,mode=0700,uid=10001,gid=10001'
        value['Mounts'].append({'Type': 'bind', 'Source': str(self.run.file('private/helper-source/fleet-inventory.py')),
            'Destination': r.FLEET_INVENTORY_MOUNT, 'RW': False})
        return value

    def probe(self, arguments, **options):
        request = runtime.request(base64.b64decode(arguments[-1]))
        self.assertEqual(request['target_plan'], TargetPlan('twenty-targets').record())
        return fixture.FleetHelper.probe(self, arguments, **options)

    def test_twenty_ready_has_exact_160_pairs_one_bounded_helper_and_three_public_sources(self):
        self.make_ready()
        self.assertEqual(len(self.session.ready_target_ids), 20)
        self.assertEqual(len(self.session.receipt['expected_pairs']), 160)
        transitions = [item for state in self.session.receipt['targets'] for item in state['transitions']]
        self.assertEqual([(item['target_id'], item['check_id']) for item in transitions],
            [(target, check) for target in self.target_plan.target_ids for check in r.EXPECTED])
        calls = [item for item in self.calls if item[:2] == ('docker', 'create')]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-2:], ('wait', '300'))
        self.assertIn('/run/input:rw,nosuid,nodev,noexec,size=512k,mode=0700,uid=10001,gid=10001', calls[0])
        self.assertEqual(len(self.session.source_bindings()), 3)
        context = read_json(self.run.file('private/readiness-controller.json'))
        self.assertEqual(context['context_version'], 4)
        self.assertEqual(context['helper_policy'], {'wait_seconds': 300, 'input_tmpfs_bytes': 524288})
        self.assertTrue(context['fleet_inventory_enabled'])
        paths = [attempt['private_log'] for child in self.session.receipt['targets'] for attempt in child['attempts']]
        self.assertEqual(len(paths), len(set(paths)))
        policy = self.session.helper_policy(); policy['wait_seconds'] = 1
        self.assertEqual(self.session.helper_policy()['wait_seconds'], 300)

    def test_actual_helper_wrong_lifetime_size_mount_or_source_never_passes_inspection(self):
        self.session.start_helper()
        for mutate in (lambda x: x['Config'].update(Cmd=['wait', '180']),
            lambda x: x['HostConfig']['Tmpfs'].update({'/run/input': 'rw,nosuid,nodev,noexec,size=64k,mode=0700,uid=10001,gid=10001'}),
            lambda x: x['Mounts'].pop(), lambda x: x['Mounts'][-1].update(RW=True)):
            value = self.helper(); mutate(value)
            with self.assertRaises(r.ReadinessError): self.session.verify_helper(value)
        source = self.session.fleet_inventory_bind_path
        source.chmod(0o600); source.write_bytes(b'# changed synthetic bytes\n'); source.chmod(0o444)
        with self.assertRaises(r.ReadinessError): self.session.verify_helper(self.helper())

    def test_twenty_context_resume_exact_policy_sources_map_and_idempotent_known_cleanup(self):
        self.session.start_helper()
        atomic_json(self.run.file('evidence/provisioning.json'), {**common(self.run.manifest()),
            'resources': [{'address': key, 'id': value} for key, value in self.ps.owned.items()]})
        self.lease._reconciliation_only = True
        path = self.run.file('private/readiness-controller.json'); original = read_json(path)
        for mutate in (lambda x: x['helper_policy'].update(wait_seconds=180),
            lambda x: x['helper_policy'].update(input_tmpfs_bytes=65536),
            lambda x: x['helper_policy'].update(wait_seconds=True), lambda x: x.update(context_version=3),
            lambda x: x.update(fleet_inventory_enabled=False), lambda x: x.update(fleet_inventory_source_sha256='f' * 64),
            lambda x: x['target_resource_ids'].pop('target-020')):
            value = deepcopy(original); mutate(value); atomic_json(path, value)
            before = len(self.calls)
            with self.assertRaises(Exception): r.ReadinessSession.resume_cleanup(self.run, self.lease)
            self.assertFalse(any(item[:2] in {('docker', 'stop'), ('docker', 'rm')} for item in self.calls[before:]))
        atomic_json(path, original)
        resumed = r.ReadinessSession.resume_cleanup(self.run, self.lease)
        self.assertEqual(resumed.target_plan.target_ids[-1], 'target-020')
        resumed.cleanup(); resumed.cleanup()
        self.assertEqual(len([item for item in self.calls if item[:2] == ('docker', 'rm')]), 1)
        self.assertEqual(len(resumed.source_bindings()), 3)

    def test_readiness_cannot_return_success_after_late_final_verification(self):
        self.make_ready()
        self.session.deadline = time.monotonic() + 2
        def late(): self.session.deadline = time.monotonic() - 1
        with patch.object(self.session, 'require_ready', side_effect=late), self.assertRaises(r.ReadinessError):
            self.session.wait_ready()
        self.assertEqual(self.session.receipt['status'], 'failed')
        self.assertIsNotNone(self.session.receipt['primary_failure'])


class LegacyHelperPolicy(unittest.TestCase):
    def test_only_twenty_uses_larger_input_and_wait_and_projection_rejects_unbounded_or_boolean_size(self):
        for profile, expected in [('smoke', (180, 65536)), ('five-targets', (180, 65536)), ('twenty-targets', (300, 524288))]:
            session = r.ReadinessSession.__new__(r.ReadinessSession); session.target_plan = TargetPlan(profile)
            self.assertEqual(tuple(session.helper_policy().values()), expected)
        from test_admission import observed
        from wormhole.admission import build_plan
        from types import SimpleNamespace
        run = SimpleNamespace(id='12345678-1234-4234-9234-123456789abc')
        limits = build_plan('twenty-targets', observed())['limits']['helper']
        for invalid in (True, 0, 524289, '524288', None):
            with self.assertRaises(images.ImageError): images.runtime_arguments(run, 'helper', r.HELPER_IMAGE,
                fixture.NETWORK, limits, helper_input_tmpfs_bytes=invalid)


if __name__ == '__main__': unittest.main()
