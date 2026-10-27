"""No Docker/SSH/Ansible execution: policy fixtures and real bounded Python children."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
import hashlib
from pathlib import Path
import struct
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from readiness import runtime
from wormhole import admission, images, readiness as r
from wormhole.runs import atomic_bytes, atomic_json, common, create_run, read_json
from test_admission import observed

SHA = 'a' * 40
TARGET, NETWORK, CONTROLLER, HELPER = ('b' * 64, 'c' * 64, 'd' * 64, 'e' * 64)
HOST_KEY = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))).decode()
REAL_INJECT = r.ReadinessSession.inject_inputs


class Lease:
    def __init__(self, run):
        self.run_id, self.source_revision = run.id, SHA
        self.plan = admission.build_plan('smoke', observed())
        self.plan['synthetic'] = False  # Deliberately synthetic dependency object, never admission for allocation.
        self._reconciliation_only = False
        self.record = {'resources': [{'kind': kind, 'id': identifier, 'outcome': 'pending'} for kind, identifier in
            (('container', CONTROLLER), ('container', TARGET), ('network', NETWORK))]}
        self.phases = []
    def _active(self): pass
    def set_phase(self, name): self.phases.append(name)
    def register_resource(self, kind, identifier): self.record['resources'].append({'kind': kind, 'id': identifier, 'outcome': 'pending'})
    def reconcile_resource(self, kind, identifier):
        item = next(x for x in self.record['resources'] if (x['kind'], x['id']) == (kind, identifier))
        if item['outcome'] != 'pending': raise AssertionError('Reconciliation must be idempotent at the adapter boundary')
        item['outcome'] = 'absent'


class ReadinessPolicy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='wormhole-readiness-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.run = create_run(Path(temporary.name) / 'runs', fixture=False, identity=(SHA, False))
        self.lease = Lease(self.run)
        self.started = True
        self.target_started_at = datetime.now(timezone.utc).isoformat()
        self.helper_started = False
        self.removed = False
        self.calls = []
        self.image_labels = {images.LABEL + '.source_revision': 'f' * 40, images.LABEL + '.role': 'helper'}
        self.provisioning = SimpleNamespace(run=self.run, lease=self.lease,
            owned={'docker_container.target': TARGET, 'docker_network.run': NETWORK},
            receipt={'unknown_outcome': False, 'inventory': {**common(self.run.manifest()), 'status': 'pass', 'targets': [
                {'target_id': 'target-001', 'resource_id': TARGET, 'host': '172.31.77.2', 'ssh_port': 2222, 'ssh_user': 'wormhole'}]}},
            variables={'image': 'sha256:' + '1' * 64}, verify_target=Mock())
        self.identity = patch.object(r, 'source_identity', return_value=(SHA, False)); self.identity.start(); self.addCleanup(self.identity.stop)
        for module, name, arguments in ((r.ReadinessSession, 'helper_reference', {'return_value': self.image_labels}),
            (images, 'inspect', {'side_effect': self.inspect}), (images, 'docker', {'side_effect': self.docker}),
            (images, 'cgroup_limits', {'return_value': {'synthetic': True}}),
            (r.ReadinessSession, 'public_key', {'return_value': HOST_KEY}),
            (r.ReadinessSession, 'inject_inputs', {}), (images, 'docker_configuration', {'return_value': '/synthetic/empty-config'})):
            mocked = patch.object(module, name, **arguments); mocked.start(); self.addCleanup(mocked.stop)
        self.session = r.ReadinessSession(self.provisioning)

    def target(self):
        return {'Id': TARGET, 'State': {'Status': 'running' if self.started else 'created', 'Running': self.started,
            'StartedAt': self.target_started_at if self.started else '0001-01-01T00:00:00Z'},
            'NetworkSettings': {'Networks': {'run': {'NetworkID': NETWORK, 'IPAddress': '172.31.77.2'}}}}

    def helper(self):
        spec = self.lease.plan['limits']['helper']['docker_create']
        return {'Id': HELPER, 'Image': r.HELPER_IMAGE, 'Name': '/wormhole-' + self.run.id + '-helper',
            'Config': {'User': '10001:10001', 'Entrypoint': ['/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py', 'helper'],
                'Cmd': ['wait', '180'], 'Labels': {**self.image_labels, images.LABEL + '.run_id': self.run.id,
                images.LABEL + '.role': 'helper', images.LABEL + '.source_revision': SHA},
                'Env': ['WORMHOLE_RUN_ID=' + self.run.id, 'WORMHOLE_RUNTIME_TTL_SECONDS=600']},
            'State': {'Status': 'running' if self.helper_started else 'created', 'Running': self.helper_started,
                'StartedAt': '2026-10-23T00:00:00Z' if self.helper_started else '0001-01-01T00:00:00Z', 'Pid': 999999},
            'HostConfig': {'Memory': spec['memory_bytes'], 'MemorySwap': spec['memory_swap_bytes'], 'NanoCpus': spec['nano_cpus'],
                'PidsLimit': spec['pids_limit'], 'LogConfig': {'Type': spec['log_driver'], 'Config': spec['log_opts']},
                'Privileged': False, 'ReadonlyRootfs': True, 'NetworkMode': NETWORK, 'PidMode': '', 'IpcMode': 'private',
                'RestartPolicy': {'Name': 'no'}, 'CapDrop': ['ALL'], 'CapAdd': [], 'SecurityOpt': ['no-new-privileges:true'],
                'Tmpfs': {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=10001,gid=10001',
                    '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777',
                    '/run/input': 'rw,nosuid,nodev,noexec,size=64k,mode=0700,uid=10001,gid=10001'}},
            'Mounts': [{'Type': 'bind', 'Source': str(self.run.file('private/helper-source/runtime.py')), 'Destination': r.SOURCE_MOUNT, 'RW': False}],
            'NetworkSettings': {'Networks': {'run': {'NetworkID': NETWORK}}}}

    def inspect(self, kind, identifier, **options):
        self.calls.append(('inspect', kind, identifier))
        if kind == 'image': return {'Config': {'Labels': self.image_labels}}
        if identifier == TARGET: return self.target()
        if identifier == HELPER:
            if self.removed and options.get('missing'): return None
            return self.helper()
        raise AssertionError('No foreign resources may be inspected')

    def docker(self, arguments, **options):
        self.calls.append(('docker', *arguments))
        if arguments[0] == 'create':
            self.assertIn(str(self.run.file('private/helper-source/runtime.py')), ' '.join(arguments))
            self.assertNotIn('source=' + str(r.RUNTIME), ' '.join(arguments))
            return {'log': (HELPER + '\n').encode(), 'log_truncated': False}
        if arguments[0] == 'ps': return {'log': b'', 'log_truncated': False}
        self.assertEqual(arguments[-1], HELPER, 'Only the exact helper may be mutated')
        if arguments[0] == 'start': self.helper_started = True
        if arguments[0] == 'stop': self.helper_started = False
        if arguments[0] == 'rm': self.removed = True
        return {'log': b'', 'log_truncated': False}

    def output(self, arguments, **options):
        value = runtime.request(base64.b64decode(arguments[-1]))
        operation = value['operation']; self.calls.append(('probe', operation))
        observation = {'tcp': {'tcp_connected': True}, 'ssh': {'uid': 10001}, 'python': {'configured_interpreter_usable': True},
                       'ansible-wait': {'structured_target_result': True}, 'ansible-ping': {'structured_target_result': True, 'ping': 'pong'}}[operation]
        result = {**{key: value[key] for key in ('schema_version', 'run_id', 'source_revision', 'target_id', 'operation', 'attempt')},
            'status': 'pass', 'category': None, 'returncode': 0, 'timed_out': False, 'truncated': False,
            'duration_seconds': .001, 'observation': observation, 'private_diagnostic': 'synthetic transport result'}
        return {'status': 'pass', 'returncode': 0, 'log_truncated': False, 'log': json.dumps(result).encode(), 'duration_seconds': .001}

    def test_helper_is_confined_stopped_before_start_and_only_source_file_is_bound(self):
        self.session.start_helper()
        self.assertEqual(self.lease.phases, ['provisioning', 'validating'])
        start = self.calls.index(('docker', 'start', HELPER))
        self.assertIn(('inspect', 'container', HELPER), self.calls[:start])
        self.assertFalse(self.session.receipt['unknown_outcome'])
        for field, mutation in (('privilege', lambda x: x['HostConfig'].update(Privileged=True)),
            ('socket', lambda x: x['Mounts'].append({'Type': 'bind', 'Source': '/var/run/docker.sock', 'Destination': '/socket', 'RW': True})),
            ('network', lambda x: x['NetworkSettings'].update(Networks={})),
            ('pid', lambda x: x['HostConfig'].update(PidsLimit=0))):
            value = self.helper(); mutation(value)
            with self.subTest(field=field), self.assertRaises(r.ReadinessError): self.session.verify_helper(value)

    def test_healthy_wait_requires_every_actual_helper_protocol_result_and_stays_partial(self):
        self.session.start_helper()
        # Docker StartedAt is stable, unlike a sampled current-time clock.
        target = self.target()
        with patch.object(self, 'target', return_value=target), patch.object(r, '_run_process', side_effect=self.output):
            result = self.session.wait_ready()
            self.assertTrue(self.session.require_ready())
            self.session.deadline = time.monotonic() - 1
            self.assertTrue(self.session.require_ready(), 'Existing readiness gets a fresh bounded live-identity check, not a new establishment window')
        self.assertEqual([x['check_id'] for x in result['transitions']], list(r.EXPECTED))
        self.assertEqual([x[1] for x in self.calls if x[0] == 'probe'], ['tcp', 'ssh', 'python', 'ansible-wait', 'ansible-ping'])
        self.assertFalse(result['runtime_pipeline_complete']); self.assertFalse(result['production_iso_eligible'])
        self.assertNotIn('synthetic transport result', json.dumps(result['probes']))

    def test_pending_or_failed_final_configuration_blocks_every_transport_probe(self):
        self.session.start_helper()
        initialized=SimpleNamespace(require_complete=Mock(return_value=False))
        self.session.initialization=initialized
        with patch.object(self.session,'probe') as probe:
            self.assertFalse(self.session._poll())
            self.assertEqual(self.session.last_pending,'configuration_pending')
            initialized.require_complete.side_effect=r.ReadinessError('final_account_missing','Controlled account failure')
            with self.assertRaises(r.ReadinessError) as error:self.session._poll()
        probe.assert_not_called();self.assertEqual(error.exception.code,'final_account_missing')

    def test_expected_restart_retains_epoch_without_extending_deadline_and_never_discards_trust(self):
        self.session.start_helper();self.session.endpoint()
        deadline=self.session.deadline
        self.session.invalidate(expected_restart=True)
        self.assertEqual(self.session.deadline,deadline)
        self.assertIsNone(self.session.last_started_at)
        self.assertEqual(len(read_json(self.run.file('evidence/readiness-history.json'))['epochs']['target-001']),1)
        self.session.pinned_key=HOST_KEY
        with self.assertRaises(r.ReadinessError) as error:self.session.invalidate(expected_restart=True)
        self.assertEqual(error.exception.code,'restart_trust_pin_retained');self.assertEqual(self.session.pinned_key,HOST_KEY)

    def test_delayed_and_never_start_have_measured_transitions_and_bounded_failure(self):
        self.started = False; self.session.start_helper()
        polls = []
        started_target = None
        original_target = self.target
        def callback(elapsed):
            nonlocal started_target
            polls.append(elapsed)
            if len(polls) == 2:
                self.started = True; started_target = original_target()
        def target(): return deepcopy(started_target) if started_target else {'Id': TARGET,
            'State': {'Status': 'created', 'Running': False, 'StartedAt': '0001-01-01T00:00:00Z'}}
        with patch.object(self, 'target', side_effect=target), patch.object(r, '_run_process', side_effect=self.output):
            self.session.wait_ready(on_poll=callback)
        self.assertGreaterEqual(polls[1], polls[0])
        self.assertEqual(self.session.receipt['status'], 'ready')
        self.session.receipt['status'] = 'waiting'; self.session.receipt['transitions'] = []
        self.started = False; self.session.deadline = time.monotonic() + .02
        with patch.object(r, 'RETRY_SLEEP', .005), self.assertRaises(r.ReadinessError) as error: self.session.wait_ready()
        self.assertEqual(error.exception.code, 'target_not_started')
        with self.assertRaises(r.ReadinessError): self.session.require_ready()

    def test_authentication_trust_and_interpreter_failures_block_dependent_ping(self):
        self.session.start_helper()
        for failure, operation in (('ssh_key_rejected', 'ssh'), ('ssh_user_rejected', 'ssh'),
                                   ('ssh_host_key_mismatch', 'ssh'), ('configured_interpreter_unavailable', 'python')):
            self.session.receipt.update(status='waiting', primary_failure=None, transitions=[])
            calls = []
            def probe(name, address):
                calls.append(name)
                return {'status': 'fail', 'category': failure} if name == operation or name == 'ansible-wait' else {'status': 'pass'}
            with patch.object(self.session, 'probe', side_effect=probe), patch.object(self.session, 'pin_trust', return_value=True), \
                 self.assertRaises(r.ReadinessError) as error:
                self.session.wait_ready()
            self.assertEqual(error.exception.code, failure)
            self.assertNotIn('ansible-ping', calls)
            if failure == 'configured_interpreter_unavailable': self.assertIn('ansible-wait', calls)
            self.assertEqual(self.session.receipt['primary_failure']['code'], failure)

    def test_wrong_inventory_refuses_before_transport_and_timeout_keeps_unknown(self):
        self.session.start_helper()
        self.provisioning.receipt['inventory']['targets'][0]['host'] = '127.0.0.1'
        with patch.object(r, '_run_process', side_effect=AssertionError('No arbitrary endpoint connection')), self.assertRaises(r.ReadinessError) as error:
            self.session.wait_ready()
        self.assertEqual(error.exception.code, 'inventory_endpoint_mismatch')
        self.provisioning.receipt['inventory']['targets'][0]['host'] = '172.31.77.2'
        self.session.receipt['primary_failure'] = None
        with patch.object(r, '_run_process', return_value={'status': 'timeout', 'returncode': None, 'log': b'', 'log_truncated': False}), \
             self.assertRaises(r.ReadinessError): self.session.probe('tcp', '172.31.77.2')
        self.assertTrue(self.session.receipt['unknown_outcome'])
        before = len(self.calls)
        with self.assertRaises(r.ReadinessError): self.session.cleanup()
        self.assertFalse(any(x[:2] == ('docker', 'stop') for x in self.calls[before:]))

    def test_nonzero_runtime_exit_before_authentication_is_primary_initialization_failure(self):
        target = self.target()
        target['State'].update(Status='exited', Running=False, ExitCode=23)
        with patch.object(self.session, 'inspect', return_value=target), self.assertRaises(r.ReadinessError) as error:
            self.session.poll()
        self.assertEqual(error.exception.code, 'target_initialization_failed')
        self.assertEqual(self.session.receipt['primary_failure']['code'], 'target_initialization_failed')
        self.assertFalse(self.session.receipt['probes'])

    def test_restart_after_partial_readiness_cannot_reuse_pre_restart_observations(self):
        self.session.start_helper()
        self.session.endpoint()
        self.session.transition('tcp-reachable')
        before = deepcopy(self.session.receipt['transitions'])
        self.target_started_at = datetime.now(timezone.utc).isoformat()
        with self.assertRaises(r.ReadinessError) as error:
            self.session.poll()
        self.assertEqual(error.exception.code, 'readiness_stale')
        self.assertEqual(self.session.receipt['transitions'], before)
        self.assertFalse(self.session.receipt['probes'])

    def test_completed_receipt_with_wrong_identity_or_fake_pong_is_rejected(self):
        self.session.start_helper()
        original = self.output
        for change in (lambda v: v.update(run_id='12345678-1234-4234-9234-123456789abc'),
                       lambda v: v.update(observation={'ping': 'fake'}), lambda v: v.update(category='unreviewed_error')):
            def forged(*args, **kwargs):
                result = original(*args, **kwargs); value = json.loads(result['log']); change(value)
                result['log'] = json.dumps(value).encode(); return result
            with patch.object(r, '_run_process', side_effect=forged), self.assertRaises(r.ReadinessError):
                self.session.probe('ansible-ping', '172.31.77.2')

    def test_helper_cleanup_and_resume_are_exact_id_idempotent_preserve_primary_and_never_allocate(self):
        self.session.start_helper()
        self.session.failure(r.ReadinessError('ssh_key_rejected', 'Synthetic negative'))
        self.lease._reconciliation_only = True
        recovered = r.ReadinessSession.resume_cleanup(self.run, self.lease)
        before = len(self.calls)
        result = recovered.cleanup()
        recovered.cleanup()
        mutations = [x for x in self.calls[before:] if x[0] == 'docker']
        self.assertEqual(mutations, [('docker', 'stop', '--time', '3', HELPER), ('docker', 'rm', HELPER)])
        self.assertEqual(result['primary_failure']['code'], 'ssh_key_rejected')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['cleanup'], 'completed')
        context = read_json(self.run.file('private/readiness-controller.json')); context['helper_id'] = TARGET
        atomic_json(self.run.file('private/readiness-controller.json'), context)
        with self.assertRaises(r.ReadinessError): r.ReadinessSession.resume_cleanup(self.run, self.lease)

    def test_original_hostkey_pin_is_never_replaced_and_current_public_identity_is_recorded(self):
        self.session.start_helper()
        self.assertTrue(self.session.pin_trust())
        changed = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(reversed(range(32)))).decode()
        with patch.object(self.session, 'public_key', return_value=changed):
            observation = self.session.observe_hostkey()
            self.assertTrue(self.session.pin_trust())
        self.assertFalse(observation['matches_original_pin'])
        self.assertEqual(self.session.pinned_key, HOST_KEY)
        self.assertNotEqual(observation['fingerprint'], self.session.receipt['hostkey_fingerprint'])

    def test_retained_primary_and_unknown_are_available_before_recovery_refusal(self):
        self.session.start_helper()
        self.session.failure(r.ReadinessError('ssh_host_key_mismatch', 'Synthetic negative'))
        self.session.receipt['unknown_outcome'] = True; self.session.save()
        value = r.readiness_status(self.run)
        self.assertEqual(value['primary_failure']['code'], 'ssh_host_key_mismatch')
        self.assertTrue(value['unknown_outcome'])
        self.lease._reconciliation_only = True
        before = len(self.calls)
        with self.assertRaises(r.ReadinessError) as error: r.ReadinessSession.resume_cleanup(self.run, self.lease)
        self.assertEqual(error.exception.code, 'helper_outcome_unknown')
        self.assertFalse(any(x[0] == 'docker' for x in self.calls[before:]))
        changed = read_json(self.run.file('evidence/readiness.json')); changed['source_revision'] = '9' * 40
        atomic_json(self.run.file('evidence/readiness.json'), changed)
        with self.assertRaises(r.ReadinessError): r.readiness_status(self.run)

    def test_known_precreate_failure_can_resume_no_helper_cleanup_without_allocation_or_adoption(self):
        with patch.object(self.session, 'helper_reference', side_effect=images.ImageError('helper_image_mismatch', 'Synthetic precreate refusal')), \
             self.assertRaises(images.ImageError): self.session.start_helper()
        self.assertIsNone(self.session.helper)
        self.assertFalse(self.session.receipt['unknown_outcome'])
        atomic_json(self.run.file('private/terraform/controller.json'),
            {'schema_version': '1.0', 'run_id': self.run.id, 'source_revision': SHA, 'id': CONTROLLER})
        self.lease._reconciliation_only = True
        before = len(self.calls)
        resumed = r.ReadinessSession.resume_cleanup(self.run, self.lease)
        result = resumed.cleanup()
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(result['primary_failure']['code'], 'helper_image_mismatch')
        self.assertFalse(any(x[:2] in (('docker', 'create'), ('docker', 'start'), ('docker', 'stop'), ('docker', 'rm')) for x in self.calls[before:]))
        self.lease.record['resources'].append({'kind': 'container', 'id': '9' * 64, 'outcome': 'pending'})
        with self.assertRaises(r.ReadinessError): r.ReadinessSession.resume_cleanup(self.run, self.lease)

    def test_source_copy_is_exact_readonly_single_inode_and_recovery_rejects_tampering(self):
        self.session.start_helper()
        copy = self.session.bind_path
        self.assertEqual(copy.read_bytes(), r.RUNTIME.read_bytes())
        self.assertNotEqual(copy.stat().st_ino, r.RUNTIME.stat().st_ino)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(copy.parent.stat().st_mode), 0o700)
        self.session.validate_source_copy()
        self.lease._reconciliation_only = True
        r.ReadinessSession.resume_cleanup(self.run, self.lease)
        copy.chmod(0o600); copy.write_bytes(b'changed executable code')
        copy.chmod(0o444)
        with self.assertRaises(r.ReadinessError): self.session.validate_source_copy()
        with self.assertRaises(r.ReadinessError): r.ReadinessSession.resume_cleanup(self.run, self.lease)

    def test_validation_opt_in_binds_only_the_second_fixed_readonly_source_and_recovers_its_identity(self):
        original = self.run.file('private/synthetic-validation.py')
        atomic_bytes(original, b'print("synthetic reviewed validation code")\n')
        ordinary_helper = self.helper
        def validation_helper():
            value = ordinary_helper()
            value['Mounts'].append({'Type': 'bind', 'Source': str(self.session.validation_bind_path),
                'Destination': r.VALIDATION_MOUNT, 'RW': False})
            return value
        with patch.object(r, 'VALIDATION_RUNTIME', original), patch.object(self, 'helper', side_effect=validation_helper):
            self.session = r.ReadinessSession(self.provisioning, validation=True)
            self.session.start_helper()
            self.assertEqual(self.session.validation_bind_path.read_bytes(), original.read_bytes())
            self.assertEqual({x.name for x in self.session.bind_path.parent.iterdir()}, {'runtime.py', 'validation.py'})
            self.assertEqual(len(self.helper()['Mounts']), 2)
            self.lease._reconciliation_only = True
            resumed = r.ReadinessSession.resume_cleanup(self.run, self.lease)
            self.assertTrue(resumed.validation_enabled)
            self.assertEqual(resumed.validation_source_sha256, self.session.validation_source_sha256)
            bad = self.helper(); bad['Mounts'][1]['RW'] = True
            with self.assertRaises(r.ReadinessError): resumed.verify_helper(bad)
            copy = self.session.validation_bind_path
            copy.chmod(0o600); copy.write_bytes(b'changed validation executable'); copy.chmod(0o444)
            with self.assertRaises(r.ReadinessError): self.session.validate_source_copy()
            with self.assertRaises(r.ReadinessError): r.ReadinessSession.resume_cleanup(self.run, self.lease)

    def test_validation_selection_rejects_paths_and_boolean_aliases_without_docker(self):
        before = len(self.calls)
        for choice in ('../unreviewed.py', 1, None):
            with self.subTest(choice=choice), self.assertRaises(r.ReadinessError):
                r.ReadinessSession(self.provisioning, validation=choice)
        self.assertEqual(self.calls[before:], [])

    def test_validation_source_cannot_traverse_a_symlink_parent(self):
        folder = self.run.file('private/public-code-origin'); folder.mkdir(mode=0o700)
        atomic_bytes(folder / 'runtime.py', b'print("synthetic code")\n')
        alias = self.run.file('private/code-alias')
        try:
            alias.symlink_to(folder, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('Creating a symlink requires OS support/permission')
        before = len(self.calls)
        with patch.object(r, 'VALIDATION_RUNTIME', alias / 'runtime.py'), self.assertRaises(r.ReadinessError):
            r.ReadinessSession(self.provisioning, validation=True)
        self.assertEqual(self.calls[before:], [])

    def test_late_inspect_receiver_and_final_probe_cannot_declare_new_readiness(self):
        self.session.start_helper()
        self.session.deadline = time.monotonic() + .04
        def late_inspect(*args, **kwargs):
            self.assertLessEqual(kwargs['timeout'], .04)
            time.sleep(.05)
            return self.target()
        with patch.object(images, 'inspect', side_effect=late_inspect), self.assertRaises(r.ReadinessError): self.session.poll()
        self.assertNotEqual(self.session.receipt['status'], 'ready')
        self.session.receipt['primary_failure'] = None; self.session.deadline = time.monotonic() + .04
        self.session.helper_started = True
        atomic_bytes(self.run.file('private/credentials/id_ed25519'), b'Synthetic bounded private input, never a real key')
        other = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(reversed(range(32)))).decode()
        atomic_bytes(self.run.file('private/credentials/id_ed25519.pub'), other.encode())
        def late_receiver(*args, **kwargs):
            self.assertLessEqual(kwargs['timeout'], .04)
            time.sleep(.05)
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        with patch.object(r.subprocess, 'run', side_effect=late_receiver), self.assertRaises(r.ReadinessError):
            REAL_INJECT(self.session, HOST_KEY, '172.31.77.2')
        self.assertIsNone(self.session.pinned_key)
        self.session.receipt.update(primary_failure=None, transitions=[], status='waiting')
        self.session.deadline = time.monotonic() + .04
        def late_ping(operation, address):
            if operation == 'ansible-ping': time.sleep(.05)
            return {'status': 'pass'}
        with patch.object(self.session, 'probe', side_effect=late_ping), patch.object(self.session, 'pin_trust', return_value=True), \
             self.assertRaises(r.ReadinessError): self.session.poll()
        self.assertNotEqual(self.session.receipt['status'], 'ready')


class HelperProtocol(unittest.TestCase):
    def value(self, operation='ssh', scenario='healthy'):
        return {'schema_version': '1.0', 'run_id': '12345678-1234-4234-9234-123456789abc', 'source_revision': SHA,
            'target_id': 'target-001', 'address': '172.31.77.2', 'operation': operation, 'attempt': 1,
            'scenario': scenario, 'timeout_seconds': 1}

    def test_request_rejects_arbitrary_code_urls_overrides_duplicate_fields_and_nonfinite_bounds(self):
        for change in ({'address': 'https://example.invalid'}, {'address': '127.0.0.1'}, {'operation': 'shell'},
                       {'scenario': 'custom'}, {'timeout_seconds': float('inf')}, {'attempt': True}, {'command': 'echo bad'}):
            value = {**self.value(), **change}
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)): runtime.request(json.dumps(value).encode())
        with self.assertRaises(ValueError): runtime.request(b'{"schema_version":"1.0","schema_version":"1.0"}')

    def test_ssh_policy_and_error_categories_keep_trust_and_fixed_inputs(self):
        args = runtime.ssh_options(self.value())
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertIn('IdentitiesOnly=yes', args); self.assertIn('ControlMaster=no', args)
        for log, category in (('Host key verification failed.', 'ssh_host_key_mismatch'),
            ('REMOTE HOST IDENTIFICATION HAS CHANGED!', 'ssh_host_key_mismatch'),
            ('Permission denied (publickey).', 'ssh_key_rejected'), ('Connection refused', 'ssh_transport_pending')):
            result = {'returncode': 255, 'log': log, 'timed_out': False, 'truncated': False}
            self.assertEqual(runtime.classify(self.value(scenario='wrong-key'), result), category)


@unittest.skipUnless(os.name == 'posix', 'Real child/process-group fixtures require Linux')
class HelperSubprocess(unittest.TestCase):
    def test_capture_has_real_absolute_deadline_memory_bound_and_no_ambient_provider(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-helper-runtime-synthetic-') as temporary, patch.object(runtime, 'ROOT', Path(temporary)):
            result = runtime.capture([sys.executable, '-c', 'import time;time.sleep(10)'], .05, {'PATH': os.environ['PATH']})
            self.assertTrue(result['timed_out']); self.assertLess(result['duration_seconds'], 2)
            result = runtime.capture([sys.executable, '-c', 'print("x"*1000000)'], 2, {'PATH': os.environ['PATH']})
            self.assertTrue(result['truncated']); self.assertLessEqual(len(result['log']), runtime.MAX_LOG)
            self.assertNotIn('SSH_AUTH_SOCK', runtime.environment()); self.assertNotIn('DOCKER_HOST', runtime.environment())

    def test_actual_argv_and_private_structured_ansible_result_require_expected_ping(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-ansible-protocol-synthetic-') as temporary, patch.object(runtime, 'ROOT', Path(temporary)):
            value = HelperProtocol().value('ansible-ping')
            attempt = Path(temporary) / 'attempt'; attempt.mkdir(mode=0o700)
            calls = []
            def child(argv, timeout, environment):
                calls.append(argv)
                results = attempt / 'results'; results.mkdir()
                (results / 'target-001').write_text(json.dumps({'ping': 'pong', 'changed': False}))
                return {'returncode': 0, 'log': '', 'timed_out': False, 'truncated': False}
            with patch.object(runtime, 'capture', side_effect=child):
                result, observation = runtime.ansible(value, attempt)
            self.assertEqual(result['returncode'], 0); self.assertEqual(observation['ping'], 'pong')
            self.assertIn('ansible.builtin.ping', calls[0]); self.assertIn('--tree', calls[0]); self.assertIn('--forks', calls[0])
            self.assertNotIn('-a', calls[0]); self.assertNotIn('--args', calls[0]); self.assertNotIn('{}', calls[0])
            inventory = json.loads((attempt / 'inventory.json').read_text())['all']['hosts']['target-001']
            self.assertEqual(inventory['ansible_connection'], 'ssh')
            self.assertEqual(inventory['ansible_python_interpreter'], '/usr/bin/python3')
            # Exact inventory variable names source-traced to the locked ssh
            # plugin v2.21.5 options341..366 and implementations1304..1414.
            self.assertIs(inventory['ansible_ssh_use_tty'], False)
            self.assertEqual(inventory['ansible_ssh_transfer_method'], 'piped')
            self.assertIn('StrictHostKeyChecking=yes', inventory['ansible_ssh_args'])
            self.assertIn('IdentitiesOnly=yes', inventory['ansible_ssh_args'])
            (attempt / 'results/target-001').write_text(json.dumps({'ping': 'fabricated'}))
            with patch.object(runtime, 'capture', return_value={'returncode': 0, 'log': '', 'timed_out': False, 'truncated': False}):
                result, observation = runtime.ansible(value, attempt)
            self.assertEqual(result['returncode'], 2); self.assertIsNone(observation['ping'])

    def test_wait_requires_successful_terminal_capture_and_exact_positive_shape_not_elapsed_with_error(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-ansible-wait-synthetic-') as temporary, patch.object(runtime, 'ROOT', Path(temporary)):
            root = Path(temporary)
            value = HelperProtocol().value('ansible-wait')
            cases = [({'elapsed': 0, 'changed': False}, 0, False, False, True),
                ({'elapsed': 16, 'msg': 'timed out waiting for ping module test: PTY allocation request failed'}, 0, False, False, False),
                ({'elapsed': 16, 'msg': 'timed out waiting for ping module test'}, 2, False, False, False),
                ({'elapsed': 0}, 2, False, False, False), ({'elapsed': 0}, 0, True, False, False),
                ({'elapsed': 0}, 0, False, True, False), ({'elapsed': 0, 'failed': True}, 0, False, False, False),
                ({'elapsed': 0, 'exception': 'controlled failure'}, 0, False, False, False),
                ({'elapsed': 0, 'skipped': True}, 0, False, False, False), ({'elapsed': True}, 0, False, False, False)]
            for index, (tree, code, timed_out, truncated, expected) in enumerate(cases):
                attempt = root / ('case-' + str(index)); attempt.mkdir(mode=0o700)
                def child(argv, *_):
                    self.assertEqual(argv.count('-a'), 1)
                    self.assertEqual(json.loads(argv[argv.index('-a') + 1]), {'timeout': 15, 'connect_timeout': 3, 'sleep': 1})
                    self.assertEqual(argv[argv.index('-m') + 1], 'ansible.builtin.wait_for_connection')
                    results = attempt / 'results'; results.mkdir()
                    (results / 'target-001').write_text(json.dumps(tree))
                    return {'returncode': code, 'log': '', 'timed_out': timed_out, 'truncated': truncated}
                with self.subTest(index=index), patch.object(runtime, 'capture', side_effect=child):
                    result, observation = runtime.ansible(value, attempt)
                    self.assertIs(observation['structured_target_result'], expected)
                    self.assertEqual(result['returncode'] == 0, expected)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'Root-only disposable UID10001 permission fixture; no host/container changes')
class PublicSourcePermissions(unittest.TestCase):
    def test_root0600_original_stays_private_and_uid10001_can_reopen_only_readonly_code_inode(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-source-permission-synthetic-') as temporary:
            root = Path(temporary)
            original = root / 'original.py'
            original.write_bytes(b'print("public synthetic reviewed code")\n')
            original.chmod(0o600)
            run = create_run(root / 'runs', fixture=False, identity=(SHA, False))
            session = r.ReadinessSession.__new__(r.ReadinessSession)
            session.run, session.bind_path, session.bind_identity = run, run.file('private/helper-source/runtime.py'), None
            session.validation_enabled = False
            session.validation_source_sha256 = session.validation_bind_identity = None
            session.validation_bind_path = run.file('private/helper-source/validation.py')
            with patch.object(r, 'RUNTIME', original):
                session.source_sha256 = r.runtime_hash()
                session.prepare_source_copy()
                session.validate_source_copy()
                source_fd, copy_fd = os.open(original, os.O_RDONLY), os.open(session.bind_path, os.O_RDONLY)
                try:
                    # /proc/self/fd reopens the inode and checks its permissions
                    # without traversing private host ancestry, like a single-file
                    # bind. Reading an inherited FD directly would bypass that check.
                    code = '''import hashlib,json,os,sys
out={}
for name,number in zip(('original','copy'),sys.argv[1:]):
 try:
  with open('/proc/self/fd/'+number,'rb') as f: out[name]=hashlib.sha256(f.read(65537)).hexdigest()
 except PermissionError: out[name]='permission-denied'
print(json.dumps(out))'''
                    def drop():
                        os.setgroups([]); os.setgid(10001); os.setuid(10001)
                    result = subprocess.run([sys.executable, '-I', '-c', code, str(source_fd), str(copy_fd)],
                        pass_fds=(source_fd, copy_fd), preexec_fn=drop, capture_output=True, timeout=5, check=True)
                finally:
                    os.close(source_fd); os.close(copy_fd)
                value = json.loads(result.stdout)
                self.assertEqual(value['original'], 'permission-denied')
                self.assertEqual(value['copy'], session.source_sha256)
                self.assertEqual(stat.S_IMODE(original.stat().st_mode), 0o600)
                self.assertEqual(session.bind_path.stat().st_uid, 0)


if __name__ == '__main__': unittest.main()
