"""Host-boundary checks for the real image qualification adapter."""
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from wormhole.admission import load_profile, _projection
from wormhole.images import ImageError, LABEL

SPEC = importlib.util.spec_from_file_location('qualification', Path(__file__).resolve().parents[1] / 'scripts/qualify_images.py')
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


class FakeRun:
    id = '01234567-0123-4123-8123-012345678901'
    def __init__(self, root): self.root = root
    def file(self, relative): return self.root / relative


class RuntimeBoundary(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.run = FakeRun(Path(self.folder.name))
        self.identifier = 'a' * 64
        self.image = 'sha256:' + 'b' * 64
        self.network = 'c' * 64
        self.limits = _projection(load_profile('smoke')['limits']['helper'])
        expected = self.limits['docker_create']
        self.value = {'Id': self.identifier, 'Image': self.image,
                      'Config': {'Labels': {LABEL + '.run_id': self.run.id, LABEL + '.role': 'helper'}, 'User': '10001:10001'},
                      'HostConfig': {'Memory': expected['memory_bytes'], 'MemorySwap': expected['memory_swap_bytes'],
                                     'NanoCpus': expected['nano_cpus'], 'PidsLimit': expected['pids_limit'],
                                     'LogConfig': {'Type': expected['log_driver'], 'Config': expected['log_opts']},
                                     'Privileged': False, 'ReadonlyRootfs': True, 'NetworkMode': self.network,
                                     'PidMode': '', 'IpcMode': 'private', 'UTSMode': '', 'PortBindings': {},
                                     'PublishAllPorts': False, 'RestartPolicy': {'Name': 'no'},
                                     'CapDrop': ['ALL'], 'CapAdd': [], 'SecurityOpt': ['no-new-privileges:true'],
                                     'Tmpfs': {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=10001,gid=10001',
                                               '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777',
                                               '/run/input': 'rw,nosuid,nodev,noexec,size=64k,mode=0700,uid=10001,gid=10001'}},
                      'Mounts': []}

    def inspect(self, value):
        with patch.object(qualification, 'inspect', return_value=value):
            return qualification.runtime_inspection(self.identifier, 'helper', self.image, self.network, self.run, self.limits)

    def test_runtime_rejects_image_ownership_privilege_socket_and_budget_changes(self):
        self.assertEqual(self.inspect(self.value), self.value)
        changes = [('Id', 'd' * 64), ('Image', 'sha256:' + 'd' * 64),
                   ('HostConfig.Memory', 0), ('HostConfig.MemorySwap', -1), ('HostConfig.NanoCpus', 0),
                   ('HostConfig.PidsLimit', 0), ('HostConfig.Privileged', True),
                   ('HostConfig.ReadonlyRootfs', False), ('HostConfig.PidMode', 'host'),
                   ('HostConfig.NetworkMode', 'host'), ('HostConfig.CapAdd', ['SYS_ADMIN']),
                   ('HostConfig.PublishAllPorts', True), ('HostConfig.PortBindings', {'2222/tcp': [{'HostPort': '2222'}]}),
                   ('HostConfig.SecurityOpt', ['seccomp=unconfined']), ('Config.User', '0:0'),
                   ('Mounts', [{'Type': 'bind', 'Source': '/var/run/docker.sock'}])]
        for name, new in changes:
            with self.subTest(name=name):
                value = deepcopy(self.value)
                parts = name.split('.')
                parent = value
                for part in parts[:-1]: parent = parent[part]
                parent[parts[-1]] = new
                with self.assertRaises(ImageError): self.inspect(value)

    def test_private_input_archive_is_bounded_uid_owned_tmpfs_only_and_env_isolated(self):
        path = self.run.file('private/credentials/id_ed25519')
        path.parent.mkdir(parents=True)
        path.write_bytes(b'synthetic-private-fixture-not-a-key')
        public = 'ssh-ed25519 AAAA'
        with patch.object(qualification, 'docker_configuration', return_value='/private/empty-docker'), \
             patch.object(qualification.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as command:
            qualification.inject_helper_inputs(self.run, self.identifier, public, '172.30.0.2')
        args, kwargs = command.call_args
        self.assertEqual(args[0], ['docker', '--config', '/private/empty-docker', '--host', 'unix:///var/run/docker.sock', 'cp', '-a', '-', self.identifier + ':/run/input'])
        self.assertFalse({'DOCKER_CONTEXT', 'DOCKER_HOST', 'HOME', 'AWS_SECRET_ACCESS_KEY'} & set(kwargs['env']))
        with tarfile.open(fileobj=io.BytesIO(kwargs['input'])) as archive:
            self.assertEqual([m.name for m in archive], ['id_ed25519', 'known_hosts'])
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.mode), (10001, 10001, 0o600))
        path.write_bytes(b'x' * 16385)
        with patch.object(qualification.subprocess, 'run') as command:
            with self.assertRaises(ImageError):
                qualification.inject_helper_inputs(self.run, self.identifier, public, '172.30.0.2')
            command.assert_not_called()

    def test_remote_probe_is_one_fixed_valid_python_program(self):
        argv = shlex.split(qualification.remote_probe())
        self.assertEqual(argv[:2], ['/usr/bin/python3', '-c'])
        self.assertEqual(len(argv), 3)
        compile(argv[2], '<reviewed-ssh-probe>', 'exec')
        self.assertNotIn('environ', argv[2])

    def test_preallocation_refusal_receipt_is_terminal_without_hiding_primary_error(self):
        path = Path(self.folder.name) / 'receipt.json'
        receipt = {'status': 'pending', 'run_id': self.run.id}
        with self.assertRaisesRegex(ImageError, 'capacity'):
            with qualification.report_failures(receipt, path):
                raise ImageError('capacity_refused', 'capacity')
        saved = json.loads(path.read_text())
        self.assertEqual(saved['status'], 'failed-before-allocation')
        self.assertEqual(saved['failure_code'], 'capacity_refused')
        self.assertTrue(saved['resources_reconciled'])


if __name__ == '__main__': unittest.main()
