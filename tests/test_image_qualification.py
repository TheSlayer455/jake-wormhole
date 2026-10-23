"""Host-boundary checks for the real image qualification adapter."""
from copy import deepcopy
import base64
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import os
import sys
import unittest
from unittest.mock import patch

from wormhole.admission import load_profile, _projection
from wormhole.images import ImageError, LABEL, recipe_identity, expected_labels
from wormhole.runs import atomic_json, create_run, read_json

SPEC = importlib.util.spec_from_file_location('qualification', Path(__file__).resolve().parents[1] / 'scripts/qualify_images.py')
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


class FakeRun:
    id = '01234567-0123-4123-8123-012345678901'
    def __init__(self, root): self.root = root
    def file(self, relative): return self.root / relative


class BuildProvenance(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.workspace = Path(self.folder.name) / 'runs'
        self.recipe, self.hashes = recipe_identity()
        self.target, self.target_receipt, self.target_image = self.build('target', 'a' * 40, 'sha256:' + 'd' * 64)
        self.helper, self.helper_receipt, self.helper_image = self.build('helper', 'b' * 40, 'sha256:' + 'e' * 64)

    def build(self, role, revision, image_id):
        run = create_run(self.workspace, fixture=False, identity=(revision, False))
        value = {'schema_version': '1.0', 'operation': 'ubuntu-image-assembly', 'status': 'completed',
                 'resources_reconciled': True, 'role': role, 'run_id': run.id, 'source_revision': revision,
                 'recipe_sha256': self.recipe, 'source_files': self.hashes, 'image_id': image_id}
        atomic_json(run.file('evidence/image-build-' + role + '.json'), value)
        image = {'Id': image_id, 'Os': 'linux', 'Architecture': 'amd64',
                 'Config': {'Volumes': None, 'Labels': expected_labels(run, role, self.recipe, self.hashes['images.lock.json'])}}
        return run, value, image

    def reference(self, value=None, image=None):
        if value is not None:
            atomic_json(self.target.file('evidence/image-build-target.json'), value)
        with patch.object(qualification, 'RUNS_ROOT', self.workspace), \
             patch.object(qualification, 'inspect', return_value=self.target_image if image is None else image):
            return qualification.build_reference(self.target.id, 'target')

    def test_distinct_target_helper_and_controller_sources_keep_original_provenance(self):
        controller_revision = 'c' * 40
        run = create_run(self.workspace, fixture=False, identity=(controller_revision, False))
        def inspect(kind, image_id):
            self.assertEqual(kind, 'image')
            return deepcopy({self.target_receipt['image_id']: self.target_image,
                             self.helper_receipt['image_id']: self.helper_image}[image_id])
        with patch.object(qualification, 'RUNS_ROOT', self.workspace), patch.object(qualification.sys, 'platform', 'linux'), \
             patch.object(qualification, 'source_identity', return_value=(controller_revision, False)), \
             patch.object(qualification, 'create_run', return_value=run), patch.object(qualification, 'inspect', side_effect=inspect), \
             patch.object(qualification, 'create_auth', side_effect=ImageError('fixture_stop', 'Stop before credential generation or allocation')), \
             patch.object(qualification, 'AdmissionLease') as lease:
            with self.assertRaisesRegex(ImageError, 'Stop before'):
                qualification.qualify(self.target.id, self.helper.id)
        lease.assert_not_called()
        receipt = read_json(run.file('evidence/image-qualification.json'))
        self.assertEqual(receipt['source_revision'], controller_revision)
        self.assertEqual(receipt['target_build_source_revision'], 'a' * 40)
        self.assertEqual(receipt['helper_build_source_revision'], 'b' * 40)
        self.assertEqual(receipt['source_files'], self.hashes)
        self.assertEqual(len(receipt['source_files']), 7)
        self.assertEqual(receipt['recipe_sha256'], self.recipe)
        self.assertEqual(self.target_image['Config']['Labels'][LABEL + '.source_revision'], 'a' * 40)
        self.assertEqual(self.helper_image['Config']['Labels'][LABEL + '.source_revision'], 'b' * 40)

    def test_dirty_controller_is_rejected_before_new_run_or_image_inspection(self):
        with patch.object(qualification.sys, 'platform', 'linux'), \
             patch.object(qualification, 'source_identity', return_value=('c' * 40, True)), \
             patch.object(qualification, 'create_run') as create, patch.object(qualification, 'inspect') as inspect:
            with self.assertRaises(ImageError): qualification.qualify(self.target.id, self.helper.id)
        create.assert_not_called()
        inspect.assert_not_called()

    def test_only_completed_reconciled_canonical_role_build_receipts_are_accepted(self):
        self.assertEqual(self.reference()['source_revision'], 'a' * 40)
        for field, value in (('schema_version', '2.0'), ('operation', 'image-ssh-qualification'),
                             ('status', 'pending'), ('status', 'unresolved'), ('resources_reconciled', False),
                             ('resources_reconciled', 1), ('role', 'helper'), ('run_id', self.helper.id),
                             ('source_revision', 'f' * 40), ('source_revision', 'A' * 40),
                             ('source_revision', 'abc123'), ('image_id', 'sha256:short')):
            candidate = deepcopy(self.target_receipt); candidate[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ImageError): self.reference(candidate)

    def test_original_run_must_be_clean_real_and_match_its_build_revision(self):
        original = self.target.manifest()
        for field, value in (('source_dirty', True), ('source_revision', 'f' * 40), ('mode', 'fixture')):
            manifest = deepcopy(original); manifest[field] = value
            self.target.save_manifest(manifest)
            with self.subTest(field=field), self.assertRaises(ImageError): self.reference()
        self.target.save_manifest(original)

    def test_every_recipe_file_and_combined_identity_must_match_current_controller(self):
        for name in self.hashes:
            candidate = deepcopy(self.target_receipt)
            candidate['source_files'][name] = 'f' * 64
            with self.subTest(file=name), self.assertRaises(ImageError): self.reference(candidate)
        for change in ('missing', 'extra', 'combined'):
            candidate = deepcopy(self.target_receipt)
            if change == 'missing': candidate['source_files'].pop('runtime.py')
            if change == 'extra': candidate['source_files']['unapproved.sh'] = 'f' * 64
            if change == 'combined': candidate['recipe_sha256'] = 'f' * 64
            with self.subTest(change=change), self.assertRaises(ImageError): self.reference(candidate)

    def test_actual_immutable_image_platform_volumes_and_original_build_labels_are_checked(self):
        for field, value in (('Id', self.helper_receipt['image_id']), ('Os', 'windows'),
                             ('Architecture', 'arm64'), ('Config.Volumes', {'/unapproved': {}}),
                             ('Config.Labels.' + LABEL + '.source_revision', 'c' * 40),
                             ('Config.Labels.' + LABEL + '.run_id', self.helper.id),
                             ('Config.Labels.' + LABEL + '.role', 'helper'),
                             ('Config.Labels.' + LABEL + '.recipe_sha256', 'f' * 64),
                             ('Config.Labels.' + LABEL + '.lock_sha256', 'f' * 64)):
            candidate = deepcopy(self.target_image)
            if field.startswith('Config.Labels.'):
                candidate['Config']['Labels'][field.removeprefix('Config.Labels.')] = value
            elif field == 'Config.Volumes': candidate['Config']['Volumes'] = value
            else: candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ImageError): self.reference(image=candidate)


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
                      'Config': {'Labels': {LABEL + '.run_id': self.run.id, LABEL + '.role': 'helper'}, 'User': '10001:10001',
                                 'Entrypoint': ['/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py', 'helper'],
                                 'Cmd': ['wait', '180'], 'Env': ['WORMHOLE_RUNTIME_TTL_SECONDS=600']},
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
                   ('Config.Env', ['WORMHOLE_RUNTIME_TTL_SECONDS=9999']), ('Config.Entrypoint', ['/bin/sh']),
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
        path.with_name('id_ed25519.pub').write_text('ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'\x00' * 32).decode())
        public = 'ssh-ed25519 AAAA'
        with patch.object(qualification, 'docker_configuration', return_value='/private/empty-docker'), \
             patch.object(qualification, 'owned_runtime', return_value={'State': {'Running': True}, 'Config': {'User': '10001:10001'}}), \
             patch.object(qualification.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as command:
            qualification.inject_helper_inputs(self.run, self.identifier, self.image, public, '172.30.0.2', {})
        args, kwargs = command.call_args
        self.assertEqual(args[0], ['docker', '--config', '/private/empty-docker', '--host', 'unix:///var/run/docker.sock',
            'exec', '-i', '--user', '10001:10001', self.identifier, '/opt/wormhole/venv/bin/python', '-I', '-S', '-c', qualification.INPUT_RECEIVER_COMMAND])
        self.assertFalse({'DOCKER_CONTEXT', 'DOCKER_HOST', 'HOME', 'AWS_SECRET_ACCESS_KEY'} & set(kwargs['env']))
        with tarfile.open(fileobj=io.BytesIO(kwargs['input'])) as archive:
            self.assertEqual([m.name for m in archive], ['id_ed25519', 'known_hosts', 'wrong_known_hosts'])
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.mode), (10001, 10001, 0o600))
        path.write_bytes(b'x' * 16385)
        with patch.object(qualification, 'owned_runtime', return_value={'State': {'Running': True}, 'Config': {'User': '10001:10001'}}), patch.object(qualification.subprocess, 'run') as command:
            with self.assertRaises(ImageError):
                qualification.inject_helper_inputs(self.run, self.identifier, self.image, public, '172.30.0.2', {})
            command.assert_not_called()

    def test_public_key_observation_uses_owned_live_exec_and_rejects_bad_outputs(self):
        raw = 'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'\x00' * 32).decode()
        Path(self.folder.name, 'private').mkdir(mode=0o700)
        result = {'status': 'pass', 'returncode': 0, 'duration_seconds': .01, 'log': raw.encode(), 'log_truncated': False}
        with patch.object(qualification, 'owned_runtime', return_value={'State': {'Running': True}}), \
             patch.object(qualification, 'docker_configuration', return_value='/empty'), \
             patch.object(qualification, '_run_process', return_value=result) as command:
            self.assertEqual(qualification.copied_public_key(self.identifier, self.image, self.run, {}), raw)
        argv = command.call_args.args[0]
        self.assertEqual(argv[5:12], ('exec', '--user', '0:0', self.identifier, '/usr/bin/python3', '-I', '-S'))
        self.assertNotIn('cp', argv)
        self.assertIn('/run/wormhole/hostkeys/ssh_host_ed25519_key.pub', argv[-1])
        for bad, truncated in ((b'not a public key', False), (b'x' * 513, False), (raw.encode(), True)):
            candidate = {**result, 'log': bad, 'log_truncated': truncated}
            with patch.object(qualification, 'owned_runtime', return_value={'State': {'Running': True}}), \
                 patch.object(qualification, 'docker_configuration', return_value='/empty'), \
                 patch.object(qualification, '_run_process', return_value=candidate), self.assertRaises(ImageError):
                qualification.copied_public_key(self.identifier, self.image, self.run, {})

    def test_failed_attempt_keeps_private_role_stage_and_timeout_metadata(self):
        Path(self.folder.name, 'private').mkdir(mode=0o700)
        receipt = {}
        result = {'status': 'timeout', 'returncode': None, 'log': b'synthetic dependency failure',
                  'log_truncated': False, 'duration_seconds': 5}
        with patch.object(qualification, 'docker_configuration', return_value='/empty'), \
             patch.object(qualification, '_run_process', return_value=result), self.assertRaises(ImageError):
            qualification.attempted_docker(self.run, receipt, 'helper', 'doctor', ('exec', self.identifier, 'fixed-tool'))
        self.assertEqual(receipt['attempts'][0]['role'], 'helper')
        self.assertEqual(receipt['attempts'][0]['stage'], 'doctor')
        self.assertEqual(receipt['attempts'][0]['status'], 'timeout')
        self.assertEqual(self.run.file(receipt['attempts'][0]['private_log']).read_bytes(), result['log'])
        with patch.object(qualification, 'atomic_bytes', side_effect=OSError('synthetic full storage')):
            qualification.attempt_record(self.run, receipt, 'target', 'runtime-failure', result)
        self.assertTrue(receipt['attempts'][-1]['diagnostic_write_failed'])

    def test_docker_cap_prefix_and_security_boolean_spelling_preserve_same_policy(self):
        value = deepcopy(self.value)
        value['HostConfig']['CapDrop'] = ['CAP_ALL']
        value['HostConfig']['SecurityOpt'] = ['no-new-privileges=true']
        self.inspect(value)
        value['HostConfig']['CapAdd'] = ['CAP_SYS_ADMIN']
        with self.assertRaises(ImageError): self.inspect(value)
        value['HostConfig']['CapAdd'] = []
        value['HostConfig']['SecurityOpt'] = ['no-new-privileges=false']
        with self.assertRaises(ImageError): self.inspect(value)

    def test_remote_probe_is_one_fixed_valid_python_program(self):
        argv = shlex.split(qualification.remote_probe())
        self.assertEqual(argv[:2], ['/usr/bin/python3', '-c'])
        self.assertEqual(len(argv), 3)
        compile(argv[2], '<reviewed-ssh-probe>', 'exec')
        self.assertNotIn('environ', argv[2])

    def test_helper_cleanup_failure_does_not_strand_owned_target(self):
        target, helper = 'a' * 64, 'd' * 64
        resources = [(target, 'target', self.image), (helper, 'helper', self.image)]
        calls, reconciled = [], []
        class Lease:
            def set_phase(self, phase): calls.append(('phase', phase))
            def reconcile_resource(self, kind, identifier): reconciled.append((kind, identifier))
        def owned(identifier, *_args, **_kwargs):
            if identifier == helper: raise ImageError('ownership_mismatch', 'Changed helper owner')
            return {'State': {'Running': True}}
        def inspect(kind, _identifier, **_kwargs):
            if kind == 'container': return None
            return {'Id': self.network, 'Labels': {LABEL + '.run_id': self.run.id},
                    'Containers': {helper: {}}}
        def command(argv, **_kwargs):
            calls.append(tuple(argv))
            return {'log': b'', 'log_truncated': False}
        with patch.object(qualification, 'owned_runtime', side_effect=owned), \
             patch.object(qualification, 'inspect', side_effect=inspect), \
             patch.object(qualification, 'docker', side_effect=command):
            failures = qualification.cleanup_known_resources(Lease(), resources, self.network, self.run, unknown=False)
        self.assertIn(('stop', '--time', '3', target), calls)
        self.assertIn(('rm', target), calls)
        self.assertIn(('container', target), reconciled)
        self.assertNotIn(('stop', '--time', '3', helper), calls)
        self.assertEqual({f['resource'] for f in failures}, {'helper', 'network'})

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


@unittest.skipUnless(sys.platform.startswith('linux') and Path('/dev/shm').is_dir(), 'Actual receiver fixtures require existing Linux tmpfs; no mounts are created')
class LiveTmpfsReceiver(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='wormhole-receiver-fixture-', dir='/dev/shm')
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        namespace = {}
        exec(qualification.INPUT_RECEIVER, namespace)
        self.receive = namespace['receive_inputs']
        self.uid, self.gid = os.getuid(), os.getgid()
        self.contents = {'id_ed25519': b'synthetic fixture, not a private key',
                         'known_hosts': b'synthetic public trust', 'wrong_known_hosts': b'synthetic negative public trust'}

    def archive(self, entries=None):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            for name, content, changes in (entries if entries is not None else [(n, c, {}) for n, c in self.contents.items()]):
                item = tarfile.TarInfo(name)
                item.uid, item.gid = self.uid, self.gid
                item.mode, item.size = 0o600, len(content)
                for key, value in changes.items(): setattr(item, key, value)
                archive.addfile(item, io.BytesIO(content) if item.isfile() else None)
        return data.getvalue()

    def destination(self, name):
        root = self.root / name
        root.mkdir(mode=0o700)
        return root

    def test_actual_receiver_creates_only_expected_uid_owned_private_files_without_overwrite(self):
        root = self.destination('valid')
        self.receive(io.BytesIO(self.archive()), root, self.uid, self.gid)
        self.assertEqual({p.name for p in root.iterdir()}, set(self.contents))
        for name, raw in self.contents.items():
            path = root / name
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(path.stat().st_uid, self.uid)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError): self.receive(io.BytesIO(self.archive()), root, self.uid, self.gid)
        self.assertEqual((root / 'id_ed25519').read_bytes(), self.contents['id_ed25519'])

    def test_receiver_rejects_malformed_archive_before_writing_any_entry(self):
        original = [(n, c, {}) for n, c in self.contents.items()]
        invalid = [original[:-1], original + [original[0]],
                   [('unapproved', b'x', {})] + original,
                   [('../id_ed25519', b'x', {})] + original[1:],
                   [('id_ed25519', b'x', {'type': tarfile.SYMTYPE, 'linkname': '/etc/passwd'})] + original[1:],
                   [('id_ed25519', b'x', {'uid': self.uid + 1})] + original[1:],
                   [('id_ed25519', b'x', {'mode': 0o644})] + original[1:],
                   [('id_ed25519', b'x' * 16385, {})] + original[1:],
                   [('id_ed25519', b'x', {'pax_headers': {'comment': 'unapproved'}})] + original[1:]]
        for index, entries in enumerate(invalid):
            root = self.destination('rejected-' + str(index))
            with self.subTest(index=index), self.assertRaises((ValueError, tarfile.TarError)):
                self.receive(io.BytesIO(self.archive(entries)), root, self.uid, self.gid)
            self.assertFalse(list(root.iterdir()))
        root = self.destination('oversized')
        with self.assertRaises(ValueError): self.receive(io.BytesIO(b'x' * 65537), root, self.uid, self.gid)
        self.assertFalse(list(root.iterdir()))

    def test_receiver_refuses_linked_or_nonprivate_destination(self):
        root = self.destination('ordinary')
        alias = self.root / 'alias'; alias.symlink_to(root, target_is_directory=True)
        with self.assertRaises(ValueError): self.receive(io.BytesIO(self.archive()), alias, self.uid, self.gid)
        root.chmod(0o755)
        with self.assertRaises(ValueError): self.receive(io.BytesIO(self.archive()), root, self.uid, self.gid)
        self.assertFalse(list(root.iterdir()))


if __name__ == '__main__': unittest.main()
