"""Original generated-byte/policy fixtures; every Docker operation is mocked."""
from contextlib import ExitStack
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from wormhole import candidate as c, chunks, images, provisioning as p, admission
from wormhole.runs import create_run, read_json, atomic_json
from test_admission import observed

SHA = 'a' * 40
BUILDER = 'b' * 64
DERIVED = 'sha256:' + 'c' * 64


class CandidateFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wormhole-candidate-synthetic-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = create_run(self.root / 'runs', fixture=False, identity=(SHA, False))
        for module in (c, chunks):
            item = patch.object(module, 'source_identity', return_value=(SHA, False)); item.start(); self.addCleanup(item.stop)
        self.assertEqual(chunks.execute_fixture(self.run)['status'], 'passed')
        with self.run.locked(): self.bundle = c.prepare_candidate(self.run)


class Bundle(CandidateFixture, unittest.TestCase):
    def test_exact_bundle_source_and_original_payload_hashes_are_rechecked(self):
        value = c.validate_bundle(self.run)
        self.assertEqual(value['manifest']['source_sha256'], chunks.report_chunks(self.run)['result']['verified_output']['sha256'])
        self.assertEqual([x['path'] for x in value['manifest']['files']], list(c.NAMES))
        self.assertFalse(value['manifest']['production_iso_eligible'])
        self.assertEqual(value['candidate_sha256'], c.sha(c.canonical(value['manifest'])))
        (value['directory'] / 'version.txt').write_bytes(b'wrong-version\n')
        with self.assertRaises(c.CandidateError): c.validate_bundle(self.run)

    def test_schema_matches_generated_and_unknown_path_version_or_missing_file_refuses(self):
        self.assertEqual(json.loads((c.SOURCE_ROOT / 'schemas/candidate-manifest-v1.schema.json').read_text()), c.schema())
        for mutate in (lambda x: x.update(schema_version='2.0'), lambda x: x.update(role='Owner'),
            lambda x: x['files'][0].update(path='../credential'), lambda x: x['files'].pop(),
            lambda x: x.update(source_dirty=True), lambda x: x.update(production_iso_eligible=True)):
            value = deepcopy(self.bundle['manifest']); mutate(value)
            with self.assertRaises((c.CandidateError, ValueError)): c.validate_manifest(value)

    def test_reconstructed_byte_mutation_and_extra_file_cannot_be_adopted(self):
        path = chunks.verified_source(self.run); path.write_bytes(b'changed')
        with self.assertRaises(Exception): c.validate_bundle(self.run)

    @unittest.skipUnless(os.name == 'posix', 'POSIX ordinary-file link refusal')
    def test_bundle_symlink_or_hardlink_is_refused(self):
        path = self.bundle['directory'] / 'version.txt'; original = path.read_bytes(); path.unlink()
        other = self.root / 'other'; other.write_bytes(original); other.chmod(0o600)
        path.symlink_to(other)
        with self.assertRaises(Exception): c.validate_bundle(self.run)
        path.unlink(); os.link(other, path)
        with self.assertRaises(Exception): c.validate_bundle(self.run)

    @unittest.skipUnless(os.name == 'posix', 'Explicit SIGALRM handler requires Linux')
    def test_installer_explicit_alarm_interrupts_a_blocked_authored_child(self):
        program = "import importlib.util,time\ns=importlib.util.spec_from_file_location('installer'," + repr(str(c.CONTEXT / 'install.py')) + ")\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.enable_deadline(1)\ntry: time.sleep(5)\nexcept TimeoutError: raise SystemExit(0)\nraise SystemExit(3)"
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program], timeout=3, capture_output=True)
        self.assertEqual(result.returncode, 0)


@unittest.skipUnless(os.name == 'posix', 'Linux builder policy fixtures; all Docker calls mocked')
class Build(CandidateFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.plan = admission.build_plan('smoke', observed()); self.plan['synthetic'] = False
        self.calls = []; self.running = False; self.started = False; self.polls = 0; self.removed = False; self.committed = False
        parent = self
        class Lease:
            run_id = parent.run.id; source_revision = SHA; plan = parent.plan; _reconciliation_only = False
            record = {'resources': []}
            def _active(self): pass
            def set_phase(self, phase): parent.calls.append(('phase', phase))
            def register_resource(self, kind, identity): self.record['resources'].append({'kind': kind, 'id': identity, 'outcome': 'pending'})
            def reconcile_resource(self, kind, identity, **options):
                parent.calls.append(('reconcile', kind, identity))
                for item in self.record['resources']:
                    if (item['kind'], item['id']) == (kind, identity): item['outcome'] = options.get('outcome', 'absent')
        self.lease = Lease()
        self.base_labels = c.qualified_base_labels()
        self.labels = {**self.base_labels, images.LABEL + '.role': 'candidate-builder', images.LABEL + '.run_id': self.run.id,
            images.LABEL + '.source_revision': SHA, images.LABEL + '.candidate_sha256': self.bundle['candidate_sha256']}
        self.mounts = {'/candidate-input': str(self.bundle['directory']), '/recipe/install.py': str(c.CONTEXT / 'install.py')}
        self.expected = self.plan['limits']['build']['docker_create']

    def container(self):
        e = self.expected
        if self.running:
            self.polls += 1
            if self.polls > 1: self.running = False
        return {'Id': BUILDER, 'Image': p.TARGET_IMAGE, 'Config': {'Labels': self.labels, 'User': '0:0', 'Entrypoint': ['/usr/bin/python3'],
            'Cmd': ['/recipe/install.py'], 'Env': ['PATH=/usr/bin:/bin']},
            'HostConfig': {'Memory': e['memory_bytes'], 'MemorySwap': e['memory_swap_bytes'], 'NanoCpus': e['nano_cpus'],
                'PidsLimit': e['pids_limit'], 'LogConfig': {'Type': e['log_driver'], 'Config': e['log_opts']},
                'NetworkMode': 'none', 'IpcMode': 'private', 'Privileged': False, 'ReadonlyRootfs': False, 'CapDrop': ['ALL'], 'CapAdd': [],
                'SecurityOpt': ['no-new-privileges:true'], 'RestartPolicy': {'Name': 'no'}},
            'Mounts': [{'Type': 'bind', 'RW': False, 'Source': source, 'Destination': dest} for dest, source in self.mounts.items()],
            'State': {'Running': self.running, 'Pid': 123 if self.running else 0, 'ExitCode': 0,
                'Status': 'running' if self.running else 'exited' if self.started else 'created',
                'StartedAt': '2026-10-23T17:00:00Z' if self.started else '0001-01-01T00:00:00Z'}, 'SizeRw': 65536}

    def inspect(self, kind, identity, **options):
        self.calls.append(('inspect', kind, identity))
        if kind == 'container': return None if self.removed else self.container()
        if identity == p.TARGET_IMAGE:
            return {'Id': p.TARGET_IMAGE, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': self.base_labels}}
        if not self.committed: return None
        return {'Id': DERIVED, 'Parent': p.TARGET_IMAGE, 'Size': 123456, 'Os': 'linux', 'Architecture': 'amd64',
            'Config': {'Labels': c.binding_labels(self.run, self.bundle['candidate_sha256'], self.base_labels),
                'User': '0:0', 'Entrypoint': ['/usr/bin/python3', '/opt/wormhole/runtime.py', 'target'], 'Cmd': []}}

    def docker(self, args, **options):
        self.calls.append(('docker', *args))
        if args[0] == 'create':
            self.assertNotIn('--privileged', args); self.assertIn('none', args); self.assertNotIn('--cap-add', args)
            self.assertFalse(any('credentials' in value or 'target-input' in value or 'docker.sock' in value for value in args))
            return {'log': (BUILDER + '\n').encode(), 'log_truncated': False}
        if args[0] == 'start': self.running = self.started = True
        if args[0] == 'stop': self.running = False
        if args[0] == 'rm': self.removed = True
        if args[0] == 'commit': self.committed = True
        if args[0] == 'info': return {'log': str(self.root).encode(), 'log_truncated': False}
        if args[0] == 'cp':
            raw = c.canonical({'status': 'installed', 'candidate_sha256': self.bundle['candidate_sha256'], 'files': self.bundle['manifest']['files']})
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                info = tarfile.TarInfo('candidate-installed.json'); info.size = len(raw); archive.addfile(info, io.BytesIO(raw))
            return {'log': buffer.getvalue(), 'log_truncated': False}
        return {'log': b'', 'log_truncated': False}

    def patches(self):
        stack = ExitStack()
        for target, name, value in ((images, 'RUNS_ROOT', self.run.workspace), (images, 'inspect', self.inspect),
            (images, 'docker', self.docker), (images, 'cgroup_limits', {'synthetic': True}),
            (images, 'assembly_storage_guard', None), (c.time, 'sleep', None)):
            stack.enter_context(patch.object(target, name, side_effect=value) if callable(value) else patch.object(target, name, return_value=value) if name not in {'RUNS_ROOT'} else patch.object(target, name, value))
        return stack

    def test_derived_image_journal_and_stock_defaults_stay_separate(self):
        with self.patches(): binding = c.build_candidate(self.run, self.lease, self.bundle)
        self.assertEqual(binding['image_id'], DERIVED); self.assertEqual(binding['base_image'], p.TARGET_IMAGE)
        self.assertTrue(self.removed)
        self.assertEqual(self.lease.record['resources'], [{'kind': 'container', 'id': BUILDER, 'outcome': 'absent'},
            {'kind': 'image', 'id': DERIVED, 'outcome': 'retained'}])
        self.assertNotIn(('phase', 'reconciling'), self.calls)
        self.assertEqual(c.validate_binding(self.run), binding)
        for mutate in (lambda x: x.update(Id=p.TARGET_IMAGE), lambda x: x.update(Parent='sha256:' + 'd' * 64),
            lambda x: x['Config'].update(Volumes={'/unsafe': {}})):
            actual = self.inspect('image', DERIVED); mutate(actual)
            with self.assertRaises(c.CandidateError): c.verify_image(actual, binding)

    def test_commit_timeout_preserves_unknown_and_never_removes_builder_or_adopts_image(self):
        original = self.docker
        def fail(args, **options):
            if args[0] == 'commit': raise OSError('Synthetic lost commit response')
            return original(args, **options)
        with self.patches(), patch.object(images, 'docker', side_effect=fail), self.assertRaises(OSError):
            c.build_candidate(self.run, self.lease)
        self.assertTrue(read_json(self.run.file('evidence/candidate-build.json'))['unknown_outcome'])
        self.assertFalse(self.removed); self.assertFalse(self.run.file('evidence/candidate-binding.json').exists())
        self.assertEqual(self.lease.record['resources'], [{'kind': 'container', 'id': BUILDER, 'outcome': 'pending'}])

    def test_wrong_builder_image_refuses_before_start_and_source_drift_refuses_before_commit(self):
        original = self.inspect
        def wrong(kind, identity, **options):
            value = original(kind, identity, **options)
            if kind == 'container' and value is not None: value['Image'] = DERIVED
            return value
        with self.patches(), patch.object(images, 'inspect', side_effect=wrong), self.assertRaises(c.CandidateError):
            c.build_candidate(self.run, self.lease)
        self.assertFalse(any(call[:2] == ('docker', 'start') for call in self.calls))

    def test_source_drift_during_assembly_cannot_commit_or_write_binding(self):
        original = self.docker
        def drift(args, **options):
            result = original(args, **options)
            if args[0] == 'cp': (self.bundle['directory'] / 'config.json').write_bytes(b'{"changed":true}')
            return result
        with self.patches(), patch.object(images, 'docker', side_effect=drift), self.assertRaises(c.CandidateError):
            c.build_candidate(self.run, self.lease)
        self.assertFalse(self.committed); self.assertFalse(self.run.file('evidence/candidate-binding.json').exists())


if __name__ == '__main__': unittest.main()
