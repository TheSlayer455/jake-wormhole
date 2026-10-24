"""Real local filesystem/flock/crash tests with explicitly synthetic gate inputs.

No Docker, SSH, provisioning, API or network occurs. Original component replays
have their own WORM-017 fixtures; these tests never call a mocked gate runtime
qualification. The unprivileged EACCES test alone uses a real own dropped-UID fork.
"""
from copy import deepcopy
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from wormhole import candidate as c, images, pipeline, publication as p, publication_records as r
from wormhole.runs import atomic_bytes, atomic_json, common, create_run, read_json

SHA = 'a' * 40


@unittest.skipUnless(sys.platform.startswith('linux'), 'Actual Linux private paths, descriptors, flock and fork required')
class PublicationFilesystem(unittest.TestCase):
    def setUp(self):
        # /tmp is intentionally world-writable and is not a production-trusted
        # publication ancestor. Use a dedicated owned temporary HOME child.
        self.temporary = tempfile.TemporaryDirectory(prefix='wormhole-publication-synthetic-', dir=Path.home())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.root, self.runs = self.base / 'releases', self.base / 'runs'
        self.run = create_run(self.runs, fixture=False, identity=(SHA, False), kernel_lock=True)
        self.patch(p, 'RELEASE_ROOT', self.root)
        self.patch(images, 'RUNS_ROOT', self.runs)
        self.patch(p, 'source_identity', return_value=(SHA, False))
        self.real_probe = p.probe_private_visibility
        self.probe = self.patch(p, 'probe_private_visibility', side_effect=lambda directory: {
            'owner_pid': os.getpid(), 'owner_uid': os.geteuid(), 'owner_gid': os.getegid(),
            'probe_pid': os.getpid() + 100000, 'probe_uid': 65534 if os.geteuid() != 65534 else 65533,
            'probe_gid': 65534, 'probe_path': 'REFERENCE.txt', 'errno': errno.EACCES, 'outcome': 'denied'})
        self.patch(images, 'inspect', side_effect=AssertionError('No live Docker observation is permitted'))
        self.patch(c, 'prepare_candidate', side_effect=AssertionError('Publication must not rebuild a candidate'))
        self.patch(c, 'build_candidate', side_effect=AssertionError('Publication must not build an image'))
        self.bundle_dir = self.run.file('private/candidate')
        self.bundle_dir.mkdir(mode=0o700)
        raw = {'source.synthetic.bin': b'Synthetic source fixture\x00\xff\n',
               'payload.py': b'print("synthetic-public-payload")\n',
               'version.txt': b'1.0.0-reference\n', 'config.json': b'{"synthetic":true}\n'}
        self.manifest = {**common(self.run.manifest()), 'operation': 'synthetic-filesystem-fixture',
                         'source_sha256': p.digest(raw[c.NAMES[0]]),
                         'files': [{'path': name, 'sha256': p.digest(raw[name]), 'size': len(raw[name])} for name in c.NAMES]}
        for name, value in raw.items():
            atomic_bytes(self.bundle_dir / name, value)
        atomic_bytes(self.bundle_dir / 'manifest.json', c.canonical(self.manifest))
        self.bundle = {'directory': self.bundle_dir, 'manifest': self.manifest,
                       'candidate_sha256': p.digest(c.canonical(self.manifest))}
        self.patch(c, 'validate_bundle', return_value=self.bundle)
        self.identity = {**pipeline.candidate_identity(self.manifest), 'image_digest': 'sha256:' + 'c' * 64}
        self.exports = {name: ('Synthetic original safe projection: ' + name + '\n').encode() for name in r.EVIDENCE_PATHS}
        self.decision = {**common(self.run.manifest()), 'reference_eligible': True, 'reference_scope_complete': True,
                         'production_iso_eligible': False, 'record_sha256': p.digest(self.exports['report.json'])}
        self.exports['decision.json'] = r.canonical(self.decision) + b'\n'
        self.report = {'decision': self.decision, 'record': {'status': 'passed', 'candidate': self.identity,
                       'plan_sha256': 'b' * 64, 'cleanup': {'archive_sha256': 'd' * 64}}}
        self.replay = self.patch(pipeline, 'report_pipeline', side_effect=lambda run: deepcopy(self.report))
        self.render = self.patch(pipeline, 'export_files', side_effect=lambda *args: deepcopy(self.exports))
        atomic_json(self.run.file(pipeline.REQUEST), {'platform': 'ubuntu'})
        atomic_json(self.run.file(pipeline.PLAN), {'fixture': 'synthetic-frozen-plan'})
        export = self.run.file(pipeline.EXPORT)
        export.mkdir(mode=0o700)
        for name, value in self.exports.items():
            parent = export
            for part in Path(name).parts[:-1]:
                parent = parent / part
                parent.mkdir(mode=0o700, exist_ok=True)
            atomic_bytes(export / name, value)
        p.initialize_publication_root()

    def patch(self, target, attribute, *args, **kwargs):
        item = patch.object(target, attribute, *args, **kwargs)
        result = item.start()
        self.addCleanup(item.stop)
        return result

    @property
    def destination(self):
        return self.root / ('reference-' + self.run.id)

    def failed(self, operation, code=None):
        with self.assertRaises(Exception) as caught:
            operation()
        error = caught.exception
        self.assertIsInstance(error, p.RunError)
        if code is not None:
            self.assertEqual(error.code, code)
        return error

    def receipt(self, error):
        self.assertEqual(error.run_id, self.run.id)
        self.assertTrue(error.receipt.startswith('private/publication-attempts/'))
        return r.validate_receipt(read_json(self.run.file(error.receipt)))

    def hashes(self):
        return {path.relative_to(self.destination).as_posix(): p.digest(path.read_bytes())
                for path in self.destination.rglob('*') if path.is_file()}

    def test_literal_ubuntu_copy_two_rechecks_private_modes_and_readonly_independent_inspection(self):
        originals = {path.name: path.read_bytes() for path in self.bundle_dir.iterdir()}
        receipt = p.publish_reference(self.run)
        self.assertEqual(receipt['status'], 'completed')
        self.assertTrue(receipt['durability_acknowledged'])
        self.assertEqual(self.replay.call_count, 2)
        self.assertEqual(self.render.call_count, 2)
        self.assertEqual(set(self.hashes()), set(r.publication_paths('ubuntu')))
        for name, raw in originals.items():
            self.assertEqual((self.destination / 'candidate' / name).read_bytes(), raw)
            self.assertEqual((self.bundle_dir / name).read_bytes(), raw)
        for name, raw in self.exports.items():
            self.assertEqual((self.destination / 'evidence' / name).read_bytes(), raw)
        for path in (self.destination, *self.destination.rglob('*')):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
            if path.is_file():
                self.assertEqual(path.stat().st_nlink, 1)
        before = self.hashes()
        result = p.inspect_publication(self.run.id)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['historical_durability'], 'not-inferred')
        self.assertEqual(result['completion_sha256'], receipt['completion_sha256'])
        self.assertEqual(before, self.hashes())
        self.assertFalse(result['completion']['production_eligible'])
        self.assertFalse(result['completion']['image_published'])

    def test_fixed_synthetic_ubi_branch_copies_selected_license_and_original_manifest(self):
        from wormhole import rpm_candidate, rpm_source
        atomic_json(self.run.file(pipeline.REQUEST), {'platform': 'ubi'})
        self.patch(rpm_candidate, 'validate_bundle', return_value=self.bundle)
        license_path = self.run.file('private/synthetic-license.pdf')
        license_bytes = b'SYNTHETIC PUBLIC LICENSE FIXTURE, NOT THE ACTUAL UBI PDF\n'
        atomic_bytes(license_path, license_bytes)
        self.patch(rpm_source, 'validate_eula', return_value=license_path)
        self.patch(r, 'EULA_BYTES', new=len(license_bytes))
        self.patch(r, 'EULA_SHA256', new=p.digest(license_bytes))
        receipt = p.publish_reference(self.run)
        self.assertEqual(receipt['status'], 'completed')
        self.assertEqual(set(self.hashes()), set(r.publication_paths('ubi')))
        self.assertEqual((self.destination / r.EULA_PATH).read_bytes(), license_bytes)
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'complete')

    def test_failed_gate_refuses_before_reserving_a_destination_and_preserves_failure(self):
        self.report['decision']['reference_eligible'] = False
        error = self.failed(lambda: p.publish_reference(self.run), 'publication_ineligible')
        self.assertFalse(self.destination.exists())
        value = self.receipt(error)
        self.assertEqual(value['status'], 'refused')
        self.assertFalse(value['logical_complete'])
        self.assertFalse(value['durability_acknowledged'])

    def test_final_gate_failure_and_changed_source_never_get_a_complete_marker(self):
        def change(event, detail):
            if event == 'before-complete':
                self.report['decision']['reference_eligible'] = False
        error = self.failed(lambda: p.publish_reference(self.run, checkpoint=change), 'publication_ineligible')
        self.assertFalse((self.destination / 'COMPLETE.json').exists())
        self.assertEqual(self.receipt(error)['status'], 'failed')
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')

    def test_source_mutation_during_copy_is_not_new_tested_bytes(self):
        def change(event, detail):
            if event == 'file-copied' and detail['path'] == 'candidate/source.synthetic.bin':
                (self.bundle_dir / 'source.synthetic.bin').write_bytes(b'changed source')
        error = self.failed(lambda: p.publish_reference(self.run, checkpoint=change), 'publication_source_changed')
        self.assertFalse((self.destination / 'COMPLETE.json').exists())
        self.assertFalse(self.receipt(error)['logical_complete'])

    def test_copied_destination_tampering_and_source_revision_drift_refuse(self):
        def change(event, detail):
            if event == 'before-complete':
                (self.destination / 'candidate/version.txt').write_bytes(b'changed version')
        self.failed(lambda: p.publish_reference(self.run, checkpoint=change), 'publication_destination_changed')
        self.assertFalse((self.destination / 'COMPLETE.json').exists())

    def test_replaced_destination_name_cannot_receive_a_success_for_the_old_open_descriptor(self):
        def change(event, detail):
            if event == 'file-copied':
                self.destination.rename(self.base / 'moved-owned-release')
                self.destination.mkdir(mode=0o700)
        self.failed(lambda: p.publish_reference(self.run, checkpoint=change), 'publication_destination_changed')
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertFalse((self.base / 'moved-owned-release/COMPLETE.json').exists())

    def test_source_revision_change_after_copy_cannot_be_hidden_by_a_mocked_receipt(self):
        def change(event, detail):
            if event == 'before-complete':
                p.source_identity.return_value = ('f' * 40, False)
        self.failed(lambda: p.publish_reference(self.run, checkpoint=change), 'publication_source_changed')
        self.assertFalse((self.destination / 'COMPLETE.json').exists())

    def test_symlink_source_refuses_without_following_it_or_reserving_output(self):
        original = self.bundle_dir / 'payload.py'
        alternate = self.run.file('private/synthetic-other.txt')
        atomic_bytes(alternate, original.read_bytes())
        original.unlink()
        original.symlink_to(alternate)
        self.failed(lambda: p.publish_reference(self.run))
        self.assertFalse(self.destination.exists())

    def test_hardlink_or_broad_source_permissions_refuse_without_a_destination(self):
        original = self.bundle_dir / 'payload.py'
        os.link(original, self.run.file('private/synthetic-hardlink'))
        self.failed(lambda: p.publish_reference(self.run), 'publication_unsafe_file')
        self.assertFalse(self.destination.exists())
        self.run.file('private/synthetic-hardlink').unlink()
        original.chmod(0o644)
        self.failed(lambda: p.publish_reference(self.run), 'publication_unsafe_file')
        self.assertFalse(self.destination.exists())

    def test_oversized_evidence_refuses_instead_of_truncating_or_publishing(self):
        large = b'x' * (1024 * 1024 + 1)
        self.exports['summary.json'] = large
        atomic_bytes(self.run.file(pipeline.EXPORT + '/summary.json'), large, limit=len(large))
        self.failed(lambda: p.publish_reference(self.run), 'publication_evidence_bound')
        self.assertFalse(self.destination.exists())

    def test_complete_and_incomplete_duplicates_never_overwrite_or_reuse_attempts(self):
        p.publish_reference(self.run)
        original = self.hashes()
        error = self.failed(lambda: p.publish_reference(self.run), 'publication_duplicate')
        self.assertEqual(original, self.hashes())
        self.assertEqual(self.receipt(error)['status'], 'refused')

    def test_root_initializer_is_idempotent_but_does_not_adopt_unmarked_or_linked_paths(self):
        inode = (self.root / 'publication.lock').stat().st_ino
        self.assertFalse(p.initialize_publication_root()['created'])
        self.assertEqual((self.root / 'publication.lock').stat().st_ino, inode)
        other = self.base / 'unowned'
        other.mkdir(mode=0o700)
        with patch.object(p, 'RELEASE_ROOT', other):
            self.failed(p.initialize_publication_root)
        self.assertEqual(list(other.iterdir()), [])
        link = self.base / 'linked-root'
        link.symlink_to(self.root, target_is_directory=True)
        with patch.object(p, 'RELEASE_ROOT', link):
            self.failed(p.initialize_publication_root)

    def test_real_competing_process_cannot_replace_or_share_stable_publication_flock(self):
        code = "from pathlib import Path;import sys;from wormhole import publication as p;p.RELEASE_ROOT=Path(sys.argv[1]);\ntry:\n with p._root_locked():print('unexpected')\nexcept p.RunError as e:print(e.code)"
        inode = (self.root / 'publication.lock').stat().st_ino
        with p._root_locked():
            child = subprocess.run([sys.executable, '-B', '-c', code, str(self.root)], capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0)
        self.assertEqual(child.stdout.strip(), b'publication_busy')
        self.assertEqual((self.root / 'publication.lock').stat().st_ino, inode)

    def crash(self, event):
        process = os.fork()
        if process == 0:
            try:
                def terminate(actual, metadata):
                    if actual == event:
                        os._exit(86)
                p.publish_reference(self.run, checkpoint=terminate)
            finally:
                os._exit(87)
        deadline = time.monotonic() + 10
        while True:
            waited, status = os.waitpid(process, os.WNOHANG)
            if waited:
                break
            if time.monotonic() >= deadline:
                os.kill(process, 9)  # This exact own filesystem-only fixture child.
                os.waitpid(process, 0)
                self.fail('Owned filesystem fixture did not reach its bounded checkpoint')
            time.sleep(0.01)
        self.assertEqual(waited, process)
        self.assertEqual(os.waitstatus_to_exitcode(status), 86)

    def test_actual_crash_after_reservation_keeps_incomplete_destination_and_blocks_reuse(self):
        self.crash('reserved')
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')
        self.failed(lambda: p.publish_reference(self.run), 'publication_duplicate')
        self.assertFalse((self.destination / 'COMPLETE.json').exists())

    def test_actual_crash_midcopy_has_no_complete_release(self):
        self.crash('file-copied')
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')
        self.assertFalse((self.destination / 'COMPLETE.json').exists())

    def test_actual_crash_before_marker_is_incomplete(self):
        self.crash('before-complete')
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')
        self.assertFalse((self.destination / 'COMPLETE.json').exists())

    def test_actual_crash_in_marker_link_window_is_not_a_complete_single_link_tree(self):
        self.crash('marker-linked')
        marker, pending = self.destination / 'COMPLETE.json', self.destination / '.COMPLETE.pending'
        self.assertEqual(marker.read_bytes(), pending.read_bytes())
        self.assertEqual(marker.stat().st_ino, pending.stat().st_ino)
        self.assertEqual(marker.stat().st_nlink, 2)
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')
        self.failed(lambda: p.publish_reference(self.run), 'publication_duplicate')

    def test_actual_crash_after_commit_before_receipt_remains_logically_complete_not_fsync_history(self):
        self.crash('committed-before-receipt')
        result = p.inspect_publication(self.run.id)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['historical_durability'], 'not-inferred')
        attempts = list(self.run.file('private/publication-attempts').glob('*.json'))
        self.assertEqual(len(attempts), 1)
        self.assertEqual(read_json(attempts[0])['status'], 'running')
        self.assertEqual((self.destination / 'COMPLETE.json').stat().st_nlink, 1)

    def test_directory_fsync_failure_after_link_never_acknowledges_producer_completion(self):
        original_sync = p._sync
        active = False
        def sync(descriptor):
            if active:
                raise OSError('Synthetic directory durability failure')
            original_sync(descriptor)
        def fail(event, detail):
            nonlocal active
            if event == 'marker-linked':
                active = True
        with patch.object(p, '_sync', side_effect=sync):
            error = self.failed(lambda: p.publish_reference(self.run, checkpoint=fail), 'publication_io_error')
        self.assertFalse(self.receipt(error)['durability_acknowledged'])
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')

    def test_post_unlink_fsync_failure_preserves_logical_complete_but_not_durability(self):
        original_sync = p._sync
        def sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                names = os.listdir(descriptor)
                if 'COMPLETE.json' in names and '.COMPLETE.pending' not in names:
                    raise OSError('Synthetic final directory durability failure')
            original_sync(descriptor)
        with patch.object(p, '_sync', side_effect=sync):
            error = self.failed(lambda: p.publish_reference(self.run), 'publication_io_error')
        receipt = self.receipt(error)
        inspection = p.inspect_publication(self.run.id)
        self.assertEqual(receipt['status'], 'failed')
        self.assertTrue(receipt['logical_complete'])
        self.assertFalse(receipt['durability_acknowledged'])
        self.assertEqual(inspection['status'], 'complete')
        self.assertEqual(receipt['completion_sha256'], inspection['completion_sha256'])
        self.assertEqual(inspection['historical_durability'], 'not-inferred')

    def test_complete_tree_rejects_extra_file_edited_candidate_and_swapped_source_on_inspection(self):
        p.publish_reference(self.run)
        extra = self.destination / 'private-key.txt'
        extra.write_text('Synthetic unapproved export')
        extra.chmod(0o600)
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')
        extra.unlink()
        (self.bundle_dir / 'version.txt').write_bytes(b'changed original')
        self.assertEqual(p.inspect_publication(self.run.id)['status'], 'incomplete')

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Actual dropped-UID EACCES requires root fixture operator')
    def test_actual_owned_visibility_probe_drops_groups_uid_and_observes_eacces(self):
        self.probe.side_effect = self.real_probe
        receipt = p.publish_reference(self.run)
        proof = read_json(self.run.file('private/publication-visibility-' + receipt['attempt_id'] + '.json'))
        self.assertEqual(proof['owner_pid'], os.getpid())
        self.assertEqual(proof['owner_uid'], 0)
        self.assertNotEqual(proof['probe_uid'], proof['owner_uid'])
        self.assertEqual(proof['errno'], errno.EACCES)
        self.assertEqual(proof['outcome'], 'denied')
        self.assertEqual(proof['probe_path'], 'REFERENCE.txt')
        self.assertEqual(p.inspect_publication(self.run.id)['completion']['visibility']['probe_uid'], proof['probe_uid'])


class PlatformRefusal(unittest.TestCase):
    def test_nonlinux_publisher_fails_before_any_destination_or_state_operation(self):
        with patch.object(p.sys, 'platform', 'win32'), self.assertRaises(p.PublicationError) as error:
            p.initialize_publication_root()
        self.assertEqual(error.exception.code, 'publication_linux_required')


if __name__ == '__main__':
    unittest.main()
