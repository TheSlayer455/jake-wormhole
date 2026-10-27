"""Source/fixture checks only; no test here claims an installed VM."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole import admission as a, vm_admission as v, vm_inputs as i
from wormhole.runs import RunError, atomic_json, now
from test_admission import observed


class Inputs(unittest.TestCase):
    def test_boot_entries_preserve_iso_kernel_and_add_unattended_serial(self):
        original = 'set timeout=30\n linux /casper/vmlinuz  ---\n initrd /casper/initrd\n'
        result = i.boot_config(original)
        self.assertIn('timeout=1', result)
        self.assertIn('/casper/vmlinuz  autoinstall console=ttyS0,115200n8 ---', result)
        self.assertIn('initrd /casper/initrd', result)
        for wrong in ('linux /other/kernel ---', result):
            with self.assertRaises(RunError):
                i.boot_config(wrong)

    def test_seed_contains_no_bootstrap_or_private_key_and_retains_host_key(self):
        text = i.cloud_config(str(uuid4()), 'ssh-ed25519 ' + 'A' * 68, '192.0.2.10/24', '52:54:00:11:22:33')
        value = json.loads(text.split('\n', 1)[1])['autoinstall']
        self.assertNotIn('identity', value)
        self.assertEqual([], value['user-data']['users'])
        self.assertFalse(value['user-data']['ssh_deletekeys'])
        self.assertFalse(value['refresh-installer']['update'])
        self.assertFalse(value['ssh']['allow-pw'])
        self.assertIn('curtin', text)
        self.assertIn('WORMHOLE_INSTALLATION_FAILED', text)
        self.assertIn('lab.service', text)
        with self.assertRaises(RunError):
            i.cloud_config(str(uuid4()), 'ssh-ed25519 A;echo secret', '192.0.2.10/24', '52:54:00:11:22:33')

    def test_terraform_contract_is_empty_disk_real_cdrom_isolated_network(self):
        value = i.terraform_config('wormhole-vm-0123456789ab', '/lab/pool', '/lab/candidate.iso',
                                   '/lab/seed.iso', '192.0.2.0/24', '52:54:00:11:22:33', 1001, 1002)
        resource = value['resource']
        domain = resource['libvirt_domain']['run']
        self.assertEqual(domain['type'], 'kvm')
        self.assertEqual(domain['memory'], 8192)
        self.assertNotIn('kernel', domain)
        self.assertNotIn('firmware', domain)  # explicit BIOS profile
        self.assertIn('/domain/devices/graphics', domain['xml']['xslt'])
        self.assertIn("disk[@device='disk']/driver/@type", domain['xml']['xslt'])
        self.assertIn('name="type">qcow2', domain['xml']['xslt'])
        self.assertEqual(domain['boot_device']['dev'], ['hd', 'cdrom'])
        self.assertNotIn('source', resource['libvirt_volume']['disk'])
        self.assertEqual(domain['disk'][0], {'file': '${libvirt_volume.disk.id}'})
        self.assertIn('<owner>1001</owner><group>1002</group>', resource['libvirt_volume']['disk']['xml']['xslt'])
        self.assertIn('<mode>0600</mode>', resource['libvirt_volume']['disk']['xml']['xslt'])
        self.assertEqual(resource['libvirt_network']['run']['mode'], 'none')
        self.assertFalse(resource['libvirt_network']['run']['dhcp']['enabled'])


@unittest.skipUnless(os.name == 'posix', 'Linux private storage/flock fixtures')
class SharedAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'infrastructure'
        self.patch = patch.object(a, 'CANONICAL_INFRASTRUCTURE_ROOT', self.root)
        self.patch.start()
        with a.AdmissionLease(self.root, str(uuid4()), 'a' * 40,
                              collector=lambda _: observed(), allow_synthetic=True) as lease:
            lease.finish(reconciliation_complete=True)

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_vm_exit_does_not_imply_cleanup_or_allow_container_admission(self):
        with v.VMLease(self.root, str(uuid4()), 'b' * 40) as lease:
            lease.intent('domain', 'owned-domain')
            with self.assertRaises(RunError):
                lease.finish()
        with self.assertRaises(RunError) as failure:
            with a.AdmissionLease(self.root, str(uuid4()), 'a' * 40,
                                  collector=lambda _: observed(), allow_synthetic=True):
                self.fail('Unreconciled VM admitted a container run')
        self.assertEqual(failure.exception.code, 'unreconciled_vm_run')

    def test_finished_vm_requires_durable_matching_archive(self):
        with v.VMLease(self.root, str(uuid4()), 'b' * 40) as lease:
            lease.intent('installer_iso', '/private/candidate.iso')
            lease.reconciled('installer_iso', '/private/candidate.iso', retained_input=True)
            lease.finish()
            identifier = lease.id
        v.require_vm_reconciled(self.root)
        (self.root / 'vm-history' / (identifier + '.json')).unlink()
        with self.assertRaises(OSError):
            v.require_vm_reconciled(self.root)

    def test_resume_can_only_reconcile_the_original_run(self):
        identifier = str(uuid4())
        with v.VMLease(self.root, identifier, 'b' * 40) as lease:
            lease.intent('pool', 'owned-pool')
        with self.assertRaises(RunError):
            with v.VMLease.resume(self.root, str(uuid4()), 'b' * 40):
                self.fail('Wrong run resumed')
        with v.VMLease.resume(self.root, identifier, 'b' * 40) as lease:
            with self.assertRaises(RunError):
                lease.intent('domain', 'new-allocation')
            lease.reconciled('pool', 'owned-pool')
            lease.finish()
        v.require_vm_reconciled(self.root)

    def test_vm_rejects_container_unreconciled_and_same_live_lock(self):
        with a.AdmissionLease(self.root, str(uuid4()), 'a' * 40,
                              collector=lambda _: observed(), allow_synthetic=True):
            with self.assertRaises(RunError):
                with v.VMLease(self.root, str(uuid4()), 'b' * 40):
                    self.fail('Concurrent backends admitted')
        with self.assertRaises(RunError) as failure:
            with v.VMLease(self.root, str(uuid4()), 'b' * 40):
                self.fail('Unreconciled container admitted a VM')
        self.assertEqual(failure.exception.code, 'unreconciled_container_run')

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Root-owned QEMU path fixture')
    def test_new_qemu_directory_traversal_survives_private_umask(self):
        from wormhole.vm_baseline import create_qemu_directory
        path = Path(self.temp.name) / 'qemu-share'
        previous = os.umask(0o077)
        try:
            create_qemu_directory(path, os.getgid())
        finally:
            os.umask(previous)
        self.assertEqual(path.stat().st_mode & 0o777, 0o710)
        with self.assertRaises(FileExistsError):
            create_qemu_directory(path, os.getgid())


class VMJournal(unittest.TestCase):
    def test_closed_backend_and_production_boundary(self):
        value = {'schema_version': '1.0', 'backend': 'libvirt-iso', 'run_id': str(uuid4()),
            'source_revision': 'b' * 40, 'state': 'active', 'created_at': now(), 'updated_at': now(),
            'resources': [{'kind': 'domain', 'identity': 'owned', 'outcome': 'pending'}],
            'production_iso_eligible': False}
        v.validate_record(value)
        for change in ({'backend': 'docker'}, {'production_iso_eligible': True}, {'state': 'finished'}):
            with self.assertRaises(RunError):
                v.validate_record({**value, **change})
