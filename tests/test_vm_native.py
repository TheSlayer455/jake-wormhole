"""Native XML and bounded command-boundary fixtures; not real VM acceptance."""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4
import xml.etree.ElementTree as ET

from wormhole import vm_native as native
from wormhole.runs import RunError, atomic_json


class NativeVM(unittest.TestCase):
    def config(self):
        self.name = 'wormhole-vm-' + uuid4().hex[:12]
        return native.configuration(self.name, '/native-fixture/'+self.name+'/disk',
            '/native-fixture/candidate&test.iso', '/native-fixture/seed.iso', '192.0.2.0/24',
            '52:54:00:11:22:33', 107, 108, disk_bytes=32*1024**3, filter_name=self.name+'-isolation')

    def test_xml_matches_declared_bios_guest_and_escapes_media_paths(self):
        config = self.config();roots = {key:ET.fromstring(value) for key, value in config.items()}
        domain = roots['domain'];network = roots['network'];volume = roots['volume']
        self.assertEqual(domain.get('type'), 'kvm')
        self.assertEqual(domain.find('os/type').attrib, {'arch':'x86_64', 'machine':'pc-i440fx-8.2'})
        self.assertIsNone(domain.find('os/kernel'));self.assertIsNone(domain.find('os/loader'))
        self.assertEqual([x.get('dev') for x in domain.findall('os/boot')], ['hd', 'cdrom'])
        self.assertEqual(domain.findtext('memory'), '8388608');self.assertEqual(domain.findtext('vcpu'), '2')
        self.assertEqual(domain.find('cpu').get('mode'), 'host-passthrough')
        disks = domain.findall('devices/disk')
        self.assertEqual([x.find('target').attrib for x in disks],
            [{'dev':'vda', 'bus':'virtio'}, {'dev':'hda', 'bus':'ide'}, {'dev':'hdb', 'bus':'ide'}])
        self.assertEqual(disks[1].find('source').get('file'), '/native-fixture/candidate&test.iso')
        self.assertTrue(all(x.find('readonly') is not None for x in disks[1:]))
        self.assertEqual(domain.find('devices/interface/filterref').get('filter'), self.name+'-isolation')
        self.assertEqual(domain.find('devices/console/target').attrib, {'type':'serial', 'port':'0'})
        self.assertIsNone(domain.find('devices/graphics'));self.assertIsNone(network.find('forward'))
        self.assertIsNone(network.find('ip/dhcp'));self.assertEqual(network.find('dns').get('enable'), 'no')
        self.assertEqual(network.find('ip').get('address'), '192.0.2.1')
        self.assertEqual(int(volume.findtext('capacity')), 32*1024**3)
        self.assertEqual(volume.findtext('target/permissions/mode'), '0600')
        self.assertEqual(volume.findtext('target/permissions/owner'), '107')

    @unittest.skipUnless(os.name=='posix','Linux recovery owner context')
    def test_recovery_reads_new_observations_and_preserves_previous_logs(self):
        from wormhole.ubuntu_recovery import native_reconcile
        with tempfile.TemporaryDirectory() as directory:
            run=Path(directory);old=run/'native-inspect-domain-all.log';old.write_text('historical observation')
            def observed_absent(args,**kwargs):
                self.assertIn(args[3],{'list','net-list','pool-list'})
                kwargs['stdout'].write(b'')
            with patch('wormhole.ubuntu_recovery.subprocess.run',side_effect=observed_absent):
                attempt=run/native_reconcile(run,self.config())
            self.assertEqual((attempt/'native-inspect-domain-all.log').read_text(),'')
            self.assertEqual(old.read_text(),'historical observation')
            self.assertTrue((attempt/'native-verify-pool-list.log').is_file())

    def command(self, run, observed, active, mutations, fail=None):
        def execute(args, label, *, timeout):
            self.assertEqual(args[:3], native.VIRSH);self.assertGreater(timeout, 0)
            op = args[3];output = ''
            queries = {'list':'domain', 'net-list':'network', 'pool-list':'pool'}
            dumps = {'dumpxml':'domain', 'net-dumpxml':'network', 'pool-dumpxml':'pool'}
            if op in queries:
                kind = queries[op]
                if kind in observed and ('--all' in args or kind in active):output = self.name+'\n'
            elif op in dumps:output = observed[dumps[op]]
            else:
                mutations.append(op)
                if op == fail:raise RunError('injected_creation_failure', 'Synthetic interrupted command.')
                if op == 'pool-define':observed['pool'] = Path(args[4]).read_text()
                elif op == 'pool-undefine':observed.pop('pool')
                else:self.fail('Unexpected fixture mutation: '+op)
            (run/(label+'.log')).write_text(output)
            return 0
        return execute

    def test_foreign_pool_or_network_prevents_any_domain_cleanup(self):
        config = self.config()
        for kind in ('pool', 'network'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                run = Path(directory);atomic_json(run/'native-config.json', config)
                observed = deepcopy(config);root = ET.fromstring(observed[kind])
                if kind == 'pool':root.find('target/path').text = '/unrelated'
                else:ET.SubElement(root, 'forward', {'mode':'nat'})
                observed[kind] = ET.tostring(root, encoding='unicode')
                mutations = [];command = self.command(run, observed, {'domain', 'network', 'pool'}, mutations)
                with self.assertRaises(RunError):native.destroy(run, config, command)
                self.assertEqual(mutations, [])

    def test_interrupted_before_pool_build_recovers_without_allocating_or_deleting_elsewhere(self):
        config = self.config();observed = {};mutations = []
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory);atomic_json(run/'native-config.json', config)
            command = self.command(run, observed, set(), mutations, fail='pool-build')
            with self.assertRaises(RunError):native.create(run, config, command)
            self.assertEqual(set(observed), {'pool'})
            self.assertEqual(mutations, ['pool-define', 'pool-build'])
            native.destroy(run, config, command)
            self.assertEqual(observed, {})
            self.assertEqual(mutations, ['pool-define', 'pool-build', 'pool-undefine'])
            self.assertTrue((run/'native-config.json').is_file())
            native.destroy(run, config, command)  # Recorded, already-absent resources stay absent.
            self.assertEqual(len(mutations), 3)
