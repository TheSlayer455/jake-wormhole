"""Native libvirt lifecycle for the existing owned, BIOS ISO-installation profile."""
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET

from .runs import atomic_json, read_json
from .vm_admission import require

VIRSH = ['virsh', '-c', 'qemu:///system']


def node(parent, tag, text=None, **attributes):
    child = ET.SubElement(parent, tag, {k: str(v) for k, v in attributes.items()})
    if text is not None:child.text = str(text)
    return child


def configuration(name, pool, installer, seed, network, mac, qemu_uid, qemu_gid, *,
                  disk_bytes=64*1024**3, filter_name=None):
    require(re.fullmatch('wormhole-vm-[a-f0-9]{12}', name), 'invalid_vm_name')
    require(all(type(x) is int and 0 < x < 2**32 for x in (qemu_uid, qemu_gid)), 'invalid_qemu_identity')
    require(disk_bytes in {32*1024**3, 64*1024**3}, 'invalid_guest_disk')
    paths = [PurePosixPath(str(p)) for p in (pool, installer, seed)]
    require(all(p.is_absolute() and '..' not in p.parts and '\\' not in str(p) for p in paths)
            and len(set(paths)) == 3, 'invalid_native_paths')
    pool, installer, seed = map(str, paths)
    net = ipaddress.IPv4Network(network)
    require(net.prefixlen == 24 and re.fullmatch('52:54:00(?::[a-f0-9]{2}){3}', mac), 'invalid_guest_network')
    require(filter_name in {None, name+'-isolation'}, 'invalid_native_filter')
    roots = {kind: ET.Element(kind) for kind in ('pool', 'network', 'volume', 'domain')}
    p, n, v, d = (roots[k] for k in roots)
    p.set('type', 'dir');node(p, 'name', name)
    target = node(p, 'target');node(target, 'path', pool)
    permissions = node(target, 'permissions')
    for key, value in [('mode', '0710'), ('owner', 0), ('group', qemu_gid)]:node(permissions, key, value)
    node(n, 'name', name);node(n, 'bridge', stp='on', delay='0');node(n, 'dns', enable='no')
    node(n, 'ip', address=net.network_address+1, netmask=net.netmask)
    v.set('type', 'file');node(v, 'name', name+'.qcow2')
    node(v, 'capacity', disk_bytes, unit='bytes');node(v, 'allocation', 0, unit='bytes')
    target = node(v, 'target');node(target, 'path', pool+'/'+name+'.qcow2');node(target, 'format', type='qcow2')
    permissions = node(target, 'permissions')
    for key, value in [('mode', '0600'), ('owner', qemu_uid), ('group', qemu_gid)]:node(permissions, key, value)
    d.set('type', 'kvm');node(d, 'name', name);node(d, 'description', 'jake-wormhole libvirt-iso '+name)
    node(d, 'memory', 8388608, unit='KiB');node(d, 'currentMemory', 8388608, unit='KiB')
    node(d, 'vcpu', 2, placement='static')
    os = node(d, 'os');node(os, 'type', 'hvm', arch='x86_64', machine='pc-i440fx-8.2')
    for dev in ('hd', 'cdrom'):node(os, 'boot', dev=dev)
    features = node(d, 'features')
    for feature in ('acpi', 'apic', 'pae'):node(features, feature)
    node(d, 'cpu', mode='host-passthrough', check='none', migratable='on');node(d, 'clock', offset='utc')
    for event, action in [('poweroff', 'destroy'), ('reboot', 'restart'), ('crash', 'destroy')]:node(d, 'on_'+event, action)
    devices = node(d, 'devices');node(devices, 'emulator', '/usr/bin/qemu-system-x86_64')
    for device, source, target, bus, fmt in [('disk', pool+'/'+name+'.qcow2', 'vda', 'virtio', 'qcow2'),
            ('cdrom', installer, 'hda', 'ide', 'raw'), ('cdrom', seed, 'hdb', 'ide', 'raw')]:
        disk = node(devices, 'disk', type='file', device=device)
        node(disk, 'driver', name='qemu', type=fmt);node(disk, 'source', file=source);node(disk, 'target', dev=target, bus=bus)
        if device == 'cdrom':node(disk, 'readonly')
    for kind, model in [('usb', 'piix3-uhci'), ('pci', 'pci-root'), ('ide', None), ('virtio-serial', None)]:
        controller = node(devices, 'controller', type=kind, index=0)
        if model:controller.set('model', model)
    interface = node(devices, 'interface', type='network')
    node(interface, 'mac', address=mac);node(interface, 'source', network=name);node(interface, 'model', type='virtio')
    if filter_name:node(interface, 'filterref', filter=filter_name)
    serial = node(devices, 'serial', type='pty');target = node(serial, 'target', type='isa-serial', port=0)
    node(target, 'model', name='isa-serial')
    node(node(devices, 'console', type='pty'), 'target', type='serial', port=0)
    node(node(devices, 'channel', type='unix'), 'target', type='virtio', name='org.qemu.guest_agent.0')
    for kind in ('mouse', 'keyboard'):node(devices, 'input', type=kind, bus='ps2')
    node(devices, 'audio', id=1, type='none');node(devices, 'memballoon', model='virtio')
    node(node(devices, 'rng', model='virtio'), 'backend', '/dev/urandom', model='random')
    return {kind: ET.tostring(root, encoding='unicode')+'\n' for kind, root in roots.items()}


def read(run, command, args, label):
    command(args, label, timeout=15)
    return (Path(run)/(label+'.log')).read_text()


def create(run, config, command):
    run = Path(run);name = ET.fromstring(config['domain']).findtext('name')
    pool = Path(ET.fromstring(config['pool']).findtext('target/path'))
    for query in ('list', 'net-list', 'pool-list'):
        require(name not in read(run, command, VIRSH+[query, '--all', '--name'], 'native-create-'+query).split(), 'vm_resource_conflict')
    require(not pool.exists() and not pool.is_symlink(), 'native_pool_path_exists')
    require(not (run/'native-config.json').exists() or read_json(run/'native-config.json') == config, 'native_configuration_changed')
    atomic_json(run/'native-config.json', config)
    for kind, xml in config.items():(run/('native-'+kind+'.xml')).write_text(xml)
    operations = [('pool-define', str(run/'native-pool.xml')), ('pool-build', name), ('pool-start', name),
        ('net-define', str(run/'native-network.xml')), ('net-start', name),
        ('vol-create', name, str(run/'native-volume.xml')), ('define', str(run/'native-domain.xml'))]
    for operation in operations:command(VIRSH+list(operation), 'native-'+operation[0], timeout=60)


def destroy(run, config, command):
    """Observe every existing resource before the first exact-owned mutation."""
    run = Path(run)
    require(read_json(run/'native-config.json') == config, 'native_configuration_changed')
    expected = {kind: ET.fromstring(xml) for kind, xml in config.items()}
    name = expected['domain'].findtext('name');pool = Path(expected['pool'].findtext('target/path'))
    volume = expected['volume'].findtext('name');disk = pool/volume
    present, active, observed = {}, {}, {}
    for kind, query in [('domain', 'list'), ('network', 'net-list'), ('pool', 'pool-list')]:
        present[kind] = name in read(run, command, VIRSH+[query, '--all', '--name'], 'native-inspect-'+kind+'-all').split()
        active[kind] = name in read(run, command, VIRSH+[query, '--name'], 'native-inspect-'+kind+'-active').split()
        if present[kind]:
            dump = {'domain':'dumpxml', 'network':'net-dumpxml', 'pool':'pool-dumpxml'}[kind]
            observed[kind] = ET.fromstring(read(run, command, VIRSH+[dump, name], 'native-inspect-'+kind))
            require(observed[kind].findtext('name') == name, 'native_resource_identity')
    if 'domain' in observed:
        actual = observed['domain'];wanted = expected['domain']
        def disks(root):
            return [(x.get('device'), x.find('source').get('file'), x.find('driver').get('type'),
                     x.find('target').attrib, x.find('readonly') is not None) for x in root.findall('devices/disk')]
        def interfaces(root):
            return [(x.get('type'), x.find('source').get('network'), x.find('mac').get('address'),
                     x.find('filterref').get('filter') if x.find('filterref') is not None else None)
                    for x in root.findall('devices/interface')]
        require(actual.get('type') == 'kvm' and actual.findtext('description') == wanted.findtext('description')
                and disks(actual) == disks(wanted) and interfaces(actual) == interfaces(wanted)
                and not actual.findall('devices/hostdev') and not actual.findall('devices/filesystem'), 'domain_ownership_mismatch')
    if 'pool' in observed:
        actual = observed['pool']
        require(actual.get('type') == 'dir' and actual.findtext('target/path') == expected['pool'].findtext('target/path'), 'pool_ownership_mismatch')
    if 'network' in observed:
        actual = observed['network'];wanted = expected['network']
        require(actual.find('forward') is None and len(actual.findall('ip')) == 1 and
                actual.find('ip').attrib == wanted.find('ip').attrib and actual.find('ip/dhcp') is None and
                actual.find('dns') is not None and actual.find('dns').get('enable') == 'no', 'network_ownership_mismatch')
    require(not pool.is_symlink() and not disk.is_symlink(), 'native_storage_symlink')
    if pool.exists():
        require(present['pool'] and pool.is_dir() and {p.name for p in pool.iterdir()} <= {volume}, 'native_pool_contents_mismatch')
    if disk.exists():
        require(present['pool'] and disk.is_file(), 'native_volume_owner_missing')
        info = json.loads(read(run, command, ['qemu-img', 'info', '--force-share', '--output=json', str(disk)], 'native-inspect-disk'))
        require(info['format'] == 'qcow2' and info['virtual-size'] == int(expected['volume'].findtext('capacity'))
                and not info.get('backing-filename'), 'native_volume_identity')
    # Only after all ownership checks pass can any resource change.
    if present['domain']:
        if active['domain']:command(VIRSH+['destroy', name], 'native-domain-stop', timeout=20)
        command(VIRSH+['undefine', name], 'native-domain-undefine', timeout=20)
    if disk.exists():
        if not active['pool']:command(VIRSH+['pool-start', name], 'native-pool-reopen', timeout=20);active['pool'] = True
        command(VIRSH+['vol-delete', volume, '--pool', name], 'native-volume-delete', timeout=20)
    if present['network']:
        if active['network']:command(VIRSH+['net-destroy', name], 'native-network-stop', timeout=20)
        command(VIRSH+['net-undefine', name], 'native-network-undefine', timeout=20)
    if present['pool']:
        if active['pool']:command(VIRSH+['pool-destroy', name], 'native-pool-stop', timeout=20)
        if pool.exists():command(VIRSH+['pool-delete', name], 'native-pool-delete', timeout=20)
        command(VIRSH+['pool-undefine', name], 'native-pool-undefine', timeout=20)
    for query in ('list', 'net-list', 'pool-list'):
        require(name not in read(run, command, VIRSH+[query, '--all', '--name'], 'native-verify-'+query).split(), 'native_cleanup_incomplete')
    require(not disk.exists() and not pool.exists(), 'native_storage_remains')
