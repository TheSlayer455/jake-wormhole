"""Ubuntu 22.04 installation baseline inputs, not a hardening/qualification gate.

The candidate replays the source ISO boot equipment. A separate public-key-only
NoCloud seed is a declared installation input. No private key enters either ISO.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess

from .runs import RunError, atomic_json, run_id

UBUNTU = {'release': '22.04.5', 'architecture': 'amd64', 'bytes': 2136926208,
          'sha256': '9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0'}
TERRAFORM = '1.17.0'
PROVIDER = '0.8.3'
USER = 'lab.service'
HEADLESS_XSLT = '''<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="@*|node()">
    <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
  </xsl:template>
  <xsl:template match="/domain/devices/graphics"/>
</xsl:stylesheet>
'''


def sha256(path):
    whole = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(1024 * 1024):
            whole.update(block)
    return whole.hexdigest()


def boot_config(text):
    """Require and modify actual ISO GRUB linux entries; never direct-boot a kernel."""
    count = 0
    lines = []
    for line in text.splitlines():
        if re.match(r'\s*linux\s+/casper/(?:hwe-)?vmlinuz\s', line):
            if 'autoinstall' in line or ' ---' not in line:
                raise RunError('unsupported_boot_config', 'Unexpected source ISO boot configuration.')
            line = line.replace(' ---', ' autoinstall console=ttyS0,115200n8 ---', 1)
            count += 1
        if re.match(r'^set timeout=', line):
            line = 'set timeout=1'
        lines.append(line)
    if count == 0:
        raise RunError('unsupported_boot_config', 'No supported source ISO boot entry was found.')
    return '\n'.join(lines) + '\n'


def cloud_config(identifier, public_key, guest_address, mac):
    run_id(identifier)
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{40,100}={0,2}(?: [A-Za-z0-9_.-]{1,80})?', public_key):
        raise RunError('invalid_public_key', 'Supply a single run-scoped Ed25519 public key.')
    address = ipaddress.IPv4Interface(guest_address)
    if address.network.prefixlen != 24 or not re.fullmatch(r'52:54:00(?::[a-f0-9]{2}){3}', mac):
        raise RunError('invalid_guest_network', 'Use the declared isolated /24 guest profile.')
    # JSON is valid YAML. Commands are argv vectors, not interpolated shell code.
    late = '''set -eu
useradd --create-home --shell /bin/bash --user-group lab.service
install -d -o lab.service -g lab.service -m 0700 /home/lab.service/.ssh
install -o lab.service -g lab.service -m 0600 /var/lib/wormhole/public-key /home/lab.service/.ssh/authorized_keys
printf '%s\\n' 'lab.service ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wormhole-lab
chmod 0440 /etc/sudoers.d/wormhole-lab
visudo -cf /etc/sudoers.d/wormhole-lab
ssh-keygen -A
printf '%s\\n' 'WORMHOLE_FINAL_HOST_KEY_BEGIN' > /dev/ttyS0
cat /etc/ssh/ssh_host_ed25519_key.pub > /dev/ttyS0
printf '%s\\n' 'WORMHOLE_FINAL_HOST_KEY_END' > /dev/ttyS0
touch /var/lib/wormhole/installation-complete
'''
    value = {'autoinstall': {'version': 1, 'refresh-installer': {'update': False},
        'locale': 'en_US.UTF-8', 'keyboard': {'layout': 'us'},
        'network': {'version': 2, 'ethernets': {'lab': {'match': {'macaddress': mac},
            'set-name': 'lab0', 'dhcp4': False, 'addresses': [str(address)]}}},
        'apt': {'geoip': False, 'preserve_sources_list': False},
        'storage': {'layout': {'name': 'direct'}},
        'ssh': {'install-server': True, 'allow-pw': False},
        'user-data': {'users': [], 'disable_root': True, 'ssh_deletekeys': False,
                      'preserve_hostname': False, 'hostname': 'wormhole-lab'},
        'late-commands': [
            ['mkdir', '-p', '/target/var/lib/wormhole'],
            ['sh', '-c', 'printf %s ' + public_key.split()[1] + ' > /target/var/lib/wormhole/key-body'],
            ['sh', '-c', "printf 'ssh-ed25519 %s\\n' \"$(cat /target/var/lib/wormhole/key-body)\" > /target/var/lib/wormhole/public-key"],
            ['curtin', 'in-target', '--target=/target', '--', 'sh', '-c', late]],
        'error-commands': [['sh', '-c', "printf '%s\\n' WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0"]],
        'shutdown': 'reboot'}}
    return '#cloud-config\n' + json.dumps(value, indent=2) + '\n'


def build_ubuntu(source, destination, seed_dir, identifier, public_key, guest_address, mac):
    source, destination, seed_dir = map(Path, (source, destination, seed_dir))
    if source.stat().st_size != UBUNTU['bytes'] or sha256(source) != UBUNTU['sha256']:
        raise RunError('source_identity_mismatch', 'The pinned Ubuntu source identity does not match.')
    if destination.exists() or seed_dir.exists():
        raise RunError('build_output_exists', 'Preserve existing build outputs; select a new run.')
    seed_dir.mkdir(mode=0o700)
    work = seed_dir / 'boot'
    work.mkdir(mode=0o700)
    def command(args):
        with (seed_dir / 'build.log').open('ab') as log:
            subprocess.run(args, stdout=log, stderr=log, timeout=300, check=True)
    changed = []
    for name in ('grub.cfg', 'loopback.cfg'):
        target = work / name
        command(['xorriso', '-osirrox', 'on', '-indev', str(source), '-extract', '/boot/grub/' + name, str(target)])
        target.write_text(boot_config(target.read_text()), encoding='utf-8')
        changed.extend(['-map', str(target), '/boot/grub/' + name])
    # Update the source medium's own checksum index for changed boot files.
    index = work / 'md5sum.txt'
    command(['xorriso', '-osirrox', 'on', '-indev', str(source), '-extract', '/md5sum.txt', str(index)])
    content = index.read_text()
    for name in ('grub.cfg', 'loopback.cfg'):
        digest = hashlib.md5((work / name).read_bytes(), usedforsecurity=False).hexdigest()
        content = re.sub(r'^[a-f0-9]{32}(\s+\.?/?boot/grub/' + re.escape(name) + r')$',
                         lambda match: digest + match[1], content, flags=re.M)
    index.write_text(content, encoding='utf-8')
    command(['xorriso', '-indev', str(source), '-outdev', str(destination), '-boot_image', 'any', 'replay',
             *changed, '-map', str(index), '/md5sum.txt'])
    (seed_dir / 'user-data').write_text(cloud_config(identifier, public_key, guest_address, mac), encoding='utf-8')
    (seed_dir / 'meta-data').write_text(json.dumps({'instance-id': identifier, 'local-hostname': 'wormhole-lab'}), encoding='utf-8')
    seed = destination.with_name('seed.iso')
    command(['xorriso', '-as', 'mkisofs', '-V', 'CIDATA', '-J', '-r', '-o', str(seed),
             str(seed_dir / 'user-data'), str(seed_dir / 'meta-data')])
    manifest = {'schema_version': '1.0', 'capability': 'ubuntu-iso-installation-baseline',
        'source': UBUNTU, 'candidate_sha256': sha256(destination), 'seed_sha256': sha256(seed),
        'installation_input_sha256': sha256(seed_dir / 'user-data'), 'seed_required': True,
        'firmware': 'bios', 'machine': 'pc-i440fx-8.2', 'guest_memory_mib': 8192,
        'guest_vcpus': 2, 'guest_disk_bytes': 64 * 1024**3, 'hardening_complete': False,
        'real_assessment_complete': False, 'lab_iso_qualified': False, 'production_iso_eligible': False}
    atomic_json(seed_dir / 'build-manifest.json', manifest)
    return manifest


def terraform_config(name, pool_path, installer, seed, network, mac, qemu_uid, qemu_gid):
    """Pinned provider 0.8.3 schema. ISO suffix selects a real CD-ROM device."""
    if not re.fullmatch('wormhole-vm-[a-f0-9]{12}', name):
        raise RunError('invalid_vm_name', 'Use a run-owned VM identity.')
    if not all(type(x) is int and 0 < x < 2**32 for x in (qemu_uid, qemu_gid)):
        raise RunError('invalid_qemu_identity', 'Use the observed unprivileged QEMU runtime identity.')
    net = ipaddress.IPv4Network(network)
    volume_xslt = f'''<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:template match="@*|node()"><xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy></xsl:template>
      <xsl:template match="/volume/target"><target><xsl:apply-templates select="@*|node()[not(self::permissions)]"/>
        <permissions><mode>0600</mode><owner>{qemu_uid}</owner><group>{qemu_gid}</group></permissions>
      </target></xsl:template></xsl:stylesheet>'''
    return {'terraform': {'required_version': '= ' + TERRAFORM,
            'required_providers': {'libvirt': {'source': 'dmacvicar/libvirt', 'version': '= ' + PROVIDER}}},
        'provider': {'libvirt': {'uri': 'qemu:///system'}},
        'resource': {
            'libvirt_pool': {'run': {'name': name, 'type': 'dir', 'target': {'path': str(pool_path)}}},
            'libvirt_volume': {'disk': {'name': name + '.qcow2', 'pool': '${libvirt_pool.run.name}',
                'format': 'qcow2', 'size': 64 * 1024**3, 'xml': {'xslt': volume_xslt}}},
            'libvirt_network': {'run': {'name': name, 'mode': 'none', 'addresses': [str(net)],
                'autostart': False, 'dhcp': {'enabled': False}, 'dns': {'enabled': False}}},
            'libvirt_domain': {'run': {'name': name, 'description': 'jake-wormhole libvirt-iso ' + name,
                'type': 'kvm', 'arch': 'x86_64', 'machine': 'pc-i440fx-8.2', 'memory': 8192,
                'vcpu': 2, 'autostart': False, 'qemu_agent': False, 'running': False,
                'xml': {'xslt': HEADLESS_XSLT},
                'cpu': {'mode': 'host-passthrough'}, 'boot_device': {'dev': ['hd', 'cdrom']},
                # Retain the Terraform dependency and expose the exact file path
                # to virt-aa-helper without a host policy override.
                'disk': [{'file': '${libvirt_volume.disk.id}'}, {'file': str(installer)}, {'file': str(seed)}],
                'network_interface': {'network_id': '${libvirt_network.run.id}', 'mac': mac, 'wait_for_lease': False},
                'console': {'type': 'pty', 'target_type': 'serial', 'target_port': '0'}}}}}
