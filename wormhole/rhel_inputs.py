"""Pinned RHEL 10 BIOS installation baseline; no hardening/qualification claim.

The candidate retains the DVD boot equipment and local repositories. Its separate
run seed carries Kickstart, a public key and a password hash, never a private key.
UEFI and Secure Boot are not claimed by this BIOS-only adapter.
"""
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess

from .runs import RunError, atomic_json, run_id
from .vm_inputs import sha256

RHEL = {'release': '10.0', 'architecture': 'x86_64', 'bytes': 8465612800,
        'sha256': 'edce2dd6f8e1d1b2ff0b204f89b0659bc9e320d175beb7caad60712957a19608'}
LABEL = 'RHEL-10-0-BaseOS-x86_64'
BOOT_PATH = '/boot/grub2/grub.cfg'
SEED_LABEL = 'WORMHOLEKS'
CAPABILITY = 'rhel-iso-installation-baseline'


def boot_config(text):
    """Change the DVD's BIOS GRUB entries, preserving stage2 and boot equipment."""
    if "search --no-floppy --set=root -l '" + LABEL + "'" not in text:
        raise RunError('unsupported_boot_config', 'Expected the pinned RHEL DVD label.')
    count = 0
    lines = []
    for line in text.splitlines():
        if re.match(r'\s*linux\s+/images/pxeboot/vmlinuz\s', line) and 'inst.rescue' not in line:
            if 'inst.ks=' in line or 'inst.stage2=hd:LABEL=' + LABEL not in line:
                raise RunError('unsupported_boot_config', 'Unexpected RHEL installation entry.')
            line += ' inst.ks=hd:LABEL=' + SEED_LABEL + ':/ks.cfg console=ttyS0,115200n8'
            count += 1
        if line.startswith('set default='):line = 'set default="0"'
        if line.startswith('set timeout='):line = 'set timeout=1'
        lines.append(line)
    if not count:
        raise RunError('unsupported_boot_config', 'No BIOS installation entry found.')
    return '\n'.join(lines) + '\n'


def kickstart(identifier, public_key, guest_address, mac, password_hash):
    run_id(identifier)
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{40,100}={0,2}(?: [A-Za-z0-9_.-]{1,80})?', public_key):
        raise RunError('invalid_public_key', 'Supply one run-scoped Ed25519 public key.')
    address = ipaddress.IPv4Interface(guest_address)
    if address.network.prefixlen != 24 or not re.fullmatch(r'52:54:00(?::[a-f0-9]{2}){3}', mac):
        raise RunError('invalid_guest_network', 'Use the declared isolated /24 profile.')
    if not re.fullmatch(r'\$6\$(?:rounds=[0-9]{4,9}\$)?[./0-9A-Za-z]{8,16}\$[./0-9A-Za-z]{86}', password_hash):
        raise RunError('invalid_password_hash', 'Supply a run-scoped SHA512-crypt hash, never a plaintext password.')
    return f'''# Declared installation baseline, not a STIG-qualified configuration.
text --non-interactive
cdrom
lang en_US.UTF-8
keyboard --xlayouts=us
timezone Etc/UTC --utc
timesource --ntp-disable
rootpw --lock
firstboot --disable
skipx
selinux --enforcing
firewall --enabled --service=ssh
services --enabled=sshd
network --device={mac} --bindto=mac --bootproto=static --ip={address.ip} --netmask={address.netmask} --nodefroute --noipv6 --onboot=yes --activate --hostname=vm-{identifier[:8]}
ignoredisk --only-use=vda
zerombr
clearpart --all --initlabel --drives=vda
bootloader --boot-drive=vda --append="console=ttyS0,115200n8"
reqpart --add-boot
part / --fstype=xfs --ondisk=vda --size=8192 --grow
user --name=lab.service --homedir=/home/lab.service --shell=/bin/bash --groups=wheel --iscrypted --password={password_hash}
sshkey --username=lab.service "{public_key}"
reboot

%packages
@core
python3
openssh-server
sudo
policycoreutils
shadow-utils
openscap-scanner
scap-security-guide
%end

%post --interpreter=/bin/bash --erroronfail --log=/root/wormhole-post.log
set -euo pipefail
trap 'printf "%s\\n" WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0' ERR
install -d -m 0700 /var/lib/wormhole
printf '%s\\n' '{identifier}' > /var/lib/wormhole/run-id
test "$(getent passwd lab.service | cut -d: -f6)" = /home/lab.service
chown -R lab.service:lab.service /home/lab.service
chmod 0700 /home/lab.service /home/lab.service/.ssh
chmod 0600 /home/lab.service/.ssh/authorized_keys
# The unqualified baseline mirrors the existing baseline's explicit sudo contract.
printf '%s\\n' 'lab.service ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wormhole-lab
chmod 0440 /etc/sudoers.d/wormhole-lab
visudo -cf /etc/sudoers.d/wormhole-lab
cat > /etc/ssh/sshd_config.d/00-wormhole.conf <<'SSH'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
SSH
cat > /usr/local/sbin/wormhole-ready <<'READY'
#!/bin/bash
set -euo pipefail
trap 'printf "%s\\n" WORMHOLE_FINALIZATION_FAILED > /dev/ttyS0' ERR
. /etc/os-release
test "$ID" = rhel
test "$VERSION_ID" = 10.0
findmnt -n -o SOURCE / | grep -q '^/dev/'
test "$(getenforce)" = Enforcing
ssh-keygen -A
restorecon -RF /home/lab.service /etc/ssh /etc/sudoers.d/wormhole-lab /var/lib/wormhole
/usr/sbin/sshd -t
touch /var/lib/wormhole/installation-complete
printf '%s\\n' WORMHOLE_FINAL_HOST_KEY_BEGIN > /dev/ttyS0
cat /etc/ssh/ssh_host_ed25519_key.pub > /dev/ttyS0
printf '%s\\n' WORMHOLE_FINAL_HOST_KEY_END > /dev/ttyS0
READY
chmod 0755 /usr/local/sbin/wormhole-ready
cat > /etc/systemd/system/wormhole-ready.service <<'UNIT'
[Unit]
Description=Observe the installed Wormhole baseline and publish its public host key
After=local-fs.target sshd-keygen.target
Before=sshd.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wormhole-ready
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
restorecon -RF /home/lab.service /usr/local/sbin/wormhole-ready /etc/systemd/system/wormhole-ready.service /etc/ssh /etc/sudoers.d/wormhole-lab
systemctl enable wormhole-ready.service
%end

%onerror --interpreter=/bin/bash
printf '%s\\n' WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0
%end
'''


def verify_reuse(manifest, actual_sha256, current_boot, observed_boot):
    if (manifest.get('capability') != CAPABILITY or manifest.get('source') != RHEL
            or actual_sha256 != manifest.get('candidate_sha256') or current_boot != observed_boot):
        raise RunError('stale_candidate', 'The RHEL source, candidate or current BIOS boot inputs differ.')


def build_rhel(source, destination, seed_dir, identifier, public_key, guest_address, mac, *, password_hash, reuse=None):
    source, destination, seed_dir = map(Path, (source, destination, seed_dir))
    config = kickstart(identifier, public_key, guest_address, mac, password_hash)
    if source.stat().st_size != RHEL['bytes'] or sha256(source) != RHEL['sha256']:
        raise RunError('source_identity_mismatch', 'The pinned official RHEL DVD identity does not match.')
    seed = destination.with_name('seed.iso')
    if destination.exists() or seed_dir.exists() or seed.exists():
        raise RunError('build_output_exists', 'Preserve existing installation outputs.')
    checksum_tool = shutil.which('implantisomd5')
    if checksum_tool is None and reuse is None:
        raise RunError('missing_media_checksum_tool', 'Stage the pinned implantisomd5 tool before remastering.')
    seed_dir.mkdir(mode=0o700)
    work = seed_dir / 'boot';work.mkdir(mode=0o700)
    def command(args):
        with (seed_dir / 'build.log').open('ab') as log:
            subprocess.run(args, stdout=log, stderr=log, timeout=600, check=True)
    boot = work / 'grub.cfg'
    command(['xorriso', '-osirrox', 'on', '-indev', str(source), '-extract', BOOT_PATH, str(boot)])
    boot.write_text(boot_config(boot.read_text()), encoding='utf-8')
    if reuse is None:
        command(['xorriso', '-indev', str(source), '-outdev', str(destination), '-boot_image', 'any', 'replay',
                 '-map', str(boot), BOOT_PATH])
        command([checksum_tool, '--force', str(destination)])
    else:
        previous_iso, previous_manifest = reuse
        observed = work / 'reused-grub.cfg'
        command(['xorriso', '-osirrox', 'on', '-indev', str(previous_iso), '-extract', BOOT_PATH, str(observed)])
        verify_reuse(previous_manifest, sha256(previous_iso), boot.read_bytes(), observed.read_bytes())
        shutil.copyfile(previous_iso, destination)
        if sha256(destination) != previous_manifest['candidate_sha256']:
            raise RunError('candidate_copy_mismatch', 'Reused RHEL bytes changed during copy.')
    ks = seed_dir / 'ks.cfg';ks.write_text(config, encoding='utf-8');ks.chmod(0o600)
    command(['xorriso', '-as', 'mkisofs', '-V', SEED_LABEL, '-J', '-r', '-o', str(seed), str(ks)])
    manifest = {'schema_version': '1.0', 'capability': CAPABILITY, 'source': RHEL,
        'candidate_sha256': sha256(destination), 'seed_sha256': sha256(seed),
        'installation_input_sha256': sha256(ks), 'seed_required': True,
        'firmware': 'bios', 'machine': 'pc-i440fx-8.2', 'guest_memory_mib': 8192,
        'guest_vcpus': 2, 'guest_disk_bytes': 32 * 1024**3, 'hardening_complete': False,
        'media_checksum_tool_sha256': (previous_manifest.get('media_checksum_tool_sha256') if reuse is not None else sha256(checksum_tool)),
        'candidate_reused': reuse is not None, 'real_assessment_complete': False,
        'lab_iso_qualified': False, 'production_iso_eligible': False}
    atomic_json(seed_dir / 'build-manifest.json', manifest)
    return manifest
