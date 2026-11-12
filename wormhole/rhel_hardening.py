"""Pinned RHEL 10 installation-time hardening, separate from the accepted baseline.

The ISO contains policy and code; the private seed supplies only per-run identity.
The LUKS secret arrives through the existing no-echo console protocol, not media.
Remediation exit 2 records findings, never qualification. BIOS is the only profile.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from . import rhel_inputs as baseline
from .media_store import fingerprint, require
from .runs import SOURCE_ROOT, run_id
from .ubuntu_encryption import EARLY
from .vm_inputs import sha256

CAPABILITY = 'rhel-hardened-assessment-candidate-iso'
POLICY = SOURCE_ROOT / 'profiles/rhel10-lab-policy-v1.json'
CONTENT_SHA256 = '3a22f1f747ef7b895268b2da838f680b6a7ea421c5132d6ac4141d858afc60c6'
PROFILE = 'xccdf_org.ssgproject.content_profile_stig'
LAB_PROFILE = 'xccdf_org.wormhole_profile_rhel10_lab_stig'
SSSD_CERTMAP_RULE = 'xccdf_org.ssgproject.content_rule_sssd_enable_certmap'
AUTHENTICATION_CONTRACT = 'run-scoped-ssh-public-key-and-local-password-required-sudo'
SSSD_CERTMAP_APPLICABILITY = {
    'applicable': False,
    'pki_based_authentication': False,
    'authentication_contract': AUTHENTICATION_CONTRACT,
    'reason': 'The declared lab workload does not use PKI authentication.'}
LAB_BANNER = 'Wormhole private home lab. Authorized lab use only. Activity is monitored.'
LAB_BANNER_REGEX = r'^Wormhole private home lab\. Authorized lab use only\. Activity is monitored\.$'
LAB_AUTHORIZED_USERS_REGEX = (
    r'^(root|bin|daemon|adm|lp|sync|shutdown|halt|mail|operator|games|ftp|nobody|tss|'
    r'systemd-coredump|dbus|polkitd|avahi|colord|rtkit|pipewire|clevis|sssd|geoclue|'
    r'flatpak|setroubleshoot|fapolicyd|libstoragemgmt|systemd-oom|gdm|cockpit-ws|'
    r'gnome-initial-setup|sshd|chrony|dnsmasq|postfix|tcpdump|admin|unbound|yggdrasil|'
    r'yggdrasil-worker|lab\.service)$')
CONTENT = {'release': '0.1.82', 'benchmark': 'RHEL 10 STIG V1R2',
           'sha256': CONTENT_SHA256, 'profile': PROFILE, 'rules': 1073, 'selected_rules': 472}
BOOT_ARGS = 'fips=1 init_on_free=1 pti=on vsyscall=none page_poison=1 audit=1 audit_backlog_limit=8192'


def tailoring_document():
    """Declare truthful lab values and the workload's one inapplicable PKI rule."""
    policy = json.loads(POLICY.read_text())
    tailoring = policy['tailoring']
    values = {'login_banner_text': LAB_BANNER_REGEX,
        'var_accounts_authorized_local_users_regex': LAB_AUTHORIZED_USERS_REGEX,
        'var_networkmanager_dns_mode': 'none'}
    require(tailoring == {'excluded_rules': [SSSD_CERTMAP_RULE], 'parameters': values,
        'owner_approved_exceptions': []}, 'unsupported_assessment_tailoring')
    require(policy.get('rule_applicability') == {
        SSSD_CERTMAP_RULE: SSSD_CERTMAP_APPLICABILITY}, 'unsupported_rule_applicability')
    x = '{http://checklists.nist.gov/xccdf/1.2}'
    root = ET.Element(x + 'Tailoring', id='xccdf_org.wormhole_tailoring_rhel10_lab')
    ET.SubElement(root, x + 'benchmark', href='ssg-rhel10-ds.xml')
    ET.SubElement(root, x + 'version', time='2026-11-12T00:00:00Z').text = '1'
    profile = ET.SubElement(root, x + 'Profile', id=LAB_PROFILE, extends=PROFILE)
    ET.SubElement(profile, x + 'title').text = 'Wormhole declared home-lab values and applicability'
    ET.SubElement(profile, x + 'description').text = 'Declared values cover the truthful warning banner and installed authorized accounts; the PKI certificate-map rule is not selected because the declared workload does not use PKI authentication.'
    ET.SubElement(profile, x + 'select', idref=SSSD_CERTMAP_RULE, selected='false')
    ET.SubElement(profile, x + 'set-value',
        idref='xccdf_org.ssgproject.content_value_login_banner_text').text = LAB_BANNER_REGEX
    ET.SubElement(profile, x + 'set-value',
        idref='xccdf_org.ssgproject.content_value_var_accounts_authorized_local_users_regex').text = LAB_AUTHORIZED_USERS_REGEX
    ET.SubElement(profile, x + 'set-value',
        idref='xccdf_org.ssgproject.content_value_var_networkmanager_dns_mode').text = 'none'
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)
PACKAGES = '''@core
python3
shadow-utils
cryptsetup
openscap-scanner
scap-security-guide
aide
crypto-policies
sudo
gnutls-utils
nss-tools
sequoia-sq
subscription-manager
opensc
pcsc-lite-ccid
pcsc-lite
pkcs11-provider
rsyslog-gnutls
rsyslog
firewalld
libreswan
policycoreutils-python-utils
policycoreutils
cronie
fapolicyd
postfix
s-nail
chrony
openssh-clients
openssh-server
usbguard
audispd-plugins
audit
-gdm
-gssproxy
-tuned
-unbound
-vsftpd
-nfs-utils
-telnet-server
-tftp-server
-tftp'''

# Sizes and mount separation come from this exact profile's generated Kickstart.
# BIOS metadata and /boot are clear; the PV (including swap) is LUKS2/PBKDF2.
STORAGE = '''part biosboot --fstype=biosboot --ondisk=vda --size=1
part /boot --fstype=xfs --ondisk=vda --size=2048
part pv.01 --ondisk=vda --size=1 --grow --encrypted --luks-version=luks2 --pbkdf=pbkdf2 --passphrase="{secret}"
volgroup system pv.01
logvol / --vgname=system --name=root --fstype=xfs --size=2000 --grow
logvol swap --vgname=system --name=swap --fstype=swap --size=1000
logvol /home --vgname=system --name=home --fstype=xfs --size=1024 --fsoptions=nodev,nosuid
logvol /tmp --vgname=system --name=tmp --fstype=xfs --size=1024 --fsoptions=nodev,nosuid,noexec
logvol /var --vgname=system --name=var --fstype=xfs --size=3072 --fsoptions=nodev
logvol /var/log --vgname=system --name=varlog --fstype=xfs --size=1024 --fsoptions=nodev,nosuid,noexec
logvol /var/log/audit --vgname=system --name=varlogaudit --fstype=xfs --size=10240 --fsoptions=nodev,nosuid,noexec
logvol /var/tmp --vgname=system --name=vartmp --fstype=xfs --size=1024 --fsoptions=nodev,nosuid,noexec
'''

READY = r'''#!/bin/bash
set -euo pipefail
trap 'printf "%s\n" WORMHOLE_FINALIZATION_FAILED > /dev/ttyS0' ERR
. /etc/os-release
test "$ID" = rhel
test "$VERSION_ID" = 10.0
findmnt -n -o SOURCE / | grep -q '^/dev/'
test "$(cat /proc/sys/crypto/fips_enabled)" = 1
test "$(getenforce)" = Enforcing
test -s /var/lib/wormhole/remediation-exit
test -s /var/lib/wormhole/installation-boot-id
test "$(cat /var/lib/wormhole/installation-boot-id)" != "$(cat /proc/sys/kernel/random/boot_id)"
test "$(getent passwd lab.service | cut -d: -f6)" = /home/lab.service
test "$(stat -c %U /home/lab.service/.ssh/authorized_keys)" = lab.service
test "$(stat -c %a /home/lab.service)" = 700
test "$(stat -c %a /home/lab.service/.ssh)" = 700
test "$(stat -c %a /home/lab.service/.ssh/authorized_keys)" = 600
expiry=$(getent shadow lab.service | cut -d: -f8)
today=$(( $(date -u +%s) / 86400 ))
test -n "$expiry" && test "$expiry" -gt "$today" && test "$expiry" -le $((today + 3))
test "$(stat -c %a /var/lib/wormhole)" = 755
test -s /etc/wormhole-lab-ca.crt
grep -Eq '^[[:space:]]*set superusers="wormhole_boot_admin"$' /boot/grub2/grub.cfg
grep -Fq 'password_pbkdf2 wormhole_boot_admin ${GRUB2_PASSWORD}' /boot/grub2/grub.cfg
grep -Eq '^GRUB2_PASSWORD=grub\.pbkdf2\.' /boot/grub2/user.cfg
! getent passwd wormhole_boot_admin
semanage login -l | awk '$1 == "lab.service" { found=1; if ($2 != "staff_u") exit 1 } END { if (!found) exit 1 }'
NetworkManager --print-config | grep -qx 'dns=none'
awk '$1 == "hosts:" { found=1; for (i=2; i<=NF; i++) if ($i == "dns") exit 1 } END { if (!found) exit 1 }' /etc/nsswitch.conf
test ! -s /etc/resolv.conf
test "$(firewall-cmd --get-default-zone)" = drop
test "$(firewall-cmd --get-active-zones | awk '/^[^ ]/ { print $1 }')" = drop
test -n "$(firewall-cmd --zone=drop --list-interfaces)"
test "$(firewall-cmd --zone=drop --get-target)" = DROP
test "$(firewall-cmd --zone=drop --list-services)" = ssh
test -z "$(firewall-cmd --zone=drop --list-ports)"
if ! test -f /etc/ssh/ssh_host_rsa_key; then
    ssh-keygen -q -t rsa -b 3072 -N '' -f /etc/ssh/ssh_host_rsa_key
fi
restorecon -RF /etc/ssh
/usr/sbin/sshd -t
install -m 0644 /dev/null /var/lib/wormhole/installation-complete
printf '%s\n' WORMHOLE_FINAL_HOST_KEY_BEGIN > /dev/ttyS0
cat /etc/ssh/ssh_host_rsa_key.pub > /dev/ttyS0
printf '%s\n' WORMHOLE_FINAL_HOST_KEY_END > /dev/ttyS0
'''

FINALIZE = r'''#!/bin/bash
set -euo pipefail
umask 077
trap 'printf "%s\n" WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0' ERR
test "$(cat /proc/sys/crypto/fips_enabled)" = 1
cd /usr/local/share/wormhole
sha256sum --check content.sha256
install -d -m 0700 /var/lib/wormhole/install-assessment
printf '%s\n' WORMHOLE_HARDENING_STARTED > /dev/ttyS0
if timeout --signal=TERM --kill-after=15 900 oscap xccdf eval --remediate \
    --tailoring-file lab-tailoring.xml \
    --profile xccdf_org.wormhole_profile_rhel10_lab_stig \
    --results /var/lib/wormhole/install-assessment/remediation-xccdf.xml \
    --results-arf /var/lib/wormhole/install-assessment/remediation-arf.xml \
    --report /var/lib/wormhole/install-assessment/remediation.html ssg-rhel10-ds.xml; then
    result=0
else
    result=$?
fi
case "$result" in
    0|2) ;;
    *) printf '%s\n' WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0; exit "$result" ;;
esac
test -s /var/lib/wormhole/install-assessment/remediation-xccdf.xml
printf '%s\n' "$result" > /var/lib/wormhole/remediation-exit
# The installer disables kdump, but the pinned rule also requires the final
# installed unit to be masked while kexec-tools remains available.
systemctl mask kdump.service
# Keep Anaconda's per-installation PBKDF2 hash, but replace the default `root`
# GRUB administrator in the generator and rebuild the installed BIOS config.
test -s /etc/grub.d/01_users
sed -Ei \
    -e 's/^([[:space:]]*set superusers=)"root"$/\1"wormhole_boot_admin"/' \
    -e 's/^([[:space:]]*password_pbkdf2[[:space:]]+)root([[:space:]]+)/\1wormhole_boot_admin\2/' \
    /etc/grub.d/01_users
grep -Eq '^[[:space:]]*set superusers="wormhole_boot_admin"$' /etc/grub.d/01_users
grep -Fq 'password_pbkdf2 wormhole_boot_admin \${GRUB2_PASSWORD}' /etc/grub.d/01_users
grep -Eq '^GRUB2_PASSWORD=grub\.pbkdf2\.' /boot/grub2/user.cfg
grub2-mkconfig -o /boot/grub2/grub.cfg
grep -Eq '^[[:space:]]*set superusers="wormhole_boot_admin"$' /boot/grub2/grub.cfg
grep -Fq 'password_pbkdf2 wormhole_boot_admin ${GRUB2_PASSWORD}' /boot/grub2/grub.cfg
# Complete the declared final-account contract after profile remediation. This
# is installation code, never an acceptance-time repair or passwordless bypass.
usermod -Z staff_u lab.service
chage -E "$(date -u -d '+2 days' +%F)" lab.service
chown -R lab.service:lab.service /home/lab.service
chmod 0700 /home/lab.service /home/lab.service/.ssh
chmod 0600 /home/lab.service/.ssh/authorized_keys
printf '%s\n' '%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL' 'Defaults:lab.service timestamp_timeout=0' > /etc/sudoers.d/wormhole-lab
chmod 0440 /etc/sudoers.d/wormhole-lab
visudo -c
# The pinned manual control requires literal DROP, not firewalld's `default`
# target. Keep SSH as the only declared exception for the controller path.
firewall-offline-cmd --set-default-zone=drop
firewall-offline-cmd --zone=drop --set-target=DROP
firewall-offline-cmd --zone=drop --add-service=ssh
cat > /etc/ssh/sshd_config.d/00-wormhole.conf <<'SSH'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
HostKey /etc/ssh/ssh_host_rsa_key
SSH
printf '%s\n' 'Wormhole private home lab. Authorized lab use only. Activity is monitored.' > /etc/issue
printf '%s\n' 'Banner /etc/issue' > /etc/ssh/sshd_config.d/05-wormhole-banner.conf
cat > /etc/chrony.conf <<'TIME'
# Explicit lab host-clock source, not an authenticated external time authority.
server 192.0.2.1 port 12345 iburst minpoll 4 maxpoll 4
port 0
cmdport 0
driftfile /var/lib/chrony/drift
makestep 1 -1
rtcsync
TIME
install -d -m 0755 /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/90-wormhole-dns.conf <<'DNS'
[main]
dns=none
DNS
awk '$1 == "hosts:" { printf "%s", $1; for (i=2; i<=NF; i++) if ($i != "dns") printf " %s", $i; printf "\n"; next } { print }' \
    /etc/nsswitch.conf > /etc/nsswitch.conf.wormhole
install -m 0644 /etc/nsswitch.conf.wormhole /etc/nsswitch.conf
rm -f /etc/nsswitch.conf.wormhole /etc/resolv.conf
install -m 0644 /dev/null /etc/resolv.conf
cat > /etc/rsyslog.d/70-wormhole-remote.conf <<'LOG'
global(DefaultNetstreamDriverCAFile="/etc/wormhole-lab-ca.crt")
*.* action(type="omfwd" target="192.0.2.1" port="6514" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
  StreamDriverPermittedPeers="wormhole-sandbox"
  action.resumeRetryCount="-1" queue.type="LinkedList" queue.size="10000")
LOG
rsyslogd -N1
cat > /etc/audit/audisp-remote.conf <<'AUDIT'
remote_server = 192.0.2.1
port = 6000
transport = tcp
mode = immediate
format = ascii
network_failure_action = suspend
remote_ending_action = suspend
disk_low_action = suspend
disk_full_action = suspend
disk_error_action = syslog
AUDIT
cat > /etc/audit/plugins.d/au-remote.conf <<'AUDIT'
active = yes
direction = out
path = /sbin/audisp-remote
type = always
format = string
AUDIT
# Preserve the vendor audit unit's early-boot ordering. Requiring network-online
# here creates a cycle through sysinit.target and skips auditd on boot.
# Give the isolated receiver port the vendor audit type in the installed guest.
# The default X server type denies each retry and generates further audit work.
semanage port -N -a -t audit_port_t -p tcp 6000
# Local notification delivery is useful; no SMTP ingress is declared.
postconf -e 'inet_interfaces = loopback-only'
install -d -m 0755 /var/lib/wormhole /etc/systemd/system/sshd.service.d
cat /proc/sys/kernel/random/boot_id > /var/lib/wormhole/installation-boot-id
install -m 0755 ready.sh /usr/local/sbin/wormhole-ready
cat > /etc/systemd/system/wormhole-ready.service <<'UNIT'
[Unit]
Description=Verify the freshly booted hardened installation and publish its host key
After=local-fs.target sshd-keygen.target
Before=sshd.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wormhole-ready
TimeoutStartSec=120
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/sshd.service.d/wormhole-ready.conf <<'UNIT'
[Unit]
Requires=wormhole-ready.service
After=wormhole-ready.service
UNIT
# Trust only this immutable installed observer, not arbitrary controller code.
fapolicyd-cli --file add /usr/local/sbin/wormhole-ready --trust-file wormhole
restorecon -RF /home/lab.service /etc/ssh /etc/sudoers.d/wormhole-lab \
    /var/lib/wormhole /usr/local/sbin/wormhole-ready /etc/systemd/system
systemctl enable wormhole-ready.service sshd.service
printf '%s\n' WORMHOLE_HARDENING_COMPLETE > /dev/ttyS0
'''


def prepare(content):
    """Validate the operator-staged datastream; never fetch media or content."""
    content = Path(content)
    require(content.is_file() and sha256(content) == CONTENT_SHA256, 'rhel_content_identity_mismatch')
    return dict(CONTENT)


def installation_contract():
    tailoring = tailoring_document()
    return {'id': 'wormhole-rhel10-hardened-bios-seed-v1', 'release': '10.0',
        'architecture': 'x86_64', 'firmware': 'bios', 'seed_label': baseline.SEED_LABEL,
        'final_user': 'lab.service', 'sudo': 'password-required',
        'host_trust': 'installed-system-serial-rsa-host-key', 'disk': 'luks2-pbkdf2-lvm',
        'guest_memory_mib': 8192, 'guest_vcpus': 2, 'guest_disk_bytes': 32 * 1024**3,
        'content': dict(CONTENT), 'recipe_sha256': sha256(__file__),
        'policy_sha256': sha256(POLICY),
        'tailoring_sha256': hashlib.sha256(tailoring).hexdigest(),
        'console_receiver_sha256': fingerprint(EARLY),
        'services': {'ca': 'run-seed-scoped', 'logging': 'existing-sandbox-tls',
                     'audit': 'existing-sandbox-ascii', 'time': 'lab-host-clock'},
        'qualification_policy': 'rhel10-stig-lab-v1'}


def boot_config(text):
    text = baseline.boot_config(text)
    lines = []
    for line in text.splitlines():
        if re.match(r'\s*linux\s+/images/pxeboot/vmlinuz\s', line) and 'inst.rescue' not in line:
            require(not any(token.startswith('fips=') for token in line.split()), 'unsupported_boot_config')
            # Anaconda's tmux frontend otherwise races the no-echo serial
            # receiver and can echo its input. Use the supported unattended UI.
            line += ' inst.notmux ' + BOOT_ARGS
        lines.append(line)
    return '\n'.join(lines) + '\n'


def kickstart(identifier, public_key, guest_address, mac, password_hash, boot_hash):
    run_id(identifier)
    require(re.fullmatch(r'ssh-rsa [A-Za-z0-9+/]{500,800}={0,2}(?: [A-Za-z0-9_.-]{1,80})?', public_key), 'invalid_public_key')
    address = ipaddress.IPv4Interface(guest_address)
    require(address.network.prefixlen == 24 and re.fullmatch(r'52:54:00(?::[a-f0-9]{2}){3}', mac), 'invalid_guest_network')
    require(re.fullmatch(r'\$6\$(?:rounds=[0-9]{4,9}\$)?[./0-9A-Za-z]{8,16}\$[./0-9A-Za-z]{86}', password_hash), 'invalid_password_hash')
    require(re.fullmatch(r'grub\.pbkdf2\.sha512\.[0-9]{4,9}\.[A-Fa-f0-9]{64,256}\.[A-Fa-f0-9]{64,256}', boot_hash), 'invalid_boot_hash')
    storage_writer = EARLY + '\nfrom pathlib import Path\n' + "Path('/run/wormhole-storage.ks').write_text(" + repr(STORAGE) + ".format(secret=Path('/run/wormhole-unlock').read_text()))\n" + "os.chmod('/run/wormhole-storage.ks',0o600)\n"
    return f'''# Pinned installation hardening; native findings still determine eligibility.
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
firewall --enabled
services --disabled=debug-shell,autofs,kdump --enabled=rsyslog,systemd-journald,firewalld,fapolicyd,chronyd,sshd,usbguard,auditd
network --device={mac} --bindto=mac --bootproto=static --ip={address.ip} --netmask={address.netmask} --nodefroute --noipv6 --onboot=yes --activate --hostname=vm-{identifier[:8]}
ignoredisk --only-use=vda
zerombr
clearpart --all --initlabel --disklabel=gpt --drives=vda
bootloader --boot-drive=vda --iscrypted --password={boot_hash} --append="{BOOT_ARGS} console=ttyS0,115200n8"
%include /run/wormhole-storage.ks
user --name=lab.service --homedir=/home/lab.service --shell=/bin/bash --groups=wheel --iscrypted --password={password_hash}
sshkey --username=lab.service "{public_key}"
reboot

%packages
{PACKAGES}
%end

%pre --interpreter=/bin/bash --erroronfail
set -euo pipefail
umask 077
trap 'printf "%s\\n" WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0' ERR
test -x /usr/bin/python3
/usr/bin/python3 <<'PY'
{storage_writer}PY
%end

%post --nochroot --interpreter=/bin/bash --erroronfail --log=/mnt/sysroot/root/wormhole-payload.log
set -euo pipefail
trap 'printf "%s\\n" WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0' ERR
mkdir -p /mnt/sysroot/usr/local/share/wormhole /mnt/sysroot/var/lib/wormhole
chmod 0755 /mnt/sysroot/usr/local/share/wormhole /mnt/sysroot/var/lib/wormhole
cp -a /run/install/repo/wormhole/. /mnt/sysroot/usr/local/share/wormhole/
mkdir -m 0700 /run/wormhole-seed
mount -o ro /dev/disk/by-label/WORMHOLEKS /run/wormhole-seed
cp /run/wormhole-seed/sandbox-ca.crt /mnt/sysroot/etc/wormhole-lab-ca.crt
chmod 0644 /mnt/sysroot/etc/wormhole-lab-ca.crt
umount /run/wormhole-seed
printf '%s\\n' '{identifier}' > /mnt/sysroot/var/lib/wormhole/run-id
%end

%post --interpreter=/bin/bash --erroronfail --log=/root/wormhole-hardening.log
/bin/bash /usr/local/share/wormhole/finalize.sh
%end

%post --nochroot --interpreter=/bin/bash --erroronfail --log=/mnt/sysroot/root/wormhole-secret-check.log
set -euo pipefail
trap 'printf "%s\\n" WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0' ERR
/usr/bin/python3 <<'PY'
from pathlib import Path
secret=Path('/run/wormhole-unlock').read_bytes()
paths=[Path('/mnt/sysroot/root'),Path('/mnt/sysroot/var/log/anaconda')]
for root in paths:
 for path in root.rglob('*'):
  if path.is_file() and not path.is_symlink() and secret in path.read_bytes():
   raise RuntimeError('unlock material retained in private installer evidence; preserve and investigate')
PY
%end

%onerror --interpreter=/bin/bash
printf '%s\\n' WORMHOLE_INSTALLATION_FAILED > /dev/ttyS0
%end
'''


def build(source, destination, seed_dir, identifier, public_key, guest_address, mac, *, content, password_hash, boot_hash, ca_file, reuse=None):
    """Build once or reuse identical installed inputs; always create a fresh seed."""
    source, destination, seed_dir, content = map(Path, (source, destination, seed_dir, content))
    prepare(content)
    ca_file = Path(ca_file)
    require(ca_file.is_file() and ca_file.read_bytes().startswith(b'-----BEGIN CERTIFICATE-----'), 'sandbox_ca_missing')
    contract = installation_contract()
    identity = fingerprint(contract)
    config = kickstart(identifier, public_key, guest_address, mac, password_hash, boot_hash)
    require(source.stat().st_size == baseline.RHEL['bytes'] and sha256(source) == baseline.RHEL['sha256'], 'source_identity_mismatch')
    require(not any(path.exists() for path in (destination, seed_dir, destination.with_name('seed.iso'))), 'build_output_exists')
    checksum_tool = shutil.which('implantisomd5')
    require(checksum_tool is not None or reuse is not None, 'missing_media_checksum_tool')
    seed_dir.mkdir(mode=0o700)
    def command(args):
        with (seed_dir / 'build.log').open('ab') as log:
            subprocess.run(args, stdout=log, stderr=log, timeout=600, check=True)
    boot = seed_dir / 'grub.cfg'
    command(['xorriso', '-osirrox', 'on', '-indev', str(source), '-extract', baseline.BOOT_PATH, str(boot)])
    boot.write_text(boot_config(boot.read_text()), encoding='utf-8')
    if reuse is not None:
        previous, manifest = reuse
        verify_reuse(manifest, sha256(previous), identity)
        observed = seed_dir / 'reused-grub.cfg'
        command(['xorriso', '-osirrox', 'on', '-indev', str(previous), '-extract', baseline.BOOT_PATH, str(observed)])
        require(observed.read_bytes() == boot.read_bytes(), 'stale_candidate')
        shutil.copyfile(previous, destination)
        require(sha256(destination) == manifest['candidate_sha256'], 'candidate_copy_mismatch')
    else:
        payload = seed_dir / 'payload'; payload.mkdir(mode=0o700)
        tailoring = tailoring_document()
        shutil.copyfile(content, payload / 'ssg-rhel10-ds.xml')
        (payload / 'lab-tailoring.xml').write_bytes(tailoring)
        (payload / 'content.sha256').write_text(CONTENT_SHA256 + '  ssg-rhel10-ds.xml\n'
            + hashlib.sha256(tailoring).hexdigest() + '  lab-tailoring.xml\n')
        (payload / 'finalize.sh').write_text(FINALIZE)
        (payload / 'ready.sh').write_text(READY)
        (payload / 'install-contract.json').write_text(json.dumps(contract, sort_keys=True) + '\n')
        command(['xorriso', '-indev', str(source), '-outdev', str(destination), '-boot_image', 'any', 'replay',
                 '-map', str(boot), baseline.BOOT_PATH, '-map', str(payload), '/wormhole'])
        command([checksum_tool, '--force', str(destination)])
    certificate = seed_dir / 'sandbox-ca.crt'; shutil.copyfile(ca_file, certificate)
    result = baseline.finish_seed(destination, seed_dir, config, command, seed_files=(certificate,), capability=CAPABILITY,
        source=dict(baseline.RHEL), installation_contract=contract, installed_input_fingerprint=identity,
        policy_sha256=contract['policy_sha256'],
        sandbox_ca_sha256=sha256(certificate),
        mode='hardened', assessment_content=dict(CONTENT), candidate_reused=reuse is not None,
        media_checksum_tool_sha256=(manifest.get('media_checksum_tool_sha256') if reuse is not None else sha256(checksum_tool)))
    for name in ('ks.cfg', 'sandbox-ca.crt'):
        observed = seed_dir / ('readback-' + name)
        command(['xorriso', '-osirrox', 'on', '-indev', str(destination.with_name('seed.iso')),
                 '-extract', '/' + name, str(observed)])
        require(sha256(observed) == sha256(seed_dir / name), 'identity_seed_layout_invalid')
    return result


def verify_reuse(manifest, actual_sha256, installed_input_fingerprint):
    require(manifest.get('capability') == CAPABILITY and manifest.get('source') == baseline.RHEL
        and manifest.get('installed_input_fingerprint') == installed_input_fingerprint
        and manifest.get('candidate_sha256') == actual_sha256, 'stale_candidate')
