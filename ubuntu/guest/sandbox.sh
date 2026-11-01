#!/bin/bash
# Installed-guest configuration only; acceptance never invokes this file.
set -euo pipefail
test "$(systemd-detect-virt)" = kvm
test -f /var/lib/wormhole/run-id
test -f /etc/wormhole-lab-ca.crt
python3 - <<'PY'
from pathlib import Path
import hashlib,json,re,subprocess
payload=Path('/usr/local/lib/wormhole');policy=json.loads((payload/'policy.json').read_text())
source=payload/'dod-public-roots.pem'
if hashlib.sha256(source.read_bytes()).hexdigest()!=policy['public_ca_bundle']['roots_pem_sha256']:
    raise RuntimeError('public CA source mismatch')
target=Path('/usr/local/share/ca-certificates/wormhole-public-dod');target.mkdir(mode=0o755)
for index,pem in enumerate(re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',source.read_text(),re.S)):
    (target/(str(index)+'.crt')).write_text(pem+'\n')
# This offline workload needs no inherited public Web PKI. Keep the pinned DoD
# roots in the global store; the lab service/PAM CA stays explicitly scoped.
configuration=Path('/etc/ca-certificates.conf')
configuration.write_text('\n'.join(line if not line.strip() or line.lstrip().startswith(('#','!'))
    else '!'+line.strip() for line in configuration.read_text().splitlines())+'\n')
subprocess.run(['update-ca-certificates','--fresh'],check=True,timeout=20)
PY
printf '%s\n' 'Wormhole private home lab. Authorized lab use only. Activity is monitored.' > /etc/issue.net
printf '%s\n' 'Banner /etc/issue.net' > /etc/ssh/sshd_config.d/05-wormhole-banner.conf
cat > /etc/chrony/chrony.conf <<'EOF'
# Explicit lab host-clock source, not an authenticated external time authority.
server 192.0.2.1 port 12345 iburst minpoll 4 maxpoll 4
driftfile /var/lib/chrony/chrony.drift
makestep 1 -1
rtcsync
EOF
systemctl enable chrony
systemctl restart chrony
cat > /etc/rsyslog.d/70-wormhole-remote.conf <<'EOF'
global(DefaultNetstreamDriverCAFile="/etc/wormhole-lab-ca.crt")
auth.*;authpriv.* action(type="omfile" file="/var/log/wormhole-auth.log" fileCreateMode="0600")
daemon.* action(type="omfile" file="/var/log/wormhole-daemon.log" fileCreateMode="0600")
*.* action(type="omfwd" target="192.0.2.1" port="6514" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
  StreamDriverPermittedPeers="wormhole-sandbox"
  action.resumeRetryCount="-1" queue.type="LinkedList" queue.size="10000")
EOF
rsyslogd -N1
systemctl restart rsyslog
# A cron dependency must not create an undeclared guest mail ingress service.
if systemctl list-unit-files exim4.service --no-legend | grep -q '^exim4.service'; then
  systemctl disable --now exim4.service
fi
if command -v postconf >/dev/null; then
  # Keep local cron/audit mail delivery, with no guest network SMTP ingress.
  postconf -e 'inet_interfaces = loopback-only'
  # The packaged default-instance unit waits for process teardown before start;
  # bare postfix stop only requests asynchronous shutdown.
  systemctl restart postfix@-.service
fi
openssl rehash /etc/pam_pkcs11/cacerts /etc/pam_pkcs11/crls
test -f /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
cat > /etc/pam_pkcs11/pam_pkcs11.conf <<'EOF'
pam_pkcs11 {
  use_pkcs11_module = opensc;
  pkcs11_module opensc {
    module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so;
    slot_description = "none";
    ca_dir = /etc/pam_pkcs11/cacerts;
    crl_dir = /etc/pam_pkcs11/crls;
    cert_policy = ca, signature, ocsp_on, crl_offline;
  }
  use_mappers = pwent;
  mapper pwent { debug = false; ignorecase = false; module = internal; }
}
EOF
# The login stack accepts the configured real OpenSC token when available;
# retain the existing Unix-password path for the declared service operator.
# This configuration is not evidence of mandatory physical-token enforcement.
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/pam.d/common-auth');text=p.read_text()
# The documented quiet option suppresses conversation notices when no reader is
# attached. Authentication decisions remain intact, and the dedicated probe
# retains failure evidence. Notices must not contaminate JSON or binary output.
# Linux-PAM's exact extended form of sufficient: no guessed numeric jump, and
# an earlier required failure still cannot be overridden by token success.
line='auth [success=done new_authtok_reqd=done default=ignore] pam_pkcs11.so quiet'
if not any('pam_pkcs11.so' in s and not s.lstrip().startswith('#') for s in text.splitlines()):
    p.write_text(line+'\n'+text)
PY
# Isolated acceptance service: no software-token module enters common-auth.
# Temporary token objects arrive only during probes in private /run storage.
test -f /usr/lib/softhsm/libsofthsm2.so
sed 's/use_pkcs11_module = opensc;/use_pkcs11_module = software;/;s/pkcs11_module opensc {/pkcs11_module software {/;s|/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so|/usr/lib/softhsm/libsofthsm2.so|' \
  /etc/pam_pkcs11/pam_pkcs11.conf > /etc/pam_pkcs11/wormhole-software-token.conf
printf '%s\n' 'auth required pam_pkcs11.so quiet config_file=/etc/pam_pkcs11/wormhole-software-token.conf' \
  'account required pam_permit.so' > /etc/pam.d/wormhole-token-probe
chmod 0600 /etc/pam_pkcs11/wormhole-software-token.conf /etc/pam.d/wormhole-token-probe
install -m 0700 /usr/local/lib/wormhole/audit-offload.py /etc/cron.weekly/audit-offload
cat > /etc/audit/audisp-remote.conf <<'EOF'
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
EOF
cat > /etc/audit/plugins.d/au-remote.conf <<'EOF'
active = yes
direction = out
path = /sbin/audisp-remote
type = always
format = string
EOF
# The pinned Jammy auditctl(8) accepts literal signal names, not "reload";
# its auditd unit has no ExecReload. Follow auditd.service's remote-mode ordering
# guidance so audisp-remote does not suspend before the static link is configured.
install -d -m 0755 /etc/systemd/system/auditd.service.d
cat > /etc/systemd/system/auditd.service.d/50-wormhole-network.conf <<'EOF'
[Unit]
After=
After=network-online.target local-fs.target systemd-tmpfiles-setup.service
Wants=network-online.target
Before=
Before=shutdown.target
EOF
systemctl daemon-reload
auditctl --signal HUP
# Prove routing and certificate trust through the VM's actual NIC before the
# expensive AIDE step. At this point outgoing UFW policy is still permissive,
# so the management-negative is evidence for the mandatory libvirt filter.
python3 - <<'PY'
import socket,ssl,json,subprocess
from pathlib import Path
context=ssl.create_default_context(cafile='/etc/wormhole-lab-ca.crt')
with socket.create_connection(('192.0.2.1',6514),timeout=5) as sock:
 with context.wrap_socket(sock,server_hostname='wormhole-sandbox') as tls:
  tls.sendall(('installation-route-probe '+Path('/var/lib/wormhole/run-id').read_text().strip()+'\n').encode())
with socket.create_connection(('192.0.2.1',6000),timeout=5):pass
policy=subprocess.check_output(['ufw','status','verbose'],text=True)
if 'allow (outgoing)' not in policy:raise RuntimeError('cannot establish independent NIC isolation observation')
blocked=False
try:socket.create_connection(('192.0.2.1',22),timeout=3).close()
except OSError:blocked=True
if not blocked:raise RuntimeError('management plane reachable from guest')
Path('/var/lib/wormhole/network-isolation.json').write_text(json.dumps({'run_id':Path('/var/lib/wormhole/run-id').read_text().strip(),
 'guest_outgoing_was_allow':True,'management_listener_blocked':True,'tls_and_audit_routes_verified':True}))
PY
chronyc waitsync 20 0 0 1
# These are guest rules only. The mandatory libvirt NIC filter remains the
# boundary even before this guest configuration executes or if guest root edits it.
ufw default deny outgoing
ufw allow out on lab0 to 192.0.2.1 port 6514 proto tcp
ufw allow out on lab0 to 192.0.2.1 port 6000 proto tcp
ufw allow out on lab0 to 192.0.2.1 port 8080 proto tcp
ufw allow out on lab0 to 192.0.2.1 port 12345 proto udp
logger -t wormhole-sandbox 'installation support integration event'
auditctl -m 'wormhole sandbox installation event'
