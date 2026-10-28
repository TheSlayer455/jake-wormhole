#!/bin/bash
# Installed-guest configuration only; acceptance never invokes this file.
set -euo pipefail
test "$(systemd-detect-virt)" = kvm
test -f /var/lib/wormhole/run-id
test -f /etc/wormhole-lab-ca.crt
printf '%s\n' 'Wormhole private home lab. Authorized lab use only. Activity is monitored.' > /etc/issue.net
printf '%s\n' 'Banner /etc/issue.net' > /etc/ssh/sshd_config.d/05-wormhole-banner.conf
cat > /etc/chrony/chrony.conf <<'EOF'
# Explicit lab host-clock source, not an authenticated external time authority.
server 192.0.2.1 port 12345 iburst minpoll 4 maxpoll 4
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
EOF
systemctl enable chrony
systemctl restart chrony
cat > /etc/rsyslog.d/70-wormhole-remote.conf <<'EOF'
global(DefaultNetstreamDriverCAFile="/etc/wormhole-lab-ca.crt")
*.* action(type="omfwd" target="192.0.2.1" port="6514" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
  StreamDriverPermittedPeers="wormhole-sandbox"
  action.resumeRetryCount="-1" queue.type="LinkedList" queue.size="10000")
EOF
rsyslogd -N1
systemctl restart rsyslog
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
ufw allow out on lab0 to 192.0.2.1 port 12345 proto udp
logger -t wormhole-sandbox 'installation support integration event'
auditctl -m 'wormhole sandbox installation event'
