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
systemctl reload auditd
# These are guest rules only. The mandatory libvirt NIC filter remains the
# boundary even before this guest configuration executes or if guest root edits it.
ufw default deny outgoing
ufw allow out on lab0 to 192.0.2.1 port 6514 proto tcp
ufw allow out on lab0 to 192.0.2.1 port 6000 proto tcp
ufw allow out on lab0 to 192.0.2.1 port 12345 proto udp
logger -t wormhole-sandbox 'installation support integration event'
auditctl -m 'wormhole sandbox installation event'
