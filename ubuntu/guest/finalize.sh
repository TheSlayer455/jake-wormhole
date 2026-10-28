#!/bin/bash
# Installed by the ISO; never run on the host or helper.
set -euo pipefail
test "$(id -u)" = 0
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
test "$(systemd-detect-virt)" = kvm || test "$(systemd-detect-virt)" = qemu
test -s /var/lib/wormhole/run-id
test -s /usr/local/lib/wormhole/install-contract.json
test "$(findmnt -n -o SOURCE /)" != overlay
exec >> /var/lib/wormhole/finalization.log 2>&1
trap 'rc=$?; printf "WORMHOLE_FINALIZATION_FAILED exit=%s\n" "$rc" > /dev/ttyS0; exit "$rc"' ERR
boot_id=$(cat /proc/sys/kernel/random/boot_id)
if test -f /var/lib/wormhole/firstboot-complete; then
  test "$(cat /var/lib/wormhole/firstboot-id)" != "$boot_id"
  printf '%s\n' "$boot_id" > /var/lib/wormhole/final-boot-id
  touch /var/lib/wormhole/installation-complete
  printf '%s\n' WORMHOLE_FINAL_HOST_KEY_BEGIN > /dev/ttyS0
  cat /etc/ssh/ssh_host_rsa_key.pub > /dev/ttyS0
  printf '%s\n' WORMHOLE_FINAL_HOST_KEY_END > /dev/ttyS0
  exit 0
fi
printf '%s\n' "$boot_id" > /var/lib/wormhole/firstboot-id
printf '%s\n' WORMHOLE_FINALIZATION_STARTED > /dev/ttyS0
test -x /usr/bin/oscap
oscap --version > /var/lib/wormhole/scanner-version.txt
if test -s /usr/local/lib/wormhole/remediation.sh; then
  timeout --signal=TERM --kill-after=10 900 /bin/bash /usr/local/lib/wormhole/remediation.sh
fi
/usr/sbin/sshd -t
visudo -cf /etc/sudoers.d/wormhole-lab
test "$(stat -c %a /home/lab.service/.ssh)" = 700
test "$(stat -c %a /home/lab.service/.ssh/authorized_keys)" = 600
touch /var/lib/wormhole/firstboot-complete
printf '%s\n' WORMHOLE_REQUIRED_REBOOT > /dev/ttyS0
systemctl --no-block reboot
sleep infinity
