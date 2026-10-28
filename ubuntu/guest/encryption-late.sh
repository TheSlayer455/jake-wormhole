#!/bin/bash
# INSTALLER ONLY: this file is never a host or acceptance remediation command.
set -euo pipefail
test -d /target/etc
test -s /run/wormhole-unlock
test "$(findmnt -n -o SOURCE /target)" = /dev/mapper/wormhole-root
test "$(lsblk -ndo TYPE /dev/vda)" = disk
cryptsetup isLuks /dev/vda3
# Canonical documents PBKDF2 as a prerequisite for FIPS + LUKS. This does not
# enable FIPS or establish validation of the installed crypto implementation.
if cryptsetup luksDump /dev/vda3 | grep -q 'Version:.*2'; then
  cryptsetup luksConvertKey --pbkdf pbkdf2 --pbkdf-force-iterations 600000 --key-file /run/wormhole-unlock /dev/vda3
fi
install -d -m 0700 /target/var/lib/wormhole
cryptsetup luksDump /dev/vda3 > /target/var/lib/wormhole/luks-header.txt
grep -qi pbkdf2 /target/var/lib/wormhole/luks-header.txt
# Curtin's ordinary keyfile path is not an installed key: prove crypttab asks
# for a console passphrase, and declare no swap outside encrypted root.
awk 'NF && $1 !~ /^#/ {if ($3 != "none" && $3 != "-") exit 1}' /target/etc/crypttab
curtin in-target --target=/target -- update-initramfs -u -k all
rm /run/wormhole-unlock
printf '%s\n' WORMHOLE_ENCRYPTED_INSTALL_COMPLETE > /dev/ttyS0
