#!/bin/bash
# Offline, capped project build container only; never run on the host or a guest.
set -euo pipefail
test -f /.dockerenv
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
export DEBIAN_FRONTEND=noninteractive
printf '%s\n' 'deb [trusted=yes] file:/inputs/repository ./' > /etc/apt/sources.list
apt-get -o APT::Sandbox::User=root update
apt-get -o APT::Sandbox::User=root -y --no-install-recommends install \
  python3 dpkg-dev build-essential debhelper libcurl4-openssl-dev libldap2-dev \
  libpam-dev libpcsclite-dev libssl-dev pkg-config
cd /work
dpkg-source -x /source/pam-pkcs11_0.6.11-4ubuntu0.1.dsc pam
cd pam
python3 /recipe/patch-pam-crl.py
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(dpkg-parsechangelog -S Timestamp)
export DEB_BUILD_OPTIONS=parallel=2
python3 - <<'PY'
from pathlib import Path
import os,datetime
path=Path('debian/changelog');original=path.read_text()
stamp=datetime.datetime.fromtimestamp(int(os.environ['SOURCE_DATE_EPOCH']),datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
path.write_text('pam-pkcs11 (0.6.11-4ubuntu0.1+wormhole3) jammy; urgency=medium\n\n'
    '  * Lab backport: correct OpenSSL object pointers and retain owned CRL references.\n\n'
    ' -- Wormhole Lab <nobody@example.invalid>  '+stamp+'\n\n'+original)
rules=Path('debian/rules')
text=rules.read_text()
if text.count('override_dh_auto_install:')!=1 or 'wormhole-pam-config-check' in text:
    raise RuntimeError('unexpected pinned Debian installation rules')
rules.write_text(text+'\n\tmkdir -p debian/libpam-pkcs11/usr/libexec\n'
    '\t$(CC) $(CFLAGS) $(CPPFLAGS) -I./src/scconf /recipe/pam-config-check.c '
    'src/scconf/.libs/libscconf.a $(LDFLAGS) -o debian/libpam-pkcs11/usr/libexec/wormhole-pam-config-check\n')
PY
dpkg-buildpackage -us -uc -b
cp wormhole-pam-repair.json wormhole-pam-crl.patch /work/
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > /work/build-packages.tsv
