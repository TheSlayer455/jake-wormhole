#!/bin/bash
# Offline Ubuntu 22.04 BUILD CONTAINER only, never a guest or host command.
set -euo pipefail
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
test -f /.dockerenv
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
printf 'deb [trusted=yes] file:/inputs/repository ./\n' > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*
# The read-only input mount is owner-only private storage. This ordinary,
# network-less build container already installs packages as root; limit this
# APT setting to the offline builder rather than relaxing host input permissions.
apt-get -o APT::Sandbox::User=root update
DEBIAN_FRONTEND=noninteractive apt-get -o APT::Sandbox::User=root install -y --no-install-recommends --allow-downgrades \
 build-essential cmake pkg-config libdbus-1-dev libdbus-glib-1-dev libcurl4-openssl-dev \
 libgcrypt20-dev libselinux1-dev libxslt1-dev libglib2.0-dev libacl1-dev libblkid-dev libcap-dev \
 libxml2-dev libldap2-dev libpcre2-dev libbz2-dev librpm-dev libyaml-dev libxmlsec1-dev
mkdir -p /work/source
tar -xzf /source/openscap-1.4.6.tar.gz -C /work/source --strip-components=1
cmake -S /work/source -B /work/build -DCMAKE_BUILD_TYPE=Release \
 -DCMAKE_INSTALL_PREFIX=/opt/wormhole-openscap -DCMAKE_INSTALL_RPATH=/opt/wormhole-openscap/lib \
 -DENABLE_PYTHON3=OFF -DENABLE_PERL=OFF -DENABLE_DOCS=OFF -DENABLE_TESTS=OFF
cmake --build /work/build --parallel 2
DESTDIR=/work/stage cmake --install /work/build
tar -C /work/stage/opt -czf /work/openscap-lab.tar.gz wormhole-openscap
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > /work/build-packages.tsv
LD_LIBRARY_PATH=/work/stage/opt/wormhole-openscap/lib:/work/stage/opt/wormhole-openscap/lib64 /work/stage/opt/wormhole-openscap/bin/oscap --version > /work/scanner-version.txt
