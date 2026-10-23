#!/bin/sh
# Authoritative image assembly recipe, executed only in an admitted owned builder.
set -eu
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
role=${1:-}
case "$role" in target|helper) ;; *) echo 'location=builder invalid image role' >&2; exit 2;; esac
[ -f /.dockerenv ] && [ "$(id -u)" = 0 ] || { echo 'location=builder container-only root recipe refused' >&2; exit 2; }
grep -qx 'ID=ubuntu' /etc/os-release
grep -qx 'VERSION_ID="24.04"' /etc/os-release

# Ubuntu's minimal base may not contain a CA bundle. Extract public trust anchors
# from the hash-verified snapshot package, without running its post-install hook.
mkdir -p /tmp/wormhole-bootstrap
dpkg-deb -x /artifacts/bootstrap-ca.deb /tmp/wormhole-bootstrap
cat /tmp/wormhole-bootstrap/usr/share/ca-certificates/mozilla/*.crt > /tmp/wormhole-ca.pem
rm -f /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/ubuntu.sources
cat > /etc/apt/sources.list.d/wormhole.sources <<'EOF'
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/20261023T000000Z/
Suites: noble noble-updates noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Check-Valid-Until: no
EOF
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d

# Package post-installation must not create private host keys during image build.
dpkg-divert --quiet --local --add --rename --divert /usr/bin/ssh-keygen.wormhole-original /usr/bin/ssh-keygen
printf '#!/bin/sh\nexit 0\n' > /usr/bin/ssh-keygen
chmod 755 /usr/bin/ssh-keygen
set --
while read -r group package version; do
    case "$group" in ''|'#'*) continue;; esac
    if [ "$group" = common ] || [ "$group" = "$role" ]; then
        set -- "$@" "$package=$version"
    fi
done < /recipe/apt-packages.lock
apt-get -qq -o Acquire::https::CaInfo=/tmp/wormhole-ca.pem update
apt-get -qq -o Acquire::https::CaInfo=/tmp/wormhole-ca.pem --no-install-recommends install "$@"
rm -f /usr/bin/ssh-keygen
dpkg-divert --quiet --local --remove --rename --divert /usr/bin/ssh-keygen.wormhole-original /usr/bin/ssh-keygen

groupadd --gid 10001 wormhole
useradd --uid 10001 --gid 10001 --create-home --shell /bin/sh wormhole
# A non-locked invalid password hash permits public-key auth with UsePAM=no;
# password and keyboard-interactive auth remain disabled by the sshd contract.
usermod --password x wormhole
chmod 750 /home/wormhole
mkdir -p /opt/wormhole /etc/wormhole
printf '%s\n' "$role" > /etc/wormhole/role
install -m 644 /recipe/runtime.py /opt/wormhole/runtime.py
install -m 644 /recipe/images.lock.json /opt/wormhole/images.lock.json
if [ "$role" = helper ]; then
    python3 -m venv /opt/wormhole/venv
    /opt/wormhole/venv/bin/python -m pip --isolated --disable-pip-version-check install \
        --no-index --find-links=/artifacts/wheels --only-binary=:all: \
        --require-hashes -r /recipe/helper-requirements.lock
    /opt/wormhole/venv/bin/python -m pip --isolated --disable-pip-version-check check
    install -m 644 /recipe/ssh_config /etc/ssh/ssh_config.d/90-wormhole.conf
else
    install -m 644 /recipe/sshd_config /etc/ssh/sshd_config
fi
if find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' | grep -q .; then
    echo 'location=builder unexpected host key: refusing image' >&2
    exit 1
fi
if command -v docker >/dev/null 2>&1 || [ -e /var/run/docker.sock ] || [ -e /run/docker.sock ]; then
    echo 'location=builder Docker tooling/socket is forbidden in these images' >&2
    exit 1
fi
apt-get clean
rm -rf /tmp/wormhole-bootstrap
rm -f /tmp/wormhole-ca.pem
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
if [ "$role" = helper ]; then
    python3 -c 'import os; os.setgroups([]); os.setgid(10001); os.setuid(10001); os.execv("/opt/wormhole/venv/bin/python", ["/opt/wormhole/venv/bin/python", "/opt/wormhole/runtime.py", "helper", "doctor"])' > /opt/wormhole/installed.json
else
    python3 /opt/wormhole/runtime.py target doctor > /opt/wormhole/installed.json
fi
printf 'location=builder role=%s assembly completed; runtime qualification is separate\n' "$role"
