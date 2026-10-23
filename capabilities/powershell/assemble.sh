#!/bin/sh
# Separate optional variant. Run only in the admitted offline owned builder.
set -eu
if [ "${WORMHOLE_PS_ASSEMBLY_BOUNDED:-}" != 1 ]; then
    export WORMHOLE_PS_ASSEMBLY_BOUNDED=1
    exec timeout --signal=TERM --kill-after=5s 580s /bin/sh /recipe/assemble.sh "$@"
fi
[ "${1:-}" = helper-powershell ] && [ -f /.dockerenv ] && [ "$(id -u)" = 0 ]
[ "$(cat /etc/wormhole/role)" = helper ]
[ ! -e /usr/bin/pwsh ]
export POWERSHELL_TELEMETRY_OPTOUT=1
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
python3 - <<'PY'
import hashlib,json,pathlib,subprocess
lock=json.loads(pathlib.Path('/recipe/lock.json').read_text())
for item in lock['artifacts']:
 path=pathlib.Path('/artifacts')/item['filename']
 assert path.stat().st_size==item['bytes']
 assert hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256']
PY
# No apt sources, repositories or network are used. dpkg checks the actual base
# dependency closure and refuses missing dependencies rather than finding feeds.
dpkg -i /artifacts/libicu74.deb /artifacts/powershell.deb
install -d -m 755 /opt/wormhole-capabilities/powershell
install -m 644 /recipe/runtime.py /opt/wormhole-capabilities/powershell/runtime.py
install -m 644 /recipe/lock.json /opt/wormhole-capabilities/powershell/lock.json
/opt/wormhole/venv/bin/python - <<'PY' > /opt/wormhole/capability-installed.json
import os
os.setgroups([]);os.setgid(10001);os.setuid(10001)
os.execv('/opt/wormhole/venv/bin/python',['/opt/wormhole/venv/bin/python','/opt/wormhole-capabilities/powershell/runtime.py','doctor'])
PY
