"""Installed first-boot remediation. Never invoked by acceptance."""
import json
import os
from pathlib import Path
import subprocess
import time

root = Path('/var/lib/wormhole')
payload = Path('/usr/local/lib/wormhole')
release = Path('/etc/os-release').read_text()
if os.geteuid() != 0 or 'VERSION_ID="22.04"' not in release or not (root / 'run-id').is_file():
    raise RuntimeError('not the declared installed target')
if subprocess.check_output(['systemd-detect-virt'], text=True).strip() not in {'kvm', 'qemu'}:
    raise RuntimeError('guest remediation cannot run on the control environment')
if json.loads((payload / 'install-contract.json').read_text())['mode'] != 'hardened':
    raise RuntimeError('stock audit cannot remediate')
plan = json.loads((payload / 'remediation-plan.json').read_text())
deadline = time.monotonic() + 800
outcomes = []
env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', APT_CONFIG=str(payload / 'offline-apt.conf'))
# Only the declared guest management service is admitted. No host rules change.
for command in [['ufw','default','deny','incoming'], ['ufw','default','allow','outgoing'],
                ['ufw','limit','in','on','lab0','to','any','port','22','proto','tcp'],
                ['ufw','--force','enable']]:
    subprocess.run(command, check=True, timeout=15, env=env)
for name in plan['remediation_rules']:
    if time.monotonic() >= deadline:raise RuntimeError('absolute hardening deadline')
    start = time.monotonic()
    print('WORMHOLE_HARDENING_RULE ' + name, flush=True)
    try:
        status = subprocess.run(['/bin/bash','-e',str(payload / 'remediation' / (name + '.sh'))],
            env=env, timeout=min(120,deadline-time.monotonic())).returncode
    except subprocess.TimeoutExpired:
        status = 124
    outcomes.append({'rule_id':name,'remediation_exit':status,'elapsed_seconds':round(time.monotonic()-start,3)})
    temporary=root/'remediation-results.tmp'
    temporary.write_text(json.dumps(outcomes,indent=2))
    temporary.replace(root/'remediation-results.json')
    if status:raise RuntimeError('first failed hardening operation: ' + name + ' exit=' + str(status))
print('WORMHOLE_HARDENING_COMPLETE',flush=True)
