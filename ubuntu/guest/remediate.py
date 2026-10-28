"""Installed first-boot remediation. Never invoked by acceptance."""
import json
import os
from pathlib import Path
import subprocess
import time
import signal
import resource
import shutil

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
# Protect editing/console commands while retaining unattended normal OS boot.
# Recovery entries are disabled; the separate boot secret never enters the ISO.
generator=Path('/etc/grub.d/10_linux')
if 'password_pbkdf2 boot grub.pbkdf2.sha512.100000.' not in Path('/etc/grub.d/40_custom').read_text():
    raise RuntimeError('run-scoped boot credential missing')
original=generator.read_text()
old='CLASS="--class gnu-linux --class gnu --class os"'
new='CLASS="--unrestricted --class gnu-linux --class gnu --class os"'
if new not in original:
    if original.count(old)!=1:raise RuntimeError('unsupported installed GRUB generator')
    generator.write_text(original.replace(old,new,1))
Path('/etc/default/grub.d/99-wormhole-access.cfg').write_text(
    'GRUB_DISABLE_RECOVERY=true\nGRUB_DISABLE_SUBMENU=y\n'
    'GRUB_TERMINAL_INPUT=serial\nGRUB_TERMINAL_OUTPUT=serial\n'
    'GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"\n')
subprocess.run(['update-grub'],check=True,timeout=30)
# pam_motd can create/rotate logs before the later common-session umask runs.
# Set the declared 077 mask before session modules on both login paths. This
# preserves diagnostics and fixes file creation rather than chmod after audit.
for file in (Path('/etc/pam.d/sshd'),Path('/etc/pam.d/login')):
    lines=file.read_text().splitlines()
    directive='session required pam_umask.so umask=0077 nousergroups'
    if directive not in lines:
        index=next(i for i,line in enumerate(lines) if line.lstrip().startswith('session'))
        lines.insert(index,directive)
        file.write_text('\n'.join(lines)+'\n')
# Only the declared guest management service is admitted. No host rules change.
for command in [['ufw','default','deny','incoming'], ['ufw','default','allow','outgoing'],
                ['ufw','limit','in','on','lab0','to','any','port','22','proto','tcp'],
                ['ufw','--force','enable']]:
    subprocess.run(command, check=True, timeout=15, env=env)
for name in plan['remediation_rules']:
    if time.monotonic() >= deadline:raise RuntimeError('absolute hardening deadline')
    start = time.monotonic()
    cpu_start=resource.getrusage(resource.RUSAGE_CHILDREN)
    print('WORMHOLE_HARDENING_RULE ' + name, flush=True)
    process=subprocess.Popen(['/bin/bash','-e',str(payload / 'remediation' / (name + '.sh'))],
            env=env,start_new_session=True)
    try:
        status = process.wait(timeout=min(400 if name=='aide_build_database' else 120,deadline-time.monotonic()))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid,signal.SIGTERM)
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
        status = 124
    cpu_end=resource.getrusage(resource.RUSAGE_CHILDREN)
    outcomes.append({'rule_id':name,'remediation_exit':status,'elapsed_seconds':round(time.monotonic()-start,3),
                     'child_cpu_seconds':round(cpu_end.ru_utime+cpu_end.ru_stime-cpu_start.ru_utime-cpu_start.ru_stime,3),
                     'root_used_bytes':shutil.disk_usage('/').used})
    with open('/dev/ttyS0','w') as serial:
        serial.write('WORMHOLE_HARDENING_PROGRESS completed='+str(len(outcomes))+' rule='+name+'\n')
    temporary=root/'remediation-results.tmp'
    temporary.write_text(json.dumps(outcomes,indent=2))
    temporary.replace(root/'remediation-results.json')
    if status:raise RuntimeError('first failed hardening operation: ' + name + ' exit=' + str(status))
print('WORMHOLE_HARDENING_COMPLETE',flush=True)
