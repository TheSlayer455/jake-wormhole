"""Read-only final-system observations; run inside the disposable guest."""
import hashlib
import json
from pathlib import Path
import pwd
import stat
import subprocess


def command(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, '', 'required tool absent')


def file_sha256(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            digest.update(block)
    return digest.hexdigest()


def observe():
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '22.04':
        raise RuntimeError('unsupported observation target')
    if command('systemd-detect-virt').stdout.strip() not in {'kvm', 'qemu'}:
        raise RuntimeError('observation requires installed lab VM')
    root = Path('/var/lib/wormhole')
    account = pwd.getpwnam('lab.service')
    home, ssh, key = (Path(account.pw_dir), Path(account.pw_dir) / '.ssh', Path(account.pw_dir) / '.ssh/authorized_keys')
    permissions = all(p.stat().st_uid == account.pw_uid for p in (home, ssh, key))
    permissions = permissions and stat.S_IMODE(ssh.stat().st_mode) == 0o700 and stat.S_IMODE(key.stat().st_mode) == 0o600
    checks = {
        'installed-os-identity': True,
        'installed-disk-boot': command('findmnt', '-n', '-o', 'SOURCE', '/').stdout.strip().startswith('/dev/'),
        'finalization-complete': (root / 'installation-complete').is_file(),
        'required-reboot': (root / 'firstboot-id').read_text().strip() != (root / 'final-boot-id').read_text().strip()
            == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'final-home-key-permissions': permissions and key.stat().st_size > 0 and account.pw_shell == '/bin/bash',
        'guest-apparmor-enforced': command('aa-status', '--enabled').returncode == 0
            and Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y',
        'audit-service': command('systemctl', 'is-active', '--quiet', 'auditd').returncode == 0,
        'guest-network-policy': command('ufw', 'status').stdout.startswith('Status: active'),
    }
    policy = json.loads(Path('/usr/local/lib/wormhole/policy.json').read_text())
    content = Path('/usr/local/lib/wormhole/ssg-ubuntu2204-ds.xml')
    checks['assessment-content-identity'] = file_sha256(content) == policy['content']['datastream_sha256']
    if json.loads(Path('/usr/local/lib/wormhole/install-contract.json').read_text()).get('sandbox'):
        checks['encrypted-root']=command('findmnt','-n','-o','SOURCE','/').stdout.strip()=='/dev/mapper/wormhole-root' and command('cryptsetup','isLuks','/dev/vda3').returncode==0
        checks['encrypted-pbkdf2']= 'pbkdf2' in command('cryptsetup','luksDump','/dev/vda3').stdout.lower()
        checks['no-plaintext-swap']=not Path('/proc/swaps').read_text().splitlines()[1:]
        checks['no-installed-unlock-key']=not Path('/run/wormhole-unlock').exists() and all(line.split()[2] in {'none','-'} for line in Path('/etc/crypttab').read_text().splitlines() if line.strip() and not line.startswith('#'))
    inventory = command('dpkg-query', '-W', '-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n')
    if inventory.returncode:
        raise RuntimeError('native inventory failed')
    packages = []
    for line in inventory.stdout.splitlines():
        status, name, version, architecture = line.split('\t')
        if status.startswith('ii'):
            packages.append({'name': name, 'version': version, 'architecture': architecture})
    return {'checks': checks, 'packages': packages, 'inventory_kind': 'installed-dpkg',
            'kernel': command('uname', '-r').stdout.strip(), 'run_id': (root / 'run-id').read_text().strip()}


if __name__ == '__main__':
    print(json.dumps(observe(), sort_keys=True))
