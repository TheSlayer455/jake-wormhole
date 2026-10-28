"""Pinned offline Ubuntu assessment/install inputs; no enrollment credentials."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import base64

from .runs import SOURCE_ROOT, atomic_json, read_json, workspace_path
from .vm_inputs import build_ubuntu, cloud_config, sha256
from .ubuntu_assessment import POLICY, inventory, require


def prepare(store):
    """Freeze signature-verified, isolated APT snapshot downloads."""
    store = workspace_path(store)
    policy = json.loads(POLICY.read_text())
    inventory(store / 'ssg-ubuntu2204-ds.xml', policy)
    bundle = store / 'bundle'
    if (bundle / 'manifest.json').exists():
        manifest = read_json(bundle / 'manifest.json')
        for item in manifest['files']:
            require(sha256(bundle / item['path']) == item['sha256'], 'ubuntu_bundle_corrupted')
        return manifest
    require(not bundle.exists(), 'ubuntu_bundle_incomplete')
    bundle.mkdir(mode=0o700)
    repo = bundle / 'repository';repo.mkdir(mode=0o700)
    apt = store / 'apt'
    config = ['-o', 'Dir=' + str(apt), '-o', 'Dir::State::status=' + str(apt / 'var/lib/dpkg/status'),
              '-o', 'APT::Architecture=amd64', '-o', 'Dir::Etc::netrc=/dev/null', '-o', 'Dir::Etc::netrcparts=-']
    origins = []
    for release in (apt / 'var/lib/apt/lists').glob('*_InRelease'):
        subprocess.run(['gpgv', '--keyring', '/usr/share/keyrings/ubuntu-archive-keyring.gpg', str(release)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
        origins.append({'name': release.name, 'sha256': sha256(release)})
    require(len(origins) == 3, 'ubuntu_snapshot_origins_missing')
    packages, paragraphs = [], []
    for deb in sorted((apt / 'var/cache/apt/archives').glob('*.deb')):
        fields = subprocess.check_output(['dpkg-deb', '-f', str(deb), 'Package', 'Version', 'Architecture'], timeout=10).decode()
        values = dict(re.findall(r'^(Package|Version|Architecture): (.+)$', fields, re.M))
        require(set(values) == {'Package', 'Version', 'Architecture'}, 'ubuntu_package_metadata')
        actual = sha256(deb)
        metadata = subprocess.check_output(['apt-cache', *config, 'show', values['Package'] + '=' + values['Version']], timeout=15).decode()
        require('SHA256: ' + actual in metadata, 'ubuntu_package_origin_mismatch')
        control = subprocess.check_output(['dpkg-deb', '-f', str(deb)], timeout=10).decode().strip()
        shutil.copyfile(deb, repo / deb.name)
        paragraphs.append(control + '\nFilename: ./' + deb.name + '\nSize: ' + str(deb.stat().st_size) + '\nSHA256: ' + actual)
        packages.append({'name': values['Package'], 'version': values['Version'], 'architecture': values['Architecture'], 'sha256': actual})
    require(any(x['name'] == 'libopenscap8' for x in packages), 'ubuntu_scanner_dependency_missing')
    (repo / 'Packages').write_text('\n\n'.join(paragraphs) + '\n', encoding='utf-8')
    for name in ['ssg-ubuntu2204-ds.xml', 'LICENSE']:
        shutil.copyfile(store / name, bundle / name)
    files = [{'path': p.relative_to(bundle).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha256(p)}
             for p in sorted(bundle.rglob('*')) if p.is_file()]
    manifest = {'schema_version': '1.0', 'capability': 'ubuntu-offline-assessment-inputs',
        'snapshot': policy['package_snapshot'], 'signed_origins': origins, 'packages': packages, 'files': files,
        'usg_available': False, 'fips_modules_available': False, 'production_iso_eligible': False}
    atomic_json(bundle / 'manifest.json', manifest)
    return manifest


def seed_config(identifier, public_key, address, mac, password_hash):
    require(re.fullmatch(r'ssh-rsa [A-Za-z0-9+/=]{300,900}(?: [A-Za-z0-9_.-]+)?', public_key), 'ubuntu_public_key_invalid')
    require(re.fullmatch(r'\$6\$[./A-Za-z0-9$]+', password_hash), 'ubuntu_password_hash_invalid')
    value = json.loads(cloud_config(identifier, 'ssh-ed25519 ' + 'A' * 68, address, mac).split('\n', 1)[1])
    install = """set -eu
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
install -d -m 0755 /usr/local/lib/wormhole /var/lib/wormhole
cp -a /tmp/wormhole-payload/. /usr/local/lib/wormhole/
chmod -R a+rX /usr/local/lib/wormhole/repository
printf '%s\\n' 'deb [trusted=yes] file:/usr/local/lib/wormhole/repository ./' > /etc/apt/sources.list.d/wormhole-local.list
apt-get -o Dir::Etc::sourcelist=sources.list.d/wormhole-local.list -o Dir::Etc::sourceparts=- update
DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends -o Dir::Etc::sourcelist=sources.list.d/wormhole-local.list -o Dir::Etc::sourceparts=- install libopenscap8=1.2.17-0.1ubuntu7.22.04.3
useradd --create-home --shell /bin/bash --user-group lab.service
chpasswd --encrypted < /tmp/wormhole-identity/password
install -d -o lab.service -g lab.service -m 0700 /home/lab.service/.ssh
install -o lab.service -g lab.service -m 0600 /tmp/wormhole-identity/public-key /home/lab.service/.ssh/authorized_keys
printf '%s\\n' 'lab.service ALL=(ALL) ALL' > /etc/sudoers.d/wormhole-lab
chmod 0440 /etc/sudoers.d/wormhole-lab
visudo -cf /etc/sudoers.d/wormhole-lab
printf '%s\\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin no' > /etc/ssh/sshd_config.d/10-wormhole.conf
ssh-keygen -q -t rsa -b 3072 -N '' -f /etc/ssh/ssh_host_rsa_key.new
mv /etc/ssh/ssh_host_rsa_key.new /etc/ssh/ssh_host_rsa_key
mv /etc/ssh/ssh_host_rsa_key.new.pub /etc/ssh/ssh_host_rsa_key.pub
install -m 0644 /usr/local/lib/wormhole/wormhole-finalize.service /etc/systemd/system/wormhole-finalize.service
systemctl enable wormhole-finalize.service
cat /tmp/wormhole-identity/run-id > /var/lib/wormhole/run-id
printf '%s\\n' 'users: []' 'ssh_deletekeys: false' 'preserve_hostname: true' > /etc/cloud/cloud.cfg.d/99-wormhole.cfg
printf 'vm-%s\\n' "$(cut -c1-8 /var/lib/wormhole/run-id)" > /etc/hostname
rm -rf /tmp/wormhole-identity /tmp/wormhole-payload
"""
    # Keep even encoded password hashes out of installer command arguments/logs.
    # Identity files live only in the private, run-specific NoCloud seed.
    late = [['mkdir', '-p', '/target/tmp/wormhole-payload', '/run/wormhole-seed'],
            ['cp', '-a', '/cdrom/wormhole/.', '/target/tmp/wormhole-payload/'],
            ['mount', '-o', 'ro', '/dev/disk/by-label/CIDATA', '/run/wormhole-seed'],
            ['cp', '-a', '/run/wormhole-seed/wormhole-identity', '/target/tmp/wormhole-identity'],
            ['umount', '/run/wormhole-seed']]
    late.append(['curtin', 'in-target', '--target=/target', '--', 'sh', '-c', install])
    value['autoinstall']['late-commands'] = late
    value['autoinstall']['user-data']['hostname'] = 'vm-' + identifier[:8]
    return '#cloud-config\n' + json.dumps(value, indent=2) + '\n'


def build(source, destination, seed_dir, identifier, public_key, address, mac, *, store, mode, password_hash, reuse=None):
    require(mode in {'stock-audit', 'hardened'}, 'ubuntu_mode_invalid')
    require(mode == 'stock-audit', 'hardening_not_yet_implemented')
    store, destination, seed_dir = Path(store), Path(destination), Path(seed_dir)
    prepare(store)
    manifest = build_ubuntu(source, destination, seed_dir, identifier, 'ssh-ed25519 ' + 'A' * 68, address, mac)
    payload = seed_dir / 'payload';shutil.copytree(store / 'bundle', payload)
    shutil.copyfile(SOURCE_ROOT / 'ubuntu/guest/finalize.sh', payload / 'finalize.sh')
    shutil.copyfile(SOURCE_ROOT / 'ubuntu/guest/audit.sh', payload / 'audit.sh')
    shutil.copyfile(POLICY, payload / 'policy.json')
    contract = {'mode': mode, 'policy_sha256': sha256(POLICY), 'dependency_manifest_sha256': sha256(store / 'bundle/manifest.json')}
    (payload / 'install-contract.json').write_text(json.dumps(contract, sort_keys=True))
    (payload / 'wormhole-finalize.service').write_text('[Unit]\nDescription=Wormhole installed-guest finalization\nAfter=local-fs.target cloud-config.service\nBefore=ssh.service ssh.socket\n[Service]\nType=oneshot\nRuntimeDirectory=sshd\nRuntimeDirectoryMode=0755\nExecStart=/bin/bash /usr/local/lib/wormhole/finalize.sh\nTimeoutStartSec=1000\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n')
    final_iso = destination.with_name('final-candidate.iso')
    with (seed_dir / 'payload-build.log').open('wb') as log:
        subprocess.run(['xorriso', '-indev', str(destination), '-outdev', str(final_iso), '-boot_image', 'any', 'replay',
                        '-map', str(payload), '/wormhole'], stdout=log, stderr=log, check=True, timeout=300)
    os.replace(final_iso, destination)
    (seed_dir / 'user-data').write_text(seed_config(identifier, public_key, address, mac, password_hash))
    identity = seed_dir / 'wormhole-identity';identity.mkdir(mode=0o700)
    for name, raw in {'public-key': public_key + '\n', 'password': 'lab.service:' + password_hash + '\n', 'run-id': identifier + '\n'}.items():
        (identity / name).write_text(raw)
    seed = destination.with_name('seed.iso');seed.unlink()
    subprocess.run(['xorriso', '-as', 'mkisofs', '-V', 'CIDATA', '-J', '-r', '-graft-points', '-o', str(seed),
                    'user-data=' + str(seed_dir / 'user-data'), 'meta-data=' + str(seed_dir / 'meta-data'),
                    'wormhole-identity=' + str(identity)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)
    # Prove the seed's real filesystem layout before allocating an installation.
    seed_check = seed_dir / 'seed-layout-check'
    subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(seed), '-extract', '/wormhole-identity', str(seed_check)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
    require({p.name for p in seed_check.iterdir()} == {'public-key', 'password', 'run-id'} and
            all(sha256(p) == sha256(identity / p.name) for p in seed_check.iterdir()), 'identity_seed_layout_invalid')
    manifest.update(capability='ubuntu-assessment-candidate-iso', candidate_sha256=sha256(destination), seed_sha256=sha256(seed),
        installation_input_sha256=sha256(seed_dir / 'user-data'), mode=mode, policy_sha256=sha256(POLICY),
        dependency_manifest_sha256=sha256(store / 'bundle/manifest.json'), scanner_package='libopenscap8=1.2.17-0.1ubuntu7.22.04.3',
        nonsecret_seed_template_sha256=sha256(SOURCE_ROOT / 'wormhole/ubuntu_inputs.py'))
    atomic_json(seed_dir / 'build-manifest.json', manifest)
    return manifest
