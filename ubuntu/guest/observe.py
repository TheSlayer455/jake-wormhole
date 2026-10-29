"""Read-only final-system observations; run inside the disposable guest."""
import hashlib
import json
from pathlib import Path
import pwd
import stat
import subprocess
import socket
import ssl


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


def trust_inventory(bundle='/etc/ssl/certs/ca-certificates.crt'):
    # get_ca_certs lists already-loaded roots, not the lazy capath inventory.
    # Enumerate the actual installed bundle explicitly, without changing trust.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(bundle))
    certificates=context.get_ca_certs(binary_form=True)
    return {'fingerprints':sorted({hashlib.sha256(der).hexdigest() for der in certificates}),
            'bundle_sha256':file_sha256(Path(bundle)),
            'default_verify_paths':ssl.get_default_verify_paths()._asdict(),
            'default_loaded_count':len(ssl.create_default_context().get_ca_certs()),
            'subjects':[cert['subject'] for cert in context.get_ca_certs()]}


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
    audit_offload=None
    policy = json.loads(Path('/usr/local/lib/wormhole/policy.json').read_text())
    content = Path('/usr/local/lib/wormhole/ssg-ubuntu2204-ds.xml')
    checks['assessment-content-identity'] = file_sha256(content) == policy['content']['datastream_sha256']
    if json.loads(Path('/usr/local/lib/wormhole/install-contract.json').read_text()).get('sandbox'):
        checks['encrypted-root']=command('findmnt','-n','-o','SOURCE','/').stdout.strip()=='/dev/mapper/wormhole-root' and command('cryptsetup','isLuks','/dev/vda3').returncode==0
        checks['encrypted-pbkdf2']= 'pbkdf2' in command('cryptsetup','luksDump','/dev/vda3').stdout.lower()
        checks['no-plaintext-swap']=not Path('/proc/swaps').read_text().splitlines()[1:]
        checks['no-installed-unlock-key']=not Path('/run/wormhole-unlock').exists() and all(line.split()[2] in {'none','-'} for line in Path('/etc/crypttab').read_text().splitlines() if line.strip() and not line.startswith('#'))
        checks['lab-time-synchronized']='^* 192.0.2.1' in command('chronyc','-n','sources').stdout
        context=ssl.create_default_context(cafile='/etc/wormhole-lab-ca.crt')
        try:
            with socket.create_connection(('192.0.2.1',6514),timeout=3) as sock:
                with context.wrap_socket(sock,server_hostname='wormhole-sandbox') as tls:
                    tls.sendall(('WORMHOLE_TLS_PROBE '+(root/'run-id').read_text().strip()+'\n').encode())
            checks['lab-tls-trust']=True
        except OSError:checks['lab-tls-trust']=False
        try:
            with socket.create_connection(('192.0.2.1',6514),timeout=3) as sock:context.wrap_socket(sock,server_hostname='untrusted.invalid').close()
            checks['lab-invalid-certificate-refused']=False
        except ssl.SSLCertVerificationError:checks['lab-invalid-certificate-refused']=True
        except OSError:checks['lab-invalid-certificate-refused']=False
        try:
            with socket.create_connection(('192.0.2.1',6514),timeout=3) as sock:ssl.create_default_context().wrap_socket(sock,server_hostname='wormhole-sandbox').close()
            checks['lab-invalid-certificate-refused']=False
        except ssl.SSLCertVerificationError:pass
        except OSError:checks['lab-invalid-certificate-refused']=False
        try:
            socket.create_connection(('192.0.2.1',22),timeout=2).close();checks['management-plane-blocked']=False
        except OSError:checks['management-plane-blocked']=True
        isolation=root/'network-isolation.json'
        prior=json.loads(isolation.read_text()) if isolation.exists() else {}
        checks['management-plane-blocked'] &= prior.get('run_id')==(root/'run-id').read_text().strip() and prior.get('guest_outgoing_was_allow') is True and prior.get('management_listener_blocked') is True
        checks['lab-banner']=command('sshd','-T').stdout.find('banner /etc/issue.net')>=0 and 'private home lab' in Path('/etc/issue.net').read_text()
        status=command('ufw','status')
        checks['v2r8-ufw-effective-status']=status.returncode==0 and status.stdout.splitlines()[0]=='Status: active'
        checks['v2r8-banner-effective-file']=checks['lab-banner'] and Path('/etc/issue.net').read_text().strip()=='Wormhole private home lab. Authorized lab use only. Activity is monitored.'
        trust=trust_inventory();anchors=set(trust['fingerprints'])
        source=json.loads(Path('/usr/local/lib/wormhole/dod-ca-source.json').read_text())
        checks['official-public-dod-roots-staged']=bool(source['roots']) and {r['sha256'] for r in source['roots']}<=anchors
        command('logger','-t','wormhole-acceptance',(root/'run-id').read_text().strip())
        checks['audit-event-probe']=command('auditctl','-m','wormhole acceptance '+(root/'run-id').read_text().strip()).returncode==0
        valid=command('openssl','verify','-CAfile','/etc/wormhole-lab-ca.crt','-CRLfile','/etc/pam_pkcs11/crls/lab-ca.crl',
                      '-crl_check','/usr/local/share/wormhole-pki/active.pem')
        revoked=command('openssl','verify','-CAfile','/etc/wormhole-lab-ca.crt','-CRLfile','/etc/pam_pkcs11/crls/lab-ca.crl',
                        '-crl_check','/usr/local/share/wormhole-pki/revoked.pem')
        untrusted=command('openssl','verify','-CAfile','/etc/ssl/certs/ca-certificates.crt','/usr/local/share/wormhole-pki/active.pem')
        checks['lab-client-revocation']=valid.returncode==0 and revoked.returncode!=0 and 'certificate revoked' in revoked.stderr and untrusted.returncode!=0
        checks['lab-ocsp-status']=True
        for name,status in (('active','good'),('revoked','revoked')):
            response=command('openssl','ocsp','-issuer','/etc/wormhole-lab-ca.crt','-cert','/usr/local/share/wormhole-pki/'+name+'.pem',
                '-CAfile','/etc/wormhole-lab-ca.crt','-url','http://192.0.2.1:8080','-timeout','3')
            checks['lab-ocsp-status'] &= response.returncode==0 and 'Response verify OK' in response.stderr and ': '+status in response.stdout
        # Deliberate validation snapshot/event, not remediation or package setup.
        checks['weekly-audit-offload']=command('/etc/cron.weekly/audit-offload').returncode==0
        if checks['weekly-audit-offload']:
            audit_offload=json.loads((root/'audit-offload-receipt.json').read_text())
            checks['weekly-audit-offload'] &= audit_offload.get('receiver_acknowledged') is True and audit_offload.get('run_id')==(root/'run-id').read_text().strip()
    inventory = command('dpkg-query', '-W', '-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n')
    if inventory.returncode:
        raise RuntimeError('native inventory failed')
    packages = []
    for line in inventory.stdout.splitlines():
        status, name, version, architecture = line.split('\t')
        if status.startswith('ii'):
            packages.append({'name': name, 'version': version, 'architecture': architecture})
    binary=Path('/opt/wormhole-openscap/bin/oscap') if Path('/usr/local/lib/wormhole/toolchain.json').exists() else Path('/usr/bin/oscap')
    payloads=[{'name':'openscap-scanner','version':command('oscap','--version').stdout.splitlines()[0],
               'binary_sha256':file_sha256(binary)}]
    pam_receipt=Path('/usr/local/lib/wormhole/pam-toolchain.json')
    if pam_receipt.exists():
        tool=json.loads(pam_receipt.read_text())
        library=file_sha256(Path('/lib/x86_64-linux-gnu/security/pam_pkcs11.so'))
        version=command('dpkg-query','-W','-f=${Version}','libpam-pkcs11').stdout.strip()
        checks['pam-repair-installed-identity']=version=='0.6.11-4ubuntu0.1+wormhole4' and library==tool['library_sha256']
        payloads.append({'name':'pam-pkcs11-lab-repair','version':version,'binary_sha256':library,
                         'repair_source_sha256':tool['repair_sha256'],'canonical_signed_binary':False})
    return {'checks': checks, 'packages': packages, 'payloads':payloads,'inventory_kind': 'installed-dpkg','audit_offload':audit_offload,
            'system_trust_inventory':trust_inventory(),
            'kernel': command('uname', '-r').stdout.strip(), 'run_id': (root / 'run-id').read_text().strip()}


if __name__ == '__main__':
    print(json.dumps(observe(), sort_keys=True))
