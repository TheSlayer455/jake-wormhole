"""Bounded one-VM Ubuntu ISO installation experiment, explicitly unqualified.

Run as the established runtime owner on Linux. This is an installation baseline,
not the forthcoming hardened two-OS workflow. Unknown Terraform outcomes retain
the journal and resources for inspection; there is no automatic takeover.
"""
import argparse
import fcntl
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
from uuid import uuid4
import xml.etree.ElementTree as ET

from .admission import CANONICAL_INFRASTRUCTURE_ROOT, collect_observations
from .runs import RunError, atomic_json, now, source_identity, workspace_path
from .vm_admission import VMLease, require
from .vm_inputs import UBUNTU, build_ubuntu, sha256, terraform_config

ROOT = CANONICAL_INFRASTRUCTURE_ROOT.parent
SHARED = ROOT.parent.parent / 'jake-wormhole-vm'
HELPER = 'sha256:4f7f306ecd431b4b48169777966d88c1f09f2139506176a6b85203f5bae69a71'
TF_SHA = '664b66cc0bcd7ed28fd27569719ccaa8a40c230b8be45060ce4d65e2852e1bcc'
NETWORK = '192.0.2.0/24'
ADDRESS = '192.0.2.10'

# Runs inside the existing nonroot, pinned helper; only outgoing guest SSH.
# Secrets arrive through stdin and live in its private tmpfs, never argv/env/state.
HELPER_CODE = r'''
import json,os,pathlib,subprocess,sys,time
c=json.load(sys.stdin)
p=pathlib.Path('/tmp/vm-credentials');p.mkdir(mode=0o700)
key=p/'key';key.write_text(c.pop('private_key'));key.chmod(0o600)
known=p/'known_hosts';known.write_text(c['address']+' '+c['host_key']+'\n');known.chmod(0o600)
opts=['-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
      '-o','IdentitiesOnly=yes','-o','ConnectTimeout=5','-o','ConnectionAttempts=1','-i',str(key)]
deadline=time.monotonic()+c['seconds']
check='test -f /var/lib/wormhole/installation-complete && test "$(id -un)" = lab.service && . /etc/os-release && test "$VERSION_ID" = 22.04 && findmnt -n -o SOURCE / && sudo -n true'
ready=False
while time.monotonic()<deadline:
 try:
  r=subprocess.run(['ssh',*opts,'lab.service@'+c['address'],check],capture_output=True,text=True,timeout=min(12,max(1,deadline-time.monotonic())))
  if r.returncode==0 and r.stdout.strip().startswith('/dev/'):
   ready=True;break
 except subprocess.TimeoutExpired:pass
 time.sleep(min(3,max(0,deadline-time.monotonic())))
if not ready:
 print(json.dumps({'final_authentication':False,'ansible_ready':False,'catalog_started':False,'outcome':'readiness-failed'}));sys.exit(1)
env=dict(os.environ,ANSIBLE_HOST_KEY_CHECKING='True',ANSIBLE_LOCAL_TEMP='/tmp/ansible')
common='-o StrictHostKeyChecking=yes -o UserKnownHostsFile='+str(known)+' -o IdentitiesOnly=yes'
base=['/opt/wormhole/venv/bin/ansible','all','-i',c['address']+',','-u','lab.service','--private-key',str(key),
      '-e','ansible_python_interpreter=/usr/bin/python3','--ssh-common-args',common]
for label,args in [('ansible-readiness',['-m','ping']),('functional',['-b','-m','command','-a','/usr/bin/id -u']),
                   ('inventory',['-m','command','-a','dpkg-query -W -f=${Package}=${Version}\n'])]:
 remaining=deadline-time.monotonic()
 if remaining<=0:sys.exit(1)
 r=subprocess.run(base+args,env=env,capture_output=True,text=True,timeout=min(90,remaining))
 print(json.dumps({'stage':label,'returncode':r.returncode,'output':r.stdout,'diagnostic':r.stderr}),flush=True)
 if r.returncode:sys.exit(1)
print(json.dumps({'final_authentication':True,'ansible_ready':True,'catalog_started':True,'outcome':'baseline-passed',
                  'lab_iso_qualified':False,'production_iso_eligible':False}),flush=True)
'''


def create_qemu_directory(path, group):
    """Only a newly created project directory gains QEMU group traversal."""
    path.mkdir(mode=0o700)
    os.chown(path, 0, group)
    # The private operator umask intentionally strips group bits from mkdir.
    # Set the required traversal bit explicitly on this new directory only.
    path.chmod(0o710)


def preflight(source):
    require(os.geteuid() == 0, 'runtime_owner_required')
    observation = collect_observations(CANONICAL_INFRASTRUCTURE_ROOT)
    require(observation['memory_available_bytes'] >= 13 * 1024**3, 'vm_memory_headroom')
    require(observation['runtime_disk_free_bytes'] >= 80 * 1024**3 + 3 * Path(source).stat().st_size, 'vm_disk_headroom')
    require(observation['cpu_count'] - observation['load1'] >= 3, 'vm_cpu_headroom')
    require(shutil.disk_usage('/').free >= 2 * 1024**3, 'system_disk_headroom')
    with open('/dev/kvm', 'rb', buffering=0) as kvm:
        require(fcntl.ioctl(kvm.fileno(), 0xAE00, 0) == 12, 'kvm_unavailable')
        descriptor = fcntl.ioctl(kvm.fileno(), 0xAE01, 0)
        os.close(descriptor)
    routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all'], timeout=5))
    for route in routes:
        if route.get('dst', 'default') != 'default':
            require(not ipaddress.IPv4Network(route['dst'], strict=False).overlaps(ipaddress.IPv4Network(NETWORK)),
                    'vm_subnet_overlap')
    observation.update(guest_memory_mib=8192, guest_vcpus=2, guest_disk_gib=64,
                       maximum_simultaneous_guests=1, network_mode='isolated-no-dhcp-no-dns-no-nat')
    return observation


def execute(source, terraform):
    os.umask(0o077)
    revision, dirty = source_identity()
    require(not dirty and sha256(terraform) == TF_SHA, 'unverified_execution_inputs')
    identifier = str(uuid4())
    name = 'wormhole-vm-' + identifier.replace('-', '')[:12]
    run = workspace_path(ROOT / 'vm-runs' / identifier, create=True)
    result = {'schema_version': '1.0', 'capability': 'real-iso-installation-baseline', 'run_id': identifier,
        'source_revision': revision, 'outcome': 'running', 'started_at': now(), 'stages': [],
        'lab_iso_qualified': False, 'production_iso_eligible': False, 'cleanup': 'pending'}
    atomic_json(run / 'result.json', result)
    deadline = time.monotonic() + 1800
    console = None
    helper = None
    applied = False
    unknown = False
    def save():
        atomic_json(run / 'result.json', result)
    def command(args, label, *, timeout=120, data=None, check=True):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'vm_absolute_deadline')
        started = time.monotonic()
        with (run / (label + '.log')).open('wb') as log:
            process = subprocess.Popen([str(x) for x in args], stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                process.communicate(data, timeout=min(timeout, remaining))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL);process.wait(timeout=3)
                raise RunError('vm_command_unknown', 'A bounded command timed out; reconcile its resources before retrying.') from None
        result['stages'].append({'stage': label, 'elapsed_seconds': round(time.monotonic()-started, 3), 'returncode': process.returncode})
        save()
        if check and process.returncode:
            raise RunError(label + '_failed', 'The operation failed; inspect its preserved private diagnostic.')
        return process.returncode
    def virsh(*args):
        return subprocess.check_output(['virsh', '-c', 'qemu:///system', *args], stderr=subprocess.DEVNULL, timeout=10).decode()
    with VMLease(CANONICAL_INFRASTRUCTURE_ROOT, identifier, revision) as lease:
        try:
            atomic_json(run / 'preflight.json', preflight(source))
            for query in ('list', 'net-list', 'pool-list'):
                require(name not in virsh(query, '--all', '--name').split(), 'vm_resource_conflict')
            group = grp.getgrnam('libvirt-qemu').gr_gid
            if not SHARED.exists():
                create_qemu_directory(SHARED, group)
            require(not SHARED.is_symlink() and SHARED.stat().st_uid == 0 and SHARED.stat().st_gid == group and
                    SHARED.stat().st_mode & 0o777 == 0o710, 'vm_shared_storage_ownership')
            share = SHARED / identifier
            create_qemu_directory(share, group)
            pool = share / 'disk'
            candidate, seed = share / 'candidate.iso', share / 'seed.iso'
            command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'wormhole-lab', '-f', run / 'ssh-key'], 'key-generation')
            public = (run / 'ssh-key.pub').read_text().strip()
            mac = '52:54:00:' + ':'.join(identifier.replace('-', '')[n:n+2] for n in (0, 2, 4))
            for kind, identity in [('installer_iso', str(candidate)), ('seed_iso', str(seed))]:
                lease.intent(kind, identity)
            started = time.monotonic()
            manifest = build_ubuntu(source, candidate, run / 'inputs', identifier, public, ADDRESS + '/24', mac)
            result['stages'].append({'stage': 'candidate-build', 'elapsed_seconds': round(time.monotonic()-started, 3), 'returncode': 0})
            result['build'] = manifest;save()
            for path in (candidate, seed):
                os.chown(path, 0, group);path.chmod(0o640)
            tfdir = run / 'terraform';tfdir.mkdir(mode=0o700)
            atomic_json(tfdir / 'main.tf.json', terraform_config(name, pool, candidate, seed, NETWORK, mac))
            tf = [terraform, '-chdir=' + str(tfdir)]
            command([*tf, 'init', '-input=false'], 'terraform-init')
            command([*tf, 'validate', '-no-color'], 'terraform-validate')
            command([*tf, 'plan', '-input=false', '-out=run.tfplan', '-no-color'], 'terraform-plan')
            require(sha256(candidate) == manifest['candidate_sha256'] and sha256(seed) == manifest['seed_sha256'], 'attached_media_changed')
            for kind, identity in [('domain', name), ('network', name), ('pool', name), ('disk', str(pool / (name + '.qcow2')))]:
                lease.intent(kind, identity)
            unknown = True
            command([*tf, 'apply', '-input=false', '-no-color', 'run.tfplan'], 'terraform-apply', timeout=180)
            applied = True;unknown = False
            xml = virsh('dumpxml', name)
            (run / 'domain.xml').write_text(xml)
            dom = ET.fromstring(xml)
            require(dom.attrib.get('type') == 'kvm' and dom.findtext('description') == 'jake-wormhole libvirt-iso ' + name and
                    dom.find('os/kernel') is None, 'vm_runtime_identity')
            cds = {x.find('source').get('file') for x in dom.findall('devices/disk') if x.get('device') == 'cdrom'}
            require(cds == {str(candidate), str(seed)}, 'attached_media_mismatch')
            require(sha256(candidate) == manifest['candidate_sha256'] and sha256(seed) == manifest['seed_sha256'], 'attached_media_changed')
            network_xml = ET.fromstring(virsh('net-dumpxml', name))
            require(network_xml.find('forward') is None and network_xml.find('ip/dhcp') is None,
                    'unexpected_network_forwarding')
            command(['virsh', '-c', 'qemu:///system', 'start', name], 'firmware-boot')
            console_log = (run / 'console.log').open('wb')
            console = subprocess.Popen(['virsh', '-c', 'qemu:///system', 'console', name, '--force'],
                stdin=subprocess.PIPE, stdout=console_log, stderr=subprocess.STDOUT, start_new_session=True)
            console_log.close()
            host_key = None
            installation_start = time.monotonic()
            while time.monotonic() < deadline - 180:
                path = run / 'console.log'
                require(path.stat().st_size <= 16 * 1024**2, 'installer_diagnostic_limit')
                text = path.read_text(errors='replace')
                require('WORMHOLE_INSTALLATION_FAILED' not in text, 'installation_failed')
                found = re.search(r'WORMHOLE_FINAL_HOST_KEY_BEGIN\s+(ssh-ed25519 [A-Za-z0-9+/=]+)[^\n]*\s+WORMHOLE_FINAL_HOST_KEY_END', text)
                if found:
                    host_key = found[1];break
                require(console.poll() is None, 'installer_console_lost')
                time.sleep(3)
            require(host_key is not None, 'installation_deadline')
            result['stages'].append({'stage': 'installation-to-host-key', 'elapsed_seconds': round(time.monotonic()-installation_start, 3), 'returncode': 0});save()
            args = ['docker', 'create', '-i', '--name', name + '-controller', '--label', 'application=jake-wormhole',
                '--label', 'vm-run=' + identifier, '--network', 'host', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges:true', '--user', '10001:10001', '--memory', '512m',
                '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '128', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=2',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001',
                '--entrypoint', '/opt/wormhole/venv/bin/python', HELPER, '-c', HELPER_CODE]
            # Name intent is durable before create; its exact returned ID is then bound by label verification.
            helper = name + '-controller'
            lease.intent('controller_container', helper)
            unknown = True
            command(args, 'controller-create')
            unknown = False
            payload = json.dumps({'address': ADDRESS, 'host_key': host_key, 'private_key': (run / 'ssh-key').read_text(),
                                  'seconds': max(1, int(deadline-time.monotonic()-180))}).encode()
            command(['docker', 'start', '-ai', helper], 'ssh-ansible-inventory', timeout=max(1, deadline-time.monotonic()-180), data=payload)
            result.update(outcome='baseline-passed', installed=True, final_authentication=True, ansible_ready=True)
        except Exception as error:
            result.update(outcome='unknown' if unknown else 'failed', error_category=getattr(error, 'code', type(error).__name__))
        finally:
            if console is not None:
                console.terminate()
                try:console.wait(timeout=5)
                except subprocess.TimeoutExpired:console.kill();console.wait(timeout=5)
            try:
                # Cleanup has its own reserved bounded margin; it cannot change the primary outcome.
                deadline = max(deadline, time.monotonic() + 120)
                if helper is not None:
                    inspected = subprocess.run(['docker', 'inspect', helper], capture_output=True, timeout=10)
                    if inspected.returncode == 0:
                        item = json.loads(inspected.stdout)[0]
                        require(item['Config']['Labels'].get('vm-run') == identifier and item['Config']['Image'] == HELPER,
                                'controller_ownership_mismatch')
                        command(['docker', 'rm', '-f', item['Id']], 'controller-cleanup', timeout=20)
                    require(not unknown, 'controller_state_unknown')
                    lease.reconciled('controller_container', helper)
                if applied and not unknown:
                    state = json.loads((tfdir / 'terraform.tfstate').read_text())
                    require({(x['type'], x['name']) for x in state['resources']} == {
                        ('libvirt_pool', 'run'), ('libvirt_network', 'run'), ('libvirt_domain', 'run'), ('libvirt_volume', 'disk')}, 'terraform_ownership_mismatch')
                    require(ET.fromstring(virsh('dumpxml', name)).findtext('description') == 'jake-wormhole libvirt-iso ' + name,
                            'domain_ownership_mismatch')
                    require(ET.fromstring(virsh('pool-dumpxml', name)).findtext('target/path') == str(pool), 'pool_ownership_mismatch')
                    command([*tf, 'destroy', '-auto-approve', '-input=false', '-no-color'], 'terraform-cleanup', timeout=90)
                    for query in ('list', 'net-list', 'pool-list'):
                        require(name not in virsh(query, '--all', '--name').split(), 'vm_cleanup_incomplete')
                    require(not (pool / (name + '.qcow2')).exists(), 'disk_cleanup_incomplete')
                    for kind, identity in [('domain', name), ('network', name), ('pool', name), ('disk', str(pool / (name + '.qcow2')))]:
                        lease.reconciled(kind, identity)
                require(not unknown, 'terraform_state_unknown')
                for item in list(lease.record['resources']):
                    if item['kind'] in {'installer_iso', 'seed_iso'}:
                        lease.reconciled(item['kind'], item['identity'], retained_input=Path(item['identity']).is_file())
                lease.finish()
                result['cleanup'] = 'verified-absent-inputs-retained'
            except Exception as error:
                result['cleanup'] = 'unreconciled'
                result['cleanup_error'] = getattr(error, 'code', type(error).__name__)
            result['finished_at'] = now();save()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--terraform', required=True)
    options = parser.parse_args()
    value = execute(options.source, options.terraform)
    print(json.dumps(value, indent=2))
    return 0 if value['outcome'] == 'baseline-passed' and value['cleanup'] != 'unreconciled' else 1


if __name__ == '__main__':
    raise SystemExit(main())
