"""Bounded one-VM Ubuntu/RHEL ISO installation experiment, explicitly unqualified.

Run as the established runtime owner on Linux. This is an installation baseline,
not the forthcoming hardened two-OS workflow. Unknown Terraform outcomes retain
the journal and resources for inspection; there is no automatic takeover.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import pwd
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
from .runs import SOURCE_ROOT, RunError, atomic_json, now, read_json, run_id, source_identity, workspace_path
from .vm_admission import VMLease, require
from .vm_inputs import UBUNTU, build_ubuntu, sha256, terraform_config

ROOT = CANONICAL_INFRASTRUCTURE_ROOT.parent
SHARED = ROOT.parent.parent / 'jake-wormhole-vm'
HELPER = 'sha256:4f7f306ecd431b4b48169777966d88c1f09f2139506176a6b85203f5bae69a71'
TF_SHA = '664b66cc0bcd7ed28fd27569719ccaa8a40c230b8be45060ce4d65e2852e1bcc'
NETWORK = '192.0.2.0/24'
ADDRESS = '192.0.2.10'


def process_identity(pid):
    try:
        raw=Path('/proc/'+str(pid)+'/stat').read_text()
        return {'pid':pid,'start_ticks':raw.rsplit(') ',1)[1].split()[19]}
    except FileNotFoundError:
        return None


def status(identifier):
    """Read the existing durable record; process liveness never establishes progress."""
    result=read_json(workspace_path(ROOT/'vm-runs'/run_id(identifier))/'result.json')
    supervisor=result.get('supervisor')
    alive=supervisor is not None and process_identity(supervisor['pid'])==supervisor
    age=max(0,(datetime.now(timezone.utc)-datetime.fromisoformat(result['last_progress_at'].replace('Z','+00:00'))).total_seconds())
    state=('running-with-recent-progress' if age<=60 else 'running-without-recent-progress') if alive else 'unknown-supervisor-stopped'
    if result['outcome']!='running':state='terminal-'+result['outcome']
    return {**{k:result[k] for k in ('run_id','source_revision','provisioner','phase','last_progress_at',
            'launch_acknowledged_at','progress','controller_stage','checks','first_failure','outcome','cleanup') if k in result},
            'execution_state':state,'supervisor_alive':alive,'progress_age_seconds':round(age,1)}


def controller_checks(rows, *, assessment=False):
    stages=['final-authentication','final-system-readiness','ansible-readiness','functional','inventory']
    if assessment:stages.append('assessment-archive')
    latest={r['stage']:r for r in rows if r.get('stage') in stages}
    return {stage:('pass' if latest[stage].get('returncode')==0 else 'fail') if stage in latest else 'blocked'
            for stage in stages}

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
release='rhel' if c.get('distribution')=='rhel10' else 'ubuntu'
version='10.0' if release=='rhel' else '22.04'
check='test "$(id -un)" = lab.service || exit 41; test -f /var/lib/wormhole/installation-complete || exit 42; . /etc/os-release; test "$ID" = '+release+' && test "$VERSION_ID" = '+version+' || exit 43; sudo -n true || exit 44; findmnt -n -o SOURCE /'
if release=='rhel':check+='; test "$(getenforce)" = Enforcing || exit 45'
if c.get('scenario')=='marker-inaccessible':
 r=subprocess.run(['ssh',*opts,'lab.service@'+c['address'],'sudo -n chmod 0700 /var/lib/wormhole'],capture_output=True,text=True,timeout=15)
 print(json.dumps({'stage':'controlled-readiness-fault','returncode':r.returncode,'diagnostic_intervention':True}),flush=True)
 if r.returncode:sys.exit(1)
ready=False
category='ssh-unavailable'
while time.monotonic()<deadline:
 try:
  r=subprocess.run(['ssh',*opts,'lab.service@'+c['address'],check],capture_output=True,text=True,timeout=min(12,max(1,deadline-time.monotonic())))
  if r.returncode==0 and r.stdout.strip().startswith('/dev/'):
   ready=True;break
  if r.returncode in {41,42,43,44,45}:
   category={41:'final-identity-mismatch',42:'completion-marker-inaccessible',43:'installed-os-mismatch',44:'privilege-escalation-failed',45:'selinux-not-enforcing'}[r.returncode]
   print(json.dumps({'stage':'final-authentication','returncode':0}),flush=True)
   print(json.dumps({'stage':'final-system-readiness','returncode':r.returncode,'category':category}),flush=True)
   break
  print(json.dumps({'stage':'final-authentication','returncode':r.returncode or 1,'ready':False}),flush=True)
 except subprocess.TimeoutExpired:pass
 time.sleep(min(3,max(0,deadline-time.monotonic())))
if not ready:
 print(json.dumps({'final_authentication':category!='ssh-unavailable','ansible_ready':False,'catalog_started':False,'outcome':'readiness-failed','category':category}));sys.exit(1)
print(json.dumps({'stage':'final-authentication','returncode':0,'ready':True}),flush=True)
print(json.dumps({'stage':'final-system-readiness','returncode':0}),flush=True)
env=dict(os.environ,HOME='/tmp',ANSIBLE_HOME='/tmp/.ansible',ANSIBLE_HOST_KEY_CHECKING='True',ANSIBLE_LOCAL_TEMP='/tmp/ansible')
common='-o StrictHostKeyChecking=yes -o UserKnownHostsFile='+str(known)+' -o IdentitiesOnly=yes'
base=['/opt/wormhole/venv/bin/ansible','all','-i',c['address']+',','-u','lab.service','--private-key',str(key),
      '-e','ansible_python_interpreter=/usr/bin/python3','--ssh-common-args='+common]
inventory="rpm -qa --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\\n'" if release=='rhel' else "dpkg-query -W -f='${Package}=${Version}\\n'"
for label,args in [('ansible-readiness',['-m','ping']),('functional',['-b','-m','command','-a','/usr/bin/id -u']),
                   ('inventory',['-m','command','-a',inventory])]:
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


def preflight(source, *, distribution='ubuntu', provisioner='terraform'):
    require(os.geteuid() == 0, 'runtime_owner_required')
    required=['virsh','qemu-system-x86_64','qemu-img','xorriso','dnsmasq','script','ssh-keygen','docker']
    if provisioner=='terraform':required.append('xsltproc')
    require(all(shutil.which(x) for x in required),
            'missing_vm_tool')
    observation = collect_observations(CANONICAL_INFRASTRUCTURE_ROOT)
    require(observation['memory_available_bytes'] >= 13 * 1024**3, 'vm_memory_headroom')
    # RHEL streams one output and extracts only boot files; Ubuntu retains its
    # existing three-media allowance for extraction/remastering paths.
    media_copies=1 if distribution=='rhel10' else 3
    disk_gib=32 if distribution=='rhel10' else 64
    require(observation['runtime_disk_free_bytes'] >= (disk_gib+16) * 1024**3 + media_copies * Path(source).stat().st_size, 'vm_disk_headroom')
    if distribution=='rhel10':
        flags=Path('/proc/cpuinfo').read_text().split()
        require(all(flag in flags for flag in ('avx2','bmi1','bmi2','f16c','fma','movbe','xsave')), 'rhel10_cpu_v3_required')
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
    observation.update(guest_memory_mib=8192, guest_vcpus=2, guest_disk_gib=disk_gib,
                       maximum_simultaneous_guests=1, network_mode='isolated-no-dhcp-no-dns-no-nat')
    return observation


def execute(source, terraform=None, *, reuse_run=None, ubuntu_mode=None, dependency_store=None, sandbox=False, distribution='ubuntu', provisioner='terraform', scenario='healthy'):
    os.umask(0o077)
    revision, dirty = source_identity()
    require(provisioner in {'terraform','native'},'invalid_vm_provisioner')
    require(not dirty and (provisioner=='native' or (terraform is not None and sha256(terraform)==TF_SHA)), 'unverified_execution_inputs')
    require(scenario in {'healthy','marker-inaccessible'} and (scenario=='healthy' or (distribution=='rhel10' and ubuntu_mode is None)), 'invalid_vm_scenario')
    require(provisioner=='terraform' or (distribution=='rhel10' and ubuntu_mode is None), 'native_rhel_comparison_only')
    require(ubuntu_mode in {None, 'stock-audit', 'hardened'}, 'ubuntu_mode_invalid')
    require(not sandbox or ubuntu_mode=='hardened','sandbox_requires_hardened_ubuntu')
    require(distribution in {'ubuntu','rhel10'} and (distribution=='ubuntu' or (ubuntu_mode is None and not sandbox)), 'vm_distribution_invalid')
    disk_bytes=(32 if distribution=='rhel10' else 64)*1024**3
    identifier = str(uuid4())
    name = 'wormhole-vm-' + identifier.replace('-', '')[:12]
    run = workspace_path(ROOT / 'vm-runs' / identifier, create=True)
    result = {'schema_version': '1.0', 'capability': 'real-iso-installation-baseline', 'run_id': identifier,
        'source_revision': revision, 'distribution':distribution, 'provisioner':provisioner,'scenario':scenario,
        'outcome': 'running', 'started_at': now(), 'stages': [],
        'phase': 'preflight', 'last_progress_at': now(), 'network_isolated':bool(ubuntu_mode or distribution=='rhel10'),
        'supervisor': process_identity(os.getpid()),
        'lab_iso_qualified': False, 'production_iso_eligible': False, 'cleanup': 'pending'}
    if not ubuntu_mode:result['checks']={k:'pending' for k in controller_checks([],assessment=distribution=='rhel10')}
    atomic_json(run / 'result.json', result)
    deadline = time.monotonic() + 1800
    console = None
    helper = None
    unlock = None
    support = None
    support_process = None
    filter_name = None
    applied = False
    unknown = False
    def save():
        atomic_json(run / 'result.json', result)
    def command(args, label, *, timeout=120, data=None, check=True, observe=None):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'vm_absolute_deadline')
        started = time.monotonic()
        started_at = now()
        result.update(phase=label, last_progress_at=now());save()
        with (run / (label + '.log')).open('wb') as log:
            process = subprocess.Popen([str(x) for x in args], stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            result['active_command'] = process_identity(process.pid)
            save()
            try:
                end=time.monotonic()+min(timeout,remaining)
                while True:
                    try:
                        process.communicate(data,timeout=max(.01,min(3,end-time.monotonic())))
                        break
                    except subprocess.TimeoutExpired:
                        data=None
                        if observe is not None:observe()
                        if time.monotonic()>=end:raise
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL);process.wait(timeout=3)
                raise RunError('vm_command_unknown', 'A bounded command timed out; reconcile its resources before retrying.') from None
        result.pop('active_command',None)
        result['stages'].append({'stage': label,'started_at':started_at,'finished_at':now(),
                                'elapsed_seconds': round(time.monotonic()-started, 3), 'returncode': process.returncode})
        result['last_progress_at'] = now()
        save()
        if check and process.returncode:
            raise RunError(label + '_failed', 'The operation failed; inspect its preserved private diagnostic.')
        return process.returncode
    def virsh(*args):
        return subprocess.check_output(['virsh', '-c', 'qemu:///system', *args], stderr=subprocess.DEVNULL, timeout=10).decode()
    with VMLease(CANONICAL_INFRASTRUCTURE_ROOT, identifier, revision) as lease:
        result['launch_acknowledged_at']=now();save()
        print(json.dumps({'event':'launch-acknowledged','run_id':identifier,'source_revision':revision,
                          'provisioner':provisioner,'at':result['launch_acknowledged_at']}),flush=True)
        try:
            preflight_start=time.monotonic();preflight_at=now()
            from .storage import Store, lifecycle, admission as storage_admission
            result['storage_preflight_cleanup'] = lifecycle(lease)
            usage = Store().status()
            incoming=0
            if reuse_run is None:
                incoming=Path(source).stat().st_size+16*1024**2
                if dependency_store is not None:
                    incoming+=sum(f['bytes'] for f in read_json(Path(dependency_store)/'bundle/manifest.json')['files'])
            # Source bytes already reside on disk; reserve extraction + two ISO
            # outputs, the full guest disk, and a GiB for evidence/support data.
            atomic_json(run/'storage-admission.json', storage_admission(ROOT,
                disk_bytes+1024**3 + (1 if distribution=='rhel10' else 3)*Path(source).stat().st_size,
                managed_bytes=usage['total_allocated_bytes'],
                candidate_bytes=result['storage_preflight_cleanup']['candidate_budget_allocated_bytes']+incoming))
            atomic_json(run / 'preflight.json', preflight(source,distribution=distribution,provisioner=provisioner))
            if sandbox:
                from .ubuntu_sandbox import MEMORY
                observation=read_json(run/'preflight.json')
                require(observation['memory_available_bytes']>=13*1024**3+MEMORY,'sandbox_memory_headroom')
                require(observation['cpu_count']-observation['load1']>=3.5,'sandbox_cpu_headroom')
                require(observation['runtime_disk_free_bytes']>=80*1024**3+3*Path(source).stat().st_size+32*1024**2,'sandbox_disk_headroom')
                result['support_budget']={'memory_bytes':MEMORY,'cpus':.5,'disk_evidence_limit_bytes':32*1024**2}
            result['stages'].append({'stage':'preflight','started_at':preflight_at,'finished_at':now(),
                                    'elapsed_seconds':round(time.monotonic()-preflight_start,3),'returncode':0});save()
            for query in ('list', 'net-list', 'pool-list'):
                require(name not in virsh(query, '--all', '--name').split(), 'vm_resource_conflict')
            qemu = pwd.getpwnam('libvirt-qemu')
            group = qemu.pw_gid
            if not SHARED.exists():
                create_qemu_directory(SHARED, group)
            require(not SHARED.is_symlink() and SHARED.stat().st_uid == 0 and SHARED.stat().st_gid == group and
                    SHARED.stat().st_mode & 0o777 == 0o710, 'vm_shared_storage_ownership')
            share = SHARED / identifier
            create_qemu_directory(share, group)
            pool = share / 'disk'
            candidate, seed = share / 'candidate.iso', share / 'seed.iso'
            key_args = ['-t', 'rsa', '-b', '3072'] if ubuntu_mode else ['-t', 'ed25519']
            command(['ssh-keygen', '-q', *key_args, '-N', '', '-C', 'wormhole-lab', '-f', run / 'ssh-key'], 'key-generation')
            public = (run / 'ssh-key.pub').read_text().strip()
            mac = '52:54:00:' + ':'.join(identifier.replace('-', '')[n:n+2] for n in (0, 2, 4))
            for kind, identity in [('installer_iso', str(candidate)), ('seed_iso', str(seed))]:
                lease.intent(kind, identity)
            atomic_json(run/'storage-build-intent.json',{'schema_version':'1.0','run_id':identifier,
                'source_revision':revision,'candidate':str(candidate),'seed':str(seed)})
            started = time.monotonic()
            build_at = now()
            reuse = None
            if reuse_run is not None:
                origin = workspace_path(ROOT / 'vm-runs' / run_id(reuse_run))
                original_result = read_json(origin / 'result.json')
                original_manifest = read_json(origin / 'inputs/build-manifest.json')
                require(original_result.get('build') == original_manifest and original_result.get('cleanup') ==
                        'verified-absent-inputs-retained', 'candidate_origin_unreconciled')
                reuse = (Store().resolve(reuse_run), original_manifest)
                result['candidate_origin_run'] = reuse_run
            result.update(phase='candidate-build',last_progress_at=now());save()
            if ubuntu_mode:
                import secrets
                from .ubuntu_inputs import build as build_assessed
                password = secrets.token_urlsafe(32) + 'aA1!'
                (run / 'sudo-password').write_text(password)
                hashed = subprocess.run(['openssl', 'passwd', '-6', '-stdin'], input=password + '\n',
                                        capture_output=True, text=True, check=True, timeout=10).stdout.strip()
                boot_hash=None
                if ubuntu_mode=='hardened':
                    from .ubuntu_inputs import grub_password_hash
                    boot_password=secrets.token_urlsafe(32)+'bB2!'
                    (run/'boot-password').write_text(boot_password)
                    boot_hash=grub_password_hash(boot_password,secrets.token_bytes(64))
                if sandbox:
                    from .ubuntu_encryption import ConsoleUnlock
                    from .ubuntu_sandbox import certificates
                    certificates(run)
                    unlock_file=run/'unlock-secret'
                    unlock_file.write_text(secrets.token_urlsafe(48));unlock_file.chmod(0o600)
                    unlock=ConsoleUnlock(unlock_file,probes=True)
                manifest = build_assessed(source, candidate, run / 'inputs', identifier, public, ADDRESS + '/24', mac,
                    store=dependency_store, mode=ubuntu_mode, password_hash=hashed, boot_hash=boot_hash,reuse=reuse,sandbox=sandbox)
            elif distribution=='rhel10':
                import secrets
                from .rhel_inputs import build_rhel
                password=secrets.token_urlsafe(32)+'aA1!'
                (run/'sudo-password').write_text(password)
                hashed=subprocess.run(['openssl','passwd','-6','-stdin'],input=password+'\n',capture_output=True,text=True,check=True,timeout=10).stdout.strip()
                manifest=build_rhel(source,candidate,run/'inputs',identifier,public,ADDRESS+'/24',mac,password_hash=hashed,reuse=reuse)
            else:
                manifest = build_ubuntu(source, candidate, run / 'inputs', identifier, public, ADDRESS + '/24', mac, reuse=reuse)
            result['stages'].append({'stage': 'candidate-build','started_at':build_at,'finished_at':now(),
                                    'elapsed_seconds': round(time.monotonic()-started, 3), 'returncode': 0})
            result['build'] = manifest;save()
            for path in (candidate, seed):
                os.chown(path, 0, group);path.chmod(0o640)
            if ubuntu_mode or distribution=='rhel10':
                from .ubuntu_sandbox import network_filter,attach_filter
                filter_name=name+'-isolation'
                filter_file=run/'network-filter.xml';filter_file.write_text(network_filter(filter_name))
                lease.intent('network_filter',filter_name)
                command(['virsh','-c','qemu:///system','nwfilter-define',str(filter_file)],'network-filter-define')
            if provisioner=='terraform':
                tfdir=run/'terraform';tfdir.mkdir(mode=0o700)
                shutil.copyfile(SOURCE_ROOT/'provisioning/libvirt/.terraform.lock.hcl',tfdir/'.terraform.lock.hcl')
                configuration=terraform_config(name,pool,candidate,seed,NETWORK,mac,qemu.pw_uid,group,disk_bytes=disk_bytes)
                if filter_name:configuration=attach_filter(configuration,filter_name)
                atomic_json(tfdir/'main.tf.json',configuration)
                result['terraform_configuration_sha256']=sha256(tfdir/'main.tf.json');save()
                tf=[terraform,'-chdir='+str(tfdir)]
                command([*tf,'init','-input=false','-lockfile=readonly'],'terraform-init')
                command([*tf,'validate','-no-color'],'terraform-validate')
                command([*tf,'plan','-input=false','-out=run.tfplan','-no-color'],'terraform-plan')
            else:
                from . import vm_native
                configuration=vm_native.configuration(name,pool,candidate,seed,NETWORK,mac,qemu.pw_uid,group,
                                                       disk_bytes=disk_bytes,filter_name=filter_name)
                atomic_json(run/'native-config.json',configuration)
                result['native_configuration_sha256']=sha256(run/'native-config.json');save()
            require(sha256(candidate) == manifest['candidate_sha256'] and sha256(seed) == manifest['seed_sha256'], 'attached_media_changed')
            for kind, identity in [('domain', name), ('network', name), ('pool', name), ('disk', str(pool / (name + '.qcow2')))]:
                lease.intent(kind, identity)
            unknown = True
            if provisioner=='terraform':
                command([*tf,'apply','-input=false','-no-color','run.tfplan'],'terraform-apply',timeout=180)
            else:vm_native.create(run,configuration,command)
            applied = True;unknown = False
            xml = virsh('dumpxml', name)
            (run / 'domain.xml').write_text(xml)
            dom = ET.fromstring(xml)
            require(dom.attrib.get('type') == 'kvm' and dom.findtext('description') == 'jake-wormhole libvirt-iso ' + name and
                    dom.find('os/kernel') is None, 'vm_runtime_identity')
            disks = [x for x in dom.findall('devices/disk') if x.get('device') == 'disk']
            require(len(disks) == 1 and disks[0].find('driver').get('type') == 'qcow2' and
                    disks[0].find('source').get('file') == str(pool / (name + '.qcow2')), 'vm_disk_format_mismatch')
            info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(pool / (name + '.qcow2'))], timeout=5))
            atomic_json(run/'disk-observation.json',info)
            require(info['format'] == 'qcow2' and info['virtual-size'] == disk_bytes and
                    not info.get('backing-filename'), 'vm_disk_capacity_mismatch')
            cds = {x.find('source').get('file') for x in dom.findall('devices/disk') if x.get('device') == 'cdrom'}
            require(cds == {str(candidate), str(seed)}, 'attached_media_mismatch')
            require(sha256(candidate) == manifest['candidate_sha256'] and sha256(seed) == manifest['seed_sha256'], 'attached_media_changed')
            network_xml = ET.fromstring(virsh('net-dumpxml', name))
            (run/'network.xml').write_text(ET.tostring(network_xml,encoding='unicode'))
            require(network_xml.find('forward') is None and network_xml.find('ip/dhcp') is None,
                    'unexpected_network_forwarding')
            if sandbox:
                from .ubuntu_sandbox import start,health
                support=name+'-services'
                support,support_process=start(run,name,identifier,HELPER,lease,command)
                result['support_health']=health(run)
            if filter_name is not None:
                require(dom.find('devices/interface/filterref').get('filter')==filter_name,'sandbox_filter_not_attached')
            command(['virsh', '-c', 'qemu:///system', 'start', name], 'firmware-boot')
            console_log = (run / 'console.log').open('wb')
            # virsh console requires a controlling terminal, even for private
            # unattended capture. util-linux script provides that PTY; the
            # generated name contains only validated alphanumeric/hyphen bytes.
            console = subprocess.Popen(['script', '--quiet', '--return', '--flush', '--echo', 'never', '--command',
                'virsh -c qemu:///system console ' + name + ' --force', '/dev/null'],
                stdin=subprocess.PIPE, stdout=console_log, stderr=subprocess.STDOUT, start_new_session=True)
            console_log.close()
            result['console_process']=process_identity(console.pid);save()
            host_key = None
            installation_start = time.monotonic()
            observed_phases = []
            while time.monotonic() < deadline - 180:
                path = run / 'console.log'
                require(path.stat().st_size <= 16 * 1024**2, 'installer_diagnostic_limit')
                text = path.read_text(errors='replace')
                packages=re.findall(r'Installing [^\r\n]+\((\d+)/(\d+)\)',text)
                if packages:
                    completed,total=map(int,packages[-1])
                    progress={'stage':'package-installation','completed':completed,'expected':total}
                    if result.get('progress')!=progress:
                        result.update(progress=progress,last_progress_at=now());save()
                if unlock is not None:
                    unlock.check_capture(path)
                    if unlock.observe(text,console.stdin):
                        result['unlock_events']=unlock.events
                        result.update(phase='waiting-for-unlock',last_progress_at=now());save()
                progress = re.findall(r'WORMHOLE_HARDENING_PROGRESS completed=(\d+) rule=([a-z0-9_-]+)', text)
                if progress and result.get('hardening_operations_completed') != int(progress[-1][0]):
                    result.update(hardening_operations_completed=int(progress[-1][0]),
                                  last_hardening_operation=progress[-1][1],last_progress_at=now());save()
                phase = ('required-reboot' if 'WORMHOLE_REQUIRED_REBOOT' in text else
                         'hardening-complete' if 'WORMHOLE_HARDENING_COMPLETE' in text else
                         'hardening' if 'WORMHOLE_HARDENING_STARTED' in text else
                         'installed-finalization' if 'WORMHOLE_FINALIZATION_STARTED' in text else
                         'installing' if any(marker in text for marker in ('subiquity/Install/install',
                            'Starting automated install.','WORMHOLE_INSTALLATION_STARTED')) else 'firmware-and-installer-boot')
                if result['phase'] != phase:
                    if observed_phases:
                        observed_phases[-1]['elapsed_seconds'] = round(time.monotonic() - phase_start, 3)
                    phase_start = time.monotonic()
                    observed_phases.append({'phase':phase, 'observed_at':now()})
                    result['installation_observations'] = observed_phases
                    result.update(phase=phase,last_progress_at=now());save()
                require('WORMHOLE_INSTALLATION_FAILED' not in text, 'installation_failed')
                require('WORMHOLE_FINALIZATION_FAILED' not in text, 'finalization_failed')
                if 'WORMHOLE_REQUIRED_REBOOT' in text:
                    after_reboot=text.rsplit('WORMHOLE_REQUIRED_REBOOT',1)[1]
                    require('Enter username:' not in after_reboot and 'Enter password:' not in after_reboot,
                            'bootloader_unattended_boot_blocked')
                    require(time.monotonic()-phase_start < 180,'required_reboot_progress_deadline')
                host_type = 'ssh-rsa' if ubuntu_mode else 'ssh-ed25519'
                found = re.search(r'WORMHOLE_FINAL_HOST_KEY_BEGIN\s+(' + host_type + r' [A-Za-z0-9+/=]+)[^\n]*\s+WORMHOLE_FINAL_HOST_KEY_END', text)
                if found:
                    if observed_phases:
                        observed_phases[-1]['elapsed_seconds'] = round(time.monotonic()-phase_start,3)
                    host_key = found[1];break
                require(console.poll() is None, 'installer_console_lost')
                time.sleep(3)
            require(host_key is not None, 'installation_deadline')
            result['stages'].append({'stage': 'installation-to-host-key', 'elapsed_seconds': round(time.monotonic()-installation_start, 3), 'returncode': 0});save()
            if sandbox:
                # Graceful power-off followed by logical, read-only qemu-img
                # inspection. No host block mapping, mount or disk mutation.
                cold_started=time.monotonic()
                command(['virsh','-c','qemu:///system','shutdown',name],'encrypted-poweroff',timeout=10)
                stop_by=min(deadline-180,time.monotonic()+60)
                while time.monotonic()<stop_by and virsh('domstate',name).strip()!='shut off':time.sleep(1)
                require(virsh('domstate',name).strip()=='shut off','guest_poweroff_deadline')
                try:os.killpg(console.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:console.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(console.pid,signal.SIGKILL);console.wait(timeout=5)
                from .ubuntu_encryption import offline_inspect
                result['offline_encryption']=offline_inspect(pool/(name+'.qcow2'),run,run/'unlock-secret');save()
                offset=(run/'console.log').stat().st_size
                command(['virsh','-c','qemu:///system','start',name],'encrypted-cold-start',timeout=10)
                with (run/'console.log').open('ab') as log:
                    console=subprocess.Popen(['script','--quiet','--return','--flush','--echo','never','--command',
                        'virsh -c qemu:///system console '+name+' --force','/dev/null'],stdin=subprocess.PIPE,
                        stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                result['console_process']=process_identity(console.pid);save()
                cold_by=min(deadline-180,time.monotonic()+180)
                ready=False
                while time.monotonic()<cold_by:
                    path=run/'console.log';text=path.read_text(errors='replace');unlock.check_capture(path)
                    if unlock.observe(text,console.stdin):result['unlock_events']=unlock.events;save()
                    current=path.read_bytes()[offset:].decode(errors='replace')
                    found=re.search(r'WORMHOLE_FINAL_HOST_KEY_BEGIN\s+(ssh-rsa [A-Za-z0-9+/=]+)[^\n]*\s+WORMHOLE_FINAL_HOST_KEY_END',current)
                    if found:
                        require(found[1]==host_key,'cold_start_host_identity_changed');ready=True;break
                    require(console.poll() is None,'cold_start_console_lost');time.sleep(2)
                require(ready,'cold_start_unlock_deadline')
                result['cold_start_verified']=True
                result['stages'].append({'stage':'offline-inspection-and-cold-start','elapsed_seconds':round(time.monotonic()-cold_started,3),'returncode':0});save()
            helper_code = HELPER_CODE
            if ubuntu_mode:
                from .ubuntu_runtime import HELPER_CODE as helper_code
            elif distribution=='rhel10':
                from .rhel_assessment import RHEL_AUDIT_CODE
                helper_code+=RHEL_AUDIT_CODE
            args = ['docker', 'create', '-i', '--name', name + '-controller', '--label', 'application=jake-wormhole',
                '--label', 'vm-run=' + identifier, '--network', 'host', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges:true', '--user', '10001:10001', '--memory', '512m',
                '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '128', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=2',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001',
                '--entrypoint', '/opt/wormhole/venv/bin/python', HELPER, '-c', helper_code]
            # Name intent is durable before create; its exact returned ID is then bound by label verification.
            helper = name + '-controller'
            lease.intent('controller_container', helper)
            unknown = True
            command(args, 'controller-create')
            unknown = False
            payload_data = {'address': ADDRESS, 'host_key': host_key, 'private_key': (run / 'ssh-key').read_text(),
                            'distribution':distribution,'scenario':scenario,
                            'seconds': max(1, min(900 if ubuntu_mode else 300, int(deadline-time.monotonic()-180)))}
            if ubuntu_mode:payload_data['become_password'] = password
            if sandbox:payload_data['inspection_secrets']=[(run/'unlock-secret').read_text().strip(),password,(run/'boot-password').read_text().strip()]
            if sandbox:
                payload_data['pkcs11_probe']={name:(run/'support-private'/name).read_text() for name in
                    ('token.crt','token.key','token-revoked.crt','token-revoked.key','active.crt','active.key')}
            payload = json.dumps(payload_data).encode()
            controller_seen=set()
            def observe_controller():
                # Existing small stage records; archive bytes are not progress events.
                with (run/'ssh-ansible-inventory.log').open() as log:
                    for line in log:
                        if len(line)>65536 or not line.startswith('{') or not line.endswith('\n'):continue
                        try:item=json.loads(line)
                        except ValueError:continue
                        stage=item.get('stage')
                        event=(stage,item.get('returncode'))
                        if stage and event not in controller_seen:
                            controller_seen.add(event)
                            result.update(controller_stage=stage,last_progress_at=now());save()
            controller_rc=command(['docker','start','-ai',helper],'ssh-ansible-inventory',
                timeout=max(1,deadline-time.monotonic()-180),data=payload,check=False,observe=observe_controller)
            rows = [json.loads(line) for line in (run / 'ssh-ansible-inventory.log').read_text().splitlines() if line.startswith('{')]
            terminal = rows[-1] if rows else {}
            if not ubuntu_mode:
                result.update(checks=controller_checks(rows,assessment=distribution=='rhel10'),
                    final_authentication=any(x.get('stage')=='final-authentication' and x.get('returncode')==0 for x in rows),
                    ansible_ready=any(x.get('stage')=='ansible-readiness' and x.get('returncode')==0 for x in rows),
                    catalog_started=any(x.get('stage') in {'functional','inventory','assessment-archive'} for x in rows))
                if controller_rc:result['first_failure']=terminal.get('category','controller-failed')
                save()
            require(controller_rc==0,terminal.get('category','ssh-ansible-inventory_failed'))
            require(terminal.get('outcome') == ('assessment-evidence-collected' if ubuntu_mode else 'baseline-passed') and terminal.get('final_authentication') is True and
                    terminal.get('ansible_ready') is True and {x.get('stage') for x in rows if x.get('returncode') == 0} >=
                    {'final-authentication', 'ansible-readiness', 'functional', 'inventory'}, 'controller_results_incomplete')
            result.update(outcome='baseline-passed', installed=True, final_authentication=True, ansible_ready=True)
            if distribution=='rhel10':
                from .rhel_assessment import collect
                try:assessment=collect(run,result,rows)
                except Exception:
                    result['checks']['assessment-archive']='fail'
                    raise
                result['assessment']={key:assessment[key] for key in ('capability','content_sha256','native_counts',
                    'coverage_complete','scanner_execution_completed','limitation')}
            if ubuntu_mode:
                from .ubuntu_runtime import collect
                findings = collect(run, result)
                result.update(outcome='assessment-complete' if findings['scanner_execution_completed'] else 'assessment-failed',
                              lab_status='LAB QUALIFICATION PENDING')
                if sandbox:
                    from .ubuntu_sandbox import evidence
                    result['support_verification']=evidence(run,identifier)
        except Exception as error:
            if getattr(error,'code',None)=='vm_command_unknown':unknown=True
            result.update(outcome='unknown' if unknown else 'failed', failure_phase=result['phase'],
                          error_category=getattr(error, 'code', type(error).__name__))
            result.setdefault('first_failure',result['error_category'])
            if 'checks' in result:result['checks']={k:'blocked' if v=='pending' else v for k,v in result['checks'].items()}
        finally:
            if console is not None:
                try:os.killpg(console.pid, signal.SIGTERM)
                except ProcessLookupError:pass
                try:console.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(console.pid, signal.SIGKILL);console.wait(timeout=5)
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
                if support is not None:
                    inspected=subprocess.run(['docker','inspect',support],capture_output=True,timeout=10)
                    if inspected.returncode==0:
                        item=json.loads(inspected.stdout)[0]
                        require(item['Config']['Labels'].get('vm-run')==identifier and item['Config']['Image']==HELPER,'support_ownership_mismatch')
                        command(['docker','rm','-f',item['Id']],'support-cleanup',timeout=20)
                    if support_process is not None:support_process.wait(timeout=10)
                    lease.reconciled('support_container',support)
                if applied and not unknown:
                    if provisioner=='terraform':
                        state=json.loads((tfdir/'terraform.tfstate').read_text())
                        require({(x['type'],x['name']) for x in state['resources']}=={
                            ('libvirt_pool','run'),('libvirt_network','run'),('libvirt_domain','run'),('libvirt_volume','disk')},'terraform_ownership_mismatch')
                        require(ET.fromstring(virsh('dumpxml',name)).findtext('description')=='jake-wormhole libvirt-iso '+name,'domain_ownership_mismatch')
                        require(ET.fromstring(virsh('pool-dumpxml',name)).findtext('target/path')==str(pool),'pool_ownership_mismatch')
                        command([*tf,'destroy','-auto-approve','-input=false','-no-color'],'terraform-cleanup',timeout=90)
                    else:vm_native.destroy(run,configuration,command)
                    for query in ('list', 'net-list', 'pool-list'):
                        require(name not in virsh(query, '--all', '--name').split(), 'vm_cleanup_incomplete')
                    require(not (pool / (name + '.qcow2')).exists(), 'disk_cleanup_incomplete')
                    for kind, identity in [('domain', name), ('network', name), ('pool', name), ('disk', str(pool / (name + '.qcow2')))]:
                        lease.reconciled(kind, identity)
                if filter_name is not None:
                    from .ubuntu_sandbox import remove_filter
                    remove_filter(run,filter_name)
                    lease.reconciled('network_filter',filter_name)
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
            if ubuntu_mode:
                try:
                    from .ubuntu_runtime import report
                    report(run, result)
                except Exception as error:
                    result['report_error'] = getattr(error, 'code', type(error).__name__);save()
            if result['cleanup']=='verified-absent-inputs-retained' and not result.get('report_error'):
                try:
                    from .storage import lifecycle
                    result['storage_cleanup'] = lifecycle(lease, identifier)
                    if result['storage_cleanup']['retention_budget_exceeded']:
                        result['storage_cleanup_error']='storage_retention_budget'
                except Exception as error:
                    # A secondary storage error never replaces the workload result.
                    result['storage_cleanup_error'] = getattr(error,'code',type(error).__name__)
                save()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--source')
    action.add_argument('--recover-run',help='Reconcile the exact stopped supervisor using its recorded ownership.')
    action.add_argument('--status',help='Observe an existing run without allocating or altering resources.')
    parser.add_argument('--terraform',help='Pinned Terraform executable; required only for Terraform-owned execution/recovery.')
    parser.add_argument('--provisioner',choices=['terraform','native'],default='terraform')
    parser.add_argument('--scenario',choices=['healthy','marker-inaccessible'],default='healthy')
    parser.add_argument('--distribution', choices=['ubuntu','rhel10'], default='ubuntu')
    parser.add_argument('--reuse-run', help='Exact reconciled baseline run whose unchanged ISO bytes may be reused; a new seed and acceptance are required.')
    options = parser.parse_args()
    if options.status:
        print(json.dumps(status(options.status),indent=2));return 0
    if options.recover_run:
        from .ubuntu_recovery import recover
        value=recover(options.recover_run,options.terraform)
    else:value = execute(options.source,options.terraform,reuse_run=options.reuse_run,distribution=options.distribution,
                       provisioner=options.provisioner,scenario=options.scenario)
    print(json.dumps(value, indent=2))
    return 0 if value['outcome'] == 'baseline-passed' and value['cleanup'] != 'unreconciled' else 1


if __name__ == '__main__':
    raise SystemExit(main())
