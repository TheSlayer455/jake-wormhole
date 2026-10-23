"""Explicit fixed UBI base probe; package assembly/target qualification is later.

Only the public operator allocates: fresh canonical Run, kernel lock, Docker
scope and shared admission. Probe data is observation, never package approval.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from . import images
from .admission import AdmissionLease
from .runs import RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, create_run, now, read_json, source_identity

CONTEXT = SOURCE_ROOT / 'rpm'
BASE = 'registry.access.redhat.com/ubi9/ubi@sha256:3bd1aa8b49948633375021c22ef5601ae644f5c08c869751ac2b542884622ea1'
BASE_ID = 'sha256:3bd1aa8b49948633375021c22ef5601ae644f5c08c869751ac2b542884622ea1'
CONFIG_DIGEST = 'sha256:9be18d9ba921714e79e390694315e3341047fe758ac79b62e671d92d4217c3fb'
BASE_CONTRACT_SHA = '5d1bb67aabe4f0d844cd5bb5eee7abf230c937730e35c12278896f059c5a16d4'
SOURCES_SHA = '94d0ab366b6e2993adbdb72e32e18e392c4aecb5cd08e118fdfd7b373f6f308f'
SECONDS = 45
MAX_OUTPUT = 49152
ID = re.compile(r'[a-f0-9]{64}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
SELECT_PYTHON = 'for p in /usr/bin/python3 /usr/libexec/platform-python; do if [ -x "$p" ]; then exec "$p" -I -B /opt/wormhole-rpm/probe.py; fi; done; printf \'{"status":"failed","code":"rpm_probe_python_missing"}\\n\'; exit 64'
RELEASE_COMMAND = 'printf "1\\n" > /run/wormhole-rpm-probe.start'
TMPFS = {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=0,gid=0',
         '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777,uid=0,gid=0'}
EXECUTABLES = ('/usr/bin/python3', '/usr/libexec/platform-python', '/usr/bin/rpm', '/usr/bin/dnf',
               '/usr/sbin/sshd', '/usr/bin/ssh-keygen', '/usr/sbin/useradd', '/usr/bin/getent')
KEY_PATHS = ('/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release',)
LICENSE_PATHS = ('/usr/share/doc/redhat-release/EULA', '/usr/share/licenses/redhat-release/EULA',
    '/usr/share/licenses/ubi9-release/EULA', '/etc/redhat-release', '/etc/system-release-cpe')


class RpmError(RunError):
    pass


def require(value, code='rpm_probe_invalid'):
    if not value:
        raise RpmError(code, 'UBI operation refused; retain the exact private Run, receipts and resource journal.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value): return hashlib.sha256(value).hexdigest()


def load_lock():
    path = images.safe_bind(CONTEXT / 'lock.json')
    require(path.is_file() and path.stat().st_size <= 32768, 'rpm_lock_invalid')
    value = json.loads(path.read_bytes())
    require(type(value) is dict and set(value) == {'schema_version', 'target_family', 'platform', 'base', 'probe', 'sources', 'production_iso_eligible'} and
        value['schema_version'] == '1.0' and value['target_family'] == 'ubi9-rpm' and value['platform'] == 'linux/amd64' and
        sha(canonical(value['base'])) == BASE_CONTRACT_SHA and sha(canonical(value['sources'])) == SOURCES_SHA and
        value['probe'] == {'operation': 'ubi-base-observation-v1', 'seconds': SECONDS, 'output_bytes': MAX_OUTPUT, 'max_installed_packages': 1024} and
        value['production_iso_eligible'] is False, 'rpm_lock_invalid')
    return value


def recipe_identity():
    files = {}
    for name in ('lock.json', 'probe.py'):
        path = images.safe_bind(CONTEXT / name)
        require(path.is_file() and 1 <= path.stat().st_size <= 32768, 'rpm_recipe_invalid')
        files[name] = sha(path.read_bytes())
    return sha(canonical(files)), files


def _text(value, maximum=256):
    return type(value) is str and 1 <= len(value) <= maximum and all(ord(x) >= 32 and ord(x) != 127 for x in value)


def validate_observation(run, value, probe_sha):
    """Strict fixed facts contract; missing DNF is honest available=false."""
    fields = {'schema_version','operation','status','run_id','source_revision','probe_sha256','os_release','installed_packages',
        'python','rpm','dnf','key_files','license_files','executables','execution','shared_kernel_release','packages_installed','production_iso_eligible'}
    require(type(value) is dict and set(value) == fields and len(canonical(value)) <= MAX_OUTPUT and
        value['schema_version'] == '1.0' and value['operation'] == 'ubi-base-observation-v1' and value['status'] == 'observed' and
        value['run_id'] == run.id and value['source_revision'] == run.manifest()['source_revision'] and value['probe_sha256'] == probe_sha and
        value['packages_installed'] is False and value['production_iso_eligible'] is False, 'rpm_observation_invalid')
    packages = value['installed_packages']; rows = []
    require(type(packages) is list and 1 <= len(packages) <= 1024, 'rpm_observation_invalid')
    for row in packages:
        require(type(row) is dict and set(row) == {'name','epoch','version','release','arch'} and
            type(row['epoch']) is int and 0 <= row['epoch'] <= 2**31-1 and
            all(_text(row[key], 160) for key in ('name','version','release')) and
            (_text(row['arch'],160) or row['name'] == 'gpg-pubkey' and row['arch'] is None), 'rpm_observation_invalid')
        rows.append(tuple(row[key] for key in ('name','epoch','version','release')) + (row['arch'] or '',))
    require(rows == sorted(rows) and len(rows) == len(set(rows)), 'rpm_observation_invalid')
    release = value['os_release']
    require(type(release) is dict and {'ID','VERSION_ID'} <= set(release) <= {'ID','VERSION_ID','NAME','PRETTY_NAME','CPE_NAME','PLATFORM_ID'} and
        all(_text(item) for item in release.values()), 'rpm_observation_invalid')
    require(type(value['python']) is dict and set(value['python']) == {'version','executable'} and _text(value['python']['version']) and
        value['python']['executable'] in EXECUTABLES[:2] and type(value['rpm']) is dict and set(value['rpm']) == {'version'} and
        _text(value['rpm']['version']) and _text(value['shared_kernel_release']), 'rpm_observation_invalid')
    dnf = value['dnf']
    require(type(dnf) is dict and set(dnf) == {'available','version','base_api','repos_loaded','transaction_run'} and
        type(dnf['available']) is bool and type(dnf['base_api']) is bool and dnf['repos_loaded'] is False and dnf['transaction_run'] is False and
        (dnf['available'] and _text(dnf['version']) or dnf['available'] is False and dnf['version'] is None and dnf['base_api'] is False), 'rpm_observation_invalid')
    require(value['execution'] == {'uid':0,'gid':0,'pid':1} and all(type(x) is int for x in value['execution'].values()) and
        type(value['executables']) is dict and set(value['executables']) == set(EXECUTABLES) and
        all(type(x) is bool for x in value['executables'].values()), 'rpm_observation_invalid')
    for key, paths in (('key_files',KEY_PATHS), ('license_files',LICENSE_PATHS)):
        records = value[key]; require(type(records) is list and len(records) <= len(paths), 'rpm_observation_invalid')
        used = set()
        for record in records:
            expected = {'path','bytes','sha256'} | ({'primary_fingerprints','signature_verification'} if key == 'key_files' else set())
            require(type(record) is dict and set(record) == expected and record['path'] in paths and record['path'] not in used and
                type(record['bytes']) is int and 0 <= record['bytes'] <= 65536 and type(record['sha256']) is str and SHA.fullmatch(record['sha256']), 'rpm_observation_invalid')
            used.add(record['path'])
            if key == 'key_files':
                require(record['signature_verification'] == 'not-performed' and type(record['primary_fingerprints']) is list and
                    1 <= len(record['primary_fingerprints']) <= 8 and record['primary_fingerprints'] == sorted(set(record['primary_fingerprints'])) and
                    all(type(item) is str and re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', item) for item in record['primary_fingerprints']), 'rpm_observation_invalid')
    return value


def read_base_observation(run):
    """Return only the observation bound to this Run's original complete capture."""
    manifest = run.manifest()
    require(manifest['mode'] == 'container-reference' and manifest['source_dirty'] is False and manifest['profile'] == 'smoke', 'rpm_observation_unverified')
    receipt = read_json(run.file('evidence/rpm-base-probe.json'))
    recipe, files = recipe_identity()
    require(canonical(common(receipt)) == canonical(common(run.manifest())) and source_identity()[1] is False and
        receipt['operation'] == 'ubi-base-probe' and receipt['status'] == 'passed' and receipt['recipe_sha256'] == recipe and receipt['source_files'] == files and
        receipt['unknown_outcome'] is False and receipt['cleanup'] == 'completed' and receipt['base_reference'] == BASE and
        receipt['base_image_id'] == BASE_ID, 'rpm_observation_unverified')
    raw = run.file('private/rpm-base-probe.log'); _owned(raw)
    with raw.open('rb') as stream: data = stream.read(MAX_OUTPUT + 2)
    require(len(data) <= MAX_OUTPUT + 1 and sha(data) == receipt['capture_sha256'], 'rpm_observation_changed')
    value = _parse(data)
    require(value == receipt['observation'], 'rpm_observation_changed')
    return validate_observation(run, value, receipt['source_files']['probe.py'])


def _parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'rpm_observation_invalid'); result[key] = value
        return result
    require(type(raw) is bytes and len(raw) <= MAX_OUTPUT + 1 and raw.endswith(b'\n'), 'rpm_observation_invalid')
    try: return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError): raise RpmError('rpm_observation_invalid', 'The fixed probe output is not complete bounded JSON.') from None


def _scope(run, lease):
    manifest = run.manifest(); lease._active()
    require(sys.platform.startswith('linux') and run.workspace == images.RUNS_ROOT and manifest['mode'] == 'container-reference' and
        manifest['profile'] == 'smoke' and source_identity() == (manifest['source_revision'], False) and manifest['source_dirty'] is False and
        read_json(run.file('lock-policy.json')) == {'schema_version':'1.0','run_id':run.id,'kind':'linux-flock'} and
        lease.root == images.INFRASTRUCTURE and lease.run_id == run.id and lease.source_revision == manifest['source_revision'] and
        not lease._reconciliation_only and lease.plan['synthetic'] is False and lease.plan['admitted'] is True and lease.plan['profile'] == 'smoke', 'rpm_probe_scope')


def _public_source(run, expected):
    folder = run.file('private/rpm-probe-source')
    if not folder.exists(): folder.mkdir(mode=0o700)
    _owned(folder, directory=True)
    path = folder / 'probe.py'
    if not path.exists():
        atomic_bytes(path, (CONTEXT / 'probe.py').read_bytes(), limit=32768); path.chmod(0o444)
    images.safe_bind(path); info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
        stat.S_IMODE(info.st_mode) == 0o444 and 1 <= info.st_size <= 32768 and sha(path.read_bytes()) == expected, 'rpm_probe_source_changed')
    return {'path':str(path),'device':info.st_dev,'inode':info.st_ino,'bytes':info.st_size,'sha256':expected}


def verify_base(value, lock):
    require(value.get('Id') == BASE_ID and value.get('Os') == 'linux' and value.get('Architecture') == 'amd64' and
        BASE in value.get('RepoDigests', []) and value.get('Config', {}).get('Labels') == lock['base']['labels'] and
        not value['Config'].get('Volumes') and type(value.get('Size')) is int and value['Size'] > 0 and
        value.get('Descriptor') == {'mediaType':'application/vnd.docker.distribution.manifest.v2+json','digest':BASE_ID,'size':429} and
        lock['base']['config_digest'] == CONFIG_DIGEST, 'rpm_base_invalid')


def verify_probe(run, receipt, value, limits, *, stopped=False):
    host, config = value['HostConfig'], value['Config']; expected = limits['docker_create']
    require(value.get('Id') == receipt['container_id'] and value.get('Image') == BASE_ID and value.get('Name') == '/wormhole-' + run.id + '-rpm-probe' and
        config.get('Labels') == receipt['labels'] and config.get('User') == '0:0' and config.get('WorkingDir') == '/' and
        config.get('Entrypoint') == ['/bin/sh'] and config.get('Cmd') == ['-c',SELECT_PYTHON] and
        not config.get('Tty') and not config.get('OpenStdin'), 'rpm_probe_identity')
    environment = config.get('Env') or []
    require(type(environment) is list and len(environment) == len(set(item.split('=',1)[0] for item in environment)) and
        {item for item in environment if item.startswith('WORMHOLE_')} == {
            'WORMHOLE_ROLE=rpm-base-probe','WORMHOLE_RUN_ID=' + run.id,'WORMHOLE_SOURCE_REVISION=' + receipt['source_revision']} and
        all(item in environment for item in ('HOME=/tmp','PATH=/usr/sbin:/usr/bin:/sbin:/bin','LANG=C')), 'rpm_probe_identity')
    require(host.get('NetworkMode') == 'none' and host.get('ReadonlyRootfs') is True and host.get('Privileged') is False and
        images.capability_names(host.get('CapDrop')) == {'ALL'} and not host.get('CapAdd') and
        all(host.get(actual) == expected[key] and type(host.get(actual)) is int for actual,key in
            (('Memory','memory_bytes'),('MemorySwap','memory_swap_bytes'),('NanoCpus','nano_cpus'),('PidsLimit','pids_limit'))) and
        host.get('LogConfig') == {'Type':expected['log_driver'],'Config':expected['log_opts']} and host.get('Tmpfs') == TMPFS and
        host.get('PidMode','') == '' and host.get('IpcMode') in ('','private') and host.get('UTSMode','') == '' and
        not host.get('PortBindings') and not host.get('PublishAllPorts') and not host.get('Devices') and
        host.get('RestartPolicy',{}).get('Name') == 'no' and
        set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'},{'no-new-privileges=true'},{'no-new-privileges'}), 'rpm_probe_limits')
    # Docker may report tmpfs mounts separately; allow only the two exact declared tmpfs destinations.
    mounts = value.get('Mounts', [])
    binds = [item for item in mounts if item.get('Type') == 'bind']
    require(len(binds) == 1 and binds[0].get('Source') == receipt['source_binding']['path'] and
        binds[0].get('Destination') == '/opt/wormhole-rpm/probe.py' and binds[0].get('RW') is False and
        all(item.get('Type') == 'bind' or item.get('Type') == 'tmpfs' and item.get('Destination') in TMPFS for item in mounts), 'rpm_probe_mounts')
    require(_public_source(run, receipt['source_files']['probe.py']) == receipt['source_binding'], 'rpm_probe_source_changed')
    if stopped:
        require(value['State']['Running'] is False and value['State']['Status'] == 'created' and
            value['State']['StartedAt'] == '0001-01-01T00:00:00Z', 'rpm_probe_started')


def _save(run, receipt):
    receipt['updated_at'] = now(); atomic_json(run.file('evidence/rpm-base-probe.json'), receipt)


def _mutation(run, receipt, arguments, **options):
    receipt['unknown_outcome'] = True; _save(run, receipt)
    return images.docker(arguments, **options)  # Caller clears only after the operation's exact proof.


def _empty(run):
    for command in (('ps','-a','--no-trunc'),('network','ls','--no-trunc'),('image','ls','--all','--no-trunc'),('volume','ls')):
        result = images.docker((*command,'--filter','label=' + images.LABEL + '.run_id=' + run.id,'--format','{{.ID}}'))
        require(not result['log_truncated'] and not result['log'].strip(), 'rpm_probe_leftovers')


def cleanup_probe(run, lease, receipt):
    require(receipt['unknown_outcome'] is False, 'rpm_probe_outcome_unknown')
    identifier = receipt['container_id']
    if identifier is not None:
        entries = [row for row in lease.record['resources'] if row['kind'] == 'container' and row['id'] == identifier]
        require(len(entries) == 1 and entries[0]['outcome'] in ('pending','absent'), 'rpm_probe_cleanup_unverified')
        value = images.inspect('container',identifier,missing=True)
        if value is not None:
            require(entries[0]['outcome'] == 'pending', 'rpm_probe_cleanup_unverified')
            verify_probe(run,receipt,value,lease.plan['limits']['build'])
            if value['State']['Running']:
                _mutation(run,receipt,('stop','--time','2',identifier),timeout=10)
                require(images.inspect('container',identifier)['State']['Running'] is False, 'rpm_probe_cleanup_unverified')
                receipt['unknown_outcome'] = False; _save(run,receipt)
            _mutation(run,receipt,('rm',identifier))
            require(images.inspect('container',identifier,missing=True) is None, 'rpm_probe_cleanup_unverified')
            receipt['unknown_outcome'] = False; _save(run,receipt)
        require(images.inspect('container',identifier,missing=True) is None, 'rpm_probe_cleanup_unverified')
        if entries[0]['outcome'] == 'pending': lease.reconcile_resource('container',identifier)
    _empty(run); receipt['cleanup'] = 'completed'; _save(run,receipt)


def probe_base(run, lease):
    """Caller holds Run lock/Docker scope. Leave its lease held for later phases."""
    _scope(run,lease); lock = load_lock(); recipe, files = recipe_identity()
    require(not run.file('evidence/rpm-base-probe.json').exists(), 'rpm_probe_reused')
    receipt = {**common(run.manifest()), 'operation':'ubi-base-probe','status':'pending','started_at':now(),
        'base_reference':BASE,'base_image_id':None,'container_id':None,'recipe_sha256':recipe,'source_files':files,
        'source_binding':_public_source(run,files['probe.py']),'labels':None,'capture_sha256':None,'observation':None,
        'unknown_outcome':False,'primary_failure':None,'cleanup':'pending','secondary_cleanup_failure':None,'pull_result':None,
        'daemon_pull_cgroup_capped':False,'runtime_pipeline_complete':False,'production_iso_eligible':False}
    def source(): require(source_identity() == (receipt['source_revision'],False) and recipe_identity() == (recipe,files) and
        _public_source(run,files['probe.py']) == receipt['source_binding'], 'rpm_probe_source_changed')
    _save(run,receipt)
    try:
        lease.set_phase('assembling'); base = images.inspect('image',BASE,missing=True)
        lease.set_phase('materializing')
        if base is None:
            pulled = _mutation(run,receipt,('pull','--platform','linux/amd64',BASE),timeout=lease.plan['materialization']['client_timeout_seconds'])
            require(pulled['status'] == 'pass' and pulled['returncode'] == 0 and not pulled['log_truncated'], 'rpm_pull_incomplete')
            atomic_bytes(run.file('private/rpm-base-pull.log'),pulled['log'],limit=65536)
            receipt['pull_result'] = {'reference':BASE,'platform':'linux/amd64','status':'pass','returncode':0,
                'capture_sha256':sha(pulled['log']),'size_bytes':len(pulled['log']),'recorded_at':now()}; _save(run,receipt)
            base = images.inspect('image',BASE)
        verify_base(base,lock); lease.register_resource('image',BASE_ID)
        lease.reconcile_resource('image',BASE_ID,outcome='retained',size_bytes=base['Size'])
        receipt.update(base_image_id=BASE_ID,unknown_outcome=False); _save(run,receipt)
        lease.set_phase('assembling'); source(); limits = lease.plan['limits']['build']
        receipt['labels'] = {**lock['base']['labels'],images.LABEL + '.run_id':run.id,images.LABEL + '.source_revision':receipt['source_revision'],
            images.LABEL + '.role':'rpm-base-probe',images.LABEL + '.rpm_recipe_sha256':recipe}
        args = ['create','--name','wormhole-' + run.id + '-rpm-probe','--network','none','--user','0:0','--read-only','--workdir','/',
            '--entrypoint','/bin/sh',*images.limits_arguments(limits)]
        for key,value in TMPFS.items(): args.extend(('--tmpfs',key + ':' + value))
        for item in ('HOME=/tmp','PATH=/usr/sbin:/usr/bin:/sbin:/bin','LANG=C','WORMHOLE_ROLE=rpm-base-probe',
            'WORMHOLE_RUN_ID=' + run.id,'WORMHOLE_SOURCE_REVISION=' + receipt['source_revision']): args.extend(('--env',item))
        for key,value in receipt['labels'].items(): args.extend(('--label',key + '=' + value))
        args.extend(('--mount','type=bind,source=' + receipt['source_binding']['path'] + ',target=/opt/wormhole-rpm/probe.py,readonly,bind-propagation=rprivate',BASE_ID,'-c',SELECT_PYTHON))
        result = _mutation(run,receipt,tuple(args)); identifier = result['log'].decode('ascii').strip()
        require(not result['log_truncated'] and ID.fullmatch(identifier), 'rpm_probe_create_unknown')
        lease.register_resource('container',identifier); receipt.update(container_id=identifier,unknown_outcome=False); _save(run,receipt)
        verify_probe(run,receipt,images.inspect('container',identifier),limits,stopped=True); source()
        _mutation(run,receipt,('start',identifier)); receipt['unknown_outcome'] = False; _save(run,receipt)
        value = images.inspect('container',identifier); verify_probe(run,receipt,value,limits)
        require(value['State']['Running'] is True, 'rpm_probe_runtime_failed')
        receipt['cgroups'] = images.cgroup_limits(value['State']['Pid'],limits['docker_create']); _save(run,receipt)
        _mutation(run,receipt,('exec',identifier,'/bin/sh','-c',RELEASE_COMMAND),timeout=10)
        receipt['unknown_outcome'] = False; _save(run,receipt)
        end = time.monotonic() + 30
        while True:
            require(time.monotonic() < end, 'rpm_probe_deadline')
            output = images.docker(('logs',identifier),timeout=min(5,max(.01,end-time.monotonic())))
            require(time.monotonic() < end, 'rpm_probe_deadline')
            require(not output['log_truncated'] and len(output['log']) <= MAX_OUTPUT + 1, 'rpm_probe_output_bound')
            if output['log'].endswith(b'\n'):
                raw = output['log']; break
            current = images.inspect('container',identifier,timeout=min(5,max(.01,end-time.monotonic())))
            require(current['State']['Running'] is True, 'rpm_probe_runtime_failed'); time.sleep(.05)
        atomic_bytes(run.file('private/rpm-base-probe.log'),raw,limit=MAX_OUTPUT+1)
        observation = validate_observation(run,_parse(raw),files['probe.py']); source()
        receipt.update(observation=observation,capture_sha256=sha(raw),status='passed'); _save(run,receipt)
        cleanup_probe(run,lease,receipt)
        return deepcopy(receipt)
    except BaseException as error:
        receipt['status'] = 'failed'; receipt['primary_failure'] = {'code':getattr(error,'code','rpm_probe_failed'),'recorded_at':now()}; _save(run,receipt)
        if not receipt['unknown_outcome']:
            try: cleanup_probe(run,lease,receipt)
            except Exception as cleanup_error:
                receipt['cleanup'] = 'blocked'; receipt['secondary_cleanup_failure'] = {'code':getattr(cleanup_error,'code','rpm_cleanup_failed'),'recorded_at':now()}; _save(run,receipt)
        raise


def probe(sentinel):
    from .provisioning_acceptance import snapshot
    require(type(sentinel) is str and ID.fullmatch(sentinel) and sys.platform.startswith('linux'), 'rpm_probe_input')
    revision,dirty = source_identity(); require(dirty is False, 'rpm_probe_source_dirty')
    run = create_run(images.RUNS_ROOT,fixture=False,kernel_lock=True)
    try:
        require(run.manifest()['source_revision'] == revision and run.manifest()['source_dirty'] is False, 'rpm_probe_source_changed')
        with run.locked(),images.docker_scope(run),AdmissionLease(images.INFRASTRUCTURE,run.id,revision) as lease:
            before = snapshot('container',sentinel,unrelated=True)
            try: result = probe_base(run,lease)
            except BaseException:
                path = run.file('evidence/rpm-base-probe.json')
                if path.exists():
                    receipt = read_json(path)
                    if receipt['cleanup'] == 'completed' and receipt['unknown_outcome'] is False:
                        require(snapshot('container',sentinel,unrelated=True) == before, 'rpm_sentinel_changed')
                        lease.finish(reconciliation_complete=True)
                raise
            require(snapshot('container',sentinel,unrelated=True) == before, 'rpm_sentinel_changed')
            lease.finish(reconciliation_complete=True)
            result.update(unrelated_sentinel_unchanged=True,admission_finished=True); _save(run,result)
            return result
    except BaseException as error:
        error.run_id = run.id
        raise


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Fixed public UBI base observation; no package installation.')
    commands = parser.add_subparsers(dest='command',required=True)
    command = commands.add_parser('probe'); command.add_argument('--sentinel-id',required=True)
    options = parser.parse_args(arguments)
    try:
        result = probe(options.sentinel_id)
        print(json.dumps({'run_id':result['run_id'],'status':result['status'],'evidence':'evidence/rpm-base-probe.json',
            'packages_installed':False,'runtime_pipeline_complete':False,'production_iso_eligible':False}))
        return 0
    except (RunError,OSError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({'status':'failed','code':getattr(error,'code','rpm_probe_failed'),'run_id':getattr(error,'run_id',None),
            'evidence':'evidence/rpm-base-probe.json','production_iso_eligible':False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
