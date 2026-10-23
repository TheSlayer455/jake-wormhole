"""Explicit optional PowerShell helper, with an offline build and no scanner API."""
import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit

from . import images
from .runs import Run, RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, now, read_json, source_identity
from .stages import _run_process

CONTEXT = SOURCE_ROOT / 'capabilities/powershell'
FILES = ('assemble.sh', 'runtime.py', 'lock.json')
BASE = 'sha256:4f7f306ecd431b4b48169777966d88c1f09f2139506176a6b85203f5bae69a71'
BASE_RUN = '9e864d00-ea9f-4a85-bdb5-f5873166e4d7'
BASE_SOURCE = '244ea4b8961fa3be5ca82c122f95a1bd776c210d'
PS_URL = 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.8/powershell_7.6.8-1.deb_amd64.deb'
ICU_URL = 'https://snapshot.ubuntu.com/ubuntu/20261023T000000Z/pool/main/i/icu/libicu74_74.2-1ubuntu3.1_amd64.deb'
MAX_FILE = 64 * 1024 * 1024
MAX_CACHE = 80 * 1024 * 1024
PREPARATION_TIMEOUT = 180
DESTINATION = '/opt/wormhole-capabilities/powershell/'
CHOICES = ('missing-package-fixture', 'powershell-helper')
WORKER = """import json,sys
from wormhole.runs import Run
from wormhole.powershell import _prepare_worker
try: _prepare_worker(Run(sys.argv[1],sys.argv[2]))
except Exception as error:
 print(json.dumps({'code':getattr(error,'code','capability_preparation_failed')}))
 raise SystemExit(2)
"""


class CapabilityError(RunError):
    pass


def require(value, code):
    if not value:
        raise CapabilityError(code, 'Optional PowerShell capability refused; preserve the bounded receipt and exact resource accounting.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def load_lock():
    path = CONTEXT / 'lock.json'
    images.safe_bind(path)
    require(path.is_file() and path.stat().st_size <= 32768, 'capability_lock_invalid')
    value = json.loads(path.read_bytes())
    expected = [('powershell.deb', PS_URL, 55409518, 'f687eb1a3ba7b22a1ff35d85893b64aec1045ff718f13ceb8e56c300d60494dc'),
        ('libicu74.deb', ICU_URL, 10860078, 'c9a70989678660eed9a1e904c74fa043da8bec8e2036856fc16e31ced79b04f8')]
    require(value['schema_version'] == '1.0' and value['capability'] == 'powershell-explicit' and
        value['platform'] == 'linux/amd64' and value['base_image'] == BASE and value['base_build_run'] == BASE_RUN and
        value['base_build_source'] == BASE_SOURCE and value['release'] == '7.6.8' and value['package_version'] == '7.6.8-1.deb' and
        value['policy'] == {'download_per_file': MAX_FILE, 'cache_total': MAX_CACHE, 'preparation_seconds': PREPARATION_TIMEOUT} and
        [(item['filename'], item['url'], item['bytes'], item['sha256']) for item in value['artifacts']] == expected,
        'capability_lock_invalid')
    recipe, files = images.recipe_identity()
    require(value['base_recipe_sha256'] == recipe and value['base_source_files'] == files, 'ordinary_helper_recipe_changed')
    return value


def recipe_identity():
    files = {}
    for name in FILES:
        path = images.safe_bind(CONTEXT / name)
        require(path.is_file() and path.stat().st_nlink == 1 and path.stat().st_size <= 65536, 'capability_source_invalid')
        files[name] = sha(path.read_bytes())
    return sha(canonical(files)), files


class RedirectPolicy(urllib.request.HTTPRedirectHandler):
    def __init__(self, initial):
        self.initial, self.count = initial, 0
        super().__init__()

    def redirect_request(self, request, fp, code, message, headers, newurl):
        target = urlsplit(newurl)
        require(self.initial == PS_URL and request.full_url == self.initial and self.count == 0 and
            target.scheme == 'https' and target.hostname == 'release-assets.githubusercontent.com' and
            target.port in (None, 443) and not target.username and not target.password and not target.fragment,
            'capability_redirect_refused')
        self.count += 1
        return urllib.request.Request(newurl, method='GET') # No credentials/headers follow the signed URL.


def hash_file(path, item):
    _owned(path)
    require(path.stat().st_size == item['bytes'] <= MAX_FILE, 'capability_size_mismatch')
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while raw := stream.read(65536):
            size += len(raw); require(size <= item['bytes'], 'capability_size_mismatch'); digest.update(raw)
    require(size == item['bytes'] and digest.hexdigest() == item['sha256'], 'capability_hash_mismatch')
    return size


def fetch(item, destination, *, opener=None):
    require(item['url'] in (PS_URL, ICU_URL) and Path(item['filename']).name == item['filename'] and
        type(item['bytes']) is int and 0 < item['bytes'] <= MAX_FILE and re.fullmatch('[a-f0-9]{64}', item['sha256']),
        'capability_download_invalid')
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RedirectPolicy(item['url'])).open
    partial = destination.with_suffix('.partial')
    digest, size = hashlib.sha256(), 0
    with opener(item['url'], timeout=20) as response:
        final = urlsplit(response.geturl())
        require(final.scheme == 'https' and final.hostname == urlsplit(item['url']).hostname or
            item['url'] == PS_URL and final.scheme == 'https' and final.hostname == 'release-assets.githubusercontent.com',
            'capability_redirect_refused')
        with os.fdopen(os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as stream:
            while raw := response.read1(65536):
                size += len(raw); require(size <= item['bytes'] and size <= MAX_FILE, 'capability_size_mismatch')
                stream.write(raw); digest.update(raw)
            stream.flush(); os.fsync(stream.fileno())
    require(size == item['bytes'] and digest.hexdigest() == item['sha256'], 'capability_hash_mismatch')
    require(not destination.exists() and not destination.is_symlink(), 'capability_cache_exists')
    os.replace(partial, destination)


def _prepare_worker(run):
    lock = load_lock()
    cache = run.file('private/powershell-artifacts'); cache.mkdir(mode=0o700)
    for item in lock['artifacts']: fetch(item, cache / item['filename'])


def validate_cache(run, lock):
    folder = run.file('private/powershell-artifacts'); _owned(folder, directory=True)
    require(set(os.listdir(folder)) == {item['filename'] for item in lock['artifacts']}, 'capability_cache_invalid')
    require(sum(hash_file(folder / item['filename'], item) for item in lock['artifacts']) <= MAX_CACHE, 'capability_cache_bound')
    return folder


def prepare(run, lock):
    require(not run.file('private/powershell-artifacts').exists(), 'capability_cache_exists')
    result = _run_process((sys.executable, '-c', WORKER, str(run.workspace), run.id), cwd=SOURCE_ROOT,
        timeout=PREPARATION_TIMEOUT)
    atomic_bytes(run.file('private/powershell-preparation.log'), result['log'], limit=65536)
    require(result['status'] == 'pass' and not result['log_truncated'],
        'capability_preparation_timeout' if result['status'] == 'timeout' else 'capability_preparation_failed')
    return validate_cache(run, lock)


def base_reference():
    from scripts.qualify_images import build_reference
    value = build_reference(BASE_RUN, 'helper')
    require(value['image_id'] == BASE and value['source_revision'] == BASE_SOURCE, 'capability_base_mismatch')
    return value


def binding_files(run):
    folder = run.file('private/powershell-public-source')
    folder.mkdir(mode=0o700)
    result = {}
    for name in ('runtime.py', 'lock.json'):
        raw = (CONTEXT / name).read_bytes(); path = folder / name
        atomic_bytes(path, raw, limit=65536); path.chmod(0o444)
        result[DESTINATION + name] = str(images.safe_bind(path))
    return result


def binding_identity(path):
    path = images.safe_bind(path); info = path.stat()
    require(path.is_file() and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o444,
        'capability_mount_changed')
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
        'size': info.st_size, 'mode': stat.S_IMODE(info.st_mode), 'sha256': sha(path.read_bytes())}


def verify_bindings(run, mounts, build, identities=None):
    if build:
        require(mounts == {'/recipe': str(images.safe_bind(CONTEXT)),
            '/artifacts': str(images.safe_bind(run.file('private/powershell-artifacts')))}, 'capability_mount_changed')
        for item in load_lock()['artifacts']:
            path = run.file('private/powershell-artifacts/' + item['filename']); _owned(path)
            require(path.stat().st_size == item['bytes'], 'capability_size_mismatch')
    else:
        expected = {DESTINATION + name: str(run.file('private/powershell-public-source/' + name)) for name in ('runtime.py', 'lock.json')}
        require(mounts == expected, 'capability_mount_changed')
        for destination, source in mounts.items():
            observed = binding_identity(source)
            require(identities is not None and observed == identities.get(destination) and
                observed['sha256'] == sha((CONTEXT / Path(source).name).read_bytes()), 'capability_mount_changed')


def owned(run, receipt, value):
    require(value['Id'] == receipt['container_id'] and value['Image'] == receipt['image'] and
        all(value['Config'].get('Labels', {}).get(k) == v for k, v in receipt['labels'].items()), 'capability_ownership_changed')


def verify_container(run, receipt, value):
    owned(run, receipt, value)
    if receipt['operation'] == 'build':
        verify_bindings(run, receipt['mounts'], True)
        images.verify_builder(value, identifier=receipt['container_id'], labels=receipt['labels'],
            limits=receipt['limits'], mounts=receipt['mounts'], network='none')
        return
    host, config, limits = value['HostConfig'], value['Config'], receipt['limits']['docker_create']
    require(host['Memory'] == limits['memory_bytes'] and host['MemorySwap'] == limits['memory_swap_bytes'] and
        host['NanoCpus'] == limits['nano_cpus'] and host['PidsLimit'] == limits['pids_limit'] and
        host['LogConfig'] == {'Type': limits['log_driver'], 'Config': limits['log_opts']} and
        host['Privileged'] is False and host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none' and
        not host.get('PortBindings') and not host.get('PublishAllPorts') and host.get('PidMode') == '' and
        host.get('IpcMode') in ('', 'private') and host.get('UTSMode', '') == '' and
        images.capability_names(host.get('CapDrop')) == {'ALL'} and not images.capability_names(host.get('CapAdd')) and
        set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'}, {'no-new-privileges=true'}, {'no-new-privileges'}) and
        host['RestartPolicy']['Name'] == 'no' and config['User'] == '10001:10001' and
        config['Entrypoint'] == ['/opt/wormhole/venv/bin/python'] and
        config['Cmd'] == [DESTINATION + 'runtime.py', receipt['runtime_operation']], 'capability_runtime_changed')
    require(host['Tmpfs'] == {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=10001,gid=10001',
        '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'}, 'capability_runtime_changed')
    actual = [item for item in value['Mounts'] if item['Type'] != 'tmpfs']
    require(len(actual) == len(receipt['mounts']) and all(item['Type'] == 'bind' and item['RW'] is False and
        receipt['mounts'].get(item['Destination']) == item['Source'] for item in actual), 'capability_mount_changed')
    env = config.get('Env') or []
    require(all(env.count(value) == 1 for value in ('WORMHOLE_RUN_ID=' + run.id,
        'WORMHOLE_CAPABILITY=powershell-explicit', 'POWERSHELL_TELEMETRY_OPTOUT=1')), 'capability_runtime_changed')
    if receipt['mounts']: verify_bindings(run, receipt['mounts'], False, receipt['binding_identities'])


def save(run, receipt):
    receipt['updated_at'] = now()
    atomic_json(run.file('evidence/powershell-capability.json'), receipt)


def mutation(run, receipt, arguments, *, keep_unknown=False, **options):
    receipt['unknown_outcome'] = True; save(run, receipt)
    value = images.docker(arguments, **options)
    if not keep_unknown:
        receipt['unknown_outcome'] = False; save(run, receipt)
    return value


def cleanup(run, receipt, lease):
    require(receipt['unknown_outcome'] is False, 'capability_outcome_unknown')
    lease.set_phase('reconciling')
    identifier = receipt['container_id']
    if identifier is not None:
        value = images.inspect('container', identifier, missing=True)
        if value is not None:
            owned(run, receipt, value)
            if value['State']['Running']:
                mutation(run, receipt, ('kill', identifier), timeout=10)
                require(images.inspect('container', identifier)['State']['Running'] is False, 'capability_cleanup_unverified')
            mutation(run, receipt, ('rm', identifier))
        require(images.inspect('container', identifier, missing=True) is None, 'capability_cleanup_unverified')
        lease.reconcile_resource('container', identifier)
    leftovers = images.docker(('ps', '-a', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + run.id, '--format', '{{.ID}}'))
    require(not leftovers['log_truncated'] and not leftovers['log'].strip(), 'capability_cleanup_unverified')
    lease.finish(reconciliation_complete=True)
    receipt['resources_reconciled'] = True; save(run, receipt)


def optional_image(build_id):
    build = Run(images.RUNS_ROOT, build_id); receipt = read_json(build.file('evidence/powershell-capability.json'))
    recipe, files = recipe_identity()
    require(receipt['operation'] == 'build' and receipt['status'] == 'completed' and receipt['resources_reconciled'] is True and
        receipt['unknown_outcome'] is False and receipt['run_id'] == build.id and receipt['source_revision'] == build.manifest()['source_revision'] and
        canonical({key: receipt[key] for key in common(build.manifest())}) == canonical(common(build.manifest())) and
        build.manifest()['source_dirty'] is False and build.manifest()['mode'] == 'container-reference' and
        receipt['component'] == 'optional-powershell' and receipt['selection'] == 'powershell-helper' and
        receipt['recipe_sha256'] == recipe and receipt['source_files'] == files and
        type(receipt['image_id']) is str and re.fullmatch('sha256:[a-f0-9]{64}', receipt['image_id']), 'capability_image_unqualified')
    image = images.inspect('image', receipt['image_id'])
    require(image['Id'] == receipt['image_id'] and not image['Config'].get('Volumes') and
        all(image['Config'].get('Labels', {}).get(key) == value for key, value in receipt['labels'].items()), 'capability_image_unqualified')
    return receipt['image_id']


def execute(run, *, selection, build_run=None):
    """Canonical admitted operations. An absent/unknown selection never falls back."""
    require(selection in CHOICES and (selection != 'missing-package-fixture' or build_run is None), 'capability_selection_required')
    build = selection == 'powershell-helper' and build_run is None
    require(sys.platform.startswith('linux') and run.workspace == images.RUNS_ROOT and
        run.manifest()['mode'] == 'container-reference', 'capability_host_scope')
    from .admission import AdmissionLease
    with run.locked(), images.docker_scope(run):
        base = common(run.manifest()); require(source_identity() == (base['source_revision'], False) and base['source_dirty'] is False, 'capability_source_changed')
        destination = run.file('evidence/powershell-capability.json'); require(not destination.exists(), 'capability_attempt_exists')
        lock = load_lock(); recipe, files = recipe_identity()
        receipt = {**base, 'component': 'optional-powershell', 'operation': 'build' if build else 'probe',
            'selection': selection, 'runtime_operation': None if build else 'missing' if selection == 'missing-package-fixture' else 'smoke',
            'status': 'pending', 'recipe_sha256': recipe, 'source_files': files, 'base_image': BASE, 'base_build_run': BASE_RUN,
            'image': BASE, 'image_id': None, 'container_id': None, 'unknown_outcome': False,
            'primary_failure': None, 'cleanup_failures': [], 'resources_reconciled': False,
            'production_iso_eligible': False, 'runtime_pipeline_complete': False,
            'scanner_compatibility': 'unavailable-no-authorized-package-or-documented-method'}
        save(run, receipt)
        with images.recorded_admission(AdmissionLease, run, base['source_revision'], receipt, destination) as lease:
            try:
                require(lease.plan['synthetic'] is False and lease.plan['admitted'] is True, 'capability_admission_required')
                receipt['base_reference'] = base_reference()
                if build:
                    cache = prepare(run, lock)
                    mounts = {'/recipe': str(images.safe_bind(CONTEXT)), '/artifacts': str(images.safe_bind(cache))}
                elif selection == 'missing-package-fixture': mounts = binding_files(run)
                else:
                    require(type(build_run) is str, 'capability_selection_required')
                    receipt['image'] = optional_image(build_run); receipt['build_run_id'] = build_run; mounts = {}
                require(source_identity() == (base['source_revision'], False) and recipe_identity() == (recipe, files), 'capability_source_changed')
                lease.set_phase('assembling' if build else 'provisioning')
                limits = lease.plan['limits']['build' if build else 'helper']
                role = 'helper-powershell' if build else 'helper-powershell-probe'
                labels = images.expected_labels(run, role, recipe, files['lock.json'])
                receipt.update(mounts=mounts, labels=labels, limits=limits,
                    binding_identities={key: binding_identity(path) for key, path in mounts.items()} if not build else {})
                save(run, receipt)
                arguments = ['create', '--name', 'wormhole-' + run.id + '-powershell', '--network', 'none',
                    '--user', '0:0' if build else '10001:10001', '--entrypoint', '/bin/sh' if build else '/opt/wormhole/venv/bin/python',
                    *images.limits_arguments(limits)]
                if build:
                    for capability in images.BUILD_CAPS: arguments.extend(('--cap-add', capability))
                else:
                    arguments.extend(('--read-only', '--tmpfs', '/run:rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=10001,gid=10001',
                        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777', '--env', 'WORMHOLE_RUN_ID=' + run.id,
                        '--env', 'WORMHOLE_CAPABILITY=powershell-explicit', '--env', 'POWERSHELL_TELEMETRY_OPTOUT=1'))
                for key, value in labels.items(): arguments.extend(('--label', key + '=' + value))
                for target, source in mounts.items(): arguments.extend(('--mount', 'type=bind,source=' + source + ',target=' + target + ',readonly,bind-propagation=rprivate'))
                arguments.extend((receipt['image'], '/recipe/assemble.sh', role) if build else
                    (receipt['image'], DESTINATION + 'runtime.py', receipt['runtime_operation']))
                result = mutation(run, receipt, arguments, keep_unknown=True)
                identifier = result['log'].decode().strip(); require(re.fullmatch('[a-f0-9]{64}', identifier), 'capability_allocation_unknown')
                receipt['container_id'] = identifier; save(run, receipt)
                lease.register_resource('container', identifier)
                receipt['unknown_outcome'] = False; save(run, receipt)
                value = images.inspect('container', identifier); verify_container(run, receipt, value)
                require(value['State']['Status'] == 'created' and value['State']['Running'] is False and value['State']['Pid'] == 0, 'capability_started_early')
                if build: validate_cache(run, lock)
                deadline = time.monotonic() + (limits['timeout_seconds'] if build else 60)
                mutation(run, receipt, ('start', identifier), timeout=20)
                cgroups = None
                while True:
                    require(time.monotonic() < deadline, 'capability_execution_timeout')
                    value = images.inspect('container', identifier, timeout=min(20, max(.01, deadline-time.monotonic())))
                    verify_container(run, receipt, value)
                    if not value['State']['Running']: break
                    if cgroups is None:
                        cgroups = images.cgroup_limits(value['State']['Pid'], limits['docker_create'])
                        require(images.inspect('container', identifier)['State']['Pid'] == value['State']['Pid'], 'capability_cgroups_unverified')
                    if build:
                        info = images.docker(('info', '--format', '{{.DockerRootDir}}'))
                        storage = Path(info['log'].decode().strip())
                        require(storage.is_absolute() and '..' not in storage.parts and storage.is_dir(), 'capability_storage_unverified')
                        images.assembly_storage_guard(lease.plan, storage, images.inspect('container', identifier, size=True))
                    time.sleep(min(.5, max(0, deadline-time.monotonic())))
                require(cgroups is not None and value['State']['Status'] == 'exited', 'capability_cgroups_unverified')
                logs = images.docker(('logs', '--tail', '1000', identifier)); atomic_bytes(run.file('private/powershell-runtime.log'), logs['log'], limit=65536)
                require(not logs['log_truncated'], 'capability_output_bound')
                receipt['cgroups'] = cgroups; receipt['exit_code'] = value['State']['ExitCode']
                if build:
                    require(value['State']['ExitCode'] == 0, 'capability_dependency_unavailable')
                    validate_cache(run, lock)
                    sized = images.inspect('container', identifier, size=True)
                    require(type(sized['SizeRw']) is int and 0 <= sized['SizeRw'] <= lease.plan['materialization']['writable_layer_limit_bytes'],
                        'capability_layer_bound')
                    receipt['writable_layer_bytes'] = sized['SizeRw']
                    receipt['installed'] = installed_record(identifier)
                    require(source_identity() == (base['source_revision'], False) and recipe_identity() == (recipe, files), 'capability_source_changed')
                    lease.set_phase('materializing')
                    tag = 'jake-wormhole-helper-powershell:run-' + run.id
                    require(images.inspect('image', tag, missing=True) is None, 'capability_tag_exists')
                    changes = ['USER 10001:10001', 'ENTRYPOINT ["/opt/wormhole/venv/bin/python","/opt/wormhole/runtime.py","helper"]',
                        'CMD []', 'ENV POWERSHELL_TELEMETRY_OPTOUT=1']
                    command = ['commit']
                    for change in changes: command.extend(('--change', change))
                    command.extend((identifier, tag))
                    result = mutation(run, receipt, command, keep_unknown=True, timeout=lease.plan['materialization']['client_timeout_seconds'])
                    image_id = result['log'].decode().strip(); require(re.fullmatch('sha256:[a-f0-9]{64}', image_id), 'capability_commit_unknown')
                    image = images.inspect('image', tag)
                    require(image['Id'] == image_id and not image['Config'].get('Volumes') and
                        all(image['Config'].get('Labels', {}).get(k) == v for k, v in labels.items()), 'capability_commit_unknown')
                    lease.register_resource('image', image_id); lease.reconcile_resource('image', image_id, outcome='retained', size_bytes=image['Size'])
                    receipt['unknown_outcome'] = False; save(run, receipt)
                    receipt.update(image_id=image_id, local_tag=tag, image_size_bytes=image['Size'], status='completed')
                else:
                    observed = json.loads(logs['log'])
                    require(type(observed) is dict and observed.get('production_iso_eligible') is False and
                        observed.get('runtime_pipeline_complete') is False and observed.get('scanner_compatibility') == receipt['scanner_compatibility'] and
                        observed.get('operation') == ('optional-powershell-missing-package' if selection == 'missing-package-fixture' else 'optional-powershell-smoke'),
                        'capability_result_invalid')
                    require(value['State']['ExitCode'] == (1 if selection == 'missing-package-fixture' else 0) and
                        observed.get('status') == ('failed' if selection == 'missing-package-fixture' else 'passed'), 'capability_result_invalid')
                    receipt.update(observation=observed, status='failed' if selection == 'missing-package-fixture' else 'completed')
                    if selection == 'missing-package-fixture': receipt['primary_failure'] = {'code': 'package_unavailable'}
                cleanup(run, receipt, lease); save(run, receipt)
                return receipt
            except BaseException as error:
                if receipt['primary_failure'] is None: receipt['primary_failure'] = {'code': getattr(error, 'code', 'capability_interrupted')}
                receipt['status'] = 'failed'; save(run, receipt)
                if receipt['unknown_outcome'] is False:
                    try: cleanup(run, receipt, lease)
                    except BaseException as secondary:
                        receipt['cleanup_failures'].append({'code': getattr(secondary, 'code', 'capability_cleanup_interrupted')}); save(run, receipt)
                raise


def installed_record(container):
    result = images.docker(('cp', container + ':/opt/wormhole/capability-installed.json', '-'))
    require(not result['log_truncated'], 'capability_output_bound')
    with tarfile.open(fileobj=io.BytesIO(result['log']), mode='r:*') as archive:
        members = archive.getmembers()
        require(len(members) == 1 and members[0].isfile() and members[0].size <= 16384 and
            members[0].name == 'capability-installed.json', 'capability_result_invalid')
        value = json.loads(archive.extractfile(members[0]).read(16385))
    require(value.get('status') == 'passed' and value.get('production_iso_eligible') is False and
        value.get('operation') == 'optional-powershell-smoke' and value.get('powershell', {}).get('version') == '7.6.8', 'capability_result_invalid')
    return value


def recover(run):
    """Original-source known-ID teardown only. Unknown outcomes never gain a bypass."""
    from .admission import AdmissionLease
    require(sys.platform.startswith('linux') and run.workspace == images.RUNS_ROOT, 'capability_host_scope')
    with run.locked(), images.docker_scope(run):
        receipt = read_json(run.file('evidence/powershell-capability.json'))
        base = common(run.manifest()); recipe, files = recipe_identity()
        require(source_identity() == (base['source_revision'], False) and
            canonical({key: receipt[key] for key in base}) == canonical(base) and receipt['component'] == 'optional-powershell' and
            receipt['operation'] in ('build', 'probe') and receipt['selection'] in CHOICES and
            receipt['unknown_outcome'] is False and receipt['resources_reconciled'] is False and
            receipt['recipe_sha256'] == recipe and receipt['source_files'] == files and
            type(receipt['container_id']) is str and re.fullmatch('[a-f0-9]{64}', receipt['container_id']), 'capability_recovery_refused')
        role = 'helper-powershell' if receipt['operation'] == 'build' else 'helper-powershell-probe'
        require(receipt['labels'] == images.expected_labels(run, role, recipe, files['lock.json']), 'capability_recovery_refused')
        if receipt['operation'] == 'build':
            require(receipt['image'] == BASE and receipt['selection'] == 'powershell-helper', 'capability_recovery_refused')
            verify_bindings(run, receipt['mounts'], True)
        elif receipt['selection'] == 'missing-package-fixture':
            require(receipt['image'] == BASE and receipt['runtime_operation'] == 'missing', 'capability_recovery_refused')
            verify_bindings(run, receipt['mounts'], False, receipt['binding_identities'])
        else:
            require(receipt['runtime_operation'] == 'smoke' and not receipt['mounts'] and
                receipt['image'] == optional_image(receipt['build_run_id']), 'capability_recovery_refused')
        with AdmissionLease.resume(images.INFRASTRUCTURE, run.id, base['source_revision']) as lease:
            expected = lease.plan['limits']['build' if receipt['operation'] == 'build' else 'helper']
            require(canonical(receipt['limits']) == canonical(expected) and any(item['kind'] == 'container' and
                item['id'] == receipt['container_id'] and item['outcome'] == 'pending' for item in lease.record['resources']) and
                all(item['outcome'] != 'pending' or item['kind'] == 'container' and item['id'] == receipt['container_id']
                    for item in lease.record['resources']), 'capability_recovery_refused')
            cleanup(run, receipt, lease)
            return receipt


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Explicit optional PowerShell helper; no host installation or scanner invocation.')
    parser.add_argument('selection', choices=(*CHOICES, 'recover'))
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--build-run', help='Exact completed optional variant build Run for smoke; omitted means build.')
    parser.add_argument('--workspace', default=str(images.RUNS_ROOT))
    options = parser.parse_args(arguments)
    try:
        run = Run(options.workspace, options.run_id)
        result = recover(run) if options.selection == 'recover' else execute(run, selection=options.selection, build_run=options.build_run)
        print(json.dumps(result, sort_keys=True)); return 0 if result['status'] == 'completed' else 1
    except Exception as error:
        print(json.dumps({'error': {'code': getattr(error, 'code', 'capability_refused')}, 'production_iso_eligible': False})); return 2


if __name__ == '__main__': raise SystemExit(main())
