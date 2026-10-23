"""Admitted one-target image qualification, independent of the later TF pipeline."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import shlex
import sys
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wormhole.admission import AdmissionLease
from wormhole.images import (INFRASTRUCTURE, RUNS_ROOT, LABEL, SOCKET, TARGET_CAPS,
                             ImageError, cgroup_limits, create_auth, docker, inspect,
                             require, runtime_arguments, recipe_identity, expected_labels,
                             docker_scope, docker_configuration, capability_names)
from wormhole.runs import (Run, atomic_bytes, atomic_json, create_run, now, read_json, source_identity)
from wormhole.stages import _run_process
from images.runtime import public_key, RuntimeFailure

PUBLIC_KEY_READER = '''from pathlib import Path
import stat, sys
path = Path("/run/wormhole/hostkeys/ssh_host_ed25519_key.pub")
if any(p.is_symlink() for p in (path, *path.parents)): raise SystemExit(2)
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise SystemExit(2)
with path.open("rb") as stream: raw = stream.read(513)
if not 1 <= len(raw) <= 512: raise SystemExit(2)
sys.stdout.buffer.write(raw)
'''

INPUT_RECEIVER = '''import io, os, stat, sys, tarfile
from pathlib import Path
def receive_inputs(stream=None, root=Path("/run/input"), uid=10001, gid=None):
    if gid is None: gid = uid
    if stream is None: stream = sys.stdin.buffer
    raw = stream.read(65537)
    if not 1 <= len(raw) <= 65536: raise ValueError("archive bound")
    expected = {"id_ed25519": 16384, "known_hosts": 1024, "wrong_known_hosts": 1024}
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            if member.name not in expected or member.name in files or not member.isfile() or member.issparse(): raise ValueError("entry type/name")
            if member.uid != uid or member.gid != gid or member.mode != 0o600 or member.pax_headers: raise ValueError("entry ownership/mode")
            if not 1 <= member.size <= expected[member.name]: raise ValueError("entry bound")
            content = archive.extractfile(member).read(expected[member.name] + 1)
            if len(content) != member.size: raise ValueError("entry size")
            files[member.name] = content
    if set(files) != set(expected) or sum(map(len, files.values())) > 18432: raise ValueError("entry set/bound")
    if any(p.is_symlink() for p in (root, *root.parents)): raise ValueError("linked directory")
    mounts = []
    with open("/proc/self/mountinfo") as info:
        for line in info:
            fields, filesystem = line.rstrip().split(" - ", 1)
            mount = Path(fields.split()[4].replace("\\040", " "))
            if root.is_relative_to(mount): mounts.append((len(mount.parts), filesystem.split()[0]))
    if not mounts or max(mounts)[1] != "tmpfs": raise ValueError("tmpfs required")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o700 or os.listdir(descriptor): raise ValueError("directory ownership/state")
        for name, content in files.items():
            item = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            with os.fdopen(item, "wb") as output:
                output.write(content)
                output.flush()
                check = os.fstat(output.fileno())
                if check.st_uid != uid or check.st_gid != gid or stat.S_IMODE(check.st_mode) != 0o600 or check.st_nlink != 1: raise ValueError("created ownership/mode")
    finally:
        os.close(descriptor)
'''
INPUT_RECEIVER_COMMAND = INPUT_RECEIVER + '''
try:
    receive_inputs()
except Exception:
    print("helper input provisioning refused", file=sys.stderr)
    raise SystemExit(2)
'''


@contextmanager
def report_failures(receipt, destination):
    try:
        yield
    except BaseException as error:
        if receipt['status'] == 'pending':
            receipt.update(status='failed-before-allocation', resources_reconciled=True,
                           failure_code=getattr(error, 'code', 'qualification_refused'))
        receipt['finished_at'] = now()
        atomic_json(destination, receipt)
        error.run_id = receipt['run_id']
        raise


def remote_probe():
    source = ('import json,os,platform;print(json.dumps({'
              '"uid":os.getuid(),"python":platform.python_version(),'
              '"ubuntu":\'VERSION_ID="24.04"\' in open("/etc/os-release").read(),'
              '"docker_socket":os.path.exists("/var/run/docker.sock")}))')
    return '/usr/bin/python3 -c ' + shlex.quote(source)


def build_reference(identifier, role):
    """Bind an immutable build to its original Run and the current recipe bytes.

    Controller-only fixes need not rebuild unchanged image recipes. They cannot
    replace the build's original source attribution or accept changed recipes.
    """
    run = Run(RUNS_ROOT, identifier)
    value = read_json(run.file('evidence/image-build-' + role + '.json'))
    recipe, hashes = recipe_identity()
    require(type(value) is dict and value.get('schema_version') == '1.0'
            and value.get('operation') == 'ubuntu-image-assembly'
            and value.get('status') == 'completed' and value.get('resources_reconciled') is True
            and value.get('role') == role and value.get('run_id') == identifier
            and value.get('recipe_sha256') == recipe and value.get('source_files') == hashes,
            'build_not_qualified', 'Use completed reconciled role builds with the exact current image recipe files.')
    build_revision = value.get('source_revision')
    manifest = run.manifest()
    require(type(build_revision) is str and re.fullmatch(r'[a-f0-9]{40}', build_revision)
            and type(value.get('image_id')) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', value['image_id'])
            and manifest['source_revision'] == build_revision
            and manifest['source_dirty'] is False and manifest['mode'] == 'container-reference',
            'build_not_qualified', 'Expected an exact image ID and real clean-source build run.')
    image = inspect('image', value['image_id'])
    labels = expected_labels(run, role, recipe, hashes['images.lock.json'])
    require(image['Id'] == value['image_id'] and image['Os'] == 'linux'
            and image['Architecture'] == 'amd64' and not image['Config'].get('Volumes')
            and all(image['Config'].get('Labels', {}).get(k) == v for k, v in labels.items()),
            'image_identity_mismatch', 'Actual image differs from its completed build identity.')
    return {'image_id': value['image_id'], 'source_revision': build_revision,
            'recipe_sha256': recipe, 'source_files': hashes}


def owned_runtime(identifier, role, image, run, *, missing=False):
    value = inspect('container', identifier, missing=missing)
    if value is None:
        return None
    require(value['Id'] == identifier and value['Image'] == image
            and value['Config']['Labels'].get(LABEL + '.run_id') == run.id
            and value['Config']['Labels'].get(LABEL + '.role') == role,
            'ownership_mismatch', 'Runtime exact identity/image/labels changed.')
    return value


def runtime_inspection(identifier, role, image, network, run, limits):
    value = owned_runtime(identifier, role, image, run)
    host, config = value['HostConfig'], value['Config']
    expected = limits['docker_create']
    python = '/usr/bin/python3' if role == 'target' else '/opt/wormhole/venv/bin/python'
    require(config['Entrypoint'] == [python, '/opt/wormhole/runtime.py', role]
            and (config['Cmd'] in (None, []) if role == 'target' else config['Cmd'] == ['wait', '180'])
            and [v for v in config['Env'] if v.startswith('WORMHOLE_RUNTIME_TTL_SECONDS=')]
                == ['WORMHOLE_RUNTIME_TTL_SECONDS=' + str(limits['timeout_seconds'])],
            'unsafe_runtime', 'Runtime entrypoint or finite admitted lifetime changed.')
    require(value['Id'] == identifier and value['Image'] == image
            and config['Labels'].get(LABEL + '.run_id') == run.id
            and config['Labels'].get(LABEL + '.role') == role,
            'ownership_mismatch', 'Runtime exact identity/image/labels changed.')
    require(host['Memory'] == expected['memory_bytes']
            and host['MemorySwap'] == expected['memory_swap_bytes']
            and host['NanoCpus'] == expected['nano_cpus']
            and host['PidsLimit'] == expected['pids_limit']
            and host['LogConfig'] == {'Type': expected['log_driver'], 'Config': expected['log_opts']},
            'limits_not_enforced', 'Runtime resource/log bounds differ from admission.')
    require(host['Privileged'] is False and host['ReadonlyRootfs'] is True
            and host['NetworkMode'] == network and host['PidMode'] == ''
            and host.get('IpcMode') in ('', 'private') and host.get('UTSMode', '') == ''
            and not host.get('PortBindings') and not host.get('PublishAllPorts')
            and host['RestartPolicy']['Name'] == 'no'
            and config['User'] == ('0:0' if role == 'target' else '10001:10001')
            and capability_names(host.get('CapDrop')) == {'ALL'}
            and capability_names(host.get('CapAdd')) == (set(TARGET_CAPS) if role == 'target' else set())
            and set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'}, {'no-new-privileges=true'}, {'no-new-privileges'}),
            'unsafe_runtime', 'Runtime privilege/namespace settings were changed.')
    binds = [m for m in value['Mounts'] if m['Type'] != 'tmpfs']
    if role == 'target':
        require(len(binds) == 1 and binds[0]['Type'] == 'bind' and not binds[0]['RW']
                and binds[0]['Source'] == str(run.file('private/target-input'))
                and binds[0]['Destination'] == '/run/input',
                'unsafe_runtime', 'Target may mount only the exact public-key input.')
    else:
        require(not binds, 'unsafe_runtime', 'Helper must not have host bind mounts or sockets.')
    uid = '0' if role == 'target' else '10001'
    tmpfs = {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=' + uid + ',gid=' + uid,
             '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'}
    if role == 'helper':
        tmpfs['/run/input'] = 'rw,nosuid,nodev,noexec,size=64k,mode=0700,uid=10001,gid=10001'
    require(host['Tmpfs'] == tmpfs,
            'unsafe_runtime', 'Expected bounded private runtime tmpfs mounts.')
    return value


def cleanup_known_resources(lease, resources, network, run, *, unknown):
    """Attempt every exact-owned cleanup independently; never hide uncertainty."""
    failures = []
    def failed(kind, error):
        failures.append({'resource': kind, 'code': getattr(error, 'code', 'cleanup_interrupted')})
    try:
        lease.set_phase('reconciling')
    except BaseException as error:
        failed('lease', error)
        return failures  # No unguarded cleanup after losing ownership of the lease.
    for identifier, role, image in reversed(resources):
        try:
            value = owned_runtime(identifier, role, image, run, missing=True)
            if value is not None:
                # Limits may be damaged; exact ownership is sufficient to stop
                # this resource. Do not let one damaged helper strand its target.
                if value['State']['Running']:
                    docker(('stop', '--time', '3', identifier), timeout=10)
                docker(('rm', identifier))
                require(inspect('container', identifier, missing=True) is None,
                        'cleanup_unverified', 'Owned container absence is unverified.')
            lease.reconcile_resource('container', identifier)
        except BaseException as error:
            failed(role, error)
    if network is not None:
        try:
            actual = inspect('network', network, missing=True)
            if actual is not None:
                require(actual['Id'] == network and actual['Labels'].get(LABEL + '.run_id') == run.id
                        and not actual['Containers'], 'ownership_mismatch', 'Network cleanup ownership changed.')
                docker(('network', 'rm', network))
                require(inspect('network', network, missing=True) is None, 'cleanup_unverified', 'Network absence unverified.')
            lease.reconcile_resource('network', network)
        except BaseException as error:
            failed('network', error)
    for kind, args in (('container', ('ps', '-a')), ('network', ('network', 'ls')), ('volume', ('volume', 'ls'))):
        try:
            sweep = docker((*args, '--filter', 'label=' + LABEL + '.run_id=' + run.id,
                            '--format', '{{.ID}}' if kind != 'volume' else '{{.Name}}'))
            require(not sweep['log'].strip() and not sweep['log_truncated'], 'cleanup_unverified',
                    'Run-labeled resources remain after exact-ID cleanup.')
        except BaseException as error:
            failed(kind + '-sweep', error)
    if unknown:
        failures.append({'resource': 'allocation-intent', 'code': 'unknown_allocation'})
    return failures


def attempt_record(run, receipt, role, stage, result):
    """Private bounded diagnostics only; capture failure never masks the operation."""
    try:
        entries = receipt.setdefault('attempts', [])
        if len(entries) >= 128:
            return
        name = 'qualification-' + role + '-' + stage + '-' + str(len(entries)) + '.log'
        record = {'role': role, 'stage': stage, 'status': result['status'],
                  'returncode': result.get('returncode'), 'duration_seconds': result.get('duration_seconds'),
                  'log_truncated': result.get('log_truncated', False), 'private_log': 'private/' + name}
        entries.append(record)
        try:
            atomic_bytes(run.file('private/' + name), result.get('log', b'')[:65536], limit=65536)
        except Exception:
            record['diagnostic_write_failed'] = True
    except Exception:
        pass


def attempted_docker(run, receipt, role, stage, arguments, *, timeout=20, allow_failure=False):
    result = _run_process(('docker', '--config', docker_configuration(), '--host', SOCKET, *arguments),
                          cwd=Path(__file__).resolve().parents[1], timeout=timeout)
    attempt_record(run, receipt, role, stage, result)
    require(result['status'] != 'timeout', 'docker_request_unknown', 'Bounded qualification attempt timed out at ' + role + '/' + stage)
    require(result['status'] == 'pass' or allow_failure and result['status'] == 'fail',
            'qualification_attempt_failed', 'Qualification command failed at ' + role + '/' + stage)
    return result


def runtime_failure_logs(run, receipt, resources):
    for identifier, role, image in resources:
        try:
            if owned_runtime(identifier, role, image, run, missing=True) is not None:
                result = _run_process(('docker', '--config', docker_configuration(), '--host', SOCKET,
                                       'logs', '--tail', '1000', identifier),
                                      cwd=Path(__file__).resolve().parents[1], timeout=5)
                attempt_record(run, receipt, role, 'runtime-failure', result)
        except Exception as error:
            receipt.setdefault('diagnostic_failures', []).append({'role': role, 'code': getattr(error, 'code', 'diagnostic_unavailable')})


def copied_public_key(container, image, run, receipt):
    current = owned_runtime(container, 'target', image, run)
    require(current['State']['Running'], 'target_exited', 'Owned target must be running for its public host-key observation.')
    result = attempted_docker(run, receipt, 'target', 'public-hostkey',
        ('exec', '--user', '0:0', container, '/usr/bin/python3', '-I', '-S', '-c', PUBLIC_KEY_READER), timeout=5)
    require(not result['log_truncated'] and 1 <= len(result['log']) <= 512,
            'invalid_hostkey', 'Public host-key response exceeded its bound.')
    try:
        return public_key(result['log'].decode('ascii'))
    except (RuntimeFailure, ValueError, UnicodeError):
        raise ImageError('invalid_hostkey', 'Expected one plain bounded Ed25519 public host key.') from None


def inject_helper_inputs(run, helper, image, host_key, address, receipt):
    current = owned_runtime(helper, 'helper', image, run)
    require(current['State']['Running'] and current['Config']['User'] == '10001:10001',
            'unsafe_runtime', 'Private inputs require the exact running non-root helper.')
    path = run.file('private/credentials/id_ed25519')
    with path.open('rb') as stream:
        private = stream.read(16385)
    require(1 <= len(private) <= 16384, 'invalid_auth', 'Client private key exceeds its bound.')
    known = ('[' + address + ']:2222 ' + host_key + '\n').encode()
    with path.with_name('id_ed25519.pub').open('rb') as stream:
        other_key = public_key(stream.read(513).decode('ascii'))
    require(other_key != host_key, 'invalid_trust_fixture', 'Negative trust requires a distinct public key.')
    wrong_known = ('[' + address + ']:2222 ' + other_key + '\n').encode()
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as archive:
        for name, content in (('id_ed25519', private), ('known_hosts', known), ('wrong_known_hosts', wrong_known)):
            member = tarfile.TarInfo(name)
            member.uid = member.gid = 10001
            member.mode = 0o600
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    # Execute in the live mount namespace: Docker archive APIs have private tmpfs
    # views. No shell, key argv, generic extraction or arbitrary destination path.
    try:
        result = subprocess.run(['docker', '--config', docker_configuration(), '--host', SOCKET,
                                 'exec', '-i', '--user', '10001:10001', helper,
                                 '/opt/wormhole/venv/bin/python', '-I', '-S', '-c', INPUT_RECEIVER_COMMAND],
                                input=data.getvalue(), capture_output=True, timeout=15,
                                env={k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'WINDIR') if k in os.environ})
    except subprocess.TimeoutExpired as error:
        raw = (error.stdout or b'') + (error.stderr or b'')
        attempt_record(run, receipt, 'helper', 'auth-input', {'status': 'timeout', 'returncode': None,
                       'log': raw[:65536], 'log_truncated': len(raw) > 65536})
        raise ImageError('auth_injection_timeout', 'Private helper input receiver exceeded its bounded request deadline.') from None
    attempt_record(run, receipt, 'helper', 'auth-input', {'status': 'pass' if result.returncode == 0 else 'fail',
        'returncode': result.returncode, 'log': (result.stdout + result.stderr)[:65536],
        'log_truncated': len(result.stdout) + len(result.stderr) > 65536})
    require(result.returncode == 0, 'auth_injection_failed', 'Private helper tmpfs input provisioning failed.')


def qualify(target_build, helper_build):
    require(sys.platform.startswith('linux'), 'linux_required', 'Real image qualification requires the approved Linux host.')
    revision, dirty = source_identity()
    require(not dirty, 'source_not_clean', 'Qualification requires a clean exact-source checkout.')
    run = create_run(RUNS_ROOT, fixture=False)
    receipt = {'schema_version': '1.0', 'operation': 'image-ssh-qualification',
               'run_id': run.id, 'source_revision': revision, 'started_at': now(),
               'target_build_run': target_build, 'helper_build_run': helper_build,
               'status': 'pending', 'runtime_pipeline_complete': False,
               'production_iso_eligible': False, 'independent_human_review': False}
    destination = run.file('evidence/image-qualification.json')
    atomic_json(destination, receipt)
    resources, network = [], None
    unknown = False
    with report_failures(receipt, destination), docker_scope(run):
        target_reference = build_reference(target_build, 'target')
        helper_reference = build_reference(helper_build, 'helper')
        require(target_reference['recipe_sha256'] == helper_reference['recipe_sha256']
                and target_reference['source_files'] == helper_reference['source_files'],
                'recipe_changed', 'The controller recipe changed while validating build references.')
        target_image, helper_image = target_reference['image_id'], helper_reference['image_id']
        receipt.update(target_image=target_image, helper_image=helper_image,
                       target_build_source_revision=target_reference['source_revision'],
                       helper_build_source_revision=helper_reference['source_revision'],
                       recipe_sha256=target_reference['recipe_sha256'], source_files=target_reference['source_files'])
        receipt['authentication'] = create_auth(run)
        with run.locked(), AdmissionLease(INFRASTRUCTURE, run.id, revision, 'smoke') as lease:
            try:
                require(run.file('private/credentials/id_ed25519').exists(), 'auth_missing',
                        'Qualification authentication must be provisioned before operation lock.')
                lease.set_phase('provisioning')
                unknown = True
                result = docker(('network', 'create', '--internal', '--driver', 'bridge',
                                 '--label', LABEL + '.run_id=' + run.id, 'wormhole-' + run.id + '-qualify'))
                network = result['log'].decode().strip()
                lease.register_resource('network', network)
                unknown = False
                actual = inspect('network', network)
                require(actual['Id'] == network and actual['Internal'] is True
                        and actual['Labels'].get(LABEL + '.run_id') == run.id,
                        'ownership_mismatch', 'Qualification network identity/settings changed.')
                for role, image in (('target', target_image), ('helper', helper_image)):
                    lease.set_phase('provisioning')
                    unknown = True
                    result = docker(runtime_arguments(run, role, image, network, lease.plan['limits'][role], helper_wait=180))
                    identifier = result['log'].decode().strip()
                    lease.register_resource('container', identifier)
                    resources.append((identifier, role, image))
                    unknown = False
                    value = runtime_inspection(identifier, role, image, network, run, lease.plan['limits'][role])
                    require(value['State']['Status'] == 'created' and not value['State']['Running'],
                            'unsafe_runtime', 'Runtime must be inspected stopped before start.')
                    docker(('start', identifier))
                    value = runtime_inspection(identifier, role, image, network, run, lease.plan['limits'][role])
                    require(value['State']['Running'], 'runtime_failed', 'Owned runtime did not stay running.')
                    receipt[role + '_cgroups'] = cgroup_limits(value['State']['Pid'], lease.plan['limits'][role]['docker_create'])
                lease.set_phase('validating')
                target, helper = resources[0][0], resources[1][0]
                deadline = time.monotonic() + 20
                while True:
                    value = runtime_inspection(target, 'target', target_image, network, run, lease.plan['limits']['target'])
                    require(value['State']['Running'], 'target_exited', 'Target exited before SSH qualification.')
                    # The trusted exact-ID control plane supplies the public identity.
                    try:
                        host_key = copied_public_key(target, target_image, run, receipt)
                        break
                    except ImageError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.2)
                records = [n for n in value['NetworkSettings']['Networks'].values() if n['NetworkID'] == network]
                require(len(records) == 1, 'endpoint_unavailable', 'Exact run-network endpoint is missing.')
                address = str(ipaddress.IPv4Address(records[0]['IPAddress']))
                inject_helper_inputs(run, helper, helper_image, host_key, address, receipt)
                public_blob = base64.b64decode(host_key.split()[1], validate=True)
                receipt['hostkey_fingerprint'] = 'SHA256:' + base64.b64encode(hashlib.sha256(public_blob).digest()).decode().rstrip('=')
                receipt['hostkey_trust'] = 'exact-ID ownership-checked Docker control-plane public-key file; no TOFU'
                for identifier, role, _ in resources:
                    python = '/opt/wormhole/venv/bin/python' if role == 'helper' else '/usr/bin/python3'
                    result = attempted_docker(run, receipt, role, 'doctor', ('exec', identifier, python, '/opt/wormhole/runtime.py', role, 'doctor'), allow_failure=True)
                    require(not result['log_truncated'], 'dependency_failed', 'Image-local doctor output exceeded its bound at location=' + role)
                    doctor = json.loads(result['log'])
                    receipt[role + '_doctor'] = doctor
                    require(result['status'] == 'pass' and doctor['passed'] is True and doctor['role'] == role, 'dependency_failed',
                            'Image-local doctor failed at location=' + role)
                remote = remote_probe()
                deadline = time.monotonic() + 20
                while True:
                    try:
                        result = attempted_docker(run, receipt, 'helper', 'ssh', ('exec', helper, '/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py',
                                         'helper', 'ssh', '-o', 'ConnectTimeout=3', '-p', '2222', '--',
                                         'wormhole@' + address, remote), timeout=10)
                        observed = json.loads(result['log'])
                        break
                    except ImageError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.2)
                require(observed == {'uid': 10001, 'python': '3.12.3', 'ubuntu': True, 'docker_socket': False},
                        'ssh_check_failed', 'Actual authenticated SSH user/tools differ from the image contract.')
                receipt['ssh'] = {'passed': True, 'observed': observed, 'strict_host_key_checking': True,
                                  'public_key_authentication': True, 'private_key_exported': False}
                wrong_trust = ('exec', helper, '/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py',
                               'helper', 'ssh', '-o', 'ConnectTimeout=3', '-o',
                               'UserKnownHostsFile=/run/input/wrong_known_hosts', '-p', '2222', '--',
                               'wormhole@' + address, '/usr/bin/true')
                refused = _run_process(('docker', '--config', docker_configuration(), '--host', SOCKET, *wrong_trust), cwd=Path(__file__).resolve().parents[1], timeout=10)
                attempt_record(run, receipt, 'helper', 'negative-trust', refused)
                require(refused['returncode'] == 255 and b'Host key verification failed' in refused['log']
                        and not refused['log_truncated'], 'hostkey_trust_not_rejected',
                        'An intentionally wrong host key must fail specifically at host-key verification.')
                receipt['negative_hostkey_trust'] = {'passed': True, 'verification_disabled': False,
                                                       'specific_hostkey_refusal_observed': True}
                rejected = []
                for user in ('root', 'wormhole-nonexistent'):
                    command = ('docker', '--config', docker_configuration(), '--host', SOCKET,
                               'exec', helper, '/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py',
                               'helper', 'ssh', '-o', 'ConnectTimeout=3', '-p', '2222', '--',
                               user + '@' + address, '/usr/bin/true')
                    negative = _run_process(command, cwd=Path(__file__).resolve().parents[1], timeout=10)
                    attempt_record(run, receipt, 'helper', 'negative-auth', negative)
                    require(negative['returncode'] == 255 and b'Permission denied' in negative['log']
                            and not negative['log_truncated'], 'authentication_not_rejected',
                            'Expected a specific SSH authentication refusal for ' + user)
                    rejected.append(user)
                receipt['negative_authentication'] = {'passed': True, 'denied_users': rejected,
                                                       'transport_or_trust_failure_substituted': False}
                receipt['status'] = 'passed'
            except BaseException as failure:
                receipt.update(status='failed', failure_code=getattr(failure, 'code', 'qualification_interrupted'))
                runtime_failure_logs(run, receipt, resources)
                raise
            finally:
                try:
                    cleanup_failures = cleanup_known_resources(lease, resources, network, run, unknown=unknown)
                    receipt['cleanup_failures'] = cleanup_failures
                    require(not cleanup_failures, 'cleanup_unverified', 'Known resources remain unresolved; preserve admission.')
                    lease.finish(reconciliation_complete=True)
                    receipt['resources_reconciled'] = True
                    manifest = run.manifest()
                    manifest.update(outcome='cleaned' if receipt['status'] == 'passed' else 'failed', updated_at=now())
                    run.save_manifest(manifest)
                except BaseException as cleanup_failure:
                    receipt.update(resources_reconciled=False, cleanup_failure_code=getattr(cleanup_failure, 'code', 'cleanup_interrupted'))
                    if receipt['status'] == 'passed':
                        receipt['status'] = 'unresolved'
                        raise
                finally:
                    receipt['finished_at'] = now()
                    atomic_json(destination, receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-build-run', required=True)
    parser.add_argument('--helper-build-run', required=True)
    args = parser.parse_args()
    try:
        result = qualify(args.target_build_run, args.helper_build_run)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({'run_id': getattr(error, 'run_id', None), 'error': {'code': getattr(error, 'code', 'qualification_refused'),
                                   'message': 'Image qualification failed; inspect private receipt and preserved admission state.'}}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
