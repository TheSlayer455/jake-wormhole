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
                             docker_scope, docker_configuration)
from wormhole.runs import (Run, atomic_json, create_run, now, read_json, source_identity)
from wormhole.stages import _run_process
from images.runtime import public_key


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


def build_reference(identifier, role, revision):
    run = Run(RUNS_ROOT, identifier)
    value = read_json(run.file('evidence/image-build-' + role + '.json'))
    recipe, hashes = recipe_identity()
    require(value['status'] == 'completed' and value['resources_reconciled'] is True
            and value['role'] == role and value['run_id'] == identifier
            and value['source_revision'] == revision and value['recipe_sha256'] == recipe
            and value['source_files'] == hashes, 'build_not_qualified',
            'Use completed reconciled builds from this exact clean source and recipe.')
    require(type(value['image_id']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', value['image_id'])
            and run.manifest()['source_revision'] == revision
            and run.manifest()['source_dirty'] is False
            and run.manifest()['mode'] == 'container-reference',
            'build_not_qualified', 'Expected an exact image ID and real clean-source build run.')
    image = inspect('image', value['image_id'])
    labels = expected_labels(run, role, recipe, hashes['images.lock.json'])
    require(image['Id'] == value['image_id'] and image['Os'] == 'linux'
            and image['Architecture'] == 'amd64' and not image['Config'].get('Volumes')
            and all(image['Config'].get('Labels', {}).get(k) == v for k, v in labels.items()),
            'image_identity_mismatch', 'Actual image differs from its completed build identity.')
    return value['image_id']


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
            and set(host.get('CapDrop') or []) == {'ALL'}
            and set(host.get('CapAdd') or []) == (set(TARGET_CAPS) if role == 'target' else set())
            and set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'}, {'no-new-privileges'}),
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


def copied_public_key(container):
    result = docker(('cp', container + ':/run/wormhole/hostkeys/ssh_host_ed25519_key.pub', '-'))
    require(not result['log_truncated'], 'invalid_hostkey', 'Public host-key response exceeded its bound.')
    with tarfile.open(fileobj=io.BytesIO(result['log']), mode='r:*') as archive:
        members = archive.getmembers()
        require(len(members) == 1 and members[0].isfile()
                and members[0].name == 'ssh_host_ed25519_key.pub' and 1 <= members[0].size <= 512,
                'invalid_hostkey', 'Expected one bounded public host-key file.')
        return public_key(archive.extractfile(members[0]).read(513).decode('ascii'))


def inject_helper_inputs(run, helper, host_key, address):
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
    # No shell, no disk export, no key in argv/stdout. Preserve reviewed UID/mode
    # into helper-owned tmpfs with Docker's explicit archive ownership option.
    result = subprocess.run(['docker', '--config', docker_configuration(), '--host', SOCKET,
                             'cp', '-a', '-', helper + ':/run/input'],
                            input=data.getvalue(), capture_output=True, timeout=15,
                            env={k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'WINDIR') if k in os.environ})
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
        target_image = build_reference(target_build, 'target', revision)
        helper_image = build_reference(helper_build, 'helper', revision)
        receipt.update(target_image=target_image, helper_image=helper_image)
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
                        host_key = copied_public_key(target)
                        break
                    except ImageError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.2)
                records = [n for n in value['NetworkSettings']['Networks'].values() if n['NetworkID'] == network]
                require(len(records) == 1, 'endpoint_unavailable', 'Exact run-network endpoint is missing.')
                address = str(ipaddress.IPv4Address(records[0]['IPAddress']))
                inject_helper_inputs(run, helper, host_key, address)
                public_blob = base64.b64decode(host_key.split()[1], validate=True)
                receipt['hostkey_fingerprint'] = 'SHA256:' + base64.b64encode(hashlib.sha256(public_blob).digest()).decode().rstrip('=')
                receipt['hostkey_trust'] = 'exact-ID ownership-checked Docker control-plane public-key file; no TOFU'
                for identifier, role, _ in resources:
                    python = '/opt/wormhole/venv/bin/python' if role == 'helper' else '/usr/bin/python3'
                    result = docker(('exec', identifier, python, '/opt/wormhole/runtime.py', role, 'doctor'))
                    doctor = json.loads(result['log'])
                    require(doctor['passed'] is True and doctor['role'] == role, 'dependency_failed',
                            'Image-local doctor failed at location=' + role)
                    receipt[role + '_doctor'] = doctor
                remote = remote_probe()
                deadline = time.monotonic() + 20
                while True:
                    try:
                        result = docker(('exec', helper, '/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py',
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
                wrong_trust = ('docker', '--config', docker_configuration(), '--host', SOCKET,
                               'exec', helper, '/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py',
                               'helper', 'ssh', '-o', 'ConnectTimeout=3', '-o',
                               'UserKnownHostsFile=/run/input/wrong_known_hosts', '-p', '2222', '--',
                               'wormhole@' + address, '/usr/bin/true')
                refused = _run_process(wrong_trust, cwd=Path(__file__).resolve().parents[1], timeout=10)
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
                    require(negative['returncode'] == 255 and b'Permission denied' in negative['log']
                            and not negative['log_truncated'], 'authentication_not_rejected',
                            'Expected a specific SSH authentication refusal for ' + user)
                    rejected.append(user)
                receipt['negative_authentication'] = {'passed': True, 'denied_users': rejected,
                                                       'transport_or_trust_failure_substituted': False}
                receipt['status'] = 'passed'
            except BaseException as failure:
                receipt.update(status='failed', failure_code=getattr(failure, 'code', 'qualification_interrupted'))
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
