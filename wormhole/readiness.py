"""Run-scoped genuine helper SSH/Ansible readiness under an existing lease."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import time

from scripts import qualify_images as qualification
from . import images
from .runs import Run, RunError, SOURCE_ROOT, atomic_json, common, now, read_json, source_identity
from .stages import _run_process

HELPER_BUILD = '9e864d00-ea9f-4a85-bdb5-f5873166e4d7'
HELPER_IMAGE = 'sha256:4f7f306ecd431b4b48169777966d88c1f09f2139506176a6b85203f5bae69a71'
RUNTIME = SOURCE_ROOT / 'readiness/runtime.py'
SOURCE_MOUNT = '/opt/readiness/runtime.py'
VALIDATION_RUNTIME = SOURCE_ROOT / 'validation/runtime.py'
VALIDATION_MOUNT = '/opt/validation/runtime.py'
FLEET_INVENTORY_RUNTIME = SOURCE_ROOT / 'fleet_inventory/runtime.py'
FLEET_INVENTORY_MOUNT = '/opt/wormhole/fleet-inventory.py'
SCENARIOS = ('healthy', 'wrong-key', 'wrong-user', 'configured-interpreter-unavailable')
EXPECTED = ('created', 'started', 'endpoint-discovered', 'tcp-reachable', 'ssh-identity-accepted',
            'python-usable', 'ansible-usable', 'required-test-complete')
ID = re.compile('[a-f0-9]{64}\\Z')
TIMEOUT = 90
RETRY_SLEEP = .2
CATEGORIES = {'output_bound', 'probe_timeout', 'ssh_host_key_mismatch', 'ssh_key_rejected', 'ssh_user_rejected',
    'ssh_authentication_refused', 'configured_interpreter_unavailable', 'ssh_transport_pending', 'ansible_unusable',
    'ssh_probe_failed', 'tcp_pending'}


class ReadinessError(RunError):
    pass


def require(value, code):
    if not value:
        raise ReadinessError(code, 'Readiness failed; inspect bounded private evidence and preserve resource accounting.')


def code_hash(path):
    require(path.is_file() and not any(item.is_symlink() for item in (path, *path.parents)) and
            path.stat().st_nlink == 1, 'source_changed')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    require(1 <= len(raw) <= 65536, 'source_changed')
    return hashlib.sha256(raw).hexdigest()


def runtime_hash():
    return code_hash(RUNTIME)


def readiness_status(run):
    """Read-only retained outcome for recovery, including a refusal to clean up."""
    value = read_json(run.file('evidence/readiness.json'))
    manifest = run.manifest()
    require(type(value) is dict and common(value) == common(manifest) and manifest['mode'] == 'container-reference' and
        manifest['source_dirty'] is False and value.get('operation') == 'ssh-ansible-readiness' and
        value.get('status') in {'pending', 'waiting', 'ready', 'failed'} and
        type(value.get('unknown_outcome')) is bool and value.get('cleanup') in {'not-started', 'failed', 'completed'} and
        (value.get('helper_id') is None or type(value['helper_id']) is str and ID.fullmatch(value['helper_id'])),
        'helper_recovery_scope')
    failure = value.get('primary_failure')
    require(failure is None or type(failure) is dict and set(failure) == {'code', 'recorded_at'} and
        type(failure['code']) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', failure['code']) and
        type(failure['recorded_at']) is str and len(failure['recorded_at']) <= 40, 'helper_recovery_scope')
    if failure is not None:
        try:
            stamp = datetime.fromisoformat(failure['recorded_at'].replace('Z', '+00:00'))
            require(stamp.tzinfo is not None, 'helper_recovery_scope')
        except ValueError:
            raise ReadinessError('helper_recovery_scope', 'Retained readiness failure timestamp is invalid.') from None
    return {key: deepcopy(value[key]) for key in ('status', 'primary_failure', 'unknown_outcome', 'cleanup', 'helper_id')}


class ReadinessSession:
    """Caller holds the Run lock, Docker scope and exact provisioning lease.

    on_poll is a trusted in-process coordinator callback, never imported text,
    ticket code, an executable argument or a second admission lease.
    """
    def __init__(self, provisioning, *, scenario='healthy', helper_build_run=HELPER_BUILD, validation=False):
        self.provisioning, self.run, self.lease = provisioning, provisioning.run, provisioning.lease
        self.lease._active()
        manifest = self.run.manifest()
        revision, dirty = source_identity()
        require(scenario in SCENARIOS and helper_build_run == HELPER_BUILD and type(validation) is bool,
                'unsupported_readiness_scenario')
        require(revision == manifest['source_revision'] and dirty is False and manifest['source_dirty'] is False and
            manifest['mode'] == 'container-reference' and self.lease.run_id == self.run.id and
            self.lease.source_revision == revision and self.lease.plan['synthetic'] is False and
            self.lease.plan['profile'] == 'smoke' and self.lease.plan['target_count'] == 1 and
            not self.lease._reconciliation_only, 'readiness_scope')
        indexed = getattr(provisioning, 'target_resources', None)
        require((type(indexed) is dict and set(indexed) == {'target-001'} or
                set(provisioning.owned) == {'docker_container.target', 'docker_network.run'}) and
                provisioning.receipt['unknown_outcome'] is False, 'provisioning_not_ready')
        self.scenario, self.reconciliation_only = scenario, False
        self.network = provisioning.owned['docker_network.run']
        self.target = indexed['target-001'] if type(indexed) is dict else provisioning.owned['docker_container.target']
        self.helper = None
        self.image_labels = None
        self.began = time.monotonic()
        self.deadline = self.began + TIMEOUT
        self.trust_address = None
        self.pinned_key = None
        self.counts = {}
        self.last_pending = 'target_not_started'
        self.source_sha256 = runtime_hash()
        self.bind_path = self.run.file('private/helper-source/runtime.py')
        self.bind_identity = None
        self.validation_enabled = validation
        self.validation_source_sha256 = code_hash(VALIDATION_RUNTIME) if validation else None
        self.validation_bind_path = self.run.file('private/helper-source/validation.py')
        self.validation_bind_identity = None
        self.receipt = {**common(manifest), 'operation': 'ssh-ansible-readiness', 'scenario': scenario,
            'status': 'pending', 'target_id': 'target-001', 'target_resource_id': self.target,
            'helper_id': None, 'helper_image': HELPER_IMAGE, 'helper_build_run': HELPER_BUILD,
            'expected_checks': list(EXPECTED), 'transitions': [], 'probes': [], 'attempts': [],
            'primary_failure': None, 'secondary_failures': [], 'cleanup': 'not-started', 'unknown_outcome': False,
            'configured_interpreter_absence_is_package_absence': False,
            'runtime_pipeline_complete': False, 'production_iso_eligible': False}

    def held(self):
        self.lease._active()
        manifest = self.run.manifest()
        require(self.lease.run_id == self.run.id and self.lease.source_revision == manifest['source_revision'] and
            self.lease.plan['synthetic'] is False and self.lease._reconciliation_only is self.reconciliation_only,
            'readiness_scope')

    def stage_name(self, operation):
        return operation

    def timeout(self, maximum=20):
        remaining = self.deadline - time.monotonic()
        require(remaining > .05, self.last_pending)
        return min(maximum, remaining)

    def inspect(self, kind, identifier, **options):
        value = images.inspect(kind, identifier, timeout=self.timeout(), **options)
        self.timeout()  # A late response is never accepted as within the deadline.
        return value

    def helper_reference(self):
        build = Run(images.RUNS_ROOT, HELPER_BUILD)
        value = read_json(build.file('evidence/image-build-helper.json'))
        manifest = build.manifest()
        recipe, hashes = images.recipe_identity()
        require(value.get('schema_version') == '1.0' and value.get('operation') == 'ubuntu-image-assembly' and
            value.get('status') == 'completed' and value.get('resources_reconciled') is True and
            value.get('role') == 'helper' and value.get('run_id') == HELPER_BUILD and value.get('image_id') == HELPER_IMAGE and
            value.get('recipe_sha256') == recipe and value.get('source_files') == hashes and
            value.get('source_revision') == manifest['source_revision'] and manifest['source_dirty'] is False and
            manifest['mode'] == 'container-reference', 'helper_image_mismatch')
        image = self.inspect('image', HELPER_IMAGE)
        labels = images.expected_labels(build, 'helper', recipe, hashes['images.lock.json'])
        require(image.get('Id') == HELPER_IMAGE and image.get('Os') == 'linux' and image.get('Architecture') == 'amd64' and
            not image['Config'].get('Volumes') and all(image['Config'].get('Labels', {}).get(k) == v for k, v in labels.items()),
            'helper_image_mismatch')
        return image['Config'].get('Labels') or {}

    def helper_policy(self):
        """Exact profile policy, independent of mutable receipt/controller fields."""
        profile = getattr(getattr(self, 'target_plan', None), 'profile', 'smoke')
        require(profile in {'smoke', 'five-targets', 'twenty-targets'}, 'readiness_scope')
        return {'wait_seconds': 300, 'input_tmpfs_bytes': 524288} if profile == 'twenty-targets' else {
            'wait_seconds': 180, 'input_tmpfs_bytes': 65536}

    def source_bindings(self):
        """Fixed reviewed files only; callers cannot supply executable paths."""
        require(type(self.validation_enabled) is bool and
            self.bind_path == self.run.file('private/helper-source/runtime.py') and
            self.validation_bind_path == self.run.file('private/helper-source/validation.py'), 'helper_source_invalid')
        bindings = [(RUNTIME, self.bind_path, self.source_sha256, 'bind_identity', SOURCE_MOUNT)]
        if self.validation_enabled:
            require(type(self.validation_source_sha256) is str and
                    re.fullmatch('[a-f0-9]{64}', self.validation_source_sha256), 'helper_source_invalid')
            bindings.append((VALIDATION_RUNTIME, self.validation_bind_path, self.validation_source_sha256,
                             'validation_bind_identity', VALIDATION_MOUNT))
        else:
            require(self.validation_source_sha256 is None and self.validation_bind_identity is None,
                    'helper_source_invalid')
        enabled = getattr(self, 'fleet_inventory_enabled', False)
        require(type(enabled) is bool, 'helper_source_invalid')
        if enabled:
            require(getattr(getattr(self, 'target_plan', None), 'profile', None) == 'twenty-targets' and
                self.fleet_inventory_bind_path == self.run.file('private/helper-source/fleet-inventory.py') and
                type(self.fleet_inventory_source_sha256) is str and
                re.fullmatch('[a-f0-9]{64}', self.fleet_inventory_source_sha256), 'helper_source_invalid')
            bindings.append((FLEET_INVENTORY_RUNTIME, self.fleet_inventory_bind_path, self.fleet_inventory_source_sha256,
                             'fleet_inventory_bind_identity', FLEET_INVENTORY_MOUNT))
        else:
            require(getattr(self, 'fleet_inventory_source_sha256', None) is None and
                getattr(self, 'fleet_inventory_bind_identity', None) is None, 'helper_source_invalid')
        return bindings

    def prepare_source_copy(self):
        """Expose only public reviewed code, never the private checkout ancestry."""
        bindings = self.source_bindings()
        require(all(getattr(self, item[3]) is None for item in bindings) and
                not self.bind_path.parent.exists(), 'helper_source_reused')
        self.bind_path.parent.mkdir(mode=0o700)
        identities = {}
        for original, destination, digest, identity_name, _ in bindings:
            require(code_hash(original) == digest, 'source_changed')
            with original.open('rb') as stream:
                raw = stream.read(65537)
            require(1 <= len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == digest, 'source_changed')
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                if hasattr(os, 'fchmod'):
                    os.fchmod(stream.fileno(), 0o444)
                else:  # Test-only Windows work; real admission is Linux-only.
                    os.chmod(destination, 0o444)
                info = os.fstat(stream.fileno())
            identities[identity_name] = {key: getattr(info, 'st_' + field) for key, field in
                (('device', 'dev'), ('inode', 'ino'), ('uid', 'uid'), ('gid', 'gid'), ('size', 'size'))}
        for name, identity in identities.items():
            setattr(self, name, identity)
        self.validate_source_copy()

    def validate_source_copy(self):
        bindings = self.source_bindings()
        folder = self.bind_path.parent.lstat()
        require(stat.S_ISDIR(folder.st_mode) and not self.bind_path.parent.is_symlink() and
            set(os.listdir(self.bind_path.parent)) == {item[1].name for item in bindings} and
            (os.name != 'posix' or folder.st_uid == os.getuid() and stat.S_IMODE(folder.st_mode) == 0o700), 'helper_source_invalid')
        for original, destination, digest, identity_name, _ in bindings:
            identity = getattr(self, identity_name)
            require(type(identity) is dict and set(identity) == {'device', 'inode', 'uid', 'gid', 'size'} and
                all(type(value) is int and value >= 0 for value in identity.values()) and
                identity['inode'] > 0 and 1 <= identity['size'] <= 65536, 'helper_source_invalid')
            before = destination.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                (os.name != 'posix' or before.st_uid == os.getuid() and before.st_gid == os.getgid() and stat.S_IMODE(before.st_mode) == 0o444) and
                all(getattr(before, 'st_' + field) == identity[key] for key, field in
                    (('device', 'dev'), ('inode', 'ino'), ('uid', 'uid'), ('gid', 'gid'), ('size', 'size'))), 'helper_source_invalid')
            descriptor = os.open(destination, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                current = os.fstat(stream.fileno())
                require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino), 'helper_source_invalid')
                raw = stream.read(65537)
            after = destination.lstat()
            require((after.st_dev, after.st_ino, after.st_size) == (before.st_dev, before.st_ino, before.st_size) and
                after.st_uid == before.st_uid and after.st_gid == before.st_gid and after.st_nlink == 1 and
                stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode) and
                1 <= len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == digest and code_hash(original) == digest,
                'helper_source_invalid')

    def save(self):
        self.receipt['updated_at'] = now()
        self.receipt['helper_id'] = self.helper
        atomic_json(self.run.file('evidence/readiness.json'), self.receipt)
        atomic_json(self.run.file('private/readiness-controller.json'), {**common(self.run.manifest()),
            'operation': 'readiness-helper', 'helper_id': self.helper, 'helper_image': HELPER_IMAGE,
            'network_id': self.network, 'target_resource_id': self.target, 'image_labels': self.image_labels,
            'source_path': str(RUNTIME), 'source_sha256': self.source_sha256,
            'bind_path': str(self.bind_path), 'bind_identity': self.bind_identity,
            'layout_version': 2, 'validation_enabled': self.validation_enabled,
            'validation_source_sha256': self.validation_source_sha256,
            'validation_bind_identity': self.validation_bind_identity,
            'unknown_outcome': self.receipt['unknown_outcome'], 'cleanup': self.receipt['cleanup']})

    def failure(self, error):
        code = getattr(error, 'code', 'readiness_failed')
        code = code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', code) else 'readiness_failed'
        value = {'code': code, 'recorded_at': now()}
        if self.receipt['primary_failure'] is None:
            self.receipt['primary_failure'] = value
        else:
            self.receipt['secondary_failures'].append(value)
        self.receipt['status'] = 'failed'
        self.save()

    def transition(self, check):
        require(check in EXPECTED, 'unexpected_readiness_check')
        if check not in {x['check_id'] for x in self.receipt['transitions']}:
            self.receipt['transitions'].append({'check_id': check, 'target_id': getattr(self, 'selected_target', None) or 'target-001', 'status': 'pass',
                'observed_at': now(), 'elapsed_seconds': time.monotonic() - self.began})
            self.save()

    def verify_helper(self, value, *, stopped=False, ownership_only=False):
        require(type(value) is dict and value.get('Id') == self.helper and value.get('Image') == HELPER_IMAGE and
            value.get('Name') == '/wormhole-' + self.run.id + '-helper' and
            value.get('Config', {}).get('Labels') == {**self.image_labels, images.LABEL + '.run_id': self.run.id,
                images.LABEL + '.role': 'helper', images.LABEL + '.source_revision': self.run.manifest()['source_revision']},
            'helper_ownership_mismatch')
        if ownership_only:
            return
        host, config = value['HostConfig'], value['Config']
        expected = self.lease.plan['limits']['helper']['docker_create']
        policy = self.helper_policy()
        require(config.get('User') == '10001:10001' and config.get('Entrypoint') ==
            ['/opt/wormhole/venv/bin/python', '/opt/wormhole/runtime.py', 'helper'] and config.get('Cmd') == ['wait', str(policy['wait_seconds'])] and
            {x for x in config.get('Env', []) if x.startswith('WORMHOLE_')} ==
            {'WORMHOLE_RUN_ID=' + self.run.id, 'WORMHOLE_RUNTIME_TTL_SECONDS=600'}, 'unsafe_helper')
        require(host.get('Memory') == expected['memory_bytes'] and host.get('MemorySwap') == expected['memory_swap_bytes'] and
            host.get('NanoCpus') == expected['nano_cpus'] and host.get('PidsLimit') == expected['pids_limit'] and
            host.get('LogConfig') == {'Type': expected['log_driver'], 'Config': expected['log_opts']} and
            host.get('Privileged') is False and host.get('ReadonlyRootfs') is True and
            host.get('PidMode', '') == '' and host.get('IpcMode') in ('', 'private') and host.get('UTSMode', '') == '' and
            not host.get('PortBindings') and not host.get('PublishAllPorts') and host.get('RestartPolicy', {}).get('Name') == 'no' and
            images.capability_names(host.get('CapDrop')) == {'ALL'} and not host.get('CapAdd') and
            set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'}, {'no-new-privileges=true'}, {'no-new-privileges'}), 'unsafe_helper')
        endpoints = value.get('NetworkSettings', {}).get('Networks', {})
        require(host.get('NetworkMode') == self.network and type(endpoints) is dict and len(endpoints) == 1 and
            next(iter(endpoints.values())).get('NetworkID') in ({'', self.network} if stopped else {self.network}), 'helper_network_mismatch')
        binds = [x for x in value.get('Mounts', []) if x['Type'] != 'tmpfs']
        expected_binds = {(str(item[1]), item[4]) for item in self.source_bindings()}
        require(len(binds) == len(expected_binds) and
            all(x['Type'] == 'bind' and x['RW'] is False for x in binds) and
            {(x['Source'], x['Destination']) for x in binds} == expected_binds and
            host.get('Tmpfs') == {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=10001,gid=10001',
                '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777',
                '/run/input': 'rw,nosuid,nodev,noexec,size=' + ('512k' if policy['input_tmpfs_bytes'] == 524288 else '64k') +
                    ',mode=0700,uid=10001,gid=10001'}, 'unsafe_helper_mounts')
        self.validate_source_copy()
        if stopped:
            require(value['State']['Running'] is False and value['State']['Status'] == 'created' and
                    value['State']['StartedAt'] == '0001-01-01T00:00:00Z', 'helper_premature_start')
        else:
            require(value['State']['Running'] is True, 'helper_exited')

    def start_helper(self):
        self.held()
        require(self.helper is None and not self.receipt['unknown_outcome'] and not self.reconciliation_only, 'helper_attempt_reused')
        try:
            self.image_labels = self.helper_reference()
            self.prepare_source_copy()
            policy = self.helper_policy()
            arguments = images.runtime_arguments(self.run, 'helper', HELPER_IMAGE, self.network,
                self.lease.plan['limits']['helper'], helper_wait=policy['wait_seconds'],
                helper_input_tmpfs_bytes=policy['input_tmpfs_bytes'])
            additions = []
            for _, destination, _, _, mount in self.source_bindings():
                additions += ['--mount', 'type=bind,source=' + str(images.safe_bind(destination)) + ',target=' + mount + ',readonly']
            arguments[-3:-3] = additions + ['--label', images.LABEL + '.source_revision=' + self.run.manifest()['source_revision']]
            self.lease.set_phase('provisioning')  # Fresh capacity under the same canonical flock.
            self.timeout()
            self.receipt['unknown_outcome'] = True
            self.save()
            result = images.docker(arguments, timeout=self.timeout())
            text = result['log'].decode('ascii').strip()
            require(not result['log_truncated'] and ID.fullmatch(text), 'helper_create_unknown')
            self.helper = text
            self.lease.register_resource('container', text)
            self.receipt['unknown_outcome'] = False
            self.save()
            self.verify_helper(self.inspect('container', text), stopped=True)
            self.receipt['unknown_outcome'] = True
            self.save()
            images.docker(('start', text), timeout=self.timeout())
            self.receipt['unknown_outcome'] = False
            self.save()
            actual = self.inspect('container', text)
            self.verify_helper(actual)
            self.receipt['cgroups'] = images.cgroup_limits(actual['State']['Pid'], self.lease.plan['limits']['helper']['docker_create'])
            self.receipt['unknown_outcome'] = False
            self.receipt['status'] = 'waiting'
            self.save()
            self.lease.set_phase('validating')
            self.timeout()
        except BaseException as error:
            self.failure(error)
            raise

    def endpoint(self):
        target = self.inspect('container', self.target)
        self.provisioning.verify_target(target, stopped=target.get('State', {}).get('Status') == 'created', inspection_timeout=self.timeout())
        self.timeout()
        self.transition('created')
        if target['State']['Status'] == 'created':
            self.last_pending = 'target_not_started'
            return None
        require(target['State']['Running'] is True, 'target_exited')
        self.transition('started')
        started = datetime.fromisoformat(target['State']['StartedAt'].replace('Z', '+00:00'))
        self.last_started_at = target['State']['StartedAt']
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        require(started.tzinfo is not None and 0 <= elapsed < 300 and
                300 - elapsed >= max(0, self.deadline - time.monotonic()) + 20, 'target_lifetime_budget_insufficient')
        inventory = self.provisioning.receipt.get('inventory')
        require(type(inventory) is dict and common(inventory) == common(self.run.manifest()) and
                type(inventory.get('targets')) is list and len(inventory['targets']) == 1, 'inventory_unavailable')
        item = inventory['targets'][0]
        networks = target['NetworkSettings']['Networks']
        address = item.get('host')
        try:
            parsed = ipaddress.ip_address(address)
        except (ValueError, TypeError):
            raise ReadinessError('inventory_endpoint_mismatch', 'Provider inventory does not match the exact owned target.') from None
        require(item.get('target_id') == (getattr(self, 'selected_target', None) or 'target-001') and item.get('resource_id') == self.target and
            item.get('ssh_port') == 2222 and item.get('ssh_user') == 'wormhole' and parsed.version == 4 and
            not parsed.is_loopback and not parsed.is_unspecified and len(networks) == 1 and
            next(iter(networks.values())).get('NetworkID') == self.network and
            next(iter(networks.values())).get('IPAddress') == address, 'inventory_endpoint_mismatch')
        if self.trust_address is not None:
            require(address == self.trust_address, 'inventory_endpoint_changed')
        self.transition('endpoint-discovered')
        return address

    def pin_trust(self):
        self.held()
        require(self.helper is not None and not self.reconciliation_only, 'helper_missing')
        self.verify_helper(self.inspect('container', self.helper))
        address = self.endpoint()
        if address is None:
            return False
        if self.pinned_key is not None:
            return True  # Never replace an established pin after an identity change.
        try:
            key = self.public_key()
        except images.ImageError as error:
            if error.code == 'qualification_attempt_failed':
                self.last_pending = 'hostkey_not_available'
                self.save()
                return False
            raise
        self.inject_inputs(key, address)
        self.pinned_key, self.trust_address = key, address
        blob = base64.b64decode(key.split()[1], validate=True)
        self.receipt['hostkey_fingerprint'] = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        self.receipt['hostkey_source'] = 'exact-owned target public-key reader; pin preserved, no TOFU'
        self.save()
        return True

    def public_key(self):
        actual = self.inspect('container', self.target)
        self.provisioning.verify_target(actual, inspection_timeout=self.timeout())
        require(actual['State']['Running'] is True, 'target_exited')
        result = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
            'exec', '--user', '0:0', self.target, '/usr/bin/python3', '-I', '-S', '-c', qualification.PUBLIC_KEY_READER),
            cwd=SOURCE_ROOT, timeout=self.timeout(5))
        qualification.attempt_record(self.run, self.receipt, 'target', self.stage_name('public-hostkey'), result)
        if result['status'] == 'timeout':
            self.receipt['unknown_outcome'] = True; self.save()
            raise ReadinessError('helper_probe_incomplete', 'Public identity reader did not finish before its deadline.')
        self.timeout()
        if result['status'] == 'fail':
            raise images.ImageError('qualification_attempt_failed', 'Public identity is not available yet.')
        require(result['status'] == 'pass' and not result['log_truncated'] and 1 <= len(result['log']) <= 512, 'invalid_hostkey')
        try:
            return qualification.public_key(result['log'].decode('ascii'))
        except (ValueError, UnicodeError, qualification.RuntimeFailure):
            raise ReadinessError('invalid_hostkey', 'Expected one ordinary bounded Ed25519 public host key.') from None

    def inject_inputs(self, key, address):
        self.verify_helper(self.inspect('container', self.helper))
        path = self.run.file('private/credentials/id_ed25519')
        with path.open('rb') as stream: private = stream.read(16385)
        require(1 <= len(private) <= 16384, 'invalid_auth')
        with path.with_name('id_ed25519.pub').open('rb') as stream:
            other_key = qualification.public_key(stream.read(513).decode('ascii'))
        require(other_key != key, 'invalid_trust_fixture')
        known = ('[' + address + ']:2222 ' + key + '\n').encode()
        wrong = ('[' + address + ']:2222 ' + other_key + '\n').encode()
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            for name, raw in (('id_ed25519', private), ('known_hosts', known), ('wrong_known_hosts', wrong)):
                member = tarfile.TarInfo(name); member.uid = member.gid = 10001; member.mode = 0o600; member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        try:
            result = subprocess.run(['docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
                'exec', '-i', '--user', '10001:10001', self.helper, '/opt/wormhole/venv/bin/python', '-I', '-S', '-c',
                qualification.INPUT_RECEIVER_COMMAND], input=data.getvalue(), capture_output=True, timeout=self.timeout(15),
                env={key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'WINDIR') if key in os.environ})
        except subprocess.TimeoutExpired:
            self.receipt['unknown_outcome'] = True; self.save()
            raise ReadinessError('helper_auth_injection_unknown', 'The fixed receiver exceeded the remaining deadline.') from None
        qualification.attempt_record(self.run, self.receipt, 'helper', self.stage_name('auth-input'), {'status': 'pass' if result.returncode == 0 else 'fail',
            'returncode': result.returncode, 'log': (result.stdout + result.stderr)[:65536],
            'log_truncated': len(result.stdout) + len(result.stderr) > 65536})
        self.timeout()
        require(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= 65536, 'helper_auth_injection_failed')

    def observe_hostkey(self):
        """Record the current public identity without changing an earlier pin."""
        self.held()
        require(self.pinned_key is not None and self.endpoint() is not None, 'hostkey_pin_required')
        key = self.public_key()
        blob = base64.b64decode(key.split()[1], validate=True)
        result = {'fingerprint': 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('='),
                  'matches_original_pin': key == self.pinned_key, 'observed_at': now()}
        records = self.receipt.setdefault('hostkey_observations', [])
        require(len(records) < 4, 'hostkey_observation_bound')
        records.append(result)
        self.save()
        return deepcopy(result)

    def probe(self, operation, address):
        require(operation in {'tcp', 'ssh', 'python', 'ansible-wait', 'ansible-ping'}, 'unexpected_readiness_operation')
        self.verify_helper(self.inspect('container', self.helper))
        remaining = self.deadline - time.monotonic()
        require(remaining > 3, self.last_pending)
        budget = min({'tcp': 3, 'ssh': 8, 'python': 8, 'ansible-wait': 25, 'ansible-ping': 12}[operation], remaining - 2)
        count = self.counts.get(operation, 0) + 1
        require(count <= 64, 'readiness_attempt_bound')
        self.counts[operation] = count
        request = {'schema_version': '1.0', 'run_id': self.run.id, 'source_revision': self.run.manifest()['source_revision'],
            'target_id': getattr(self, 'selected_target', None) or 'target-001', 'address': address, 'operation': operation, 'attempt': count,
            'scenario': self.scenario, 'timeout_seconds': budget}
        if getattr(self, 'selected_target', None):
            request['resource_layout'] = 'indexed-targets-v1'
            if self.target_plan.profile == 'twenty-targets':
                request['target_plan'] = self.target_plan.record()
        encoded = base64.b64encode(json.dumps(request).encode()).decode('ascii')
        result = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
            'exec', '--user', '10001:10001', self.helper, '/opt/wormhole/venv/bin/python', '-I', '-B', SOURCE_MOUNT, encoded),
            cwd=SOURCE_ROOT, timeout=min(remaining, budget + 2))
        if result['status'] == 'timeout':
            self.receipt['unknown_outcome'] = True
            self.save()
        prior = len(self.receipt['attempts'])
        qualification.attempt_record(self.run, self.receipt, 'helper', self.stage_name(operation), result)
        require(len(self.receipt['attempts']) == prior + 1 and not self.receipt['attempts'][-1].get('diagnostic_write_failed'),
                'readiness_diagnostic_unavailable')
        require(result['status'] == 'pass' and not result['log_truncated'], 'helper_probe_incomplete')
        from readiness.runtime import unique
        try:
            value = json.loads(result['log'], object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError, RecursionError):
            raise ReadinessError('helper_probe_invalid', 'A bounded complete helper result is required.') from None
        fields = {'schema_version', 'run_id', 'source_revision', 'target_id', 'operation', 'attempt', 'status', 'category',
                  'returncode', 'timed_out', 'truncated', 'duration_seconds', 'observation', 'private_diagnostic'}
        require(type(value) is dict and set(value) == fields and all(value[key] == request[key] for key in
            ('schema_version', 'run_id', 'source_revision', 'target_id', 'operation', 'attempt')) and
            value['status'] in {'pass', 'fail'} and type(value['attempt']) is int and
            type(value['returncode']) is int and -(2**31) <= value['returncode'] < 2**31 and
            (value['category'] is None or type(value['category']) is str and value['category'] in CATEGORIES) and
            (value['status'] != 'fail' or value['category'] is not None) and
            type(value['timed_out']) is bool and type(value['truncated']) is bool and
            type(value['duration_seconds']) in (int, float) and math.isfinite(value['duration_seconds']) and
            0 <= value['duration_seconds'] <= budget + 2 and type(value['observation']) is dict and
            type(value['private_diagnostic']) is str and len(value['private_diagnostic'].encode()) <= 32768 and
            (value['status'] == 'pass') == (value['category'] is None and value['returncode'] == 0 and
                                          not value['timed_out'] and not value['truncated']), 'helper_probe_invalid')
        if value['status'] == 'pass':
            expected = {'tcp': ('tcp_connected', True), 'ssh': ('uid', 10001), 'python': ('configured_interpreter_usable', True),
                        'ansible-wait': ('structured_target_result', True), 'ansible-ping': ('ping', 'pong')}[operation]
            require(type(value['observation'].get(expected[0])) is type(expected[1]) and
                    value['observation'][expected[0]] == expected[1], 'helper_probe_invalid')
        self.receipt['probes'].append({key: value[key] for key in value if key not in {'private_diagnostic', 'observation'}})
        self.save()
        return value

    def _poll(self):
        self.held()
        require(not self.reconciliation_only and self.receipt['primary_failure'] is None and
                not self.receipt['unknown_outcome'], 'readiness_failed')
        require(time.monotonic() < self.deadline, self.last_pending)
        address = self.endpoint()
        if address is None:
            return False
        if self.receipt['status'] == 'ready':
            require(self.receipt['ready_started_at'] == self.last_started_at, 'readiness_stale')
            return True
        for operation, check in (('tcp', 'tcp-reachable'), ('ssh', 'ssh-identity-accepted'), ('python', 'python-usable'),
                                 ('ansible-wait', 'ansible-usable'), ('ansible-ping', 'required-test-complete')):
            if check in {x['check_id'] for x in self.receipt['transitions']}:
                continue
            if operation == 'ssh' and not self.pin_trust():
                return False
            result = self.probe(operation, address)
            if result['status'] != 'pass':
                code = result['category']
                if code in {'tcp_pending', 'ssh_transport_pending', 'probe_timeout'} and operation in {'tcp', 'ssh'}:
                    self.last_pending = code
                    return False
                if operation == 'python' and code == 'configured_interpreter_unavailable':
                    confirmation = self.probe('ansible-wait', address)
                    require(confirmation['status'] == 'fail', 'interpreter_fault_inconsistent')
                raise ReadinessError(code, 'The actual helper probe failed; retain its private bounded diagnostic.')
            self.timeout()
            self.transition(check)
        self.timeout()
        self.receipt['status'] = 'ready'
        self.receipt['ready_started_at'] = self.last_started_at
        self.save()
        return True

    def poll(self):
        try:
            return self._poll()
        except BaseException as error:
            if self.receipt['primary_failure'] is None:
                self.failure(error)
            raise

    def wait_ready(self, *, on_poll=None):
        try:
            require(on_poll is None or callable(on_poll), 'invalid_coordinator')
            while True:
                if on_poll is not None:
                    on_poll(time.monotonic() - self.began)
                self.timeout()
                if self.poll():
                    self.require_ready()
                    return deepcopy(self.receipt)
                time.sleep(min(RETRY_SLEEP, max(0, self.deadline - time.monotonic())))
        except BaseException as error:
            if self.receipt['primary_failure'] is None:
                self.failure(error)
            raise

    def require_ready(self, *, inspection_timeout=20):
        self.held()
        require(self.receipt['status'] == 'ready' and self.receipt['primary_failure'] is None and
            not self.receipt['unknown_outcome'] and [x['check_id'] for x in self.receipt['transitions']] == list(EXPECTED),
            'readiness_required')
        # Revalidate an existing snapshot later without resetting the original
        # window for establishing new readiness. No checks are added here.
        original_deadline = self.deadline
        require(type(inspection_timeout) in (int, float) and math.isfinite(inspection_timeout) and .1 <= inspection_timeout <= 20,
                'invalid_readiness_timeout')
        self.deadline = time.monotonic() + inspection_timeout
        try:
            self.verify_helper(self.inspect('container', self.helper))
            self.endpoint()
            require(self.receipt['ready_started_at'] == self.last_started_at, 'readiness_stale')
            self.timeout()
        finally:
            self.deadline = original_deadline
        return True

    def cleanup(self):
        self.held()
        require(not self.receipt['unknown_outcome'], 'helper_outcome_unknown')
        try:
            self.lease.set_phase('reconciling')
            if self.helper is not None:
                entries = [x for x in self.lease.record['resources'] if x['kind'] == 'container' and x['id'] == self.helper]
                require(len(entries) == 1 and entries[0]['outcome'] in {'pending', 'absent'}, 'helper_recovery_scope')
                value = images.inspect('container', self.helper, missing=True)
                require(entries[0]['outcome'] == 'pending' or value is None, 'helper_cleanup_unverified')
                if value is not None:
                    self.verify_helper(value, ownership_only=True)
                    if value['State']['Running']:
                        self.receipt['unknown_outcome'] = True
                        self.save()
                        images.docker(('stop', '--time', '3', self.helper), timeout=10)
                        self.receipt['unknown_outcome'] = False
                        self.save()
                    self.receipt['unknown_outcome'] = True
                    self.save()
                    images.docker(('rm', self.helper))
                    self.receipt['unknown_outcome'] = False
                    self.save()
                    require(images.inspect('container', self.helper, missing=True) is None, 'helper_cleanup_unverified')
                if entries[0]['outcome'] == 'pending':
                    self.lease.reconcile_resource('container', self.helper)
            self.receipt['cleanup'] = 'completed'
            self.save()
            return deepcopy(self.receipt)
        except BaseException as error:
            self.receipt['cleanup'] = 'failed'
            self.failure(error)
            raise

    @classmethod
    def resume_cleanup(cls, run, lease):
        context = read_json(run.file('private/readiness-controller.json'))
        if type(context) is dict and context.get('resource_layout') == 'indexed-targets-v1':
            from .fleet_readiness import BatchReadinessSession
            return BatchReadinessSession.resume_cleanup(run, lease)
        lease._active()
        revision, dirty = source_identity()
        manifest = run.manifest()
        retained = readiness_status(run)
        require(retained['unknown_outcome'] is False, 'helper_outcome_unknown')
        require(lease._reconciliation_only and lease.run_id == run.id and lease.source_revision == revision == manifest['source_revision'] and
            dirty is False and manifest['source_dirty'] is False and manifest['mode'] == 'container-reference' and
            lease.plan['synthetic'] is False, 'helper_recovery_scope')
        context = read_json(run.file('private/readiness-controller.json'))
        fields = set(common(manifest)) | {'operation', 'helper_id', 'helper_image', 'network_id', 'target_resource_id', 'image_labels',
            'source_path', 'source_sha256', 'bind_path', 'bind_identity', 'unknown_outcome', 'cleanup',
            'layout_version', 'validation_enabled', 'validation_source_sha256', 'validation_bind_identity'}
        require(type(context) is dict and set(context) == fields and common(context) == common(manifest) and
            context['operation'] == 'readiness-helper' and type(context['layout_version']) is int and context['layout_version'] == 2 and
            type(context['validation_enabled']) is bool and context['helper_image'] == HELPER_IMAGE and
            (context['helper_id'] is None or type(context['helper_id']) is str and ID.fullmatch(context['helper_id'])) and
            type(context['network_id']) is str and ID.fullmatch(context['network_id']) and
            type(context['target_resource_id']) is str and ID.fullmatch(context['target_resource_id']) and
            context['source_path'] == str(RUNTIME) and context['source_sha256'] == runtime_hash() and
            context['bind_path'] == str(run.file('private/helper-source/runtime.py')) and
            (context['image_labels'] is None or type(context['image_labels']) is dict) and
            context['unknown_outcome'] is False, 'helper_recovery_scope')
        if context['validation_enabled']:
            require(context['validation_source_sha256'] == code_hash(VALIDATION_RUNTIME), 'helper_recovery_scope')
        else:
            require(context['validation_source_sha256'] is None and context['validation_bind_identity'] is None,
                    'helper_recovery_scope')
        if context['helper_id'] is not None:
            require(images.inspect('image', HELPER_IMAGE)['Config'].get('Labels') == context['image_labels'], 'helper_recovery_scope')
        receipt = read_json(run.file('evidence/readiness.json'))
        require(common(receipt) == common(manifest) and receipt.get('operation') == 'ssh-ansible-readiness' and
            receipt.get('helper_id') == context['helper_id'] and receipt.get('unknown_outcome') is False and
            receipt.get('cleanup') == context['cleanup'], 'helper_recovery_scope')
        if context['helper_id'] is None:
            controller = read_json(run.file('private/terraform/controller.json'))
            require(controller.get('schema_version') == '1.0' and controller.get('run_id') == run.id and
                controller.get('source_revision') == revision and type(controller.get('id')) is str and ID.fullmatch(controller['id']),
                'helper_recovery_scope')
            allowed = {('container', controller['id']), ('container', context['target_resource_id']), ('network', context['network_id'])}
            require(all((item['kind'], item['id']) in allowed for item in lease.record['resources']), 'helper_recovery_scope')
            observed = images.docker(('ps', '-a', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + run.id,
                '--filter', 'label=' + images.LABEL + '.role=helper', '--format', '{{.ID}}'))
            require(not observed['log_truncated'] and not observed['log'].strip(), 'helper_recovery_scope')
        else:
            matches = [x for x in lease.record['resources'] if x['kind'] == 'container' and x['id'] == context['helper_id']]
            require(len(matches) == 1 and matches[0]['outcome'] in {'pending', 'absent'}, 'helper_recovery_scope')
        session = cls.__new__(cls)
        session.run, session.lease, session.provisioning = run, lease, None
        session.helper, session.network, session.target = context['helper_id'], context['network_id'], context['target_resource_id']
        session.image_labels, session.source_sha256 = context['image_labels'], context['source_sha256']
        session.bind_path, session.bind_identity = run.file('private/helper-source/runtime.py'), context['bind_identity']
        session.validation_enabled = context['validation_enabled']
        session.validation_source_sha256 = context['validation_source_sha256']
        session.validation_bind_identity = context['validation_bind_identity']
        session.validation_bind_path = run.file('private/helper-source/validation.py')
        session.receipt, session.reconciliation_only = receipt, True
        if session.bind_identity is not None or session.helper is not None:
            session.validate_source_copy()
        return session
