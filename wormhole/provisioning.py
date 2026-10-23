"""Real smoke Terraform lifecycle, using one already-held infrastructure lease.

Only the trusted provisioner receives Docker control. Failed requests preserve
private state and exact accounting; native deletion never substitutes for destroy.
"""
import argparse
from copy import deepcopy
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat

from . import images
from .admission import AdmissionLease
from .runs import (RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common,
                   create_run, now, read_json, source_identity)
from .stages import _run_process, execute_run

CONTEXT = SOURCE_ROOT / 'provisioning'
TARGET_IMAGE = 'sha256:6d15eb2c495d48c1eb6485a74d1adaef3e0e3a6e7c83063ba8459f90c27c683e'
PROVIDER = 'registry.terraform.io/kreuzwerker/docker'
H1 = 'h1:1jD5QVpeLkdxKEWWJpTzNdxtR0WNNFq28Po4yq9w+VM='
ADDRESSES = {'docker_network.run', 'docker_container.target'}
ID = re.compile(r'[a-f0-9]{64}\Z')
MAX_OUTPUT = 4 * 1024 * 1024
SCENARIOS = ('healthy', 'provider-unavailable')
UNAVAILABLE_ENDPOINT = 'unix:///run/wormhole/provider-unavailable.sock'


class ProvisioningError(RunError):
    pass


def require(value, code, message):
    if not value:
        raise ProvisioningError(code, message)


def _same(value, expected):
    return type(value) is type(expected) and value == expected


def _labels(values):
    require(type(values) is list and all(type(x) is dict and set(x) == {'label', 'value'} and
            type(x['label']) is str and type(x['value']) is str for x in values),
            'unsafe_plan', 'Labels must be exact typed Terraform blocks.')
    result = {x['label']: x['value'] for x in values}
    require(len(result) == len(values), 'unsafe_plan', 'Duplicate labels are refused.')
    return result


def resources(value):
    require(type(value) is dict, 'unsafe_state', 'State must be a structured Terraform result.')
    values = value.get('values', value.get('planned_values', {}))
    require(type(values) is dict, 'unsafe_state', 'Terraform values must be a structured object.')
    module = values.get('root_module', {})
    require(type(module) is dict and not module.get('child_modules'), 'unsafe_state', 'Nested infrastructure modules are unsupported.')
    items = module.get('resources', [])
    require(type(items) is list and len(items) <= 2 and
            all(type(x) is dict and x.get('mode') == 'managed' and x.get('provider_name') == PROVIDER and
                x.get('address') in ADDRESSES and type(x.get('values')) is dict for x in items),
            'unsafe_state', 'Only the two fixed managed resources are permitted.')
    result = {x['address']: x['values'] for x in items}
    require(len(result) == len(items), 'unsafe_state', 'Resource addresses cannot repeat.')
    return result


def validate_refresh(value, variables, owned):
    """Terraform 1.17 refresh-only records refreshed resources in prior_state.

    Drift describes observations, not infrastructure actions. Empty planned
    resources must never be interpreted as a new create graph or empty ownership.
    """
    require(type(owned) is dict and set(owned) == ADDRESSES and
            all(type(x) is str and ID.fullmatch(x) for x in owned.values()) and
            value.get('resource_changes', []) == [] and value.get('complete') is True,
            'unsafe_plan', 'Refresh requires both exact owned IDs and no infrastructure actions.')
    prior = value.get('prior_state')
    require(type(prior) is dict and prior.get('format_version') == '1.0' and prior.get('terraform_version') == '1.17.0',
            'unsafe_plan', 'Refresh requires the actual supported refreshed prior-state record.')
    refreshed = resources(prior)
    require(set(refreshed) == ADDRESSES and all(refreshed[key].get('id') == owned[key] for key in ADDRESSES),
            'unsafe_plan', 'Refresh must preserve the complete exact managed identities.')
    planned = resources(value)
    require(not planned or planned == refreshed, 'unsafe_plan', 'Planned refresh resources contradict the observed prior state.')
    drift = value.get('resource_drift', [])
    require(type(drift) is list and len(drift) <= 2, 'unsafe_plan', 'Observed resource drift is bounded to this smoke graph.')
    seen = set()
    for item in drift:
        require(type(item) is dict and item.get('address') in ADDRESSES and item['address'] not in seen and
                item.get('mode') == 'managed' and item.get('provider_name') == PROVIDER and
                not any(item.get(key) for key in ('deposed', 'generated_config', 'importing')) and
                type(item.get('change')) is dict, 'unsafe_plan', 'Unexpected resource drift identity or provider.')
        address, change = item['address'], item['change']
        seen.add(address)
        require(change.get('actions') == ['update'] and type(change.get('before')) is dict and
                type(change.get('after')) is dict and change['before'].get('id') == owned[address] and
                change['after'].get('id') == owned[address] and change['after'] == refreshed[address] and
                change.get('after_unknown', {}) == {},
                'unsafe_plan', 'Drift may only update observed values for the same exact owned identity.')
    outputs = value.get('planned_values', {}).get('outputs', {})
    require(type(outputs) is dict and set(outputs) == {'run'} and type(outputs['run']) is dict and
            outputs['run'].get('sensitive') is False and type(outputs['run'].get('value')) is dict,
            'unsafe_plan', 'Refresh requires the one non-sensitive run output.')
    output = outputs['run']['value']
    require(output.get('network_id') == owned['docker_network.run'] and output.get('target_id') == owned['docker_container.target'] and
            output.get('image') == variables['image'] and output.get('network_name') == 'wormhole-' + variables['run_id'] + '-network',
            'unsafe_plan', 'Refresh output must remain bound to the exact managed run identities.')
    configuration = value.get('configuration', {}).get('root_module', {})
    require(type(configuration) is dict and not configuration.get('module_calls') and
            type(configuration.get('resources', [])) is list and len(configuration.get('resources', [])) <= 2 and
            all(type(x) is dict and not x.get('provisioners') for x in configuration.get('resources', [])),
            'unsafe_plan', 'Refresh cannot introduce modules or executable Terraform provisioners.')


def validate_plan(value, variables, *, operation='create', owned=None):
    """Typed allowlist for actual Terraform JSON, not text matching the plan UI."""
    require(type(value) is dict and value.get('format_version') == '1.2' and
            value.get('terraform_version') == '1.17.0' and value.get('errored', False) is False,
            'unsafe_plan', 'Unsupported or errored Terraform plan format/version.')
    if 'variables' in value:
        require(value['variables'] == {key: {'value': item} for key, item in variables.items()},
                'unsafe_plan', 'The plan is not bound to the exact generated inputs.')
    if operation == 'refresh':
        validate_refresh(value, variables, owned)
        return
    changes = value.get('resource_changes', [])
    require(type(changes) is list and len(changes) <= 2, 'unsafe_plan', 'Unexpected resource graph.')
    addresses = set()
    for item in changes:
        require(type(item) is dict and type(item.get('change')) is dict, 'unsafe_plan', 'Malformed resource change.')
        address, change = item.get('address'), item.get('change', {})
        require(address in ADDRESSES and address not in addresses and item.get('mode') == 'managed' and
                item.get('provider_name') == PROVIDER and not item.get('deposed') and
                not item.get('generated_config') and not item.get('importing'), 'unsafe_plan', 'Unapproved resource/provider operation.')
        addresses.add(address)
        unsafe_unknown = {'start', 'must_run', 'privileged', 'read_only', 'user', 'ports', 'publish_all_ports',
            'mounts', 'volumes', 'devices', 'device_requests', 'gpus', 'capabilities', 'security_opts',
            'pid_mode', 'ipc_mode', 'cgroupns_mode', 'network_mode', 'networks_advanced', 'env', 'entrypoint',
            'command', 'memory', 'memory_swap', 'cpus', 'log_driver', 'log_opts', 'labels', 'tmpfs'}
        def unknown(item):
            return item is True or type(item) is dict and any(unknown(x) for x in item.values()) or type(item) is list and any(unknown(x) for x in item)
        require(not any(unknown(item) for key, item in change.get('after_unknown', {}).items() if key in unsafe_unknown),
                'unsafe_plan', 'Security-sensitive values cannot remain unknown before apply.')
        if operation == 'create':
            require(change.get('actions') == ['create'] and change.get('before') is None,
                    'unsafe_plan', 'Fresh creation cannot update, import, delete or replace existing resources.')
        elif operation == 'destroy':
            require(change.get('actions') == ['delete'] and change.get('after') is None and
                    type(change.get('before')) is dict and owned is not None and
                    change['before'].get('id') == owned.get(address), 'unsafe_plan', 'Destroy must contain only the exact verified owned IDs.')
        else:
            raise ProvisioningError('unsafe_plan', 'Only fixed create, refresh and destroy operations are supported.')
    if operation == 'destroy':
        require(addresses == set(owned), 'unsafe_plan', 'Destroy is incomplete or includes an unexpected resource.')
        return
    if operation == 'create':
        require(addresses == ADDRESSES, 'unsafe_plan', 'Fresh creation requires both exact resource changes.')
    planned = resources(value)
    require(set(planned) == ADDRESSES, 'unsafe_plan', 'The complete smoke graph must be present.')
    for item in changes:
        after = item['change'].get('after')
        require(type(after) is dict and all(_same(after.get(key), planned[item['address']].get(key))
                for key in unsafe_unknown), 'unsafe_plan', 'Planned values contradict the actual resource changes.')
    prefix = 'wormhole-' + variables['run_id']
    expected_labels = {images.LABEL + '.run_id': variables['run_id'],
                       images.LABEL + '.source_revision': variables['source_revision']}
    network = planned['docker_network.run']
    for key, expected in {'name': prefix + '-network', 'driver': 'bridge', 'internal': True,
                          'attachable': False, 'ingress': False, 'ipv6': False}.items():
        require(_same(network.get(key), expected), 'unsafe_plan', 'The network differs from the fixed internal bridge.')
    require(_labels(network.get('labels')) == {**expected_labels, images.LABEL + '.role': 'network'},
            'unsafe_plan', 'Network ownership labels differ.')
    require(not network.get('options') and not network.get('ipam_options'), 'unsafe_plan', 'Network driver overrides are forbidden.')
    target = planned['docker_container.target']
    for key, expected in {'name': prefix + '-target-001', 'image': variables['image'], 'start': False,
        'must_run': False, 'privileged': False, 'read_only': True, 'user': '0:0', 'restart': 'no',
        'rm': False, 'publish_all_ports': False, 'network_mode': 'bridge', 'ipc_mode': 'private',
        'cgroupns_mode': 'private', **variables['target_limits']}.items():
        require(_same(target.get(key), expected), 'unsafe_plan', 'A required target limit, identity or confinement field differs.')
    for key in ('ports', 'mounts', 'devices', 'device_requests', 'device_cgroup_rules', 'gpus', 'pid_mode',
                'group_add', 'host', 'links', 'dns', 'dns_opts', 'dns_search', 'sysctls', 'storage_opts',
                'cgroup_parent', 'runtime'):
        require(not target.get(key), 'unsafe_plan', 'Unapproved target ports, privileges, namespaces, mounts or commands.')
    require(target.get('entrypoint') == ['/usr/bin/python3', '/opt/wormhole/runtime.py'] and target.get('command') == ['target'],
            'unsafe_plan', 'Only the fixed qualified target entrypoint is permitted.')
    require(set(target.get('security_opts') or []) == {'no-new-privileges:true'} and
            _labels(target.get('labels')) == {**expected_labels, images.LABEL + '.role': 'target'},
            'unsafe_plan', 'Target security or ownership differs.')
    caps = target.get('capabilities')
    require(type(caps) is list and len(caps) == 1 and set(caps[0]) == {'add', 'drop'} and
            set(caps[0]['add']) == set(images.TARGET_CAPS) and caps[0]['drop'] == ['ALL'],
            'unsafe_plan', 'Only the qualified SSH target capabilities are permitted.')
    require(target.get('tmpfs') == {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=0,gid=0',
            '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'} and
            set(target.get('env') or []) == {'WORMHOLE_RUN_ID=' + variables['run_id'], 'WORMHOLE_RUNTIME_TTL_SECONDS=300'},
            'unsafe_plan', 'Only fixed tmpfs and bounded target environment are permitted.')
    volumes = target.get('volumes')
    require(type(volumes) is list and len(volumes) == 1 and volumes[0].get('host_path') == variables['public_input'] and
            volumes[0].get('container_path') == '/run/input' and volumes[0].get('read_only') is True and
            not volumes[0].get('volume_name') and not volumes[0].get('from_container'),
            'unsafe_plan', 'Only the exact public authorized-key input bind is allowed.')
    networks = target.get('networks_advanced')
    require(type(networks) is list and len(networks) == 1 and networks[0].get('name') == prefix + '-network' and
            not networks[0].get('ipv4_address') and not networks[0].get('ipv6_address'),
            'unsafe_plan', 'Only the run bridge with a daemon-assigned endpoint is allowed.')
    configuration = value.get('configuration', {}).get('root_module', {})
    require(not configuration.get('module_calls') and not any(x.get('provisioners') for x in configuration.get('resources', [])),
            'unsafe_plan', 'Modules and executable Terraform provisioners are forbidden.')


def bounded_json(path, limit=MAX_OUTPUT):
    _owned(path)
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'terraform_output_bound', 'Private structured output exceeded its bound.')
    from .runs import _no_duplicates
    try:
        return json.loads(raw, object_pairs_hook=_no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise ProvisioningError('terraform_output_invalid', 'Terraform output is not bounded strict JSON.') from None


def file_digest(path, limit=MAX_OUTPUT):
    _owned(path)
    digest, count = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while chunk := stream.read(65536):
            count += len(chunk)
            require(count <= limit, 'terraform_output_bound', 'A private operation file exceeded its reviewed bound.')
            digest.update(chunk)
    return digest.hexdigest(), count


def provisioner_identity():
    socket = Path('/var/run/docker.sock').stat()
    require(stat.S_ISSOCK(socket.st_mode), 'socket_invalid', 'The fixed existing Docker socket is required.')
    uid, gid = os.getuid(), os.getgid()
    groups = [] if socket.st_uid == uid or socket.st_gid == gid else [str(socket.st_gid)]
    return uid, gid, groups


def verified_toolchain(run, supplied=None):
    from .toolchain import load_lock, validate_cache
    verified = validate_cache(run, load_lock())
    require(supplied is None or supplied == verified, 'toolchain_scope', 'Supplied tool metadata differs from the actual pinned run cache.')
    return verified


def scenario_source(scenario):
    require(type(scenario) is str and scenario in SCENARIOS, 'invalid_scenario', 'Only fixed reviewed scenarios are supported.')
    raw = (CONTEXT / 'main.tf').read_bytes()
    expected = b'provider "docker" { host = "unix:///var/run/docker.sock" }'
    require(raw.count(expected) == 1, 'input_changed', 'The source must contain the one fixed reviewed provider endpoint.')
    return raw if scenario == 'healthy' else raw.replace(expected,
        ('provider "docker" { host = "' + UNAVAILABLE_ENDPOINT + '" }').encode())


def unavailable_diagnostic(raw):
    """Pinned provider/SDK messages bind diagnostics; probes establish ENOENT."""
    endpoint = UNAVAILABLE_ENDPOINT.encode()
    wrapped = b'Cannot connect to the Docker daemon at ' + endpoint + b'. Is the docker daemon running?'
    provider = (b'Error: failed to create Docker client: Error pinging Docker server, please make sure that ' + endpoint +
        b" is reachable and has a  '_ping' endpoint. Error: " + wrapped)
    return type(raw) is bytes and provider in raw and b'with docker_network.run,' in raw and \
        b'in resource "docker_network" "run":' in raw


class ProvisioningSession:
    """Caller owns run.locked(), docker_scope(run) and the canonical held lease."""
    def __init__(self, run, lease, *, toolchain=None, scenario='healthy'):
        require(type(scenario) is str and scenario in SCENARIOS, 'invalid_scenario', 'Only fixed reviewed scenarios are supported.')
        manifest = run.manifest()
        revision, dirty = source_identity()
        require(os.name == 'posix' and manifest['mode'] == 'container-reference' and
                manifest['source_revision'] == revision and manifest['source_dirty'] is False and dirty is False,
                'source_scope', 'Real provisioning requires the exact clean recorded Linux source.')
        lease._active()
        require(lease.run_id == run.id and lease.source_revision == revision and lease.plan['synthetic'] is False and
                lease.plan['profile'] == 'smoke' and lease.plan['target_count'] == 1 and not lease._reconciliation_only,
                'admission_scope', 'Only this exact admitted real smoke run may allocate.')
        self.run, self.lease, self.toolchain = run, lease, toolchain
        self.scenario = scenario
        self.destroy_only = False
        self.state = run.file('private/terraform')
        self.provisioner = None
        self.owned = {}
        self.attempts = {}
        self.receipt = {**common(manifest), 'operation': 'terraform-smoke', 'status': 'in-progress',
            'terraform_version': '1.17.0', 'provider': PROVIDER, 'provider_version': '4.6.0',
            'target_image': TARGET_IMAGE, 'operations': [], 'resources': [], 'inventory': None,
            'cleanup': 'not-started', 'primary_failure': None, 'secondary_failures': [],
            'unknown_outcome': False, 'scenario': scenario,
            'runtime_pipeline_complete': False, 'production_iso_eligible': False}
        self.variables = {'run_id': run.id, 'source_revision': revision, 'image': TARGET_IMAGE,
            'public_input': str(images.safe_bind(run.file('private/target-input'))),
            'target_limits': deepcopy(lease.plan['limits']['target']['terraform'])}
        self.variables['target_limits'].pop('start'); self.variables['target_limits'].pop('must_run')
        self.inputs = {}

    def held(self, *, allocating=False):
        self.lease._active()
        require(self.lease.run_id == self.run.id and self.lease.source_revision == self.variables['source_revision'] and
                self.lease.plan['synthetic'] is False and self.lease._reconciliation_only is self.destroy_only,
                'admission_scope', 'The exact real admission lease must remain held for this operation.')
        require(not allocating or not self.destroy_only, 'destroy_only', 'Retained recovery cannot allocate or enter the provisioning path.')

    def save(self):
        self.receipt['updated_at'] = now()
        self.receipt['resources'] = [{'address': key, 'id': value} for key, value in sorted(self.owned.items())]
        atomic_json(self.run.file('evidence/provisioning.json'), self.receipt)
        if self.provisioner is not None:
            atomic_json(self.state / 'controller.json', {'schema_version': '1.0', 'run_id': self.run.id,
                'source_revision': self.variables['source_revision'], 'id': self.provisioner,
                'uid': self.uid, 'gid': self.gid, 'groups': self.socket_groups, 'mounts': self.mounts,
                'image_labels': self.image_labels, 'inputs': self.inputs, 'scenario': self.scenario})

    def failure(self, error):
        if self.receipt['primary_failure'] is None:
            self.receipt['primary_failure'] = {'code': getattr(error, 'code', 'provisioning_failed'), 'recorded_at': now()}
        else:
            self.receipt['secondary_failures'].append({'code': getattr(error, 'code', 'secondary_operation_failed')})
        self.receipt['status'] = 'failed'
        self.save()

    def prepare(self):
        self.held(allocating=True)
        require(not self.inputs and self.provisioner is None, 'attempt_reused', 'Provisioning preparation cannot overwrite a previous attempt.')
        _owned(self.state, directory=True)
        require(not any(self.state.iterdir()), 'state_not_empty', 'Fresh Terraform state must be empty.')
        public_input = Path(self.variables['public_input'])
        require({x.name for x in public_input.iterdir()} == {'authorized_keys'} and
                (public_input / 'authorized_keys').is_file() and not (public_input / 'authorized_keys').is_symlink(),
                'public_input_invalid', 'Target input must contain only this run public authorized key.')
        from images.runtime import public_key
        public_key((public_input / 'authorized_keys').read_bytes()[:513].decode('ascii'))
        if self.toolchain is None:
            from .toolchain import prepare_toolchain
            self.toolchain = prepare_toolchain(self.run)
        self.toolchain = verified_toolchain(self.run, self.toolchain)
        root = images.safe_bind(self.toolchain['root'])
        require(root.is_relative_to(self.run.file('private')) and self.toolchain['terraform'] == root / 'bin/terraform' and
                self.toolchain['mirror'] == root / 'mirror', 'toolchain_scope', 'Only the verified run-owned fixed toolchain is permitted.')
        self.receipt['toolchain'] = deepcopy(self.toolchain['receipt'])
        for name, raw in {'main.tf': scenario_source(self.scenario),
                          '.terraform.lock.hcl': (CONTEXT / '.terraform.lock.hcl').read_bytes(),
                          'terraform.tfvars.json': json.dumps(self.variables, sort_keys=True).encode(),
                          'wormhole.tfrc': b'disable_checkpoint = true\nprovider_installation {\n filesystem_mirror {\n path = "/opt/toolchain/mirror"\n include = ["registry.terraform.io/kreuzwerker/docker"]\n }\n}\n'}.items():
            atomic_bytes(self.state / name, raw)
            self.inputs[name] = hashlib.sha256(raw).hexdigest()
        self.receipt['input_hashes'] = dict(self.inputs)
        self.save()

    def check_inputs(self):
        for name, digest in self.inputs.items():
            _owned(self.state / name)
            require(hashlib.sha256((self.state / name).read_bytes()).hexdigest() == digest,
                    'input_changed', 'Reviewed configuration or dependency lock changed during the operation.')
        require({x.name for x in self.state.iterdir() if x.name.endswith(('.tf', '.tf.json'))} == {'main.tf'},
                'input_changed', 'Additional Terraform configuration is forbidden.')

    def labels(self, role):
        return {images.LABEL + '.run_id': self.run.id, images.LABEL + '.source_revision': self.variables['source_revision'],
                images.LABEL + '.role': role}

    def start_provisioner(self):
        self.held(allocating=True)
        self.check_inputs()
        self.toolchain = verified_toolchain(self.run, self.toolchain)
        image = images.inspect('image', TARGET_IMAGE)
        require(image['Id'] == TARGET_IMAGE and image.get('Os') == 'linux' and image.get('Architecture') == 'amd64' and
                image['Config'].get('Labels', {}).get(images.LABEL + '.role') == 'target' and not image['Config'].get('Volumes'),
                'image_unqualified', 'The exact qualified target image/provenance is required for the separate provisioner.')
        self.image_labels = dict(image['Config'].get('Labels') or {})
        self.uid, self.gid, self.socket_groups = provisioner_identity()
        limits = self.lease.plan['limits']['provisioner']
        self.mounts = {'/opt/toolchain': (str(self.toolchain['root']), False), '/opt/provisioning': (str(images.safe_bind(CONTEXT)), False),
                       '/state': (str(images.safe_bind(self.state)), True), '/var/run/docker.sock': ('/var/run/docker.sock', True)}
        args = ['create', '--name', 'wormhole-' + self.run.id + '-provisioner', '--network', 'none',
                '--user', str(self.uid) + ':' + str(self.gid), '--read-only',
                *images.limits_arguments(limits), '--env', 'WORMHOLE_ROLE=provisioner',
                '--env', 'WORMHOLE_RUN_ID=' + self.run.id, '--entrypoint', '/usr/bin/python3',
                '--tmpfs', '/run:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=' + str(self.uid) + ',gid=' + str(self.gid),
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777']
        for group in self.socket_groups: args.extend(('--group-add', group))
        for key, value in self.labels('provisioner').items(): args.extend(('--label', key + '=' + value))
        for destination, (source, writable) in self.mounts.items():
            args.extend(('--mount', 'type=bind,source=' + source + ',target=' + destination + ('' if writable else ',readonly') + ',bind-propagation=rprivate'))
        args.extend((TARGET_IMAGE, '/opt/provisioning/runtime.py', 'serve'))
        self.lease.set_phase('provisioning')
        response = images.docker(tuple(args))
        identifier = response['log'].decode('ascii').strip()
        require(ID.fullmatch(identifier), 'resource_identity', 'The provisioner create response must be one exact ID.')
        self.provisioner = identifier
        self.lease.register_resource('container', identifier)
        self.save()
        self.verify_provisioner(images.inspect('container', identifier), stopped=True)
        images.docker(('start', identifier))
        live = images.inspect('container', identifier)
        self.verify_provisioner(live)
        self.receipt['provisioner_cgroups'] = images.cgroup_limits(live['State']['Pid'], limits['docker_create'])
        self.receipt['provisioner_id'] = identifier
        self.save()

    def verify_provisioner(self, value, *, stopped=False):
        require(value.get('Id') == self.provisioner and value.get('Image') == TARGET_IMAGE and
                value['Config'].get('Labels') == {**self.image_labels, **self.labels('provisioner')}, 'ownership_mismatch', 'Provisioner identity/labels changed.')
        self.verify_limits(value, 'provisioner', stopped=stopped)
        host, config = value['HostConfig'], value['Config']
        require(host['NetworkMode'] == 'none' and config['User'] == str(self.uid) + ':' + str(self.gid) and
                not host.get('Binds') and
                set(host.get('GroupAdd') or []) == set(self.socket_groups) and not host.get('CapAdd') and
                config['Entrypoint'] == ['/usr/bin/python3'] and config['Cmd'] == ['/opt/provisioning/runtime.py', 'serve'],
                'unsafe_provisioner', 'Only the fixed non-networked provisioner command/user is permitted.')
        require(host.get('Tmpfs') == {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=' + str(self.uid) + ',gid=' + str(self.gid),
                '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'} and
                set(x for x in config.get('Env', []) if x.startswith('WORMHOLE_')) ==
                {'WORMHOLE_ROLE=provisioner', 'WORMHOLE_RUN_ID=' + self.run.id},
                'unsafe_provisioner', 'Provisioner tmpfs, role or run identity differs.')
        mounts = value.get('Mounts', [])
        require(len(mounts) == len(self.mounts) and all(x['Type'] == 'bind' and
                self.mounts.get(x['Destination']) == (x['Source'], x['RW']) for x in mounts),
                'unsafe_provisioner', 'Only verified tools/source, private Terraform state and the fixed socket may be mounted.')

    def verify_limits(self, value, role, *, stopped=False, pid_pending=False):
        expected = self.lease.plan['limits'][role]['docker_create']; host = value['HostConfig']
        require(all(type(host.get(key)) is int and host[key] == expected[source] for key, source in
                    (('Memory', 'memory_bytes'), ('MemorySwap', 'memory_swap_bytes'), ('NanoCpus', 'nano_cpus'))) and
                (host.get('PidsLimit') is None or type(host.get('PidsLimit')) is int) and
                (pid_pending or host.get('PidsLimit') == expected['pids_limit']),
                'limits_not_enforced', 'Actual CPU/memory/swap/PID limits must match before start.')
        require(host.get('ReadonlyRootfs') is True and host.get('Privileged') is False and
                images.capability_names(host.get('CapDrop')) == {'ALL'} and
                host.get('PidMode') == '' and host.get('IpcMode') in ('', 'private') and
                host.get('UTSMode', '') == '' and host.get('CgroupnsMode', 'private') == 'private' and
                not host.get('PortBindings') and not host.get('PublishAllPorts') and not host.get('Devices') and
                not host.get('DeviceRequests') and not host.get('VolumesFrom') and
                host.get('AutoRemove', False) is False and
                host.get('RestartPolicy', {}).get('Name') == 'no' and
                set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'}, {'no-new-privileges=true'}, {'no-new-privileges'}) and
                host.get('LogConfig') == {'Type': expected['log_driver'], 'Config': expected['log_opts']},
                'unsafe_container', 'Actual namespaces, privilege, ports or log confinement differ.')
        require(not stopped or value['State']['Running'] is False, 'premature_start', 'Limits must be inspected while stopped.')

    def operation(self, name):
        from provisioning.runtime import OPERATIONS, JSON_OPERATIONS
        require(name in OPERATIONS, 'unsupported_operation', 'Only fixed Terraform operations are allowed.')
        self.held()
        require(not self.destroy_only or name in {'show-state', 'destroy-plan', 'show-destroy-plan', 'destroy', 'final-state'},
                'destroy_only', 'Resumed provisioners may execute only fixed state inspection and saved destroy operations.')
        self.check_inputs()
        self.verify_provisioner(images.inspect('container', self.provisioner))
        attempt = self.attempts.get(name, 0) + 1
        require(attempt <= 4, 'attempt_bound', 'Operation attempts exceeded the reviewed bound.')
        self.attempts[name] = attempt
        mutating = name in {'apply', 'refresh-apply', 'destroy'}
        previous_unknown = self.receipt['unknown_outcome']
        require(not mutating or previous_unknown is False, 'daemon_outcome_unknown',
                'An uncertain prior operation cannot authorize another mutating Terraform command.')
        if mutating:
            self.receipt['unknown_outcome'] = True
            self.save()  # Write intent before a mutating exec can lose its response.
        result = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
                    'exec', self.provisioner, '/usr/bin/python3', '/opt/provisioning/runtime.py', name, str(attempt)),
                    cwd=SOURCE_ROOT, timeout=135)
        stem = self.state / 'operations' / (name + '-' + str(attempt))
        if result['status'] == 'timeout' or not stem.with_suffix('.json').exists():
            self.receipt['unknown_outcome'] = True
            self.save()
        require(stem.with_suffix('.json').exists(), 'terraform_result_missing', 'The bounded provisioner did not produce a complete result; daemon outcome may be unknown.')
        try:
            record = read_json(stem.with_suffix('.json'))
            require(type(record) is dict and set(record) == {'operation', 'attempt', 'returncode', 'duration_seconds',
                    'output_bytes', 'output_sha256', 'truncated', 'timed_out', 'passed'} and
                    record['operation'] == name and type(record['attempt']) is int and record['attempt'] == attempt and
                    type(record['output_bytes']) is int and 0 <= record['output_bytes'] <= MAX_OUTPUT and
                    type(record['returncode']) is int and -(2**31) <= record['returncode'] < 2**31 and
                    type(record['duration_seconds']) in (int, float) and math.isfinite(record['duration_seconds']) and
                    0 <= record['duration_seconds'] <= 135 and type(record['output_sha256']) is str and ID.fullmatch(record['output_sha256']) and
                    all(type(record[key]) is bool for key in ('truncated', 'timed_out', 'passed')) and
                    record['passed'] == (record['returncode'] == 0 and not record['timed_out'] and not record['truncated']),
                    'terraform_result_invalid', 'The operation receipt identity/fields differ.')
            path = stem.with_suffix('.out')
            digest, size = file_digest(path)
            require(size == record['output_bytes'] and digest == record['output_sha256'],
                    'terraform_result_invalid', 'Private Terraform output changed after capture.')
        except Exception:
            self.receipt['unknown_outcome'] = True
            self.save()
            raise
        complete = result['status'] in {'pass', 'fail'} and not result['log_truncated'] and not record['timed_out'] and not record['truncated'] and \
            (not mutating or result['status'] == 'pass' and record['passed'])
        self.receipt['unknown_outcome'] = previous_unknown if complete else True
        self.receipt['operations'].append({**record, 'client_status': result['status'],
            'client_returncode': result['returncode'], 'client_log_truncated': result['log_truncated'],
            'evidence': 'private/terraform/operations/' + stem.name + '.out'})
        self.save()
        require(result['status'] == 'pass' and not result['log_truncated'] and record['passed'],
                'terraform_failed', 'Terraform failed, timed out or exceeded output bounds; preserve private diagnostics and state.')
        return bounded_json(path) if name in JSON_OPERATIONS else record

    def record_state(self, value, *, complete=False):
        found = resources(value)
        if complete: require(set(found) == ADDRESSES, 'incomplete_state', 'Actual Terraform state is missing the smoke resources.')
        for address, values in found.items():
            identifier = values.get('id')
            require(type(identifier) is str and ID.fullmatch(identifier), 'resource_identity', 'Actual provider state must contain exact IDs.')
            role = 'target' if address.startswith('docker_container.') else 'network'
            actual = images.inspect('container' if role == 'target' else 'network', identifier)
            self.verify_owned(actual, role, identifier)
            require(address not in self.owned or self.owned[address] == identifier, 'ownership_mismatch', 'State cannot replace this run resource identity.')
            if address not in self.owned:
                self.lease.register_resource('container' if role == 'target' else 'network', identifier)
                self.owned[address] = identifier
        self.save()
        return found

    def verify_owned(self, actual, role, identifier):
        labels = actual.get('Config', {}).get('Labels') if role == 'target' else actual.get('Labels')
        name = 'wormhole-' + self.run.id + ('-target-001' if role == 'target' else '-network')
        expected_labels = self.labels(role) if role == 'network' else {**self.image_labels, **self.labels(role)}
        require(actual.get('Id') == identifier and labels == expected_labels and actual.get('Name', '').lstrip('/') == name,
                'ownership_mismatch', 'Exact resource labels, name or identity differ from this run.')
        if role == 'network':
            require(actual.get('Driver') == 'bridge' and actual.get('Internal') is True and actual.get('Scope') == 'local' and
                    not actual.get('Ingress'), 'unsafe_network', 'Only the internal local run bridge may be managed.')
        else:
            require(actual.get('Image') == TARGET_IMAGE, 'ownership_mismatch', 'The target image is not the qualified immutable input.')

    def verify_target(self, actual, *, stopped=False, pid_pending=False, inspection_timeout=20):
        self.verify_owned(actual, 'target', self.owned['docker_container.target'])
        self.verify_limits(actual, 'target', stopped=stopped, pid_pending=pid_pending)
        require(not stopped or actual['State'].get('Status') == 'created' and actual['State'].get('Pid') == 0 and
                actual['State'].get('StartedAt') == '0001-01-01T00:00:00Z' and actual.get('RestartCount', 0) == 0,
                'premature_start', 'The target must be observed created and never started before PID enforcement/start.')
        host, config = actual['HostConfig'], actual['Config']
        require(config.get('User') == '0:0' and images.capability_names(host.get('CapAdd')) == set(images.TARGET_CAPS) and
                host.get('NetworkMode') == 'bridge' and
                config.get('Entrypoint') == ['/usr/bin/python3', '/opt/wormhole/runtime.py'] and config.get('Cmd') == ['target'] and
                set(x for x in config.get('Env', []) if x.startswith('WORMHOLE_')) ==
                {'WORMHOLE_RUN_ID=' + self.run.id, 'WORMHOLE_RUNTIME_TTL_SECONDS=300'},
                'unsafe_target', 'The target runtime/user/privilege/lifetime differs from the qualified image contract.')
        mounts = actual.get('Mounts', [])
        require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['Source'] == self.variables['public_input'] and
                mounts[0]['Destination'] == '/run/input' and mounts[0]['RW'] is False,
                'unsafe_target', 'Only the exact public authorized-key input may be mounted into a target.')
        require(not host.get('Binds') or host['Binds'] == [self.variables['public_input'] + ':/run/input:ro'],
                'unsafe_target', 'An unapproved legacy bind is forbidden.')
        require(host.get('Tmpfs') == {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=0,gid=0',
                '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'}, 'unsafe_target', 'Actual target tmpfs bounds differ.')
        expected_network = 'wormhole-' + self.run.id + '-network'
        endpoints = actual.get('NetworkSettings', {}).get('Networks', {})
        require(type(endpoints) is dict and set(endpoints) == {expected_network} and
                type(endpoints[expected_network]) is dict,
                'unsafe_target', 'Target networking differs from the exact run bridge.')
        network_id = self.owned['docker_network.run']
        self.verify_owned(images.inspect('network', network_id, timeout=inspection_timeout), 'network', network_id)
        # Docker can leave the stopped NetworkConnect endpoint ID unresolved until
        # start. The sole named endpoint is pending intent, backed by independent
        # exact owned internal-network inspection; running targets require its ID.
        require(endpoints[expected_network].get('NetworkID') in ({'', network_id} if stopped else {network_id}),
                'unsafe_target', 'Target endpoint does not resolve to the exact owned run bridge.')

    def create_stopped(self):
        """Create and confine the exact target without starting its runtime."""
        try:
            self.held(allocating=True)
            self.prepare(); self.start_provisioner()
            version = self.operation('version')
            require(version.get('terraform_version') == '1.17.0' and version.get('platform') == 'linux_amd64',
                    'tool_version_mismatch', 'The actual provisioner Terraform version/platform differs.')
            self.operation('init')  # readonly lock verifies the unpacked mirror contents hash in actual Terraform.
            schema = self.operation('schema')['provider_schemas'][PROVIDER]['resource_schemas']
            require({'docker_container', 'docker_network'} <= set(schema) and
                    {'start', 'must_run', 'cpus', 'memory', 'memory_swap'} <= set(schema['docker_container']['block']['attributes']) and
                    'pids_limit' not in schema['docker_container']['block']['attributes'],
                    'provider_schema_mismatch', 'Actual provider capabilities differ from the reviewed stopped-target/PID-gap policy.')
            self.receipt['actual_tools'] = {'terraform_version': version['terraform_version'], 'platform': version['platform'],
                'provider_version': '4.6.0', 'offline_readonly_lock_h1_confirmed': H1, 'provider_schema_observed': True}
            self.operation('plan')
            validate_plan(self.operation('show-plan'), self.variables)
            saved, _ = file_digest(self.state / 'apply.tfplan')
            self.check_inputs()
            require(file_digest(self.state / 'apply.tfplan')[0] == saved,
                    'plan_changed', 'The validated saved plan changed before apply.')
            self.receipt['validated_plan_sha256'] = saved
            self.lease.refresh()
            if self.scenario == 'provider-unavailable':
                self.receipt['provider_unavailable_probe_before'] = self.operation('probe-unavailable')
                self.save()
            self.operation('apply')
            require(self.scenario == 'healthy', 'expected_failure_missing', 'The fixed unavailable provider unexpectedly applied; preserve resources for review.')
            self.record_state(self.operation('show-state'), complete=True)
            target = self.owned['docker_container.target']
            self.lease.refresh()
            before = images.inspect('container', target)
            self.verify_target(before, stopped=True, pid_pending=True)
            self.receipt['target_before_pid_update'] = {'status': before['State']['Status'],
                'started_at': before['State']['StartedAt'], 'pids_limit': before['HostConfig'].get('PidsLimit')}
            images.docker(('update', '--pids-limit', str(self.lease.plan['limits']['target']['pids_limit']), target))
            self.verify_target(images.inspect('container', target), stopped=True)
            self.receipt['status'] = 'created-stopped'
            self.save()
            return deepcopy(self.owned)
        except BaseException as error:
            self._provision_failure(error)
            raise

    def start_and_inventory(self):
        """Start the confined target once, then obtain its actual provider output."""
        try:
            self.held(allocating=True)
            require(self.scenario == 'healthy' and self.receipt['status'] == 'created-stopped' and
                    self.receipt['unknown_outcome'] is False and set(self.owned) == ADDRESSES,
                    'target_not_ready', 'Start requires this complete, confined, never-started target.')
            target = self.owned['docker_container.target']
            self.check_inputs()
            controller = images.inspect('container', self.provisioner)
            self.verify_provisioner(controller)
            state = controller['State']
            require(state.get('Running') is True and state.get('Status') == 'running' and
                    type(state.get('Pid')) is int and state['Pid'] > 0 and
                    not state.get('Paused', False) and not state.get('Restarting', False),
                    'provisioner_unavailable', 'The retained provisioner must still be running before target start.')
            self.verify_target(images.inspect('container', target), stopped=True)
            self.lease.refresh()
            images.docker(('start', target))
            live = images.inspect('container', target)
            self.verify_target(live)
            self.receipt['target_started_at'] = live['State']['StartedAt']
            self.receipt['target_cgroups'] = images.cgroup_limits(live['State']['Pid'], self.lease.plan['limits']['target']['docker_create'])
            self.operation('refresh-plan')
            validate_plan(self.operation('show-refresh-plan'), self.variables, operation='refresh', owned=self.owned)
            self.operation('refresh-apply')
            output = self.operation('output')
            self.receipt['inventory'] = self.inventory(output)
            self.run.save_artifact('inventory', self.receipt['inventory'])
            self.receipt['status'] = 'provisioned'
            self.save()
            return deepcopy(self.receipt['inventory'])
        except BaseException as error:
            self._provision_failure(error)
            raise

    def provision(self):
        self.create_stopped()
        return self.start_and_inventory()

    def _provision_failure(self, error):
        self.failure(error)
        # Diagnostics do not replace the primary error or delete owned resources.
        if self.provisioner is not None:
            try: self.record_state(self.operation('show-state'))
            except Exception as diagnostic: self.failure(diagnostic)

    def inventory(self, output):
        require(type(output) is dict and set(output) == {'run'} and output['run'].get('sensitive') is False,
                'inventory_invalid', 'Expected exactly the non-sensitive provider run output.')
        value = output['run']['value']
        require(value.get('target_id') == self.owned['docker_container.target'] and value.get('network_id') == self.owned['docker_network.run'] and
                value.get('image') == TARGET_IMAGE and value.get('network_name') == 'wormhole-' + self.run.id + '-network',
                'inventory_invalid', 'Provider output identity differs from actual owned state.')
        endpoints = [x for x in value.get('network_data', []) if x.get('network_name') == value['network_name']]
        require(len(endpoints) == 1, 'inventory_invalid', 'Provider must observe exactly one run-network endpoint.')
        address = endpoints[0].get('ip_address', '')
        try: parsed = ipaddress.ip_address(address)
        except ValueError: raise ProvisioningError('inventory_invalid', 'The provider has no actual numeric endpoint.') from None
        actual = images.inspect('container', value['target_id']); self.verify_target(actual)
        observed = actual['NetworkSettings']['Networks'][value['network_name']]
        require(parsed.version == 4 and not parsed.is_loopback and not parsed.is_unspecified and address == observed['IPAddress'] and
                observed['NetworkID'] == value['network_id'], 'inventory_invalid', 'Provider endpoint does not match exact network inspection.')
        return {**common(self.run.manifest()), 'status': 'pass', 'targets': [{'target_id': 'target-001',
            'resource_id': value['target_id'], 'host': address, 'ssh_port': 2222, 'ssh_user': 'wormhole',
            'image_digest': TARGET_IMAGE, 'status': 'started'}]}

    def prove_provider_unavailable(self):
        """Clear only a fixed zero-contact negative case, never a general failure."""
        self.held()
        self.check_inputs()
        require(not self.destroy_only and self.scenario == 'provider-unavailable' and not self.owned and
                self.receipt['inventory'] is None and self.receipt['unknown_outcome'] is True and
                self.receipt['primary_failure'] is not None and self.receipt['primary_failure']['code'] == 'terraform_failed' and
                self.inputs['main.tf'] == hashlib.sha256(scenario_source('provider-unavailable')).hexdigest(),
                'zero_contact_unproven', 'Only this exact fixed unavailable-provider failure can be proved.')
        expected_probe = {'endpoint': UNAVAILABLE_ENDPOINT, 'path_absent': True, 'connect_errno': 'ENOENT'}
        require(self.receipt.get('provider_unavailable_probe_before') == expected_probe,
                'zero_contact_unproven', 'The fixed endpoint was not proved absent before actual apply.')
        mutations = [x for x in self.receipt['operations'] if x['operation'] in {'apply', 'refresh-apply', 'destroy'}]
        require(len(mutations) == 1, 'zero_contact_unproven', 'Only one known failed saved apply may be reconciled.')
        failed = mutations[0]
        before = self.receipt['operations'][:self.receipt['operations'].index(failed)]
        require([x['operation'] for x in before] == ['version', 'init', 'schema', 'plan', 'show-plan', 'probe-unavailable'] and
                all(x['passed'] is True and x.get('client_status') == 'pass' for x in before) and
                self.receipt.get('validated_plan_sha256') == file_digest(self.state / 'apply.tfplan')[0],
                'zero_contact_unproven', 'Actual successful preparation and the exact validated saved plan must precede apply.')
        require(failed['operation'] == 'apply' and failed['returncode'] != 0 and failed['passed'] is False and
                failed['timed_out'] is False and failed['truncated'] is False and failed.get('client_status') == 'fail' and
                failed.get('client_returncode') == 2 and failed.get('client_log_truncated') is False,
                'zero_contact_unproven', 'The actual saved apply needs a complete known nonzero terminal result.')
        path = self.state / 'operations' / ('apply-' + str(failed['attempt']) + '.out')
        digest, size = file_digest(path)
        require(digest == failed['output_sha256'] and size == failed['output_bytes'],
                'zero_contact_unproven', 'Actual apply diagnostics changed after capture.')
        raw = path.read_bytes()
        require(unavailable_diagnostic(raw),
                'zero_contact_unproven', 'The actual provider failure does not identify the fixed absent Unix endpoint.')
        require(self.operation('probe-unavailable') == expected_probe and not resources(self.operation('show-state')),
                'zero_contact_unproven', 'The endpoint must remain absent and actual Terraform state must be empty.')
        pending = {(x['kind'], x['id']) for x in self.lease.record['resources'] if x['outcome'] == 'pending'}
        require(pending == {('container', self.provisioner)}, 'zero_contact_unproven', 'Only the existing exact controller may remain journaled.')
        checks = []
        for arguments, expected in (
            (('ps', '-a', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + self.run.id, '--format', '{{.ID}}'), {self.provisioner}),
            (('network', 'ls', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + self.run.id, '--format', '{{.ID}}'), set())):
            observed = images.docker(arguments)
            require(not observed['log_truncated'], 'zero_contact_unproven', 'The exact run-label observation must be complete.')
            values = observed['log'].decode('ascii').splitlines()
            require(set(values) == expected and len(values) == len(expected),
                    'zero_contact_unproven', 'Unexpected run resources prevent zero-contact proof.')
            checks.append({'kind': 'container' if arguments[0] == 'ps' else 'network', 'count': len(values)})
        # A crash/missing result from any attempt is not made safe by a later
        # empty snapshot. Bind every operation file to its completed record.
        expected_files = set()
        for record in self.receipt['operations']:
            stem = record['operation'] + '-' + str(record['attempt'])
            expected_files.update({stem + '.out', stem + '.json'})
            require(record['timed_out'] is False and record['truncated'] is False and
                    record.get('client_status') in {'pass', 'fail'} and record.get('client_log_truncated') is False,
                    'zero_contact_unproven', 'Incomplete prior operation evidence remains uncertain.')
            metadata = read_json(self.state / 'operations' / (stem + '.json'))
            require(metadata == {key: value for key, value in record.items()
                    if key not in {'client_status', 'client_returncode', 'client_log_truncated', 'evidence'}},
                    'zero_contact_unproven', 'Captured terminal metadata differs from the bound operation record.')
            digest, size = file_digest(self.state / 'operations' / (stem + '.out'))
            require(digest == record['output_sha256'] and size == record['output_bytes'],
                    'zero_contact_unproven', 'Captured operation output changed after the terminal result.')
        require({x.name for x in (self.state / 'operations').iterdir()} == expected_files,
                'zero_contact_unproven', 'Unrecorded or incomplete operations prevent zero-contact proof.')
        proof = {'scenario': self.scenario, 'status': 'proved-zero-contact', 'endpoint': UNAVAILABLE_ENDPOINT,
            'before_and_after_enoent': True, 'actual_saved_apply_failed': True, 'terraform_state_empty': True,
            'run_resources': checks, 'source_sha256': self.inputs['main.tf'], 'recorded_at': now()}
        self.receipt['provider_unavailable_proof'] = proof
        self.receipt['unknown_outcome'] = False
        self.save()
        return deepcopy(proof)

    def destroy(self):
        """Terraform owns deletion. Every current state ID is inspected before planning it."""
        try:
            self.held()
            require(self.receipt['unknown_outcome'] is False, 'daemon_outcome_unknown',
                    'Unknown daemon work must be resolved by a specific reviewed proof before destroy.')
            require(self.provisioner is not None, 'provisioner_missing', 'Retained exact provisioner is required for Terraform destroy.')
            controller = None
            if self.receipt.get('cleanup_progress', {}).get('controller_remove_requested') is True:
                controller = images.inspect('container', self.provisioner, missing=True)
                if controller is None:
                    self._final_state_proof()
                    for address, identifier in self.owned.items():
                        self._reconcile_absent('container' if address.startswith('docker_container.') else 'network', identifier)
                    self._reconcile_absent('container', self.provisioner)
                    return self._cleanup_complete()
            state = resources(self.operation('show-state'))
            require(set(state) <= set(self.owned) and all(x.get('id') == self.owned[key] for key, x in state.items()),
                    'ownership_mismatch', 'State resources changed; destructive operations are refused.')
            self.verify_provisioner(controller if controller is not None else images.inspect('container', self.provisioner))
            remaining = {}
            for address, identifier in self.owned.items():
                role = 'target' if address.startswith('docker_container.') else 'network'
                actual = images.inspect('container' if role == 'target' else 'network', identifier, missing=True)
                if actual is None: continue
                require(address in state, 'ownership_mismatch', 'A surviving owned object is missing from Terraform state; no native deletion or adoption is permitted.')
                self.verify_owned(actual, role, identifier)
                remaining[address] = identifier
                if role == 'network':
                    require(set(actual.get('Containers', {})) <= {self.owned.get('docker_container.target')},
                            'ownership_mismatch', 'An unexpected endpoint is attached; refuse network destruction.')
            self.operation('destroy-plan')
            validate_plan(self.operation('show-destroy-plan'), self.variables, operation='destroy', owned=remaining)
            self.operation('destroy')
            require(not resources(self.operation('final-state')), 'destroy_incomplete', 'Terraform still records managed resources after destroy.')
            self.receipt.setdefault('cleanup_progress', {})['terraform_final_state_empty'] = True
            self.save()  # Durable before absence acknowledgements or controller removal.
            for address, identifier in self.owned.items():
                kind = 'container' if address.startswith('docker_container.') else 'network'
                self._reconcile_absent(kind, identifier)
            self.verify_provisioner(images.inspect('container', self.provisioner))
            images.docker(('stop', '--time', '2', self.provisioner))
            self.verify_provisioner(images.inspect('container', self.provisioner), stopped=True)
            self.receipt['cleanup_progress']['controller_remove_requested'] = True
            self.save()
            images.docker(('rm', self.provisioner))
            self._reconcile_absent('container', self.provisioner)
            return self._cleanup_complete()
        except BaseException as error:
            self.receipt['cleanup'] = 'failed'; self.failure(error)
            raise

    def _reconcile_absent(self, kind, identifier):
        require(images.inspect(kind, identifier, missing=True) is None, 'destroy_incomplete', 'An exact cleanup resource still exists.')
        entries = [x for x in self.lease.record['resources'] if (x['kind'], x['id']) == (kind, identifier)]
        require(len(entries) == 1 and entries[0]['outcome'] in {'pending', 'absent'},
                'recovery_scope', 'Historical cleanup identity differs from the exact journal.')
        if entries[0]['outcome'] == 'pending': self.lease.reconcile_resource(kind, identifier)

    def _final_state_proof(self):
        require(self.receipt.get('cleanup_progress', {}).get('terraform_final_state_empty') is True and
                self.receipt['cleanup_progress'].get('controller_remove_requested') is True,
                'recovery_scope', 'A missing controller requires recorded completed Terraform teardown and exact removal intent.')
        records = [x for x in self.receipt['operations'] if x['operation'] == 'final-state']
        mutations = [x for x in self.receipt['operations'] if x['operation'] in {'apply', 'refresh-apply', 'destroy'}]
        require(mutations and mutations[-1]['operation'] == 'destroy' and mutations[-1]['passed'] is True and
                mutations[-1].get('client_status') == 'pass' and mutations[-1]['returncode'] == 0,
                'recovery_scope', 'The last mutation must be a bound successful saved Terraform destroy.')
        require(records and records[-1]['passed'] is True and records[-1].get('client_status') == 'pass' and
                records[-1].get('client_log_truncated') is False and records[-1]['timed_out'] is False and records[-1]['truncated'] is False,
                'recovery_scope', 'A missing controller requires its bound successful empty final-state observation.')
        for record in (mutations[-1], records[-1]):
            require(type(record.get('attempt')) is int and 1 <= record['attempt'] <= 4 and record.get('client_returncode') == 0 and
                    record.get('client_log_truncated') is False and record.get('timed_out') is False and record.get('truncated') is False,
                    'recovery_scope', 'The completed teardown needs bound successful client and runtime results.')
            stem = self.state / 'operations' / (record['operation'] + '-' + str(record['attempt']))
            digest, size = file_digest(stem.with_suffix('.out'))
            require(digest == record['output_sha256'] and size == record['output_bytes'] and
                    read_json(stem.with_suffix('.json')) == {key: value for key, value in record.items()
                        if key not in {'client_status', 'client_returncode', 'client_log_truncated', 'evidence'}},
                    'recovery_scope', 'The completed teardown captures are missing or changed.')
        require(not resources(bounded_json(stem.with_suffix('.out'))),
                'recovery_scope', 'The completed final-state capture is nonempty.')

    def _cleanup_complete(self):
        for arguments in (('ps', '-a', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + self.run.id, '--format', '{{.ID}}'),
                          ('network', 'ls', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + self.run.id, '--format', '{{.ID}}')):
            sweep = images.docker(arguments)
            require(not sweep['log_truncated'] and not sweep['log'].strip(), 'cleanup_unresolved', 'Run-label leftovers remain; no automatic deletion is authorized.')
        self.receipt['cleanup'] = 'completed'
        self.receipt['status'] = 'completed' if self.receipt['primary_failure'] is None else 'failed'
        self.save()
        return deepcopy(self.receipt)

    @classmethod
    def resume_destroy(cls, run, lease):
        """Only the retained exact controller; never create a replacement.

        General leftover adoption/migration is WORM-008. An uncertain previous
        daemon result is outside this narrow adapter and remains blocked.
        """
        lease._active()
        manifest = run.manifest()
        revision, dirty = source_identity()
        require(lease._reconciliation_only and lease.run_id == run.id and lease.source_revision == manifest['source_revision'] and
                revision == manifest['source_revision'] and not dirty and not manifest['source_dirty'] and
                lease.plan['profile'] == 'smoke' and lease.plan['synthetic'] is False,
                'recovery_scope', 'Destroy recovery requires this exact clean-source run and held reconciliation-only lease.')
        session = cls.__new__(cls)
        session.run, session.lease = run, lease
        session.destroy_only = True
        session.state = run.file('private/terraform')
        record = read_json(session.state / 'controller.json')
        require(set(record) == {'schema_version', 'run_id', 'source_revision', 'id', 'uid', 'gid', 'groups', 'mounts', 'image_labels', 'inputs', 'scenario'} and
                record['schema_version'] == '1.0' and record['run_id'] == run.id and record['source_revision'] == revision and
                type(record['id']) is str and ID.fullmatch(record['id']) and record['scenario'] in SCENARIOS,
                'recovery_scope', 'Retained controller metadata is missing or differs.')
        session.scenario = record['scenario']
        session.provisioner, session.uid, session.gid = record['id'], record['uid'], record['gid']
        session.socket_groups, session.image_labels, session.inputs = record['groups'], record['image_labels'], record['inputs']
        require((session.uid, session.gid, session.socket_groups) == provisioner_identity(),
                'recovery_scope', 'Existing state/socket ownership changed; do not alter host ownership.')
        session.mounts = {key: tuple(item) for key, item in record['mounts'].items()}
        session.variables = bounded_json(session.state / 'terraform.tfvars.json')
        session.receipt = read_json(run.file('evidence/provisioning.json'))
        require(common(session.receipt) == common(manifest) and session.receipt.get('scenario') == session.scenario and
                session.receipt.get('provisioner_id', session.provisioner) == session.provisioner and
                session.receipt.get('unknown_outcome') is False,
                'daemon_outcome_unknown', 'Uncertain daemon work remains blocked for separately reviewed recovery; time passing is insufficient.')
        session.owned = {x['address']: x['id'] for x in session.receipt['resources']}
        require(set(session.owned) <= ADDRESSES and len(session.owned) == len(session.receipt['resources']),
                'recovery_scope', 'Only already-accounted exact Terraform resources can be recovered.')
        pending = {(x['kind'], x['id']) for x in lease.record['resources'] if x['outcome'] == 'pending'}
        required = {('container', session.provisioner)} | {('container' if address.startswith('docker_container.') else 'network', identifier)
                       for address, identifier in session.owned.items()}
        recorded = {(x['kind'], x['id']) for x in lease.record['resources']}
        require(pending <= required <= recorded and len(required) == len(session.owned) + 1,
                'recovery_scope', 'The retained historical IDs must match the journal and no unexplained pending resource may exist.')
        for item in lease.record['resources']:
            if (item['kind'], item['id']) in required and item['outcome'] == 'absent':
                require(images.inspect(item['kind'], item['id'], missing=True) is None,
                        'recovery_scope', 'A reconciled exact resource unexpectedly exists; refuse recovery.')
        session.attempts = {}
        operation_files = list((session.state / 'operations').iterdir())
        require(all(x.suffix in {'.json', '.out'} and x.is_file() for x in operation_files) and
                {x.stem for x in operation_files if x.suffix == '.out'} == {x.stem for x in operation_files if x.suffix == '.json'},
                'recovery_scope', 'Incomplete or unexpected operation files prevent retained-controller execution.')
        for path in (x for x in operation_files if x.suffix == '.json'):
            match = re.fullmatch(r'([a-z-]+)-([1-4])\.json', path.name)
            require(match is not None, 'recovery_scope', 'Unexpected operation metadata prevents recovery.')
            from provisioning.runtime import OPERATIONS
            terminal = read_json(path)
            digest, size = file_digest(path.with_suffix('.out'))
            require(match[1] in OPERATIONS and terminal.get('operation') == match[1] and terminal.get('attempt') == int(match[2]) and
                    terminal.get('timed_out') is False and terminal.get('truncated') is False and
                    type(terminal.get('returncode')) is int and terminal.get('output_bytes') == size and terminal.get('output_sha256') == digest,
                    'daemon_outcome_unknown', 'Every prior operation needs a complete bound terminal result before recovery.')
            session.attempts[match[1]] = max(session.attempts.get(match[1], 0), int(match[2]))
        session.check_inputs()
        session.toolchain = verified_toolchain(run)
        expected_mounts = {'/opt/toolchain', '/opt/provisioning', '/state', '/var/run/docker.sock'}
        require(set(session.mounts) == expected_mounts and session.mounts['/opt/provisioning'] == (str(images.safe_bind(CONTEXT)), False) and
                session.mounts['/state'] == (str(session.state), True) and session.mounts['/var/run/docker.sock'] == ('/var/run/docker.sock', True) and
                session.mounts['/opt/toolchain'] == (str(session.toolchain['root']), False),
                'recovery_scope', 'Retained mounts do not match the exact fixed reviewed source/state/toolchain/socket boundaries.')
        actual = images.inspect('container', session.provisioner, missing=True)
        if actual is None:
            session._final_state_proof()
            return session  # No replacement or restart; destroy only acknowledges proven absence.
        session.verify_provisioner(actual)
        lease.set_phase('reconciling')
        capacity = lease.check_destroy_recovery_capacity(session.provisioner)
        atomic_json(session.state / 'destroy-recovery-capacity.json', capacity)
        if actual['State']['Running'] is False:
            images.docker(('start', session.provisioner))
        live = images.inspect('container', session.provisioner); session.verify_provisioner(live)
        session.receipt['destroy_recovery_cgroups'] = images.cgroup_limits(live['State']['Pid'], lease.plan['limits']['provisioner']['docker_create'])
        session.save()
        return session


def qualify(scenario='healthy'):
    require(type(scenario) is str and scenario in SCENARIOS, 'invalid_scenario', 'Only fixed reviewed scenarios are supported.')
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    try:
        with run.locked():
            execute_run(run)  # Preserve the unsupported complete-pipeline outcome; this is a separate partial operation.
        images.create_auth(run)
        with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE, run.id, run.manifest()['source_revision'], 'smoke') as lease:
            session = ProvisioningSession(run, lease, scenario=scenario)
            try:
                session.provision()
            except ProvisioningError:
                if scenario != 'provider-unavailable': raise
                session.prove_provider_unavailable()
            receipt = session.destroy()
            lease.finish(reconciliation_complete=True)
    except BaseException as error:
        error.run_id = run.id
        raise
    return {'run_id': run.id, 'partial_operation': receipt['status'], 'inventory': receipt['inventory'],
            'receipt': 'evidence/provisioning.json', 'cleanup': receipt['cleanup'],
            'runtime_pipeline_complete': False, 'production_iso_eligible': False}


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Admitted real one-target Terraform qualification; no complete-pipeline claim.')
    parser.add_argument('operation', choices=('qualify', 'recover'))
    parser.add_argument('--run-id')
    parser.add_argument('--scenario', choices=SCENARIOS, default='healthy')
    options = parser.parse_args(arguments)
    try:
        if options.operation == 'qualify':
            require(options.run_id is None, 'invalid_arguments', 'Qualification always creates a fresh run.')
            result = qualify(options.scenario)
        else:
            require(options.scenario == 'healthy', 'invalid_arguments', 'Recovery uses the existing recorded scenario.')
            from .runs import Run
            run = Run(images.RUNS_ROOT, options.run_id)
            with run.locked(), images.docker_scope(run), AdmissionLease.resume(images.INFRASTRUCTURE, run.id, run.manifest()['source_revision'], 'smoke') as lease:
                session = ProvisioningSession.resume_destroy(run, lease)
                receipt = session.destroy()
                lease.finish(reconciliation_complete=True)
            result = {'run_id': run.id, 'cleanup': receipt['cleanup'], 'primary_failure': receipt['primary_failure'],
                      'runtime_pipeline_complete': False, 'production_iso_eligible': False}
        print(json.dumps(result, sort_keys=True, indent=2)); return 0
    except Exception as error:
        print(json.dumps({'error': {'code': getattr(error, 'code', 'provisioning_failed'),
            'run_id': getattr(error, 'run_id', options.run_id), 'receipt': 'evidence/provisioning.json',
            'message': 'Terraform qualification failed; preserve private state, primary diagnostics and resource accounting.'}})); return 2


if __name__ == '__main__':
    raise SystemExit(main())
