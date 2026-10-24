"""Synthetic plan/policy and subprocess fixtures; every Docker call is mocked."""
import base64
import errno
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from provisioning import runtime
from wormhole import provisioning as p, admission as a, images
from wormhole.runs import create_run, atomic_json
from test_admission import observed

SHA = 'a' * 40
CID, NET, CONTROLLER = 'a' * 64, 'b' * 64, 'c' * 64
# Sanitized actual pinned-provider diagnostic, containing only the fixed endpoint
# and authored network context; no run identity, credentials or private key data.
WRAPPED_UNAVAILABLE = (b'docker_network.run: Creating...\n\n'
    b'Error: failed to create Docker client: Error pinging Docker server, please make sure that '
    b"unix:///run/wormhole/provider-unavailable.sock is reachable and has a  '_ping' endpoint. Error: "
    b'Cannot connect to the Docker daemon at unix:///run/wormhole/provider-unavailable.sock. Is the docker daemon running?\n\n'
    b'  with docker_network.run,\n  on main.tf line 24, in resource "docker_network" "run":\n'
    b'  24: resource "docker_network" "run" {\n\n')


def inputs(identifier='12345678-1234-4234-9234-123456789abc'):
    limits = deepcopy(a.build_plan('smoke', observed())['limits']['target']['terraform'])
    limits.pop('start'); limits.pop('must_run')
    return {'run_id': identifier, 'source_revision': SHA, 'image': p.TARGET_IMAGE,
            'public_input': '/synthetic/run/public-only', 'target_limits': limits}


def plan(variables, operation='create'):
    if 'target_ids' in variables:
        legacy = deepcopy(variables); ids = legacy.pop('target_ids')
        value = plan(legacy, operation)
        value['variables'] = {key: {'value': item} for key, item in variables.items()}
        def expand(items, values_key):
            result = []
            for item in items:
                if item['address'] != 'docker_container.target':
                    row = deepcopy(item); row.update(type='docker_network', name='run'); result.append(row); continue
                for number, target_id in enumerate(ids, 1):
                    row = deepcopy(item); row['address'] = 'docker_container.target[' + json.dumps(target_id) + ']'; row['index'] = target_id
                    row.update(type='docker_container', name='target')
                    blobs = [row['change'].get(key) for key in ('before', 'after')] if values_key == 'change' else [row['values']]
                    for blob in blobs:
                        if blob is None: continue
                        blob['name'] = 'wormhole-' + variables['run_id'] + '-' + target_id
                        blob['labels'].append({'label': images.LABEL + '.target_id', 'value': target_id})
                        if 'id' in blob: blob['id'] = CID if number == 1 else format(number, '064x')
                    result.append(row)
            return result
        if value['planned_values'].get('root_module', {}).get('resources'):
            value['planned_values']['root_module']['resources'] = expand(value['planned_values']['root_module']['resources'], 'values')
        value['resource_changes'] = expand(value['resource_changes'], 'change')
        if operation == 'refresh':
            value['prior_state']['values']['root_module']['resources'] = expand(value['prior_state']['values']['root_module']['resources'], 'values')
            value['resource_drift'] = expand(value['resource_drift'], 'change')
            output = value['planned_values']['outputs']['run']['value']
            value['planned_values']['outputs']['run']['value'] = {'network_id': NET, 'network_name': output['network_name'],
                'targets': {target_id: {'resource_id': CID if number == 1 else format(number, '064x'), 'image': variables['image'],
                    'network_data': []} for number, target_id in enumerate(ids, 1)}}
        return value
    prefix = 'wormhole-' + variables['run_id']
    common = {images.LABEL + '.run_id': variables['run_id'], images.LABEL + '.source_revision': SHA}
    label = lambda role: [{'label': key, 'value': value} for key, value in {**common, images.LABEL + '.role': role}.items()]
    network = {'name': prefix + '-network', 'driver': 'bridge', 'internal': True, 'attachable': False,
               'ingress': False, 'ipv6': False, 'labels': label('network')}
    target = {'name': prefix + '-target-001', 'image': variables['image'], 'start': False, 'must_run': False,
        'privileged': False, 'read_only': True, 'user': '0:0', 'restart': 'no', 'rm': False,
        'publish_all_ports': False, 'network_mode': 'bridge', 'ipc_mode': 'private', 'cgroupns_mode': 'private',
        **variables['target_limits'], 'entrypoint': ['/usr/bin/python3', '/opt/wormhole/runtime.py'], 'command': ['target'],
        'security_opts': ['no-new-privileges:true'], 'labels': label('target'),
        'capabilities': [{'add': list(variables.get('target_capabilities',images.TARGET_CAPS)), 'drop': ['ALL']}],
        'tmpfs': {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=0,gid=0', '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'},
        'env': ['WORMHOLE_RUN_ID=' + variables['run_id'], 'WORMHOLE_RUNTIME_TTL_SECONDS=300'],
        'volumes': [{'host_path': variables['public_input'], 'container_path': '/run/input', 'read_only': True}],
        'networks_advanced': [{'name': prefix + '-network'}]}
    entries = [{'address': address, 'mode': 'managed', 'type': address.split('.')[0], 'name': address.split('.')[1],
                'provider_name': p.PROVIDER, 'values': values} for address, values in
                (('docker_network.run', network), ('docker_container.target', target))]
    if operation != 'create':
        network['id'], target['id'] = NET, CID
    result = {'format_version': '1.2', 'terraform_version': '1.17.0', 'planned_values': {'root_module': {'resources': entries}},
              'variables': {key: {'value': value} for key, value in variables.items()}, 'resource_changes': [],
              'configuration': {'root_module': {'resources': []}}}
    for entry in entries:
        values = deepcopy(entry['values'])
        result['resource_changes'].append({key: entry[key] for key in ('address', 'mode', 'provider_name')})
        result['resource_changes'][-1]['change'] = {'actions': [{'create': 'create', 'destroy': 'delete', 'refresh': 'no-op'}[operation]],
            'before': values if operation != 'create' else None, 'after': None if operation == 'destroy' else values, 'after_unknown': {}}
    if operation == 'refresh':
        # Labeled synthetic reproduction of actual Terraform 1.17 refresh-only
        # shape: observations in prior_state; planned root_module is empty.
        result['complete'] = True
        result['prior_state'] = {'format_version': '1.0', 'terraform_version': '1.17.0', 'values': deepcopy(result['planned_values'])}
        result['resource_drift'] = []
        for entry in entries:
            before, after = deepcopy(entry['values']), deepcopy(entry['values'])
            if entry['address'] == 'docker_container.target':
                before['network_data'] = []
                after['network_data'] = [{'network_name': prefix + '-network', 'ip_address': '192.0.2.3'}]
            else:
                before['ipam_options'], after['ipam_options'] = None, {}
            next(x for x in result['prior_state']['values']['root_module']['resources'] if x['address'] == entry['address'])['values'] = deepcopy(after)
            result['resource_drift'].append({key: entry[key] for key in ('address', 'mode', 'provider_name')})
            result['resource_drift'][-1]['change'] = {'actions': ['update'], 'before': before, 'after': after, 'after_unknown': {}}
        result['resource_changes'] = []
        result['planned_values'] = {'root_module': {}, 'outputs': {'run': {'sensitive': False, 'value': {
            'network_id': NET, 'target_id': CID, 'image': variables['image'], 'network_name': prefix + '-network'}}}}
    return result


class PlanPolicy(unittest.TestCase):
    def test_fixed_create_refresh_destroy_graphs_and_no_executable_or_key_inputs(self):
        values = inputs()
        p.validate_plan(plan(values), values)
        owned = {'docker_network.run': NET, 'docker_container.target': CID}
        p.validate_plan(plan(values, 'refresh'), values, operation='refresh', owned=owned)
        p.validate_plan(plan(values, 'destroy'), values, operation='destroy', owned=owned)
        source = (p.CONTEXT / 'main.tf').read_text()
        self.assertNotIn('private_key', source)
        self.assertNotIn('provisioner "', source)
        self.assertNotIn('ports {', source)
        self.assertIn('start             = false', source)
        self.assertIn('internal   = true', source)
        self.assertIn(p.H1, (p.CONTEXT / '.terraform.lock.hcl').read_text())

    def test_known_multi_argument_hcl_blocks_use_multiline_form(self):
        # This is a narrow regression for actual init's reported syntax error,
        # not an HCL parser or a substitute for real capped Terraform init.
        source = (p.CONTEXT / 'main.tf').read_text()
        self.assertNotRegex(source, r'(?m)^[ \t]*(?:content|capabilities|volumes)[ \t]*\{[ \t]*\S')

    def test_dangerous_fields_unknowns_bool_aliases_and_inconsistent_changes_are_rejected(self):
        values = inputs()
        for key, bad in (('start', True), ('privileged', True), ('read_only', False), ('memory', True),
                         ('network_mode', 'host'), ('pid_mode', 'host'), ('ports', [{'internal': 2222, 'external': 2222}]),
                         ('entrypoint', ['/bin/sh']), ('command', []), ('command', ['shell']), ('devices', [{'host_path': '/dev/kvm'}]),
                         ('volumes', [{'host_path': '/private/keys', 'container_path': '/keys', 'read_only': True}])):
            value = plan(values)
            value['planned_values']['root_module']['resources'][1]['values'][key] = bad
            value['resource_changes'][1]['change']['after'][key] = bad
            with self.subTest(field=key), self.assertRaises(p.ProvisioningError): p.validate_plan(value, values)
        value = plan(values); value['resource_changes'][1]['change']['after_unknown']['ports'] = True
        with self.assertRaises(p.ProvisioningError): p.validate_plan(value, values)
        value = plan(values); value['resource_changes'][1]['change']['after_unknown']['command'] = True
        with self.assertRaises(p.ProvisioningError): p.validate_plan(value, values)
        value = plan(values); value['resource_changes'][1]['change']['after']['privileged'] = True
        with self.assertRaises(p.ProvisioningError): p.validate_plan(value, values)

    def test_wrong_provider_nested_graph_replacements_and_external_destroy_are_refused(self):
        values = inputs()
        for mutate in (lambda x: x['resource_changes'][0].update(provider_name='registry.terraform.io/other/docker'),
                       lambda x: x.update(resource_changes=[]),
                       lambda x: x['resource_changes'].pop(),
                       lambda x: x['resource_changes'][0]['change'].update(actions=['delete', 'create']),
                       lambda x: x['planned_values']['root_module'].update(child_modules=[{}]),
                       lambda x: x['configuration']['root_module'].update(module_calls={'remote': {}}),
                       lambda x: x['configuration']['root_module']['resources'].append({'provisioners': [{'type': 'local-exec'}]}),
                       lambda x: x['variables'].update(private_key={'value': 'synthetic-never-authorized'})):
            value = plan(values); mutate(value)
            with self.assertRaises(p.ProvisioningError): p.validate_plan(value, values)
        wrong = {'docker_network.run': NET, 'docker_container.target': 'd' * 64}
        with self.assertRaises(p.ProvisioningError): p.validate_plan(plan(values, 'destroy'), values, operation='destroy', owned=wrong)
        with self.assertRaises(p.ProvisioningError): p.validate_plan(plan(values, 'refresh'), values, operation='refresh', owned=wrong)

    def test_actual_refresh_only_layout_uses_owned_prior_state_without_allowing_actions_or_id_drift(self):
        values = inputs(); owned = {'docker_network.run': NET, 'docker_container.target': CID}
        actual_shape = plan(values, 'refresh')
        self.assertEqual(actual_shape['planned_values']['root_module'], {})
        p.validate_plan(actual_shape, values, operation='refresh', owned=owned)
        for mutate in (
            lambda x: x.update(resource_changes=[{'change': {'actions': ['no-op']}}]),
            lambda x: x.pop('prior_state'),
            lambda x: x['prior_state']['values']['root_module']['resources'].pop(),
            lambda x: x['prior_state']['values']['root_module'].update(child_modules=[{}]),
            lambda x: x['prior_state']['values']['root_module']['resources'][0]['values'].update(id='e' * 64),
            lambda x: x['resource_drift'][0]['change'].update(actions=['create']),
            lambda x: x['resource_drift'][0]['change'].update(actions=['delete']),
            lambda x: x['resource_drift'][0]['change']['before'].update(id='e' * 64),
            lambda x: x['resource_drift'][0].update(provider_name='registry.terraform.io/other/docker'),
            lambda x: x['resource_drift'].append(deepcopy(x['resource_drift'][0])),
            lambda x: x['resource_drift'][0]['change'].update(after_unknown={'id': True}),
            lambda x: x['planned_values']['outputs']['run']['value'].update(target_id='e' * 64),
            lambda x: x['configuration']['root_module'].update(module_calls={'unapproved': {}}),
        ):
            value = deepcopy(actual_shape); mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(p.ProvisioningError):
                p.validate_plan(value, values, operation='refresh', owned=owned)

    def test_fixed_runtime_commands_scrub_ambient_authority_and_never_execute_unknown_input(self):
        with patch.dict(os.environ, {'TF_CLI_ARGS': '-destroy', 'TF_REATTACH_PROVIDERS': 'evil', 'DOCKER_CONTEXT': 'remote',
                                     'AWS_SECRET_ACCESS_KEY': 'synthetic-not-real', 'HOME': '/personal'}):
            environment = runtime.environment()
        self.assertEqual(environment['HOME'], '/run/wormhole/home')
        self.assertTrue(all(key not in environment for key in ('TF_CLI_ARGS', 'TF_REATTACH_PROVIDERS', 'DOCKER_CONTEXT', 'AWS_SECRET_ACCESS_KEY', 'WORMHOLE_ROLE')))
        self.assertEqual(runtime.OPERATIONS['apply'][-1], 'apply.tfplan')
        self.assertIn('-lockfile=readonly', runtime.OPERATIONS['init'])
        for operation in ('../destroy', 'shell', 'apply -auto-approve'):
            with self.assertRaises(ValueError): runtime.operation(operation, 1)

    def test_unavailable_scenario_accepts_only_the_fixed_reviewed_enum(self):
        healthy, unavailable = p.scenario_source('healthy'), p.scenario_source('provider-unavailable')
        self.assertEqual(unavailable, healthy.replace(b'unix:///var/run/docker.sock', p.UNAVAILABLE_ENDPOINT.encode()))
        for value in ('remote', 'unix:///tmp/arbitrary.sock', '', None):
            with self.assertRaises(p.ProvisioningError): p.scenario_source(value)

    def test_provider_sdk_wrapped_diagnostic_is_bound_to_exact_fixed_endpoint_and_ping_failure(self):
        self.assertTrue(p.unavailable_diagnostic(WRAPPED_UNAVAILABLE))
        for raw in (b'Cannot connect to the Docker daemon',
                    WRAPPED_UNAVAILABLE.replace(b'provider-unavailable.sock', b'arbitrary.sock'),
                    WRAPPED_UNAVAILABLE.replace(b'Error pinging Docker server', b'Other error'),
                    WRAPPED_UNAVAILABLE.replace(b'with docker_network.run,', b'with unrelated.resource,'),
                    WRAPPED_UNAVAILABLE.replace(b'in resource "docker_network" "run":', b'in resource "docker_container" "target":'),
                    b'dial unix /run/wormhole/provider-unavailable.sock: connect: no such file or directory',
                    b'Error pinging Docker server: timeout at unix:///run/wormhole/provider-unavailable.sock',
                    WRAPPED_UNAVAILABLE.decode()):
            with self.subTest(raw=raw): self.assertFalse(p.unavailable_diagnostic(raw))

    @unittest.skipUnless(hasattr(runtime.socket, 'AF_UNIX'), 'Unix endpoint probe requires Linux AF_UNIX; socket calls are mocked')
    def test_fixed_unix_probe_never_accepts_an_existing_or_wrong_failure_endpoint(self):
        with patch.object(runtime.os, 'lstat', side_effect=FileNotFoundError), patch.object(runtime.socket, 'socket') as factory:
            client = factory.return_value.__enter__.return_value
            client.connect.side_effect = FileNotFoundError(errno.ENOENT, 'Synthetic absent endpoint')
            self.assertEqual(runtime.probe_unavailable(), {'endpoint': p.UNAVAILABLE_ENDPOINT, 'path_absent': True, 'connect_errno': 'ENOENT'})
            client.connect.assert_called_once_with('/run/wormhole/provider-unavailable.sock')
            client.settimeout.assert_called_once_with(1)
            client.connect.side_effect = PermissionError(errno.EACCES, 'Synthetic inaccessible endpoint')
            with self.assertRaises(ValueError): runtime.probe_unavailable()
            client.connect.side_effect = None
            with self.assertRaises(ValueError): runtime.probe_unavailable()
        with patch.object(runtime.os, 'lstat', return_value=object()), patch.object(runtime.socket, 'socket') as factory:
            with self.assertRaises(ValueError): runtime.probe_unavailable()
            factory.assert_not_called()

    def test_bounded_json_refuses_duplicate_nonfinite_symlink_and_overlarge_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'output'
            for raw in (b'{"a":1,"a":2}', b'{"value":NaN}', b'x' * 1025):
                path.write_bytes(raw); path.chmod(0o600)
                with self.assertRaises(p.ProvisioningError): p.bounded_json(path, 1024)


@unittest.skipUnless(os.name == 'posix', 'Linux trusted-controller fixtures; all Docker calls mocked')
class Controller(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='wormhole-provisioning-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = create_run(self.root / 'runs', fixture=False, profile=getattr(self, 'fixture_profile', 'smoke'), identity=(SHA, False))
        target_input = self.run.file('private/target-input'); target_input.mkdir(mode=0o755)
        blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))
        (target_input / 'authorized_keys').write_text('ssh-ed25519 ' + base64.b64encode(blob).decode() + '\n')
        self.plan = a.build_plan(getattr(self, 'fixture_profile', 'smoke'), observed()); self.plan['synthetic'] = False
        calls = self.calls = []
        class Lease:
            run_id = self.run.id
            source_revision = SHA
            plan = self.plan
            _reconciliation_only = False
            record = {'resources': []}
            def _active(self): pass
            def set_phase(self, phase): calls.append(('phase', phase))
            def refresh(self): calls.append(('refresh',))
            def check_destroy_recovery_capacity(self, identifier):
                calls.append(('recovery-capacity', identifier)); return {'synthetic_fixture': True, 'allocation_permitted': False}
            def register_resource(self, kind, identifier):
                calls.append(('register', kind, identifier))
                self.record['resources'].append({'kind': kind, 'id': identifier, 'outcome': 'pending'})
            def reconcile_resource(self, kind, identifier):
                calls.append(('reconcile', kind, identifier))
                for value in self.record['resources']:
                    if value['kind'] == kind and value['id'] == identifier: value['outcome'] = 'absent'
        self.lease = Lease()
        tools = self.run.file('private/tools'); tools.mkdir(mode=0o700)
        (tools / 'bin').mkdir(mode=0o700); (tools / 'mirror').mkdir(mode=0o700)
        self.tools = {'root': tools, 'terraform': tools / 'bin/terraform', 'mirror': tools / 'mirror',
                      'archives': (), 'receipt': {'synthetic': True, 'executed': False}}
        self.cache = patch.object(p, 'verified_toolchain', return_value=self.tools); self.cache.start(); self.addCleanup(self.cache.stop)
        self.source = patch.object(p, 'source_identity', return_value=(SHA, False)); self.source.start(); self.addCleanup(self.source.stop)
        self.session = p.ProvisioningSession(self.run, self.lease, toolchain=self.tools)
        self.image_labels = {images.LABEL + '.role': 'target', images.LABEL + '.recipe_sha256': 'f' * 64}
        self.running = {CID: False, CONTROLLER: False}
        self.removed = set(); self.target_pid_limit = None

    def container(self, identifier):
        role = 'provisioner' if identifier == CONTROLLER else 'target'
        expected = self.plan['limits'][role]['docker_create']
        root = identifier == CONTROLLER
        config = {'Labels': {**self.image_labels, **self.session.labels(role)},
                  'User': '0:0', 'Entrypoint': ['/usr/bin/python3'] if root else ['/usr/bin/python3', '/opt/wormhole/runtime.py'],
                  'Cmd': ['/opt/provisioning/runtime.py', 'serve'] if root else ['target'],
                  'Env': ['WORMHOLE_RUN_ID=' + self.run.id, 'WORMHOLE_ROLE=provisioner'] if root else
                         ['WORMHOLE_RUN_ID=' + self.run.id, 'WORMHOLE_RUNTIME_TTL_SECONDS=300']}
        host = {'Memory': expected['memory_bytes'], 'MemorySwap': expected['memory_swap_bytes'], 'NanoCpus': expected['nano_cpus'],
            'PidsLimit': expected['pids_limit'] if root else self.target_pid_limit, 'ReadonlyRootfs': True, 'Privileged': False,
            'CapDrop': ['ALL'], 'CapAdd': [] if root else list(self.session.target_runtime_policy.capabilities), 'PidMode': '', 'IpcMode': 'private',
            'NetworkMode': 'none' if root else 'bridge', 'LogConfig': {'Type': expected['log_driver'], 'Config': expected['log_opts']},
            'SecurityOpt': ['no-new-privileges:true'], 'RestartPolicy': {'Name': 'no'}, 'GroupAdd': [],
            'Tmpfs': {'/run': 'rw,nosuid,nodev,noexec,size=16m,mode=' + ('0700' if root else '0755') + ',uid=0,gid=0',
                      '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'}}
        mounts = [{'Type': 'bind', 'Source': source, 'Destination': target, 'RW': writable}
                  for target, (source, writable) in self.session.mounts.items()] if root else [
                  {'Type': 'bind', 'Source': self.session.variables['public_input'], 'Destination': '/run/input', 'RW': False}]
        return {'Id': identifier, 'Image': p.TARGET_IMAGE, 'Name': '/wormhole-' + self.run.id + ('-provisioner' if root else '-target-001'),
            'Config': config, 'HostConfig': host, 'Mounts': mounts, 'State': {'Running': self.running[identifier],
                'Pid': 123 if self.running[identifier] else 0, 'Status': 'running' if self.running[identifier] else 'created',
                'StartedAt': '2026-10-23T14:00:00Z' if self.running[identifier] else '0001-01-01T00:00:00Z'},
            'NetworkSettings': {'Networks': {} if root else {'wormhole-' + self.run.id + '-network': {'NetworkID': NET, 'IPAddress': '172.31.77.2'}}}}

    def inspect(self, kind, identifier, **kwargs):
        self.calls.append(('inspect', kind, identifier))
        if identifier in self.removed: return None
        if kind == 'image': return {'Id': p.TARGET_IMAGE, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': self.image_labels}}
        if kind == 'network': return {'Id': NET, 'Name': 'wormhole-' + self.run.id + '-network',
            'Labels': self.session.labels('network'), 'Internal': True, 'Driver': 'bridge', 'Scope': 'local', 'Containers': {}}
        return self.container(identifier)

    def docker(self, args, **kwargs):
        self.calls.append(('docker', *args))
        if args[0] == 'create':
            text = ' '.join(args)
            self.assertIn('--network none', text)
            self.assertNotIn('private/credentials', text)
            self.assertNotIn('target-input', text)
            self.assertNotIn('--privileged', text)
            return {'log': (CONTROLLER + '\n').encode(), 'log_truncated': False}
        if args[0] == 'update': self.target_pid_limit = int(args[2])
        if args[0] == 'start': self.running[args[1]] = True
        if args[0] == 'stop': self.running[args[-1]] = False
        if args[0] == 'rm': self.removed.add(args[1])
        if args[0] == 'ps':
            return {'log': (CONTROLLER + '\n').encode() if CONTROLLER not in self.removed else b'', 'log_truncated': False}
        return {'log': b'', 'log_truncated': False}

    def operation(self, name):
        self.calls.append(('operation', name))
        if name == 'version': return {'terraform_version': '1.17.0', 'platform': 'linux_amd64'}
        if name == 'schema': return {'provider_schemas': {p.PROVIDER: {'resource_schemas': {
            'docker_container': {'block': {'attributes': {key: {} for key in ('start', 'must_run', 'memory', 'memory_swap', 'cpus')}}}, 'docker_network': {}}}}}
        if name in ('plan', 'refresh-plan', 'destroy-plan'):
            filename = {'plan': 'apply.tfplan', 'refresh-plan': 'refresh.tfplan', 'destroy-plan': 'destroy.tfplan'}[name]
            self.session.state.joinpath(filename).write_bytes(b'synthetic saved plan'); self.session.state.joinpath(filename).chmod(0o600)
        if name.startswith('show-') and name.endswith('plan'):
            return plan(self.session.variables, 'refresh' if name == 'show-refresh-plan' else 'destroy' if name == 'show-destroy-plan' else 'create')
        if name == 'show-state':
            value = plan(self.session.variables, 'refresh'); return value['prior_state']
        if name == 'output': return {'run': {'sensitive': False, 'value': {'network_id': NET,
            'network_name': 'wormhole-' + self.run.id + '-network', 'targets': {'target-001': {'resource_id': CID, 'image': p.TARGET_IMAGE,
            'network_data': [{'network_name': 'wormhole-' + self.run.id + '-network', 'ip_address': '172.31.77.2'}]}}}}}
        if name == 'destroy': self.removed.update({CID, NET})
        if name == 'final-state': return {'values': {'root_module': {'resources': []}}}
        return {'synthetic': True}

    def patches(self, *, mock_operations=True):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(p, 'provisioner_identity', return_value=(0, 0, [])))
        stack.enter_context(patch.object(images, 'inspect', side_effect=self.inspect))
        stack.enter_context(patch.object(images, 'docker', side_effect=self.docker))
        stack.enter_context(patch.object(images, 'cgroup_limits', return_value={'synthetic': True}))
        if mock_operations: stack.enter_context(patch.object(self.session, 'operation', side_effect=self.operation))
        return stack

    def unavailable_capture(self, args, **kwargs):
        """Actual operation() records, synthetic process/provider output only."""
        name, attempt = args[-2], int(args[-1])
        if name in ('plan', 'destroy-plan'):
            saved = self.session.state / ('apply.tfplan' if name == 'plan' else 'destroy.tfplan')
            saved.write_bytes(b'synthetic saved plan'); saved.chmod(0o600)
        if name == 'apply': raw = WRAPPED_UNAVAILABLE
        elif name == 'probe-unavailable': raw = json.dumps({'endpoint': p.UNAVAILABLE_ENDPOINT, 'path_absent': True, 'connect_errno': 'ENOENT'}).encode()
        elif name in ('show-state', 'final-state'): raw = b'{"values":{"root_module":{"resources":[]}}}'
        elif name == 'show-destroy-plan': raw = json.dumps({'format_version': '1.2', 'terraform_version': '1.17.0', 'resource_changes': [], 'variables': {key: {'value': value} for key, value in self.session.variables.items()}}).encode()
        elif name == 'show-plan': raw = json.dumps(plan(self.session.variables)).encode()
        elif name in ('version', 'schema'): raw = json.dumps(self.operation(name)).encode()
        else: raw = b'Synthetic completed fixed operation'
        folder = self.session.state / 'operations'; folder.mkdir(mode=0o700, exist_ok=True)
        stem = folder / (name + '-' + str(attempt)); stem.with_suffix('.out').write_bytes(raw); stem.with_suffix('.out').chmod(0o600)
        passed = name != 'apply'
        atomic_json(stem.with_suffix('.json'), {'operation': name, 'attempt': attempt, 'returncode': 0 if passed else 1,
            'duration_seconds': .01, 'output_bytes': len(raw), 'output_sha256': hashlib.sha256(raw).hexdigest(),
            'truncated': False, 'timed_out': False, 'passed': passed})
        return {'status': 'pass' if passed else 'fail', 'returncode': 0 if passed else 2, 'log': b'synthetic runtime receipt', 'log_truncated': False}

    def test_fixed_unavailable_apply_failure_needs_specific_proof_then_empty_saved_destroy(self):
        self.session = p.ProvisioningSession(self.run, self.lease, toolchain=self.tools, scenario='provider-unavailable')
        with self.patches(mock_operations=False), patch.object(images, 'docker_configuration', return_value='/synthetic/config'), \
             patch.object(p, '_run_process', side_effect=self.unavailable_capture):
            with self.assertRaises(p.ProvisioningError) as error: self.session.provision()
            self.assertEqual(error.exception.code, 'terraform_failed')
            self.assertTrue(self.session.receipt['unknown_outcome'])
            with self.assertRaises(p.ProvisioningError): self.session.destroy()
            self.assertEqual(self.session.owned, {})
            proof = self.session.prove_provider_unavailable()
            self.assertEqual(proof['status'], 'proved-zero-contact')
            self.assertFalse(self.session.receipt['unknown_outcome'])
            result = self.session.destroy()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['primary_failure']['code'], 'terraform_failed')
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(result['resources'], [])
        names = [x['operation'] for x in result['operations']]
        self.assertIn('apply', names); self.assertIn('destroy', names)
        self.assertEqual(names.count('probe-unavailable'), 2)
        self.assertFalse(any(call[:2] == ('docker', 'update') or call == ('docker', 'start', CID) for call in self.calls))

    def test_unavailable_proof_refuses_extra_operation_or_owned_resource_without_clearing_unknown(self):
        self.session = p.ProvisioningSession(self.run, self.lease, toolchain=self.tools, scenario='provider-unavailable')
        with self.patches(mock_operations=False), patch.object(images, 'docker_configuration', return_value='/synthetic/config'), \
             patch.object(p, '_run_process', side_effect=self.unavailable_capture):
            with self.assertRaises(p.ProvisioningError): self.session.provision()
            self.lease.record['resources'].append({'kind': 'network', 'id': NET, 'outcome': 'pending'})
            with self.assertRaises(p.ProvisioningError): self.session.prove_provider_unavailable()
            self.assertTrue(self.session.receipt['unknown_outcome'])
            self.lease.record['resources'].pop()
            (self.session.state / 'operations/unaccounted-1.out').write_bytes(b'Synthetic incomplete request')
            with self.assertRaises(p.ProvisioningError): self.session.prove_provider_unavailable()
            self.assertTrue(self.session.receipt['unknown_outcome'])

    def test_healthy_scenario_cannot_use_the_specific_unavailable_proof_or_repeat_unknown_mutation(self):
        self.session.prepare()
        self.session.receipt['unknown_outcome'] = True
        with self.assertRaises(p.ProvisioningError): self.session.prove_provider_unavailable()
        self.session.verify_provisioner = lambda _: None
        with patch.object(images, 'inspect', return_value={}), patch.object(p, '_run_process') as execute:
            with self.assertRaises(p.ProvisioningError) as error: self.session.operation('apply')
            self.assertEqual(error.exception.code, 'daemon_outcome_unknown')
            execute.assert_not_called()

    def test_stopped_stage_allows_pause_without_start_or_invented_inventory(self):
        with self.patches():
            owned = self.session.create_stopped()
            self.assertEqual(owned, {'docker_container.target[\"target-001\"]': CID, 'docker_network.run': NET})
            self.assertEqual(self.session.receipt['status'], 'created-stopped')
            self.assertIsNone(self.session.receipt['inventory'])
            self.assertFalse(self.running[CID])
            self.assertEqual(self.target_pid_limit, self.plan['limits']['target']['pids_limit'])
            self.assertNotIn(('docker', 'start', CID), self.calls)
            inventory = self.session.start_and_inventory()
            self.assertEqual(inventory['targets'][0]['resource_id'], CID)
            self.assertEqual(self.session.receipt['target_started_at'], '2026-10-23T14:00:00Z')
            with self.assertRaises(p.ProvisioningError) as error:
                self.session.start_and_inventory()
            self.assertEqual(error.exception.code, 'target_not_ready')
            self.assertEqual(self.calls.count(('docker', 'start', CID)), 1)

    def test_expired_controller_during_pause_cannot_start_target_or_allocate_replacement(self):
        with self.patches():
            self.session.create_stopped()
            self.running[CONTROLLER] = False
            with self.assertRaises(p.ProvisioningError) as error:
                self.session.start_and_inventory()
            self.assertEqual(error.exception.code, 'provisioner_unavailable')
            self.assertEqual(self.session.receipt['primary_failure']['code'], 'provisioner_unavailable')
            self.assertNotIn(('docker', 'start', CID), self.calls)
            self.assertEqual(self.calls.count(('docker', 'start', CONTROLLER)), 1)
            self.assertIsNone(self.session.receipt['inventory'])

    def test_resumed_start_rechecks_stopped_limits_and_preserves_failure(self):
        with self.patches():
            self.session.create_stopped()
            self.target_pid_limit = 1
            with self.assertRaises(p.ProvisioningError) as error:
                self.session.start_and_inventory()
            self.assertEqual(error.exception.code, 'limits_not_enforced')
            self.assertEqual(self.session.receipt['primary_failure']['code'], 'limits_not_enforced')
            self.assertNotIn(('docker', 'start', CID), self.calls)
            self.assertIsNone(self.session.receipt['inventory'])

    def test_stock_target_cannot_inherit_the_ubi_only_audit_write_capability(self):
        self.assertIs(self.session.target_runtime_policy,p.TargetRuntimePolicy.QUALIFIED_SSH)
        with self.patches():
            self.session.create_stopped()
            target=self.container(CID);target['HostConfig']['CapAdd'].append('AUDIT_WRITE')
            with self.assertRaises(p.ProvisioningError) as error:self.session.verify_target(target,stopped=True)
            self.assertEqual(error.exception.code,'unsafe_target')
            self.assertFalse(self.running[CID])
            self.session.destroy()

    def test_actual_workflow_policy_orders_pid_and_inspection_before_start_then_provider_refresh_destroy(self):
        with self.patches():
            inventory = self.session.provision()
            self.assertEqual(inventory['targets'][0]['host'], '172.31.77.2')
            result = self.session.destroy()
        update = self.calls.index(('docker', 'update', '--pids-limit', '64', CID))
        start = self.calls.index(('docker', 'start', CID))
        self.assertLess(update, start)
        self.assertIn(('inspect', 'container', CID), self.calls[update + 1:start])
        self.assertLess(self.calls.index(('operation', 'refresh-apply')), self.calls.index(('operation', 'output')))
        self.assertLess(self.calls.index(('operation', 'destroy')), self.calls.index(('docker', 'rm', CONTROLLER)))
        self.assertFalse(any(call[:2] == ('docker', 'rm') and CID in call for call in self.calls))
        self.assertEqual(result['cleanup'], 'completed')
        self.assertFalse(result['runtime_pipeline_complete'])
        self.assertFalse(result['production_iso_eligible'])

    def test_apply_failure_keeps_primary_private_state_and_never_native_deletes_targets(self):
        original = self.operation
        def fail(name):
            if name == 'apply': raise p.ProvisioningError('synthetic_provider_create_failure', 'Synthetic provider failure')
            if name == 'show-state': raise p.ProvisioningError('synthetic_diagnostic_failure', 'Secondary failure')
            return original(name)
        with self.patches(), patch.object(self.session, 'operation', side_effect=fail):
            with self.assertRaises(p.ProvisioningError): self.session.provision()
        self.assertEqual(self.session.receipt['primary_failure']['code'], 'synthetic_provider_create_failure')
        self.assertEqual(self.session.receipt['secondary_failures'][0]['code'], 'synthetic_diagnostic_failure')
        self.assertTrue(self.session.state.joinpath('apply.tfplan').exists())
        self.assertFalse(any(call[:2] in (('docker', 'rm'), ('operation', 'destroy')) for call in self.calls))

    def test_previously_started_target_is_refused_before_pid_update_or_start(self):
        original = self.inspect
        def previously_started(kind, identifier, **kwargs):
            result = original(kind, identifier, **kwargs)
            if identifier == CID:
                result['State'].update(Status='exited', StartedAt='2026-10-23T14:00:00Z')
            return result
        with self.patches(), patch.object(images, 'inspect', side_effect=previously_started):
            with self.assertRaises(p.ProvisioningError) as error: self.session.provision()
        self.assertEqual(error.exception.code, 'premature_start')
        self.assertFalse(any(call[:2] == ('docker', 'update') or call == ('docker', 'start', CID) for call in self.calls))
        self.assertEqual(self.session.owned['docker_container.target[\"target-001\"]'], CID)

    def test_only_the_independently_verified_internal_run_endpoint_is_allowed(self):
        with self.patches():
            self.session.provision()
            name = 'wormhole-' + self.run.id + '-network'
            cases = []
            value = self.container(CID); value['HostConfig']['NetworkMode'] = 'foreign-network'; cases.append(value)
            value = self.container(CID); value['NetworkSettings']['Networks'] = {'bridge': {'NetworkID': NET}}; cases.append(value)
            value = self.container(CID); value['NetworkSettings']['Networks']['bridge'] = {'NetworkID': 'e' * 64}; cases.append(value)
            for identifier in ('', 'e' * 64):
                value = self.container(CID); value['NetworkSettings']['Networks'][name]['NetworkID'] = identifier; cases.append(value)
            for value in cases:
                with self.subTest(value=value), self.assertRaises(p.ProvisioningError): self.session.verify_target(value)
            self.running[CID] = False
            pending = self.container(CID); pending['NetworkSettings']['Networks'][name]['NetworkID'] = ''
            self.session.verify_target(pending, stopped=True)
            original = self.inspect
            for mutation in ('foreign-label', 'external', 'wrong-id'):
                def wrong(kind, identifier, **kwargs):
                    value = original(kind, identifier, **kwargs)
                    if kind == 'network':
                        if mutation == 'foreign-label': value['Labels'][images.LABEL + '.run_id'] = 'foreign'
                        if mutation == 'external': value['Internal'] = False
                        if mutation == 'wrong-id': value['Id'] = 'e' * 64
                    return value
                with self.subTest(mutation=mutation), patch.object(images, 'inspect', side_effect=wrong), self.assertRaises(p.ProvisioningError):
                    self.session.verify_target(pending, stopped=True)

    def test_observed_target_must_keep_the_exact_split_entrypoint_and_command(self):
        with self.patches():
            self.session.provision()
            for key, wrong in (('Cmd', []), ('Cmd', ['shell']), ('Entrypoint', ['/usr/bin/python3', '/opt/wormhole/runtime.py', 'target'])):
                value = self.container(CID); value['Config'][key] = wrong
                with self.subTest(field=key, value=wrong), self.assertRaises(p.ProvisioningError):
                    self.session.verify_target(value)

    def test_supplied_dictionary_cannot_bypass_actual_tool_cache_revalidation(self):
        from wormhole import toolchain
        self.cache.stop()
        with patch.object(toolchain, 'validate_cache', side_effect=p.ProvisioningError('tool_hash_mismatch', 'Synthetic unverified cache')) as validator, \
             patch.object(images, 'docker', side_effect=AssertionError('No allocation with unverified tools')):
            with self.assertRaises(p.ProvisioningError) as error: self.session.prepare()
        self.assertEqual(error.exception.code, 'tool_hash_mismatch')
        validator.assert_called_once()

    def test_destroy_ownership_mismatch_blocks_terraform_delete_and_preserves_primary(self):
        with self.patches():
            self.session.provision()
            self.session.receipt['primary_failure'] = {'code': 'earlier_readiness_failure'}
            original = self.inspect
            def wrong(kind, identifier, **kwargs):
                value = original(kind, identifier, **kwargs)
                if kind == 'container' and identifier == CID: value['Config']['Labels'][images.LABEL + '.run_id'] = 'unrelated-sentinel'
                return value
            with patch.object(images, 'inspect', side_effect=wrong), self.assertRaises(p.ProvisioningError): self.session.destroy()
        self.assertNotIn(('operation', 'destroy-plan'), self.calls)
        self.assertNotIn(('operation', 'destroy'), self.calls)
        self.assertEqual(self.session.receipt['primary_failure']['code'], 'earlier_readiness_failure')
        self.assertEqual(self.session.receipt['cleanup'], 'failed')

    def test_provider_output_cannot_redirect_inventory_and_input_edits_fail(self):
        with self.patches():
            self.session.provision()
            output = self.operation('output'); output['run']['value']['targets']['target-001']['network_data'][0]['ip_address'] = '127.0.0.1'
            with self.assertRaises(p.ProvisioningError): self.session.inventory(output)
            self.session.state.joinpath('main.tf').write_text('resource "unsafe" "injected" {}')
            with self.assertRaises(p.ProvisioningError): self.session.check_inputs()

    def test_serial_runs_have_disjoint_state_names_and_public_input(self):
        other = create_run(self.root / 'runs', fixture=False, identity=(SHA, False))
        self.assertNotEqual(other.id, self.run.id)
        self.assertNotEqual(other.file('private/terraform'), self.session.state)
        self.assertNotEqual(inputs(other.id)['run_id'], self.session.variables['run_id'])

    def test_released_lease_and_destroy_only_operation_cannot_create_resources(self):
        with patch.object(self.lease, '_active', side_effect=p.ProvisioningError('lease_inactive', 'Synthetic released lease')):
            with self.assertRaises(p.ProvisioningError): self.session.prepare()
        self.session.destroy_only = True; self.lease._reconciliation_only = True
        with patch.object(images, 'inspect', side_effect=AssertionError('No Docker observation for forbidden operation')):
            for name in ('plan', 'apply', 'refresh-plan', 'refresh-apply', 'init'):
                with self.assertRaises(p.ProvisioningError) as error: self.session.operation(name)
                self.assertEqual(error.exception.code, 'destroy_only')
        with self.assertRaises(p.ProvisioningError): self.session.start_provisioner()

    def test_operation_requires_complete_bounded_receipt_and_matching_captured_output(self):
        self.session.prepare()
        self.session.provisioner = CONTROLLER; self.session.image_labels = self.image_labels
        self.session.uid, self.session.gid, self.session.socket_groups = 0, 0, []
        self.session.mounts = {}
        self.session.verify_provisioner = lambda _: None
        operations = self.session.state / 'operations'; operations.mkdir(mode=0o700)
        def capture(args, **kwargs):
            name, attempt = args[-2], int(args[-1])
            raw = b'{"terraform_version":"1.17.0","platform":"linux_amd64"}'
            stem = operations / (name + '-' + str(attempt)); stem.with_suffix('.out').write_bytes(raw); stem.with_suffix('.out').chmod(0o600)
            value = {'operation': name, 'attempt': attempt, 'returncode': 0, 'duration_seconds': .01,
                'output_bytes': len(raw), 'output_sha256': hashlib.sha256(raw).hexdigest(),
                'truncated': False, 'timed_out': False, 'passed': True}
            if attempt == 2: value['output_sha256'] = '0' * 64
            if attempt == 3: value['truncated'] = True
            atomic_json(stem.with_suffix('.json'), value)
            return {'status': 'pass', 'returncode': 0, 'log': b'bounded synthetic receipt', 'log_truncated': False}
        with patch.object(images, 'inspect', return_value={}), patch.object(images, 'docker_configuration', return_value='/synthetic/config'), \
             patch.object(p, '_run_process', side_effect=capture):
            self.assertEqual(self.session.operation('version')['terraform_version'], '1.17.0')
            with self.assertRaises(p.ProvisioningError): self.session.operation('version')
            with self.assertRaises(p.ProvisioningError): self.session.operation('version')
            self.assertTrue(self.session.receipt['unknown_outcome'])

    def test_mutating_exec_crash_persists_unknown_intent_before_launch(self):
        self.session.prepare()
        self.session.provisioner = CONTROLLER; self.session.image_labels = self.image_labels
        self.session.uid, self.session.gid, self.session.socket_groups = 0, 0, []
        self.session.mounts = {}; self.session.verify_provisioner = lambda _: None
        def crash(*args, **kwargs):
            value = json.loads(self.run.file('evidence/provisioning.json').read_text())
            self.assertTrue(value['unknown_outcome'])
            raise KeyboardInterrupt
        with patch.object(images, 'inspect', return_value={}), patch.object(images, 'docker_configuration', return_value='/synthetic/config'), \
             patch.object(p, '_run_process', side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.session.operation('apply')
        self.assertTrue(json.loads(self.run.file('evidence/provisioning.json').read_text())['unknown_outcome'])

    def test_nonzero_mutating_result_keeps_unknown_daemon_outcome_despite_terminal_capture(self):
        self.session.prepare()
        self.session.provisioner = CONTROLLER; self.session.image_labels = self.image_labels
        self.session.uid, self.session.gid, self.session.socket_groups = 0, 0, []
        self.session.mounts = {}; self.session.verify_provisioner = lambda _: None
        operations = self.session.state / 'operations'; operations.mkdir(mode=0o700)
        def capture(args, **kwargs):
            attempt = int(args[-1]); passed = attempt == 1
            raw = b'Synthetic completed Terraform result, not an actual Docker observation'
            stem = operations / ('apply-' + str(attempt))
            stem.with_suffix('.out').write_bytes(raw); stem.with_suffix('.out').chmod(0o600)
            atomic_json(stem.with_suffix('.json'), {'operation': 'apply', 'attempt': attempt, 'returncode': 0 if passed else 1,
                'duration_seconds': .01, 'output_bytes': len(raw), 'output_sha256': hashlib.sha256(raw).hexdigest(),
                'truncated': False, 'timed_out': False, 'passed': passed})
            return {'status': 'pass' if passed else 'fail', 'returncode': 0 if passed else 2,
                    'log': b'bounded synthetic receipt', 'log_truncated': False}
        with patch.object(images, 'inspect', return_value={}), patch.object(images, 'docker_configuration', return_value='/synthetic/config'), \
             patch.object(p, '_run_process', side_effect=capture):
            self.session.operation('apply')
            self.assertFalse(self.session.receipt['unknown_outcome'])
            with self.assertRaises(p.ProvisioningError): self.session.operation('apply')
            self.assertTrue(self.session.receipt['unknown_outcome'])
        self.assertTrue(json.loads(self.run.file('evidence/provisioning.json').read_text())['unknown_outcome'])

    def test_retained_recovery_revalidates_capacity_before_restart_and_refuses_unknown_or_incomplete(self):
        with self.patches():
            self.session.provision()
            self.running[CONTROLLER] = False
            self.lease._reconciliation_only = True
            self.lease.record = {'resources': [{'kind': kind, 'id': identifier, 'outcome': 'pending'} for kind, identifier in
                (('container', CONTROLLER), ('container', CID), ('network', NET))]}
            (self.session.state / 'operations').mkdir(mode=0o700)
            resumed = p.ProvisioningSession.resume_destroy(self.run, self.lease)
            self.assertTrue(resumed.destroy_only)
            self.assertLess(self.calls.index(('recovery-capacity', CONTROLLER)),
                            len(self.calls) - 1 - self.calls[::-1].index(('docker', 'start', CONTROLLER)))
            resumed.receipt['unknown_outcome'] = True; resumed.save()
            with self.assertRaises(p.ProvisioningError) as error: p.ProvisioningSession.resume_destroy(self.run, self.lease)
            self.assertEqual(error.exception.code, 'daemon_outcome_unknown')
            resumed.receipt['unknown_outcome'] = False; resumed.save()
            (self.session.state / 'operations/apply-1.out').write_bytes(b'incomplete synthetic operation')
            with self.assertRaises(p.ProvisioningError) as error: p.ProvisioningSession.resume_destroy(self.run, self.lease)
            self.assertEqual(error.exception.code, 'recovery_scope')


@unittest.skipUnless(os.name == 'posix', 'Actual bounded synthetic subprocess requires POSIX process groups')
class RuntimeCapture(unittest.TestCase):
    def test_probe_child_receives_only_fixed_role_after_parent_guard_and_actual_bounded_capture(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-probe-child-synthetic-') as temporary:
            root = Path(temporary)
            original = runtime.subprocess.Popen
            def synthetic_child(arguments, **kwargs):
                self.assertEqual(arguments, [sys.executable, str(Path(runtime.__file__).resolve()), 'probe-unavailable-internal'])
                self.assertEqual(kwargs['env']['WORMHOLE_ROLE'], 'provisioner')
                self.assertNotIn('DOCKER_CONTEXT', kwargs['env'])
                # The real child process verifies environment transport only. Its
                # execution-location guard is a labeled fixture, not container proof.
                return original([sys.executable, '-c', 'import json,os;print(json.dumps({"role":os.environ.get("WORMHOLE_ROLE")}))'], **kwargs)
            with patch.object(runtime, 'STATE', root), patch.object(runtime, 'guard') as guard, \
                 patch.object(runtime.subprocess, 'Popen', side_effect=synthetic_child), \
                 patch.dict(os.environ, {'WORMHOLE_ROLE': 'untrusted-ambient-role', 'DOCKER_CONTEXT': 'synthetic-remote'}):
                self.assertEqual(runtime.operation('probe-unavailable', 1), 0)
                guard.assert_called_once()
            self.assertEqual(json.loads((root / 'operations/probe-unavailable-1.out').read_text()), {'role': 'provisioner'})
            with patch.object(runtime, 'STATE', root), patch.object(runtime, 'guard', side_effect=ValueError('Synthetic invalid parent boundary')), \
                 patch.object(runtime.subprocess, 'Popen') as execute, self.assertRaises(ValueError):
                runtime.operation('probe-unavailable', 2)
            execute.assert_not_called()
            self.assertFalse((root / 'operations/probe-unavailable-2.out').exists())

    def test_capture_bounds_timeout_and_attempt_immutability_without_terraform(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-runtime-synthetic-') as temporary:
            root = Path(temporary)
            with patch.object(runtime, 'STATE', root), patch.object(runtime, 'TOOL', sys.executable), \
                 patch.dict(runtime.OPERATIONS, {'synthetic': ('-c', 'print("x" * 400000)')}, clear=True), \
                 patch.object(runtime, 'environment', return_value={'PATH': os.environ['PATH']}):
                # Python does not accept Terraform's -chdir global flag: remove that one fixed prefix in the subprocess fixture.
                original = runtime.subprocess.Popen
                def fixture(arguments, **kwargs): return original([arguments[0], *arguments[2:]], **kwargs)
                with patch.object(runtime.subprocess, 'Popen', side_effect=fixture):
                    self.assertEqual(runtime.operation('synthetic', 1), 2)
                    self.assertTrue(json.loads((root / 'operations/synthetic-1.json').read_text())['truncated'])
                    self.assertLessEqual((root / 'operations/synthetic-1.out').stat().st_size, runtime.LOG_LIMIT)
                    with self.assertRaises(ValueError): runtime.operation('synthetic', 1)
                    with patch.dict(runtime.OPERATIONS, {'synthetic': ('-c', 'import time;time.sleep(10)')}, clear=True), \
                         patch.object(runtime, 'OPERATION_TIMEOUT', .2):
                        self.assertEqual(runtime.operation('synthetic', 2), 2)
                    record = json.loads((root / 'operations/synthetic-2.json').read_text())
                    self.assertTrue(record['timed_out'])
                    self.assertLess(record['duration_seconds'], 2)


if __name__ == '__main__': unittest.main()
