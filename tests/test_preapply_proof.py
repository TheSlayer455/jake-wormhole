"""Synthetic captured-byte models only; no Terraform, Docker or host recovery.

Git reads retrieve public authored source bytes. Every operation output and
receipt below is a labeled synthetic model, never a live execution claim.
"""
import ast
import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from wormhole import preapply_proof as p


def capture(raw):
    return {'sha256': p.sha(raw), 'size_bytes': len(raw), 'raw_base64': base64.b64encode(raw).decode('ascii')}


def replace_operation(bundle, name, *, raw=None, changes=None):
    item = next(value for value in bundle['provisioning_receipt']['operations'] if value['operation'] == name)
    meta = p.decode(base64.b64decode(bundle['operation_files'][name+'-1.json']['raw_base64']))
    if raw is not None:
        meta.update(output_bytes=len(raw), output_sha256=p.sha(raw))
        bundle['operation_files'][name+'-1.out'] = capture(raw)
    meta.update(changes or {})
    item.update(meta)
    bundle['operation_files'][name+'-1.json'] = capture(p.canonical(meta))


def synthetic_bundle(sources):
    common = deepcopy(p.COMMON)
    target_plan = {'schema_version': '1.0', 'resource_layout': 'indexed-targets-v1', 'profile': 'twenty-targets',
        'target_count': 20, 'target_ids': list(p.TARGETS)}
    root = '/srv/homelab/jake-wormhole/runtime/runs/' + p.RUN
    limits = json.loads(sources['profiles/admission-v1.json'])['limits']['target']
    variables = {'run_id': p.RUN, 'source_revision': p.SOURCE, 'image': p.IMAGE, 'public_input': root+'/private/target-input',
        'target_ids': list(p.TARGETS), 'target_limits': {'memory': limits['memory_mib'], 'memory_swap': limits['memory_mib'],
            'cpus': format(limits['cpus'], '.6g'), 'log_driver': 'json-file',
            'log_opts': {'max-size': str(limits['log_max_size_bytes']), 'max-file': str(limits['log_max_files'])}},
        'target_capabilities': p.POLICY['capabilities']}
    inputs = {'main.tf': sources['provisioning/main.tf'], '.terraform.lock.hcl': sources['provisioning/.terraform.lock.hcl'],
        'terraform.tfvars.json': json.dumps(variables, sort_keys=True).encode(), 'wormhole.tfrc': p.TFRC}
    hashes = {name: p.sha(raw) for name, raw in inputs.items()}
    lock = json.loads(sources['provisioning/tools.lock.json'])
    members, archives = [], []
    for artifact in lock['artifacts']:
        prefix = 'bin/' if artifact['kind'] == 'terraform' else 'mirror/registry.terraform.io/kreuzwerker/docker/4.6.0/linux_amd64/'
        members.extend({'path': prefix+item['name'], 'bytes': item['bytes'], 'sha256': item['sha256'], 'mode': item['mode']}
            for item in artifact['members'])
        archives.append({'path': 'archives/'+artifact['filename'], 'bytes': artifact['bytes'], 'sha256': artifact['sha256']})
    tool = {key: common[key] for key in ('schema_version', 'run_id', 'source_revision', 'source_dirty')}
    tool.update(operation='terraform-toolchain-preparation', status='prepared', members=members, archives=archives,
        lock_sha256=p.SOURCE_FILES['provisioning/tools.lock.json'], downloaded_binaries_executed=False,
        host_tools_installed=False, provider_h1={'value': p.H1})
    receipt = {**common, 'operation': 'terraform-smoke', 'status': 'failed', 'scenario': 'healthy', 'unknown_outcome': True,
        'resources': [], 'inventory': None, 'cleanup': 'not-started', 'provisioner_id': p.CONTROLLER, 'target_image': p.IMAGE,
        'resource_layout': 'indexed-targets-v1', 'target_plan': target_plan, 'pending_target_ids': list(p.TARGETS),
        'target_runtime_policy': deepcopy(p.POLICY), 'runtime_pipeline_complete': False, 'production_iso_eligible': False,
        'primary_failure': deepcopy(p.PRIMARY), 'secondary_failures': [], 'updated_at': '2026-10-24T17:46:11.000Z',
        'actual_tools': {'terraform_version': '1.17.0', 'platform': 'linux_amd64', 'provider_version': '4.6.0',
            'offline_readonly_lock_h1_confirmed': p.H1, 'provider_schema_observed': True},
        'terraform_version': '1.17.0', 'provider_version': '4.6.0', 'provider': 'registry.terraform.io/kreuzwerker/docker',
        'toolchain': tool, 'provisioner_cgroups': {'memory.max': '536870912', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '50000 100000'},
        'input_hashes': hashes, 'operations': []}
    controller = {'schema_version': '1.0', 'run_id': p.RUN, 'source_revision': p.SOURCE, 'id': p.CONTROLLER, 'uid': 0, 'gid': 0,
        'groups': [], 'image_labels': {'synthetic': 'Not an image-inspection proof; caller must verify actual exact labels.'},
        'mounts': {'/opt/toolchain': [root+'/private/toolchain', False],
            '/opt/provisioning': ['/srv/homelab/jake-wormhole/source/'+p.SOURCE+'/provisioning', False],
            '/state': [root+'/private/terraform', True], '/var/run/docker.sock': ['/var/run/docker.sock', True]},
        'inputs': hashes, 'scenario': 'healthy', 'resource_layout': 'indexed-targets-v1', 'target_plan': deepcopy(target_plan),
        'target_runtime_policy': deepcopy(p.POLICY)}
    schema = {'provider_schemas': {'registry.terraform.io/kreuzwerker/docker': {'resource_schemas': {
        'docker_network': {}, 'docker_container': {'block': {'attributes': {name: {} for name in ('start', 'must_run', 'cpus', 'memory', 'memory_swap')}}}}}}}
    outputs = {'version': p.canonical({'terraform_version': '1.17.0', 'platform': 'linux_amd64'}),
        'init': b'Synthetic offline init completed; no command was executed.', 'schema': p.canonical(schema),
        'plan': b'Synthetic partial diagnostic chunk before truncation.', 'show-state': p.canonical({'format_version': '1.0'})}
    files = {}
    for name in p.NAMES:
        raw = outputs[name]; truncated = name == 'plan'
        meta = {'operation': name, 'attempt': 1, 'returncode': -9 if truncated else 0, 'duration_seconds': .001,
            'output_bytes': len(raw), 'output_sha256': p.sha(raw), 'truncated': truncated, 'timed_out': False, 'passed': not truncated}
        files[name+'-1.out'] = capture(raw); files[name+'-1.json'] = capture(p.canonical(meta))
        receipt['operations'].append({**meta, 'client_status': 'fail' if truncated else 'pass', 'client_returncode': 2 if truncated else 0,
            'client_log_truncated': False, 'evidence': 'private/terraform/operations/'+name+'-1.out'})
    return {'schema_version': '1.0', 'manifest': {**common, 'profile': 'twenty-targets', 'created_at': '2026-10-24T17:46:00.000Z',
            'runtime_pipeline_complete': False, 'production_iso_eligible': False}, 'controller': controller, 'provisioning_receipt': receipt,
        'journal': {'run_id': p.RUN, 'source_revision': p.SOURCE, 'state': 'active', 'phase': 'provisioning',
            'resources': [{'kind': 'container', 'id': p.CONTROLLER, 'outcome': 'pending', 'size_bytes': 0}],
            'plan': {'profile': 'twenty-targets', 'target_count': 20, 'synthetic': False, 'admitted': True}},
        'source_files': {name: capture(raw) for name, raw in sources.items()}, 'input_files': {name: capture(raw) for name, raw in inputs.items()},
        'operation_files': files, 'state_files': {'apply.tfplan': {'sha256': p.sha(b'synthetic partial saved plan'), 'size_bytes': 28},
            'terraform.tfstate': {'sha256': p.sha(b''), 'size_bytes': 0}}}


class PreapplyProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.sources = {name: subprocess.run(['git', 'show', p.SOURCE+':'+name], cwd=root, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15).stdout for name in p.SOURCE_FILES}

    def setUp(self):
        self.bundle = synthetic_bundle(self.sources)

    def prove(self):
        return p.prove_preapply_failure(self.bundle)

    def refused(self, changes):
        original = deepcopy(self.bundle)
        changes(self.bundle)
        with self.assertRaises(p.PreapplyProofError): self.prove()
        self.bundle = original

    def test_specific_terminal_plan_truncation_returns_proof_without_clearing_unknown_or_touching_input(self):
        original = deepcopy(self.bundle)
        with patch('builtins.open', side_effect=AssertionError('Pure proof performed IO')):
            result = self.prove()
        self.assertEqual(self.bundle, original)
        self.assertEqual(result, self.prove())
        self.assertEqual(result['primary_failure'], p.PRIMARY)
        self.assertTrue(result['original_unknown_outcome'])
        self.assertFalse(result['unknown_cleared'])
        self.assertFalse(result['allocation_permitted'])
        self.assertEqual(result['mutating_operations_observed'], [])
        self.assertEqual(len(result['operations']), 5)
        self.assertEqual(result['commands']['plan'][0], 'plan')
        self.assertLess(len(p.canonical(result)), 32768)
        self.assertNotIn('raw_base64', p.canonical(result).decode())
        self.assertNotIn(self.bundle['operation_files']['plan-1.out']['raw_base64'], p.canonical(result).decode())

    def test_mutation_probe_retry_and_unrecorded_attempts_never_establish_preapply_proof(self):
        for name in ('apply', 'refresh-apply', 'destroy', 'probe-unavailable', 'plan-2'):
            with self.subTest(name=name):
                self.refused(lambda b: b['operation_files'].update({name+'-1.out': capture(b'Synthetic unrecorded attempt')}))
                self.refused(lambda b: b['provisioning_receipt']['operations'].append({'operation': name}))
        self.refused(lambda b: b['provisioning_receipt']['operations'].reverse())
        self.refused(lambda b: b['operation_files'].pop('plan-1.json'))
        self.refused(lambda b: b['provisioning_receipt'].update(inflight_operation='apply'))

    def test_timeout_client_timeout_or_other_failed_operation_is_not_the_specific_safe_terminal_path(self):
        for changes in ({'timed_out': True}, {'returncode': -15}, {'truncated': False}, {'passed': True},
            {'attempt': True}, {'duration_seconds': float('nan')}):
            with self.subTest(changes=changes):
                if 'duration_seconds' in changes:
                    self.refused(lambda b: b['provisioning_receipt']['operations'][3].update(changes))
                else: self.refused(lambda b: replace_operation(b, 'plan', changes=changes))
        for changes in ({'client_status': 'timeout'}, {'client_returncode': -9}, {'client_log_truncated': True}):
            self.refused(lambda b: b['provisioning_receipt']['operations'][3].update(changes))
        self.refused(lambda b: replace_operation(b, 'schema', changes={'truncated': True}))

    def test_metadata_output_hashes_exact_record_and_raw_size_are_required(self):
        self.refused(lambda b: b['operation_files']['plan-1.out'].update(sha256='0'*64))
        self.refused(lambda b: b['operation_files']['schema-1.out'].update(size_bytes=True))
        self.refused(lambda b: b['operation_files'].update({'plan-1.json': capture(b'{"operation":"plan","operation":"apply"}')}))
        self.refused(lambda b: b['provisioning_receipt']['operations'][0].update(output_sha256='0'*64))
        self.refused(lambda b: b['operation_files']['init-1.out'].update(raw_base64='@@@'))
        self.refused(lambda b: b['operation_files']['plan-1.json'].update(raw_base64=''))

    def test_empty_snapshot_alone_never_overrides_allocated_resources_or_started_targets(self):
        self.refused(lambda b: b['journal']['resources'].append({'kind': 'network', 'id': '1'*64, 'outcome': 'pending', 'size_bytes': 0}))
        self.refused(lambda b: b['journal']['resources'][0].update(outcome='absent'))
        self.refused(lambda b: b['provisioning_receipt'].update(resources=[{'id': '1'*64}]))
        self.refused(lambda b: b['provisioning_receipt'].update(targets_started=[]))
        self.refused(lambda b: b['provisioning_receipt'].update(validated_plan_sha256='1'*64))
        self.refused(lambda b: replace_operation(b, 'show-state', raw=p.canonical({'format_version': '1.0', 'values': {'root_module': {}}})))

    def test_exact_source_identity_twenty_plan_controller_and_first_primary_are_bound(self):
        for mutate in (
            lambda b: b['manifest'].update(source_dirty=True), lambda b: b['manifest'].update(run_id='foreign'),
            lambda b: b['manifest'].update(profile='five-targets'), lambda b: b['controller'].update(id='2'*64),
            lambda b: b['controller']['target_plan']['target_ids'].pop(), lambda b: b['controller'].update(uid=False),
            lambda b: b['controller']['target_runtime_policy']['capabilities'].append('AUDIT_CONTROL'),
            lambda b: b['journal']['plan'].update(target_count=True), lambda b: b['journal']['plan'].update(synthetic=True),
            lambda b: b['provisioning_receipt']['primary_failure'].update(recorded_at='2026-10-24T17:46:10.000Z'),
            lambda b: b['provisioning_receipt'].update(unknown_outcome=False),
            lambda b: b['provisioning_receipt']['secondary_failures'].append({'code': 'later_failure'})):
            self.refused(mutate)

    def test_changed_hcl_and_mutually_changed_input_hashes_still_refuse(self):
        def changed(b):
            raw = self.sources['provisioning/main.tf'] + b'\n# Synthetic tampering\n'
            b['input_files']['main.tf'] = capture(raw)
            for parent in (b['controller']['inputs'], b['provisioning_receipt']['input_hashes']): parent['main.tf'] = p.sha(raw)
        self.refused(changed)
        self.refused(lambda b: b['source_files'].update({'provisioning/main.tf': capture(b'Synthetic replaced source')}))
        self.refused(lambda b: b['source_files'].pop('wormhole/provisioning.py'))
        self.refused(lambda b: b['input_files'].update({'arbitrary.tf': capture(b'Synthetic extra input')}))

    def test_changed_tfvars_even_with_mutually_changed_hashes_or_writable_source_mount_refuse(self):
        def changed(b):
            raw = p.decode(base64.b64decode(b['input_files']['terraform.tfvars.json']['raw_base64']))
            raw['target_capabilities'].append('KILL'); raw = json.dumps(raw, sort_keys=True).encode()
            b['input_files']['terraform.tfvars.json'] = capture(raw)
            for parent in (b['controller']['inputs'], b['provisioning_receipt']['input_hashes']): parent['terraform.tfvars.json'] = p.sha(raw)
        self.refused(changed)
        self.refused(lambda b: b['controller']['mounts']['/opt/provisioning'].__setitem__(1, True))
        self.refused(lambda b: b['controller']['mounts'].update({'/host': ['/', True]}))

    def test_real_toolchain_members_h1_provider_and_cgroup_contract_are_required(self):
        for mutate in (lambda b: b['provisioning_receipt']['toolchain']['members'][0].update(sha256='0'*64),
            lambda b: b['provisioning_receipt']['toolchain'].update(host_tools_installed=True),
            lambda b: b['provisioning_receipt']['actual_tools'].update(offline_readonly_lock_h1_confirmed='wrong'),
            lambda b: b['provisioning_receipt'].update(provider='arbitrary/provider'),
            lambda b: b['provisioning_receipt']['provisioner_cgroups'].update(**{'pids.max': 'max'})):
            self.refused(mutate)

    def test_retained_partial_plan_and_empty_state_are_hash_descriptors_never_apply_authority(self):
        self.bundle['state_files']['.terraform.tfstate.lock.info'] = {'sha256': 'a'*64, 'size_bytes': 141}
        result = self.prove()
        self.assertEqual(result['retained_state_files'], self.bundle['state_files'])
        self.refused(lambda b: b['state_files'].update({'destroy.tfplan': {'sha256': 'a'*64, 'size_bytes': 4}}))
        self.refused(lambda b: b['state_files']['apply.tfplan'].update(size_bytes=17*1024**2))
        self.refused(lambda b: b['state_files']['apply.tfplan'].update(raw_base64='unexpected'))

    def test_malformed_oversize_nonfinite_or_non_json_bundle_has_controlled_refusal(self):
        for value in (None, [], {'unexpected': True}, {'schema_version': 'x'*(6*1024**2+1)}, {'value': float('inf')}, {'value': object()}):
            with self.subTest(type=type(value).__name__), self.assertRaises(p.PreapplyProofError): p.prove_preapply_failure(value)
        self.refused(lambda b: b.update(unexpected=True))
        self.refused(lambda b: replace_operation(b, 'version', raw=b'{"terraform_version":NaN}'))

    def test_pure_module_does_not_import_or_execute_runtime_io(self):
        tree = ast.parse(Path(p.__file__).read_text(encoding='utf-8'))
        imported = {node.names[0].name if isinstance(node, ast.Import) else node.module for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))}
        self.assertFalse(imported & {'os', 'pathlib', 'subprocess', 'socket', 'urllib', 'requests'})


if __name__ == '__main__': unittest.main()
