"""Pure proof for one original-source pre-apply diagnostic truncation.

This validates captured bytes only. It neither clears unknown_outcome nor grants
cleanup authority. The caller must independently hold the original Run/lease,
verify the exact controller, stop it and prove all processes/resources absent.
No filesystem, subprocess, network, Docker or mutable runtime API is imported.
"""
import ast
import base64
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import math
import re

SOURCE = '6f3f28e830911aea21f216d6e1c006a96202a771'
RUN = '37cb8286-4fc9-4ee0-ab2b-0001fe1edc8d'
CONTROLLER = '7adf95f8512ddf4cff5727373de4bc765f63f29b44a7466ed04c2ab91f42be99'
IMAGE = 'sha256:6d15eb2c495d48c1eb6485a74d1adaef3e0e3a6e7c83063ba8459f90c27c683e'
H1 = 'h1:1jD5QVpeLkdxKEWWJpTzNdxtR0WNNFq28Po4yq9w+VM='
PRIMARY = {'code': 'terraform_failed', 'recorded_at': '2026-10-24T17:46:09.446Z'}
SOURCE_FILES = {
    'provisioning/runtime.py': 'b7ac44a04b32b5f9d746f87c273ae6e485258fbfa62b1ece169798b1df0fbb94',
    'provisioning/main.tf': '6c9a271ad8d6ac0c74a087cd181c64419e1bbd40bba6c9f0f84f57e6ad41c16d',
    'provisioning/.terraform.lock.hcl': 'ab67cfd34439d786d0357a1f74deeebaeab1088e896cdeca3fd7439645ebec52',
    'provisioning/tools.lock.json': 'a0f8f4932e7a8ee837e73903e1b6fdddbed809fe2a029fda8db2dee57ad6ed4c',
    'profiles/admission-v1.json': '446b9970c1edb60eb38c9be589a2003fd4f697fb5751159f0f61d7d3f74f3c96',
    'wormhole/provisioning.py': '1f4d79a81a58795ec30c8dbfbd141787fb0a79f4c91d50d47dae460db390fb1a',
    'images/images.lock.json': '44e7c225a1e13a0b70d0778fb9b3ff12bc99adfaf5083816c90e2b537d26257e',
}
NAMES = ('version', 'init', 'schema', 'plan', 'show-state')
INPUTS = ('main.tf', '.terraform.lock.hcl', 'terraform.tfvars.json', 'wormhole.tfrc')
EXTRAS = {'apply.tfplan', 'terraform.tfstate', 'terraform.tfstate.backup', '.terraform.tfstate.lock.info', '.terraform/terraform.tfstate'}
TARGETS = ['target-' + str(i).zfill(3) for i in range(1, 21)]
COMMON = {'schema_version': '1.0', 'run_id': RUN, 'source_revision': SOURCE, 'source_dirty': False, 'mode': 'container-reference'}
POLICY = {'id': 'qualified-ssh-v1', 'capabilities': ['SETGID', 'SETUID', 'SYS_CHROOT']}
TFRC = b'disable_checkpoint = true\nprovider_installation {\n filesystem_mirror {\n path = "/opt/toolchain/mirror"\n include = ["registry.terraform.io/kreuzwerker/docker"]\n }\n}\n'
MAX_BUNDLE_BYTES = 10 * 1024**2


class PreapplyProofError(Exception):
    def __init__(self, code='preapply_proof_refused'):
        self.code = code
        super().__init__('Specific original pre-apply proof refused; preserve the failed Run and uncertainty.')


def require(value, code='preapply_proof_refused'):
    if not value:
        raise PreapplyProofError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same(left, right):
    return canonical(left) == canonical(right)


def bounded(value):
    pending = [(value, 0)]; count = 0; total = 0
    while pending:
        item, depth = pending.pop(); count += 1
        require(depth <= 32 and count <= 30000, 'preapply_bundle_bound')
        if type(item) is dict:
            require(len(item) <= 512 and all(type(key) is str for key in item), 'preapply_bundle_bound')
            pending.extend((key, depth+1) for key in item); pending.extend((part, depth+1) for part in item.values())
        elif type(item) is list:
            require(len(item) <= 512, 'preapply_bundle_bound'); pending.extend((part, depth+1) for part in item)
        elif type(item) is str:
            require(len(item) <= 6*1024**2, 'preapply_bundle_bound'); total += len(item)
        elif type(item) is float:
            require(math.isfinite(item), 'preapply_bundle_bound')
        else:
            require(item is None or type(item) in (bool, int), 'preapply_bundle_bound')
        require(total <= MAX_BUNDLE_BYTES, 'preapply_bundle_bound')


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'preapply_duplicate_json_key'); value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(PreapplyProofError()))


def captured(value, maximum):
    require(type(value) is dict and set(value) == {'sha256', 'size_bytes', 'raw_base64'} and
        type(value['sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['sha256']) and
        type(value['size_bytes']) is int and 0 <= value['size_bytes'] <= maximum and type(value['raw_base64']) is str and
        len(value['raw_base64']) <= ((maximum+2)//3)*4, 'preapply_capture_bound')
    raw = base64.b64decode(value['raw_base64'], validate=True)
    require(len(raw) == value['size_bytes'] and sha(raw) == value['sha256'], 'preapply_capture_changed')
    return raw


def timestamp(value):
    require(type(value) is str and len(value) <= 40)
    date = datetime.fromisoformat(value.replace('Z', '+00:00')); require(date.tzinfo is not None)
    return date


def original_runtime(raw):
    tree = ast.parse(raw)
    def value(node):
        # Original constants use integer multiplication. Interpret only that
        # tiny syntax; captured source is never imported or evaluated.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            left, right = value(node.left), value(node.right)
            require(type(left) is int and type(right) is int and 0 <= left*right <= 4*1024**2)
            return left*right
        return ast.literal_eval(node)
    def literal(name):
        found = [value(node.value) for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        require(len(found) == 1); return found[0]
    operations = literal('OPERATIONS')
    expected = {'version': ('version', '-json'), 'init': ('init', '-input=false', '-no-color', '-lockfile=readonly', '-get=false'),
        'schema': ('providers', 'schema', '-json'), 'plan': ('plan', '-parallelism=1', '-input=false', '-no-color', '-lock-timeout=0s', '-out=apply.tfplan'),
        'show-state': ('show', '-json')}
    require(all(operations[name] == command for name, command in expected.items()) and literal('LOG_LIMIT') == 65536 and
        literal('JSON_LIMIT') == 4*1024**2 and literal('OPERATION_TIMEOUT') == 120, 'preapply_command_policy_changed')
    return {key: list(value) for key, value in expected.items()}


def _prove(bundle):
    bounded(bundle)
    require(type(bundle) is dict and set(bundle) == {'schema_version', 'manifest', 'controller', 'provisioning_receipt', 'journal',
        'source_files', 'input_files', 'operation_files', 'state_files'} and bundle['schema_version'] == '1.0', 'preapply_closed_bundle')
    manifest, controller, receipt, journal = (bundle[key] for key in ('manifest', 'controller', 'provisioning_receipt', 'journal'))
    require(all(same({key: value.get(key) for key in COMMON}, COMMON) for value in (manifest, receipt)) and
        manifest['profile'] == 'twenty-targets' and manifest['runtime_pipeline_complete'] is False and manifest['production_iso_eligible'] is False,
        'preapply_original_identity')
    require(type(bundle['source_files']) is dict and set(bundle['source_files']) == set(SOURCE_FILES), 'preapply_source_file_set')
    sources = {name: captured(value, 256*1024) for name, value in bundle['source_files'].items()}
    require(all(sha(sources[name]) == digest for name, digest in SOURCE_FILES.items()), 'preapply_original_source_changed')
    commands = original_runtime(sources['provisioning/runtime.py'])
    target_plan = {'schema_version': '1.0', 'resource_layout': 'indexed-targets-v1', 'profile': 'twenty-targets',
        'target_count': 20, 'target_ids': TARGETS}
    fields = {'schema_version', 'run_id', 'source_revision', 'id', 'uid', 'gid', 'groups', 'mounts', 'image_labels', 'inputs',
        'scenario', 'target_runtime_policy', 'resource_layout', 'target_plan'}
    require(type(controller) is dict and set(controller) == fields and controller['schema_version'] == '1.0' and
        controller['run_id'] == RUN and controller['source_revision'] == SOURCE and controller['id'] == CONTROLLER and
        type(controller['uid']) is int and controller['uid'] == 0 and type(controller['gid']) is int and controller['gid'] == 0 and
        controller['groups'] == [] and controller['scenario'] == 'healthy' and controller['resource_layout'] == 'indexed-targets-v1' and
        same(controller['target_plan'], target_plan) and same(controller['target_runtime_policy'], POLICY), 'preapply_controller_scope')
    root = '/srv/homelab/jake-wormhole/runtime/runs/' + RUN
    mounts = {'/opt/toolchain': [root+'/private/toolchain', False], '/opt/provisioning': ['/srv/homelab/jake-wormhole/source/'+SOURCE+'/provisioning', False],
        '/state': [root+'/private/terraform', True], '/var/run/docker.sock': ['/var/run/docker.sock', True]}
    require(same(controller['mounts'], mounts), 'preapply_controller_mounts')
    require(journal['run_id'] == RUN and journal['source_revision'] == SOURCE and journal['state'] == 'active' and
        journal['phase'] == 'provisioning' and same(journal['resources'], [{'kind': 'container', 'id': CONTROLLER, 'outcome': 'pending', 'size_bytes': 0}]) and
        journal['plan']['profile'] == 'twenty-targets' and type(journal['plan']['target_count']) is int and journal['plan']['target_count'] == 20 and
        journal['plan']['synthetic'] is False and journal['plan']['admitted'] is True, 'preapply_only_owned_controller')
    require(receipt['operation'] == 'terraform-smoke' and receipt['status'] == 'failed' and receipt['scenario'] == 'healthy' and
        receipt['unknown_outcome'] is True and receipt['resources'] == [] and receipt['inventory'] is None and receipt['cleanup'] == 'not-started' and
        receipt['provisioner_id'] == CONTROLLER and receipt['target_image'] == IMAGE and receipt['resource_layout'] == 'indexed-targets-v1' and
        same(receipt['target_plan'], target_plan) and receipt['pending_target_ids'] == TARGETS and same(receipt['target_runtime_policy'], POLICY) and
        receipt['runtime_pipeline_complete'] is False and receipt['production_iso_eligible'] is False and
        'validated_plan_sha256' not in receipt and 'targets_started' not in receipt and 'target_binding' not in receipt, 'preapply_failed_before_apply')
    receipt_fields = set(COMMON) | {'operation', 'status', 'scenario', 'unknown_outcome', 'resources', 'inventory', 'cleanup', 'provisioner_id',
        'target_image', 'resource_layout', 'target_plan', 'pending_target_ids', 'target_runtime_policy', 'runtime_pipeline_complete',
        'production_iso_eligible', 'primary_failure', 'secondary_failures', 'updated_at', 'actual_tools', 'terraform_version', 'provider_version',
        'provider', 'input_hashes', 'operations', 'toolchain', 'provisioner_cgroups'}
    require(set(receipt) == receipt_fields, 'preapply_unrecorded_receipt_fields')
    failure = receipt['primary_failure']
    require(same(failure, PRIMARY) and
        timestamp(manifest['created_at']) <= timestamp(failure['recorded_at']) <= timestamp(receipt['updated_at']) and
        receipt['secondary_failures'] == [], 'preapply_first_primary_changed')
    require(same(receipt['actual_tools'], {'terraform_version': '1.17.0', 'platform': 'linux_amd64', 'provider_version': '4.6.0',
        'offline_readonly_lock_h1_confirmed': H1, 'provider_schema_observed': True}) and
        receipt['terraform_version'] == '1.17.0' and receipt['provider_version'] == '4.6.0' and
        receipt['provider'] == 'registry.terraform.io/kreuzwerker/docker', 'preapply_tool_identity')
    tool = receipt['toolchain']; lock = decode(sources['provisioning/tools.lock.json'])
    members, archives = [], []
    for artifact in lock['artifacts']:
        prefix = 'bin/' if artifact['kind'] == 'terraform' else 'mirror/registry.terraform.io/kreuzwerker/docker/4.6.0/linux_amd64/'
        members.extend({'path': prefix+item['name'], 'bytes': item['bytes'], 'sha256': item['sha256'], 'mode': item['mode']}
            for item in artifact['members'])
        archives.append({'path': 'archives/'+artifact['filename'], 'bytes': artifact['bytes'], 'sha256': artifact['sha256']})
    require(same({key: tool.get(key) for key in ('schema_version', 'run_id', 'source_revision', 'source_dirty')},
        {key: COMMON[key] for key in ('schema_version', 'run_id', 'source_revision', 'source_dirty')}) and
        tool['operation'] == 'terraform-toolchain-preparation' and tool['status'] == 'prepared' and
        tool['lock_sha256'] == SOURCE_FILES['provisioning/tools.lock.json'] and same(tool['members'], members) and same(tool['archives'], archives) and
        tool['downloaded_binaries_executed'] is False and tool['host_tools_installed'] is False and tool['provider_h1']['value'] == H1 and
        same(receipt['provisioner_cgroups'], {'memory.max': '536870912', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '50000 100000'}),
        'preapply_toolchain_identity')
    require(type(bundle['input_files']) is dict and set(bundle['input_files']) == set(INPUTS), 'preapply_fixed_inputs')
    inputs = {name: captured(value, 256*1024) for name, value in bundle['input_files'].items()}
    limits = decode(sources['profiles/admission-v1.json'])['limits']['target']
    variables = {'run_id': RUN, 'source_revision': SOURCE, 'image': IMAGE, 'public_input': root+'/private/target-input', 'target_ids': TARGETS,
        'target_limits': {'memory': limits['memory_mib'], 'memory_swap': limits['memory_mib'], 'cpus': format(limits['cpus'], '.6g'),
            'log_driver': 'json-file', 'log_opts': {'max-size': str(limits['log_max_size_bytes']), 'max-file': str(limits['log_max_files'])}},
        'target_capabilities': POLICY['capabilities']}
    expected = {'main.tf': sources['provisioning/main.tf'], '.terraform.lock.hcl': sources['provisioning/.terraform.lock.hcl'],
        'terraform.tfvars.json': json.dumps(variables, sort_keys=True).encode(), 'wormhole.tfrc': TFRC}
    hashes = {name: sha(raw) for name, raw in inputs.items()}
    require(inputs == expected and same(controller['inputs'], hashes) and same(receipt['input_hashes'], hashes), 'preapply_input_bytes_changed')
    names = {name+'-1'+suffix for name in NAMES for suffix in ('.json', '.out')}
    require(type(bundle['operation_files']) is dict and set(bundle['operation_files']) == names and type(receipt['operations']) is list and
        [item.get('operation') for item in receipt['operations']] == list(NAMES), 'preapply_no_unrecorded_or_mutating_attempt')
    output, evidence = {}, []
    for name, item in zip(NAMES, receipt['operations']):
        meta = decode(captured(bundle['operation_files'][name+'-1.json'], 16384))
        raw = captured(bundle['operation_files'][name+'-1.out'], 65536 if name in {'init', 'plan'} else 4*1024**2)
        fields = {'operation', 'attempt', 'returncode', 'duration_seconds', 'output_bytes', 'output_sha256', 'truncated', 'timed_out', 'passed'}
        truncated = name == 'plan'
        require(type(meta) is dict and set(meta) == fields and set(item) == fields | {'client_status', 'client_returncode', 'client_log_truncated', 'evidence'} and
            same(meta, {key: item[key] for key in fields}) and meta['operation'] == name and type(meta['attempt']) is int and meta['attempt'] == 1 and
            type(meta['returncode']) is int and meta['returncode'] == (-9 if truncated else 0) and meta['truncated'] is truncated and
            meta['timed_out'] is False and meta['passed'] is (not truncated) and type(meta['duration_seconds']) in (int, float) and
            math.isfinite(meta['duration_seconds']) and 0 <= meta['duration_seconds'] <= 130 and type(meta['output_bytes']) is int and
            meta['output_bytes'] == len(raw) and sha(raw) == meta['output_sha256'] and (not truncated or 0 < len(raw) <= 65536) and
            item['client_status'] == ('fail' if truncated else 'pass') and type(item['client_returncode']) is int and
            item['client_returncode'] == (2 if truncated else 0) and item['client_log_truncated'] is False and
            item['evidence'] == 'private/terraform/operations/'+name+'-1.out', 'preapply_terminal_pair_changed')
        if name in {'version', 'schema', 'show-state'}: output[name] = decode(raw)
        evidence.append({'operation': name, 'attempt': 1, 'output_sha256': sha(raw), 'output_bytes': len(raw),
            'metadata_sha256': bundle['operation_files'][name+'-1.json']['sha256'], 'terminal': True, 'truncated': truncated})
    require(output['version']['terraform_version'] == '1.17.0' and output['version']['platform'] == 'linux_amd64' and
        same(output['show-state'], {'format_version': '1.0'}), 'preapply_empty_observed_state')
    schema = output['schema']['provider_schemas']['registry.terraform.io/kreuzwerker/docker']['resource_schemas']
    require({'docker_network', 'docker_container'} <= set(schema) and
        {'start', 'must_run', 'cpus', 'memory', 'memory_swap'} <= set(schema['docker_container']['block']['attributes']) and
        'pids_limit' not in schema['docker_container']['block']['attributes'], 'preapply_provider_schema')
    require(type(bundle['state_files']) is dict and set(bundle['state_files']) <= EXTRAS, 'preapply_unexpected_state_file')
    for item in bundle['state_files'].values():
        require(type(item) is dict and set(item) == {'sha256', 'size_bytes'} and type(item['size_bytes']) is int and
            0 <= item['size_bytes'] <= 16*1024**2 and type(item['sha256']) is str and re.fullmatch('[a-f0-9]{64}', item['sha256']), 'preapply_state_descriptor')
    return {'schema_version': '1.0', 'operation': 'specific-preapply-diagnostic-truncation-proof-v1', 'run_id': RUN, 'source_revision': SOURCE,
        'profile': 'twenty-targets', 'controller_id': CONTROLLER, 'primary_failure': deepcopy(failure), 'original_unknown_outcome': True,
        'unknown_cleared': False, 'original_truncation_preserved': True, 'mutating_operations_observed': [], 'observed_state_empty': True,
        'scope': 'Exact original fixed Terraform plan failed after bounded diagnostic truncation; no apply was attempted.',
        'bundle_sha256': sha(canonical(bundle)), 'receipt_sha256': sha(canonical(receipt)), 'commands': commands, 'operations': evidence,
        'source_sha256': dict(SOURCE_FILES), 'input_sha256': hashes, 'retained_state_files': deepcopy(bundle['state_files']),
        'requires_live_checks': ['exact original source and exclusive Run/admission locks', 'full exact controller configuration and source/toolchain mounts',
            'unchanged complete operation/input/state file enumeration', 'no other run-labeled resources', 'stop exact controller and prove stopped PID zero and process death',
            'remove only exact controller then prove absence before public journal reconciliation'],
        'allocation_permitted': False, 'production_iso_eligible': False}


def prove_preapply_failure(bundle):
    """No mutation or authority grant; return only a bounded byte-bound proof."""
    try:
        proof = _prove(bundle)
        require(len(canonical(proof)) <= 32768, 'preapply_proof_bound')
        return proof
    except PreapplyProofError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError, UnicodeError, OverflowError):
        raise PreapplyProofError() from None
