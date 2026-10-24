"""Offline original Terraform and helper-capture replay for stock twenty scope.

No Docker call, executable launch, trust establishment or allocation is allowed.
The caller owns the Run lock; original private evidence stays outside exports.
"""
import base64
from copy import deepcopy
import hashlib
import json
import math
from types import SimpleNamespace

from scripts import qualify_images as qualification
from . import candidate as c, images, pipeline_replay as base, provisioning as p, readiness as r
from .admission import replay_plan
from .fleet_readiness import BatchReadinessSession, validate_children
from .runs import RunError, common, read_json, source_identity
from .targets import TargetPlan, LAYOUT

RUNTIME = 'private/twenty-runtime.json'
TARGET_IDS = TargetPlan('twenty-targets').target_ids


class TwentyReplayError(RunError):
    pass


def require(value, code='twenty_original_evidence_invalid'):
    if not value:
        raise TwentyReplayError(code, 'Original twenty-target evidence did not replay; preserve all private captures.')


def raw_file(run, relative, maximum=65536):
    return base.raw_file(run, relative, maximum)


def fingerprint(run, relative, maximum=1048576):
    raw = raw_file(run, relative, maximum)
    return {'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}


def source(run, archive):
    manifest = run.manifest()
    require(run.workspace == images.RUNS_ROOT and manifest['mode'] == 'container-reference' and
        manifest['profile'] == 'twenty-targets' and manifest['source_dirty'] is False and
        source_identity() == (manifest['source_revision'], False), 'twenty_replay_source_changed')
    require(archive['run_id'] == run.id and archive['source_revision'] == manifest['source_revision'] and
        archive['state'] == 'finished' and archive['phase'] == 'reconciling' and archive['plan']['synthetic'] is False and
        archive['plan']['profile'] == 'twenty-targets' and type(archive['plan']['target_count']) is int and
        archive['plan']['target_count'] == 20 and base.same(archive['plan'], replay_plan('twenty-targets', archive['plan']['observations'])) and
        len(archive['resources']) == 23 and len({(row['kind'], row['id']) for row in archive['resources']}) == 23 and
        all(row['outcome'] == 'absent' for row in archive['resources']), 'twenty_replay_archive_changed')
    return manifest


def operations(run, session, receipt):
    """Bind every terminal metadata/output pair and exact fixed operation order."""
    from provisioning.runtime import OPERATIONS, JSON_OPERATIONS
    captures, expected_files, counts = {}, set(), {}
    require(type(receipt['operations']) is list and 1 <= len(receipt['operations']) <= 64)
    for item in receipt['operations']:
        name, attempt = item['operation'], item['attempt']; counts[name] = counts.get(name, 0) + 1
        require(name in OPERATIONS and name != 'probe-unavailable' and type(attempt) is int and attempt == counts[name] and attempt <= 4)
        stem = name + '-' + str(attempt); expected_files |= {stem + '.json', stem + '.out'}
        metadata = read_json(session.state / 'operations' / (stem + '.json'))
        require(set(item) == set(metadata) | {'client_status', 'client_returncode', 'client_log_truncated', 'evidence'} and
            base.same(metadata, {key: item[key] for key in metadata}) and
            set(metadata) == {'operation', 'attempt', 'returncode', 'duration_seconds', 'output_bytes', 'output_sha256', 'truncated', 'timed_out', 'passed'} and
            metadata['passed'] is True and type(metadata['returncode']) is int and metadata['returncode'] == 0 and
            metadata['truncated'] is False and metadata['timed_out'] is False and item['client_status'] == 'pass' and
            type(item['client_returncode']) is int and item['client_returncode'] == 0 and item['client_log_truncated'] is False and
            type(metadata['duration_seconds']) in (int, float) and math.isfinite(metadata['duration_seconds']) and
            0 <= metadata['duration_seconds'] <= 135 and item['evidence'] == 'private/terraform/operations/' + stem + '.out')
        raw = raw_file(run, item['evidence'], p.MAX_OUTPUT)
        require(type(metadata['output_bytes']) is int and len(raw) == metadata['output_bytes'] and
            hashlib.sha256(raw).hexdigest() == metadata['output_sha256'], 'twenty_original_capture_changed')
        if name in JSON_OPERATIONS:
            captures.setdefault(name, []).append(p.bounded_json(session.state / 'operations' / (stem + '.out')))
    require({path.name for path in (session.state / 'operations').iterdir()} == expected_files, 'twenty_original_capture_changed')
    required = ['version', 'init', 'schema', 'plan', 'show-plan', 'apply', 'show-state', 'refresh-plan', 'show-refresh-plan',
        'refresh-apply', 'output', 'show-state', 'destroy-plan', 'show-destroy-plan', 'destroy', 'final-state']
    require([item['operation'] for item in receipt['operations']] == required, 'twenty_original_operation_incomplete')
    return captures


def report_provisioning(run, archive):
    """Replay actual saved plans/state/output/destroy and all retained configs."""
    from .software_inventory import validate_tools
    manifest = source(run, archive)
    receipt = read_json(run.file('evidence/provisioning.json'))
    context = read_json(run.file('private/terraform/controller.json'))
    require(c.bound_common(receipt, manifest) and receipt['operation'] == 'terraform-smoke' and receipt['scenario'] == 'healthy' and
        'target_binding' not in receipt and 'target_binding' not in context and receipt['target_image'] == p.TARGET_IMAGE and
        receipt['primary_failure'] is None and receipt['unknown_outcome'] is False and receipt['cleanup'] == 'completed' and
        receipt['runtime_pipeline_complete'] is False and receipt['production_iso_eligible'] is False)
    validate_tools(receipt['actual_tools'])
    fields = {'schema_version', 'run_id', 'source_revision', 'id', 'uid', 'gid', 'groups', 'mounts', 'image_labels', 'inputs',
        'scenario', 'target_runtime_policy', 'resource_layout', 'target_plan'}
    require(set(context) == fields and context['run_id'] == run.id and context['source_revision'] == manifest['source_revision'] and
        context['schema_version'] == '1.0' and context['scenario'] == 'healthy' and context['id'] == receipt['provisioner_id'] and
        context['resource_layout'] == receipt['resource_layout'] == LAYOUT)
    session = p.ProvisioningSession.__new__(p.ProvisioningSession)
    session.run, session.receipt, session.state = run, receipt, run.file('private/terraform')
    session.target_binding, session.target_plan, session.scenario = None, TargetPlan.from_record(context['target_plan']), 'healthy'
    session.variables, session.inputs = p.bounded_json(session.state / 'terraform.tfvars.json'), context['inputs']
    session.owned = {row['address']: row['id'] for row in receipt['resources']}
    session.provisioner = context['id']; session.uid, session.gid, session.socket_groups = context['uid'], context['gid'], context['groups']
    session.mounts, session.image_labels = {key: tuple(item) for key, item in context['mounts'].items()}, context['image_labels']
    session.lease = SimpleNamespace(plan=archive['plan'])
    require(session.target_plan == TargetPlan('twenty-targets') and receipt['target_plan'] == session.target_plan.record() and
        set(session.owned) == session.target_plan.expected_addresses and len(receipt['resources']) == 21 and
        len(set(session.owned.values())) == 21 and all(type(value) is str and p.ID.fullmatch(value) for value in session.owned.values()) and
        base.same(context['target_runtime_policy'], session.target_runtime_policy.record()) and
        base.same(receipt['target_runtime_policy'], session.target_runtime_policy.record()))
    tools = p.verified_toolchain(run)
    require(session.mounts == {'/opt/toolchain': (str(tools['root']), False), '/opt/provisioning': (str(p.CONTEXT), False),
        '/state': (str(session.state), True), '/var/run/docker.sock': ('/var/run/docker.sock', True)}, 'twenty_original_input_changed')
    expected_variables = {'run_id': run.id, 'source_revision': manifest['source_revision'], 'image': p.TARGET_IMAGE,
        'public_input': str(run.file('private/target-input')), 'target_ids': list(TARGET_IDS),
        'target_limits': deepcopy(archive['plan']['limits']['target']['terraform']),
        'target_capabilities': list(session.target_runtime_policy.capabilities)}
    expected_variables['target_limits'].pop('start'); expected_variables['target_limits'].pop('must_run')
    require(base.same(session.variables, expected_variables), 'twenty_original_input_changed')
    session.check_inputs()
    require(base.same(receipt['input_hashes'], session.inputs), 'twenty_original_input_changed')
    fixed = {'main.tf': p.scenario_source('healthy'), '.terraform.lock.hcl': (p.CONTEXT / '.terraform.lock.hcl').read_bytes(),
        'terraform.tfvars.json': json.dumps(expected_variables, sort_keys=True).encode(),
        'wormhole.tfrc': b'disable_checkpoint = true\nprovider_installation {\n filesystem_mirror {\n path = "/opt/toolchain/mirror"\n include = ["registry.terraform.io/kreuzwerker/docker"]\n }\n}\n'}
    require(set(session.inputs) == set(fixed) and all(raw == raw_file(run, 'private/terraform/' + name) and
        hashlib.sha256(raw).hexdigest() == session.inputs[name] for name, raw in fixed.items()), 'twenty_original_input_changed')
    require(p.file_digest(session.state / 'apply.tfplan')[0] == receipt['validated_plan_sha256'], 'twenty_original_plan_changed')
    captures = operations(run, session, receipt)
    require(captures['version'][0]['terraform_version'] == '1.17.0' and captures['version'][0]['platform'] == 'linux_amd64')
    schema = captures['schema'][0]['provider_schemas'][p.PROVIDER]['resource_schemas']
    require({'docker_container', 'docker_network'} <= set(schema) and
        {'start', 'must_run', 'cpus', 'memory', 'memory_swap'} <= set(schema['docker_container']['block']['attributes']) and
        'pids_limit' not in schema['docker_container']['block']['attributes'])
    for name, operation in [('show-plan', 'create'), ('show-refresh-plan', 'refresh'), ('show-destroy-plan', 'destroy')]:
        p.validate_plan(captures[name][0], session.variables, operation=operation,
            owned=session.owned if operation != 'create' else None, target_plan=session.target_plan, runtime_policy=session.target_runtime_policy)
    require(all({key: value['id'] for key, value in p.resources(state, session.target_plan).items()} == session.owned
        for state in captures['show-state']), 'twenty_original_resource_changed')
    output = captures['output'][0]
    require(type(output) is dict and set(output) == {'run'} and output['run'].get('sensitive') is False)
    provider_targets = p.validate_output_identity(output['run']['value'], session.variables, session.owned, session.target_plan)
    require(not p.resources(captures['final-state'][0], session.target_plan), 'twenty_original_destroy_incomplete')
    session._final_state_proof()
    runtime = read_json(run.file(RUNTIME))
    require(c.bound_common(runtime, manifest) and set(runtime) == set(common(manifest)) | {'operation', 'network', 'provisioner', 'helper',
        'targets_stopped', 'targets_live'} and runtime['operation'] == 'twenty-runtime-observations-v1' and
        set(runtime['targets_stopped']) == set(runtime['targets_live']) == set(TARGET_IDS))
    session.verify_owned(runtime['network'], 'network', session.network_id)
    session.verify_provisioner(runtime['provisioner'])
    require(runtime['provisioner']['State']['Running'] is True)
    base.check_cgroups(receipt['provisioner_cgroups'], archive['plan']['limits']['provisioner']['docker_create'])
    require(set(receipt['targets_before_pid_update']) == set(receipt['targets_started']) == set(TARGET_IDS) and
        receipt['targets_confined'] is True and receipt['pending_target_ids'] == [] and
        c.bound_common(receipt['inventory'], manifest) and receipt['inventory']['status'] == 'pass' and
        [row['target_id'] for row in receipt['inventory']['targets']] == list(TARGET_IDS))
    for target in TARGET_IDS:
        stopped, live = runtime['targets_stopped'][target], runtime['targets_live'][target]
        session.verify_target(stopped, target_id=target, stopped=True, network_observation=runtime['network'])
        session.verify_target(live, target_id=target, network_observation=runtime['network'])
        require(stopped['Id'] == live['Id'] == session.target_resources[target] and live['State']['Running'] is True)
        endpoint = live['NetworkSettings']['Networks']['wormhole-' + run.id + '-network']
        data = provider_targets[target]['network_data']; inventory = session.target_inventory(target)
        require(type(data) is list and len(data) == 1 and data[0]['ip_address'] == endpoint['IPAddress'] == inventory['host'] and
            data[0]['network_name'] == 'wormhole-' + run.id + '-network' and endpoint['NetworkID'] == session.network_id and
            base.same(inventory, {'target_id': target, 'resource_id': session.target_resources[target], 'host': endpoint['IPAddress'],
                'ssh_port': 2222, 'ssh_user': 'wormhole', 'image_digest': p.TARGET_IMAGE, 'status': 'started'}) and
            receipt['targets_started'][target]['started_at'] == live['State']['StartedAt'], 'twenty_original_resource_changed')
        base.check_cgroups(receipt['targets_started'][target]['cgroups'], archive['plan']['limits']['target']['docker_create'])
        before = receipt['targets_before_pid_update'][target]
        require(before['status'] == 'created' and before['started_at'] == '0001-01-01T00:00:00Z' and
            (before['pids_limit'] is None or type(before['pids_limit']) is int))
    expected = {('container', session.provisioner), ('network', session.network_id),
        *(('container', value) for value in session.target_resources.values())}
    require(expected < {(row['kind'], row['id']) for row in archive['resources']}, 'twenty_original_destroy_incomplete')
    return {'targets': session.target_resources, 'network_id': session.network_id, 'provisioner_id': session.provisioner,
        'receipt': receipt, 'runtime': runtime, 'proof': {'target_count': 20, 'terraform_resources': 21, 'terminal_operations': 16,
            'receipt': fingerprint(run, 'evidence/provisioning.json'), 'runtime': fingerprint(run, RUNTIME)}}


def report_readiness(run, archive, provisioned):
    """Reparse each original packet/key/receiver result; compare all160 rows."""
    from readiness.runtime import unique
    manifest = source(run, archive)
    receipt = read_json(run.file('evidence/readiness.json')); context = read_json(run.file('private/readiness-controller.json'))
    plan, targets = TargetPlan('twenty-targets'), provisioned['targets']
    fields = set(common(manifest)) | {'operation', 'resource_layout', 'context_version', 'target_plan', 'target_resource_ids',
        'helper_id', 'helper_image', 'network_id', 'image_labels', 'source_path', 'source_sha256', 'bind_path', 'bind_identity',
        'validation_enabled', 'validation_source_sha256', 'validation_bind_identity', 'unknown_outcome', 'cleanup',
        'readiness_budget_seconds', 'helper_policy', 'fleet_inventory_enabled', 'fleet_inventory_source_sha256', 'fleet_inventory_bind_identity'}
    require(set(context) == fields and c.bound_common(context, manifest) and c.bound_common(receipt, manifest) and
        context['operation'] == 'readiness-helper' and context['resource_layout'] == receipt['resource_layout'] == LAYOUT and
        type(context['context_version']) is int and context['context_version'] == receipt['context_version'] == 5 and
        base.same(context['target_plan'], plan.record()) and base.same(receipt['target_plan'], plan.record()) and
        context['target_resource_ids'] == receipt['target_resource_ids'] == targets and
        context['network_id'] == provisioned['network_id'] and context['helper_id'] == receipt['helper_id'] and
        type(context['helper_id']) is str and r.ID.fullmatch(context['helper_id']) and
        context['helper_image'] == receipt['helper_image'] == r.HELPER_IMAGE and receipt['helper_build_run'] == r.HELPER_BUILD and
        context['validation_enabled'] is True and context['fleet_inventory_enabled'] is True and
        context['source_path'] == str(r.RUNTIME) and context['bind_path'] == str(run.file('private/helper-source/runtime.py')) and
        context['source_sha256'] == r.runtime_hash() and context['validation_source_sha256'] == r.code_hash(r.VALIDATION_RUNTIME) and
        context['fleet_inventory_source_sha256'] == r.code_hash(r.FLEET_INVENTORY_RUNTIME) and
        context['cleanup'] == receipt['cleanup'] == 'completed' and context['unknown_outcome'] is False)
    validate_children(receipt, manifest, plan, targets)
    adapter = BatchReadinessSession.__new__(BatchReadinessSession)
    adapter.run, adapter.target_plan, adapter.helper, adapter.network = run, plan, receipt['helper_id'], provisioned['network_id']
    adapter.image_labels, adapter.lease = context['image_labels'], SimpleNamespace(plan=archive['plan'])
    adapter.validation_enabled = adapter.fleet_inventory_enabled = True
    for prefix, path in [('', 'runtime.py'), ('validation_', 'validation.py'), ('fleet_inventory_', 'fleet-inventory.py')]:
        setattr(adapter, prefix + 'source_sha256', context[prefix + 'source_sha256'])
        setattr(adapter, prefix + 'bind_identity', context[prefix + 'bind_identity'])
        setattr(adapter, prefix + 'bind_path', run.file('private/helper-source/' + path))
    require(base.same(context['helper_policy'], adapter.helper_policy()) and
        all(base.same(context.get(key), value) and base.same(receipt.get(key), value)
            for key, value in adapter.context_policy().items()))
    adapter.verify_helper(provisioned['runtime']['helper'])
    base.check_cgroups(receipt['cgroups'], archive['plan']['limits']['helper']['docker_create'])
    require(('container', adapter.helper) in {(row['kind'], row['id']) for row in archive['resources']})
    total = 0
    stages = {'tcp', 'ssh', 'python', 'ansible-wait', 'ansible-ping'}
    for child in receipt['targets']:
        target = child['target_id']; probes, keys, count, passed, auth = [], [], {}, set(), 0
        require(child['status'] == 'ready' and child['primary_failure'] is None and child['unknown_outcome'] is False and
            [row['check_id'] for row in child['transitions']] == list(r.EXPECTED) and
            child['ready_started_at'] == provisioned['runtime']['targets_live'][target]['State']['StartedAt'])
        for index, attempt in enumerate(child['attempts']):
            prefix = target + '-'; require(attempt['stage'].startswith(prefix))
            stage = attempt['stage'][len(prefix):]
            require(stage in stages | {'public-hostkey', 'auth-input'} and attempt['private_log'] ==
                'private/qualification-' + attempt['role'] + '-' + attempt['stage'] + '-' + str(index) + '.log' and
                attempt['log_truncated'] is False and type(attempt['returncode']) is int and attempt['status'] in {'pass', 'fail'})
            raw = raw_file(run, attempt['private_log'])
            if stage == 'auth-input':
                require(attempt['role'] == 'helper' and attempt['status'] == 'pass' and attempt['returncode'] == 0); auth += 1
            if stage == 'public-hostkey' and attempt['status'] == 'pass':
                require(attempt['role'] == 'target'); keys.append(qualification.public_key(raw.decode('ascii')))
            if stage not in stages:
                continue
            require(attempt['role'] == 'helper' and attempt['status'] == 'pass' and attempt['returncode'] == 0)
            value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            fields = {'schema_version', 'run_id', 'source_revision', 'target_id', 'operation', 'attempt', 'status', 'category',
                'returncode', 'timed_out', 'truncated', 'duration_seconds', 'observation', 'private_diagnostic'}
            count[stage] = count.get(stage, 0) + 1
            require(type(value) is dict and set(value) == fields and value['schema_version'] == '1.0' and value['run_id'] == run.id and
                value['source_revision'] == manifest['source_revision'] and value['target_id'] == target and value['operation'] == stage and
                type(value['attempt']) is int and value['attempt'] == count[stage] and value['status'] in {'pass', 'fail'} and
                type(value['returncode']) is int and type(value['timed_out']) is bool and type(value['truncated']) is bool and
                type(value['duration_seconds']) in (int, float) and math.isfinite(value['duration_seconds']) and
                0 <= value['duration_seconds'] <= {'tcp': 5, 'ssh': 10, 'python': 10, 'ansible-wait': 27, 'ansible-ping': 14}[stage] and
                type(value['observation']) is dict and type(value['private_diagnostic']) is str and
                len(value['private_diagnostic'].encode()) <= 32768 and
                (value['status'] == 'pass') == (value['returncode'] == 0 and value['category'] is None and
                    value['timed_out'] is False and value['truncated'] is False))
            if value['status'] == 'pass':
                key, expected = {'tcp': ('tcp_connected', True), 'ssh': ('uid', 10001), 'python': ('configured_interpreter_usable', True),
                    'ansible-wait': ('structured_target_result', True), 'ansible-ping': ('ping', 'pong')}[stage]
                require(base.same(value['observation'].get(key), expected)); passed.add(stage)
            else:
                require(value['category'] in {'tcp_pending', 'ssh_transport_pending', 'probe_timeout'})
            probes.append({key: value[key] for key in value if key not in {'private_diagnostic', 'observation'}})
        require(base.same(probes, child['probes']) and keys and len(set(keys)) == 1 and auth == 1 and passed == stages)
        blob = base64.b64decode(keys[0].split()[1], validate=True)
        expected = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        require(child['hostkey_fingerprint'] == expected and child['hostkey_source'] == 'exact-owned target public-key reader; pin preserved, no TOFU')
        total += len(child['transitions'])
    require(receipt['status'] == 'ready' and receipt['primary_failure'] is None and receipt['unknown_outcome'] is False and total == 160)
    return {'target_count': 20, 'required_pairs': 160, 'passed_pairs': 160,
        'helper_id': adapter.helper, 'network_id': adapter.network,
        'receipt': fingerprint(run, 'evidence/readiness.json'), 'context': fingerprint(run, 'private/readiness-controller.json')}
