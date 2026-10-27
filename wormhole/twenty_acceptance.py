"""One actual stock twenty-target graph with full checks and scoped teardown.

The operator invokes this on approved Linux storage. Reporting replays original
captures without provisioning. Stock scale qualification is distinct from the
candidate reference pipeline, publication and production ISO eligibility.
"""
from copy import deepcopy
import hashlib
import json
import math
import re
import sys
import time

from . import admission, images, readiness as r, validation as v
from .fleet_readiness import BatchReadinessSession, validate_children
from .fleet_samples import collect_sample, compare_samples
from .fleet_validation import BatchValidationSession, report_batch_validation
from .isolation_acceptance import raw_file
from .provisioning import ProvisioningSession
from .provisioning_acceptance import disk_sample, scan_private_material, snapshot
from .recovery import cleanup_session, safe_code, valid_failure
from .runs import Run, RunError, atomic_bytes, atomic_json, common, create_run, now, read_json, source_identity
from .targets import TargetPlan
from .initialization import InitializationSession,report_initialization

EVIDENCE = 'evidence/twenty-acceptance.json'
SAMPLE_BEFORE = 'evidence/twenty-sample-before.json'
SAMPLE_AFTER = 'evidence/twenty-sample-after.json'
USAGE = 'evidence/twenty-usage.json'
TARGET_IDS = tuple('target-' + str(number).zfill(3) for number in range(1, 21))
OPERATION = 'real-stock-twenty-target-acceptance-v2'
MAX_RECORD = 262144
EXPECTED_RESULTS=tuple((target,check) for target in TARGET_IDS for check in v.CHECKS)


class TwentyError(RunError):
    pass


def require(value, code='twenty_acceptance_invalid'):
    if not value:
        raise TwentyError(code, 'Twenty-target qualification stopped; retain the actual primary, evidence and exact resource accounting.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def initialization_summary(run):
    value=report_initialization(run,require_passed=True)
    require(value['expected_targets']==list(TARGET_IDS),'twenty_initialization_incomplete')
    return {'targets_initialized':20,'targets_configured':20,'record':fingerprint(run,'evidence/initialization.json')}


def fingerprint(run, relative):
    raw = raw_file(run.file(relative), MAX_RECORD)
    return {'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}


def source(run=None):
    revision, dirty = source_identity()
    require(dirty is False, 'twenty_source_changed')
    if run is not None:
        manifest = run.manifest()
        require(run.workspace == images.RUNS_ROOT and manifest['source_revision'] == revision and
            manifest['source_dirty'] is False and manifest['mode'] == 'container-reference' and
            manifest['profile'] == 'twenty-targets', 'twenty_source_changed')
    return revision


def readiness_summary(run, targets):
    value = read_json(run.file('evidence/readiness.json'))
    plan = TargetPlan.from_record(value['target_plan'])
    require(plan.profile == 'twenty-targets' and plan.target_ids == TARGET_IDS and
        value['target_resource_ids'] == targets and value['status'] == 'ready' and
        value['primary_failure'] is None and value['unknown_outcome'] is False, 'twenty_readiness_incomplete')
    validate_children(value, run.manifest(), plan, targets)
    observed = [(child['target_id'], row['check_id']) for child in value['targets'] for row in child['transitions']]
    require(observed == [(target, check) for target in TARGET_IDS for check in r.EXPECTED] and len(observed) == 160,
        'twenty_readiness_incomplete')
    return {'status': 'passed', 'target_count': 20, 'required_pairs': 160, 'passed_pairs': 160,
        'evidence': fingerprint(run, 'evidence/readiness.json')}


def functional_summary(run, targets, concurrency):
    plan = read_json(run.file('evidence/batch-validation-plan.json'))
    report = report_batch_validation(run); result = report['result']
    require(plan['target_plan']['profile'] == 'twenty-targets' and plan['target_plan']['target_ids'] == list(TARGET_IDS) and
        plan['target_resource_ids'] == targets and plan['controller_concurrency'] == concurrency and
        result['status'] == 'passed' and result['unknown_outcome'] is False and result['primary_failure'] is None and
        result['attempted_targets'] == list(TARGET_IDS) and result['blocked_targets'] == {}, 'twenty_functional_incomplete')
    rows = result['checks']
    require([(row['target_id'], row['check_id']) for row in rows] == [(target, check) for target in TARGET_IDS for check in v.CHECKS] and
        len(rows) == 200 and all(row['required'] is True and row['status'] == 'pass' for row in rows), 'twenty_functional_incomplete')
    require(all(report['text'].splitlines().count(row['target_id'] + ' / ' + row['check_id'] + ': pass') == 1 for row in rows),
        'twenty_functional_report')
    return {'status': 'passed', 'target_count': 20, 'configured_ansible_forks': concurrency,
        'required_rows': 200, 'passed_rows': 200, 'plan_sha256': plan['plan_sha256'],
        'evidence': fingerprint(run, 'evidence/batch-validation.json'),
        'text_sha256': hashlib.sha256(report['text'].encode()).hexdigest()}


def inventory_summary(run, targets, concurrency):
    from .fleet_inventory import report_fleet_inventory
    from .fleet_inventory_records import TARGET_IDS as INVENTORY_IDS
    report = report_fleet_inventory(run); index = report['index']
    require(tuple(INVENTORY_IDS) == TARGET_IDS and index['target_count'] == 20 and
        index['controller_concurrency'] == concurrency and index['status'] == 'passed' and
        index['unknown_outcome'] is False and index['primary_failure'] is None and len(report['targets']) == 20,
        'twenty_inventory_incomplete')
    observed = []
    for target, entry in zip(TARGET_IDS, report['targets']):
        record = entry['record']
        require(record['target_id'] == target and record['target']['resource_id'] == targets[target] and
            record['status'] == 'passed' and len(record['checks']) == 10 and
            all(row['target_id'] == target and row['required'] is True and row['status'] == 'pass' for row in record['checks']) and
            len(record['observation']['packages']) > 0, 'twenty_inventory_incomplete')
        observed.append({'target_id': target, 'resource_id': targets[target],
            'installed_packages': len(record['observation']['packages']), 'required_rows': 10, 'passed_rows': 10})
    return {'status': 'passed', 'target_count': 20, 'configured_ansible_forks': concurrency,
        'required_rows': 200, 'passed_rows': 200, 'native_inventories': observed,
        'index': fingerprint(run, 'evidence/fleet-inventory-index.json')}


def owned_graph(ps, ready):
    rows = [{'kind': 'container', 'id': ps.target_resources[target], 'role': 'target', 'target_id': target}
        for target in TARGET_IDS]
    rows.extend(({'kind': 'network', 'id': ps.network_id, 'role': 'network', 'target_id': None},
        {'kind': 'container', 'id': ps.provisioner, 'role': 'provisioner', 'target_id': None},
        {'kind': 'container', 'id': ready.helper, 'role': 'helper', 'target_id': None}))
    validate_graph(rows)
    return rows


def validate_graph(rows):
    expected = [('container', 'target', target) for target in TARGET_IDS] + [
        ('network', 'network', None), ('container', 'provisioner', None), ('container', 'helper', None)]
    require(type(rows) is list and len(rows) == 23 and
        all(type(row) is dict and set(row) == {'kind', 'id', 'role', 'target_id'} for row in rows) and
        [(row['kind'], row['role'], row['target_id']) for row in rows] == expected and
        len({row['id'] for row in rows}) == 23 and all(type(row['id']) is str and
            re.fullmatch('[a-f0-9]{64}', row['id']) for row in rows), 'twenty_graph_invalid')


def archive_summary(run, graph):
    validate_graph(graph)
    raw = raw_file(images.INFRASTRUCTURE / 'history' / (run.id + '.json'), MAX_RECORD)
    record = admission._journal(json.loads(raw))
    require(canonical(record['plan']) == canonical(admission.replay_plan('twenty-targets', record['plan']['observations'])) and
        record['plan']['admitted'] is True, 'twenty_admission_changed')
    require(record['run_id'] == run.id and record['source_revision'] == run.manifest()['source_revision'] and
        record['state'] == 'finished' and record['phase'] == 'reconciling' and record['plan']['profile'] == 'twenty-targets' and
        record['plan']['synthetic'] is False and len(record['resources']) == 23 and
        {(row['kind'], row['id']) for row in record['resources']} == {(row['kind'], row['id']) for row in graph} and
        all(row['outcome'] == 'absent' for row in record['resources']), 'twenty_archive_incomplete')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw), 'resource_count': 23,
        'pending_resources': 0, 'all_transient_absent': True, 'admitted_requirements': deepcopy(record['plan']['requirements'])}


def sample_totals(point):
    totals = {key: sum(row[field] if section is None else row[section][field] for row in point['containers'])
        for key, section, field in (('memory_current_bytes', 'usage', 'memory_current_bytes'),
            ('pids_current', 'usage', 'pids_current'), ('writable_layer_bytes', None, 'writable_layer_bytes'),
            ('log_tail_captured_bytes', 'log_tail', 'captured_bytes'))}
    require(canonical(totals) == canonical(point['totals']) and
        all(type(value) is int and value >= 0 for value in totals.values()), 'twenty_measurement_totals')
    for row in point['containers']:
        tail = row['log_tail']
        require(set(tail) == {'captured_bytes', 'truncated', 'maximum_bytes', 'maximum_lines', 'full_history'} and
            type(tail['captured_bytes']) is int and 0 <= tail['captured_bytes'] <= 65536 and
            type(tail['truncated']) is bool and type(tail['maximum_bytes']) is int and tail['maximum_bytes'] == 65536 and
            type(tail['maximum_lines']) is int and tail['maximum_lines'] == 1000 and tail['full_history'] is False,
            'twenty_measurement_logs')
    return totals


def usage_summary(run, graph):
    from .twenty_replay import RUNTIME
    from .pipeline_replay import check_cgroups
    runtime = read_json(run.file(RUNTIME))
    limits = admission.load_profile('twenty-targets')['limits']
    first, last = read_json(run.file(SAMPLE_BEFORE)), read_json(run.file(SAMPLE_AFTER))
    interval = compare_samples(first, last)
    require(canonical(common(interval)) == canonical(common(run.manifest())) and canonical(interval) == canonical(read_json(run.file(USAGE))) and
        {row['resource_id'] for row in interval['containers']} == {row['id'] for row in graph if row['kind'] == 'container'},
        'twenty_measurement_identity')
    for point in (first, last):
        sample_totals(point)
        require(point['guaranteed_peak'] is False and point['disk_quota'] is False and point['production_iso_eligible'] is False,
            'twenty_measurement_claim')
        for row in point['containers']:
            observed = runtime['targets_live'][row['target_id']] if row['role'] == 'target' else runtime[row['role']]
            require(row['resource_id'] == observed['Id'] and row['image_id'] == observed['Image'] and
                row['usage']['pid'] == observed['State']['Pid'] and observed['State']['Running'] is True,
                'twenty_measurement_identity')
            projected = admission._projection(limits[row['role']])['docker_create']
            check_cgroups(row['usage']['limits'], projected)
            require(type(row['usage']['memory_events']['oom']) is int and type(row['usage']['memory_events']['oom_kill']) is int,
                'twenty_measurement_oom')
        require(all(row['usage']['memory_events']['oom'] == 0 and row['usage']['memory_events']['oom_kill'] == 0
            for row in point['containers']), 'twenty_measurement_oom')
    return {'status': 'passed', 'target_count': 20, 'container_count': 22, 'usage': fingerprint(run, USAGE),
        'sample_totals': [deepcopy(first['totals']), deepcopy(last['totals'])],
        'cpu_interval_seconds': {'minimum': min(row['elapsed_seconds'] for row in interval['containers']),
            'maximum': max(row['elapsed_seconds'] for row in interval['containers'])},
        'guaranteed_peak': False, 'disk_quota': False, 'full_log_history': False}


def original_summary(run, graph):
    from .twenty_replay import report_provisioning, report_readiness
    archive = admission._journal(json.loads(raw_file(images.INFRASTRUCTURE / 'history' / (run.id + '.json'), MAX_RECORD)))
    provisioned = report_provisioning(run, archive)
    require(provisioned['targets'] == {row['target_id']: row['id'] for row in graph if row['role'] == 'target'} and
        provisioned['network_id'] == next(row['id'] for row in graph if row['role'] == 'network') and
        provisioned['provisioner_id'] == next(row['id'] for row in graph if row['role'] == 'provisioner') and
        provisioned['runtime']['helper']['Id'] == next(row['id'] for row in graph if row['role'] == 'helper'),
        'twenty_original_graph_changed')
    return {'provisioning': provisioned['proof'], 'readiness': report_readiness(run, archive, provisioned)}


def _report_twenty(run):
    """Caller holds the Run lock. Reconstruct all passed scope from originals."""
    source(run); value = read_json(run.file(EVIDENCE))
    require(set(value) == set(common(run.manifest())) | {'operation', 'profile', 'target_count', 'controller_concurrency',
        'status', 'phase', 'created_at', 'updated_at', 'primary_failure', 'checks', 'owned_resources', 'stopped_targets',
        'stage_seconds', 'disk_samples', 'cleanup', 'artifacts', 'stock_twenty_scope_complete', 'reference_eligible',
        'production_iso_eligible', 'simulation','expected_results'} and
        canonical(common(value)) == canonical(common(run.manifest())) and value['operation'] == OPERATION and
        value['profile'] == 'twenty-targets' and type(value['target_count']) is int and value['target_count'] == 20 and
        type(value['controller_concurrency']) is int and 1 <= value['controller_concurrency'] <= 4 and
        value['production_iso_eligible'] is False and value['reference_eligible'] is False and
        value['simulation'] is False and value['status'] in ('passed', 'failed'), 'twenty_record_invalid')
    require(type(value['expected_results']) is list and
        [(row['target_id'],row['check_id']) for row in value['expected_results']]==list(EXPECTED_RESULTS) and
        all(set(row)=={'target_id','check_id','status'} and row['status'] in
            {'pass','fail','error','unreachable','blocked','unverified','skipped'} for row in value['expected_results']),
        'twenty_result_grid_invalid')
    if value['status'] == 'failed':
        require(value['primary_failure'] is not None and valid_failure(value['primary_failure']) and
            value['stock_twenty_scope_complete'] is False, 'twenty_false_pass')
        return deepcopy(value)
    require(value['primary_failure'] is None and value['stock_twenty_scope_complete'] is True,
        'twenty_false_pass')
    original=report_batch_validation(run)['result']['checks']
    require(value['expected_results']==[{key:row[key] for key in ('target_id','check_id','status')} for row in original] and
        all(row['status']=='pass' for row in value['expected_results']),'twenty_result_grid_invalid')
    validate_graph(value['owned_resources'])
    targets = {row['target_id']: row['id'] for row in value['owned_resources'] if row['role'] == 'target'}
    require(tuple(targets) == TARGET_IDS, 'twenty_graph_invalid')
    require(type(value['stopped_targets']) is list and len(value['stopped_targets']) == 20 and
        [row['target_id'] for row in value['stopped_targets']] == list(TARGET_IDS) and
        all(set(row) == {'target_id', 'resource_id', 'pid', 'status', 'started_at', 'pids_limit'} and
            row['resource_id'] == targets[row['target_id']] and type(row['pid']) is int and row['pid'] == 0 and
            row['status'] == 'created' and row['started_at'] == '0001-01-01T00:00:00Z' and
            type(row['pids_limit']) is int and row['pids_limit'] == 64 for row in value['stopped_targets']),
        'twenty_stopped_grid')
    actual = {'initialization':initialization_summary(run),'readiness': readiness_summary(run, targets),
        'functional': functional_summary(run, targets, value['controller_concurrency']),
        'inventory': inventory_summary(run, targets, value['controller_concurrency']),
        'usage': usage_summary(run, value['owned_resources']),
        'originals': original_summary(run, value['owned_resources'])}
    for name in actual: require(canonical(actual[name]) == canonical(value['checks'][name]), 'twenty_replay_changed')
    for name, relative in ((SAMPLE_BEFORE, SAMPLE_BEFORE), (SAMPLE_AFTER, SAMPLE_AFTER), (USAGE, USAGE)):
        require(fingerprint(run, relative) == value['artifacts'][name], 'twenty_replay_changed')
    interval = compare_samples(read_json(run.file(SAMPLE_BEFORE)), read_json(run.file(SAMPLE_AFTER)))
    archive = archive_summary(run, value['owned_resources'])
    require(canonical(interval) == canonical(read_json(run.file(USAGE))) and canonical(value['cleanup']['archive']) == canonical(archive) and
        value['cleanup']['status'] == 'completed' and value['cleanup']['unknown_outcome'] is False and
        value['checks']['sentinel_unchanged'] is True and
        set(value['checks']) == {'initialization','readiness', 'functional', 'inventory', 'usage', 'originals', 'sentinel_unchanged', 'sentinel',
            'credential_scan_before_cleanup', 'credential_scan_after_cleanup'} and
        set(value['checks']['sentinel']) == {'resource_id', 'before_sha256', 'after_sha256'} and
        re.fullmatch('[a-f0-9]{64}', value['checks']['sentinel']['resource_id']) and
        value['checks']['sentinel']['resource_id'] not in {row['id'] for row in value['owned_resources']} and
        re.fullmatch('[a-f0-9]{64}', value['checks']['sentinel']['before_sha256']) and
        value['checks']['sentinel']['before_sha256'] == value['checks']['sentinel']['after_sha256'], 'twenty_replay_changed')
    require(all(type(number) in (int, float) and math.isfinite(number) and number >= 0
        for number in value['stage_seconds'].values()) and value['phase'] == 'completed' and
        all(value['checks'][name]['status'] == 'pass' and value['checks'][name]['secret_contents_exported'] is False
            for name in ('credential_scan_before_cleanup', 'credential_scan_after_cleanup')), 'twenty_record_invalid')
    for point in actual['usage']['sample_totals']:
        require(point['memory_current_bytes'] <= archive['admitted_requirements']['runtime_memory_bytes'] and
            point['pids_current'] <= archive['admitted_requirements']['pids_peak'] and
            point['writable_layer_bytes'] <= archive['admitted_requirements']['disk_bytes'], 'twenty_observed_budget_exceeded')
    return deepcopy(value)


def report_twenty(run):
    """Bounded read-only replay; malformed original records are explicit errors."""
    try:
        return _report_twenty(run)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        raise TwentyError('twenty_record_invalid', 'Original twenty-target evidence is malformed; no scope is qualified.') from None


def gate_twenty(run):
    value = report_twenty(run)
    return {**common(value), 'operation': 'stock-twenty-target-decision-v1', 'profile': 'twenty-targets',
        'stock_twenty_scope_complete': value['status'] == 'passed' and value['stock_twenty_scope_complete'],
        'reference_eligible': False, 'production_iso_eligible': False,
        'reasons': [] if value['status'] == 'passed' else [value['primary_failure']['code']]}


def acceptance(sentinel_id, *, controller_concurrency=4):
    """Own the single full Run lifecycle. No caller locks or arbitrary profile."""
    from .candidate_acceptance import sweep
    from .fleet_inventory import FleetInventorySession
    require(sys.platform.startswith('linux') and type(sentinel_id) is str and
        re.fullmatch('[a-f0-9]{64}', sentinel_id), 'twenty_input')
    require(type(controller_concurrency) is int and 1 <= controller_concurrency <= 4, 'twenty_concurrency')
    revision = source()
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True, profile='twenty-targets')
    start = time.monotonic()
    value = {**common(run.manifest()), 'operation': OPERATION, 'profile': 'twenty-targets', 'target_count': 20,
        'controller_concurrency': controller_concurrency, 'status': 'running', 'phase': 'authentication',
        'created_at': now(), 'updated_at': now(), 'primary_failure': None, 'checks': {}, 'owned_resources': [],
        'stopped_targets': [], 'stage_seconds': {}, 'disk_samples': [], 'cleanup': None, 'artifacts': {},
        'stock_twenty_scope_complete': False, 'reference_eligible': False, 'production_iso_eligible': False,
        'simulation': False,'expected_results':[{'target_id':target,'check_id':check,'status':'blocked'} for target,check in EXPECTED_RESULTS]}
    def save():
        value['updated_at'] = now()
        atomic_bytes(run.file(EVIDENCE), canonical(value) + b'\n', limit=MAX_RECORD)
    def stage(name, function):
        value['phase'] = name; save(); began = time.monotonic()
        try: return function()
        finally: value['stage_seconds'][name] = time.monotonic() - began; save()
    with run.locked(): save()
    try:
        images.create_auth(run)
        with run.locked(), images.docker_scope(run):
            baseline = snapshot('container', sentinel_id, unrelated=True)
            value['phase'] = 'measured-admission'; save()
            with admission.AdmissionLease(images.INFRASTRUCTURE, run.id, revision, 'twenty-targets') as lease:
                ps = ProvisioningSession(run, lease)
                ready = None; primary = None; cleaned = None;validation=None
                runtime = {**common(run.manifest()), 'operation': 'twenty-runtime-observations-v1',
                    'targets_stopped': {}, 'targets_live': {}}
                try:
                    stage('create-stopped', ps.create_stopped)
                    for target in TARGET_IDS:
                        observed = images.inspect('container', ps.target_resources[target])
                        ps.verify_target(observed, target_id=target, stopped=True)
                        runtime['targets_stopped'][target] = deepcopy(observed)
                        value['stopped_targets'].append({'target_id': target, 'resource_id': observed['Id'],
                            'pid': observed['State']['Pid'], 'status': observed['State']['Status'],
                            'started_at': observed['State']['StartedAt'], 'pids_limit': observed['HostConfig']['PidsLimit']})
                    require(len(value['stopped_targets']) == 20, 'twenty_stopped_grid')
                    stage('start-targets', ps.start_and_inventory)
                    initialization=InitializationSession(ps,absolute_deadline=start+240)
                    def initialize():
                        for target in TARGET_IDS:initialization.wait_complete(target)
                    stage('initialization',initialize)
                    value['checks']['initialization']=initialization_summary(run)
                    ready = BatchReadinessSession(ps, validation=True, fleet_inventory=True,initialization=initialization)
                    stage('start-helper', ready.start_helper)
                    value['owned_resources'] = owned_graph(ps, ready)
                    require(sentinel_id not in {row['id'] for row in value['owned_resources']}, 'twenty_sentinel_owned')
                    stage('readiness', ready.wait_ready)
                    targets = dict(ps.target_resources)
                    runtime['network'] = images.inspect('network', ps.network_id)
                    runtime['provisioner'] = images.inspect('container', ps.provisioner)
                    runtime['helper'] = images.inspect('container', ready.helper)
                    ps.verify_provisioner(runtime['provisioner']); ready.verify_helper(runtime['helper'])
                    for target in TARGET_IDS:
                        observed = images.inspect('container', targets[target])
                        ps.verify_target(observed, target_id=target, network_observation=runtime['network'])
                        runtime['targets_live'][target] = deepcopy(observed)
                    from .twenty_replay import RUNTIME
                    atomic_bytes(run.file(RUNTIME), canonical(runtime) + b'\n', limit=1024 * 1024)
                    readiness_summary(run, targets)
                    first = stage('sample-before', lambda: collect_sample(ps, ready, 'before-checks'))
                    atomic_json(run.file(SAMPLE_BEFORE), first)
                    # Consume the larger remaining-lifetime requirement first.
                    # Both stages retain their own deadlines and refuse expired
                    # targets; no container lifetime is extended for scale.
                    inventory = FleetInventorySession(ready, controller_concurrency=controller_concurrency)
                    stage('inventory', inventory.collect); inventory.require_passed()
                    inventory_summary(run, targets, controller_concurrency)
                    validation = BatchValidationSession(ready, controller_concurrency=controller_concurrency)
                    result=stage('functional', validation.validate)
                    value['expected_results']=[{key:row[key] for key in ('target_id','check_id','status')} for row in result['checks']]
                    validation.require_passed()
                    functional_summary(run, targets, controller_concurrency)
                    last = stage('sample-after', lambda: collect_sample(ps, ready, 'after-checks'))
                    atomic_json(run.file(SAMPLE_AFTER), last)
                    atomic_json(run.file(USAGE), compare_samples(first, last))
                    value['checks']['usage'] = usage_summary(run, value['owned_resources'])
                    require(all(point['totals']['memory_current_bytes'] <= lease.plan['requirements']['runtime_memory_bytes'] and
                        point['totals']['pids_current'] <= lease.plan['requirements']['pids_peak'] and
                        point['totals']['writable_layer_bytes'] <= lease.plan['requirements']['disk_bytes'] for point in (first, last)),
                        'twenty_observed_budget_exceeded')
                    value['checks']['credential_scan_before_cleanup'] = scan_private_material(run)
                    value['disk_samples'].append(disk_sample(run, 'twenty-before-cleanup'))
                except BaseException as error:
                    primary = error
                    if validation is not None and type(getattr(validation,'receipt',None)) is dict:
                        value['expected_results']=[{key:row[key] for key in ('target_id','check_id','status')}
                            for row in validation.receipt['checks']]
                    if ps.receipt['primary_failure'] is None: ps.failure(error)
                    failures = [receipt.get('primary_failure') for receipt in
                        (ps.receipt, ready.receipt if ready is not None else {})]
                    failures = [item for item in failures if item is not None and valid_failure(item)]
                    if failures: value['primary_failure'] = deepcopy(min(failures, key=lambda item: item['recorded_at']))
                finally:
                    try:
                        cleaned = stage('cleanup', lambda: cleanup_session(ps, lease,
                            reason='failure' if primary is not None else 'success', helper=ready))
                        value['cleanup'] = deepcopy(cleaned)
                        require(cleaned['status'] == 'completed' and cleaned['unknown_outcome'] is False,
                            'twenty_cleanup_incomplete')
                        lease.finish(reconciliation_complete=True)
                    except BaseException as error:
                        if primary is None: primary = error
                if primary is not None: raise primary
                require(cleaned['primary_failure'] is None, 'twenty_primary_not_clear')
                value['cleanup']['archive'] = archive_summary(run, value['owned_resources'])
                value['checks']['originals'] = stage('original-replay', lambda: original_summary(run, value['owned_resources']))
                value['checks'].update(readiness=readiness_summary(run, targets),
                    functional=functional_summary(run, targets, controller_concurrency),
                    inventory=inventory_summary(run, targets, controller_concurrency))
            sweep(run)
            observed_sentinel = snapshot('container', sentinel_id, unrelated=True)
            value['checks']['sentinel'] = {'resource_id': sentinel_id, 'before_sha256': baseline, 'after_sha256': observed_sentinel}
            value['checks']['sentinel_unchanged'] = observed_sentinel == baseline
            require(value['checks']['sentinel_unchanged'], 'twenty_sentinel_changed')
            value['checks']['credential_scan_after_cleanup'] = scan_private_material(run)
            value['disk_samples'].append(disk_sample(run, 'twenty-after-cleanup'))
            for relative in (SAMPLE_BEFORE, SAMPLE_AFTER, USAGE): value['artifacts'][relative] = fingerprint(run, relative)
            source(run)
            value.update(status='passed', phase='completed', stock_twenty_scope_complete=True)
            value['stage_seconds']['total'] = time.monotonic() - start; save()
            require(report_twenty(run) == value and gate_twenty(run)['stock_twenty_scope_complete'] is True,
                'twenty_final_replay')
            return deepcopy(value)
    except BaseException as error:
        value.update(status='failed', phase='failed', stock_twenty_scope_complete=False)
        if value['primary_failure'] is None:
            value['primary_failure'] = {'code': safe_code(error), 'recorded_at': now()}
        value['stage_seconds']['total'] = time.monotonic() - start
        try:
            with run.locked(): save()
        except Exception: pass
        if isinstance(error, RunError):
            error.run_id = run.id
            raise
        converted = TwentyError(safe_code(error), 'Twenty-target qualification failed; preserve its original Run and cleanup evidence.')
        converted.run_id = run.id
        raise converted from None
