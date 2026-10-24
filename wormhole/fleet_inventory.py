"""Stock twenty-target inventory, replayed from five original bounded captures.

The caller retains the Run lock, Docker scope and the same admission lease.
Private transport bytes never enter the safe per-target JSON/text exports.
Only the stock twenty-target profile is supported: five sequential batches of
four with independently selected forks 1..4, 32 KiB canonical native packets,
256 KiB original batch captures and a 90-second complete-stage deadline. The
old candidate SVD and functional executor limits are unchanged. Read-only
reporting replays retained originals after cleanup without live Docker calls.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import time

from fleet_inventory import runtime
from . import images, readiness as r, validation as v
from .fleet_inventory_capture import capture_inventory
from .provisioning import H1
from .runs import RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, now, read_json, source_identity
from .targets import TargetPlan

TIMEOUT = 90
PLAN = 'evidence/fleet-inventory-plan.json'
INDEX = 'evidence/fleet-inventory-index.json'
CONTROLLER = 'evidence/fleet-inventory-controller.json'
TRANSPORT = 'evidence/fleet-inventory-transport.json'
RUNTIME = SOURCE_ROOT / 'fleet_inventory/runtime.py'
TARGET_IDS = runtime.TARGET_IDS
PACKAGES = ('ca-certificates', 'python3', 'python3.12', 'openssh-client', 'openssh-server', 'openssh-sftp-server')
CHECKS = ('target-identity', 'userland', 'package-inventory', 'runtime-sha256',
          *(('package-' + name.replace('.', '-')) for name in PACKAGES))


class FleetInventoryError(RunError):
    pass


def require(value, code='fleet_inventory_invalid'):
    if not value:
        raise FleetInventoryError(code, 'Stock fleet inventory refused; preserve original captures and exact ownership.')


def pure():
    from . import fleet_inventory_records
    return fleet_inventory_records


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(left, right):
    """JSON equality must preserve bool/int and other wire-type distinctions."""
    return canonical(left) == canonical(right)


def code(error):
    value = getattr(error, 'code', 'fleet_inventory_failed')
    return value if type(value) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', value) else 'fleet_inventory_failed'


def batch_for(target):
    require(target in TARGET_IDS, 'fleet_inventory_target')
    return 'batch-' + str((int(target[-3:]) - 1) // 4 + 1).zfill(3)


def log_path(batch):
    require(batch in runtime.BATCHES, 'fleet_inventory_batch')
    return 'private/fleet-inventory/' + batch + '.log'


def exports(target):
    require(target in TARGET_IDS, 'fleet_inventory_target')
    root = 'evidence/fleet-inventory/targets/' + target + '/svd'
    return root + '.json', root + '.txt'


def directory(run, relative):
    current = run.path
    for part in Path(relative).parts:
        current = current / part
        if not current.exists(): current.mkdir(mode=0o700)
        _owned(current, directory=True)
    return current


def read_bytes(path, maximum, *, minimum=1):
    _owned(path)
    info = path.lstat()
    require(info.st_nlink == 1 and minimum <= info.st_size <= maximum, 'fleet_inventory_capture_changed')
    with path.open('rb') as stream: raw = stream.read(maximum + 1)
    after = path.lstat()
    require(len(raw) == info.st_size and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'fleet_inventory_capture_changed')
    return raw


def source_hash():
    return r.code_hash(RUNTIME)


def target_value(target, identifier):
    return {'target_id': target, 'resource_id': identifier, 'image_digest': v.TARGET_IMAGE}


def make_plan(run, target_plan, targets, network, concurrency):
    require(target_plan.profile == 'twenty-targets' and tuple(target_plan.target_ids) == TARGET_IDS and
        set(targets) == set(TARGET_IDS) and len(set(targets.values())) == 20 and
        all(type(item) is str and re.fullmatch('[a-f0-9]{64}', item) for item in targets.values()) and
        type(network) is str and re.fullmatch('[a-f0-9]{64}', network) and
        type(concurrency) is int and 1 <= concurrency <= 4, 'fleet_inventory_scope')
    recipe, files = images.recipe_identity()
    packages = images.load_lock()['apt']['packages']
    versions = {**packages['common'], **packages['target']}
    require(set(versions) == set(PACKAGES), 'fleet_inventory_source_changed')
    expected = {}
    for target in TARGET_IDS:
        values = {'target-identity': canonical(target_value(target, targets[target])).decode(),
            'userland': canonical({'id': 'ubuntu', 'version_id': '24.04', 'architecture': 'amd64'}).decode(),
            'package-inventory': 'complete-installed-dpkg-inventory', 'runtime-sha256': files['runtime.py']}
        values.update({'package-' + name.replace('.', '-'): versions[name] for name in PACKAGES})
        expected[target] = values
    value = {**common(run.manifest()), 'operation': 'stock-fleet-inventory-plan-v1', 'profile': 'twenty-targets',
        'target_plan': target_plan.record(), 'target_resource_ids': dict(targets), 'network_id': network,
        'target_count': 20, 'controller_concurrency': concurrency,
        'stock_build': {'run_id': v.TARGET_BUILD, 'source_revision': v.TARGET_BUILD_SOURCE,
                        'recipe_sha256': recipe, 'runtime_sha256': files['runtime.py']},
        'recipe_files': files, 'collector': {'version': '1.0', 'sha256': digest(runtime.STOCK_PROGRAM.encode()),
            'helper_source_sha256': source_hash(), 'readiness_source_sha256': r.runtime_hash()},
        'batches': {key: list(ids) for key, ids in runtime.BATCHES.items()}, 'expectations': expected,
        'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    return {**value, 'plan_sha256': digest(canonical(value))}


def validate_plan(run, plan):
    context = read_json(run.file('private/terraform/controller.json'))
    provisioning = read_json(run.file('evidence/provisioning.json'))
    ready = read_json(run.file('private/readiness-controller.json'))
    manifest = run.manifest()
    require(all(exact(common(item), common(manifest)) for item in (plan, provisioning, ready)) and
        all(exact(context.get(key), manifest[key]) for key in ('schema_version', 'run_id', 'source_revision')) and
        manifest['profile'] == 'twenty-targets' and manifest['source_dirty'] is False and
        manifest['mode'] == 'container-reference', 'fleet_inventory_plan_changed')
    targets = {item['address']: item['id'] for item in provisioning['resources']}
    expected_addresses = {'docker_network.run', *('docker_container.target["' + target + '"]' for target in TARGET_IDS)}
    require(len(targets) == len(provisioning['resources']) and set(targets) == expected_addresses and
        provisioning.get('target_binding') is None and provisioning['target_image'] == v.TARGET_IMAGE,
        'fleet_inventory_stock_scope')
    mapping = {target: targets['docker_container.target["' + target + '"]'] for target in TARGET_IDS}
    target_plan = TargetPlan.from_record(context['target_plan'])
    require(exact(plan, make_plan(run, target_plan, mapping, targets['docker_network.run'], plan['controller_concurrency'])) and
        exact(ready['target_resource_ids'], mapping) and ready['network_id'] == plan['network_id'] and
        ready['fleet_inventory_enabled'] is True and ready['fleet_inventory_source_sha256'] == source_hash(),
        'fleet_inventory_plan_changed')
    return ready, provisioning, context


def parse_response(raw, plan, batch, budget):
    try:
        require(type(raw) is bytes and 1 <= len(raw) <= runtime.MAX_RESPONSE, 'fleet_inventory_response_invalid')
        value = json.loads(raw, object_pairs_hook=runtime.unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        fields = {'schema_version', 'run_id', 'source_revision', 'plan_sha256', 'batch_id', 'status', 'returncode',
            'timed_out', 'duration_seconds', 'targets', 'helper_provenance', 'diagnostic_bytes', 'diagnostic_truncated'}
        require(type(value) is dict and set(value) == fields and all(value[key] == plan[key] for key in
            ('schema_version', 'run_id', 'source_revision', 'plan_sha256')) and value['batch_id'] == batch and
            value['status'] in ('pass', 'fail') and type(value['returncode']) is int and type(value['timed_out']) is bool and
            type(value['duration_seconds']) in (int, float) and math.isfinite(value['duration_seconds']) and
            0 <= value['duration_seconds'] <= budget and type(value['diagnostic_bytes']) is int and
            0 <= value['diagnostic_bytes'] <= 4096 and type(value['diagnostic_truncated']) is bool and
            type(value['targets']) is list and [item['target_id'] for item in value['targets']] == list(runtime.BATCHES[batch]),
            'fleet_inventory_response_invalid')
        provenance = value['helper_provenance']
        require(type(provenance) is dict and set(provenance) == {'python_version', 'ansible_core_version'} and
            provenance['ansible_core_version'] == '2.21.5' and type(provenance['python_version']) is str and
            re.fullmatch(r'3\.12\.\d{1,3}', provenance['python_version']), 'fleet_inventory_response_invalid')
        observations = {}
        for item in value['targets']:
            require(type(item) is dict and set(item) == {'target_id', 'status', 'category', 'module_returncode', 'collector_base64'} and
                item['status'] in ('pass', 'error', 'unreachable', 'skipped') and
                (item['module_returncode'] is None or type(item['module_returncode']) is int) and
                (item['category'] is None or type(item['category']) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}', item['category'])),
                'fleet_inventory_response_invalid')
            observed = None
            if item['status'] == 'pass':
                require(item['category'] is None and item['module_returncode'] == 0 and value['timed_out'] is False and
                    type(item['collector_base64']) is str and 1 <= len(item['collector_base64']) <= runtime.MAX_BASE64,
                    'fleet_inventory_response_invalid')
                packet = base64.b64decode(item['collector_base64'], validate=True)
                require(1 <= len(packet) <= runtime.MAX_PACKET, 'fleet_inventory_response_invalid')
                observed = json.loads(packet, object_pairs_hook=runtime.unique)
                require(canonical(observed) == packet, 'fleet_inventory_response_invalid')
                pure().validate_observation(observed)
            else:
                require(item['category'] is not None and item['collector_base64'] is None, 'fleet_inventory_response_invalid')
            observations[item['target_id']] = observed
        require((value['status'] == 'pass') == (value['returncode'] == 0 and value['timed_out'] is False and
            all(item['status'] == 'pass' for item in value['targets'])), 'fleet_inventory_response_invalid')
        return value, observations
    except FleetInventoryError:
        raise
    except Exception:
        raise FleetInventoryError('fleet_inventory_response_invalid', 'A complete original four-target response is required.') from None


def make_record(plan, target, actual, observed, capture, provenance, primary, unknown, stamp):
    value = {**{key: plan[key] for key in common(plan)}, 'operation': 'stock-fleet-software-description-v1',
        'profile': 'twenty-targets', 'target_id': target, 'status': 'failed', 'plan_sha256': plan['plan_sha256'],
        'stock_build': deepcopy(plan['stock_build']), 'collector': deepcopy(plan['collector']), 'target': deepcopy(actual),
        'observation': deepcopy(observed), 'execution_provenance': deepcopy(provenance), 'checks': [],
        'capture': deepcopy(capture), 'primary_failure': deepcopy(primary), 'unknown_outcome': unknown,
        'updated_at': stamp, 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    values = pure().observed_values(value)
    for check in CHECKS:
        result = values.get(check, '')
        status = 'unverified' if observed is None and check != 'target-identity' or actual is None else (
            'pass' if result == plan['expectations'][target][check] else 'fail')
        value['checks'].append({'check_id': check, 'target_id': target, 'required': True,
            'expected': plan['expectations'][target][check], 'observed': result, 'status': status,
            'evidence': [PLAN, 'captures/stock-inventory/' + batch_for(target)]})
    passing = (observed is not None and capture is not None and capture['complete'] and not unknown and
        primary is None and all(item['status'] == 'pass' for item in value['checks']))
    value['status'] = 'passed' if passing else 'failed'
    if not passing and value['primary_failure'] is None:
        value['primary_failure'] = {'code': 'fleet_inventory_required_check_failed', 'recorded_at': value['updated_at']}
    return pure().validate_record(value)


def controller_provenance(run, plan):
    ready, ps, tf = validate_plan(run, plan)
    path = run.file(CONTROLLER)
    if not path.exists(): return None
    value = read_json(path)
    require(exact(common(value), common(run.manifest())) and set(value) == {*common(run.manifest()), 'operation', 'targets',
        'network_id', 'helper_id', 'helper_image', 'provisioner_id', 'provisioner_image', 'actual_tools'} and
        value['operation'] == 'stock-fleet-controller-v1' and value['network_id'] == plan['network_id'] and
        exact(value['targets'], {target: target_value(target, plan['target_resource_ids'][target]) for target in TARGET_IDS}) and
        value['helper_id'] == ready['helper_id'] and value['helper_image'] == r.HELPER_IMAGE and
        value['provisioner_id'] == tf['id'] and value['provisioner_image'] == v.TARGET_IMAGE and
        exact(value['actual_tools'], ps['actual_tools']) and exact(value['actual_tools'],
            {'terraform_version': '1.17.0', 'platform': 'linux_amd64', 'provider_version': '4.6.0',
             'offline_readonly_lock_h1_confirmed': H1, 'provider_schema_observed': True}),
        'fleet_inventory_provenance_changed')
    return value


def replay(run):
    plan = read_json(run.file(PLAN)); validate_plan(run, plan)
    transport = read_json(run.file(TRANSPORT)); controller = controller_provenance(run, plan)
    require(exact(common(transport), common(run.manifest())) and set(transport) == {*common(run.manifest()), 'operation',
        'plan_sha256', 'attempts', 'primary_failure', 'unknown_outcome', 'updated_at'} and
        transport['operation'] == 'stock-fleet-transport-v1' and transport['plan_sha256'] == plan['plan_sha256'] and
        type(transport['attempts']) is list and len(transport['attempts']) <= 5 and
        type(transport['unknown_outcome']) is bool, 'fleet_inventory_transport_changed')
    from .recovery import valid_failure, _timestamp
    require(valid_failure(transport['primary_failure']) and _timestamp(transport['updated_at']), 'fleet_inventory_transport_changed')
    data = {}
    for position, attempt in enumerate(transport['attempts']):
        batch = list(runtime.BATCHES)[position]
        require(type(attempt) is dict and set(attempt) == {'batch_id', 'path', 'sha256', 'size_bytes', 'status', 'returncode',
            'duration_seconds', 'log_truncated', 'budget_seconds', 'response_validation'} and attempt['batch_id'] == batch and
            attempt['path'] == log_path(batch) and type(attempt['budget_seconds']) in (int, float) and
            math.isfinite(attempt['budget_seconds']) and .1 <= attempt['budget_seconds'] <= 27 and
            attempt['status'] in ('pass', 'fail', 'error', 'timeout') and type(attempt['log_truncated']) is bool and
            (attempt['returncode'] is None or type(attempt['returncode']) is int) and
            type(attempt['duration_seconds']) in (int, float) and math.isfinite(attempt['duration_seconds']) and
            0 <= attempt['duration_seconds'] <= attempt['budget_seconds'] + 6 and
            attempt['response_validation'] in ('not-validated', 'valid', 'invalid'), 'fleet_inventory_transport_changed')
        raw = read_bytes(run.file(log_path(batch)), runtime.MAX_RESPONSE, minimum=0)
        require(attempt['sha256'] == digest(raw) and type(attempt['size_bytes']) is int and attempt['size_bytes'] == len(raw),
                'fleet_inventory_capture_changed')
        outer_complete = attempt['status'] == 'pass' and attempt['returncode'] == 0 and not attempt['log_truncated']
        require(outer_complete or attempt['response_validation'] == 'not-validated', 'fleet_inventory_transport_changed')
        if attempt['response_validation'] == 'invalid':
            try: parse_response(raw, plan, batch, attempt['budget_seconds'])
            except FleetInventoryError: pass
            else: require(False, 'fleet_inventory_transport_changed')
        complete = outer_complete and attempt['response_validation'] == 'valid'
        response, observations = parse_response(raw, plan, batch, attempt['budget_seconds']) if complete else (None, {})
        for target in runtime.BATCHES[batch]:
            observed = observations.get(target)
            response_item = next((item for item in response['targets'] if item['target_id'] == target), None) if response else None
            capture = {'batch_id': batch, 'path': 'captures/stock-inventory/' + batch, 'sha256': digest(raw),
                'size_bytes': len(raw), 'complete': complete, 'collector_sha256': digest(canonical(observed)) if observed is not None else None,
                'collector_bytes': len(canonical(observed)) if observed is not None else 0} if raw else None
            provenance = None if controller is None or response is None else {
                'helper': {'image_digest': controller['helper_image'], **response['helper_provenance']},
                'provisioner': {'image_digest': controller['provisioner_image'], 'terraform_version': '1.17.0', 'provider_version': '4.6.0'}}
            failure = None
            if response_item is None or response_item['status'] != 'pass':
                failure = transport['primary_failure'] or {'code': response_item['category'] if response_item else 'fleet_inventory_probe_incomplete', 'recorded_at': transport['updated_at']}
            data[target] = (observed, capture, provenance, failure, attempt['status'] == 'timeout')
    result = {}
    for target in TARGET_IDS:
        observed, capture, provenance, failure, unknown = data.get(target, (None, None, None,
            transport['primary_failure'] or {'code': 'fleet_inventory_not_collected', 'recorded_at': transport['updated_at']}, False))
        actual = controller['targets'][target] if controller is not None else None
        result[target] = make_record(plan, target, actual, observed, capture, provenance, failure, unknown, transport['updated_at'])
    return plan, transport, result


def report_fleet_inventory(run):
    plan, transport, expected = replay(run)
    index = pure().validate_index(read_json(run.file(INDEX)))
    require(exact(common(index), common(run.manifest())) and index['plan_sha256'] == plan['plan_sha256'] and
        index['controller_concurrency'] == plan['controller_concurrency'] and
        exact(index['primary_failure'], transport['primary_failure']) and index['unknown_outcome'] is transport['unknown_outcome'] and
        index['updated_at'] == transport['updated_at'],
        'fleet_inventory_index_changed')
    targets, rows = [], []
    for row, target in zip(index['targets'], TARGET_IDS):
        record = pure().validate_record(read_json(run.file(exports(target)[0])))
        require(exact(record, expected[target]), 'fleet_inventory_record_changed')
        raw, text = pure().render_json(record), pure().render_text(record)
        require(read_bytes(run.file(exports(target)[0]), pure().MAX_RECORD_BYTES) == raw and
            read_bytes(run.file(exports(target)[1]), 262144) == text.encode() and
            row['record'] == {'path': exports(target)[0], 'sha256': digest(raw), 'size_bytes': len(raw)} and
            row['text'] == {'path': exports(target)[1], 'sha256': digest(text.encode()), 'size_bytes': len(text.encode())} and
            row['status'] == record['status'] and row['checks'] == [{key: item[key] for key in ('check_id', 'status')} for item in record['checks']],
            'fleet_inventory_export_changed')
        targets.append({'record': record, 'text': text})
        rows.append({'target_id': target, 'status': record['status'],
            'record': {'path': exports(target)[0], 'sha256': digest(raw), 'size_bytes': len(raw)},
            'text': {'path': exports(target)[1], 'sha256': digest(text.encode()), 'size_bytes': len(text.encode())},
            'checks': [{key: item[key] for key in ('check_id', 'status')} for item in record['checks']]})
    require(exact(index, make_index(run, plan, transport, rows)), 'fleet_inventory_index_changed')
    return {'index': index, 'targets': targets}


def make_index(run, plan, transport, rows):
    passed = transport['primary_failure'] is None and not transport['unknown_outcome'] and all(row['status'] == 'passed' for row in rows)
    require(passed or transport['primary_failure'] is not None, 'fleet_inventory_required_check_failed')
    return pure().validate_index({**common(run.manifest()), 'operation': 'stock-fleet-software-inventory-index-v1',
        'profile': 'twenty-targets', 'status': 'passed' if passed else 'failed', 'plan_sha256': plan['plan_sha256'],
        'target_count': 20, 'controller_concurrency': plan['controller_concurrency'], 'targets': rows,
        'primary_failure': transport['primary_failure'], 'unknown_outcome': transport['unknown_outcome'],
        'updated_at': transport['updated_at'], 'runtime_pipeline_complete': False, 'production_iso_eligible': False})


class FleetInventorySession:
    def __init__(self, readiness, *, controller_concurrency=None):
        self.readiness, self.run, self.lease = readiness, readiness.run, readiness.lease
        readiness.held(); self.ps = readiness.parent_provisioning
        revision, dirty = source_identity(); target_plan = TargetPlan.from_lease(self.lease)
        require(target_plan.profile == 'twenty-targets' and tuple(target_plan.target_ids) == TARGET_IDS and
            readiness.target_plan == target_plan and readiness.fleet_inventory_enabled is True and
            readiness.fleet_inventory_source_sha256 == source_hash() and revision == self.run.manifest()['source_revision'] and
            dirty is False and not self.lease._reconciliation_only, 'fleet_inventory_scope')
        cap = self.lease.plan['controller_concurrency']
        concurrency = cap if controller_concurrency is None else controller_concurrency
        require(type(cap) is int and type(concurrency) is int and 1 <= concurrency <= min(cap, 4), 'fleet_inventory_scope')
        build = v.qualification.build_reference(v.TARGET_BUILD, 'target')
        require(build['image_id'] == v.TARGET_IMAGE and build['source_revision'] == v.TARGET_BUILD_SOURCE, 'fleet_inventory_stock_scope')
        self.plan = make_plan(self.run, target_plan, readiness.target_resources, readiness.network, concurrency)
        require(not self.run.file(PLAN).exists(), 'fleet_inventory_attempt_reused')
        directory(self.run, 'private/fleet-inventory')
        for target in TARGET_IDS: directory(self.run, str(Path(exports(target)[0]).parent))
        atomic_json(self.run.file(PLAN), self.plan)
        self.transport = {**common(self.run.manifest()), 'operation': 'stock-fleet-transport-v1',
            'plan_sha256': self.plan['plan_sha256'], 'attempts': [], 'primary_failure': None, 'unknown_outcome': False,
            'updated_at': now()}
        self.started = False; self.save()

    def save(self):
        self.transport['updated_at'] = now()
        atomic_json(self.run.file(TRANSPORT), self.transport)

    def remaining(self, deadline, maximum=20):
        left = deadline - time.monotonic(); require(left > .1, 'fleet_inventory_timeout')
        return min(left, maximum)

    def failure(self, error):
        # Recording an uncertain exec must not call the batch readiness policy
        # that correctly refuses further probes once provisioning is unknown.
        r.ReadinessSession.held(self.readiness); self.ps.held()
        require(self.readiness.run.path == self.run.path and self.readiness.lease is self.lease and
            self.readiness.parent_provisioning is self.ps and self.ps.run.path == self.run.path and
            self.ps.lease is self.lease, 'fleet_inventory_scope')
        if self.ps.receipt['primary_failure'] is None:
            self.ps.failure(FleetInventoryError(code(error), 'A required stock inventory stage failed.'))
        if self.transport['primary_failure'] is None:
            self.transport['primary_failure'] = {'code': code(error), 'recorded_at': now()}
        self.save()

    def export(self):
        plan, transport, records = replay(self.run)
        rows = []
        for target in TARGET_IDS:
            record = records[target]; raw = pure().render_json(record); text = pure().render_text(record).encode()
            atomic_bytes(self.run.file(exports(target)[0]), raw, limit=pure().MAX_RECORD_BYTES)
            atomic_bytes(self.run.file(exports(target)[1]), text, limit=262144)
            rows.append({'target_id': target, 'status': record['status'],
                'record': {'path': exports(target)[0], 'sha256': digest(raw), 'size_bytes': len(raw)},
                'text': {'path': exports(target)[1], 'sha256': digest(text), 'size_bytes': len(text)},
                'checks': [{key: item[key] for key in ('check_id', 'status')} for item in record['checks']]})
        index = make_index(self.run, plan, transport, rows)
        atomic_json(self.run.file(INDEX), index)
        return index

    def collect(self):
        require(not self.started, 'fleet_inventory_attempt_reused'); self.started = True
        deadline = time.monotonic() + TIMEOUT
        try:
            self.readiness.held(); validate_plan(self.run, self.plan)
            helper = images.inspect('container', self.readiness.helper, timeout=self.remaining(deadline))
            self.readiness.verify_helper(helper)
            controller = images.inspect('container', self.ps.provisioner, timeout=self.remaining(deadline)); self.ps.verify_provisioner(controller)
            actual_targets = {}
            for target in TARGET_IDS:
                self.readiness.require_ready(target, inspection_timeout=self.remaining(deadline))
                inventory = self.ps.target_inventory(target)
                actual = images.inspect('container', self.plan['target_resource_ids'][target], timeout=self.remaining(deadline))
                self.ps.verify_target(actual, target_id=target, inspection_timeout=self.remaining(deadline))
                require(inventory is not None and actual['Id'] == inventory['resource_id'] == self.plan['target_resource_ids'][target] and
                    actual['Image'] == v.TARGET_IMAGE and inventory['host'] == self.readiness._states[target]['trust_address'],
                    'fleet_inventory_target_identity')
                for stamp, lifetime in ((actual['State']['StartedAt'], 300), (helper['State']['StartedAt'], self.readiness.helper_policy()['wait_seconds'])):
                    start = datetime.fromisoformat(stamp.replace('Z', '+00:00')); elapsed = (datetime.now(timezone.utc) - start).total_seconds()
                    require(start.tzinfo is not None and 0 <= elapsed and lifetime - elapsed >= TIMEOUT + 20, 'fleet_inventory_lifetime_budget')
                actual_targets[target] = target_value(target, actual['Id'])
            atomic_json(self.run.file(CONTROLLER), {**common(self.run.manifest()), 'operation': 'stock-fleet-controller-v1',
                'targets': actual_targets, 'network_id': self.plan['network_id'], 'helper_id': self.readiness.helper,
                'helper_image': helper['Image'], 'provisioner_id': self.ps.provisioner, 'provisioner_image': controller['Image'],
                'actual_tools': deepcopy(self.ps.receipt['actual_tools'])})
            for batch, ids in runtime.BATCHES.items():
                budget = self.remaining(deadline, 27); require(budget > 3, 'fleet_inventory_timeout')
                request = {key: self.plan[key] for key in ('schema_version', 'run_id', 'source_revision', 'plan_sha256')}
                request.update(operation='stock-fleet-inventory-batch-v1', batch_id=batch,
                    targets=[{'target_id': target, 'address': self.readiness._states[target]['trust_address']} for target in ids],
                    controller_concurrency=self.plan['controller_concurrency'],
                    readiness_source_sha256=self.plan['collector']['readiness_source_sha256'], timeout_seconds=min(25, budget - 2))
                runtime.decode(canonical(request))
                result = capture_inventory(self.readiness.helper, base64.b64encode(canonical(request)).decode(), timeout=budget)
                if result['status'] == 'timeout':
                    self.transport['unknown_outcome'] = True
                    self.ps.receipt['unknown_outcome'] = True; self.ps.save()
                    self.readiness.receipt['unknown_outcome'] = True; self.readiness.save()
                    self.save()  # Uncertainty is durable before any diagnostic write.
                raw = result['log']; require(type(raw) is bytes and len(raw) <= runtime.MAX_RESPONSE, 'fleet_inventory_capture_bound')
                atomic_bytes(self.run.file(log_path(batch)), raw, limit=runtime.MAX_RESPONSE)
                self.transport['attempts'].append({'batch_id': batch, 'path': log_path(batch), 'sha256': digest(raw),
                    'size_bytes': len(raw), 'status': result['status'], 'returncode': result['returncode'],
                    'duration_seconds': result['duration_seconds'], 'log_truncated': result['log_truncated'], 'budget_seconds': budget,
                    'response_validation': 'not-validated'})
                self.save(); require(result['status'] == 'pass' and result['returncode'] == 0 and not result['log_truncated'], 'fleet_inventory_probe_incomplete')
                self.remaining(deadline)
                try: response, observations = parse_response(raw, self.plan, batch, budget)
                except FleetInventoryError:
                    self.transport['attempts'][-1]['response_validation'] = 'invalid'; self.save()
                    raise
                self.transport['attempts'][-1]['response_validation'] = 'valid'; self.save()
                require(response['status'] == 'pass' and all(observations[target] is not None for target in ids), 'fleet_inventory_required_check_failed')
            self.remaining(deadline)
            index = self.export(); self.remaining(deadline)
            require(index['status'] == 'passed', 'fleet_inventory_required_check_failed')
            self.require_passed(); self.remaining(deadline)
            return index
        except BaseException as error:
            self.failure(error)
            try: self.export()
            except Exception:
                pass  # Never replace the primary failure with a failed safe export.
            raise

    def require_passed(self):
        require(report_fleet_inventory(self.run)['index']['status'] == 'passed', 'fleet_inventory_required')
        return True
