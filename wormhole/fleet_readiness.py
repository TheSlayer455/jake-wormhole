"""One bounded helper, independent target trust/readiness, exact indexed recovery."""
import base64
from contextlib import contextmanager
from copy import deepcopy
import io
import json
import math
import os
import re
import subprocess
import tarfile
import time

from . import images, readiness as r
from .runs import RunError, SOURCE_ROOT, atomic_json, common, now, read_json, source_identity
from .targets import TargetPlan, LAYOUT

STATE = ('receipt', 'scenario', 'target', 'provisioning', 'trust_address', 'pinned_key', 'counts',
         'last_pending', 'last_started_at')
RECEIVER = r.qualification.INPUT_RECEIVER + r'''
try:
    target=sys.argv[1]
    counts={'smoke':1,'five-targets':5,'twenty-targets':20}
    if len(sys.argv)!=3 or sys.argv[2] not in counts or target not in tuple('target-'+str(i).zfill(3) for i in range(1,counts[sys.argv[2]]+1)): raise ValueError('target identity')
    parent=Path('/run/input')
    if any(p.is_symlink() for p in (parent,*parent.parents)): raise ValueError('linked input')
    info=parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=10001 or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError('input owner')
    root=parent/target
    root.mkdir(mode=0o700)
    receive_inputs(root=root)
except Exception:
    print('fixed target input refused',file=sys.stderr)
    raise SystemExit(2)
'''


def readiness_budget(plan):
    """One shared absolute window; per-probe and container limits stay fixed."""
    return 120 if plan.profile == 'twenty-targets' else r.TIMEOUT


def validate_children(receipt, manifest, plan, targets):
    """Validate retained child outcomes before any executable recovery adapter."""
    from .recovery import valid_failure, _timestamp
    budget = readiness_budget(plan)
    r.require((type(receipt.get('readiness_budget_seconds')) is int and receipt['readiness_budget_seconds'] == budget and
        type(receipt.get('context_version')) is int and receipt['context_version'] == 5) if plan.profile == 'twenty-targets' else
        'readiness_budget_seconds' not in receipt, 'helper_recovery_scope')
    r.require(valid_failure(receipt.get('primary_failure')) and type(receipt.get('secondary_failures')) is list and
        len(receipt['secondary_failures']) <= 64 and all(value is not None and valid_failure(value)
            for value in receipt['secondary_failures']) and _timestamp(receipt.get('updated_at')) and
        receipt.get('expected_pairs') == [{'target_id': target, 'check_id': check}
            for target in plan.target_ids for check in r.EXPECTED] and receipt.get('runtime_pipeline_complete') is False and
        receipt.get('production_iso_eligible') is False, 'helper_recovery_scope')
    r.require(type(receipt.get('targets')) is list and len(receipt['targets']) == len(plan.target_ids), 'helper_recovery_scope')
    children = receipt['targets']
    base = set(common(manifest)) | {'status', 'target_id', 'target_resource_id', 'transitions', 'probes', 'attempts',
        'primary_failure', 'secondary_failures', 'unknown_outcome', 'cleanup'}
    optional = {'ready_started_at', 'hostkey_fingerprint', 'hostkey_source', 'hostkey_observations'}
    for target, item in zip(plan.target_ids, children):
        r.require(type(item) is dict and base <= set(item) <= base | optional and common(item) == common(manifest) and
            item['target_id'] == target and item['target_resource_id'] == targets[target] and
            item['status'] in {'pending', 'waiting', 'ready', 'failed'} and item['unknown_outcome'] is False and
            item['cleanup'] == 'not-started' and valid_failure(item['primary_failure']) and
            (item['status'] == 'failed') == (item['primary_failure'] is not None) and
            type(item['secondary_failures']) is list and len(item['secondary_failures']) <= 64 and
            all(value is not None and valid_failure(value) for value in item['secondary_failures']), 'helper_recovery_scope')
        checks = item['transitions']
        r.require(type(checks) is list and len(checks) <= len(r.EXPECTED) and
            [value.get('check_id') for value in checks] == list(r.EXPECTED[:len(checks)]), 'helper_recovery_scope')
        for check in checks:
            r.require(type(check) is dict and set(check) == {'check_id', 'target_id', 'status', 'observed_at', 'elapsed_seconds'} and
                check['target_id'] == target and check['status'] == 'pass' and _timestamp(check['observed_at']) and
                type(check['elapsed_seconds']) in (int, float) and math.isfinite(check['elapsed_seconds']) and
                0 <= check['elapsed_seconds'] <= budget, 'helper_recovery_scope')
        if item['status'] == 'ready':
            r.require(len(checks) == len(r.EXPECTED) and type(item.get('ready_started_at')) is str and
                1 <= len(item['ready_started_at']) <= 40, 'helper_recovery_scope')
        r.require(type(item['probes']) is list and len(item['probes']) <= 320 and type(item['attempts']) is list and
            len(item['attempts']) <= 512, 'helper_recovery_scope')
        for probe in item['probes']:
            r.require(type(probe) is dict and set(probe) == {'schema_version', 'run_id', 'source_revision', 'target_id',
                'operation', 'attempt', 'status', 'category', 'returncode', 'timed_out', 'truncated', 'duration_seconds'} and
                all(probe[key] == manifest[key] for key in ('schema_version', 'run_id', 'source_revision')) and
                probe['target_id'] == target and probe['operation'] in {'tcp', 'ssh', 'python', 'ansible-wait', 'ansible-ping'} and
                type(probe['attempt']) is int and 1 <= probe['attempt'] <= 64 and probe['status'] in {'pass', 'fail'} and
                (probe['category'] is None or type(probe['category']) is str and probe['category'] in r.CATEGORIES) and type(probe['returncode']) is int and
                type(probe['timed_out']) is bool and type(probe['truncated']) is bool and
                type(probe['duration_seconds']) in (int, float) and math.isfinite(probe['duration_seconds']) and
                0 <= probe['duration_seconds'] <= r.TIMEOUT and (probe['status'] == 'pass') ==
                (probe['category'] is None and probe['returncode'] == 0 and not probe['timed_out'] and not probe['truncated']),
                'helper_recovery_scope')
        for attempt in item['attempts']:
            r.require(type(attempt) is dict and set(attempt) == {'role', 'stage', 'status', 'returncode', 'duration_seconds',
                'log_truncated', 'private_log'} and attempt['role'] in {'helper', 'target'} and
                type(attempt['stage']) is str and attempt['stage'].startswith(target + '-') and len(attempt['stage']) <= 80 and
                attempt['status'] in {'pass', 'fail', 'error', 'timeout', 'unsupported'} and
                (attempt['returncode'] is None or type(attempt['returncode']) is int) and type(attempt['log_truncated']) is bool and
                (attempt['duration_seconds'] is None or type(attempt['duration_seconds']) in (int, float) and math.isfinite(attempt['duration_seconds']) and
                0 <= attempt['duration_seconds'] <= r.TIMEOUT) and type(attempt['private_log']) is str and
                re.fullmatch('private/qualification-(helper|target)-' + re.escape(target) + '-[a-z-]+-[0-9]+[.]log', attempt['private_log']),
                'helper_recovery_scope')
        if 'hostkey_fingerprint' in item:
            r.require(type(item['hostkey_fingerprint']) is str and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', item['hostkey_fingerprint']) and
                item.get('hostkey_source') == 'exact-owned target public-key reader; pin preserved, no TOFU', 'helper_recovery_scope')
        if 'hostkey_observations' in item:
            r.require(type(item['hostkey_observations']) is list and len(item['hostkey_observations']) <= 4 and all(
                type(value) is dict and set(value) == {'fingerprint', 'matches_original_pin', 'observed_at'} and
                type(value['fingerprint']) is str and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', value['fingerprint']) and
                type(value['matches_original_pin']) is bool and _timestamp(value['observed_at']) for value in item['hostkey_observations']),
                'helper_recovery_scope')
    first = next((item['primary_failure'] for item in children if item['primary_failure'] is not None), None)
    r.require((first is None or receipt['primary_failure'] is not None) and
        (receipt['status'] != 'ready' or all(item['status'] == 'ready' for item in children)) and
        (receipt['status'] != 'failed' or receipt['primary_failure'] is not None), 'helper_recovery_scope')


class TargetView:
    """Exact per-target projection; no resource allocation or invented endpoints."""
    def __init__(self, provisioning, target_id):
        self.parent, self.target_id = provisioning, provisioning.target_plan.resolve(target_id)
        self.run, self.lease, self.variables = provisioning.run, provisioning.lease, provisioning.variables
        self.expected_network_id = provisioning.network_id
        self.owned = {'docker_container.target': provisioning.target_resources[target_id], 'docker_network.run': provisioning.network_id}

    @property
    def receipt(self):
        item = self.parent.target_inventory(self.target_id)
        return {'unknown_outcome': self.parent.receipt['unknown_outcome'], 'inventory': {
            **common(self.run.manifest()), 'status': 'pass' if item is not None else 'unverified',
            'targets': [] if item is None else [deepcopy(item)]}}

    def verify_target(self, actual, **options):
        endpoints = actual.get('NetworkSettings', {}).get('Networks', {})
        r.require(type(endpoints) is dict and len(endpoints) == 1 and next(iter(endpoints.values())).get('NetworkID') in
            ({'', self.expected_network_id} if actual.get('State', {}).get('Status') == 'created' else {self.expected_network_id}),
            'inventory_network_mismatch')
        return self.parent.verify_target(actual, target_id=self.target_id, **options)


class BatchReadinessSession(r.ReadinessSession):
    """Run lock/lease/Docker scope remain caller-owned; readiness retries allocate nothing."""
    def __init__(self, provisioning, *, scenarios=None, validation=True, fleet_inventory=False):
        self.run, self.lease, self.parent_provisioning = provisioning.run, provisioning.lease, provisioning
        self.target_plan = TargetPlan.from_lease(self.lease)
        revision, dirty = source_identity(); manifest = self.run.manifest()
        r.require(self.target_plan.profile in {'smoke', 'five-targets', 'twenty-targets'} and self.target_plan == provisioning.target_plan and
            not self.lease._reconciliation_only and self.lease.plan['synthetic'] is False and validation is True and
            type(fleet_inventory) is bool and (not fleet_inventory or self.target_plan.profile == 'twenty-targets') and
            revision == manifest['source_revision'] == self.lease.source_revision and dirty is False and
            manifest['source_dirty'] is False and manifest['mode'] == 'container-reference', 'readiness_scope')
        self.target_resources = provisioning.target_resources
        r.require(set(self.target_resources) == set(self.target_plan.target_ids) and
            all(type(value) is str and r.ID.fullmatch(value) for value in self.target_resources.values()) and
            len(set(self.target_resources.values())) == len(self.target_resources) and
            provisioning.receipt['unknown_outcome'] is False, 'provisioning_not_ready')
        scenarios = {} if scenarios is None else scenarios
        r.require(type(scenarios) is dict and set(scenarios) <= set(self.target_plan.target_ids) and
            all(value in r.SCENARIOS for value in scenarios.values()), 'unsupported_readiness_scenario')
        self.network, self.helper, self.image_labels = provisioning.network_id, None, None
        self.reconciliation_only, self.selected_target, self._on_poll = False, None, None
        self.began = time.monotonic()
        self.deadline = self.began + readiness_budget(self.target_plan)
        self.source_sha256, self.bind_path, self.bind_identity = r.runtime_hash(), self.run.file('private/helper-source/runtime.py'), None
        self.validation_enabled, self.validation_source_sha256 = True, r.code_hash(r.VALIDATION_RUNTIME)
        self.validation_bind_path, self.validation_bind_identity = self.run.file('private/helper-source/validation.py'), None
        self.fleet_inventory_enabled = fleet_inventory
        self.fleet_inventory_source_sha256 = r.code_hash(r.FLEET_INVENTORY_RUNTIME) if fleet_inventory else None
        self.fleet_inventory_bind_path = self.run.file('private/helper-source/fleet-inventory.py')
        self.fleet_inventory_bind_identity = None
        self.target, self.provisioning, self.scenario = next(iter(self.target_resources.values())), provisioning, 'healthy'
        pending = 'deadline_exhausted' if self.target_plan.profile == 'twenty-targets' else 'target_not_started'
        self.trust_address, self.pinned_key, self.counts, self.last_pending, self.last_started_at = None, None, {}, pending, None
        self._aggregate = {**common(manifest), 'operation': 'ssh-ansible-readiness', 'resource_layout': LAYOUT,
            'context_version': self.context_version(), 'target_plan': self.target_plan.record(), 'target_resource_ids': dict(self.target_resources),
            'status': 'pending', 'helper_id': None, 'helper_image': r.HELPER_IMAGE, 'helper_build_run': r.HELPER_BUILD,
            'expected_pairs': [{'target_id': target, 'check_id': check} for target in self.target_plan.target_ids for check in r.EXPECTED],
            'targets': [], 'attempts': [], 'primary_failure': None, 'secondary_failures': [], 'cleanup': 'not-started',
            'unknown_outcome': False, 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
        self._states = {}
        for target in self.target_plan.target_ids:
            receipt = {**common(manifest), 'status': 'pending', 'target_id': target, 'target_resource_id': self.target_resources[target],
                'transitions': [], 'probes': [], 'attempts': [], 'primary_failure': None, 'secondary_failures': [],
                'unknown_outcome': False, 'cleanup': 'not-started'}
            self._states[target] = dict(receipt=receipt, scenario=scenarios.get(target, 'healthy'), target=self.target_resources[target],
                provisioning=TargetView(provisioning, target), trust_address=None, pinned_key=None, counts={},
                last_pending=pending, last_started_at=None)
        self.receipt = self._aggregate
        self._aggregate.update(self.context_policy())

    def context_version(self):
        return 5 if self.target_plan.profile == 'twenty-targets' else 3

    def context_policy(self):
        if self.context_version() == 3:
            return {}
        return {'readiness_budget_seconds': readiness_budget(self.target_plan),
            'helper_policy': self.helper_policy(), 'fleet_inventory_enabled': self.fleet_inventory_enabled,
            'fleet_inventory_source_sha256': self.fleet_inventory_source_sha256,
            'fleet_inventory_bind_identity': self.fleet_inventory_bind_identity}

    def held(self):
        super().held()
        r.require(self.target_plan == TargetPlan.from_lease(self.lease), 'readiness_scope')
        if not self.reconciliation_only:
            r.require(self.parent_provisioning.run.path == self.run.path and self.parent_provisioning.lease is self.lease and
                self.parent_provisioning.target_resources == self.target_resources and
                self.parent_provisioning.receipt['unknown_outcome'] is False, 'provisioning_not_ready')

    @contextmanager
    def selected(self, target_id):
        target_id = self.target_plan.resolve(target_id)
        r.require(self.selected_target is None and not self.reconciliation_only, 'readiness_scope')
        previous = {key: getattr(self, key) for key in STATE}
        self.selected_target = target_id
        for key, value in self._states[target_id].items(): setattr(self, key, value)
        try:
            yield self
        finally:
            self._states[target_id] = {key: getattr(self, key) for key in STATE}
            for key, value in previous.items(): setattr(self, key, value)
            self.selected_target = None

    def stage_name(self, operation):
        return self.selected_target + '-' + operation if self.selected_target else operation

    def save(self):
        if self.selected_target:
            self._states[self.selected_target] = {key: getattr(self, key) for key in STATE}
        record = self._aggregate
        record['targets'] = [deepcopy(self._states[target]['receipt']) for target in self.target_plan.target_ids]
        record['unknown_outcome'] = record['unknown_outcome'] or any(item['unknown_outcome'] for item in record['targets'])
        if record['primary_failure'] is None:
            record['primary_failure'] = next((item['primary_failure'] for item in record['targets'] if item['primary_failure']), None)
        if record['primary_failure'] is not None: record['status'] = 'failed'
        elif all(item['status'] == 'ready' for item in record['targets']): record['status'] = 'ready'
        record.update(helper_id=self.helper, updated_at=now(), **self.context_policy())
        atomic_json(self.run.file('evidence/readiness.json'), record)
        atomic_json(self.run.file('private/readiness-controller.json'), {**common(self.run.manifest()),
            'operation': 'readiness-helper', 'resource_layout': LAYOUT, 'context_version': self.context_version(),
            'target_plan': self.target_plan.record(), 'target_resource_ids': dict(self.target_resources),
            'helper_id': self.helper, 'helper_image': r.HELPER_IMAGE, 'network_id': self.network,
            'image_labels': self.image_labels, 'source_path': str(r.RUNTIME), 'source_sha256': self.source_sha256,
            'bind_path': str(self.bind_path), 'bind_identity': self.bind_identity, 'validation_enabled': True,
            'validation_source_sha256': self.validation_source_sha256, 'validation_bind_identity': self.validation_bind_identity,
            'unknown_outcome': record['unknown_outcome'], 'cleanup': record['cleanup'], **self.context_policy()})

    def transition(self, check):
        if self.target_plan.profile == 'twenty-targets' and check == 'started' and self.last_pending == 'target_not_started':
            # A previous observation of a created container is superseded by
            # this actual start; expiry must not later relabel it unstarted.
            self.last_pending = 'deadline_exhausted'
        super().transition(check)
        if self._on_poll is not None:
            self._on_poll(time.monotonic() - self.began)
            self.timeout()

    def inject_inputs(self, key, address):
        r.require(self.selected_target in self.target_plan.target_ids, 'readiness_scope')
        self.verify_helper(self.inspect('container', self.helper))
        path = self.run.file('private/credentials/id_ed25519')
        with path.open('rb') as stream: private = stream.read(1025)
        r.require(1 <= len(private) <= 1024, 'invalid_auth')
        with path.with_name('id_ed25519.pub').open('rb') as stream:
            other = r.qualification.public_key(stream.read(513).decode('ascii'))
        r.require(other != key, 'invalid_trust_fixture')
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            for name, raw in (('id_ed25519', private), ('known_hosts', ('[' + address + ']:2222 ' + key + '\n').encode()),
                              ('wrong_known_hosts', ('[' + address + ']:2222 ' + other + '\n').encode())):
                member = tarfile.TarInfo(name); member.uid = member.gid = 10001; member.mode = 0o600; member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        began = time.monotonic()
        try:
            result = subprocess.run(['docker', '--config', images.docker_configuration(), '--host', images.SOCKET, 'exec', '-i',
                '--user', '10001:10001', self.helper, '/opt/wormhole/venv/bin/python', '-I', '-S', '-c', RECEIVER,
                self.selected_target, self.target_plan.profile],
                input=data.getvalue(), capture_output=True, timeout=self.timeout(15),
                env={key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'WINDIR') if key in os.environ})
        except subprocess.TimeoutExpired:
            self.receipt['unknown_outcome'] = True; self.save()
            raise r.ReadinessError('helper_auth_injection_unknown', 'The exact target receiver did not finish.') from None
        r.qualification.attempt_record(self.run, self.receipt, 'helper', self.stage_name('auth-input'),
            {'status': 'pass' if result.returncode == 0 else 'fail', 'returncode': result.returncode,
             'duration_seconds': time.monotonic() - began,
             'log': (result.stdout + result.stderr)[:65536], 'log_truncated': len(result.stdout) + len(result.stderr) > 65536})
        self.timeout()
        r.require(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= 65536, 'helper_auth_injection_failed')

    def pin_trust(self, target_id=None):
        if self.selected_target: return super().pin_trust()
        with self.selected(self.target_plan.resolve(target_id)):
            return super().pin_trust()

    def observe_hostkey(self, target_id=None):
        with self.selected(self.target_plan.resolve(target_id)):
            return super().observe_hostkey()

    def poll(self):
        self.held(); r.require(not self._aggregate['unknown_outcome'], 'helper_outcome_unknown')
        for target in self.target_plan.target_ids:
            with self.selected(target):
                if self.receipt['primary_failure'] is not None or self.receipt['status'] == 'ready': continue
                try:
                    super()._poll()
                except Exception as error:
                    super().failure(error)
                    if getattr(error, 'code', None) in {'cancelled', 'cancellation_requested'}: raise
                if self._aggregate['unknown_outcome']: break
        self.save()
        return all(item['receipt']['status'] in {'ready', 'failed'} for item in self._states.values())

    def wait_ready(self, *, on_poll=None):
        r.require(on_poll is None or callable(on_poll), 'invalid_coordinator')
        self._on_poll = on_poll
        try:
            while time.monotonic() < self.deadline:
                if on_poll is not None: on_poll(time.monotonic() - self.began)
                try:
                    self.timeout()
                    if self.poll(): break
                except r.ReadinessError:
                    if time.monotonic() < self.deadline: raise
                    break
                time.sleep(min(r.RETRY_SLEEP, max(0, self.deadline - time.monotonic())))
            for target in self.target_plan.target_ids:
                with self.selected(target):
                    if self.receipt['status'] not in {'ready', 'failed'}:
                        super().failure(r.ReadinessError(self.last_pending, 'This target did not reach readiness before the shared deadline.'))
            self.save()
            if self._aggregate['primary_failure'] is not None:
                raise r.ReadinessError(self._aggregate['primary_failure']['code'], 'One or more exact planned targets failed readiness.')
            try:
                self.require_ready()
                self.timeout()
            except Exception as error:
                super().failure(error)
                raise
            return deepcopy(self._aggregate)
        finally:
            self._on_poll = None

    def require_ready(self, target_id=None, *, inspection_timeout=20):
        r.require(not self._aggregate['unknown_outcome'], 'helper_outcome_unknown')
        import math
        r.require(type(inspection_timeout) in (int, float) and math.isfinite(inspection_timeout) and .1 <= inspection_timeout <= 20,
                  'invalid_readiness_timeout')
        ids = self.target_plan.target_ids if target_id is None else (self.target_plan.resolve(target_id),)
        deadline = time.monotonic() + inspection_timeout
        for target in ids:
            budget = deadline - time.monotonic(); r.require(budget > .1, 'readiness_required')
            with self.selected(target): super().require_ready(inspection_timeout=min(20, budget))
        r.require(all(self._states[target]['receipt']['status'] == 'ready' for target in ids), 'readiness_required')
        r.require(time.monotonic() < deadline, 'readiness_required')
        return True

    def target_state(self, target_id):
        return deepcopy(self._states[self.target_plan.resolve(target_id)]['receipt'])

    @property
    def ready_target_ids(self):
        return tuple(target for target in self.target_plan.target_ids if self._states[target]['receipt']['status'] == 'ready')

    @classmethod
    def resume_cleanup(cls, run, lease):
        lease._active(); revision, dirty = source_identity(); manifest = run.manifest()
        context = read_json(run.file('private/readiness-controller.json'))
        retained = r.readiness_status(run)
        r.require(type(context) is dict, 'helper_recovery_scope')
        plan = TargetPlan.from_record(context.get('target_plan'))
        version = 5 if plan.profile == 'twenty-targets' else 3
        fields = set(common(manifest)) | {'operation', 'resource_layout', 'context_version', 'target_plan', 'target_resource_ids',
            'helper_id', 'helper_image', 'network_id', 'image_labels', 'source_path', 'source_sha256', 'bind_path', 'bind_identity',
            'validation_enabled', 'validation_source_sha256', 'validation_bind_identity', 'unknown_outcome', 'cleanup'}
        if version == 5:
            fields |= {'readiness_budget_seconds', 'helper_policy', 'fleet_inventory_enabled', 'fleet_inventory_source_sha256', 'fleet_inventory_bind_identity'}
        r.require(type(context) is dict and set(context) == fields and common(context) == common(manifest) and
            context['resource_layout'] == LAYOUT and type(context['context_version']) is int and context['context_version'] == version and context['operation'] == 'readiness-helper' and
            context['helper_image'] == r.HELPER_IMAGE and context['validation_enabled'] is True and
            context['source_path'] == str(r.RUNTIME) and context['source_sha256'] == r.runtime_hash() and
            context['bind_path'] == str(run.file('private/helper-source/runtime.py')) and
            context['validation_source_sha256'] == r.code_hash(r.VALIDATION_RUNTIME) and
            context['unknown_outcome'] is False and retained['unknown_outcome'] is False and
            lease._reconciliation_only and lease.run_id == run.id and lease.source_revision == revision == manifest['source_revision'] and
            dirty is False and manifest['source_dirty'] is False and manifest['mode'] == 'container-reference' and
            lease.plan['synthetic'] is False, 'helper_recovery_scope')
        targets = context['target_resource_ids']
        r.require(plan == TargetPlan.from_lease(lease) and plan.profile in {'smoke', 'five-targets', 'twenty-targets'} and
            type(targets) is dict and set(targets) == set(plan.target_ids) and
            all(type(x) is str and r.ID.fullmatch(x) for x in targets.values()) and len(set(targets.values())) == len(targets) and
            type(context['network_id']) is str and r.ID.fullmatch(context['network_id']) and
            (context['helper_id'] is None or type(context['helper_id']) is str and r.ID.fullmatch(context['helper_id'])), 'helper_recovery_scope')
        receipt = read_json(run.file('evidence/readiness.json'))
        r.require(common(receipt) == common(manifest) and receipt.get('target_plan') == plan.record() and
            type(receipt.get('context_version')) is int and receipt['context_version'] == version and receipt.get('resource_layout') == LAYOUT and
            receipt.get('target_resource_ids') == targets and receipt.get('helper_id') == context['helper_id'] and
            receipt.get('cleanup') == context['cleanup'] and receipt.get('unknown_outcome') is False, 'helper_recovery_scope')
        validate_children(receipt, manifest, plan, targets)
        ps = read_json(run.file('evidence/provisioning.json'))
        r.require(common(ps) == common(manifest) and type(ps.get('resources')) is list and
            len(ps['resources']) == len(plan.expected_addresses), 'helper_recovery_scope')
        owned = {item['address']: item['id'] for item in ps['resources']}
        r.require(set(owned) == plan.expected_addresses and owned['docker_network.run'] == context['network_id'] and
            all(owned[plan.address_for(target)] == targets[target] for target in plan.target_ids) and
            type(receipt.get('targets')) is list and [item.get('target_id') for item in receipt['targets']] == list(plan.target_ids) and
            all(type(item) is dict and item.get('target_resource_id') == targets[item['target_id']] and item.get('unknown_outcome') is False
                for item in receipt['targets']), 'helper_recovery_scope')
        if context['helper_id'] is not None:
            r.require(images.inspect('image', r.HELPER_IMAGE)['Config'].get('Labels') == context['image_labels'], 'helper_recovery_scope')
            entries = [x for x in lease.record['resources'] if x['kind'] == 'container' and x['id'] == context['helper_id']]
            r.require(len(entries) == 1 and entries[0]['outcome'] in {'pending', 'absent'}, 'helper_recovery_scope')
        else:
            controller = read_json(run.file('private/terraform/controller.json'))
            r.require(controller.get('run_id') == run.id and controller.get('source_revision') == revision and
                type(controller.get('id')) is str and r.ID.fullmatch(controller['id']), 'helper_recovery_scope')
            allowed = {('container', controller['id']), ('network', context['network_id']), *(('container', item) for item in targets.values())}
            r.require(all((item['kind'], item['id']) in allowed for item in lease.record['resources']), 'helper_recovery_scope')
            found = images.docker(('ps', '-a', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + run.id,
                '--filter', 'label=' + images.LABEL + '.role=helper', '--format', '{{.ID}}'))
            r.require(not found['log_truncated'] and not found['log'].strip(), 'helper_recovery_scope')
        value = cls.__new__(cls)
        value.run, value.lease, value.parent_provisioning, value.provisioning = run, lease, None, None
        value.target_plan, value.target_resources, value.network, value.helper = plan, targets, context['network_id'], context['helper_id']
        value.target, value.image_labels, value.source_sha256 = next(iter(targets.values())), context['image_labels'], context['source_sha256']
        value.bind_path, value.bind_identity = run.file('private/helper-source/runtime.py'), context['bind_identity']
        value.validation_enabled, value.validation_source_sha256 = True, context['validation_source_sha256']
        value.validation_bind_path, value.validation_bind_identity = run.file('private/helper-source/validation.py'), context['validation_bind_identity']
        value.fleet_inventory_enabled = context.get('fleet_inventory_enabled', False)
        value.fleet_inventory_source_sha256 = context.get('fleet_inventory_source_sha256')
        value.fleet_inventory_bind_path = run.file('private/helper-source/fleet-inventory.py')
        value.fleet_inventory_bind_identity = context.get('fleet_inventory_bind_identity')
        if version == 5:
            policy = context['helper_policy']
            r.require(type(context['readiness_budget_seconds']) is int and context['readiness_budget_seconds'] == readiness_budget(plan) and
                type(policy) is dict and set(policy) == {'wait_seconds', 'input_tmpfs_bytes'} and
                all(type(item) is int for item in policy.values()) and policy == value.helper_policy() and
                type(value.fleet_inventory_enabled) is bool and
                (value.fleet_inventory_source_sha256 == r.code_hash(r.FLEET_INVENTORY_RUNTIME) if value.fleet_inventory_enabled else
                    value.fleet_inventory_source_sha256 is None and value.fleet_inventory_bind_identity is None) and
                json.dumps({key: receipt.get(key) for key in value.context_policy()}, sort_keys=True) ==
                    json.dumps(value.context_policy(), sort_keys=True), 'helper_recovery_scope')
        value.receipt = value._aggregate = receipt; value.reconciliation_only, value.selected_target, value._on_poll = True, None, None
        value._states = {item['target_id']: {'receipt': item} for item in receipt['targets']}
        r.require(set(value._states) == set(plan.target_ids), 'helper_recovery_scope')
        if value.bind_identity is not None or value.helper is not None: value.validate_source_copy()
        return value
