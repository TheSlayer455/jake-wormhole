"""Fixed initialization operations on already verified, project-owned targets.

Docker exec observes/configures the disposable target; SSH/Ansible acceptance
still runs through the actual validation helper. No host policy is changed.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from . import images
from .runs import RunError, SOURCE_ROOT, atomic_bytes, atomic_json, common, now, read_json
from .stages import _run_process
from initialization import runtime

SOURCE = SOURCE_ROOT / 'initialization/runtime.py'
RECORD = 'evidence/initialization.json'
CATEGORIES = {'initialization_command_failed', 'final_account_missing', 'final_home_inaccessible',
              'authorized_key_missing', 'simulated_installation_source_missing'}
TERMINAL_READER = '''import os,sys
from pathlib import Path
number=sys.argv[1]
if not number.isdigit() or not 0<=int(number)<80: raise SystemExit(2)
path=Path('/run/wormhole/initialization')/(number+'.json')
if any(item.is_symlink() for item in (path,*path.parents)) or not path.is_file(): raise SystemExit(3)
with path.open('rb') as stream: raw=stream.read(8193)
if not 1<=len(raw)<=8192 or path.stat().st_uid!=0: raise SystemExit(2)
sys.stdout.buffer.write(raw)
'''


def require(value, code='initialization_invalid'):
    if not value: raise RunError(code, 'Initialization did not establish the required final target configuration.')


def decode(raw, run_id, scenario):
    require(type(raw) is bytes and 1 <= len(raw) <= 8192)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value); value[key] = item
        return value
    try: value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError): raise RunError('initialization_invalid', 'Initialization output is incomplete or malformed.') from None
    require(type(value) is dict and set(value) == {'schema_version', 'operation', 'run_id', 'scenario', 'status',
        'stage', 'category', 'command_returncode', 'checks', 'events', 'simulated_installation', 'production_iso_eligible'})
    require(value['category'] is None or type(value['category']) is str)
    require(value['schema_version'] == '1.0' and value['operation'] == 'container-initialization-v1' and
        value['run_id'] == run_id and value['scenario'] == scenario and scenario in runtime.SCENARIOS and
        value['status'] in {'pending', 'passed', 'failed'} and value['stage'] in {'initialization', 'configuration', 'hardening'} and
        type(value['checks']) is dict and set(value['checks']) == set(runtime.FIELDS) and
        all(type(item) is bool for item in value['checks'].values()) and
        value['simulated_installation'] is (scenario == 'installation-source-missing') and value['production_iso_eligible'] is False and
        type(value['events']) is list and 1 <= len(value['events']) <= 5 and all(item in {
            'initialization-started', 'initialization-complete', 'configuration-started', 'configuration-complete', 'hardening-applied'} for item in value['events']))
    require((value['status'] == 'failed') == (value['category'] in CATEGORIES) and
        (value['category'] is None or value['category'] in CATEGORIES) and
        (value['status'] == 'passed') == all(value['checks'].values()))
    require(value['command_returncode'] is None or scenario == 'initialization-command-fails' and
        type(value['command_returncode']) is int and value['command_returncode'] == 23)
    if scenario == 'initialization-command-fails':
        require(value['status']=='failed' and value['category']=='initialization_command_failed' and
            value['command_returncode']==23 and value['stage']=='initialization')
    if value['status']=='passed':
        require(value['events']==['initialization-started','initialization-complete','configuration-started','configuration-complete'] and
            value['stage']=='configuration')
    return value


class InitializationSession:
    def __init__(self, provisioning, *, absolute_deadline=None):
        provisioning.held()
        self.provisioning, self.run = provisioning, provisioning.run
        self.deadline = min(time.monotonic() + 30, absolute_deadline) if absolute_deadline is not None else time.monotonic() + 30
        self.run_deadline=absolute_deadline if absolute_deadline is not None else self.deadline
        self.source = SOURCE.read_bytes()
        require(1 <= len(self.source) <= 16384 and not SOURCE.is_symlink())
        self.record = {**common(self.run.manifest()), 'operation': 'owned-container-initialization-v1',
            'source_sha256': hashlib.sha256(self.source).hexdigest(), 'expected_targets': list(provisioning.target_plan.target_ids),
            'targets': {}, 'attempts': [],
            'unknown_outcome': False, 'production_iso_eligible': False}
        require(not self.run.file(RECORD).exists(), 'initialization_attempt_reused')
        self.save()

    def save(self):
        self.record['updated_at'] = now(); atomic_json(self.run.file(RECORD), self.record)

    def remaining(self):
        budget = self.deadline - time.monotonic()
        require(budget > .1, 'initialization_deadline_exhausted')
        return min(12, budget)

    def observe(self, target_id, scenario='healthy'):
        require(scenario in runtime.SCENARIOS)
        ps = self.provisioning; ps.held()
        require(not getattr(ps,'destroy_only',False),'initialization_recovery_observation_only')
        ps.check_inputs()
        require(not ps.receipt['unknown_outcome'] and not self.record['unknown_outcome'], 'initialization_outcome_unknown')
        target_id = ps.target_plan.resolve(target_id)
        resource = ps.target_resources[target_id]
        if scenario == 'hardening-breaks-home':
            require(self.record['targets'].get(target_id, {}).get('observation', {}).get('status') == 'passed', 'hardening_baseline_required')
        before = images.inspect('container', resource, timeout=self.remaining())
        ps.verify_target(before, target_id=target_id, inspection_timeout=self.remaining())
        require(before['State']['Running'] is True, 'initialization_runtime_not_started')
        require(hashlib.sha256(SOURCE.read_bytes()).hexdigest() == self.record['source_sha256'], 'initialization_source_changed')
        began = time.monotonic()
        index = len(self.record['attempts']); require(index < 80, 'initialization_attempt_bound')
        attempt = {'target_id':target_id,'scenario':scenario,'resource_id':resource,
            'started_at':before['State']['StartedAt'],'capture':None,'sha256':None,
            'duration_seconds':None,'process_status':'unknown','returncode':None}
        before_path='private/initialization-provider-before-'+str(index).zfill(3)+'.json'
        atomic_json(self.run.file(before_path),deepcopy(ps.receipt))
        attempt.update(provider_before=before_path,
            provider_before_sha256=hashlib.sha256(self.run.file(before_path).read_bytes()).hexdigest())
        self.record['attempts'].append(attempt)
        self.record['unknown_outcome'] = True;self.save()
        ps.receipt['unknown_outcome'] = True; ps.save()
        result = _run_process(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
            'exec', '--user', '0:0', resource, '/usr/bin/python3', '-I', '-S', '-c', self.source.decode(),
            scenario, 'true' if ps.variables.get('mutable_home', False) else 'false', str(index)),
            cwd=SOURCE_ROOT, timeout=min(.25,self.remaining()) if scenario=='observer-lost' else self.remaining())
        path = 'private/initialization-' + str(index).zfill(3) + '.json'
        raw = result['log']; atomic_bytes(self.run.file(path), raw, limit=8192)
        attempt.update(capture=path,sha256=hashlib.sha256(raw).hexdigest(),
            duration_seconds=time.monotonic()-began,process_status=result['status'],returncode=result['returncode'])
        if result['status'] == 'timeout':
            self.record['unknown_outcome'] = True; ps.receipt['unknown_outcome'] = True; ps.save(); self.save()
            raise RunError('initialization_outcome_unknown', 'The target operation may still be running; preserve ownership and reconcile it.')
        require(not result['log_truncated'] and result['status'] in {'pass', 'fail'}, 'initialization_capture_incomplete')
        value = decode(raw, self.run.id, scenario)
        require((value['status'] != 'failed') == (result['returncode'] == 0), 'initialization_exit_inconsistent')
        after = images.inspect('container', resource, timeout=self.remaining())
        ps.verify_target(after, target_id=target_id, inspection_timeout=self.remaining())
        require(after['State']['Running'] is True and after['State']['StartedAt'] == before['State']['StartedAt'], 'initialization_restarted')
        self.record['targets'][target_id] = {'resource_id': resource, 'attempt': index, 'observation': value}
        self.record['unknown_outcome'] = False; ps.receipt['unknown_outcome'] = False; ps.save()
        self.save(); return deepcopy(value)

    @classmethod
    def resume(cls,run,lease):
        """Issue only a read/stop adapter after original provider proof replays."""
        from .initialization_recovery import InitializationProof
        from .provisioning import ProvisioningSession
        proof=InitializationProof(run,lease)
        session=cls.__new__(cls);session.provisioning=ProvisioningSession._load_retained(run,lease,initialization=proof)
        session.run=run;session.source=SOURCE.read_bytes();session.record=deepcopy(proof.record)
        session.deadline=session.run_deadline=time.monotonic()+8
        return session

    def reconcile(self, target_id, *, absolute_deadline=None):
        """A verified durable result resolves observation loss; elapsed time does not."""
        ps = self.provisioning; ps.held(); ps.check_inputs()
        deadline=min(time.monotonic()+8,absolute_deadline) if absolute_deadline is not None else time.monotonic()+8
        def budget(maximum):
            remaining=deadline-time.monotonic()
            require(remaining>.1,'initialization_terminal_unavailable')
            return min(maximum,remaining)
        target_id = ps.target_plan.resolve(target_id)
        attempts = [(index,item) for index,item in enumerate(self.record['attempts']) if item['target_id']==target_id]
        require(self.record['unknown_outcome'] and attempts, 'initialization_reconciliation_required')
        index,attempt = attempts[-1]
        actual = images.inspect('container',attempt['resource_id'],timeout=budget(5))
        ps.verify_target(actual,target_id=target_id,inspection_timeout=budget(5))
        require(actual['State']['Running'] is True and actual['State']['StartedAt']==attempt['started_at'], 'initialization_restarted')
        result = _run_process(('docker','--config',images.docker_configuration(),'--host',images.SOCKET,
            'exec','--user','0:0',attempt['resource_id'],'/usr/bin/python3','-I','-S','-c',TERMINAL_READER,str(index)),
            cwd=SOURCE_ROOT,timeout=budget(3))
        budget(3)
        require(result['status']=='pass' and result['returncode']==0 and not result['log_truncated'], 'initialization_terminal_unavailable')
        value = decode(result['log'],self.run.id,attempt['scenario'])
        require(value['status']!='pending','initialization_terminal_unavailable')
        path='private/initialization-reconciled-'+str(index).zfill(3)+'.json'
        atomic_bytes(self.run.file(path),result['log'],limit=8192)
        attempt.update(capture=path,sha256=hashlib.sha256(result['log']).hexdigest(),
            terminal_marker_verified=True,reconciled_at=now())
        self.record['targets'][target_id]={'resource_id':attempt['resource_id'],'attempt':index,'observation':value}
        self.record['unknown_outcome']=False;ps.receipt['unknown_outcome']=False;ps.save();self.save()
        return deepcopy(value)

    def cancel_and_confirm(self,target_id):
        """Resolve only this contained exec by stopping its exact owned PID namespace.

        This cannot resolve an unknown create, Terraform request or image commit:
        observe() accepted a known provider state before recording this exec intent.
        """
        ps=self.provisioning;ps.held();ps.check_inputs()
        target_id=ps.target_plan.resolve(target_id)
        attempts=[item for item in self.record['attempts'] if item['target_id']==target_id]
        require(self.record['unknown_outcome'] is True and attempts,'initialization_reconciliation_required')
        attempt=attempts[-1];identifier=attempt['resource_id']
        require(identifier==ps.target_resources[target_id],'initialization_scope')
        before=images.inspect('container',identifier,timeout=5)
        if before['State']['Running'] is True:ps.verify_target(before,target_id=target_id,inspection_timeout=5)
        else:
            ps.verify_owned(before,'target',identifier,target_id=target_id);ps.verify_limits(before,'target',stopped=True)
        require(before['State']['StartedAt']==attempt['started_at'],'initialization_restarted')
        if before['State']['Running'] is True:images.docker(('stop','--time','2',identifier),timeout=5)
        after=images.inspect('container',identifier,timeout=5)
        ps.verify_owned(after,'target',identifier,target_id=target_id)
        ps.verify_limits(after,'target',stopped=True)
        require(after['State']['Running'] is False and after['State']['Pid']==0 and after['State']['Status']=='exited' and
            after['State']['StartedAt']==attempt['started_at'],
            'initialization_stop_unconfirmed')
        attempt['stop_proof']={'resource_id':identifier,'started_at':attempt['started_at'],
            'status':'exited','pid':0,'confirmed_at':now()}
        self.record['targets'][target_id]={'resource_id':identifier,'attempt':self.record['attempts'].index(attempt),
            'observation':None,'terminal_outcome':'cancelled-confirmed-stopped'}
        self.record['unknown_outcome']=False;ps.receipt['unknown_outcome']=False;ps.save();self.save()
        return deepcopy(attempt['stop_proof'])

    def begin_phase(self):
        self.deadline=min(time.monotonic()+30,self.run_deadline)
        self.remaining()

    def wait_result(self,target_id,scenario='healthy'):
        while True:
            value = self.observe(target_id,scenario)
            if value['status'] != 'pending': return value
            time.sleep(min(.1, self.remaining()))

    def wait_complete(self, target_id):
        self.wait_result(target_id)
        return self.require_complete(target_id)

    def require_complete(self, target_id, *, allow_pending=False):
        target_id = self.provisioning.target_plan.resolve(target_id)
        require(not self.record['unknown_outcome'], 'initialization_outcome_unknown')
        value = self.record['targets'].get(target_id, {}).get('observation')
        if value is None or value['status'] == 'pending':
            if allow_pending: return False
            raise RunError('configuration_pending', 'Final configuration has not been observed complete.')
        require(value['status'] == 'passed', value['category'] or 'configuration_incomplete')
        return True


def report_initialization(run, *, require_passed=False):
    record = read_json(run.file(RECORD))
    require(common(record) == common(run.manifest()) and record['source_sha256'] == hashlib.sha256(SOURCE.read_bytes()).hexdigest())
    require(type(record['expected_targets']) is list and 1 <= len(record['expected_targets']) <= 20 and
        len(set(record['expected_targets'])) == len(record['expected_targets']) and
        set(record['targets']) <= set(record['expected_targets']))
    if require_passed:
        require(record['unknown_outcome'] is False and set(record['targets']) == set(record['expected_targets']) and
            all(type(item.get('observation')) is dict and item['observation']['status'] == 'passed'
                for item in record['targets'].values()), 'initialization_required')
    for target, item in record['targets'].items():
        attempt = record['attempts'][item['attempt']]
        latest=max(index for index,value in enumerate(record['attempts']) if value['target_id']==target)
        require(item['attempt']==latest,'initialization_old_result')
        if item.get('observation') is None:
            require(item.get('terminal_outcome')=='cancelled-confirmed-stopped' and
                attempt.get('stop_proof',{}).get('resource_id')==item['resource_id'] and
                attempt['stop_proof'].get('pid')==0 and attempt['stop_proof'].get('status')=='exited')
            continue
        raw = run.file(attempt['capture']).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == attempt['sha256'] and attempt['target_id'] == target and
            attempt['resource_id'] == item['resource_id'] and decode(raw, run.id, attempt['scenario']) == item['observation'])
        require(attempt.get('terminal_marker_verified') is True or
            attempt['process_status'] in {'pass','fail'} and
            (item['observation']['status']!='failed')==(attempt['returncode']==0),'initialization_exit_inconsistent')
    return record
