"""Fixed UBI/RPM and identical candidate-byte checks over strict SSH/Ansible."""
import base64
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
import json
import math
import re
import time

from validation import runtime
from scripts import qualify_images as qualification
from . import candidate as c, images, rpm_candidate as rc, rpm_target as t, validation as v
from .contracts import validate_artifact
from .runs import SOURCE_ROOT,_owned,atomic_json,common,now,read_json,source_identity

SCENARIOS=('healthy','missing-optional-package','version-expectation-mismatch','unsupported-os')
TIMEOUT=60
LOG='private/qualification-helper-rpm-validation-0.log'
EVIDENCE=['evidence/rpm-validation-plan.json','evidence/rpm-observations.json']


def check_ids(scenario):
    t.require(scenario in SCENARIOS,'rpm_scenario_invalid')
    return list(rc.CHECKS)+([rc.OPTIONAL] if scenario=='missing-optional-package' else [])


def expected_values(binding,scenario):
    t.require(scenario in SCENARIOS,'rpm_scenario_invalid');manifest=binding['manifest']
    values={'rpm-userland':v.canonical({'id':'ubuntu','version_id':'24.04'} if scenario=='unsupported-os' else
        {'id':manifest['applicability']['os_id'],'version_id':manifest['applicability']['os_version']}),
        'candidate-source-sha256':manifest['source_sha256'],'candidate-manifest-sha256':binding['candidate_sha256'],
        'candidate-content-sha256':binding['content_sha256'],
        'candidate-payload-sha256':next(item['sha256'] for item in manifest['files'] if item['path']=='payload.py'),
        'candidate-version':manifest['version'],'candidate-configuration':v.canonical(manifest['configuration']),
        'candidate-function':v.canonical({'status':'observed','value':{'version':manifest['version'],
            'message':manifest['configuration']['greeting'],'source_sha256':manifest['source_sha256']}})}
    for name in rc.PACKAGES:
        version=deepcopy(manifest['packages'][name])
        if scenario=='version-expectation-mismatch' and name=='openssh-server':version['version']+='-controlled-mismatch'
        values['rpm-'+name]=v.canonical({'status':'installed',**version})
    if scenario=='missing-optional-package':values[rc.OPTIONAL]=v.canonical({'status':'installed',**rc.PACKAGE_VERSIONS['openssh']})
    return values


def make_plan(run,binding,target,network,scenario):
    values=expected_values(binding,scenario)
    value={**common(run.manifest()),'operation':'ubi9-rpm-validation-plan','scenario':scenario,'target_id':'target-001',
        'target_resource_id':target,'network_id':network,'target_image':binding['image_id'],'candidate_sha256':binding['candidate_sha256'],
        'content_sha256':binding['content_sha256'],'source_candidate_sha256':binding['source_candidate_sha256'],
        'test_contract_sha256':binding['test_contract_sha256'],'execution_contract_sha256':c.sha(c.canonical(rc.test_contract())),
        'validation_source_sha256':v.runtime_hash(),
        'readiness_source_sha256':hashlib.sha256((SOURCE_ROOT/'readiness/runtime.py').read_bytes()).hexdigest(),
        'collector_sha256':c.sha(runtime.RPM_PROGRAM.encode()),
        'checks':[{'target_id':'target-001','check_id':key,'required':True,'expected':values[key]} for key in check_ids(scenario)],
        'userland':'Red Hat Universal Base Image9.8-derived container','kernel_scope':'shared host kernel, not installed userland software',
        'iso_processing':'none','runtime_pipeline_complete':False,'production_iso_eligible':False}
    return {**value,'plan_sha256':v.digest(value)}


def validate_plan(run,plan):
    binding=rc.validate_binding(run)
    t.require(type(plan) is dict and c.bound_common(plan,run.manifest()) and
        type(plan.get('target_resource_id')) is str and t.ID.fullmatch(plan['target_resource_id']) and
        type(plan.get('network_id')) is str and t.ID.fullmatch(plan['network_id']) and
        c.canonical(plan)==c.canonical(make_plan(run,binding,plan['target_resource_id'],plan['network_id'],plan.get('scenario'))),'rpm_plan_changed')
    provisioning=read_json(run.file('evidence/provisioning.json'));owned={row['address']:row['id'] for row in provisioning['resources']}
    t.require(c.bound_common(provisioning,run.manifest()) and provisioning.get('target_binding')==binding and
        provisioning.get('target_image')==binding['image_id'] and owned.get('docker_container.target["target-001"]')==plan['target_resource_id'] and
        owned.get('docker_network.run')==plan['network_id'],'rpm_plan_changed')
    if plan['scenario']=='missing-optional-package':
        build_run=run
        if 'reuse' in binding:
            from .candidate_cache import origin
            build_run,_=origin(run,binding['reuse'])
        build=read_json(build_run.file('evidence/rpm-candidate-build.json'))
        t.require(not any(row['name']=='openssh-clients' for row in build['installed']['installed_packages']),'rpm_missing_fixture_unavailable')
    return binding


def rows(plan,observed=None,*,status='unverified',category='not-attempted'):
    values={}
    if observed is not None:
        runtime.rpm_observation(observed)
        values={'rpm-userland':v.canonical(observed['os']),'candidate-source-sha256':observed['source_sha256'],
            'candidate-manifest-sha256':observed['candidate_sha256'],'candidate-content-sha256':observed['content_sha256'],
            'candidate-payload-sha256':observed['payload_sha256'],'candidate-version':observed['version'],
            'candidate-configuration':v.canonical(observed['configuration']),'candidate-function':v.canonical(observed['function'])}
        for name,package in observed['packages'].items():values['rpm-'+name]=v.canonical({'status':'missing'} if package is None else {'status':'installed',**package})
    result=[]
    for item in plan['checks']:
        outcome=status;actual=category
        if observed is not None:
            key=item['check_id'];actual=values[key]
            outcome='unverified' if (key.startswith('rpm-') and key!='rpm-userland' and values['rpm-userland']!=plan['checks'][0]['expected']) or (
                key=='candidate-function' and observed['function']['status']=='unverified') else 'pass' if actual==item['expected'] else 'fail'
        result.append({**item,'status':outcome,'observed':actual,'evidence':list(EVIDENCE)})
    return result


def parse_response(raw,plan,budget):
    try:
        t.require(type(raw) is bytes and 1<=len(raw)<=65536,'rpm_capture_invalid')
        value=json.loads(raw,object_pairs_hook=runtime.unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        fields={'schema_version','run_id','source_revision','target_id','plan_sha256','status','category','returncode','timed_out',
            'truncated','duration_seconds','observation','private_diagnostic'}
        t.require(type(value) is dict and set(value)==fields and all(type(value[key]) is str and value[key]==plan[key] for key in
            ('schema_version','run_id','source_revision','target_id','plan_sha256')) and value['status'] in {'pass','fail','error','unreachable','skipped'} and
            type(value['returncode']) is int and -(2**31)<=value['returncode']<2**31 and type(value['timed_out']) is bool and type(value['truncated']) is bool and
            type(value['duration_seconds']) in (int,float) and math.isfinite(value['duration_seconds']) and 0<=value['duration_seconds']<=budget and
            type(value['private_diagnostic']) is str and len(value['private_diagnostic'].encode())<=8192 and
            (value['category'] is None or value['category'] in v.CATEGORIES) and
            (value['status']=='pass')==(value['returncode']==0 and value['category'] is None and value['timed_out'] is False and
                value['truncated'] is False and value['observation'] is not None) and
            (value['observation'] is None or value['status']=='pass'),'rpm_capture_invalid')
        if value['observation'] is not None:runtime.rpm_observation(value['observation'])
        return value
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        raise t.RpmError('rpm_capture_invalid','A complete original bound RPM helper response is required.') from None


def report_rpm_validation(run):
    from .recovery import valid_failure,_timestamp
    plan,result=read_json(run.file('evidence/rpm-validation-plan.json')),read_json(run.file('evidence/rpm-validation.json'));validate_plan(run,plan)
    fields=set(common(run.manifest()))|{'operation','plan_sha256','status','checks','capture','attempts','primary_failure','unknown_outcome',
        'updated_at','runtime_pipeline_complete','production_iso_eligible'}
    t.require(type(result) is dict and set(result)==fields and c.bound_common(result,run.manifest()) and result['operation']=='ubi9-rpm-validation' and
        result['plan_sha256']==plan['plan_sha256'] and result['status'] in {'passed','failed'} and type(result['unknown_outcome']) is bool and
        result['runtime_pipeline_complete'] is False and result['production_iso_eligible'] is False and valid_failure(result['primary_failure']) and
        (result['status']=='failed')==(result['primary_failure'] is not None) and _timestamp(result['updated_at']) and
        type(result['attempts']) is list and len(result['attempts'])<=1,'rpm_result_invalid')
    for attempt in result['attempts']:
        t.require(type(attempt) is dict and set(attempt)=={'role','stage','status','returncode','duration_seconds','log_truncated','private_log'} and
            attempt['role']=='helper' and attempt['stage']=='rpm-validation' and attempt['status'] in {'pass','fail','error','timeout','unsupported'} and
            (attempt['returncode'] is None or type(attempt['returncode']) is int) and type(attempt['log_truncated']) is bool and
            type(attempt['duration_seconds']) in (int,float) and math.isfinite(attempt['duration_seconds']) and
            0<=attempt['duration_seconds']<=TIMEOUT+2 and attempt['private_log']==LOG,'rpm_result_invalid')
    observation=read_json(run.file('evidence/rpm-observations.json'))
    t.require(type(observation) is dict and set(observation)==set(common(run.manifest()))|{'operation','plan_sha256','response'} and
        c.bound_common(observation,run.manifest()) and observation['operation']=='ubi9-rpm-observations' and observation['plan_sha256']==plan['plan_sha256'],'rpm_result_invalid')
    response=observation['response'];capture=result['capture']
    if capture is None:t.require(response is None and not result['attempts'] and result['status']=='failed','rpm_capture_invalid')
    else:
        t.require(type(capture) is dict and set(capture)=={'path','sha256','size_bytes','budget_seconds','complete'} and capture['path']==LOG and
            type(capture['size_bytes']) is int and 0<=capture['size_bytes']<=65536 and type(capture['budget_seconds']) in (int,float) and
            .1<=capture['budget_seconds']<=35 and type(capture['complete']) is bool and len(result['attempts'])==1,'rpm_capture_invalid')
        _owned(run.file(LOG))
        with run.file(LOG).open('rb') as stream:raw=stream.read(65537)
        t.require((len(raw),c.sha(raw))==(capture['size_bytes'],capture['sha256']),'rpm_capture_invalid')
        if capture['complete']:t.require(c.canonical(response)==c.canonical(parse_response(raw,plan,capture['budget_seconds'])) and
            result['attempts'][0]['status']=='pass' and result['attempts'][0]['returncode']==0 and result['attempts'][0]['log_truncated'] is False,'rpm_capture_invalid')
        else:t.require(response is None and result['status']=='failed','rpm_capture_invalid')
    actual=None if response is None else response['observation']
    expected_rows=rows(plan,actual,status='error' if response is None else response['status'],
        category=result['primary_failure']['code'] if response is None else response['category'] or 'observed')
    t.require(c.canonical(result['checks'])==c.canonical(expected_rows) and (result['status']=='passed')==
        (actual is not None and all(row['status']=='pass' for row in expected_rows) and not result['unknown_outcome'] and result['primary_failure'] is None),'rpm_result_invalid')
    validate_artifact('test-results',{**common(run.manifest()),'status':'pass' if result['status']=='passed' else 'fail','checks':result['checks']})
    lines=[f"Run {run.id}: UBI9-derived container validation {result['status']}",'Shared host kernel is not installed userland software. No VM/ISO/boot/STIG/scanner acceptance.']
    lines += [f"{row['check_id']}: {row['status']} expected={row['expected']} observed={row['observed']}" for row in result['checks']]
    return {'plan':plan,'result':result,'text':'\n'.join(lines)+'\n'}


class RPMValidationSession:
    def __init__(self,readiness,binding,*,scenario='healthy'):
        self.readiness,self.run,self.lease=readiness,readiness.run,readiness.lease;readiness.held();provisioning=readiness.provisioning
        self.binding=rc.validate_binding(self.run,binding)
        t.require(source_identity()==(self.run.manifest()['source_revision'],False) and self.run.manifest()['profile']=='smoke' and
            readiness.scenario=='healthy' and readiness.validation_enabled is True and not self.lease._reconciliation_only and
            provisioning.target_binding==self.binding and provisioning.target_image_id==self.binding['image_id'] and
            readiness.validation_source_sha256==v.runtime_hash(),'rpm_validation_scope')
        t.require(not self.run.file('evidence/rpm-validation-plan.json').exists(),'rpm_validation_reused')
        self.plan=make_plan(self.run,self.binding,readiness.target,readiness.network,scenario);validate_plan(self.run,self.plan)
        atomic_json(self.run.file('evidence/rpm-validation-plan.json'),self.plan)
        self.receipt={**common(self.run.manifest()),'operation':'ubi9-rpm-validation','plan_sha256':self.plan['plan_sha256'],'status':'pending',
            'checks':rows(self.plan),'capture':None,'attempts':[],'primary_failure':None,'unknown_outcome':False,
            'runtime_pipeline_complete':False,'production_iso_eligible':False}
        self.response,self.started=None,False;self.save()

    def save(self):
        self.receipt['updated_at']=now();atomic_json(self.run.file('evidence/rpm-observations.json'),{**common(self.run.manifest()),
            'operation':'ubi9-rpm-observations','plan_sha256':self.plan['plan_sha256'],'response':self.response})
        atomic_json(self.run.file('evidence/rpm-validation.json'),self.receipt)

    def failure(self,error):
        code=getattr(error,'code','rpm_validation_failed')
        if type(code) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,79}',code):code='rpm_validation_failed'
        provisioning=self.readiness.provisioning;t.require(provisioning.run.id==self.run.id and provisioning.lease is self.lease,'rpm_validation_scope')
        provisioning.held();provisioning.failure(t.RpmError(code,'UBI/RPM validation failed.'))
        if self.receipt['primary_failure'] is None:self.receipt['primary_failure']={'code':code,'recorded_at':now()}
        self.receipt['status']='failed'
        if self.response is None:self.receipt['checks']=rows(self.plan,status='error',category=code)
        self.save()

    remaining=v.ValidationSession.remaining

    def validate(self):
        t.require(not self.started,'rpm_validation_reused');self.started=True;deadline=time.monotonic()+TIMEOUT
        try:
            self.readiness.held();validate_plan(self.run,self.plan)
            t.require(c.canonical(read_json(self.run.file('evidence/rpm-validation-plan.json')))==c.canonical(self.plan),'rpm_plan_changed')
            self.readiness.require_ready(inspection_timeout=self.remaining(deadline));helper=images.inspect('container',self.readiness.helper,timeout=self.remaining(deadline))
            self.readiness.verify_helper(helper)
            for stamp,lifetime in ((helper['State']['StartedAt'],180),(self.readiness.last_started_at,300)):
                began=datetime.fromisoformat(stamp.replace('Z','+00:00'));elapsed=(datetime.now(timezone.utc)-began).total_seconds()
                t.require(began.tzinfo is not None and 0<=elapsed and lifetime-elapsed>=TIMEOUT+20,'rpm_lifetime_budget')
            inventory=self.readiness.provisioning.target_inventory('target-001')
            t.require(inventory is not None and inventory['resource_id']==self.plan['target_resource_id'] and inventory['image_digest']==self.binding['image_id'] and
                inventory['host']==self.readiness.trust_address,'rpm_endpoint_mismatch')
            budget=self.remaining(deadline,35);request={key:self.plan[key] for key in ('schema_version','run_id','source_revision','target_id','plan_sha256','readiness_source_sha256')}
            request.update(operation='rpm-functional-v1',address=inventory['host'],scenario='healthy',expected_payload_sha256=
                next(item['sha256'] for item in self.binding['manifest']['files'] if item['path']=='payload.py'),timeout_seconds=budget-2)
            runtime.decode(c.canonical(request));encoded=base64.b64encode(c.canonical(request)).decode()
            result=v._run_process(('docker','--config',images.docker_configuration(),'--host',images.SOCKET,'exec','--user','10001:10001',
                self.readiness.helper,'/opt/wormhole/venv/bin/python','-I','-B',v.VALIDATION_MOUNT,encoded),cwd=SOURCE_ROOT,timeout=budget)
            if result['status']!='pass' or result['log_truncated']:
                self.receipt['unknown_outcome']=True;self.readiness.receipt['unknown_outcome']=True;self.readiness.save()
            qualification.attempt_record(self.run,self.receipt,'helper','rpm-validation',result)
            t.require(len(self.receipt['attempts'])==1 and not self.receipt['attempts'][0].get('diagnostic_write_failed'),'rpm_diagnostic_unavailable')
            raw=result['log'];t.require(type(raw) is bytes and len(raw)<=65536,'rpm_capture_invalid')
            self.receipt['capture']={'path':LOG,'sha256':c.sha(raw),'size_bytes':len(raw),'budget_seconds':budget,'complete':False};self.save()
            t.require(result['status']=='pass' and result['log_truncated'] is False,'rpm_probe_incomplete')
            self.remaining(deadline);self.response=parse_response(raw,self.plan,budget);self.receipt['capture']['complete']=True
            self.receipt['checks']=rows(self.plan,self.response['observation'],status=self.response['status'],category=self.response['category'] or 'observed')
            self.remaining(deadline)
            t.require(self.response['status']=='pass' and self.response['observation'] is not None,self.response['category'] or 'rpm_observation_missing')
            failed={row['check_id'] for row in self.receipt['checks'] if row['status']!='pass'}
            code='rpm_applicability_mismatch' if 'rpm-userland' in failed else 'rpm_missing_package' if rc.OPTIONAL in failed else \
                'rpm_version_mismatch' if any(key in failed for key in ('rpm-'+name for name in rc.PACKAGES)) else 'rpm_required_check_mismatch'
            t.require(not failed,code);self.receipt['status']='passed';self.save();self.require_passed();self.remaining(deadline)
            return deepcopy(self.receipt)
        except BaseException as error:
            if self.receipt['primary_failure'] is None:self.failure(error)
            raise

    def require_passed(self):
        t.require(report_rpm_validation(self.run)['result']['status']=='passed','rpm_validation_required');return True
