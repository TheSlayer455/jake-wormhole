"""Full observed software inventory through the existing strict SSH helper.

Caller holds the Run lock and canonical lease. This component installs nothing,
never changes cleanup ownership, and does not infer a complete pipeline result.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import time

from validation import runtime
from scripts import qualify_images as qualification
from . import candidate as c, images, provisioning as p, rpm_candidate as rc, validation as v
from .runs import RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, now, read_json, source_identity

SCENARIOS=('healthy','missing-package','wrong-version','collector-unavailable','wrong-identity')
BASE_CHECKS=('target-identity','userland','package-inventory','payload-version','payload-sha256',
             'candidate-manifest-sha256','candidate-content-sha256','candidate-source-sha256')
TIMEOUT=60
LOG='private/qualification-helper-software-inventory-0.log'
PLAN='evidence/software-inventory-plan.json'
RECORD='evidence/software-inventory.json'
CONTROLLER='evidence/software-inventory-controller.json'
TRANSPORT='evidence/software-inventory-transport.json'
JSON_EXPORT='evidence/svd.json'
TEXT_EXPORT='evidence/svd.txt'
EVIDENCE=[PLAN,RECORD]
SHA=re.compile(r'[a-f0-9]{64}\Z')
ID=re.compile(r'[a-f0-9]{64}\Z')


class InventoryError(RunError):
    pass


def require(value,code='svd_invalid'):
    if not value:raise InventoryError(code,'Software inventory refused; preserve original private observations and exact ownership.')


def records_module():
    from . import observed_svd
    return observed_svd


def fixed_provenance(run,plan,controller):
    from .readiness import HELPER_IMAGE
    fields=set(common(run.manifest()))|{'operation','target','helper_id','helper_image','provisioner_id','provisioner'}
    require(type(controller) is dict and set(controller)==fields and c.bound_common(controller,run.manifest()) and
        controller['operation']=='software-inventory-controller-v1' and controller['target']==plan['target'] and
        type(controller['helper_id']) is str and ID.fullmatch(controller['helper_id']) and
        type(controller['provisioner_id']) is str and ID.fullmatch(controller['provisioner_id']) and
        controller['helper_image']==HELPER_IMAGE and c.canonical(controller['provisioner'])==c.canonical({
            'image_digest':p.TARGET_IMAGE,'terraform_version':'1.17.0','provider_version':'4.6.0'}),'svd_provenance_invalid')
    ready=read_json(run.file('private/readiness-controller.json'))
    terraform=read_json(run.file('private/terraform/controller.json'))
    tools=read_json(run.file('evidence/provisioning.json')).get('actual_tools')
    require(c.bound_common(ready,run.manifest()) and ready.get('operation')=='readiness-helper' and
        ready.get('helper_id')==controller['helper_id'] and ready.get('helper_image')==HELPER_IMAGE and
        ready.get('target_resource_id')==plan['target']['resource_id'] and ready.get('network_id')==plan['network_id'] and
        ready.get('source_sha256')==plan['collector']['readiness_source_sha256'] and ready.get('validation_enabled') is True and
        ready.get('validation_source_sha256')==plan['collector']['helper_source_sha256'] and
        all(type(terraform.get(key)) is str and terraform.get(key)==expected for key,expected in (
            ('schema_version','1.0'),('run_id',run.id),('source_revision',run.manifest()['source_revision']),('id',controller['provisioner_id']))) and
        c.canonical(terraform.get('target_binding'))==c.canonical(validate_binding(run)),'svd_provenance_invalid')
    validate_tools(tools)


def validate_tools(tools):
    require(c.canonical(tools)==c.canonical({'terraform_version':'1.17.0','platform':'linux_amd64','provider_version':'4.6.0',
        'offline_readonly_lock_h1_confirmed':p.H1,'provider_schema_observed':True}),'svd_provenance_invalid')


def platform_for(binding):
    operation=binding.get('operation') if type(binding) is dict else None
    require(operation in {'candidate-image-binding','ubi9-candidate-image-binding'},'svd_binding_invalid')
    return 'ubi' if operation=='ubi9-candidate-image-binding' else 'ubuntu'


def package_expectations(platform,scenario):
    require(platform in {'ubuntu','ubi'} and scenario in SCENARIOS,'svd_scenario_invalid')
    require(scenario not in {'missing-package','wrong-version'} or platform=='ubi','svd_scenario_invalid')
    if platform=='ubuntu':
        lock=images.load_lock()['apt']['packages'];versions={**lock['common'],**lock['target']}
        return {name:{'name':name,'version':version,'architecture':'all' if name=='ca-certificates' else 'amd64'} for name,version in sorted(versions.items())}
    values={name:{'name':name,**deepcopy(version)} for name,version in sorted(rc.PACKAGE_VERSIONS.items())}
    if scenario=='wrong-version':values['openssh-server']['version']+='-controlled-mismatch'
    if scenario=='missing-package':values['openssh-clients']={'name':'openssh-clients',**rc.PACKAGE_VERSIONS['openssh']}
    return dict(sorted(values.items()))


def check_ids(platform,scenario='healthy'):
    return list(BASE_CHECKS)+['package-'+name.replace('.','-') for name in package_expectations(platform,scenario)]


def validate_binding(run,binding=None):
    receipt=read_json(run.file('evidence/provisioning.json'))
    require(c.bound_common(receipt,run.manifest()) and type(receipt.get('target_binding')) is dict,'svd_binding_invalid')
    saved=receipt['target_binding'];policy,_=p.target_binding_policy(saved)
    saved=policy.validate_binding(run,saved)
    require(receipt.get('target_image')==saved['image_id'] and (binding is None or c.canonical(binding)==c.canonical(saved)),'svd_binding_invalid')
    return saved


def target_identity(binding,identifier):
    manifest=binding['manifest']
    return {'target_id':'target-001','resource_id':identifier,'image_digest':binding['image_id'],
        'candidate_sha256':binding['candidate_sha256'],
        'source_candidate_sha256':binding.get('source_candidate_sha256',binding['candidate_sha256']),
        'content_sha256':binding.get('content_sha256',rc.content_identity(manifest))}


def expected_values(binding,identifier,scenario):
    platform=platform_for(binding);manifest=binding['manifest']
    values={'target-identity':'0'*64 if scenario=='wrong-identity' else identifier,
        'userland':v.canonical({'id':'rhel' if platform=='ubi' else 'ubuntu','version_id':'9.8' if platform=='ubi' else '24.04'}),
        'package-inventory':'complete installed native package database','payload-version':manifest['version'],
        'payload-sha256':next(row['sha256'] for row in manifest['files'] if row['path']=='payload.py'),
        'candidate-manifest-sha256':binding['candidate_sha256'],
        'candidate-content-sha256':binding.get('content_sha256',rc.content_identity(manifest)),
        'candidate-source-sha256':manifest['source_sha256']}
    for name,row in package_expectations(platform,scenario).items():values['package-'+name.replace('.','-')]=v.canonical(row)
    return values


def make_plan(run,binding,identifier,network,scenario):
    require(type(identifier) is str and ID.fullmatch(identifier) and identifier!='0'*64 and type(network) is str and ID.fullmatch(network),'svd_target_identity_mismatch')
    platform=platform_for(binding);values=expected_values(binding,identifier,scenario)
    value={**common(run.manifest()),'operation':'software-inventory-plan-v1','scenario':scenario,'platform':platform,
        'target':target_identity(binding,identifier),'network_id':network,
        'collector':{'version':runtime.SVD_VERSION,'sha256':c.sha(runtime.SVD_PROGRAM.encode()),'helper_source_sha256':v.runtime_hash(),
            'readiness_source_sha256':c.sha((SOURCE_ROOT/'readiness/runtime.py').read_bytes())},
        'checks':[{'check_id':key,'target_id':'target-001','required':True,'expected':values[key]} for key in check_ids(platform,scenario)],
        'runtime_pipeline_complete':False,'production_iso_eligible':False}
    return {**value,'plan_sha256':v.digest(value)}


def validate_plan(run,plan):
    binding=validate_binding(run);receipt=read_json(run.file('evidence/provisioning.json'))
    resources=receipt.get('resources');require(type(resources) is list,'svd_plan_changed')
    owned={row['address']:row['id'] for row in resources}
    require(len(owned)==len(resources) and set(owned)=={'docker_network.run','docker_container.target["target-001"]'},'svd_plan_changed')
    rebuilt=make_plan(run,binding,owned['docker_container.target["target-001"]'],owned['docker_network.run'],plan.get('scenario'))
    require(c.canonical(plan)==c.canonical(rebuilt),'svd_plan_changed')
    if plan['scenario']=='missing-package':
        build=read_json(run.file('evidence/rpm-candidate-build.json'))
        require(not any(row['name']=='openssh-clients' for row in build['installed']['installed_packages']),'svd_missing_fixture_unavailable')
    return binding


def rows(plan,observed=None,target=None):
    values={}
    if target is not None:values['target-identity']=target['resource_id']
    if observed is not None:
        records_module().validate_observation(observed)
        payload=observed['payload']
        values.update({'userland':v.canonical({key:observed['os'][key] for key in ('id','version_id')}),
            'package-inventory':'complete installed native package database','payload-version':payload['version'],'payload-sha256':payload['sha256'],
            'candidate-manifest-sha256':payload['manifest_sha256'],'candidate-content-sha256':payload['content_sha256'],
            'candidate-source-sha256':payload['source_sha256']})
        for name,expected in package_expectations(plan['platform'],plan['scenario']).items():
            found=[row for row in observed['packages'] if row['name']==name]
            values['package-'+name.replace('.','-')]=v.canonical(found[0] if len(found)==1 else {'status':'missing','name':name} if not found else {'status':'multiple','packages':found})
    return [{**item,'observed':values.get(item['check_id'],'not-observed'),'status':'unverified' if item['check_id'] not in values else
        'pass' if values[item['check_id']]==item['expected'] else 'fail','evidence':list(EVIDENCE)} for item in plan['checks']]


def parse_response(raw,plan,budget):
    try:
        require(type(raw) is bytes and 1<=len(raw)<=65536,'svd_capture_invalid')
        value=json.loads(raw,object_pairs_hook=runtime.unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        fields={'schema_version','run_id','source_revision','target_id','plan_sha256','status','category','returncode','timed_out','truncated',
            'duration_seconds','collector_base64','helper_provenance','private_diagnostic'}
        require(type(value) is dict and set(value)==fields and all(type(value[key]) is str and value[key]==expected for key,expected in
            (('schema_version',plan['schema_version']),('run_id',plan['run_id']),('source_revision',plan['source_revision']),('target_id','target-001'),('plan_sha256',plan['plan_sha256']))) and
            value['status'] in {'pass','error'} and type(value['returncode']) is int and -(2**31)<=value['returncode']<2**31 and
            type(value['timed_out']) is bool and type(value['truncated']) is bool and type(value['duration_seconds']) in (int,float) and
            math.isfinite(value['duration_seconds']) and 0<=value['duration_seconds']<=budget and
            type(value['private_diagnostic']) is str and len(value['private_diagnostic'].encode())<=2048,'svd_capture_invalid')
        helper=value['helper_provenance']
        require(type(helper) is dict and set(helper)=={'python_version','ansible_core_version'} and
            helper['ansible_core_version']=='2.21.5' and type(helper['python_version']) is str and re.fullmatch(r'3\.12\.[0-9]{1,3}',helper['python_version']),'svd_capture_invalid')
        allowed={'ansible_result_invalid','validation_timeout','output_bound','ansible_unreachable','unexpected_skip','configured_interpreter_unavailable','svd_collector_failed'}
        require((value['status']=='pass')==(value['returncode']==0 and value['category'] is None and value['timed_out'] is False and value['truncated'] is False and value['collector_base64'] is not None) and
            (value['category'] is None if value['status']=='pass' else value['category'] in allowed) and
            (value['status']=='pass' or value['collector_base64'] is None),'svd_capture_invalid')
        observed=None;packet=None
        if value['collector_base64'] is not None:
            require(type(value['collector_base64']) is str and 1<=len(value['collector_base64'])<=runtime.SVD_PACKET_LIMIT,'svd_capture_invalid')
            packet=base64.b64decode(value['collector_base64'],validate=True);require(1<=len(packet)<=runtime.SVD_RAW_LIMIT,'svd_capture_invalid')
            observed=json.loads(packet,object_pairs_hook=runtime.unique)
            require(c.canonical(observed)==packet,'svd_capture_invalid');records_module().validate_observation(observed)
        return value,observed,packet
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        raise InventoryError('svd_capture_invalid','A complete original bound inventory response is required.') from None


def read_capture(run,path,maximum):
    actual=run.file(path);_owned(actual);require(actual.stat().st_size<=maximum,'svd_capture_invalid')
    with actual.open('rb') as stream:raw=stream.read(maximum+1)
    require(len(raw)<=maximum,'svd_capture_invalid');return raw


def reconstruct_record(run,record):
    plan=read_json(run.file(PLAN));validate_plan(run,plan)
    pure=records_module();record=pure.validate_record(record)
    require(c.bound_common(record,run.manifest()) and record['collector']==plan['collector'] and record['plan_sha256']==plan['plan_sha256'],'svd_record_changed')
    controller=read_json(run.file(CONTROLLER)) if run.file(CONTROLLER).exists() else None
    if record['target'] is not None:
        fixed_provenance(run,plan,controller)
        require(record['target']==controller['target'],'svd_record_changed')
    observed=None;response=None
    capture=record['capture']
    transport=read_json(run.file(TRANSPORT))
    require(set(transport)==set(common(run.manifest()))|{'operation','attempts'} and
        c.bound_common(transport,run.manifest()) and transport['operation']=='software-inventory-transport-v1' and
        type(transport['attempts']) is list and len(transport['attempts'])<2,'svd_capture_invalid')
    if capture is not None:
        require(len(transport['attempts'])==1 and capture['path']==LOG,'svd_capture_invalid')
        attempt=transport['attempts'][0]
        require(set(attempt)=={'role','stage','status','returncode','duration_seconds','log_truncated','private_log'} and
            attempt['role']=='helper' and attempt['stage']=='software-inventory' and attempt['private_log']==LOG and
            attempt['status'] in {'pass','fail','error','timeout','unsupported'} and (attempt['returncode'] is None or type(attempt['returncode']) is int) and
            type(attempt['duration_seconds']) in (int,float) and math.isfinite(attempt['duration_seconds']) and 0<=attempt['duration_seconds']<=TIMEOUT and
            type(attempt['log_truncated']) is bool,'svd_capture_invalid')
        raw=read_capture(run,LOG,65536)
        require(len(raw)==capture['size_bytes'] and c.sha(raw)==capture['sha256'],'svd_capture_invalid')
        if capture['complete']:
            require(attempt['status']=='pass' and attempt['returncode']==0 and attempt['log_truncated'] is False,'svd_capture_invalid')
            response,observed,packet=parse_response(raw,plan,capture['budget_seconds'])
            require(capture['collector_sha256']==(c.sha(packet) if packet is not None else None) and capture['collector_bytes']==(len(packet) if packet is not None else 0),'svd_capture_invalid')
        else:require(record['status']=='failed' and record['observation'] is None and capture['collector_sha256'] is None and capture['collector_bytes']==0,'svd_capture_invalid')
    else:require(not transport['attempts'],'svd_capture_invalid')
    require(c.canonical(record['observation'])==c.canonical(observed) and c.canonical(record['checks'])==c.canonical(rows(plan,observed,record['target'])),'svd_record_changed')
    if response is not None:
        require(controller is not None and record['execution_provenance']=={
            'helper':{'image_digest':controller['helper_image'],**response['helper_provenance']},'provisioner':controller['provisioner']},'svd_record_changed')
    else:require(record['execution_provenance'] is None,'svd_record_changed')
    if plan['scenario']=='wrong-identity':require(record['status']=='failed' and record['primary_failure']['code']=='svd_target_identity_mismatch' and capture is None,'svd_record_changed')
    if response is not None and response['status']!='pass':require(record['status']=='failed' and record['primary_failure']['code']==response['category'],'svd_record_changed')
    return pure.validate_record(record)


def report_software_inventory(run):
    pure=records_module();record=reconstruct_record(run,read_json(run.file(RECORD)));text=pure.render_text(record)
    require(read_capture(run,JSON_EXPORT,524288)==pure.render_json(record) and read_capture(run,TEXT_EXPORT,524288)==text.encode(),'svd_export_changed')
    return {'record':record,'text':text}


class SoftwareInventorySession:
    def __init__(self,readiness,binding,scenario='healthy'):
        require(type(scenario) is str and scenario in SCENARIOS,'svd_scenario_invalid')
        self.readiness,self.run,self.lease=readiness,readiness.run,readiness.lease
        readiness.held();require(readiness.scenario=='healthy' and readiness.validation_enabled is True and not self.lease._reconciliation_only,'svd_scope')
        require(source_identity()==(self.run.manifest()['source_revision'],False) and readiness.validation_source_sha256==v.runtime_hash(),'svd_source_changed')
        require(not any(self.run.file(path).exists() for path in (PLAN,RECORD,JSON_EXPORT,TEXT_EXPORT,TRANSPORT,CONTROLLER)),'svd_attempt_reused')
        self.binding=validate_binding(self.run,binding);self.scenario=scenario
        self.plan=make_plan(self.run,self.binding,readiness.target,readiness.network,scenario);validate_plan(self.run,self.plan)
        atomic_json(self.run.file(PLAN),self.plan)
        self.transport={**common(self.run.manifest()),'operation':'software-inventory-transport-v1','attempts':[]}
        self.receipt={**common(self.run.manifest()),'operation':'observed-software-description-v1','status':'pending','plan_sha256':self.plan['plan_sha256'],
            'collector':deepcopy(self.plan['collector']),'target':None,'observation':None,'execution_provenance':None,
            'checks':rows(self.plan),'capture':None,'primary_failure':None,'unknown_outcome':False,'updated_at':now(),
            'runtime_pipeline_complete':False,'production_iso_eligible':False}
        self.started=False;self.save()

    def save(self):
        self.receipt['updated_at']=now();atomic_json(self.run.file(RECORD),self.receipt);atomic_json(self.run.file(TRANSPORT),self.transport)

    def export(self):
        pure=records_module();record=reconstruct_record(self.run,self.receipt)
        atomic_bytes(self.run.file(JSON_EXPORT),pure.render_json(record),limit=524288)
        atomic_bytes(self.run.file(TEXT_EXPORT),pure.render_text(record).encode(),limit=524288)

    def remaining(self,deadline,maximum=20):
        left=deadline-time.monotonic();require(left>.1,'svd_timeout');return min(left,maximum)

    def failure(self,error):
        code=getattr(error,'code','svd_failed');code=code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}',code) else 'svd_failed'
        self.readiness.held();ps=self.readiness.provisioning
        require(ps.run.id==self.run.id and ps.run.path==self.run.path and ps.lease is self.lease,'svd_scope');ps.held()
        ps.failure(InventoryError(code,'Software inventory failed.'))
        if self.receipt['primary_failure'] is None:self.receipt['primary_failure']={'code':code,'recorded_at':now()}
        self.receipt['status']='failed';self.save()

    def collect(self):
        require(not self.started,'svd_attempt_reused');self.started=True;deadline=time.monotonic()+TIMEOUT
        try:
            self.readiness.held();validate_plan(self.run,self.plan)
            require(c.canonical(read_json(self.run.file(PLAN)))==c.canonical(self.plan),'svd_plan_changed')
            self.readiness.require_ready(inspection_timeout=self.remaining(deadline))
            ps=self.readiness.provisioning;ps.held()
            actual=images.inspect('container',self.readiness.target,timeout=self.remaining(deadline));ps.verify_target(actual,inspection_timeout=self.remaining(deadline))
            helper=images.inspect('container',self.readiness.helper,timeout=self.remaining(deadline));self.readiness.verify_helper(helper)
            controller=images.inspect('container',ps.provisioner,timeout=self.remaining(deadline));ps.verify_provisioner(controller)
            tools=ps.receipt['actual_tools']
            from .readiness import HELPER_IMAGE
            validate_tools(tools)
            require(helper.get('Image')==HELPER_IMAGE and controller.get('Image')==p.TARGET_IMAGE,'svd_provenance_invalid')
            self.receipt['target']={**self.plan['target'],'resource_id':actual['Id'],'image_digest':actual['Image']}
            metadata={**common(self.run.manifest()),'operation':'software-inventory-controller-v1','target':deepcopy(self.receipt['target']),
                'helper_id':self.readiness.helper,'provisioner_id':ps.provisioner,
                'helper_image':helper['Image'],'provisioner':{'image_digest':controller['Image'],'terraform_version':tools['terraform_version'],'provider_version':tools['provider_version']}}
            fixed_provenance(self.run,self.plan,metadata)
            atomic_json(self.run.file(CONTROLLER),metadata);self.receipt['checks']=rows(self.plan,target=self.receipt['target']);self.save()
            require(self.receipt['checks'][0]['status']=='pass','svd_target_identity_mismatch')
            inventory=ps.target_inventory('target-001')
            require(inventory is not None and inventory['resource_id']==actual['Id'] and inventory['image_digest']==actual['Image'] and inventory['host']==self.readiness.trust_address,'svd_target_identity_mismatch')
            for stamp,lifetime in ((helper['State']['StartedAt'],180),(actual['State']['StartedAt'],300)):
                began=datetime.fromisoformat(stamp.replace('Z','+00:00'));elapsed=(datetime.now(timezone.utc)-began).total_seconds()
                require(began.tzinfo is not None and 0<=elapsed and lifetime-elapsed>=TIMEOUT+20,'svd_lifetime_budget')
            budget=self.remaining(deadline,35)
            request={key:self.plan[key] for key in ('schema_version','run_id','source_revision','plan_sha256')}
            request.update(operation='software-inventory-v1',target_id='target-001',address=inventory['host'],
                scenario='collector-unavailable' if self.scenario=='collector-unavailable' else 'healthy',
                readiness_source_sha256=self.plan['collector']['readiness_source_sha256'],timeout_seconds=budget-2)
            runtime.decode_software_inventory(c.canonical(request));encoded=base64.b64encode(c.canonical(request)).decode()
            result=v._run_process(('docker','--config',images.docker_configuration(),'--host',images.SOCKET,'exec','--user','10001:10001',self.readiness.helper,
                '/opt/wormhole/venv/bin/python','-I','-B',v.VALIDATION_MOUNT,encoded),cwd=SOURCE_ROOT,timeout=budget)
            if result['status']!='pass' or result['log_truncated']:
                self.receipt['unknown_outcome']=True;self.readiness.receipt['unknown_outcome']=True;self.readiness.save()
            qualification.attempt_record(self.run,self.transport,'helper','software-inventory',result)
            require(len(self.transport['attempts'])==1 and not self.transport['attempts'][0].get('diagnostic_write_failed'),'svd_diagnostic_unavailable')
            raw=result['log'];require(type(raw) is bytes and len(raw)<=65536,'svd_capture_invalid')
            self.receipt['capture']={'path':LOG,'sha256':c.sha(raw),'size_bytes':len(raw),'budget_seconds':budget,'complete':False,'collector_sha256':None,'collector_bytes':0};self.save()
            require(result['status']=='pass' and result['returncode']==0 and result['log_truncated'] is False,'svd_probe_incomplete')
            self.remaining(deadline);response,observed,packet=parse_response(raw,self.plan,budget)
            self.receipt['capture'].update(complete=True,collector_sha256=c.sha(packet) if packet is not None else None,collector_bytes=len(packet) if packet is not None else 0)
            self.receipt['observation']=observed
            self.receipt['execution_provenance']={'helper':{'image_digest':helper['Image'],**response['helper_provenance']},'provisioner':metadata['provisioner']}
            self.receipt['checks']=rows(self.plan,observed,self.receipt['target']);self.save();self.remaining(deadline)
            require(response['status']=='pass',response['category'] or 'svd_collector_failed')
            failed=[row for row in self.receipt['checks'] if row['status']!='pass']
            missing=any(row['check_id'].startswith('package-') and '"status":"missing"' in row['observed'] for row in failed)
            code='svd_missing_package' if missing else 'svd_version_mismatch' if any(row['check_id'].startswith('package-') and row['check_id']!='package-inventory' for row in failed) else 'svd_required_check_mismatch'
            require(not failed,code);self.receipt['status']='passed';self.save();self.export();self.remaining(deadline);self.require_passed();self.remaining(deadline)
            return deepcopy(self.receipt)
        except BaseException as error:
            if self.receipt['primary_failure'] is None:self.failure(error)
            try:self.export()
            except Exception as secondary:
                atomic_json(self.run.file('evidence/software-inventory-export-error.json'),{**common(self.run.manifest()),
                    'operation':'software-inventory-export-error-v1','primary_code':self.receipt['primary_failure']['code'],
                    'secondary_code':getattr(secondary,'code','svd_export_failed'),'runtime_pipeline_complete':False,'production_iso_eligible':False})
            raise

    def require_passed(self):
        require(report_software_inventory(self.run)['record']['status']=='passed','svd_required');return True
