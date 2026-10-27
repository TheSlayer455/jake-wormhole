"""Offline original-observation replay for the bounded reference pipeline.

These functions open retained private files; they never contact Docker, execute
Terraform, establish trust again, or turn an absent observation into success.
"""
import base64
from copy import deepcopy
from fractions import Fraction
import json
import math
import re
from datetime import datetime,timedelta
from types import SimpleNamespace

from scripts import qualify_images as qualification
from . import candidate as c, images, provisioning as p, readiness as r
from .admission import _journal,replay_plan
from .runs import RunError, SOURCE_ROOT, _owned, common, read_json, source_identity
from .targets import TargetPlan

RUNTIME='private/pipeline-runtime.json'


class ReplayError(RunError):pass


def require(value,code='pipeline_evidence_invalid'):
    if not value:raise ReplayError(code,'Original reference-pipeline evidence did not replay; preserve private inputs.')


def raw_file(run,relative,maximum=65536):
    path=run.file(relative);_owned(path);require(path.stat().st_size<=maximum,'pipeline_capture_bound')
    with path.open('rb') as stream:raw=stream.read(maximum+1)
    require(len(raw)<=maximum,'pipeline_capture_bound');return raw


def same(left,right):return c.canonical(left)==c.canonical(right)


def source(run):
    value=run.manifest()
    require(value['mode']=='container-reference' and value['profile']=='smoke' and value['source_dirty'] is False and
        source_identity()==(value['source_revision'],False),'pipeline_source_changed')
    return value


def admission_archive(run):
    value=_journal(read_json(images.INFRASTRUCTURE/'history'/(run.id+'.json')))
    require(value['run_id']==run.id and value['source_revision']==run.manifest()['source_revision'] and
        value['state']=='finished' and value['phase']=='reconciling' and value['plan']['profile']=='smoke' and
        value['plan']['synthetic'] is False and value['plan']['target_count']==1 and
        all(item['outcome'] in {'absent','retained'} for item in value['resources']),'pipeline_admission_unfinished')
    require(same(value['plan'],replay_plan('smoke',value['plan']['observations'])),'pipeline_admission_changed')
    try:
        created=datetime.fromisoformat(value['created_at'].replace('Z','+00:00'))
        ended=datetime.fromisoformat(value['updated_at'].replace('Z','+00:00'))
        measured=datetime.fromisoformat(value['plan']['observations']['observed_at'].replace('Z','+00:00'))
        require(all(stamp.tzinfo is not None for stamp in (created,ended,measured)) and created<=ended and
            created-timedelta(seconds=2)<=measured<=ended+timedelta(seconds=2),'pipeline_admission_changed')
    except (TypeError,ValueError,AttributeError):raise ReplayError('pipeline_admission_changed','Historical admission time is malformed.') from None
    return value


def archive_bytes(run):
    path=images.INFRASTRUCTURE/'history'/(run.id+'.json');_owned(path)
    require(path.stat().st_size<=262144,'pipeline_admission_invalid')
    with path.open('rb') as stream:raw=stream.read(262145)
    require(len(raw)<=262144,'pipeline_admission_invalid');return raw


def check_cgroups(observed,limits):
    require(type(observed) is dict and set(observed)=={'memory.max','memory.swap.max','cpu.max','pids.max'} and
        all(type(value) is str for value in observed.values()),'pipeline_confinement_invalid')
    pair=observed['cpu.max'].split();require(len(pair)==2 and all(x.isdigit() for x in pair) and int(pair[1])>0,'pipeline_confinement_invalid')
    require(observed['memory.max']==str(limits['memory_bytes']) and observed['memory.swap.max']=='0' and
        observed['pids.max']==str(limits['pids_limit']) and Fraction(int(pair[0]),int(pair[1]))==Fraction(limits['nano_cpus'],10**9),'pipeline_confinement_invalid')


def report_candidate(run,platform):
    if platform=='ubuntu':
        binding=c.validate_binding(run);built=read_json(run.file('evidence/candidate-build.json'))
        require(built.get('primary_failure') is None,'pipeline_candidate_failure')
        return binding
    from . import rpm_candidate as rc,rpm_assembly as assembly,rpm_source as sources,rpm_target as rt,rpm_resolution as resolver
    binding=rc.validate_binding(run);built=read_json(run.file('evidence/rpm-candidate-build.json'))
    request=read_json(run.file('private/rpm-assembly-request.json'))
    require(c.bound_common(request,run.manifest()) and request['operation']=='ubi9-assembly-request-v1' and
        request['manifest']==binding['manifest'] and request['candidate_sha256']==binding['candidate_sha256'] and
        request['source_files']==binding['source_files'] and request['recipe_sha256']==binding['recipe_sha256'],'pipeline_candidate_changed')
    assembly.validate_installed(built['installed'],request,binding['source_files']);sources.validate_eula(run)
    resolve=read_json(run.file(resolver.EVIDENCE));raw=raw_file(run,'private/rpm-resolution.log')
    resolve_request=read_json(run.file('private/rpm-sources/resolve-request.json'))
    resolution=sources.validate_resolution(run,raw,resolve_request)
    require(c.bound_common(resolve,run.manifest()) and resolve['operation']=='ubi-offline-resolution' and resolve['status']=='passed' and
        resolve['unknown_outcome'] is False and resolve['primary_failure'] is None and resolve['cleanup']=='completed' and
        resolver.recipe_identity()==(resolve['recipe_sha256'],resolve['source_files']) and
        resolve['capture_bytes']==len(raw) and resolve['capture_sha256']==c.sha(raw) and same(resolve['resolution'],resolution) and
        same(request['resolution'],resolution),'pipeline_resolution_changed')
    reference=resolve_request['base_probe'];base_run=__import__('wormhole.runs',fromlist=['Run']).Run(run.workspace,reference['run_id'])
    observed=rt.read_base_observation(base_run)
    require(c.sha(c.canonical(observed))==resolve_request['base_observation_sha256'] and
        c.sha(c.canonical(sources.validate_observation(observed)))==resolve_request['base_packages_sha256'],'pipeline_resolution_changed')
    sources.validate_packages(run,None,resolution)
    return binding


def report_provisioning(run,archive,binding):
    """Replay saved plans, exact config observations, original outputs and destroy."""
    from .software_inventory import validate_tools
    from provisioning.runtime import OPERATIONS,JSON_OPERATIONS
    source(run);receipt=read_json(run.file('evidence/provisioning.json'));context=read_json(run.file('private/terraform/controller.json'))
    require(c.bound_common(receipt,run.manifest()) and receipt['operation']=='terraform-smoke' and
        receipt['scenario']=='healthy' and receipt['target_binding']==binding and receipt['target_image']==binding['image_id'] and
        receipt['unknown_outcome'] is False and receipt['runtime_pipeline_complete'] is False and receipt['production_iso_eligible'] is False,'pipeline_provisioning_invalid')
    validate_tools(receipt['actual_tools'])
    require(context['run_id']==run.id and context['source_revision']==run.manifest()['source_revision'] and
        context['schema_version']=='1.0' and context['target_binding']==binding and context['id']==receipt['provisioner_id'],'pipeline_provisioning_invalid')
    session=p.ProvisioningSession.__new__(p.ProvisioningSession)
    session.run,session.receipt,session.state=run,receipt,run.file('private/terraform')
    session.target_binding=binding;session.target_plan=TargetPlan.from_record(context['target_plan']);session.scenario='healthy'
    session.variables=p.bounded_json(session.state/'terraform.tfvars.json');session.inputs=context['inputs']
    session.owned={item['address']:item['id'] for item in receipt['resources']};session.provisioner=context['id']
    session.uid,session.gid,session.socket_groups=context['uid'],context['gid'],context['groups']
    session.mounts={key:tuple(item) for key,item in context['mounts'].items()};session.image_labels=context['image_labels']
    session.lease=SimpleNamespace(plan=archive['plan'])
    tools=p.verified_toolchain(run)
    require(session.mounts=={'/opt/toolchain':(str(tools['root']),False),'/opt/provisioning':(str(p.CONTEXT),False),
        '/state':(str(session.state),True),'/var/run/docker.sock':('/var/run/docker.sock',True)},'pipeline_input_changed')
    require(session.target_plan.profile=='smoke' and set(session.owned)==session.target_plan.expected_addresses and
        len(set(session.owned.values()))==2 and session.variables['image']==binding['image_id'] and
        same(context['target_runtime_policy'],session.target_runtime_policy.record()) and
        same(receipt['target_runtime_policy'],session.target_runtime_policy.record()) and
        session.variables['target_capabilities']==list(session.target_runtime_policy.capabilities),'pipeline_provisioning_invalid')
    session.check_inputs()
    fixed={'main.tf':p.scenario_source('healthy'),'.terraform.lock.hcl':(p.CONTEXT/'.terraform.lock.hcl').read_bytes(),
        'terraform.tfvars.json':json.dumps(session.variables,sort_keys=True).encode(),
        'wormhole.tfrc':b'disable_checkpoint = true\nprovider_installation {\n filesystem_mirror {\n path = "/opt/toolchain/mirror"\n include = ["registry.terraform.io/kreuzwerker/docker"]\n }\n}\n'}
    require(set(session.inputs)==set(fixed) and all(replay_bytes==raw_file(run,'private/terraform/'+name) and
        c.sha(replay_bytes)==session.inputs[name] for name,replay_bytes in fixed.items()),'pipeline_input_changed')
    expected_variables={'run_id':run.id,'source_revision':run.manifest()['source_revision'],'image':binding['image_id'],
        'public_input':str(run.file('private/target-input')),'target_ids':['target-001'],
        'target_limits':deepcopy(archive['plan']['limits']['target']['terraform']),
        'target_capabilities':list(session.target_runtime_policy.capabilities)}
    if 'mutable_home' in session.variables:expected_variables['mutable_home']=False
    expected_variables['target_limits'].pop('start');expected_variables['target_limits'].pop('must_run')
    require(same(session.variables,expected_variables),'pipeline_input_changed')
    captures={};expected_files=set();counters={}
    require(type(receipt['operations']) is list and 1<=len(receipt['operations'])<=64,'pipeline_provisioning_invalid')
    for item in receipt['operations']:
        name,attempt=item['operation'],item['attempt'];counters[name]=counters.get(name,0)+1
        require(name in OPERATIONS and name!='probe-unavailable' and type(attempt) is int and attempt==counters[name] and attempt<=4,'pipeline_operation_invalid')
        stem=name+'-'+str(attempt);expected_files|={stem+'.json',stem+'.out'}
        metadata=read_json(session.state/'operations'/(stem+'.json'))
        require(set(item)==set(metadata)|{'client_status','client_returncode','client_log_truncated','evidence'} and
            same(metadata,{key:item[key] for key in metadata}) and set(metadata)=={'operation','attempt','returncode','duration_seconds','output_bytes','output_sha256','truncated','timed_out','passed'} and
            metadata['passed'] is True and metadata['returncode']==0 and type(metadata['returncode']) is int and
            metadata['truncated'] is False and metadata['timed_out'] is False and item['client_status']=='pass' and
            item['client_returncode']==0 and type(item['client_returncode']) is int and item['client_log_truncated'] is False and
            type(metadata['duration_seconds']) in (int,float) and math.isfinite(metadata['duration_seconds']) and 0<=metadata['duration_seconds']<=135 and
            item['evidence']=='private/terraform/operations/'+stem+'.out','pipeline_operation_invalid')
        raw=raw_file(run,item['evidence'],p.MAX_OUTPUT)
        require(type(metadata['output_bytes']) is int and len(raw)==metadata['output_bytes'] and c.sha(raw)==metadata['output_sha256'],'pipeline_operation_changed')
        if name in JSON_OPERATIONS:captures.setdefault(name,[]).append(p.bounded_json(session.state/'operations'/(stem+'.out')))
    require({path.name for path in (session.state/'operations').iterdir()}==expected_files,'pipeline_operation_changed')
    names=[item['operation'] for item in receipt['operations']]
    required=['version','init','schema','plan','show-plan','apply','show-state','refresh-plan','show-refresh-plan','refresh-apply','output','show-state','destroy-plan','show-destroy-plan','destroy','final-state']
    require(names==required,'pipeline_operation_incomplete')
    require(captures['version'][0]['terraform_version']=='1.17.0' and captures['version'][0]['platform']=='linux_amd64','pipeline_tool_mismatch')
    schema=captures['schema'][0]['provider_schemas'][p.PROVIDER]['resource_schemas']
    require({'docker_container','docker_network'}<=set(schema) and 'pids_limit' not in schema['docker_container']['block']['attributes'],'pipeline_tool_mismatch')
    p.validate_plan(captures['show-plan'][0],session.variables,target_plan=session.target_plan,runtime_policy=session.target_runtime_policy)
    actual=p.resources(captures['show-state'][0],session.target_plan)
    require({key:value['id'] for key,value in actual.items()}==session.owned,'pipeline_resource_changed')
    p.validate_plan(captures['show-refresh-plan'][0],session.variables,operation='refresh',owned=session.owned,target_plan=session.target_plan,runtime_policy=session.target_runtime_policy)
    output=captures['output'][0]
    require(type(output) is dict and set(output)=={'run'} and output['run'].get('sensitive') is False,'pipeline_resource_changed')
    provider_targets=p.validate_output_identity(output['run']['value'],session.variables,session.owned,session.target_plan)
    p.validate_plan(captures['show-destroy-plan'][0],session.variables,operation='destroy',owned=session.owned,target_plan=session.target_plan,runtime_policy=session.target_runtime_policy)
    require(not p.resources(captures['final-state'][0],session.target_plan) and receipt['cleanup']=='completed','pipeline_destroy_incomplete')
    session._final_state_proof()
    runtime=read_json(run.file(RUNTIME))
    require(c.bound_common(runtime,run.manifest()) and runtime['operation']=='reference-runtime-observations-v1','pipeline_runtime_invalid')
    policy,_=p.target_binding_policy(binding);policy.verify_image(runtime['image'],binding)
    session.verify_owned(runtime['network'],'network',session.network_id)
    session.verify_target(runtime['target_stopped'],stopped=True,network_observation=runtime['network'])
    session.verify_target(runtime['target_live'],network_observation=runtime['network'])
    session.verify_provisioner(runtime['provisioner'])
    require(runtime['target_live']['State']['Running'] is True and runtime['provisioner']['State']['Running'] is True and
        runtime['target_stopped']['Id']==runtime['target_live']['Id'],'pipeline_runtime_invalid')
    endpoint=runtime['target_live']['NetworkSettings']['Networks']['wormhole-'+run.id+'-network']
    network_data=provider_targets['target-001']['network_data']
    require(type(network_data) is list and len(network_data)==1 and network_data[0]['ip_address']==endpoint['IPAddress'] and
        network_data[0]['network_name']=='wormhole-'+run.id+'-network' and endpoint['NetworkID']==session.network_id and
        receipt['inventory']['targets'][0]['host']==endpoint['IPAddress'],'pipeline_resource_changed')
    check_cgroups(receipt['target_cgroups'],archive['plan']['limits']['target']['docker_create'])
    check_cgroups(receipt['provisioner_cgroups'],archive['plan']['limits']['provisioner']['docker_create'])
    before=receipt['targets_before_pid_update']['target-001']
    require(before['status']=='created' and before['started_at']=='0001-01-01T00:00:00Z' and
        (before['pids_limit'] is None or type(before['pids_limit']) is int),'pipeline_runtime_invalid')
    expected={('container',session.provisioner),('container',session.target_resources['target-001']),('network',session.network_id)}
    require(expected<={(item['kind'],item['id']) for item in archive['resources'] if item['outcome']=='absent'},'pipeline_destroy_incomplete')
    return {'receipt':receipt,'runtime':runtime,'target':{'target_id':'target-001','resource_id':session.target_resources['target-001'],'image_digest':binding['image_id']}}


def report_readiness(run,archive,provisioned):
    """Reparse every original readiness attempt after the helper is gone."""
    source(run);receipt=read_json(run.file('evidence/readiness.json'));context=read_json(run.file('private/readiness-controller.json'))
    require(c.bound_common(receipt,run.manifest()) and c.bound_common(context,run.manifest()) and
        receipt['operation']=='ssh-ansible-readiness' and receipt['scenario']=='healthy' and receipt['helper_image']==r.HELPER_IMAGE and
        receipt['helper_build_run']==r.HELPER_BUILD and receipt['target_resource_id']==provisioned['target']['resource_id'] and
        context['target_resource_id']==provisioned['target']['resource_id'] and
        context['network_id']==provisioned['runtime']['network']['Id'] and
        context['helper_id']==receipt['helper_id'] and context['helper_image']==r.HELPER_IMAGE and context['validation_enabled'] is True and
        context['source_sha256']==r.runtime_hash() and context['validation_source_sha256']==r.code_hash(r.VALIDATION_RUNTIME) and
        receipt['expected_checks']==list(r.EXPECTED) and receipt['runtime_pipeline_complete'] is False and receipt['production_iso_eligible'] is False,
        'pipeline_readiness_invalid')
    adapter=r.ReadinessSession.__new__(r.ReadinessSession)
    adapter.run,adapter.helper,adapter.network=run,receipt['helper_id'],context['network_id']
    adapter.image_labels=context['image_labels'];adapter.lease=SimpleNamespace(plan=archive['plan'])
    adapter.validation_enabled=True;adapter.source_sha256=context['source_sha256'];adapter.validation_source_sha256=context['validation_source_sha256']
    adapter.bind_path=run.file('private/helper-source/runtime.py');adapter.validation_bind_path=run.file('private/helper-source/validation.py')
    adapter.bind_identity=context['bind_identity'];adapter.validation_bind_identity=context['validation_bind_identity']
    adapter.verify_helper(provisioned['runtime']['helper'])
    require(('container',adapter.helper) in {(item['kind'],item['id']) for item in archive['resources'] if item['outcome']=='absent'},'pipeline_readiness_invalid')
    transitions=receipt['transitions']
    require(type(transitions) is list and [item['check_id'] for item in transitions]==list(r.EXPECTED)[:len(transitions)] and
        all(item['status']=='pass' and item['target_id']=='target-001' and type(item['elapsed_seconds']) in (int,float) and
            math.isfinite(item['elapsed_seconds']) and 0<=item['elapsed_seconds']<=90 for item in transitions),'pipeline_readiness_invalid')
    probes=[];passed=set();keys=[];count={};auth=0
    stages={'tcp','ssh','python','ansible-wait','ansible-ping'}
    require(type(receipt['attempts']) is list and 1<=len(receipt['attempts'])<=128,'pipeline_readiness_invalid')
    for index,attempt in enumerate(receipt['attempts']):
        require(set(attempt)=={'role','stage','status','returncode','duration_seconds','log_truncated','private_log'} and
            attempt['private_log']=='private/qualification-'+attempt['role']+'-'+attempt['stage']+'-'+str(index)+'.log' and
            attempt['role'] in {'helper','target'} and attempt['stage'] in stages|{'public-hostkey','auth-input'} and
            attempt['log_truncated'] is False and type(attempt['returncode']) is int and attempt['status'] in {'pass','fail'},'pipeline_readiness_invalid')
        raw=raw_file(run,attempt['private_log'])
        if attempt['stage']=='auth-input':
            require(attempt['role']=='helper' and attempt['status']=='pass' and attempt['returncode']==0,'pipeline_readiness_invalid');auth+=1
        if attempt['stage']=='public-hostkey' and attempt['status']=='pass':keys.append(qualification.public_key(raw.decode('ascii')))
        if attempt['stage'] not in stages:continue
        require(attempt['role']=='helper' and attempt['status']=='pass' and attempt['returncode']==0,'pipeline_readiness_invalid')
        value=json.loads(raw,object_pairs_hook=__import__('readiness.runtime',fromlist=['unique']).unique)
        fields={'schema_version','run_id','source_revision','target_id','operation','attempt','status','category','returncode','timed_out','truncated','duration_seconds','observation','private_diagnostic'}
        count[attempt['stage']]=count.get(attempt['stage'],0)+1
        require(type(value) is dict and set(value)==fields and value['schema_version']=='1.0' and value['run_id']==run.id and
            value['source_revision']==run.manifest()['source_revision'] and value['target_id']=='target-001' and value['operation']==attempt['stage'] and
            type(value['attempt']) is int and value['attempt']==count[attempt['stage']] and value['status'] in {'pass','fail'} and
            type(value['returncode']) is int and type(value['timed_out']) is bool and type(value['truncated']) is bool and
            type(value['duration_seconds']) in (int,float) and math.isfinite(value['duration_seconds']) and
            0<=value['duration_seconds']<={'tcp':5,'ssh':10,'python':10,'ansible-wait':27,'ansible-ping':14}[attempt['stage']] and
            type(value['observation']) is dict and (value['status']=='pass')==(value['returncode']==0 and value['category'] is None and value['timed_out'] is False and value['truncated'] is False),'pipeline_readiness_invalid')
        if value['status']=='pass':
            expected={'tcp':('tcp_connected',True),'ssh':('uid',10001),'python':('configured_interpreter_usable',True),'ansible-wait':('structured_target_result',True),'ansible-ping':('ping','pong')}[attempt['stage']]
            require(same(value['observation'].get(expected[0]),expected[1]),'pipeline_readiness_invalid');passed.add(attempt['stage'])
        else:require(value['category'] in {'tcp_pending','ssh_transport_pending','probe_timeout'},'pipeline_readiness_invalid')
        probes.append({key:value[key] for key in value if key not in {'private_diagnostic','observation'}})
    require(same(probes,receipt['probes']) and keys and len(set(keys))==1 and auth==1,'pipeline_readiness_invalid')
    blob=base64.b64decode(keys[0].split()[1],validate=True)
    fingerprint='SHA256:'+base64.b64encode(__import__('hashlib').sha256(blob).digest()).decode().rstrip('=')
    require(receipt['hostkey_fingerprint']==fingerprint and receipt['hostkey_source']=='exact-owned target public-key reader; pin preserved, no TOFU' and
        receipt['status']=='ready' and receipt['unknown_outcome'] is False and receipt['primary_failure'] is None and
        len(transitions)==len(r.EXPECTED) and passed==stages and receipt['cleanup']=='completed','pipeline_readiness_incomplete')
    return receipt
