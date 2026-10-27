"""One source-bound, one-target container reference pipeline and replay gate.

This operation has its own versioned scope. Legacy component completeness flags
stay false. Caller owns the Run lock when reporting/gating; execute owns it.
"""
from copy import deepcopy
from datetime import datetime,timezone
import json
import math
from pathlib import Path
import re
import sys
import time
from uuid import UUID

from . import assessments as a, candidate as c, chunks, images, provisioning as p, readiness as r
from . import pipeline_replay as replay, software_inventory as svd
from .admission import AdmissionLease
from .recovery import cleanup_session,cancellation_requested,valid_failure,validate_cleanup
from .runs import Run,RunError,SOURCE_ROOT,_owned,atomic_bytes,atomic_json,common,now,read_json,source_identity
from .initialization import InitializationSession, report_initialization
from .lifecycle import Lifecycle, initialization_events, readiness_events, report_lifecycle

REQUEST='evidence/pipeline-request.json'
PLAN='evidence/pipeline-plan.json'
RECORD='evidence/pipeline.json'
CONTEXT='private/pipeline-controller.json'
EXPORT='evidence/reference'
SCENARIOS=('healthy','version-expectation-mismatch')


class PipelineError(RunError):pass


def require(value,code='pipeline_invalid'):
    if not value:raise PipelineError(code,'Reference pipeline refused; retain original run evidence and exact resource accounting.')


def records():
    from . import pipeline_records
    return pipeline_records


def make_request(run,platform='ubuntu',scenario='healthy',base_run_id=None,*,observed_initialization=True):
    require(type(observed_initialization) is bool,'pipeline_selection_invalid')
    require(type(platform) is str and platform in {'ubuntu','ubi'} and type(scenario) is str and scenario in SCENARIOS and
        (scenario=='healthy' or platform=='ubuntu'),'pipeline_selection_invalid')
    try:base_valid=base_run_id is None if platform=='ubuntu' else type(base_run_id) is str and str(UUID(base_run_id))==base_run_id
    except (ValueError,AttributeError):base_valid=False
    require(base_valid,'pipeline_base_required')
    value={**common(run.manifest()),'operation':'reference-pipeline-request-v1','platform':platform,'scenario':scenario,
        'profile':'smoke','capabilities':[],'base_run_id':base_run_id,'assessment_case':'pass',
        'assessment_sha256':c.sha(a.fixture('pass')),'assessment_plan_sha256':a.make_plan(run,a.FIXTURE_EXPECTED)['plan_sha256']}
    if observed_initialization:value['execution_contract']='observed-initialization-v1'
    return {**value,'request_sha256':c.sha(c.canonical(value))}


def validate_request(run,value):
    require('execution_contract' not in value or value['execution_contract']=='observed-initialization-v1','pipeline_request_changed')
    expected=make_request(run,value.get('platform'),value.get('scenario'),value.get('base_run_id'),
        observed_initialization='execution_contract' in value)
    require(c.canonical(value)==c.canonical(expected),'pipeline_request_changed');return value


def prepared_manifest(run,platform):
    bundle=c.validate_bundle(run);manifest=bundle['manifest']
    from .candidate_cache import selected_manifest
    selected=selected_manifest(run,platform)
    if selected is not None:return selected
    if platform=='ubuntu':return manifest
    from . import rpm_candidate as rc,rpm_target as rt
    value=deepcopy(manifest);value.update(operation='ubi9-reference-candidate',applicability=deepcopy(rc.APPLICABILITY),
        source_candidate_manifest=manifest,source_candidate_sha256=bundle['candidate_sha256'],content_sha256=rc.content_identity(manifest),
        base_reference=rt.BASE,base_image=rt.BASE_ID,packages=deepcopy(rc.PACKAGE_VERSIONS),
        artifact_contract='installed-payload-v1',test_contract_sha256=c.sha(c.canonical(rc.installed_contract())))
    return rc.validate_manifest(value)


def candidate_identity(manifest):
    from . import rpm_candidate as rc
    digest=c.sha(c.canonical(manifest))
    return {'manifest_sha256':digest,'source_candidate_sha256':manifest.get('source_candidate_sha256',digest),
        'content_sha256':rc.content_identity(manifest),'source_sha256':manifest['source_sha256']}


def build_plan(run,request,manifest=None):
    from .candidate_validation import expected_values as ubuntu_values
    from .rpm_validation import expected_values as ubi_values
    pseudo=None if manifest is None else {'operation':'candidate-image-binding' if request['platform']=='ubuntu' else 'ubi9-candidate-image-binding',
        'manifest':manifest,'candidate_sha256':c.sha(c.canonical(manifest)),
        'source_candidate_sha256':manifest.get('source_candidate_sha256',c.sha(c.canonical(manifest))),'content_sha256':candidate_identity(manifest)['content_sha256']}
    functions={} if pseudo is None else (ubuntu_values(pseudo,request['scenario']) if request['platform']=='ubuntu' else ubi_values(pseudo,'healthy'))
    inventory={} if pseudo is None else svd.expected_values(pseudo,'1'*64,'healthy')
    values=[]
    for row in records().grid(request['platform']):
        expected='verified'
        if row['component']=='functional':expected=functions.get(row['check_id'],'not-prepared')
        if row['component']=='svd':expected='exact-owned-target-001' if row['check_id']=='target-identity' else inventory.get(row['check_id'],'not-prepared')
        if row['component']=='assessment':expected='Not Applicable' if row['check_id']=='fixture-delta' else 'Not a Finding'
        values.append({**row,'expected':expected})
    plan={**common(run.manifest()),'operation':'reference-pipeline-plan-v1','policy':'reference-smoke-v1',
        'platform':request['platform'],'profile':'smoke','targets':['target-001'],'capabilities':[],
        'candidate':None if manifest is None else candidate_identity(manifest),'expected_rows':values}
    plan['plan_sha256']=c.sha(c.canonical(plan));return records().validate_plan(plan)


def validate_plan(run,plan,request):
    require(c.canonical(plan)==c.canonical(build_plan(run,request,prepared_manifest(run,request['platform']) if plan['candidate'] is not None else None)),
        'pipeline_plan_changed')
    if plan['candidate'] is None:require(not run.file('evidence/provisioning.json').exists(),'pipeline_plan_changed')


def _component_binding(run,platform):
    return replay.report_candidate(run,platform)


def _artifact(run,identifier,path,kind='component',maximum=4*1024*1024):
    raw=replay.raw_file(run,path,maximum)
    return {'artifact_id':identifier,'kind':kind,'sha256':c.sha(raw),'size_bytes':len(raw)}


def assemble_record(run):
    """Rebuild all rows from originals. No cached counts/status authorize a pass."""
    replay.source(run);request=validate_request(run,read_json(run.file(REQUEST)));plan=read_json(run.file(PLAN));validate_plan(run,plan,request)
    context=read_json(run.file(CONTEXT));context_fields=set(common(run.manifest()))|{'operation','request_sha256','primary_failure','secondary_failures','unknown_outcome','cleanup_status','pending_resources','updated_at'}
    require(set(context) in (context_fields,context_fields|{'initialization_policy'}) and
        ('initialization_policy' not in context or context['initialization_policy']=='observed-v1') and
        c.bound_common(context,run.manifest()) and context['operation']=='reference-pipeline-controller-v1' and
        context['request_sha256']==request['request_sha256'] and valid_failure(context['primary_failure']) and
        type(context['unknown_outcome']) is bool and type(context['pending_resources']) is int and 0<=context['pending_resources']<=128 and
        type(context['secondary_failures']) is list and len(context['secondary_failures'])<=64 and all(valid_failure(item) for item in context['secondary_failures']),'pipeline_context_invalid')
    require('execution_contract' not in request or context.get('initialization_policy')=='observed-v1','pipeline_context_invalid')
    artifacts=[_artifact(run,'request',REQUEST,'plan'),_artifact(run,'execution-plan',PLAN,'plan')]
    rowmap={};errors=[];binding=None;targets=[];archive=None;cleanup={'status':'not-started','admission_finished':False,'archive_sha256':None,'pending_resources':0}
    def set_rows(component,values=None,status='pass',reason='verified',evidence=None):
        if values is not None:
            require(type(values) is dict and set(values)=={item['check_id'] for item in plan['expected_rows'] if item['component']==component},'pipeline_result_incomplete')
        for declaration in plan['expected_rows']:
            if declaration['component']!=component:continue
            item=None if values is None else values[declaration['check_id']]
            observed=declaration['expected'] if status=='pass' else 'not-observed'
            actual=status
            if item is not None:observed,actual=item['observed'],item['status']
            rowmap[(component,declaration['check_id'])]={**declaration,'observed':observed,'status':actual,'reason_code':reason if actual!='pass' else 'verified',
                'message':'Original source-bound evidence verified.' if actual=='pass' else 'Required reference result is unavailable or failed.',
                'evidence':list(evidence or ['execution-plan'])}
    def attempt(component,path,action):
        if not run.file(path).exists():set_rows(component,status='blocked',reason='not_executed');return None
        try:
            result=action();identifier=component+'-record';artifacts.append(_artifact(run,identifier,path));set_rows(component,evidence=[identifier]);return result
        except Exception as error:
            code=safe_code(error);errors.append(code);set_rows(component,status='error',reason=code);return None
    set_rows('preflight',evidence=['request'])
    source_result=attempt('chunks','evidence/chunks.json',lambda:chunks.verified_source(run))
    if source_result is not None:require(plan['candidate'] is not None and c.sha(c.bounded_file(source_result))==plan['candidate']['source_sha256'],'pipeline_candidate_changed')
    assessment=attempt('assessment',a.RECEIPT,lambda:a.report_assessment(run))
    if assessment is not None:
        require(c.canonical(read_json(run.file(a.PLAN)))==c.canonical(a.make_plan(run,a.FIXTURE_EXPECTED)) and
            assessment['result']['plan_sha256']==request['assessment_plan_sha256'] and
            c.sha(a.original_bytes(run))==request['assessment_sha256'],'pipeline_assessment_changed')
        entries=assessment['result']['result']
        require(entries is not None,'pipeline_assessment_incomplete')
        set_rows('assessment',{item['finding_id']:{'observed':item['status'],'status':'pass' if item['status']==('Not Applicable' if item['finding_id']=='fixture-delta' else 'Not a Finding') else 'fail'} for item in entries['findings']},evidence=['assessment-record'])
    path='evidence/candidate-binding.json' if request['platform']=='ubuntu' else 'evidence/rpm-candidate-binding.json'
    binding=attempt('candidate',path,lambda:_component_binding(run,request['platform']))
    candidate=None
    if binding is not None:
        candidate={**candidate_identity(binding['manifest']),'image_digest':binding['image_id']}
        require(c.canonical({key:candidate[key] for key in plan['candidate']})==c.canonical(plan['candidate']),'pipeline_candidate_changed')
    try:
        archive=replay.admission_archive(run);raw=replay.archive_bytes(run)
        artifacts.append({'artifact_id':'admission-archive','kind':'admission','sha256':c.sha(raw),'size_bytes':len(raw)})
        cleanup.update(admission_finished=True,archive_sha256=c.sha(raw),pending_resources=0)
        set_rows('admission',evidence=['admission-archive'])
    except Exception as error:
        errors.append(safe_code(error));set_rows('admission',status='blocked',reason='pipeline_admission_unfinished')
    provisioned=None
    if binding is not None and archive is not None:
        provisioned=attempt('provisioning','evidence/provisioning.json',lambda:replay.report_provisioning(run,archive,binding))
        if provisioned is not None:targets=[provisioned['target']]
    else:set_rows('provisioning',status='blocked',reason='not_executed')
    if provisioned is not None:attempt('readiness','evidence/readiness.json',lambda:replay.report_readiness(run,archive,provisioned))
    else:set_rows('readiness',status='blocked',reason='not_executed')
    if context.get('initialization_policy')=='observed-v1' and provisioned is not None:
        try:
            report_initialization(run,require_passed=True)
            artifacts.append(_artifact(run,'initialization-record','evidence/initialization.json'))
        except Exception as error:
            errors.append(safe_code(error));set_rows('readiness',status='error',reason='initialization_evidence_incomplete')
    from .candidate_validation import report_candidate_validation
    from .rpm_validation import report_rpm_validation
    functional_path='evidence/candidate-validation.json' if request['platform']=='ubuntu' else 'evidence/rpm-validation.json'
    functional=attempt('functional',functional_path,lambda:(report_candidate_validation(run) if request['platform']=='ubuntu' else report_rpm_validation(run)))
    if functional is not None:set_rows('functional',{row['check_id']:row for row in functional['result']['checks']},evidence=['functional-record'])
    if context.get('initialization_policy')=='observed-v1' and functional is not None:
        try:
            lifecycle=report_lifecycle(run,expected_targets=['target-001'],
                expected_checks=[item['check_id'] for item in plan['expected_rows'] if item['component']=='functional'],require_passed=True)
            require(lifecycle['candidate_identity']['image_id']==binding['image_id'],'lifecycle_candidate_changed')
            artifacts.append(_artifact(run,'lifecycle-record','evidence/lifecycle.json'))
        except Exception as error:
            errors.append(safe_code(error));set_rows('functional',status='error',reason='lifecycle_evidence_incomplete')
    inventory=attempt('svd',svd.RECORD,lambda:svd.report_software_inventory(run))
    if inventory is not None:
        values={item['check_id']:deepcopy(item) for item in inventory['record']['checks']}
        identity=values['target-identity']
        if identity['status']=='pass':identity['observed']='exact-owned-target-001'
        set_rows('svd',values,evidence=['svd-record'])
        if inventory['record']['capture'] is not None:artifacts.append(_artifact(run,'svd-original',svd.LOG,'log-capture',65536))
    # Portable descriptors bind original capture bytes; no private path or raw
    # diagnostics are copied into the export. The component replayers above
    # validate their identities/semantics independently of these hashes.
    for component,path in (('readiness','evidence/readiness.json'),('functional',functional_path),('svd',svd.RECORD)):
        if run.file(path).exists():
            value=read_json(run.file(path))
            for index,item in enumerate(value.get('attempts',[])):
                artifacts.append(_artifact(run,component+'-log-'+str(index),item['private_log'],'log-capture',65536))
    if run.file('evidence/provisioning.json').exists():
        for index,item in enumerate(read_json(run.file('evidence/provisioning.json'))['operations']):
            artifacts.append(_artifact(run,'terraform-log-'+str(index),item['evidence'],'log-capture'))
    if run.file('evidence/cleanup.json').exists():
        value=validate_cleanup(read_json(run.file('evidence/cleanup.json')))
        require(c.bound_common(value,run.manifest()),'pipeline_cleanup_invalid')
        cleanup.update(status=value['status'] if value['status'] in {'completed','failed','blocked'} else 'blocked',
            pending_resources=sum(item['disposition'] in {'pending','unknown'} for item in value['resources']))
        artifacts.append(_artifact(run,'cleanup-record','evidence/cleanup.json','cleanup'))
        if archive is not None:
            archived={(item['kind'],item['id']):item['outcome'] for item in archive['resources']}
            cleaned={(item['kind'],item['id']):item['disposition'] for item in value['resources']}
            require(archived==cleaned,'pipeline_cleanup_graph_changed')
            if binding is not None and provisioned is not None:
                build=read_json(run.file('evidence/candidate-build.json' if request['platform']=='ubuntu' else 'evidence/rpm-candidate-build.json'))
                ready_context=read_json(run.file('private/readiness-controller.json'))
                expected={('image',binding['image_id']):'retained',
                    ('container',read_json(run.file('private/terraform/controller.json'))['id']):'absent',
                    ('container',targets[0]['resource_id']):'absent',('network',provisioned['runtime']['network']['Id']):'absent',
                    ('container',ready_context['helper_id']):'absent'}
                if build['builder_id'] is not None:expected[('container',build['builder_id'])]='absent'
                sizes={item['id']:item['size_bytes'] for item in archive['resources'] if item['kind']=='image'}
                require(sizes.get(binding['image_id'])==provisioned['runtime']['image']['Size'] and type(sizes.get(binding['image_id'])) is int and sizes[binding['image_id']]>0,'pipeline_cleanup_graph_changed')
                if request['platform']=='ubi':
                    from . import rpm_target as rt
                    expected[('image',rt.BASE_ID)]='retained'
                    if 'reuse' not in binding:
                        resolver=read_json(run.file('evidence/rpm-resolution.json'))
                        expected[('container',resolver['container_id'])]='absent'
                    rt.verify_base(provisioned['runtime']['base_image'],rt.load_lock())
                    require(sizes.get(rt.BASE_ID)==provisioned['runtime']['base_image']['Size'],'pipeline_cleanup_graph_changed')
                require(archived==expected,'pipeline_cleanup_graph_changed')
    else:
        cleanup.update(status='blocked' if run.file('evidence/provisioning.json').exists() else context['cleanup_status'],pending_resources=context['pending_resources'])
    set_rows('cleanup',status='pass' if cleanup['status']=='completed' and cleanup['admission_finished'] else 'blocked',
        reason='pipeline_cleanup_incomplete',evidence=['admission-archive'] if archive is not None else ['execution-plan'])
    set_rows('evidence',status='error' if errors else 'pass',reason=errors[0] if errors else 'verified',evidence=['execution-plan'])
    rows=[rowmap[(item['component'],item['check_id'])] for item in plan['expected_rows']]
    primary=context['primary_failure']
    if primary is None and errors:primary={'code':errors[0],'recorded_at':context['updated_at']}
    if primary is not None and all(row['status']=='pass' for row in rows):
        set_rows('evidence',status='error',reason=primary['code']);rows=[rowmap[(item['component'],item['check_id'])] for item in plan['expected_rows']]
    passed=all(item['status']=='pass' for item in rows) and primary is None and not context['unknown_outcome'] and candidate is not None and len(targets)==1 and cleanup['status']=='completed' and cleanup['admission_finished']
    value={**common(run.manifest()),'operation':'reference-pipeline-result-v1','policy':'reference-smoke-v1','plan_sha256':plan['plan_sha256'],
        'status':'passed' if passed else 'blocked' if context['unknown_outcome'] or cleanup['status']=='blocked' else 'failed',
        'candidate':candidate,'targets':targets,'rows':rows,'artifacts':artifacts,'primary_failure':primary,
        'secondary_failures':context['secondary_failures'],'cleanup':cleanup,'unknown_outcome':context['unknown_outcome'],
        'reference_scope_complete':passed,'reference_eligible':passed,'production_iso_eligible':False,'updated_at':context['updated_at']}
    return records().validate_record(value,plan)


def safe_code(error):
    code=getattr(error,'code','pipeline_io_error')
    return code if type(code) is str and re.fullmatch('[a-z][a-z0-9_]{0,79}',code) else 'pipeline_io_error'


def export_files(run,record,plan):
    inventory=svd.report_software_inventory(run)['record'] if run.file(svd.RECORD).exists() else None
    files=records().safe_export(record,plan,svd_record=inventory)
    files.pop('checksums.json',None);files.pop('decision.json',None)
    checksums={path:{'sha256':c.sha(raw),'size_bytes':len(raw)} for path,raw in sorted(files.items())}
    files['checksums.json']=c.canonical({'schema_version':'1.0','run_id':run.id,'files':checksums})+b'\n'
    reasons=sorted({row['reason_code'] for row in record['rows'] if row['status']!='pass'}|
        ({record['primary_failure']['code']} if record['primary_failure'] else set()))
    files['decision.json']=c.canonical({**common(run.manifest()),'operation':'reference-pipeline-decision-v1','policy':'reference-smoke-v1',
        'reference_eligible':record['reference_eligible'],'reference_scope_complete':record['reference_scope_complete'],
        'production_iso_eligible':False,'reasons':reasons,'record_sha256':c.sha(files['report.json']),
        'checksums_sha256':c.sha(files['checksums.json'])})+b'\n'
    return files


def report_pipeline(run):
    value=assemble_record(run);saved=read_json(run.file(RECORD));require(c.canonical(value)==c.canonical(saved),'pipeline_record_changed')
    plan=read_json(run.file(PLAN));files=export_files(run,value,plan)
    directory=run.file(EXPORT)
    _owned(directory,directory=True)
    expected=set(files)
    allowed_directories={str(Path(path).parent).replace('\\','/') for path in files}
    allowed_directories|={'targets','targets/target-001','.'}
    actual=set()
    for path in directory.rglob('*'):
        relative=path.relative_to(directory).as_posix()
        _owned(path,directory=path.is_dir())
        if path.is_dir():require(relative in allowed_directories,'pipeline_export_changed')
        else:actual.add(relative)
    require(actual==expected,'pipeline_export_changed')
    for path,raw in files.items():require(replay.raw_file(run,EXPORT+'/'+path,1024*1024)==raw,'pipeline_export_changed')
    return {'record':value,'json':files['report.json'],'text':files['report.txt'].decode(),'junit':files['report.junit.xml'].decode(),
        'decision':json.loads(files['decision.json'])}


def gate_pipeline(run):
    try:return report_pipeline(run)['decision']
    except Exception as error:
        return {**common(run.manifest()),'operation':'reference-pipeline-decision-v1','policy':'reference-smoke-v1',
            'reference_eligible':False,'reference_scope_complete':False,'production_iso_eligible':False,'reasons':[safe_code(error)],
            'record_sha256':None,'checksums_sha256':None}


def _write_exports(run,files):
    folder=run.file(EXPORT);folder.mkdir(mode=0o700)
    for path,raw in files.items():
        destination=run.file(EXPORT+'/'+path);parent=folder
        for part in Path(path).parts[:-1]:
            parent=parent/part;parent.mkdir(mode=0o700,exist_ok=True);_owned(parent,directory=True)
        atomic_bytes(destination,raw,limit=1024*1024)


class PipelineSession:
    def __init__(self,run,request,*,reuse_candidates=True):
        require(type(reuse_candidates) is bool,'pipeline_selection_invalid')
        self.reuse_candidates=reuse_candidates
        self.run=run;self.request=validate_request(run,request)
        require(self.request.get('execution_contract')=='observed-initialization-v1','pipeline_execution_contract_required')
        require(run.workspace==images.RUNS_ROOT and sys.platform.startswith('linux'),'pipeline_host_scope')
        replay.source(run);require(not any(run.file(path).exists() for path in (REQUEST,PLAN,RECORD,CONTEXT)),'pipeline_attempt_reused')
        self.context={**common(run.manifest()),'operation':'reference-pipeline-controller-v1','request_sha256':request['request_sha256'],
            'primary_failure':None,'secondary_failures':[],'unknown_outcome':False,'cleanup_status':'not-started','pending_resources':0,'updated_at':now(),
            'initialization_policy':'observed-v1'}
        self.session=self.readiness=self.lease=None
        self.lifecycle=None;self.execution_deadline=time.monotonic()+600
        self.timings={**common(run.manifest()),'operation':'reference-stage-timings-v1','stages':[],
            'construction':'not-started','production_iso_eligible':False}

    def timed(self,name,action):
        began=time.monotonic()
        timing={'stage':name,'started_at':now(),'finished_at':None,'elapsed_seconds':None,'outcome':'running'}
        self.timings['stages'].append(timing)
        def save():atomic_json(self.run.file('evidence/pipeline-timings.json'),self.timings)
        save()
        try:
            value=action()
            failed=(type(value) is dict and value.get('status') in {'failed','fail','error','blocked','pending'}) or (
                name=='cleanup' and self.context.get('cleanup_status')!='completed')
            timing['outcome']='failed' if failed else 'passed'
            return value
        except BaseException:
            timing['outcome']='failed';raise
        finally:
            timing.update(finished_at=now(),elapsed_seconds=time.monotonic()-began)
            original=sys.exc_info()[1]
            try:save()
            except OSError:
                if original is None:raise
                self.context['secondary_failures'].append({'code':'pipeline_timing_write_failed','recorded_at':now()})
                try:self.save()
                except OSError:pass

    def save(self):
        self.context['updated_at']=now();atomic_json(self.run.file(CONTEXT),self.context)

    def failure(self,error):
        failure={'code':safe_code(error),'recorded_at':now()}
        if self.context['primary_failure'] is None:self.context['primary_failure']=failure
        else:self.context['secondary_failures'].append(failure)
        self.save()

    def _budget(self,seconds):
        require(self.readiness is not None,'pipeline_readiness_required')
        for value,lifetime in ((images.inspect('container',self.readiness.helper),180),(images.inspect('container',self.readiness.target),300)):
            started=datetime.fromisoformat(value['State']['StartedAt'].replace('Z','+00:00'))
            elapsed=(datetime.now(timezone.utc)-started).total_seconds()
            require(started.tzinfo is not None and 0<=elapsed and lifetime-elapsed>=seconds,'pipeline_lifetime_budget')

    def _snapshot(self,phase):
        ps=self.session;path=self.run.file(replay.RUNTIME)
        value=read_json(path) if path.exists() else {**common(self.run.manifest()),'operation':'reference-runtime-observations-v1'}
        if phase=='stopped':
            value.update(image=images.inspect('image',ps.target_image_id),network=images.inspect('network',ps.network_id),
                target_stopped=images.inspect('container',ps.target_resources['target-001']),provisioner=images.inspect('container',ps.provisioner))
            if self.request['platform']=='ubi':
                from .rpm_target import BASE_ID
                value['base_image']=images.inspect('image',BASE_ID)
        else:value.update(target_live=images.inspect('container',ps.target_resources['target-001']),helper=images.inspect('container',self.readiness.helper))
        atomic_json(path,value)

    def _runtime(self):
        from .candidate_validation import CandidateValidationSession
        from .rpm_validation import RPMValidationSession
        from .rpm_assembly import build as build_rpm
        from . import candidate_cache
        platform=self.request['platform']
        if self.run.file(candidate_cache.SELECTION).exists():
            self.timings['construction']='verified-image-reuse'
            if platform=='ubi':candidate_cache.verify_base_request(self.run,self.request['base_run_id'])
            binding=self.timed('candidate-integrity',lambda:candidate_cache.reuse(self.run,self.lease))
        elif platform=='ubuntu':
            self.timings['construction']='fresh-build'
            binding=self.timed('candidate-construction',lambda:c.build_candidate(self.run,self.lease))
            candidate_cache.publish(self.run,self.lease,binding)
        else:
            self.timings['construction']='fresh-ubi-build'
            binding=self.timed('candidate-construction',lambda:build_rpm(self.run,self.lease,base_run=Run(images.RUNS_ROOT,self.request['base_run_id'])))
            candidate_cache.publish(self.run,self.lease,binding)
        # The UBI assembler returns its binding; immutable planned bytes must agree.
        require(candidate_identity(binding['manifest'])==read_json(self.run.file(PLAN))['candidate'],'pipeline_candidate_changed')
        self.session=p.ProvisioningSession(self.run,self.lease,target_binding=binding)
        self.timed('provisioning',self.session.create_stopped);self._snapshot('stopped')
        self.timed('runtime-start',self.session.start_and_inventory)
        checks=[item['check_id'] for item in read_json(self.run.file(PLAN))['expected_rows'] if item['component']=='functional']
        self.lifecycle=Lifecycle(self.run,['target-001'],candidate_identity={'image_id':binding['image_id'],
            'candidate_sha256':binding['candidate_sha256']},checks=checks,budget_seconds=300,absolute_deadline=self.execution_deadline)
        self.lifecycle.event('target-001','created',evidence='evidence/provisioning.json')
        self.lifecycle.event('target-001','runtime-started',evidence='evidence/provisioning.json')
        initialization=InitializationSession(self.session,absolute_deadline=self.lifecycle.deadline-20)
        self.timed('initialization',lambda:initialization.wait_result('target-001'))
        initialization_events(self.lifecycle,'target-001',initialization.record['targets']['target-001']['observation'],'evidence/initialization.json')
        initialization.require_complete('target-001')
        self.readiness=r.ReadinessSession(self.session,validation=True,initialization=initialization);self.readiness.start_helper()
        self.readiness.deadline=min(self.readiness.deadline,self.lifecycle.deadline-20)
        def cancelled(_):require(not cancellation_requested(self.run),'cancelled')
        self.timed('ssh-ansible-readiness',lambda:self.readiness.wait_ready(on_poll=cancelled));self._snapshot('live')
        readiness_events(self.lifecycle,'target-001',self.readiness.receipt)
        # The original 180/300s lifetimes are unchanged. Reserve full component
        # budgets plus safe cleanup time; a slow readiness attempt refuses here.
        self._budget(140)
        validator=CandidateValidationSession(self.readiness,binding,scenario=self.request['scenario']) if platform=='ubuntu' else RPMValidationSession(self.readiness,binding)
        self.lifecycle.start_validation()
        result=self.timed('functional-validation',validator.validate)
        for item in result['checks']:self.lifecycle.test_result('target-001',item['check_id'],item['status'],persist=False)
        self.lifecycle.finalize();self._budget(80)
        self.timed('installed-inventory',svd.SoftwareInventorySession(self.readiness,binding).collect)

    def _cleanup(self,error):
        lease=self.lease
        if self.lifecycle is not None and error is not None and self.lifecycle.record['terminal_outcome']!='passed':
            try:
                self.lifecycle.event('target-001','failure',evidence='lifecycle/controller-failure',category=safe_code(error))
                if self.session.receipt['unknown_outcome']:
                    self.lifecycle.event('target-001','remote-unknown',evidence='lifecycle/lost-observation')
                self.lifecycle.finalize()
            except Exception as failure:self.failure(failure)
        try:
            if self.session is not None:
                self.context['unknown_outcome']=self.session.receipt['unknown_outcome'] or (self.readiness is not None and self.readiness.receipt['unknown_outcome'])
                result=cleanup_session(self.session,lease,helper=self.readiness,reason='failure' if error else 'success')
                self.context['cleanup_status']=result['status'];self.context['unknown_outcome']|=result['unknown_outcome']
                for failure in result['secondary_failures']:
                    if self.context['primary_failure'] is None:self.context['primary_failure']=deepcopy(failure)
                    else:self.context['secondary_failures'].append(deepcopy(failure))
                if result['status']=='completed':lease.finish(reconciliation_complete=True)
            else:
                empty=lease.record['phase']=='reserved' and not lease.record['resources']
                build_path='evidence/candidate-build.json' if self.request['platform']=='ubuntu' else 'evidence/rpm-candidate-build.json'
                known=read_json(self.run.file(build_path)) if self.run.file(build_path).exists() else None
                resolved=(known is not None and c.bound_common(known,self.run.manifest()) and known.get('unknown_outcome') is False and
                    all(item['outcome'] in {'absent','retained'} for item in lease.record['resources']))
                # The UBI resolver can finish cleanup before source preparation
                # fails, before any assembly request/build receipt exists.
                resolution_path=self.run.file('evidence/rpm-resolution.json')
                if self.request['platform']=='ubi' and known is None and resolution_path.exists():
                    from .rpm_resolution import recipe_identity
                    resolution=read_json(resolution_path);recipe,files=recipe_identity()
                    resolved=(c.bound_common(resolution,self.run.manifest()) and
                        resolution.get('operation')=='ubi-offline-resolution' and resolution.get('status') in {'passed','failed'} and
                        resolution.get('recipe_sha256')==recipe and resolution.get('source_files')==files and
                        resolution.get('cleanup')=='completed' and resolution.get('unknown_outcome') is False and
                        resolution.get('secondary_cleanup_failure') is None and
                        all(item['outcome'] in {'absent','retained'} for item in lease.record['resources']))
                if empty or resolved:self.context['cleanup_status']='completed';lease.finish(reconciliation_complete=True)
                else:self.context['cleanup_status']='blocked';self.context['unknown_outcome']=True
        except BaseException as failure:
            self.failure(failure);self.context['cleanup_status']='blocked'
            self.context['unknown_outcome']|=any(item['outcome']=='pending' for item in lease.record['resources'])
        finally:
            self.context['pending_resources']=sum(item['outcome']=='pending' for item in lease.record['resources']);self.save()

    def _finalize(self):
        self.save();value=assemble_record(self.run);atomic_json(self.run.file(RECORD),value)
        files=export_files(self.run,value,read_json(self.run.file(PLAN)));_write_exports(self.run,files)
        require(report_pipeline(self.run)['record']==value,'pipeline_final_replay')
        require(value['reference_eligible'],self.context['primary_failure']['code'] if self.context['primary_failure'] else 'pipeline_gate_refused')
        return deepcopy(value)

    def execute(self):
        error=None
        try:
            try:images.create_auth(self.run) # Existing API owns its short lock.
            except BaseException as failure:
                with self.run.locked():
                    atomic_json(self.run.file(REQUEST),self.request);self.failure(failure)
                    atomic_json(self.run.file(PLAN),build_plan(self.run,self.request,None));return self._finalize()
            with self.run.locked() as guard,images.docker_scope(self.run):
                atomic_json(self.run.file(REQUEST),self.request);self.save();manifest=None
                try:
                    result=self.timed('source',lambda:chunks.execute_fixture_held(self.run,guard,transport='local',scenario='healthy'))
                    require(result['status']=='passed','pipeline_chunks_failed')
                    self.timed('synthetic-assessment',lambda:a.assess_run_held(self.run,guard,a.fixture('pass'),a.FIXTURE_EXPECTED))
                    self.timed('candidate-inputs',lambda:c.prepare_candidate(self.run))
                    if self.reuse_candidates:
                        from .candidate_cache import select,verify_base_request
                        selected=select(self.run,self.request['platform'])
                        if selected is not None and self.request['platform']=='ubi':verify_base_request(self.run,self.request['base_run_id'])
                    manifest=prepared_manifest(self.run,self.request['platform'])
                except BaseException as failure:self.failure(failure);error=failure
                atomic_json(self.run.file(PLAN),build_plan(self.run,self.request,manifest))
                if error is None:
                    try:
                        with AdmissionLease(images.INFRASTRUCTURE,self.run.id,self.run.manifest()['source_revision'],'smoke') as lease:
                            self.lease=lease
                            try:self._runtime()
                            except BaseException as failure:self.failure(failure);error=failure
                            finally:self.timed('cleanup',lambda:self._cleanup(error))
                    except BaseException as failure:self.failure(failure);error=failure
                return self._finalize()
        except BaseException as failure:
            failure.run_id=self.run.id
            raise
