"""Small immutable-image index, governed by the existing canonical admission.

Reuse preserves the original manifest, image labels and build Run. The new Run
gets a separate attributable binding and must execute every acceptance check.
No qualification decision, credentials or runtime result is reused.
"""
from copy import deepcopy

from . import candidate as c, images
from .runs import Run, _owned, atomic_json, common, now, read_json

SELECTION='evidence/candidate-selection.json'
OPERATION='candidate-image-reuse-v1'


def policy(platform):
    c.require(platform in ('ubuntu','ubi'),'candidate_cache_platform')
    if platform=='ubuntu':return c
    from . import rpm_candidate
    return rpm_candidate


def paths(platform):
    policy(platform)
    prefix='rpm-' if platform=='ubi' else ''
    return ('evidence/'+prefix+'candidate-binding.json','evidence/'+prefix+'candidate-build.json',
        'evidence/'+prefix+'candidate-inputs.json')


def input_identity(run,platform='ubuntu'):
    bundle=c.validate_bundle(run)
    value=c.input_identity(bundle['manifest']['source_sha256']);policy(platform)
    if platform=='ubi':
        from . import rpm_candidate as rc,rpm_source,rpm_resolution,rpm_target
        inputs=value['build_inputs']
        inputs.update(base_image=rpm_target.BASE_ID,
            build_tool_identity={'image_id':rpm_target.BASE_ID,'entrypoint':'fixed-offline-rpm-assembly-v1'},
            rpm_recipe=rc.recipe_identity()[1],rpm_resolution=rpm_resolution.recipe_identity()[1],
            package_lock_sha256=c.sha(rpm_source.lock_bytes()),packages=deepcopy(rc.PACKAGE_VERSIONS))
        value['input_sha256']=c.sha(c.canonical(inputs))
    return value


def input_record(run,manifest):
    return {**common(run.manifest()),'operation':'ubi-construction-inputs-v1',**input_identity(run,'ubi'),
        'generation_attempt':run.id,'candidate_sha256':c.sha(c.canonical(manifest)),'production_iso_eligible':False}


def key(run,platform='ubuntu'):
    return c.sha(c.canonical({'inputs':input_identity(run,platform),
        'installed_manifest_contract':c.sha(c.canonical(policy(platform).installed_contract()))}))


def index_path(run,platform='ubuntu'):
    return images.INFRASTRUCTURE/'candidate-cache'/(key(run,platform)+'.json')


def origin(run, selection):
    platform=selection.get('platform','ubuntu') if type(selection) is dict else 'ubuntu'
    module=policy(platform);binding_path,build_path,inputs_path=paths(platform)
    fields=set(common(run.manifest()))|{'operation','cache_key','origin_run_id','origin_binding_sha256',
        'candidate_sha256','image_id','input_sha256'}
    if platform=='ubi':fields.add('platform')
    c.require(type(selection) is dict and set(selection)==fields and c.bound_common(selection,run.manifest()) and
        selection['operation']==OPERATION and selection['cache_key']==key(run,platform) and selection['origin_run_id']!=run.id,
        'candidate_reuse_invalid')
    # Run validates canonical UUID, ownership, links and the existing private store.
    old=Run(run.workspace,selection['origin_run_id'])
    saved=read_json(old.file(binding_path))
    c.require('reuse' not in saved,'candidate_reuse_chain_refused')
    binding=module.validate_origin(old) if platform=='ubi' else c.validate_binding(old)
    c.require(read_json(old.file(build_path)).get('primary_failure') is None,'candidate_reuse_invalid')
    previous=read_json(old.file(inputs_path))
    current=input_identity(run,platform)
    previous={name:previous[name] for name in ('build_inputs','input_sha256')}
    c.require(c.compare_inputs(previous,current)['content_reusable'] and
        selection['input_sha256']==current['input_sha256'] and
        selection['origin_binding_sha256']==c.sha(c.canonical(binding)) and
        selection['candidate_sha256']==binding['candidate_sha256'] and selection['image_id']==binding['image_id'],
        'candidate_stale')
    # The old, immutable embedded manifest is the bytes actually installed.
    intended=c.validate_bundle(run)['manifest']
    if platform=='ubi':
        from . import rpm_candidate as rc
        intended.update(applicability=deepcopy(rc.APPLICABILITY),
            test_contract_sha256=c.sha(c.canonical(rc.manifest_contract(binding['manifest']))))
    c.require(all(binding['manifest'][name]==intended[name] for name in
        ('files','version','configuration','source_sha256','applicability','test_contract_sha256')),
        'candidate_stale')
    return old,binding


def select(run,platform='ubuntu'):
    """Read-only selection before the test plan freezes; no Docker allocation."""
    c.require(not run.file(SELECTION).exists(),'candidate_selection_reused')
    path=index_path(run,platform)
    if not path.exists():return None
    index=read_json(path)
    fields={'operation','cache_key','origin_run_id','origin_binding_sha256','candidate_sha256','image_id','input_sha256'}
    if platform=='ubi':fields.add('platform')
    c.require(type(index) is dict and set(index)==fields and index.get('platform','ubuntu')==platform and
        index['operation']==OPERATION and index['cache_key']==key(run,platform),
        'candidate_cache_invalid')
    selection={**common(run.manifest()),**index}
    _,binding=origin(run,selection)
    atomic_json(run.file(SELECTION),selection)
    return binding['manifest']


def selected_manifest(run,platform='ubuntu'):
    if not run.file(SELECTION).exists():return None
    selection=read_json(run.file(SELECTION))
    c.require(selection.get('platform','ubuntu')==platform,'candidate_cache_platform')
    return origin(run,selection)[1]['manifest']


def verify_base_request(run,base_run_id):
    """Reuse must satisfy the explicitly requested UBI base observation too."""
    from . import rpm_target,rpm_source
    selection=read_json(run.file(SELECTION));c.require(selection.get('platform')=='ubi','candidate_cache_platform')
    old,_=origin(run,selection)
    observation=rpm_target.read_base_observation(Run(run.workspace,base_run_id))
    request=read_json(old.file('private/rpm-sources/resolve-request.json'))
    c.require(c.sha(c.canonical(rpm_source.validate_observation(observation)))==request['base_packages_sha256'],
        'candidate_base_changed')


def publish(run,lease,binding):
    """Index only a fully verified fresh build while the shared lease is held."""
    lease._active()
    c.require(lease.run_id==run.id and not lease._reconciliation_only and
        lease.source_revision==run.manifest()['source_revision'] and
        run.workspace==images.RUNS_ROOT and 'reuse' not in binding,'candidate_cache_scope')
    platform='ubi' if binding.get('operation')=='ubi9-candidate-image-binding' else 'ubuntu'
    module=policy(platform);module.validate_binding(run,binding)
    if platform=='ubi':module.validate_origin(run)
    c.require(any(item['kind']=='image' and item['id']==binding['image_id'] and item['outcome']=='retained'
        for item in lease.record['resources']),'candidate_cache_scope')
    folder=images.INFRASTRUCTURE/'candidate-cache';folder.mkdir(mode=0o700,exist_ok=True);_owned(folder,directory=True)
    value={'operation':OPERATION,'cache_key':key(run,platform),'origin_run_id':run.id,
        'origin_binding_sha256':c.sha(c.canonical(binding)),'candidate_sha256':binding['candidate_sha256'],
        'image_id':binding['image_id'],'input_sha256':input_identity(run,platform)['input_sha256']}
    if platform=='ubi':value['platform']='ubi'
    atomic_json(index_path(run,platform),value)


def reuse(run,lease):
    lease._active()
    c.require(lease.run_id==run.id and not lease._reconciliation_only and
        lease.source_revision==run.manifest()['source_revision'] and run.workspace==images.RUNS_ROOT and
        c.source_identity()==(run.manifest()['source_revision'],False),'candidate_reuse_scope')
    selection=read_json(run.file(SELECTION));_,old=origin(run,selection)
    platform=selection.get('platform','ubuntu');module=policy(platform)
    binding_path,build_path,_=paths(platform);path=run.file(build_path)
    c.require(not path.exists() and not run.file(binding_path).exists(),'candidate_attempt_reused')
    record={**common(run.manifest()),'operation':OPERATION,'status':'pending',
        'candidate_sha256':old['candidate_sha256'],'builder_id':None,'image_id':None,
        'unknown_outcome':False,'primary_failure':None,'reuse':selection,
        'runtime_pipeline_complete':False,'production_iso_eligible':False,'updated_at':now()}
    atomic_json(path,record)
    try:
        actual=images.inspect('image',old['image_id'])
        module.verify_image(actual,old)
        c.require(type(actual.get('Size')) is int and actual['Size']>0,'candidate_image_mismatch')
        # Read-only verification precedes adopting this exact immutable image.
        # Image registration uses the existing materialization journal contract;
        # these phase reservations create no builder and perform no image commit.
        lease.set_phase('assembling')
        lease.set_phase('materializing')
        lease.register_resource('image',old['image_id'])
        lease.reconcile_resource('image',old['image_id'],outcome='retained',size_bytes=actual['Size'])
        if platform=='ubi':
            from . import rpm_target
            base=images.inspect('image',rpm_target.BASE_ID);rpm_target.verify_base(base,rpm_target.load_lock())
            c.require(type(base.get('Size')) is int and base['Size']>0,'candidate_image_mismatch')
            lease.register_resource('image',base['Id'])
            lease.reconcile_resource('image',base['Id'],outcome='retained',size_bytes=base['Size'])
        record.update(status='built',image_id=old['image_id'],updated_at=now());atomic_json(path,record)
        binding={**deepcopy(old),**common(run.manifest()),'reuse':selection}
        atomic_json(run.file(binding_path),binding)
        return validate_binding(run,binding)
    except BaseException as error:
        record.update(status='failed',primary_failure={'code':getattr(error,'code','candidate_reuse_failed'),'recorded_at':now()},updated_at=now())
        atomic_json(path,record);raise


def validate_binding(run,saved):
    selection=read_json(run.file(SELECTION));_,original=origin(run,selection)
    expected={**original,**common(run.manifest()),'reuse':selection}
    c.require(c.canonical(saved)==c.canonical(expected),'candidate_reuse_invalid')
    built=read_json(run.file(paths(selection.get('platform','ubuntu'))[1]))
    expected_fields=set(common(run.manifest()))|{'operation','status','candidate_sha256','builder_id','image_id',
        'unknown_outcome','primary_failure','reuse','runtime_pipeline_complete','production_iso_eligible','updated_at'}
    c.require(set(built)==expected_fields and c.bound_common(built,run.manifest()) and
        built['operation']==OPERATION and built['status']=='built' and built['candidate_sha256']==saved['candidate_sha256'] and
        built['builder_id'] is None and built['image_id']==saved['image_id'] and built['unknown_outcome'] is False and
        built['primary_failure'] is None and built['reuse']==selection and built['runtime_pipeline_complete'] is False and
        built['production_iso_eligible'] is False,'candidate_reuse_invalid')
    return deepcopy(saved)
