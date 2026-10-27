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


def key(run):
    bundle=c.validate_bundle(run)
    return c.sha(c.canonical({'inputs':c.input_identity(bundle['manifest']['source_sha256']),
        'installed_manifest_contract':c.sha(c.canonical(c.test_contract()))}))


def index_path(run):
    return images.INFRASTRUCTURE/'candidate-cache'/(key(run)+'.json')


def origin(run, selection):
    fields=set(common(run.manifest()))|{'operation','cache_key','origin_run_id','origin_binding_sha256',
        'candidate_sha256','image_id','input_sha256'}
    c.require(type(selection) is dict and set(selection)==fields and c.bound_common(selection,run.manifest()) and
        selection['operation']==OPERATION and selection['cache_key']==key(run) and selection['origin_run_id']!=run.id,
        'candidate_reuse_invalid')
    # Run validates canonical UUID, ownership, links and the existing private store.
    old=Run(run.workspace,selection['origin_run_id'])
    saved=read_json(old.file('evidence/candidate-binding.json'))
    c.require('reuse' not in saved,'candidate_reuse_chain_refused')
    binding=c.validate_binding(old)
    c.require(read_json(old.file('evidence/candidate-build.json')).get('primary_failure') is None,'candidate_reuse_invalid')
    previous=read_json(old.file('evidence/candidate-inputs.json'))
    current=c.input_identity(c.validate_bundle(run)['manifest']['source_sha256'])
    previous={name:previous[name] for name in ('build_inputs','input_sha256')}
    c.require(c.compare_inputs(previous,current)['content_reusable'] and
        selection['input_sha256']==current['input_sha256'] and
        selection['origin_binding_sha256']==c.sha(c.canonical(binding)) and
        selection['candidate_sha256']==binding['candidate_sha256'] and selection['image_id']==binding['image_id'],
        'candidate_stale')
    # The old, immutable embedded manifest is the bytes actually installed.
    intended=c.validate_bundle(run)['manifest']
    c.require(all(binding['manifest'][name]==intended[name] for name in
        ('files','version','configuration','source_sha256','applicability','test_contract_sha256')),
        'candidate_stale')
    return old,binding


def select(run):
    """Read-only selection before the test plan freezes; no Docker allocation."""
    c.require(not run.file(SELECTION).exists(),'candidate_selection_reused')
    path=index_path(run)
    if not path.exists():return None
    index=read_json(path)
    c.require(type(index) is dict and set(index)=={'operation','cache_key','origin_run_id','origin_binding_sha256',
        'candidate_sha256','image_id','input_sha256'} and index['operation']==OPERATION and index['cache_key']==key(run),
        'candidate_cache_invalid')
    selection={**common(run.manifest()),**index}
    _,binding=origin(run,selection)
    atomic_json(run.file(SELECTION),selection)
    return binding['manifest']


def selected_manifest(run):
    if not run.file(SELECTION).exists():return None
    return origin(run,read_json(run.file(SELECTION)))[1]['manifest']


def publish(run,lease,binding):
    """Index only a fully verified fresh build while the shared lease is held."""
    lease._active()
    c.require(lease.run_id==run.id and not lease._reconciliation_only and
        lease.source_revision==run.manifest()['source_revision'] and
        run.workspace==images.RUNS_ROOT and 'reuse' not in binding,'candidate_cache_scope')
    c.validate_binding(run,binding)
    c.require(any(item['kind']=='image' and item['id']==binding['image_id'] and item['outcome']=='retained'
        for item in lease.record['resources']),'candidate_cache_scope')
    folder=images.INFRASTRUCTURE/'candidate-cache';folder.mkdir(mode=0o700,exist_ok=True);_owned(folder,directory=True)
    value={'operation':OPERATION,'cache_key':key(run),'origin_run_id':run.id,
        'origin_binding_sha256':c.sha(c.canonical(binding)),'candidate_sha256':binding['candidate_sha256'],
        'image_id':binding['image_id'],'input_sha256':c.input_identity(binding['manifest']['source_sha256'])['input_sha256']}
    atomic_json(index_path(run),value)


def reuse(run,lease):
    lease._active()
    c.require(lease.run_id==run.id and not lease._reconciliation_only and
        lease.source_revision==run.manifest()['source_revision'] and run.workspace==images.RUNS_ROOT and
        c.source_identity()==(run.manifest()['source_revision'],False),'candidate_reuse_scope')
    selection=read_json(run.file(SELECTION));_,old=origin(run,selection)
    path=run.file('evidence/candidate-build.json')
    c.require(not path.exists() and not run.file('evidence/candidate-binding.json').exists(),'candidate_attempt_reused')
    record={**common(run.manifest()),'operation':OPERATION,'status':'pending',
        'candidate_sha256':old['candidate_sha256'],'builder_id':None,'image_id':None,
        'unknown_outcome':False,'primary_failure':None,'reuse':selection,
        'runtime_pipeline_complete':False,'production_iso_eligible':False,'updated_at':now()}
    atomic_json(path,record)
    try:
        actual=images.inspect('image',old['image_id'])
        c.verify_image(actual,old)
        c.require(type(actual.get('Size')) is int and actual['Size']>0,'candidate_image_mismatch')
        # Read-only verification precedes adopting this exact immutable image.
        lease.register_resource('image',old['image_id'])
        lease.reconcile_resource('image',old['image_id'],outcome='retained',size_bytes=actual['Size'])
        record.update(status='built',image_id=old['image_id'],updated_at=now());atomic_json(path,record)
        binding={**deepcopy(old),**common(run.manifest()),'reuse':selection}
        atomic_json(run.file('evidence/candidate-binding.json'),binding)
        return validate_binding(run,binding)
    except BaseException as error:
        record.update(status='failed',primary_failure={'code':getattr(error,'code','candidate_reuse_failed'),'recorded_at':now()},updated_at=now())
        atomic_json(path,record);raise


def validate_binding(run,saved):
    selection=read_json(run.file(SELECTION));_,original=origin(run,selection)
    expected={**original,**common(run.manifest()),'reuse':selection}
    c.require(c.canonical(saved)==c.canonical(expected),'candidate_reuse_invalid')
    built=read_json(run.file('evidence/candidate-build.json'))
    expected_fields=set(common(run.manifest()))|{'operation','status','candidate_sha256','builder_id','image_id',
        'unknown_outcome','primary_failure','reuse','runtime_pipeline_complete','production_iso_eligible','updated_at'}
    c.require(set(built)==expected_fields and c.bound_common(built,run.manifest()) and
        built['operation']==OPERATION and built['status']=='built' and built['candidate_sha256']==saved['candidate_sha256'] and
        built['builder_id'] is None and built['image_id']==saved['image_id'] and built['unknown_outcome'] is False and
        built['primary_failure'] is None and built['reuse']==selection and built['runtime_pipeline_complete'] is False and
        built['production_iso_eligible'] is False,'candidate_reuse_invalid')
    return deepcopy(saved)
