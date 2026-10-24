"""Fixed UBI9 application of the same verified four-file reference candidate.

This is an explicit platform contract, not a replacement for Ubuntu defaults.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from . import candidate as c, images, rpm_target as t
from .contracts import _bounded_json, _validate
from .runs import SOURCE_ROOT, atomic_bytes, atomic_json, common, read_json, source_identity

CONTEXT = SOURCE_ROOT / 'rpm'
PACKAGES = ('python3','openssh','openssh-server','shadow-utils')
PACKAGE_VERSIONS = {'python3':{'epoch':0,'version':'3.9.25','release':'7.el9_8.3','arch':'x86_64'},
    'openssh':{'epoch':0,'version':'9.9p1','release':'13.el9_8','arch':'x86_64'},
    'openssh-server':{'epoch':0,'version':'9.9p1','release':'13.el9_8','arch':'x86_64'},
    'shadow-utils':{'epoch':2,'version':'4.9','release':'16.el9','arch':'x86_64'}}
APPLICABILITY = {'distribution':'Red Hat Universal Base Image','family':'ubi9','os_id':'rhel','os_version':'9.8',
    'platform':'linux/amd64','container_only':True}
CHECKS = ('rpm-userland','rpm-python3','rpm-openssh','rpm-openssh-server','rpm-shadow-utils',
    'candidate-source-sha256','candidate-manifest-sha256','candidate-content-sha256','candidate-payload-sha256',
    'candidate-version','candidate-configuration','candidate-function')
OPTIONAL = 'rpm-openssh-clients'
ASSEMBLY_FILES = ('assembly.json','assemble.py','probe.py','resolve.py','lock.json')
MANIFEST = deepcopy(c.MANIFEST)
MANIFEST['properties'].update({
    'operation':{'type':'string','const':'ubi9-reference-candidate'},
    'applicability':c.obj({key:{'type':type(value).__name__ if type(value) is not bool else 'boolean','const':value}
                         for key,value in APPLICABILITY.items()}),
    'source_candidate_manifest':deepcopy(c.MANIFEST), 'source_candidate_sha256':c.SHA, 'content_sha256':c.SHA,
    'base_reference':{'type':'string','const':t.BASE},'base_image':{'type':'string','const':t.BASE_ID},
    'packages':c.obj({name:c.obj({key:{'type':'integer','const':value,'minimum':value,'maximum':value} if type(value) is int else {'type':'string','const':value}
                                 for key,value in PACKAGE_VERSIONS[name].items()}) for name in PACKAGES})})
for field in ('source_candidate_manifest','source_candidate_sha256','content_sha256','base_reference','base_image','packages'):
    MANIFEST['required'].append(field)
# JSON Schema uses string, not Python's str type name.
for value in MANIFEST['properties']['applicability']['properties'].values():
    if value['type']=='str':value['type']='string'


def content_identity(manifest):
    return c.sha(c.canonical({'files':manifest['files']}))


def test_contract():
    from validation.runtime import RPM_PROGRAM
    return {'schema_version':'1.0','collector':'fixed-ssh-ansible-rpm-candidate-v1',
        'collector_sha256':c.sha(RPM_PROGRAM.encode()),'checks':list(CHECKS),'optional_failure_check':OPTIONAL,
        'packages':deepcopy(PACKAGE_VERSIONS),'applicability':deepcopy(APPLICABILITY),
        'iso_processing':'none','production_iso_eligible':False}


def schema():
    return {'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:jake-wormhole:ubi-candidate-manifest:1.0',
        'title':'Fixed UBI9 reference installation manifest v1',**deepcopy(MANIFEST)}


def validate_manifest(value):
    try:
        _bounded_json(value);_validate(MANIFEST,value,'$')
        original=c.validate_manifest(value['source_candidate_manifest'])
        t.require(value['mode']=='container-reference' and value['source_dirty'] is False and
            c.canonical(common(value))==c.canonical(common(original)) and
            value['source_candidate_sha256']==c.sha(c.canonical(original)) and
            value['content_sha256']==content_identity(original) and value['files']==original['files'] and
            all(value[key]==original[key] for key in ('version','configuration','source_sha256','chunk_plan_sha256','chunk_manifest_sha256')) and
            value['test_contract_sha256']==c.sha(c.canonical(test_contract())), 'rpm_candidate_manifest_invalid')
    except (ValueError,TypeError,KeyError,RecursionError):
        raise t.RpmError('rpm_candidate_manifest_invalid','A complete fixed UBI installation manifest is required.') from None
    return value


def prepare_manifest(run):
    bundle=c.validate_bundle(run);original=bundle['manifest']
    value=deepcopy(original);value.update(operation='ubi9-reference-candidate',applicability=deepcopy(APPLICABILITY),
        source_candidate_manifest=original,source_candidate_sha256=bundle['candidate_sha256'],content_sha256=content_identity(original),
        base_reference=t.BASE,base_image=t.BASE_ID,packages=deepcopy(PACKAGE_VERSIONS),
        test_contract_sha256=c.sha(c.canonical(test_contract())))
    validate_manifest(value)
    directory=run.file('private/rpm-candidate');directory.mkdir(mode=0o700)
    for record in value['files']:
        raw=c.bounded_file(bundle['directory']/record['path']);atomic_bytes(directory/record['path'],raw,limit=c.MAX_BUNDLE)
    atomic_bytes(directory/'manifest.json',c.canonical(value),limit=32768)
    atomic_json(run.file('evidence/rpm-candidate-manifest.json'),value)
    return validate_bundle(run)


def validate_bundle(run):
    value=validate_manifest(read_json(run.file('evidence/rpm-candidate-manifest.json')))
    t.require(c.bound_common(value,run.manifest()),'rpm_candidate_source_changed')
    original=c.validate_bundle(run)
    t.require(value['source_candidate_sha256']==original['candidate_sha256'],'rpm_candidate_source_changed')
    directory=run.file('private/rpm-candidate')
    t.require(set(path.name for path in directory.iterdir())==set(c.NAMES)|{'manifest.json'},'rpm_candidate_file_set')
    t.require(c.bounded_file(directory/'manifest.json',32768)==c.canonical(value),'rpm_candidate_manifest_changed')
    for record in value['files']:
        raw=c.bounded_file(directory/record['path'])
        t.require((len(raw),c.sha(raw))==(record['size'],record['sha256']) and raw==c.bounded_file(original['directory']/record['path']), 'rpm_candidate_file_changed')
    return {'manifest':value,'candidate_sha256':c.sha(c.canonical(value)),'directory':directory}


def recipe_identity():
    files={}
    for name in ASSEMBLY_FILES:
        path=images.safe_bind(CONTEXT/name)
        t.require(path.is_file() and 1<=path.stat().st_size<=65536,'rpm_assembly_source_invalid')
        files['rpm/'+name]=c.sha(path.read_bytes())
    for name in ('runtime.py','sshd_config'):
        path=images.safe_bind(SOURCE_ROOT/'images'/name);files['images/'+name]=c.sha(path.read_bytes())
    files['candidate/install.py']=c.sha((SOURCE_ROOT/'candidate/install.py').read_bytes())
    return c.sha(c.canonical(files)),files


def binding_labels(run, manifest, recipe):
    return {**t.load_lock()['base']['labels'],images.LABEL+'.run_id':run.id,
        images.LABEL+'.source_revision':run.manifest()['source_revision'],images.LABEL+'.role':'target',
        images.LABEL+'.rpm_recipe_sha256':recipe,images.LABEL+'.candidate_sha256':c.sha(c.canonical(manifest)),
        images.LABEL+'.candidate_content_sha256':manifest['content_sha256']}


def validate_binding(run, value=None, *, artifacts=True):
    saved=read_json(run.file('evidence/rpm-candidate-binding.json'));_bounded_json(saved)
    fields=set(common(run.manifest()))|{'operation','status','candidate_sha256','content_sha256','source_candidate_sha256','manifest',
        'base_image','image_id','image_labels','recipe_sha256','source_files','test_contract_sha256','runtime_pipeline_complete','production_iso_eligible'}
    t.require(type(saved) is dict and set(saved)==fields and c.bound_common(saved,run.manifest()) and
        saved['operation']=='ubi9-candidate-image-binding' and saved['status']=='built' and saved['base_image']==t.BASE_ID and
        type(saved['image_id']) is str and c.IMAGE.fullmatch(saved['image_id']) and
        saved['runtime_pipeline_complete'] is False and saved['production_iso_eligible'] is False,'rpm_candidate_binding_invalid')
    manifest=validate_manifest(saved['manifest'])
    names={'rpm/'+name for name in ASSEMBLY_FILES}|{'images/runtime.py','images/sshd_config','candidate/install.py'}
    t.require(c.bound_common(manifest,run.manifest()) and saved['candidate_sha256']==c.sha(c.canonical(manifest)) and
        saved['content_sha256']==manifest['content_sha256'] and saved['source_candidate_sha256']==manifest['source_candidate_sha256'] and
        saved['test_contract_sha256']==manifest['test_contract_sha256'] and type(saved['source_files']) is dict and set(saved['source_files'])==names and
        all(type(value) is str and t.SHA.fullmatch(value) for value in saved['source_files'].values()) and
        saved['recipe_sha256']==c.sha(c.canonical(saved['source_files'])) and
        saved['image_labels']==binding_labels(run,manifest,saved['recipe_sha256']), 'rpm_candidate_binding_invalid')
    record=read_json(run.file('evidence/rpm-candidate-build.json'))
    t.require(c.bound_common(record,run.manifest()) and record['operation']=='ubi9-candidate-build' and record['status']=='built' and
        record['unknown_outcome'] is False and record['primary_failure'] is None and record['image_id']==saved['image_id'] and
        record['candidate_sha256']==saved['candidate_sha256'] and record['recipe_sha256']==saved['recipe_sha256'] and
        record['source_files']==saved['source_files'], 'rpm_candidate_binding_invalid')
    if artifacts:
        t.require(source_identity()==(run.manifest()['source_revision'],False) and recipe_identity()==(saved['recipe_sha256'],saved['source_files']) and
            validate_bundle(run)['candidate_sha256']==saved['candidate_sha256'],'rpm_candidate_source_changed')
    if value is not None:t.require(c.canonical(value)==c.canonical(saved),'rpm_candidate_binding_mismatch')
    return saved


IMAGE_ENV=('HOME=/tmp','PATH=/usr/sbin:/usr/bin:/sbin:/bin','LANG=C','container=oci')


def clean_image_environment(value):
    return type(value) is list and len(value)==len(IMAGE_ENV) and all(type(item) is str for item in value) and set(value)==set(IMAGE_ENV)


def verify_image(actual,binding):
    t.require(actual.get('Id')==binding['image_id'] and actual.get('Parent')==t.BASE_ID and actual.get('Os')=='linux' and
        actual.get('Architecture')=='amd64' and actual.get('Config',{}).get('Labels')==binding['image_labels'] and
        actual['Config'].get('User')=='0:0' and actual['Config'].get('WorkingDir')=='/home/wormhole' and
        actual['Config'].get('Entrypoint')==['/usr/bin/python3','/opt/wormhole/runtime.py'] and
        actual['Config'].get('Cmd')==['target'] and clean_image_environment(actual['Config'].get('Env')) and
        not actual['Config'].get('Volumes'),'rpm_candidate_image_mismatch')


def build_rpm_candidate(run,lease,*,base_run):
    from .rpm_assembly import build
    return build(run,lease,base_run=base_run)
