"""Fixed actual WORM-019 interruption before either completion marker exists.

Only this module's owned filesystem-only child exits at the source-defined
checkpoint. It does not interrupt any Docker/Terraform operation or repair a
partial destination. The fresh original reference pipeline owns its cleanup.
"""
import json
import os
import sys
from uuid import UUID

from . import candidate, images
from .pipeline_records import EXPORT_PATHS
from .provisioning_acceptance import error_code, snapshot
from .publication_acceptance import file_bytes, identity, release_files, cli_inspect
from .reference_acceptance import qualify_case
from .runs import Run, SOURCE_ROOT, read_json, source_identity
from .stages import _run_process

CHECKPOINT = 'private/isolation-publication-checkpoint.json'
CRASH_EXIT = 86
WORKER = '''import os,sys
from wormhole.images import RUNS_ROOT
from wormhole.publication import publish_reference
from wormhole.runs import Run,atomic_json
run=Run(RUNS_ROOT,sys.argv[1])
def checkpoint(event,metadata):
    if event == 'before-complete':
        atomic_json(run.file('private/isolation-publication-checkpoint.json'),
            {'event':event,'metadata':metadata,'publisher_pid':os.getpid()})
        os._exit(86)
publish_reference(run,checkpoint=checkpoint)
raise SystemExit(87)
'''


def require(value, code='isolation_publication_invalid'):
    candidate.require(value, code)


def validate_checkpoint(value, run_id):
    require(type(value) is dict and set(value) == {'event', 'metadata', 'publisher_pid'} and
        value['event'] == 'before-complete' and type(value['publisher_pid']) is int and
        value['publisher_pid'] > 1 and value['publisher_pid'] != os.getpid(), 'isolation_publication_checkpoint')
    metadata = value['metadata']
    require(type(metadata) is dict and set(metadata) == {'run_id', 'attempt_id', 'release_id'} and
        metadata['run_id'] == run_id and metadata['release_id'] == 'reference-' + run_id and
        type(metadata['attempt_id']) is str,
        'isolation_publication_checkpoint')
    try: valid = str(UUID(metadata['attempt_id'])) == metadata['attempt_id']
    except (ValueError, TypeError, AttributeError): valid = False
    require(valid, 'isolation_publication_checkpoint')
    return value


def _originals(run):
    paths = ('manifest.json', 'evidence/reference-acceptance.json',
        *('evidence/reference/' + name for name in EXPORT_PATHS),
        *('private/candidate/' + name for name in (*candidate.NAMES, 'manifest.json')))
    return {name: identity(file_bytes(run.file(name))) for name in paths}


def publication_case(sentinel_id, *, suite_run_id):
    from .pipeline import gate_pipeline
    from .publication import RELEASE_ROOT, initialize_publication_root, publish_reference
    require(sys.platform.startswith('linux') and type(sentinel_id) is str and
        candidate.IDENTIFIER.fullmatch(sentinel_id), 'isolation_publication_input')
    require(type(suite_run_id) is str and str(UUID(suite_run_id)) == suite_run_id,
        'isolation_publication_input')
    revision, dirty = source_identity()
    require(dirty is False, 'isolation_publication_source')
    initialize_publication_root()
    # The legacy qualifier requires a UUID even for Ubuntu; it never consults
    # that argument or supplies a UBI base to the Ubuntu pipeline.
    pipeline = qualify_case('ubuntu', 'healthy', sentinel_id, suite_run_id)
    run = Run(images.RUNS_ROOT, pipeline['run_id'])
    try:
        require(pipeline['status'] == 'passed' and pipeline['operation_status'] == 'passed' and
            pipeline['source_revision'] == revision and pipeline['source_dirty'] is False and
            pipeline['decision']['reference_eligible'] is True and pipeline['unrelated_sentinel_unchanged'] is True,
            'isolation_publication_pipeline')
        with images.docker_scope(run):
            sentinel_before = snapshot('container', sentinel_id, unrelated=True)
            with run.locked():
                before = _originals(run)
                decision = gate_pipeline(run)
            child = _run_process((sys.executable, '-B', '-c', WORKER, run.id), cwd=SOURCE_ROOT, timeout=60)
            require(child['returncode'] == CRASH_EXIT and child['status'] == 'fail' and
                child['log_truncated'] is False, 'isolation_publication_child')
            crash = validate_checkpoint(read_json(run.file(CHECKPOINT)), run.id)
            release = RELEASE_ROOT / ('reference-' + run.id)
            preserved = release_files(release)
            require('COMPLETE.json' not in preserved and '.COMPLETE.pending' not in preserved and
                not (release / 'COMPLETE.json').exists() and not (release / '.COMPLETE.pending').exists() and
                len(preserved) == 23 and all(row['links'] == 1 for row in preserved.values()),
                'isolation_publication_marker_present')
            inspection, cli = cli_inspect(run.id, 1)
            require(inspection['status'] == 'incomplete' and inspection['logical_complete'] is False,
                'isolation_publication_false_complete')
            refusal = None
            try: publish_reference(run)
            except Exception as error: refusal = error_code(error)
            require(refusal == 'publication_duplicate' and release_files(release) == preserved,
                'isolation_publication_overwrite')
            with run.locked():
                require(_originals(run) == before and gate_pipeline(run) == decision,
                    'isolation_publication_original_changed')
            require(snapshot('container', sentinel_id, unrelated=True) == sentinel_before,
                'isolation_publication_sentinel_changed')
        require(source_identity() == (revision, False), 'isolation_publication_source')
        return {'run_ids': [run.id], 'checks': {
            'same-source-reference-passed': True, 'before-complete-owned-child': True,
            'both-markers-absent': True, 'inspector-incomplete': True, 'duplicate-preserved': True,
            'original-evidence-unchanged': True, 'sentinel-unchanged': True},
            'proof': {'run_id': run.id, 'source_revision': revision, 'source_dirty': False,
                'pipeline': {name: pipeline[name] for name in ('status', 'operation_status', 'counts',
                    'decision', 'cli_gate', 'report_sha256', 'admission_resources', 'unrelated_sentinel_unchanged')},
                'reference_acceptance': identity(file_bytes(run.file('evidence/reference-acceptance.json'))),
                'original_files': before, 'checkpoint': crash, 'interrupted_output': preserved,
                'publisher_exit': child['returncode'], 'publisher_duration_seconds': child['duration_seconds'],
                'inspection': inspection, 'cli_inspection': cli, 'duplicate_refusal': refusal,
                'sentinel_before': sentinel_before, 'sentinel_after': sentinel_before,
                'image_published': False, 'remote_release': False, 'production_iso_eligible': False}}
    except BaseException as error:
        error.run_id = run.id
        raise
