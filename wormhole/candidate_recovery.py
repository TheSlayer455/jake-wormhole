"""Known failed, zero-allocation candidate recovery; no Docker mutation or adoption."""
import argparse
from copy import deepcopy
import json
import os
from uuid import uuid4

from . import candidate as c, images
from .admission import AdmissionLease
from .recovery import valid_failure, _timestamp
from .runs import Run, atomic_json, common, now, read_json, source_identity


def reconcile_preallocation(run, lease):
    """Caller holds exact original-source Run/Docker scopes and resumed lease."""
    lease._active(finalizing=True)
    manifest = run.manifest(); revision, dirty = source_identity()
    c.require(os.name == 'posix' and run.workspace == images.RUNS_ROOT and lease.root == images.INFRASTRUCTURE and
        manifest['mode'] == 'container-reference' and manifest['profile'] == 'smoke' and manifest['source_dirty'] is False and
        revision == manifest['source_revision'] and dirty is False and lease._reconciliation_only and lease.run_id == run.id and
        lease.source_revision == revision and lease.plan['profile'] == 'smoke' and lease.plan['synthetic'] is False and
        lease.record['resources'] == [] and ((lease.record['state'] == 'active' and lease.record['phase'] == 'reserved') or
        (lease.record['state'] == 'finished' and lease.record['phase'] == 'reconciling')), 'candidate_preallocation_scope')
    built = read_json(run.file('evidence/candidate-build.json'))
    fields = set(common(manifest)) | {'operation', 'status', 'candidate_sha256', 'builder_id', 'image_id', 'unknown_outcome',
        'primary_failure', 'daemon_materialization_cgroup_capped', 'runtime_pipeline_complete', 'production_iso_eligible', 'updated_at'}
    c.require(type(built) is dict and set(built) == fields and c.bound_common(built, manifest) and
        built['operation'] == 'candidate-image-build' and built['status'] == 'failed' and
        built['unknown_outcome'] is False and built['builder_id'] is None and built['image_id'] is None and
        built['primary_failure'] is not None and valid_failure(built['primary_failure']) and
        _timestamp(built['updated_at']) and
        built['daemon_materialization_cgroup_capped'] is False and built['runtime_pipeline_complete'] is False and
        built['production_iso_eligible'] is False, 'candidate_preallocation_scope')
    bundle = c.validate_bundle(run)
    c.require(built['candidate_sha256'] == bundle['candidate_sha256'] and
        not run.file('evidence/candidate-binding.json').exists() and
        not run.file('private/readiness-controller.json').exists() and
        not run.file('evidence/provisioning.json').exists() and
        not any(run.file('private/terraform').iterdir()), 'candidate_preallocation_scope')
    sweeps = []
    for kind, args in (
        ('container', ('ps', '-a', '--no-trunc')),
        ('network', ('network', 'ls', '--no-trunc')),
        ('image', ('image', 'ls', '--all', '--no-trunc')),
        ('volume', ('volume', 'ls'))):
        result = images.docker((*args, '--filter', 'label=' + images.LABEL + '.run_id=' + run.id,
            '--format', '{{.Name}}' if kind == 'volume' else '{{.ID}}'))
        c.require(result['log_truncated'] is False and type(result['log']) is bytes and result['log'].strip() == b'', 'candidate_preallocation_resources')
        sweeps.append({'kind': kind, 'status': 'observed-empty'})
    proof = {**common(manifest), 'operation': 'candidate-preallocation-recovery', 'attempt_id': str(uuid4()),
        'status': 'reconciled', 'primary_failure': deepcopy(built['primary_failure']), 'candidate_sha256': built['candidate_sha256'],
        'resources': [], 'read_only_sweeps': sweeps, 'unknown_outcome': False, 'private_state_removed': False,
        'runtime_pipeline_complete': False, 'production_iso_eligible': False, 'updated_at': now()}
    folder = run.file('evidence/candidate-recovery-attempts')
    if not folder.exists(): folder.mkdir(mode=0o700)
    def save():
        atomic_json(folder / (proof['attempt_id'] + '.json'), proof)
        atomic_json(run.file('evidence/candidate-preallocation-recovery.json'), proof)
    save()
    lease.finish(reconciliation_complete=True)  # Durable archive first; no journal edits or phase override.
    proof['status'] = 'completed'; proof['updated_at'] = now(); save()
    return deepcopy(proof)


def recover_preallocation(run):
    """Public exact-source entrypoint. Existing owned storage only, no allocation."""
    manifest = run.manifest()
    c.require(os.name == 'posix' and run.workspace == images.RUNS_ROOT and manifest['mode'] == 'container-reference' and
        manifest['profile'] == 'smoke' and manifest['source_dirty'] is False and
        source_identity() == (manifest['source_revision'], False), 'candidate_preallocation_scope')
    with run.locked(), images.docker_scope(run), AdmissionLease.resume(images.INFRASTRUCTURE,
            run.id, manifest['source_revision'], manifest['profile']) as lease:
        return reconcile_preallocation(run, lease)


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Recover only an exact original-source failed candidate with zero allocations.')
    parser.add_argument('run_id'); options = parser.parse_args(arguments)
    try:
        print(json.dumps(recover_preallocation(Run(images.RUNS_ROOT, options.run_id)), sort_keys=True)); return 0
    except Exception as error:
        from .provisioning_acceptance import error_code
        print(json.dumps({'error': {'code': error_code(error)}, 'run_id': options.run_id, 'state_preserved': True})); return 1


if __name__ == '__main__': raise SystemExit(main())
