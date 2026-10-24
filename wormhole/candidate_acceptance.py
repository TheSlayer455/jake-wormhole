"""Reviewed explicit one-target candidate acceptance; never run on import.

Only the operator invokes this on the approved Linux host. Four fresh serial
Runs preserve negative primary outcomes and exact unrelated sentinel identity.
"""
import argparse
from copy import deepcopy
import json
import os
import sys
from uuid import UUID

from . import candidate as c, chunks, images
from .admission import AdmissionLease
from .candidate_validation import CandidateValidationSession, report_candidate_validation
from .provisioning import ProvisioningSession, TARGET_IMAGE
from .provisioning_acceptance import snapshot, scan_private_material, disk_sample, error_code
from .readiness import ReadinessSession
from .recovery import cleanup_session
from .runs import RunError, atomic_json, common, create_run, now, read_json, source_identity
from .stages import execute_run

CASES = ('healthy', 'wrong-candidate', 'wrong-image', 'version-expectation-mismatch')
EXPECTED = {'wrong-candidate': 'candidate_binding_invalid', 'wrong-image': 'candidate_image_mismatch',
            'version-expectation-mismatch': 'candidate_required_check_mismatch'}


def sweep(run):
    for args in (('ps', '-a', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + run.id, '--format', '{{.ID}}'),
                 ('network', 'ls', '--no-trunc', '--filter', 'label=' + images.LABEL + '.run_id=' + run.id, '--format', '{{.ID}}')):
        result = images.docker(args)
        c.require(not result['log_truncated'] and not result['log'].strip(), 'candidate_resources_remain')


def reconcile_image_phase(run, lease, binding):
    """Known completed derivation with no Terraform/helper allocation only."""
    binding = c.validate_binding(run, binding)
    built = read_json(run.file('evidence/candidate-build.json'))
    c.require(c.bound_common(built, run.manifest()) and built['unknown_outcome'] is False and built['status'] == 'built' and
        not run.file('private/terraform/controller.json').exists() and not run.file('private/readiness-controller.json').exists(),
        'candidate_image_phase_unresolved')
    resources = lease.record['resources']
    c.require(len(resources) == 2 and {(item['kind'], item['id'], item['outcome']) for item in resources} ==
        {('container', built['builder_id'], 'absent'), ('image', binding['image_id'], 'retained')}, 'candidate_image_phase_unresolved')
    c.require(images.inspect('container', built['builder_id'], missing=True) is None, 'candidate_builder_remains')
    c.verify_image(images.inspect('image', binding['image_id']), binding)
    sweep(run)
    return {'status': 'completed', 'terraform_or_helper_allocated': False,
        'resources': deepcopy(resources), 'private_state_removed': False, 'retained_candidate_image': binding['image_id']}


def qualify_case(scenario, sentinel):
    c.require(scenario in CASES and type(sentinel) is str and c.IDENTIFIER.fullmatch(sentinel), 'candidate_acceptance_input')
    revision, dirty = source_identity(); c.require(os.name == 'posix' and dirty is False, 'candidate_acceptance_source')
    run = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    result = {**common(run.manifest()), 'operation': 'real-candidate-acceptance', 'scenario': scenario, 'status': 'running',
        'phase': 'source', 'created_at': now(), 'iso_processing': 'none', 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    atomic_json(run.file('evidence/candidate-acceptance.json'), result)
    session = readiness = binding = None
    try:
        with run.locked(): execute_run(run)  # Full runtime pipeline remains unsupported.
        component = chunks.execute_fixture(run, transport='local', scenario='healthy')
        c.require(component['status'] == 'passed', 'candidate_source_unverified')
        images.create_auth(run)
        with run.locked(), images.docker_scope(run), AdmissionLease(images.INFRASTRUCTURE, run.id, revision, 'smoke') as lease:
            before = snapshot('container', sentinel, unrelated=True)
            bundle = c.prepare_candidate(run)
            result['phase'] = 'derive-image'; atomic_json(run.file('evidence/candidate-acceptance.json'), result)
            binding = c.build_candidate(run, lease, bundle)
            result.update(candidate_sha256=binding['candidate_sha256'], source_sha256=binding['manifest']['source_sha256'],
                chunk_manifest_sha256=binding['manifest']['chunk_manifest_sha256'], derived_image=binding['image_id'],
                stock_base_image=binding['base_image'], test_contract_sha256=binding['test_contract_sha256'])
            result['phase'] = 'bind-or-provision'; atomic_json(run.file('evidence/candidate-acceptance.json'), result)
            observed = None
            if scenario in {'wrong-candidate', 'wrong-image'}:
                try:
                    if scenario == 'wrong-candidate':
                        altered = deepcopy(binding); altered['candidate_sha256'] = '0' * 64
                        c.require(altered['candidate_sha256'] != binding['candidate_sha256'], 'candidate_negative_collision')
                        ProvisioningSession(run, lease, target_binding=altered)
                    else:
                        # Actual immutable stock image metadata cannot qualify this candidate.
                        c.verify_image(images.inspect('image', TARGET_IMAGE), binding)
                except c.CandidateError as error: observed = error.code
                c.require(observed == EXPECTED[scenario], 'candidate_negative_not_observed')
                refusal = {**common(run.manifest()), 'operation': 'candidate-identity-refusal', 'status': 'failed',
                    'primary_failure': {'code': observed, 'recorded_at': now()}, 'terraform_or_helper_allocated': False,
                    'candidate_sha256': binding['candidate_sha256'], 'target_image': binding['image_id']}
                atomic_json(run.file('evidence/candidate-refusal.json'), refusal)
                cleanup = reconcile_image_phase(run, lease, binding)
            else:
                session = ProvisioningSession(run, lease, target_binding=binding)
                session.provision()
                result['phase'] = 'ssh-ansible'; atomic_json(run.file('evidence/candidate-acceptance.json'), result)
                c.require(sentinel not in {session.provisioner, *session.owned.values()}, 'candidate_sentinel_is_owned')
                readiness = ReadinessSession(session, validation=True)
                readiness.start_helper(); readiness.wait_ready(); readiness.require_ready()
                validation = CandidateValidationSession(readiness, binding, scenario=scenario)
                try: validation.validate()
                except c.CandidateError as error: observed = error.code
                c.require(observed == EXPECTED.get(scenario), 'candidate_unexpected_outcome')
                report = report_candidate_validation(run)
                c.require(report['result'] == validation.receipt and len(report['result']['checks']) == len(c.CHECKS), 'candidate_report_mismatch')
                if scenario == 'healthy':
                    c.require(report['result']['status'] == 'passed' and all(item['status'] == 'pass' for item in report['result']['checks']), 'candidate_checks_incomplete')
                else:
                    c.require(report['result']['status'] == 'failed' and session.receipt['primary_failure']['code'] == EXPECTED[scenario] and
                        [item['check_id'] for item in report['result']['checks'] if item['status'] != 'pass'] == ['candidate-version'], 'candidate_negative_not_observed')
                result.update(target_resource_id=session.target_resources['target-001'], network_id=session.network_id,
                    validation_plan_sha256=validation.plan['plan_sha256'], checks=deepcopy(report['result']['checks']))
                cleanup = cleanup_session(session, lease, helper=readiness, reason='failure' if observed else 'success')
                c.require(cleanup['status'] == 'completed' and cleanup['unknown_outcome'] is False and
                    (cleanup['primary_failure'] is None if observed is None else cleanup['primary_failure']['code'] == observed), 'candidate_cleanup_failed')
                sweep(run)
            result.update(credential_scan=scan_private_material(run), disk_sample=disk_sample(run, 'candidate-cleaned'))
            c.require(snapshot('container', sentinel, unrelated=True) == before, 'candidate_sentinel_changed')
            c.require(source_identity() == (revision, False) and common(run.manifest())['source_revision'] == revision, 'candidate_acceptance_source')
            result.update(status='passed', phase='completed', operation_status='failed' if observed else 'passed', failure_code=observed,
                cleanup=cleanup, unrelated_sentinel_unchanged=True, finished_at=now())
            atomic_json(run.file('evidence/candidate-acceptance.json'), result)
            lease.finish(reconciliation_complete=True)
        return result
    except BaseException as error:
        result.update(status='failed', error_code=error_code(error), finished_at=now())
        # Attempt normal exact cleanup only for known established provisioning.
        # Unknown build/daemon work remains active; never adopt, prune or retry.
        if session is not None:
            try:
                from .recovery import recover_run
                result['failure_cleanup'] = recover_run(run)
            except Exception: pass
        elif run.file('evidence/candidate-build.json').exists():
            try:
                from .candidate_recovery import recover_preallocation
                result['failure_cleanup'] = recover_preallocation(run)
            except Exception: pass  # Nonempty/uncertain image phases remain active; no fallback.
        atomic_json(run.file('evidence/candidate-acceptance.json'), result)
        error.run_id = run.id
        raise


def acceptance(sentinel):
    revision = source_identity(); c.require(revision[1] is False, 'candidate_acceptance_source')
    suite = create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)
    result = {**common(suite.manifest()), 'operation': 'real-candidate-acceptance-suite', 'suite_run_id': suite.id,
        'status': 'running', 'cases': [], 'pending_scenario': None, 'iso_processing': 'none', 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    def save(): atomic_json(suite.file('evidence/candidate-acceptance-suite.json'), result)
    with suite.locked():
        save()
        value = None
        try:
            c.require(suite.manifest()['source_revision'] == revision[0] and suite.manifest()['source_dirty'] is False, 'candidate_acceptance_source')
            for scenario in CASES:
                value = None  # A refusal before this child exists must not blame the preceding successful child.
                c.require(source_identity() == revision, 'candidate_acceptance_source')
                result['pending_scenario'] = scenario; save()
                value = qualify_case(scenario, sentinel)
                c.require(value['status'] == 'passed' and value['source_revision'] == revision[0] and value['source_dirty'] is False and
                    value['scenario'] == scenario and str(UUID(value['run_id'])) == value['run_id'] and
                    type(value['derived_image']) is str and c.IMAGE.fullmatch(value['derived_image']) and
                    source_identity() == revision, 'candidate_acceptance_source')
                c.require(value['run_id'] != suite.id and value['run_id'] not in {item['run_id'] for item in result['cases']} and
                    value['derived_image'] not in {item['derived_image'] for item in result['cases']}, 'candidate_runs_not_isolated')
                result['cases'].append(value); result['pending_scenario'] = None; save()
            c.require(len({item['run_id'] for item in result['cases']}) == len(CASES) and
                len({item['derived_image'] for item in result['cases']}) == len(CASES), 'candidate_runs_not_isolated')
            result['status'] = 'passed'; save(); return result
        except BaseException as error:
            if not hasattr(error, 'run_id') and value is not None: error.run_id = value.get('run_id')
            result.update(status='failed', failed_child_run_id=getattr(error, 'run_id', None), error_code=error_code(error)); save()
            error.suite_run_id = suite.id
            raise


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Explicit approved-host candidate qualification; real capped Docker/TF/SSH/Ansible.')
    parser.add_argument('--sentinel', required=True); parser.add_argument('--case', choices=CASES, default='healthy'); parser.add_argument('--all', action='store_true')
    options = parser.parse_args(arguments)
    try:
        value = acceptance(options.sentinel) if options.all else qualify_case(options.case, options.sentinel)
        print(json.dumps(value, sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({'error': {'code': error_code(error)}, 'run_id': getattr(error, 'run_id', None),
            'suite_run_id': getattr(error, 'suite_run_id', None), 'private_evidence_retained': True})); return 1


if __name__ == '__main__': raise SystemExit(main())
