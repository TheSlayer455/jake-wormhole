"""Four serial owned operations; actual execution is explicitly operator invoked."""
import argparse
import json
import re
import sys

from . import images, powershell as capability
from .provisioning_acceptance import snapshot
from .runs import Run, RunError, atomic_json, common, create_run, now, source_identity


def require(value, code):
    if not value: raise RunError(code, 'Optional capability acceptance failed; retain exact stage receipts and accounting.')


def new_run():
    return create_run(images.RUNS_ROOT, fixture=False, kernel_lock=True)


def ordinary_diagnostics(sentinel):
    from .validation_acceptance import qualify_case
    from .validation import report_validation
    value = qualify_case('healthy', sentinel)
    report = report_validation(Run(images.RUNS_ROOT, value['run_id']))
    require(value['status'] == 'pass' and report['result']['status'] == 'passed' and
        len(report['result']['checks']) == 10 and all(row['status'] == 'pass' and row['required'] is True
            for row in report['result']['checks']), 'independent_diagnostics_failed')
    return value


def acceptance(sentinel):
    require(sys.platform.startswith('linux') and type(sentinel) is str and re.fullmatch('[a-f0-9]{64}', sentinel), 'invalid_acceptance_context')
    revision = source_identity(); require(revision[1] is False, 'source_dirty')
    suite = new_run()
    value = {**common(suite.manifest()), 'component': 'optional-powershell-acceptance', 'status': 'pending',
        'stages': [], 'primary_failure': None, 'production_iso_eligible': False, 'runtime_pipeline_complete': False,
        'scanner_compatibility': 'unavailable-no-authorized-package-or-documented-method'}
    destination = suite.file('evidence/powershell-acceptance.json')
    used = {suite.id}
    with suite.locked(), images.docker_scope(suite):
        baseline = snapshot('container', sentinel, unrelated=True)
        atomic_json(destination, value)
        def guard():
            require(source_identity() == revision, 'source_changed')
            require(snapshot('container', sentinel, unrelated=True) == baseline, 'sentinel_changed')
        def record(name, result, expected):
            require(type(result) is dict and result.get('source_revision') == revision[0] and
                result.get('source_dirty') is False and result.get('status') == expected and
                type(result.get('run_id')) is str and result['run_id'] not in used, 'stage_identity_changed')
            used.add(result['run_id']); guard()
            value['stages'].append({'stage': name, 'run_id': result['run_id'], 'source_revision': result['source_revision'],
                'operation_status': result['status'], 'acceptance_status': 'passed'})
            value['updated_at'] = now(); atomic_json(destination, value)
        try:
            guard(); missing = new_run()
            result = capability.execute(missing, selection='missing-package-fixture')
            require(result.get('resources_reconciled') is True and result.get('unknown_outcome') is False and
                result.get('primary_failure') == {'code': 'package_unavailable'} and
                result.get('observation', {}).get('failure') == {'code': 'package_unavailable', 'package': 'powershell',
                    'expected_version': '7.6.8-1.deb', 'execution_location': 'optional-helper-package-source-fixture', 'returncode': 100},
                'missing_package_not_proved')
            record('missing-package-fixture', result, 'failed')
            guard(); normal = ordinary_diagnostics(sentinel)
            record('independent-ordinary-terraform-ssh-ansible', normal, 'pass')
            guard(); build = new_run()
            built = capability.execute(build, selection='powershell-helper')
            require(built.get('resources_reconciled') is True and built.get('unknown_outcome') is False and
                built.get('primary_failure') is None and built.get('image_id') != capability.BASE and
                type(built.get('image_id')) is str and re.fullmatch('sha256:[a-f0-9]{64}', built['image_id']) and
                built.get('base_reference', {}).get('image_id') == capability.BASE and
                built.get('base_reference', {}).get('source_revision') == capability.BASE_SOURCE and
                built.get('installed', {}).get('powershell', {}).get('version') == '7.6.8', 'optional_build_not_proved')
            record('offline-optional-image-build', built, 'completed')
            guard(); smoke = new_run()
            observed = capability.execute(smoke, selection='powershell-helper', build_run=build.id)
            powershell = observed.get('observation', {}).get('powershell', {})
            require(observed.get('resources_reconciled') is True and observed.get('unknown_outcome') is False and
                observed.get('primary_failure') is None and observed.get('image') == built['image_id'] and
                powershell.get('version') == '7.6.8' and powershell.get('edition') == 'Core' and
                powershell.get('platform') == 'Unix' and type(powershell.get('result')) is int and powershell['result'] == 2 and
                observed.get('observation', {}).get('ordinary_helper_doctor', {}).get('passed') is True,
                'optional_smoke_not_proved')
            record('fresh-optional-powershell-smoke', observed, 'completed')
            require(len(value['stages']) == 4 and len(used) == 5, 'incomplete_acceptance')
            guard(); value.update(status='passed', optional_image_id=built['image_id'], existing_sentinel_modified=False)
            atomic_json(destination, value)
            return value
        except BaseException as error:
            value.update(status='failed', primary_failure={'code': getattr(error, 'code', 'acceptance_interrupted')}, updated_at=now())
            atomic_json(destination, value)
            raise


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Explicit real optional capability acceptance, no scanner.')
    parser.add_argument('--sentinel-id', required=True)
    options = parser.parse_args(arguments)
    try:
        print(json.dumps(acceptance(options.sentinel_id), sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({'error': {'code': getattr(error, 'code', 'acceptance_failed')}, 'production_iso_eligible': False})); return 2


if __name__ == '__main__': raise SystemExit(main())
