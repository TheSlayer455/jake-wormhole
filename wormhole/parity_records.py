"""Closed synthetic manual/CI parity projections; no filesystem or execution.

The core proves original component replay. This module checks its declared grid,
preserves domain values, and normalizes only four explicitly named volatile
fields. Export validation proves safe bytes/contracts, not successful execution.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re

from .contracts import ContractError, _bounded_json, _validate
from .runs import RunError

FILES = ('plan.json', 'results.json', 'decision.json', 'execution.json', 'checksums.json')
MODES = ('all', 'required-failure', 'unexpected-success')
CHECK_IDS = ('execution', 'report-replay', 'domain-result', 'cleanup')
SCENARIOS = ('healthy', 'missing', 'duplicate', 'reordered', 'truncated', 'corrupted')
FINDING_IDS = ('fixture-alpha', 'fixture-beta', 'fixture-gamma', 'fixture-delta')
FINDING_STATUSES = ('Open', 'Not a Finding', 'Not Reviewed', 'Not Applicable')
MAX_FILE_BYTES = 262144
MAX_TOTAL_BYTES = 1048576


class ParityRecordError(RunError):
    pass


def require(value, code='parity_record_invalid'):
    if not value:
        raise ParityRecordError(code, 'Synthetic parity data refused; preserve the original controlled outcome.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same(a, b):
    return canonical(a) == canonical(b)


def obj(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def text(maximum=512, minimum=1, **extra):
    return {'type': 'string', 'minLength': minimum, 'maxLength': maximum, **extra}


def enum(*values):
    return {'type': 'string', 'enum': list(values)}


def const(value):
    return {'type': 'boolean' if type(value) is bool else 'string', 'const': value}


def integer(maximum, minimum=0):
    return {'type': 'integer', 'minimum': minimum, 'maximum': maximum}


def array(items, maximum, minimum=0):
    return {'type': 'array', 'items': items, 'minItems': minimum, 'maxItems': maximum}


def nullable(value):
    result = deepcopy(value); result['type'] = [value['type'], 'null']
    if 'enum' in result: result['enum'].append(None)
    return result


SHA = text(64, pattern=r'^[a-f0-9]{64}$(?![\s\S])')
UUID = text(36, format='uuid', pattern=r'^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$(?![\s\S])')
CODE = text(80, pattern=r'^[a-z][a-z0-9_-]{0,79}$(?![\s\S])')
DATE = text(32, format='date-time', pattern=r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$(?![\s\S])')
COMMON = {'schema_version': const('1.0'), 'source_revision': text(40, pattern=r'^[a-f0-9]{40}$(?![\s\S])'),
          'source_dirty': const(False), 'mode': enum(*MODES), 'synthetic': const(True)}
FLAGS = {'reference_eligible': const(False), 'production_iso_eligible': const(False)}
CASE_PLAN = obj({'case_id': CODE, 'component': enum('chunks', 'assessment'),
    'transport': nullable(enum('local', 'http-loopback')), 'scenario': CODE,
    'expected_status': enum('passed', 'rejected', 'failed'), 'expected_exit_code': integer(2),
    'expected_error_code': nullable(CODE), 'required': const(True), 'check_ids': array(CODE, 4, 4)})
PLAN = obj({**COMMON, 'operation': const('synthetic-parity-plan-v1'), 'cases': array(CASE_PLAN, 17, 17),
            **FLAGS, 'plan_sha256': SHA})
CHECK = obj({'check_id': CODE, 'required': const(True), 'expected': text(),
             'observed': nullable(text(512, 0)), 'status': enum('pass', 'fail', 'unverified')})
DETAILS = obj({'input_sha256': nullable(SHA), 'output_sha256': nullable(SHA),
    'checked_chunks': array(obj({'index': integer(4), 'size': integer(65536, 1), 'sha256': SHA}), 5),
    'findings': array(obj({'finding_id': CODE, 'status': enum(*FINDING_STATUSES), 'summary': text(),
                          'applicable': {'type': 'boolean'}, 'reason': text(512, 0)}), 4),
    'counts': nullable(obj({status: integer(4) for status in FINDING_STATUSES})),
    'policy_verdict': nullable(enum('pass', 'reject'))})
CLEANUP = obj({'status': enum('completed', 'failed', 'not-started'), 'private_removed': {'type': 'boolean'}})
CASE = obj({'case_id': CODE, 'run_id': nullable(UUID), 'updated_at': DATE,
    'duration_seconds': {'type': 'number', 'minimum': 0, 'maximum': 60}, 'loopback_port': nullable(integer(65535, 1)),
    'status': enum('passed', 'failed', 'not-run'), 'actual_status': enum('passed', 'rejected', 'failed', 'unverified'),
    'component_cli_exit_code': nullable(integer(2)), 'exit_code_kind': const('domain-cli-contract-mapping'),
    'error_code': nullable(CODE), 'checks': array(CHECK, 4, 4), 'details': DETAILS, 'cleanup': CLEANUP})
NORMAL_CASE = deepcopy(CASE)
NORMAL_CASE['properties'].update(run_id=nullable(text(100)), updated_at=const('normalized-time'),
    duration_seconds=const('normalized-duration'), loopback_port=nullable(enum('normalized-loopback-port')))
FAILURE = nullable(obj({'code': CODE, 'case_id': nullable(CODE)}))
RECORD = obj({**COMMON, 'operation': const('synthetic-parity-results-v1'), 'plan_sha256': SHA,
    'status': enum('passed', 'failed'), 'cases': array(CASE, 17, 17), 'primary_failure': FAILURE,
    'cleanup': obj({'status': enum('completed', 'failed'), 'private_removed': {'type': 'boolean'}}), **FLAGS})
NORMAL_RECORD = deepcopy(RECORD); NORMAL_RECORD['properties']['cases'] = array(NORMAL_CASE, 17, 17)
DECISION = obj({**COMMON, 'operation': const('synthetic-parity-decision-v1'), 'plan_sha256': SHA,
    'status': enum('passed', 'failed'), 'exit_code': integer(1), 'case_count': integer(17, 17),
    'passed_cases': integer(17), 'failed_cases': integer(17), 'primary_failure': FAILURE, **FLAGS})
GITHUB = nullable(obj({'repository': const('TheSlayer455/jake-wormhole'),
    'run_id': text(30, pattern=r'^[1-9][0-9]{0,29}$(?![\s\S])'), 'run_attempt': integer(1000, 1),
    'runner_os': enum('Linux', 'Windows', 'macOS'), 'runner_arch': enum('X64', 'ARM64', 'X86')}))
PROVENANCE = obj({'source_revision': COMMON['source_revision'],
    'python_version': text(20, pattern=r'^3\.12\.\d{1,3}$(?![\s\S])'), 'platform': text(256), 'architecture': text(64),
    'execution_mode': enum('manual', 'github-actions', 'gitlab'), 'command': array(text(80), 9, 9),
    'exit_code': integer(1), 'exit_code_kind': const('computed-runner-return-code'), 'created_at': DATE,
    'case_run_ids': array(UUID, 17), 'original_records': array(obj({'case_id': CODE,
        'plan_sha256': nullable(SHA), 'receipt_sha256': nullable(SHA)}), 17), 'github': GITHUB})
EXECUTION = obj({'schema_version': const('1.0'), 'operation': const('synthetic-parity-execution-v1'),
    **PROVENANCE['properties'], 'synthetic': const(True), **FLAGS})
FILE = obj({'sha256': SHA, 'size_bytes': integer(MAX_FILE_BYTES, 1)})
CHECKSUMS = obj({**COMMON, 'operation': const('synthetic-parity-checksums-v1'),
    'files': obj({name: FILE for name in FILES[:4]}), **FLAGS})


def schema():
    definitions = dict(zip(FILES, (PLAN, NORMAL_RECORD, DECISION, EXECUTION, CHECKSUMS)))
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'wormhole:synthetic-parity-export:v1',
        '$defs': deepcopy(definitions), 'oneOf': [{'$ref': '#/$defs/' + name.replace('~', '~0').replace('/', '~1')} for name in FILES],
        '$comment': 'Fixed contract family; cross-file/grid/hash/privacy invariants are also enforced by parity_records.'}


def safe_values(value):
    if type(value) is str:
        require(all(32 <= ord(char) <= 126 for char in value), 'parity_unsafe_text')
        require(not re.search(r'(?i)(?:private/|\.tfstate|\.tfplan|[a-z]:[\\/]|/(?:srv|home|root|Users)/|BEGIN[^\n]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9_]{8}|github_pat_)', value),
                'parity_unsafe_text')
    elif type(value) is dict:
        for key, item in value.items(): safe_values(key); safe_values(item)
    elif type(value) is list:
        for item in value: safe_values(item)


def bounded(definition, value):
    try:
        _bounded_json(value); _validate(definition, value, '$')
        require(len(canonical(value)) + 1 <= MAX_FILE_BYTES, 'parity_size_bound')
        safe_values(value)
    except ContractError:
        raise ParityRecordError('parity_record_invalid', 'A closed typed parity record is required.') from None
    return value


def build_plan(mode, source_revision):
    cases = []
    for transport in ('local', 'http-loopback'):
        for scenario in SCENARIOS:
            code = {'missing': 'chunk_set_mismatch', 'duplicate': 'chunk_manifest_invalid',
                'reordered': 'chunk_manifest_order', 'truncated': 'chunk_http_response' if transport == 'http-loopback' else 'chunk_size_mismatch',
                'corrupted': 'chunk_hash_mismatch'}.get(scenario)
            cases.append({'case_id': 'chunks-' + transport + '-' + scenario, 'component': 'chunks', 'transport': transport,
                'scenario': scenario, 'expected_status': 'passed' if scenario == 'healthy' else 'failed',
                'expected_exit_code': 0 if scenario == 'healthy' else 1, 'expected_error_code': code,
                'required': True, 'check_ids': list(CHECK_IDS)})
    for scenario in ('pass', 'reject', 'malformed', 'unsupported', 'incomplete'):
        status, exit_code, error = {'pass': ('passed', 0, None), 'reject': ('rejected', 1, None),
            'malformed': ('failed', 2, 'malformed_assessment'), 'unsupported': ('failed', 2, 'unsupported_assessment_format'),
            'incomplete': ('failed', 2, 'incomplete_assessment')}[scenario]
        if mode == 'required-failure' and scenario == 'reject': status, exit_code, error = 'passed', 0, None
        if mode == 'unexpected-success' and scenario == 'pass': status, exit_code, error = 'rejected', 1, None
        cases.append({'case_id': 'assessment-' + scenario, 'component': 'assessment', 'transport': None, 'scenario': scenario,
            'expected_status': status, 'expected_exit_code': exit_code, 'expected_error_code': error, 'required': True, 'check_ids': list(CHECK_IDS)})
    value = {'schema_version': '1.0', 'operation': 'synthetic-parity-plan-v1', 'source_revision': source_revision,
        'source_dirty': False, 'mode': mode, 'synthetic': True, 'cases': cases, **{key: False for key in FLAGS}}
    value['plan_sha256'] = sha(canonical(value)); bounded(PLAN, value)
    return value


def validate_plan(plan):
    bounded(PLAN, plan)
    require(same(plan, build_plan(plan['mode'], plan['source_revision'])), 'parity_plan_changed')
    return deepcopy(plan)


def execution_value(status, exit_code, error_code):
    return canonical({'status': status, 'component_cli_exit_code': exit_code, 'error_code': error_code}).decode()


def check_expectations(declaration):
    return {'execution': execution_value(declaration['expected_status'], declaration['expected_exit_code'], declaration['expected_error_code']),
        'report-replay': 'identical', 'domain-result': 'validated-native-result', 'cleanup': 'private-fixture-removed'}


def fixture_content(declaration):
    """Source-declared deterministic synthetic inputs, never filesystem reads."""
    if declaration['component'] == 'chunks':
        pattern = hashlib.sha256(b'WORMHOLE SYNTHETIC BINARY FIXTURE v1\x00').digest() * 2048
        raw = pattern * 4 + pattern[:37]
        chunks = [{'index': index, 'size': len(raw[start:start + 65536]), 'sha256': sha(raw[start:start + 65536])}
                  for index, start in enumerate(range(0, len(raw), 65536))]
        return sha(raw), chunks
    scenario = declaration['scenario']
    findings = [{'finding_id': ident, 'status': 'Not a Finding' if index != 3 else 'Not Applicable',
        'summary': 'Generated synthetic finding ' + ident + '.',
        'reason': '' if index != 3 else 'Synthetic fixture excludes this capability.'} for index, ident in enumerate(FINDING_IDS)]
    original = {'format': 'wormhole.synthetic-checklist', 'schema_version': '1.0', 'synthetic': True, 'findings': findings}
    if scenario == 'reject': findings[0]['status'] = 'Open'; findings[2]['status'] = 'Not Reviewed'
    elif scenario == 'malformed': return sha(b'{"format":'), []
    elif scenario == 'unsupported': original['format'] = 'not-a-supported-scanner-format'
    elif scenario == 'incomplete': findings.pop()
    return sha(canonical(original)), findings


def validate_details(row, declaration):
    details = row['details']
    empty = {'input_sha256': None, 'output_sha256': None, 'checked_chunks': [], 'findings': [], 'counts': None, 'policy_verdict': None}
    if same(details, empty) and row['checks'][2]['status'] != 'pass':
        require(row['status'] != 'passed', 'parity_unverified_native_result')
        return  # Preserve the actual API outcome while refusing invented replay data.
    expected_input, expected_native = fixture_content(declaration)
    require(details['input_sha256'] is None or details['input_sha256'] == expected_input, 'parity_input_changed')
    if declaration['component'] == 'chunks':
        require(not details['findings'] and details['counts'] is None and details['policy_verdict'] is None, 'parity_component_details')
        chunks = details['checked_chunks']
        require(same(chunks, expected_native[:len(chunks)]), 'parity_chunk_order')
        if row['actual_status'] == 'passed':
            require(details['input_sha256'] is not None and details['output_sha256'] == details['input_sha256'] and
                [item['size'] for item in chunks] == [65536] * 4 + [37], 'parity_chunk_content')
        else: require(details['output_sha256'] is None, 'parity_unverified_output')
    else:
        require(not details['checked_chunks'], 'parity_component_details')
        if row['actual_status'] in ('passed', 'rejected'):
            findings = details['findings']
            require([item['finding_id'] for item in findings] == list(FINDING_IDS) and
                all(item['applicable'] is (index != 3) for index, item in enumerate(findings)), 'parity_applicability')
            require(same([{key: item[key] for key in ('finding_id', 'status', 'summary', 'reason')} for item in findings], expected_native),
                    'parity_native_findings_changed')
            counts = {status: sum(item['status'] == status for item in findings) for status in FINDING_STATUSES}
            reasons = []
            for item in findings:
                if item['status'] == 'Open': reasons.append(item['finding_id'] + ': open finding')
                elif item['status'] == 'Not Reviewed': reasons.append(item['finding_id'] + ': not reviewed')
                elif item['status'] == 'Not Applicable' and (item['applicable'] or item['reason'] != 'Synthetic fixture excludes this capability.'):
                    reasons.append(item['finding_id'] + ': applicability was not declared with this reason')
                elif item['status'] == 'Not a Finding' and not item['applicable']:
                    reasons.append(item['finding_id'] + ': contradicts declared applicability')
            verdict = 'reject' if reasons else 'pass'
            original = {'findings': [{key: item[key] for key in ('finding_id', 'status', 'summary', 'reason')} for item in findings],
                'counts': counts, 'policy_verdict': verdict, 'policy_reasons': reasons}
            require(same(details['counts'], counts) and details['policy_verdict'] == verdict and
                (row['actual_status'] == 'passed') == (verdict == 'pass') and details['input_sha256'] is not None and
                details['output_sha256'] == sha(canonical(original)), 'parity_assessment_content')
        else:
            require(not details['findings'] and details['counts'] is None and details['policy_verdict'] is None and
                details['output_sha256'] is None, 'parity_unverified_output')


def validate_record(record, plan, *, _normalized=False):
    validate_plan(plan); bounded(NORMAL_RECORD if _normalized else RECORD, record)
    require(all(same(record[key], plan[key]) for key in COMMON) and record['plan_sha256'] == plan['plan_sha256'], 'parity_identity')
    require([row['case_id'] for row in record['cases']] == [row['case_id'] for row in plan['cases']], 'parity_case_grid')
    ids = [row['run_id'] for row in record['cases'] if row['run_id'] is not None]
    require(len(ids) == len(set(ids)), 'parity_run_reused')
    for row, declaration in zip(record['cases'], plan['cases']):
        require([item['check_id'] for item in row['checks']] == list(CHECK_IDS), 'parity_check_grid')
        expected = check_expectations(declaration)
        require(all(item['expected'] == expected[item['check_id']] for item in row['checks']), 'parity_expectation_changed')
        require(all((item['status'] == 'pass') == (item['observed'] is not None and item['observed'] == item['expected']) and
            (item['status'] != 'unverified' or item['observed'] is None) for item in row['checks']), 'parity_check_false_pass')
        if _normalized:
            require(row['run_id'] is None or row['run_id'] == 'run-' + row['case_id'], 'parity_normalized_identity')
        if declaration['transport'] != 'http-loopback': require(row['loopback_port'] is None, 'parity_endpoint')
        if row['status'] == 'not-run':
            require(row['run_id'] is None and row['actual_status'] == 'unverified' and row['component_cli_exit_code'] is None and
                all(item['status'] == 'unverified' for item in row['checks']), 'parity_unattempted_case')
        else:
            require(row['run_id'] is not None and row['actual_status'] != 'unverified' and row['component_cli_exit_code'] is not None,
                'parity_attempt_identity')
            require(row['checks'][0]['observed'] == execution_value(row['actual_status'], row['component_cli_exit_code'], row['error_code']),
                'parity_underlying_outcome')
            if row['actual_status'] in ('passed', 'rejected'):
                require(row['component_cli_exit_code'] == (0 if row['actual_status'] == 'passed' else 1) and row['error_code'] is None,
                        'parity_component_exit_mapping')
            require(declaration['component'] != 'chunks' or row['actual_status'] != 'rejected', 'parity_component_exit_mapping')
        validate_details(row, declaration)
        passing = all(item['status'] == 'pass' for item in row['checks']) and row['cleanup'] == {'status': 'completed', 'private_removed': True}
        require((row['status'] == 'passed') == passing, 'parity_case_false_pass')
        require(not passing or row['details']['input_sha256'] is not None, 'parity_missing_input')
        require((row['checks'][-1]['status'] == 'pass') == (row['cleanup'] == {'status': 'completed', 'private_removed': True}),
                'parity_cleanup_check')
        require(row['cleanup']['status'] != 'completed' or row['cleanup']['private_removed'] is True, 'parity_cleanup_false_pass')
    passing = all(row['status'] == 'passed' for row in record['cases']) and record['cleanup'] == {'status': 'completed', 'private_removed': True} and record['primary_failure'] is None
    require(record['cleanup']['status'] != 'completed' or record['cleanup']['private_removed'] is True, 'parity_cleanup_false_pass')
    require((record['status'] == 'passed') == passing and (record['status'] != 'failed' or record['primary_failure'] is not None), 'parity_false_pass')
    require(record['primary_failure'] is None or record['primary_failure']['case_id'] is None or
        record['primary_failure']['case_id'] in {row['case_id'] for row in plan['cases']}, 'parity_primary_scope')
    return deepcopy(record)


def decision(plan, record):
    passed = sum(row['status'] == 'passed' for row in record['cases'])
    return {**{key: deepcopy(record[key]) for key in COMMON}, 'operation': 'synthetic-parity-decision-v1',
        'plan_sha256': plan['plan_sha256'], 'status': record['status'], 'exit_code': 0 if record['status'] == 'passed' else 1,
        'case_count': 17, 'passed_cases': passed, 'failed_cases': 17 - passed,
        'primary_failure': deepcopy(record['primary_failure']), **{key: False for key in FLAGS}}


def normalize(plan, record):
    validate_record(record, plan)
    result = deepcopy(record)
    for row in result['cases']:
        row['run_id'] = None if row['run_id'] is None else 'run-' + row['case_id']
        row.update(updated_at='normalized-time', duration_seconds='normalized-duration')
        if row['loopback_port'] is not None: row['loopback_port'] = 'normalized-loopback-port'
    validate_record(result, plan, _normalized=True)
    return {'plan': deepcopy(plan), 'result': result, 'decision': decision(plan, result)}


def validate_execution(provenance, plan, record, *, exported=False):
    bounded(EXECUTION if exported else PROVENANCE, provenance)
    require(provenance['source_revision'] == plan['source_revision'] and provenance['command'] ==
        ['python3', '-B', '-m', 'wormhole.parity', 'run', '--output', 'ci-safe', '--mode', plan['mode']] and
        provenance['exit_code'] == decision(plan, record)['exit_code'], 'parity_execution_contract')
    require((provenance['github'] is not None) == (provenance['execution_mode'] == 'github-actions'), 'parity_runner_context')
    attempted = [row for row in record['cases'] if row['run_id'] is not None]
    require(len(provenance['case_run_ids']) == len(attempted) and len(set(provenance['case_run_ids'])) == len(attempted) and
        [row['case_id'] for row in provenance['original_records']] == [row['case_id'] for row in attempted], 'parity_original_grid')
    if not exported: require(provenance['case_run_ids'] == [row['run_id'] for row in attempted], 'parity_original_identity')
    require(all(row['status'] != 'passed' or original['plan_sha256'] is not None and original['receipt_sha256'] is not None
        for row, original in zip(attempted, provenance['original_records'])), 'parity_missing_original')
    return deepcopy(provenance)


def export_files(record, plan, provenance):
    normalized = normalize(plan, record); validate_execution(provenance, plan, record)
    execution = {'schema_version': '1.0', 'operation': 'synthetic-parity-execution-v1', **deepcopy(provenance),
                 'synthetic': True, **{key: False for key in FLAGS}}
    values = [normalized['plan'], normalized['result'], normalized['decision'], execution]
    files = {name: canonical(value) + b'\n' for name, value in zip(FILES, values)}
    table = {name: {'sha256': sha(raw), 'size_bytes': len(raw)} for name, raw in files.items()}
    checksums = {**{key: deepcopy(plan[key]) for key in COMMON}, 'operation': 'synthetic-parity-checksums-v1',
                 'files': table, **{key: False for key in FLAGS}}
    files[FILES[-1]] = canonical(checksums) + b'\n'
    validate_exports(files)
    return files


def validate_exports(files):
    require(type(files) is dict and set(files) == set(FILES) and all(type(raw) is bytes and 1 <= len(raw) <= MAX_FILE_BYTES
        for raw in files.values()) and sum(map(len, files.values())) <= MAX_TOTAL_BYTES, 'parity_export_file_set')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'parity_duplicate_member'); result[key] = value
        return result
    values = {}
    try:
        for name in FILES:
            value = json.loads(files[name], object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            require(files[name] == canonical(value) + b'\n', 'parity_noncanonical_bytes'); values[name] = value
    except (ValueError, UnicodeError, RecursionError):
        raise ParityRecordError('parity_export_json', 'Closed canonical parity JSON is required.') from None
    plan, record, selected, execution, checksums = (values[name] for name in FILES)
    validate_record(record, plan, _normalized=True); bounded(DECISION, selected)
    require(same(selected, decision(plan, record)), 'parity_decision_changed')
    validate_execution(execution, plan, record, exported=True); bounded(CHECKSUMS, checksums)
    expected = {**{key: deepcopy(plan[key]) for key in COMMON}, 'operation': 'synthetic-parity-checksums-v1',
        'files': {name: {'sha256': sha(files[name]), 'size_bytes': len(files[name])} for name in FILES[:4]},
        **{key: False for key in FLAGS}}
    require(same(checksums, expected), 'parity_checksums_changed')
    return {'status': 'valid', 'source_revision': plan['source_revision'], 'mode': plan['mode'], 'case_count': 17,
        'decision_status': selected['status'], 'computed_runner_return_code': selected['exit_code'],
        'plan_sha256': plan['plan_sha256'],
        'files': {name: {'sha256': sha(files[name]), 'size_bytes': len(files[name])} for name in FILES},
        **{key: False for key in FLAGS}}
