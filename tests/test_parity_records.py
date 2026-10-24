"""Pure synthetic parity contracts; no domain execution, files or CI claims."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from uuid import UUID

from wormhole import parity_records as p

SHA = 'a' * 40
STAMP = '2026-10-24T18:00:00.000Z'


def fixture(mode='all', seed=1):
    plan = p.build_plan(mode, SHA)
    actual_plan = p.build_plan('all', SHA)
    rows = []
    for index, (declaration, actual) in enumerate(zip(plan['cases'], actual_plan['cases'])):
        source, native = p.fixture_content(actual)
        details = {'input_sha256': source, 'output_sha256': None, 'checked_chunks': [],
                   'findings': [], 'counts': None, 'policy_verdict': None}
        if actual['component'] == 'chunks' and actual['expected_status'] == 'passed':
            details.update(output_sha256=source, checked_chunks=native)
        if actual['component'] == 'assessment' and actual['expected_status'] in ('passed', 'rejected'):
            findings = [{**item, 'applicable': i != 3} for i, item in enumerate(native)]
            counts = {status: sum(item['status'] == status for item in findings) for status in p.FINDING_STATUSES}
            verdict = 'pass' if actual['expected_status'] == 'passed' else 'reject'
            reasons = [] if verdict == 'pass' else ['fixture-alpha: open finding', 'fixture-gamma: not reviewed']
            details.update(findings=findings, counts=counts, policy_verdict=verdict,
                output_sha256=p.sha(p.canonical({'findings': native, 'counts': counts, 'policy_verdict': verdict, 'policy_reasons': reasons})))
        expected = p.check_expectations(declaration)
        observed = {**expected, 'execution': p.execution_value(actual['expected_status'], actual['expected_exit_code'], actual['expected_error_code'])}
        checks = [{'check_id': key, 'required': True, 'expected': expected[key], 'observed': observed[key],
                   'status': 'pass' if expected[key] == observed[key] else 'fail'} for key in p.CHECK_IDS]
        passed = all(item['status'] == 'pass' for item in checks)
        rows.append({'case_id': declaration['case_id'], 'run_id': str(UUID(int=index + seed)), 'updated_at': STAMP,
            'duration_seconds': .01, 'loopback_port': 35000 + index if declaration['transport'] == 'http-loopback' else None,
            'status': 'passed' if passed else 'failed', 'actual_status': actual['expected_status'],
            'component_cli_exit_code': actual['expected_exit_code'], 'exit_code_kind': 'domain-cli-contract-mapping',
            'error_code': actual['expected_error_code'], 'checks': checks, 'details': details,
            'cleanup': {'status': 'completed', 'private_removed': True}})
    failed = next((row for row in rows if row['status'] != 'passed'), None)
    record = {key: deepcopy(plan[key]) for key in p.COMMON}
    record.update(operation='synthetic-parity-results-v1', plan_sha256=plan['plan_sha256'],
        status='passed' if failed is None else 'failed', cases=rows,
        primary_failure=None if failed is None else {'code': 'parity_expected_outcome_mismatch', 'case_id': failed['case_id']},
        cleanup={'status': 'completed', 'private_removed': True}, reference_eligible=False, production_iso_eligible=False)
    provenance = {'source_revision': SHA, 'python_version': '3.12.14', 'platform': 'Windows-11', 'architecture': 'AMD64',
        'execution_mode': 'manual', 'command': ['python3', '-B', '-m', 'wormhole.parity', 'run', '--output', 'ci-safe', '--mode', mode],
        'exit_code': 0 if failed is None else 1, 'exit_code_kind': 'computed-runner-return-code', 'created_at': STAMP,
        'case_run_ids': [row['run_id'] for row in rows],
        'original_records': [{'case_id': row['case_id'], 'plan_sha256': 'b' * 64, 'receipt_sha256': 'c' * 64} for row in rows], 'github': None}
    return plan, record, provenance


class ParityRecords(unittest.TestCase):
    def test_exact_seventeen_scenarios_with_independent_required_failure_modes(self):
        all_plan = p.build_plan('all', SHA)
        self.assertEqual(len(all_plan['cases']), 17)
        self.assertEqual([row['component'] for row in all_plan['cases']], ['chunks'] * 12 + ['assessment'] * 5)
        for mode, changed in [('required-failure', 'assessment-reject'), ('unexpected-success', 'assessment-pass')]:
            plan, record, provenance = fixture(mode)
            self.assertEqual([a['case_id'] for a, b in zip(plan['cases'], all_plan['cases']) if not p.same(a, b)], [changed])
            result = p.validate_exports(p.export_files(record, plan, provenance))
            self.assertEqual((record['status'], result['decision_status'], result['computed_runner_return_code']), ('failed', 'failed', 1))
            target = next(row for row in record['cases'] if row['case_id'] == changed)
            self.assertEqual(target['actual_status'], 'rejected' if mode == 'required-failure' else 'passed')

    def test_only_named_volatility_normalizes_same_semantics_bytes(self):
        plan, first, provenance = fixture(seed=1)
        _, second, _ = fixture(seed=100)
        for row in second['cases']:
            row.update(updated_at='2026-10-24T19:00:00.000Z', duration_seconds=1.5)
            if row['loopback_port'] is not None: row['loopback_port'] += 100
        a, b = p.normalize(plan, first), p.normalize(plan, second)
        self.assertEqual(a, b)
        self.assertEqual(a['plan']['source_revision'], SHA)
        self.assertEqual(a['plan']['plan_sha256'], p.sha(p.canonical({k: v for k, v in a['plan'].items() if k != 'plan_sha256'})))
        self.assertEqual(first['cases'][0]['run_id'], str(UUID(int=1)))
        self.assertNotEqual(first['cases'][0]['run_id'], a['result']['cases'][0]['run_id'])
        files = p.export_files(first, plan, provenance)
        self.assertEqual(tuple(files), p.FILES)
        self.assertEqual(p.validate_exports(files)['decision_status'], 'passed')
        self.assertEqual(tuple(p.validate_exports(files)['files']), p.FILES)

    def test_missing_duplicate_foreign_case_or_check_cannot_be_a_smaller_success(self):
        plan, record, _ = fixture()
        for action in (lambda x: x['cases'].pop(), lambda x: x['cases'].__setitem__(1, deepcopy(x['cases'][0])),
                lambda x: x['cases'][0].update(case_id='foreign'), lambda x: x['cases'][0]['checks'].pop(),
                lambda x: x['cases'][0]['checks'][0].update(required=False),
                lambda x: x['cases'][0]['checks'][0].update(check_id='foreign')):
            value = deepcopy(record); action(value)
            with self.assertRaises(p.ParityRecordError): p.validate_record(value, plan)

    def test_coherently_edited_plan_or_underlying_success_cannot_match_expected_negative(self):
        plan, record, provenance = fixture('unexpected-success')
        value = deepcopy(record); value.update(status='passed', primary_failure=None)
        value['cases'][12]['status'] = 'passed'; value['cases'][12]['checks'][0]['status'] = 'pass'
        with self.assertRaises(p.ParityRecordError): p.export_files(value, plan, provenance)
        changed = deepcopy(plan); changed['cases'][0]['expected_exit_code'] = 1
        changed['plan_sha256'] = p.sha(p.canonical({k: v for k, v in changed.items() if k != 'plan_sha256'}))
        with self.assertRaises(p.ParityRecordError): p.validate_plan(changed)

    def test_content_hash_chunks_findings_and_applicability_are_not_stripped(self):
        plan, record, _ = fixture()
        for action in (lambda x: x['cases'][0]['details'].update(input_sha256='e' * 64),
                lambda x: x['cases'][0]['details']['checked_chunks'][0].update(sha256='e' * 64),
                lambda x: x['cases'][12]['details']['findings'][3].update(applicable=True),
                lambda x: x['cases'][12]['details']['findings'][0].update(summary='invented'),
                lambda x: x['cases'][12]['details']['counts'].update(Open=1),
                lambda x: x['cases'][2]['details'].update(input_sha256=None),
                lambda x: x['cases'][0]['details'].update(output_sha256=None)):
            value = deepcopy(record); action(value)
            with self.assertRaises(p.ParityRecordError): p.validate_record(value, plan)

    def test_wire_types_unknown_fields_false_flags_and_cleanup_consistency(self):
        plan, record, _ = fixture()
        for action in (lambda x: x.update(source_dirty=0), lambda x: x.update(synthetic=1),
                lambda x: x.update(reference_eligible=True), lambda x: x.update(production_iso_eligible=True),
                lambda x: x.update(unexpected='rejected'), lambda x: x['cases'][0].update(component_cli_exit_code=False),
                lambda x: x['cases'][0].update(duration_seconds=float('nan')),
                lambda x: x['cases'][0]['cleanup'].update(private_removed=False)):
            value = deepcopy(record); action(value)
            with self.assertRaises(p.ParityRecordError): p.validate_record(value, plan)

    def test_private_text_control_bytes_and_unbounded_inputs_never_export(self):
        plan, record, provenance = fixture()
        for unsafe in ('/root/secret', 'C:\\Users\\person', 'private/state', 'terraform.tfstate',
                '-----BEGIN ' + 'PRIVATE KEY-----', 'gh' + 'p_' + 'x' * 36, '\x1b[31m', 'x' * 300000):
            value = deepcopy(provenance); value['platform'] = unsafe
            with self.subTest(unsafe_kind=len(unsafe)), self.assertRaises(p.ParityRecordError): p.export_files(record, plan, value)

    def test_five_file_set_bytes_canonical_json_and_checksums_are_closed(self):
        plan, record, provenance = fixture(); files = p.export_files(record, plan, provenance)
        for action in (lambda x: x.pop('decision.json'), lambda x: x.update(extra=b'{}\n'),
                lambda x: x.update({'plan.json': b'{"schema_version":"1.0","schema_version":"1.0"}\n'}),
                lambda x: x.update({'execution.json': x['execution.json'] + b' '}),
                lambda x: x.update({'results.json': 'not bytes'}),
                lambda x: x.update({'results.json': b'x' * (p.MAX_FILE_BYTES + 1)})):
            value = deepcopy(files); action(value)
            with self.assertRaises(p.ParityRecordError): p.validate_exports(value)
        value = deepcopy(files); execution = json.loads(value['execution.json']); execution['platform'] = 'Linux'
        value['execution.json'] = p.canonical(execution) + b'\n'
        with self.assertRaises(p.ParityRecordError): p.validate_exports(value)

    def test_actual_process_observation_is_not_invented_by_preexit_execution_metadata(self):
        plan, record, provenance = fixture()
        self.assertEqual(provenance['exit_code_kind'], 'computed-runner-return-code')
        self.assertEqual(record['cases'][0]['exit_code_kind'], 'domain-cli-contract-mapping')
        for action in (lambda x: x.update(exit_code_kind='actual-process-exit'), lambda x: x.update(exit_code=1),
                lambda x: x['command'].__setitem__(0, '/usr/bin/python3'),
                lambda x: x['case_run_ids'].__setitem__(1, x['case_run_ids'][0]),
                lambda x: x['original_records'][0].update(plan_sha256=None)):
            value = deepcopy(provenance); action(value)
            with self.assertRaises(p.ParityRecordError): p.export_files(record, plan, value)

    def test_failed_replay_keeps_successful_api_outcome_but_never_invents_missing_native_details(self):
        plan, record, provenance = fixture()
        row = record['cases'][0]
        row.update(status='failed', details={'input_sha256': None, 'output_sha256': None,
            'checked_chunks': [], 'findings': [], 'counts': None, 'policy_verdict': None})
        row['checks'][1].update(status='fail', observed='replay-refused')
        row['checks'][2].update(status='unverified', observed=None)
        record.update(status='failed', primary_failure={'code': 'parity_replay_failed', 'case_id': row['case_id']})
        provenance['exit_code'] = 1
        summary = p.validate_exports(p.export_files(record, plan, provenance))
        self.assertEqual(summary['decision_status'], 'failed')
        self.assertEqual(row['actual_status'], 'passed')
        row['checks'][2].update(status='pass', observed=row['checks'][2]['expected'])
        with self.assertRaises(p.ParityRecordError): p.export_files(record, plan, provenance)

    def test_closed_github_projection_retains_run_context_without_environment_dump(self):
        plan, record, provenance = fixture()
        provenance.update(execution_mode='github-actions', github={'repository': 'TheSlayer455/jake-wormhole',
            'run_id': '123456', 'run_attempt': 1, 'runner_os': 'Linux', 'runner_arch': 'X64'})
        self.assertEqual(p.validate_exports(p.export_files(record, plan, provenance))['status'], 'valid')
        for action in (lambda x: x['github'].update(environment={'TOKEN': 'rejected'}),
                lambda x: x['github'].update(repository='foreign/project'), lambda x: x.update(github=None),
                lambda x: x['github'].update(run_attempt=True)):
            value = deepcopy(provenance); action(value)
            with self.assertRaises(p.ParityRecordError): p.export_files(record, plan, value)

    def test_schema_is_independent_generated_fixed_family(self):
        a = p.schema(); b = p.schema(); a['$defs'].clear()
        self.assertEqual(set(b['$defs']), set(p.FILES))
        self.assertTrue(all(value['additionalProperties'] is False for value in b['$defs'].values()))
        self.assertEqual(json.loads((Path(__file__).resolve().parents[1] / 'schemas/parity-export-v1.schema.json').read_bytes()), p.schema())


if __name__ == '__main__':
    unittest.main()
