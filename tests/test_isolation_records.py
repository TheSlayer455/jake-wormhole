"""Synthetic receipt tests; no process, credential or infrastructure proof."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import UUID

from wormhole import isolation_records as i


def identifier(number):
    return str(UUID(int=number))


def receipt(status='passed'):
    value = {'schema_version': '1.0', 'run_id': identifier(1), 'source_revision': 'a' * 40,
        'source_dirty': False, 'mode': 'container-reference', 'operation': i.OPERATION, 'profile': 'smoke',
        **{key: definition['const'] for key, definition in i.FLAGS.items()},
        'status': status, 'cases': [], 'primary_failure': None,
        'created_at': '2026-10-24T17:00:00.000Z', 'updated_at': '2026-10-24T17:01:00.000Z'}
    for number, name in enumerate(i.CASE_NAMES, 2):
        passed = status == 'passed'
        value['cases'].append({'name': name, 'status': 'passed' if passed else 'not-run',
            'run_ids': [identifier(number)] if passed else [],
            'proof': {'logical_path': 'evidence/isolation-' + name + '.json',
                'sha256': 'b' * 64, 'size_bytes': 123} if passed else None,
            'failure_code': None, 'checks': {key: True if passed else None for key in i.checks_for(name)}})
    if status == 'failed':
        value['primary_failure'] = {'code': 'controlled_interruption', 'recorded_at': value['updated_at']}
    return value


class IsolationRecords(unittest.TestCase):
    def rejected(self, value):
        with self.assertRaises(i.IsolationRecordError) as raised:
            i.validate_receipt(value)
        self.assertNotIn('SYNTHETIC-SENSITIVE', str(raised.exception))

    def test_schema_is_generated_from_the_same_closed_definitions(self):
        path = Path(__file__).resolve().parents[1] / 'schemas/isolation-receipt-v1.schema.json'
        self.assertEqual(json.loads(path.read_bytes()), i.schema())
        cases = i.schema()['properties']['cases']
        self.assertEqual(cases['items'], False)
        self.assertEqual([item['properties']['name']['const'] for item in cases['prefixItems']], list(i.CASE_NAMES))

    def test_passed_receipt_returns_a_copy_and_deterministic_bytes_without_proof_access(self):
        value = receipt(); before = deepcopy(value)
        with patch('builtins.open', side_effect=AssertionError('Pure contract must not open proof files.')):
            copied = i.validate_receipt(value)
            raw = i.render_receipt(value)
        copied['cases'][0]['checks']['live-process-overlap'] = False
        self.assertEqual(value, before)
        self.assertEqual(raw, i.canonical(value) + b'\n')
        self.assertEqual(json.loads(raw), value)

    def test_running_preflight_and_partial_case_do_not_claim_unrun_work(self):
        value = receipt('running')
        self.assertEqual(i.validate_receipt(value), value)
        first = value['cases'][0]
        first.update(status='running', run_ids=[identifier(8)])
        first['checks']['busy-no-allocation'] = True
        self.assertEqual(i.validate_receipt(value), value)
        first['checks']['live-process-overlap'] = False
        self.assertEqual(i.validate_receipt(value), value)

    def test_failed_preflight_and_partial_case_keep_explicit_primary(self):
        value = receipt('failed')
        self.assertEqual(i.validate_receipt(value), value)
        first = value['cases'][0]
        first.update(status='failed', failure_code='infrastructure_busy', run_ids=[identifier(9)])
        first['checks']['busy-no-allocation'] = True
        self.assertEqual(i.validate_receipt(value), value)
        for field in ('primary_failure',):
            changed = deepcopy(value); changed[field] = None; self.rejected(changed)
        changed = deepcopy(value); changed['cases'][0]['failure_code'] = None; self.rejected(changed)

    def test_all_four_cases_and_every_exact_check_are_required(self):
        for action in ('missing-case', 'duplicate-case', 'reordered', 'missing-check', 'extra-check'):
            value = receipt()
            if action == 'missing-case': value['cases'].pop()
            elif action == 'duplicate-case': value['cases'][1] = deepcopy(value['cases'][0])
            elif action == 'reordered': value['cases'][0], value['cases'][1] = value['cases'][1], value['cases'][0]
            elif action == 'missing-check': del value['cases'][0]['checks']['distinct-authentication']
            else: value['cases'][0]['checks']['simultaneous-resource-graphs'] = True
            with self.subTest(action=action): self.rejected(value)

    def test_missing_false_or_integer_check_cannot_be_a_pass(self):
        for flag in (False, None, 1, 0, 'pass', [], {}):
            value = receipt(); value['cases'][0]['checks']['distinct-authentication'] = flag
            with self.subTest(flag=flag): self.rejected(value)
        value = receipt(); value['cases'][1]['status'] = 'not-run'; self.rejected(value)

    def test_proof_metadata_is_fixed_bounded_and_required_for_each_pass(self):
        for proof in (None, {'logical_path': '../private/key', 'sha256': 'b' * 64, 'size_bytes': 1},
                {'logical_path': 'evidence/isolation-interrupted-run.json', 'sha256': 'b' * 64, 'size_bytes': 1},
                {'logical_path': 'evidence/isolation-overlap.json', 'sha256': 'B' * 64, 'size_bytes': 1},
                {'logical_path': 'evidence/isolation-overlap.json', 'sha256': 'b' * 64, 'size_bytes': 0},
                {'logical_path': 'evidence/isolation-overlap.json', 'sha256': 'b' * 64, 'size_bytes': i.MAX_PROOF_BYTES + 1}):
            value = receipt(); value['cases'][0]['proof'] = proof
            with self.subTest(proof=proof): self.rejected(value)

    def test_fresh_child_run_identities_cannot_reuse_suite_or_another_attempt(self):
        for ids in ([identifier(1)], [identifier(2), identifier(2)], [identifier(3)],
                    [identifier(number) for number in range(10, 15)], ['not-a-uuid']):
            value = receipt(); value['cases'][0]['run_ids'] = ids
            with self.subTest(ids=ids): self.rejected(value)
        value = receipt(); value['cases'][0]['run_ids'] = []; self.rejected(value)

    def test_fixed_scope_refuses_simultaneous_graph_or_twenty_target_credit(self):
        changes = {'overlap_model': 'simultaneous-resource-graphs', 'allocation_scope': 'twenty-targets',
            'oversized_capacity_synthetic': False, 'twenty_target_execution': True,
            'production_iso_eligible': True, 'simulation': True, 'profile': 'five-targets',
            'source_dirty': True, 'mode': 'fixture', 'schema_version': '2.0'}
        for key, wrong in changes.items():
            value = receipt(); value[key] = wrong
            with self.subTest(key=key): self.rejected(value)

    def test_closed_records_cannot_export_auth_material_unknown_messages_or_other_claims(self):
        for section in ('root', 'case', 'proof', 'checks', 'primary'):
            value = receipt('failed') if section == 'primary' else receipt()
            target = {'root': value, 'case': value['cases'][0], 'proof': value['cases'][0]['proof'],
                'checks': value['cases'][0]['checks'], 'primary': value['primary_failure']}[section]
            target['private_key_sha256'] = 'SYNTHETIC-SENSITIVE'
            with self.subTest(section=section): self.rejected(value)

    def test_no_pass_after_a_failed_running_or_unrun_case(self):
        for status in ('not-run', 'running', 'failed'):
            value = receipt('running')
            value['cases'][1] = receipt()['cases'][1]
            if status == 'running': value['cases'][0]['status'] = 'running'
            elif status == 'failed':
                value.update(status='failed', primary_failure={'code': 'controlled_interruption', 'recorded_at': value['updated_at']})
                value['cases'][0].update(status='failed', failure_code='controlled_interruption')
            with self.subTest(status=status): self.rejected(value)

    def test_timestamps_and_primary_states_cannot_hide_or_reverse_failures(self):
        for field, wrong in (('created_at', '2026-10-24T17:02:00Z'), ('updated_at', '2026-02-30T00:00:00Z'),
                ('created_at', '2026-10-24T17:00:00+00:00'), ('updated_at', '2026-10-24T17:01:00Z\n')):
            value = receipt(); value[field] = wrong
            with self.subTest(field=field, wrong=wrong): self.rejected(value)
        for when in ('2026-10-24T16:59:59Z', '2026-10-24T17:01:01Z'):
            value = receipt('failed'); value['primary_failure']['recorded_at'] = when; self.rejected(value)
        value = receipt(); value['primary_failure'] = {'code': 'hidden_failure', 'recorded_at': value['updated_at']}; self.rejected(value)
        value = receipt('failed'); value['cases'][0]['status'] = 'running'; self.rejected(value)

    def test_cyclic_non_json_deep_and_oversized_records_refuse_with_safe_errors(self):
        values = [[], None, True, {'unexpected': float('nan')}, {'unexpected': object()}]
        cycle = receipt(); cycle['cases'].append(cycle); values.append(cycle)
        huge = receipt(); huge['unexpected'] = 'SYNTHETIC-SENSITIVE' * i.MAX_RECEIPT_BYTES; values.append(huge)
        deep = receipt(); child = deep
        for _ in range(20): child['unexpected'] = {}; child = child['unexpected']
        values.append(deep)
        for number, value in enumerate(values):
            with self.subTest(number=number): self.rejected(value)

    def test_named_check_lookup_rejects_unknown_case_without_echo(self):
        for name in ('SYNTHETIC-SENSITIVE', [], True, None):
            with self.subTest(name=name), self.assertRaises(i.IsolationRecordError): i.checks_for(name)
        self.assertIn('distinct-authentication', i.checks_for('overlap'))


if __name__ == '__main__':
    unittest.main()
