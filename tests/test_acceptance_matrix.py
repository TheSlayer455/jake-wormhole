"""Historical evidence index rejects changes to source-bound facts."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('historical_acceptance', ROOT / 'scripts/verify_acceptance_matrix.py')
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class OriginalEvidenceIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads((ROOT / 'docs/acceptance-matrix.json').read_bytes())

    def test_original_evidence_grid_and_markdown_agree(self):
        result = MATRIX.validate(self.original, ROOT)
        self.assertEqual(result, {'rows': 83, 'evidence_files': 16, 'categories': 11})
        self.assertEqual((ROOT / 'docs/acceptance-matrix.md').read_text(encoding='utf-8'),
                         MATRIX.render_markdown(self.original))

    def test_original_revision_hash_scope_and_failure_history_cannot_be_rewritten(self):
        mutations = [
            lambda value: value.update(production_iso_eligible=True),
            lambda value: value.update(historical_execution_is_final_source_rerun=True),
            lambda value: value.update(gitlab_runner_executed=True),
            lambda value: value['rows'][0].update(tested_source_revision='0' * 40),
            lambda value: value['rows'][0]['evidence'].update(sha256='0' * 64),
            lambda value: value['rows'][0]['evidence'].update(path='../private.json'),
            lambda value: value['preserved_twenty_failure_history'].pop(),
            lambda value: value['ci_history'][0]['runs'][0].update(conclusion='success'),
        ]
        for mutate in mutations:
            value = deepcopy(self.original)
            mutate(value)
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(ValueError):
                MATRIX.validate(value, ROOT)


if __name__ == '__main__':
    unittest.main()
