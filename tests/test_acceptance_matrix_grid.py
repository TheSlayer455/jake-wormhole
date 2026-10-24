"""Original-evidence coverage must not shrink behind complete category counts."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('acceptance_matrix_grid', ROOT / 'scripts/verify_acceptance_matrix.py')
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class OriginalGridTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads((ROOT / 'docs/acceptance-matrix.json').read_bytes())

    def refused(self, change):
        value = deepcopy(self.original)
        change(value)
        with self.assertRaises(ValueError):
            MATRIX.validate(value, ROOT)

    def test_original_grid_and_markdown_are_complete(self):
        self.assertEqual(MATRIX.validate(self.original, ROOT),
                         {'rows': 83, 'evidence_files': 16, 'categories': 11})
        self.assertEqual((ROOT / 'docs/acceptance-matrix.md').read_text(encoding='utf-8'),
                         MATRIX.render_markdown(self.original))

    def test_omitted_unexpected_skip_refuses_with_other_categories_intact(self):
        self.assertEqual(self.original['rows'][22]['scenario'], 'unexpected-skip')
        self.refused(lambda value: value['rows'].pop(22))

    def test_duplicate_case_refuses(self):
        self.refused(lambda value: value['rows'].__setitem__(22, deepcopy(value['rows'][23])))

    def test_coherent_substituted_case_refuses_even_with_unique_id(self):
        def substitute(value):
            replacement = deepcopy(value['rows'][23])
            replacement['id'] = value['rows'][22]['id']
            value['rows'][22] = replacement
        self.refused(substitute)

    def test_category_and_execution_kind_are_source_specific(self):
        self.refused(lambda value: value['rows'][22].update(category='integrity-evidence'))
        self.refused(lambda value: value['rows'][22].update(execution_kind='actual-local-fixture'))

    def test_original_revision_and_stable_row_id_are_required(self):
        self.refused(lambda value: value['rows'][22].update(tested_source_revision='a'*40))
        self.refused(lambda value: value['rows'][22].update(id='H999'))

    def test_reordering_is_not_a_substitute_for_the_frozen_grid(self):
        def reorder(value):
            value['rows'][22], value['rows'][23] = value['rows'][23], value['rows'][22]
        self.refused(reorder)


if __name__ == '__main__':
    unittest.main()
