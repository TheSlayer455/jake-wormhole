"""Publication CLI dispatch checks, separate from actual publication evidence."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from wormhole import cli
from wormhole.images import RUNS_ROOT
from wormhole.runs import RunError

RUN_ID = 'baf69558-c809-4ea5-b145-fc3659cc1331'


class PublicationCLITests(unittest.TestCase):
    def setUp(self):
        self.publication = ModuleType('wormhole.publication')
        self.publication.publish_reference = Mock(return_value={'status': 'published'})
        self.publication.inspect_publication = Mock(return_value={'status': 'complete'})
        self.publication.initialize_publication_root = Mock(return_value={'status': 'initialized'})

    def invoke(self, *args):
        output = io.StringIO()
        with patch.dict(sys.modules, {'wormhole.publication': self.publication}), redirect_stdout(output):
            status = cli.main(list(args))
        return status, json.loads(output.getvalue())

    def test_publish_uses_fixed_workspace_and_library_owns_lock(self):
        run = object()
        with patch.object(cli, 'Run', return_value=run) as factory:
            status, value = self.invoke('publish-reference', RUN_ID)
        self.assertEqual(status, 0)
        self.assertEqual(value, {'status': 'published'})
        factory.assert_called_once_with(RUNS_ROOT, RUN_ID)
        self.publication.publish_reference.assert_called_once_with(run)

    def test_arbitrary_workspace_refuses_before_run_or_publisher(self):
        with patch.object(cli, 'Run') as factory:
            status, value = self.invoke('publish-reference', RUN_ID, '--workspace', '/tmp/other-runs')
        self.assertEqual(status, 2)
        self.assertEqual(value['error']['code'], 'publication_unsupported')
        factory.assert_not_called()
        self.publication.publish_reference.assert_not_called()

    def test_inspection_does_not_create_or_modify_a_run(self):
        with patch.object(cli, 'Run') as factory:
            status, value = self.invoke('publication-status', RUN_ID)
        self.assertEqual(status, 0)
        self.assertEqual(value, {'status': 'complete'})
        factory.assert_not_called()
        self.publication.inspect_publication.assert_called_once_with(RUN_ID)

    def test_publication_failure_remains_nonzero_and_keeps_reason(self):
        self.publication.publish_reference.side_effect = RunError('publication_duplicate', 'Existing release is preserved.')
        with patch.object(cli, 'Run', return_value=object()):
            status, value = self.invoke('publish-reference', RUN_ID)
        self.assertEqual(status, 2)
        self.assertEqual(value['error']['code'], 'publication_duplicate')

    def test_incomplete_inspection_is_nonzero_without_repair(self):
        self.publication.inspect_publication.return_value = {'status': 'incomplete'}
        status, value = self.invoke('publication-status', RUN_ID)
        self.assertEqual(status, 1)
        self.assertEqual(value['status'], 'incomplete')
        self.publication.publish_reference.assert_not_called()

    def test_init_has_no_operator_selected_destination(self):
        status, value = self.invoke('publication-init')
        self.assertEqual(status, 0)
        self.assertEqual(value['status'], 'initialized')
        self.publication.initialize_publication_root.assert_called_once_with()

    def test_cli_cannot_choose_output_or_fault_hook(self):
        for extra in (('--output', '/tmp/release'), ('--fault', 'before-complete')):
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.invoke('publish-reference', RUN_ID, *extra)
        self.publication.publish_reference.assert_not_called()


if __name__ == '__main__':
    unittest.main()
