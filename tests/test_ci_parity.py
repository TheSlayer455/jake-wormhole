"""Provider wiring and failure propagation; real CLI runs are qualified separately."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('controlled_ci_job', ROOT / 'scripts/run_ci_parity.py')
JOB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JOB)


class JobFailurePropagation(unittest.TestCase):
    def run_job(self, exit_code=0, stage_error=False, timeout=False, existing=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            if existing:
                (root / existing).mkdir()
            calls = []
            wire = {'plan.json': b'bounded validated fixture projection'}

            def read(path):
                calls.append(('read', path.name))
                if stage_error:
                    raise ValueError('unsafe export')
                return wire

            def write(path, files):
                calls.append(('write', path.name, files is wire))

            seam = types.SimpleNamespace(read_export_files=read, write_export_files=write)
            completed = subprocess.CompletedProcess([], exit_code)
            effect = subprocess.TimeoutExpired(['fixed'], 300) if timeout else None
            original_path = sys.path.copy()
            try:
                with patch.object(JOB, 'ROOT', root), patch.object(JOB.Path, 'cwd', return_value=root), \
                        patch.dict(sys.modules, {'wormhole.parity': seam}), \
                        patch.object(JOB.subprocess, 'run', return_value=completed, side_effect=effect) as run, \
                        patch('builtins.print'):
                    result = JOB.main(['--mode', 'required-failure'])
                    invocation = run.call_args
                    count = run.call_count
            finally:
                sys.path[:] = original_path
            return result, calls, invocation, count

    def test_genuine_failure_remains_nonzero_after_safe_diagnostics(self):
        result, calls, invocation, count = self.run_job(exit_code=1)
        self.assertEqual(result, 1)
        self.assertEqual(count, 1)
        self.assertEqual(calls, [('read', 'ci-safe'), ('write', 'ci-artifacts', True), ('read', 'ci-artifacts')])
        self.assertEqual(invocation.args[0], [sys.executable, '-B', '-m', 'wormhole.parity', 'run',
                                             '--output', 'ci-safe', '--mode', 'required-failure'])
        self.assertEqual(invocation.kwargs['timeout'], 300)
        self.assertNotIn('shell', invocation.kwargs)

    def test_missing_or_unsafe_diagnostics_cannot_turn_success_green(self):
        self.assertEqual(self.run_job(stage_error=True)[0], 2)

    def test_missing_diagnostics_preserves_original_failure(self):
        self.assertEqual(self.run_job(exit_code=7, stage_error=True)[0], 7)

    def test_timeout_and_signal_are_job_failures(self):
        self.assertEqual(self.run_job(timeout=True)[0], 124)
        self.assertEqual(self.run_job(exit_code=-9)[0], 1)

    def test_existing_outputs_refuse_before_any_child_or_staging(self):
        for name in ('ci-safe', 'ci-artifacts'):
            with self.subTest(name=name):
                result, calls, invocation, count = self.run_job(existing=name)
                self.assertEqual((result, calls, invocation, count), (2, [], None, 0))


class AuthoredProviderContract(unittest.TestCase):
    def test_gitlab_is_closed_one_job_with_exact_safe_artifact_list(self):
        config = json.loads((ROOT / '.gitlab-ci.yml').read_text())
        self.assertEqual(set(config), {'stages', 'verify'})
        job = config['verify']
        self.assertFalse(job['allow_failure'])
        self.assertEqual(job['variables']['GIT_DEPTH'], '0')
        self.assertEqual(job['script'][-1], 'python3 -B scripts/run_ci_parity.py --mode all')
        self.assertEqual(job['artifacts']['when'], 'always')
        self.assertEqual(job['artifacts']['paths'], ['ci-artifacts/' + name for name in
                         ('plan.json', 'results.json', 'decision.json', 'execution.json', 'checksums.json')])
        self.assertNotIn('after_script', job)

    def test_github_keeps_failure_status_and_uploads_only_validated_literals(self):
        workflow = (ROOT / '.github/workflows/verify.yml').read_text()
        self.assertNotIn('continue-on-error', workflow)
        self.assertNotIn('|| true', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha || github.sha }}', workflow)
        self.assertIn('fetch-depth: 0', workflow)
        self.assertIn("steps.safe_diagnostics.outcome == 'success'", workflow)
        self.assertIn('python3 -B -m wormhole.parity validate --output ci-artifacts', workflow)
        self.assertIn('actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9', workflow)
        self.assertEqual(workflow.count('ci-artifacts/'), 5)
        self.assertNotIn('ci-artifacts/*', workflow)
        self.assertIn('--mode required-failure', workflow)
        self.assertIn('--mode unexpected-success', workflow)
        self.assertIn('include-hidden-files: false', workflow)


if __name__ == '__main__':
    unittest.main()
