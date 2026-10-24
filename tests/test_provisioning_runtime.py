"""Actual local synthetic processes; no Terraform binary, Docker or host service."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from provisioning import runtime
from wormhole import stages


class DiagnosticPolicy(unittest.TestCase):
    def test_private_terraform_diagnostic_cap_is_distinct_from_json_and_outer_stage_caps(self):
        self.assertEqual(runtime.LOG_LIMIT, 262144)
        self.assertEqual(runtime.JSON_LIMIT, 4 * 1024 * 1024)
        self.assertEqual(stages.LOG_LIMIT, 65536)
        # The plan remains a saved, noninteractive fixed Terraform operation;
        # this fix does not introduce event-stream parsing or new CLI options.
        self.assertEqual(runtime.OPERATIONS['plan'], ('plan', '-parallelism=1', '-input=false', '-no-color',
            '-lock-timeout=0s', '-out=apply.tfplan'))
        self.assertNotIn('plan', runtime.JSON_OPERATIONS)


@unittest.skipUnless(os.name == 'posix', 'Actual bounded local POSIX subprocess fixture')
class ActualDiagnosticCapture(unittest.TestCase):
    def execute(self, payload, returncode=0):
        """Assert the real fixed argv, substitute only a known local byte producer."""
        temporary = tempfile.TemporaryDirectory(prefix='worm-twenty-plan-diagnostics-')
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name); state.chmod(0o700)
        fixture = state / 'synthetic-diagnostic-input.bin'; fixture.write_bytes(payload); fixture.chmod(0o600)
        original = runtime.subprocess.Popen
        script = ('import sys\nwith open(sys.argv[1], "rb") as stream:\n'
            ' while chunk := stream.read(4096):\n  sys.stdout.buffer.write(chunk);sys.stdout.flush()\n'
            'sys.exit(int(sys.argv[2]))')
        def child(arguments, **kwargs):
            self.assertEqual(arguments, [runtime.TOOL, '-chdir=/state', *runtime.OPERATIONS['plan']])
            self.assertEqual(kwargs['env'], runtime.environment())
            self.assertIs(kwargs['stderr'], runtime.subprocess.STDOUT)
            return original([sys.executable, '-I', '-B', '-c', script, str(fixture), str(returncode)], **kwargs)
        capture = io.StringIO()
        with patch.object(runtime, 'STATE', state), patch.object(runtime.subprocess, 'Popen', side_effect=child), redirect_stdout(capture):
            status = runtime.operation('plan', 1)
        raw = (state / 'operations/plan-1.out').read_bytes()
        record = json.loads((state / 'operations/plan-1.json').read_bytes())
        self.assertEqual(json.loads(capture.getvalue()), record)
        self.assertEqual(record['output_bytes'], len(raw))
        self.assertEqual(record['output_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertLess(len(capture.getvalue().encode()), stages.LOG_LIMIT)
        self.assertEqual(record['timed_out'], False)
        return status, record, raw

    def test_twenty_representative_saved_plan_diagnostics_over_64k_are_complete(self):
        block = ('  # docker_container.target["target-{0:03}"] will be created\n' +
            '    + inspected_fixed_attribute = "synthetic-plan-fixture"\n' * 85)
        payload = ''.join(block.format(number) for number in range(1, 21)).encode()
        self.assertGreater(len(payload), 65536); self.assertLess(len(payload), runtime.LOG_LIMIT)
        status, record, raw = self.execute(payload)
        self.assertEqual(status, 0); self.assertTrue(record['passed']); self.assertFalse(record['truncated'])
        self.assertEqual(record['returncode'], 0); self.assertEqual(raw, payload)

    def test_over_256k_flood_is_killed_or_terminal_but_always_failed_and_hash_bounded(self):
        status, record, raw = self.execute(b'x' * (runtime.LOG_LIMIT + 65537))
        self.assertEqual(status, 2); self.assertFalse(record['passed']); self.assertTrue(record['truncated'])
        self.assertLessEqual(len(raw), runtime.LOG_LIMIT)

    def test_nonzero_terraform_equivalent_remains_failed_even_with_complete_large_diagnostics(self):
        payload = b'Synthetic fixed provider diagnostic\n' * 2500
        self.assertGreater(len(payload), 65536)
        status, record, raw = self.execute(payload, returncode=3)
        self.assertEqual(status, 2); self.assertFalse(record['passed']); self.assertFalse(record['truncated'])
        self.assertEqual(record['returncode'], 3); self.assertEqual(raw, payload)


if __name__ == '__main__': unittest.main()
