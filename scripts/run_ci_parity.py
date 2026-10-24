"""One controlled fixture job, with safe diagnostics and honest process status.

The same command is used manually and by the authored CI definitions. The core
CLI owns fresh synthetic Runs and their cleanup. This observer never provisions
Docker, reads credentials, or executes a supplied command. Only validated five-
file projections are staged for the provider's artifact uploader.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MODES = ('all', 'required-failure', 'unexpected-success')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=MODES, default='all')
    options = parser.parse_args(argv)
    try:
        if Path.cwd().resolve() != ROOT:
            raise ValueError('repository_cwd_required')
        for path in (ROOT, *ROOT.parents):
            if path.is_symlink() or path.is_junction():
                raise ValueError('ordinary_source_required')
        for name in ('ci-safe', 'ci-artifacts'):
            path = ROOT / name
            if path.exists() or path.is_symlink() or path.is_junction():
                raise ValueError('fresh_output_required')
        sys.path.insert(0, str(ROOT))
        from wormhole.parity import read_export_files, write_export_files
    except Exception:
        print('{"error":"parity_job_preflight_refused"}', file=sys.stderr)
        return 2

    command = [sys.executable, '-B', '-m', 'wormhole.parity', 'run',
               '--output', 'ci-safe', '--mode', options.mode]
    try:
        # No shell and no output buffering. The core CLI prints bounded summaries.
        child = subprocess.run(command, cwd=ROOT, timeout=120, check=False)
        observed_exit = child.returncode
    except subprocess.TimeoutExpired:
        observed_exit = 124
    except OSError:
        observed_exit = 127

    staged = False
    try:
        files = read_export_files(ROOT / 'ci-safe')
        write_export_files(ROOT / 'ci-artifacts', files)
        # Recheck the final bytes through the same complete safe contract.
        if read_export_files(ROOT / 'ci-artifacts') != files:
            raise ValueError('staged_bytes_changed')
        staged = True
    except Exception:
        print('{"error":"safe_parity_diagnostics_unavailable"}', file=sys.stderr)

    job_exit = observed_exit if 0 <= observed_exit <= 255 else 1
    if not staged and job_exit == 0:
        job_exit = 2
    print(json.dumps({'operation': 'controlled-parity-job', 'mode': options.mode,
        'observed_component_process_exit_code': observed_exit,
        'diagnostics_staged': staged, 'job_exit_code': job_exit}, sort_keys=True))
    return job_exit


if __name__ == '__main__':
    raise SystemExit(main())
