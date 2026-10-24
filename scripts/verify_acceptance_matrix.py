"""Read-only historical evidence/link verifier; not a runtime or parity gate."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = (
    'healthy-reference', 'readiness-auth-trust-network-python',
    'functional-version', 'powershell-source', 'integrity-evidence',
    'interruption-recovery', 'overlap-resource-refusal',
    'native-inventory', 'publication', 'synthetic-assessment', 'twenty-targets',
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def require(value, code):
    if not value:
        raise ValueError(code)


def pointer(value, path):
    require(type(path) is str and (path == '' or path.startswith('/')), 'pointer')
    for part in path.split('/')[1:]:
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if type(value) is list else value[part]
    return value


def render_markdown(value):
    lines = ['# Historical acceptance matrix', '',
        'This is an index of original, source-bound observations, not a rerun at the',
        'current WORM-021 source. Expected-negative harness success retains the failed',
        'underlying operation. Full hashes, exact JSON selectors, selected original',
        'fields, cleanup references and limitations are in [the JSON record](acceptance-matrix.json).', '',
        'WORM-021 is In Progress at this snapshot. Controlled manual/hosted parity and',
        'safe failing-job diagnostics still need their own final evidence. GitLab runner',
        'execution, scanner/STIG, VM/ISO and production eligibility are unverified or excluded.', '',
        '| ID | Category / scenario | Original tested source | Observation | Evidence |',
        '| --- | --- | --- | --- | --- |']
    for row in value['rows']:
        fields = row['observed_fields']
        parts = []
        for key in ('/status', '/qualification_status', '/acceptance_status',
                    '/operation_status', '/underlying_status', '/component_status'):
            if key in fields:
                parts.append(key[1:] + '=' + str(fields[key]))
        if row['execution_kind'] == 'synthetic-capacity':
            parts.append('synthetic; no allocation')
        observed = '; '.join(parts) or 'source fields retained in JSON'
        label = row['scenario'].replace('|', '\\|')
        lines.append(f"| {row['id']} | {row['category']} / {label} | `{row['tested_source_revision'][:12]}` | {observed} | [{row['ticket']}](../{row['evidence']['path']}) |")
    lines += ['', '## Interpretation', '',
        '- PowerShell missing-package evidence uses an isolated empty local APT source/state; ordinary helper checks passed separately. It is not a package removed from the normal helper.',
        '- Wrong-version, wrong-identity and applicability cases use declared controlled expectations; they do not claim a naturally broken production payload.',
        '- WORM-019 overlaps live coordinators while serializing allocation. Its oversized-capacity refusal is synthetic; WORM-020 separately ran twenty simultaneous stock targets.',
        '- Native inventories retain full target package versions and architectures. Helper/provisioner versions and the shared kernel are separate provenance.',
        '- Publication is verified private local filesystem publication of tested reference bytes, not a remote release or image export.',
        '- Original checkpoints, evidence, reviews and failed attempts remain unchanged. Private state, raw logs and credentials are not copied here.', '',
        '## CI history', '',
        'WORM-020 delivery source `193a9fd78b31595861904df2a93c26323bec2834` failed hosted verification because a depth-one checkout lacked the original `6f3f28e` fixture source.',
        'The reviewed `fetch-depth: 0` correction preserves pinned actions, read-only permissions, disabled credential persistence and all tests.',
        'Both hosted checks passed at `65db67b90fb104e1e58efffb5fb0e3d80f0c0871`. This is fixture CI success, not WORM-021 normalized parity.', '',
        'Verify this index with `python scripts/verify_acceptance_matrix.py`.', '']
    return '\n'.join(lines)


def validate(value, root=ROOT):
    require(type(value) is dict and value.get('schema_version') == '1.0' and
            value.get('operation') == 'historical-acceptance-matrix-v1', 'matrix_identity')
    require(value.get('production_iso_eligible') is False and
            value.get('historical_execution_is_final_source_rerun') is False and
            value.get('gitlab_runner_executed') is False, 'fidelity_flags')
    require(value.get('categories') == list(CATEGORIES), 'declared_categories')
    rows = value.get('rows')
    require(type(rows) is list and 1 <= len(rows) <= 128, 'rows_bound')
    require(len({row['id'] for row in rows}) == len(rows), 'unique_rows')
    require(set(row['category'] for row in rows) == set(CATEGORIES), 'category_coverage')
    sources = {}
    for row in rows:
        require(row['ticket'] in {f'WORM-{n:03}' for n in range(5, 21)} and
                re.fullmatch('[a-f0-9]{40}', row['tested_source_revision']), 'original_source')
        evidence = row['evidence']; name = evidence['path']
        require(name == 'handoff/evidence/' + row['ticket'] + '.json', 'fixed_evidence_path')
        if name not in sources:
            path = root / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2*1024*1024, 'ordinary_bounded_evidence')
            raw = path.read_bytes(); sources[name] = (hashlib.sha256(raw).hexdigest(), json.loads(raw))
        digest, original = sources[name]
        require(evidence['sha256'] == digest, 'original_file_hash')
        selected = pointer(original, evidence['json_pointer'])
        require(hashlib.sha256(canonical(selected)).hexdigest() == evidence['record_sha256'], 'selected_record_hash')
        require(type(row['observed_fields']) is dict and row['observed_fields'], 'observed_fields')
        for key, observed in row['observed_fields'].items():
            require(canonical(pointer(selected, key)) == canonical(observed), 'typed_original_observation')
        for ref in row['cleanup_evidence']:
            target = pointer(original, ref['json_pointer'])
            require(hashlib.sha256(canonical(target)).hexdigest() == ref['record_sha256'], 'cleanup_record_hash')
        identity = original.get('tested_source_revision', original.get('tested_controller_revision'))
        if row['ticket'] == 'WORM-005':
            identity = selected['source_revision']
        require(identity == row['tested_source_revision'], 'original_tested_revision')
        require(row['execution_kind'] in ('actual-container', 'actual-local-fixture',
                'private-local-publication', 'synthetic-capacity') and
                type(row['expected_outcome']) is str and row['expected_outcome'] and
                type(row['limits']) is list and row['limits'], 'scope')
        if row['execution_kind'] == 'synthetic-capacity':
            require(selected.get('synthetic') is True and selected.get('allocation_performed') is False,
                    'no_actual_overload_claim')
    twenty = sources['handoff/evidence/WORM-020.json'][1]
    require(len(twenty['prior_failed_attempts']) == 4 and
            canonical(value.get('preserved_twenty_failure_history')) ==
            canonical(twenty['prior_failed_attempts']), 'preserved_four_actual_failures')
    ci = value.get('ci_history')
    require(type(ci) is list and len(ci) == 2, 'ci_history')
    expected = (
        ('193a9fd78b31595861904df2a93c26323bec2834', 'failure', {40122081169, 40122084718}),
        ('65db67b90fb104e1e58efffb5fb0e3d80f0c0871', 'success', {40122478923, 40122482009}),
    )
    for entry, (revision, conclusion, identifiers) in zip(ci, expected):
        require(entry['source_revision'] == revision and
                re.fullmatch('[a-f0-9]{64}', entry['original_private_receipt_sha256']), 'ci_original_identity')
        runs = entry['runs']
        require(type(runs) is list and len(runs) == 2 and
                {row['id'] for row in runs} == identifiers and
                {row['event'] for row in runs} == {'push', 'pull_request'}, 'ci_actual_events')
        for run in runs:
            require(type(run['id']) is int and run['head_sha'] == revision and
                    run['status'] == 'completed' and run['conclusion'] == conclusion and
                    run['html_url'] == 'https://github.com/TheSlayer455/jake-wormhole/actions/runs/' + str(run['id']),
                    'ci_actual_conclusion')
    return {'rows': len(rows), 'evidence_files': len(sources), 'categories': len(CATEGORIES)}


def main():
    try:
        path = ROOT / 'docs/acceptance-matrix.json'
        require(path.stat().st_size <= 2*1024*1024, 'matrix_bound')
        value = json.loads(path.read_bytes()); result = validate(value)
        require((ROOT / 'docs/acceptance-matrix.md').read_text(encoding='utf-8') == render_markdown(value),
                'markdown_parity')
        print(json.dumps({'status': 'passed', 'scope': 'historical evidence index only', **result}, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
        print(json.dumps({'status': 'failed', 'error_type': type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
