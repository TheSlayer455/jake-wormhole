"""Real Ubuntu XCCDF inventory/results. Native failures and coverage stay visible."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from .runs import RunError, SOURCE_ROOT

X = '{http://checklists.nist.gov/xccdf/1.2}'
NATIVE = {'pass', 'fail', 'error', 'unknown', 'notchecked', 'notapplicable', 'notselected', 'informational', 'fixed'}
POLICY = SOURCE_ROOT / 'profiles/ubuntu-lab-policy-v1.json'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, code):
    if not condition:
        raise RunError(code, 'Ubuntu assessment identity, coverage or policy evidence is incomplete.')


def xml(path):
    require(0 < Path(path).stat().st_size <= 64 * 1024**2, 'assessment_size')
    return ET.parse(path)


def inventory(content, policy=None):
    policy = policy or json.loads(POLICY.read_text())
    if 'tailoring' in policy:
        require(policy['tailoring']=={'excluded_rules':[],'parameters':{},'owner_approved_exceptions':[]},
                'unsupported_assessment_tailoring')
    require(digest(content) == policy['content']['datastream_sha256'], 'assessment_content_mismatch')
    root = xml(content)
    profile = root.find('./' + X + 'Profile')
    profiles = [x for x in root.iter(X + 'Profile') if x.get('id') == policy['content']['profile_id']]
    require(len(profiles) == 1, 'assessment_profile_mismatch')
    profile = profiles[0]
    # This pinned profile has explicit selections and no inherited profile.
    require(profile.get('extends') is None, 'unsupported_profile_inheritance')
    selections = {x.get('idref'): x.get('selected') == 'true' for x in profile.findall(X + 'select')}
    groups = {x.get('id') for x in root.iter(X + 'Group')}
    require(set(selections) <= {x.get('id') for x in root.iter(X + 'Rule')} | groups, 'benchmark_rule_coverage')
    require(not any(selections.get(g) is True for g in groups), 'unsupported_group_selection')
    suppressed = set()
    for group in root.iter(X + 'Group'):
        if selections.get(group.get('id')) is False:
            suppressed.update(x.get('id') for x in group.iter(X + 'Rule'))
    require(not any(selections.get(r) is True for r in suppressed), 'conflicting_profile_selection')
    rows = {}
    for rule in root.iter(X + 'Rule'):
        identifier = rule.get('id')
        require(identifier not in rows, 'duplicate_benchmark_rule')
        rows[identifier] = {'rule_id': identifier, 'title': rule.findtext(X + 'title'),
            'severity': rule.get('severity'), 'selected': selections.get(identifier, rule.get('selected') == 'true') and identifier not in suppressed,
            'references': [{'href': x.get('href'), 'value': x.text} for x in rule.findall(X + 'reference')]}
    require(rows, 'benchmark_rule_coverage')
    return rows


def read_results(content, native_result, *, expected_target, scanner_exit, policy=None):
    require(type(scanner_exit) is int, 'assessment_exit_status_invalid')
    policy = policy or json.loads(POLICY.read_text())
    planned = inventory(content, policy)
    root = xml(native_result)
    results = list(root.iter(X + 'TestResult'))
    require(len(results) == 1, 'assessment_testresult_count')
    result = results[0]
    profile = result.find(X + 'profile')
    require(profile is not None and profile.get('idref') == policy['content']['profile_id'], 'assessment_profile_mismatch')
    require(expected_target in [x.text for x in result.findall(X + 'target')], 'assessment_target_mismatch')
    observed = {}
    for row in result.findall(X + 'rule-result'):
        key, status = row.get('idref'), row.findtext(X + 'result')
        require(key in planned and key not in observed and status in NATIVE, 'assessment_rule_result_invalid')
        observed[key] = {'native_status': status, 'messages': [x.text for x in row.findall(X + 'message')]}
    rows = []
    for key, expected in planned.items():
        row = {**expected, **observed.get(key, {'native_status': 'missing', 'messages': []})}
        # Upstream non-selected rules remain distinguishable from tailoring exclusions.
        row['selection_origin'] = 'upstream-stig' if row['selected'] else 'upstream-notselected'
        rows.append(row)
    selected = [x for x in rows if x['selected']]
    complete = all(x['native_status'] != 'missing' for x in rows)
    automated_clean = all(x['native_status'] in {'pass', 'notapplicable'} for x in selected)
    return {'schema_version': '1.0', 'capability': 'real-ubuntu-scap-assessment',
        'content_sha256': digest(content), 'native_result_sha256': digest(native_result),
        'profile_id': policy['content']['profile_id'], 'target': expected_target,
        'scanner_exit': scanner_exit, 'scanner_execution_completed': scanner_exit in {0, 2},
        'coverage_complete': complete, 'upstream_rule_count': len(rows), 'selected_rule_count': len(selected),
        'native_counts': dict(Counter(x['native_status'] for x in rows)),
        'selected_native_counts': dict(Counter(x['native_status'] for x in selected)),
        'all_selected_automated_clean': automated_clean, 'rules': rows,
        'lab_status': 'LAB QUALIFICATION PENDING', 'lab_iso_qualified': False,
        'unresolved_requirements': policy['unresolved_requirements'], 'production_iso_eligible': False}
