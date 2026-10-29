"""Pinned DVD vendor-STIG observation; never an ISO qualification decision."""
import base64
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import tarfile
import xml.etree.ElementTree as ET

from .runs import atomic_json, run_id
from .vm_admission import require
from .ubuntu_assessment import NATIVE, X

CONTENT_SHA = '5a8594747bba185dad188b0774215ec8e6aa97811bd51ae8986c68f566a7519d'
PROFILE = 'xccdf_org.ssgproject.content_profile_stig'
FILES = {'datastream.xml', 'xccdf.xml', 'arf.xml', 'report.html', 'scanner-version.txt', 'scan.log', 'receipt.json'}
LIMIT = 192 * 1024**2

# Appended to the existing helper after its real SSH/Ansible/inventory checks.
RHEL_AUDIT_CODE = r'''
import base64,hashlib
remaining=deadline-time.monotonic()
if remaining<=35:raise RuntimeError('assessment_deadline')
audit=r"""set -euo pipefail
umask 077
out=/var/lib/wormhole/assessment
mkdir -m 0700 "$out"
content=/usr/share/xml/scap/ssg/content/ssg-rhel10-ds.xml
printf '%s  %s\n' '@CONTENT_SHA@' "$content" | sha256sum --check --status
cp "$content" "$out/datastream.xml"
oscap --version > "$out/scanner-version.txt"
touch "$out/xccdf.xml" "$out/arf.xml" "$out/report.html"
set +e
timeout --signal=TERM --kill-after=5 @SECONDS@ oscap xccdf eval \
  --profile @PROFILE@ --results "$out/xccdf.xml" --results-arf "$out/arf.xml" \
  --report "$out/report.html" "$content" > "$out/scan.log" 2>&1
status=$?
set -e
python3 - "$status" <<'PY'
import hashlib,json,pathlib,socket,sys
p=pathlib.Path('/var/lib/wormhole/assessment')
receipt={'run_id':pathlib.Path('/var/lib/wormhole/run-id').read_text().strip(),
 'content_sha256':hashlib.sha256((p/'datastream.xml').read_bytes()).hexdigest(),
 'profile_id':'@PROFILE@','target':socket.gethostname(),
 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'scanner_exit':int(sys.argv[1])}
(p/'receipt.json').write_text(json.dumps(receipt)+'\n')
PY
tar -C "$out" -czf - datastream.xml xccdf.xml arf.xml report.html scanner-version.txt scan.log receipt.json
"""
started=time.monotonic()
r=subprocess.run(['ssh',*opts,'lab.service@'+c['address'],'sudo -n /bin/bash -s'],
 input=audit.replace('@SECONDS@',str(int(remaining-30))).encode(),capture_output=True,timeout=remaining)
if r.returncode or len(r.stdout)>64*1024**2:
 print(json.dumps({'stage':'assessment-archive','returncode':r.returncode or 1,
  'diagnostic':r.stderr.decode(errors='replace')[-4096:]}),flush=True);sys.exit(1)
print(json.dumps({'stage':'assessment-archive','returncode':0,'elapsed_seconds':round(time.monotonic()-started,3),
 'sha256':hashlib.sha256(r.stdout).hexdigest(),'archive_base64':base64.b64encode(r.stdout).decode()}),flush=True)
print(json.dumps({'final_authentication':True,'ansible_ready':True,'catalog_started':True,'outcome':'baseline-passed',
 'lab_iso_qualified':False,'production_iso_eligible':False}),flush=True)
'''.replace('@CONTENT_SHA@', CONTENT_SHA).replace('@PROFILE@', PROFILE)


def read_results(content, native, *, expected_target, scanner_exit, expected_hash=CONTENT_SHA, expected_rules=948):
    """Fixture overrides are explicit; the live collector always uses DVD pins."""
    require(0 < len(content) <= 64 * 1024**2 and 0 < len(native) <= 64 * 1024**2, 'assessment_size')
    require(hashlib.sha256(content).hexdigest() == expected_hash, 'assessment_content_mismatch')
    root = ET.fromstring(content)
    profiles = [p for p in root.iter(X + 'Profile') if p.get('id') == PROFILE]
    require(len(profiles) == 1 and profiles[0].get('extends') is None, 'assessment_profile_mismatch')
    rules = list(root.iter(X + 'Rule'))
    planned = {r.get('id'): r.findtext(X + 'title') for r in rules}
    require(len(planned) == len(rules) == expected_rules and all(planned), 'assessment_expected_rules')
    results = list(ET.fromstring(native).iter(X + 'TestResult'))
    require(len(results) == 1, 'assessment_testresult_count')
    result = results[0]
    profile = result.find(X + 'profile')
    require(profile is not None and profile.get('idref') == PROFILE, 'assessment_profile_mismatch')
    require(expected_target in [t.text for t in result.findall(X + 'target')], 'assessment_target_mismatch')
    observed = {}
    for row in result.findall(X + 'rule-result'):
        key, status = row.get('idref'), row.findtext(X + 'result')
        require(key in planned and key not in observed and status in NATIVE, 'assessment_rule_result_invalid')
        observed[key] = status
    require(set(observed) == set(planned), 'assessment_coverage_incomplete')
    require(type(scanner_exit) is int and scanner_exit in {0, 2}, 'scanner_execution_failed')
    return {'schema_version': '1.0', 'capability': 'real-rhel-vendor-stig-baseline',
        'content_sha256': expected_hash, 'content_version': '0.1.76', 'content_status': 'draft',
        'profile_id': PROFILE, 'target': expected_target, 'scanner_exit': scanner_exit,
        'scanner_execution_completed': True, 'coverage_complete': True, 'upstream_rule_count': len(planned),
        'native_counts': dict(Counter(observed.values())),
        'rules': [{'rule_id': key, 'title': planned[key], 'native_status': status} for key, status in observed.items()],
        'lab_iso_qualified': False, 'production_iso_eligible': False,
        'limitation': 'DVD vendor draft anticipates RHEL 10 STIG; no released DISA benchmark alignment or hardening qualification.'}


def collect(run, result, rows):
    """Persist the fixed native bundle before the existing VM teardown."""
    records = [r for r in rows if r.get('stage') == 'assessment-archive' and r.get('returncode') == 0]
    require(len(records) == 1, 'assessment_artifact_missing')
    record = records[0]
    require(len(record['archive_base64']) <= 90 * 1024**2, 'assessment_archive_size')
    archive = base64.b64decode(record['archive_base64'], validate=True)
    require(len(archive) <= 64 * 1024**2 and hashlib.sha256(archive).hexdigest() == record['sha256'], 'assessment_archive_identity')
    out = Path(run) / 'assessment';out.mkdir(mode=0o700)
    names, total = set(), 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for member in tar:
            require(member.isfile() and member.name in FILES and member.name not in names and
                    0 <= member.size <= 64 * 1024**2, 'assessment_archive_member')
            total += member.size
            require(total <= LIMIT, 'assessment_archive_size')
            raw = tar.extractfile(member).read()
            require(len(raw) == member.size, 'assessment_archive_truncated')
            (out / member.name).write_bytes(raw);names.add(member.name)
    require(names == FILES, 'assessment_native_files_missing')
    receipt = json.loads((out / 'receipt.json').read_text())
    target = 'vm-' + result['run_id'][:8]
    require(receipt.get('run_id') == result['run_id'] and receipt.get('target') == target and
            receipt.get('content_sha256') == CONTENT_SHA and receipt.get('profile_id') == PROFILE, 'assessment_receipt_identity')
    run_id(receipt.get('boot_id'))
    content = (out / 'datastream.xml').read_bytes()
    summary = read_results(content, (out / 'xccdf.xml').read_bytes(), expected_target=target, scanner_exit=receipt.get('scanner_exit'))
    arf = read_results(content, (out / 'arf.xml').read_bytes(), expected_target=target, scanner_exit=receipt.get('scanner_exit'))
    require(arf['rules'] == summary['rules'] and (out / 'report.html').stat().st_size > 0 and
            (out / 'scanner-version.txt').stat().st_size > 0, 'assessment_native_files_inconsistent')
    summary.update(run_id=result['run_id'], boot_id=receipt['boot_id'],
                   native_hashes={name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in sorted(FILES)})
    atomic_json(Path(run) / 'assessment.json', summary)
    (Path(run) / 'assessment.txt').write_text('RHEL 10 DVD vendor-STIG baseline (draft 0.1.76)\n'
        + '\n'.join(f'{key}: {value}' for key, value in sorted(summary['native_counts'].items()))
        + '\nAll 948 rules accounted for. Lab and production qualification: false.\n' + summary['limitation'] + '\n')
    return summary
