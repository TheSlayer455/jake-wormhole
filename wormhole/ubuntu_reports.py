"""Ubuntu run reports; one expected grid drives JSON, text and JUnit."""
from collections import Counter
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from .runs import atomic_json
from .ubuntu_assessment import POLICY, inventory, digest


def generate(run, result, *, findings=None, observations=None, controller_records=()):
    run = Path(run)
    policy = json.loads(POLICY.read_text())
    rule_rows=(findings or {}).get('rules',[])
    content=run/'inputs/payload/ssg-ubuntu2204-ds.xml'
    if not rule_rows and content.exists():
        rule_rows=[dict(row,native_status='missing') for row in inventory(content).values()]
    coverage={'upstream_rule_count':len(rule_rows) if rule_rows else None,
              'selected_rule_count':sum(r['selected'] for r in rule_rows) if rule_rows else None,
              'native_counts':dict(Counter(r['native_status'] for r in rule_rows)),
              'assessment_executed':findings is not None,
              'rules':[{'rule_id':r['rule_id'],'selected':r['selected'],'native_status':r['native_status']} for r in rule_rows]}
    from .ubuntu_coverage import summarize
    coverage['profile_mapping']=summarize(rule_rows)
    (run/'assessment-coverage.json').write_text(json.dumps(coverage,indent=2))
    rows = []
    observed = (observations or {}).get('checks', {})
    stages = {r.get('stage'): r for r in controller_records}
    manual_record=stages.get('manual-observations')
    if manual_record and manual_record.get('returncode')==0:
        try:manual=json.loads(manual_record['output'])
        except (ValueError,KeyError):manual={'objective_results':{},'disposition':'invalid-observation'}
        atomic_json(run/'manual-evidence.json',manual)
    else:manual={'objective_results':{},'disposition':'not-collected'}
    derived = {
        'pkcs11-pam-positive-and-negative':stages['pkcs11-pam-probe']['evidence'].get('all_expected_observed') if 'pkcs11-pam-probe' in stages else None,
        'pkcs11-mapper-config-parser':set(stages['pkcs11-pam-probe']['evidence'].get('parser',{}))=={'vendor_configuration_parses','missing_semicolon_refused','pwent_with_required_semicolon'} and
            all(v is True for v in stages['pkcs11-pam-probe']['evidence']['parser'].values()) if stages.get('pkcs11-pam-probe',{}).get('returncode')==0 else None,
        'audit-offload-readback':result.get('support_verification',{}).get('audit_snapshot_readback_verified'),
        'no-retained-install-secrets':stages.get('secret-retention-inspection',{}).get('returncode')==0 if 'secret-retention-inspection' in stages else None,
        'remote-syslog-received':result.get('support_verification',{}).get('syslog_guest_event_received'),
        'remote-audit-received':result.get('support_verification',{}).get('audit_guest_event_received'),
        'encrypted-cold-start':result.get('cold_start_verified'),
        'offline-encryption-proof':result.get('offline_encryption',{}).get('luks_magic_verified'),
        'private-secret-lifecycle':stages.get('private-secret-lifecycle',{}).get('returncode')==0 if 'private-secret-lifecycle' in stages else None,
        'trusted-final-ssh': stages['final-authentication'].get('returncode')==0 if 'final-authentication' in stages else result.get('final_authentication'),
        'ansible-ping': stages['ansible-readiness'].get('returncode')==0 if 'ansible-readiness' in stages else result.get('ansible_ready'),
        'native-package-inventory': observations.get('inventory_complete') if observations else None,
        'password-required-sudo': stages.get('password-required-sudo', {}).get('returncode') == 0 if 'password-required-sudo' in stages else None,
        'scanner-native-results': findings.get('scanner_execution_completed') and findings.get('coverage_complete') if findings else None,
    }
    for key in policy['functional_checks']:
        value = observed.get(key, derived.get(key))
        rows.append({'id': key, 'status': 'pass' if value is True else 'fail' if value is False else 'blocked',
                     'evidence': 'installed-observations' if key in observed else 'controller/native-assessment',
                     'reason': '' if value is True else result.get('error_category', 'required observation absent or failed')})
    reasons = list(policy['unresolved_requirements'])
    if any(r['status'] != 'pass' for r in rows):reasons.append('functional-results-incomplete-or-failed')
    if not findings:reasons.append('native-assessment-unavailable')
    else:
        if not findings['coverage_complete']:reasons.append('assessment-rule-coverage-incomplete')
        if not findings['scanner_execution_completed']:reasons.append('scanner-execution-failed')
        if not findings['all_selected_automated_clean']:reasons.append('selected-controls-unresolved')
    reasons.append('two-independent-matching-installations-not-yet-verified')
    if result.get('cleanup') != 'verified-absent-inputs-retained':reasons.append('cleanup-not-verified')
    report = {'schema_version': '1.0', 'capability': 'ubuntu-lab-evidence-report', 'run_id': result['run_id'],
              'report_implementation_sha256':digest(__file__),
              'source_revision': result['source_revision'], 'candidate_sha256': result.get('build', {}).get('candidate_sha256'),
              'mode': result.get('build', {}).get('mode'), 'outcome': result['outcome'], 'cleanup': result['cleanup'],
              'policy_id': policy['policy_id'], 'policy_sha256': result.get('build', {}).get('policy_sha256'),
              'functional_results': rows, 'functional_counts': dict(Counter(r['status'] for r in rows)),
              'assessment': {k:v for k,v in (findings or {}).items() if k not in {'rules','target'}},
              'stages': result.get('stages', []), 'qualification_reasons': reasons,
              'manual_evidence':manual,
              'lab_status': 'LAB QUALIFICATION PENDING', 'lab_iso_qualified': False, 'production_iso_eligible': False}
    atomic_json(run / 'qualification.json', report)
    atomic_json(run/'encryption-evidence.json',{'offline':result.get('offline_encryption'),
        'cold_start_verified':result.get('cold_start_verified'),'unlock_events':result.get('unlock_events',[]),
        'secrets_included':False})
    atomic_json(run/'timing.json',{'stages':result.get('stages',[]),'installation':result.get('installation_observations',[]),
        'source_revision':result['source_revision']})
    text = ['Ubuntu 22.04 lab evidence', report['lab_status'],
            'Implementation: '+result['source_revision'],
            'Candidate SHA256: ' + str(report['candidate_sha256']),
            'Functional: ' + json.dumps(report['functional_counts'], sort_keys=True),
            'Assessment native totals: ' + json.dumps(report['assessment'].get('native_counts', {}), sort_keys=True),
            'Selected totals: ' + json.dumps(report['assessment'].get('selected_native_counts', {}), sort_keys=True),
            'Cleanup: ' + result['cleanup'], '', 'Required functional checks:']
    text += [r['id'] + ': ' + r['status'] for r in rows]
    text += ['', 'Qualification unresolved:'] + reasons
    text += ['', 'Encryption and support evidence:',
             'Cold start: '+str(result.get('cold_start_verified','not observed')),
             'Offline encryption: '+json.dumps(result.get('offline_encryption',{}),sort_keys=True),
             'Receiver verification: '+json.dumps(result.get('support_verification',{}),sort_keys=True),
             'Scanner build: '+str(result.get('build',{}).get('scanner_toolchain',{}).get('version','distribution package')),
             '', 'Selected nonpassing/native manual outcomes:']
    text += [r['rule_id']+': '+r['native_status']+' ('+str(r.get('severity','unknown'))+')'
             for r in rule_rows if r['selected'] and r['native_status'] not in {'pass','notapplicable'}]
    text += ['', 'Manual observations (native scanner statuses preserved):']
    text += [key+': '+('observed condition met' if value.get('observed_satisfied') is True else 'unresolved')
             for key,value in manual.get('objective_results',{}).items()]
    (run / 'qualification.txt').write_text('\n'.join(text) + '\n')
    tests = ET.Element('testsuite', name='ubuntu-functional-and-assessment')
    if not rule_rows:
        case=ET.SubElement(tests,'testcase',classname='scap',name='benchmark-inventory-unavailable')
        ET.SubElement(case,'failure',message='Required rule inventory unavailable; expected counts are unknown.')
    for row in rows:
        case = ET.SubElement(tests, 'testcase', classname='functional', name=row['id'])
        if row['status'] != 'pass':
            ET.SubElement(case, 'failure' if row['status'] == 'fail' else 'skipped',
                          message=row['reason']).text = row['status']
    for row in rule_rows:
        case = ET.SubElement(tests, 'testcase', classname='scap', name=row['rule_id'])
        status = row['native_status']
        if status=='missing' and findings is None:
            ET.SubElement(case, 'skipped', message='blocked: assessment unavailable')
        elif status in {'notselected','notapplicable','informational'}:
            ET.SubElement(case, 'skipped', message=status)
        elif status != 'pass':
            ET.SubElement(case, 'failure', message=status)
    tests.set('tests', str(len(tests)))
    tests.set('failures', str(len(tests.findall('./testcase/failure'))))
    tests.set('skipped', str(len(tests.findall('./testcase/skipped'))))
    ET.ElementTree(tests).write(run / 'junit.xml', encoding='utf-8', xml_declaration=True)
    if observations:
        svd = {'schema_version':'1.0','kind':'observed-installed-software','run_id':result['run_id'],
               'candidate_sha256':report['candidate_sha256'], 'kernel':observations['kernel'],
               'packages':observations['packages'],'snaps':observations.get('snaps',[]),
               'payloads':observations.get('payloads',[]),
               'inventory_complete':observations.get('inventory_complete',False)}
        (run / 'installed-svd.json').write_text(json.dumps(svd, indent=2))
        lines=['Observed installed software','Kernel: '+observations['kernel'],'Debian packages:']
        lines += [p['name']+' '+p['version']+' '+p['architecture'] for p in observations['packages']]
        lines += ['','Snap entries:']+[p['name']+' '+p['version']+' revision='+p['revision']+' channel='+p['tracking'] for p in observations.get('snaps',[])]
        lines += ['','Installed payloads:']+[p['name']+' '+p['version']+' sha256='+p['binary_sha256'] for p in observations.get('payloads',[])]
        (run / 'installed-svd.txt').write_text('\n'.join(lines)+'\n')
    return report
