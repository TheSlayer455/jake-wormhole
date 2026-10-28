"""Ubuntu real-audit command using the existing VM lifecycle and shared admission."""
import argparse
import base64
import io
import json
from pathlib import Path
import tarfile

from . import vm_baseline
from .runs import atomic_json, read_json, run_id
from .ubuntu_assessment import POLICY, read_results, require
from .vm_inputs import sha256

# Reuse proven SSH/readiness dispatch; change credentials and append a real audit.
HELPER_CODE = vm_baseline.HELPER_CODE.replace(
 "check='test -f", "password=p/'become';password.write_text(c.pop('become_password')+'\\n');password.chmod(0o600)\ncheck='test -f")
HELPER_CODE = HELPER_CODE.replace(' && sudo -n true', '')
HELPER_CODE = HELPER_CODE.replace("'--ssh-common-args='+common]", "'--ssh-common-args='+common,'--become-password-file',str(password)]")
HELPER_CODE = HELPER_CODE.replace("'inventory',['-m'", "'inventory',['-b','-m'")
HELPER_CODE = HELPER_CODE.replace("'ansible-readiness',['-m'", "'ansible-readiness',['-m'")
HELPER_CODE = HELPER_CODE.replace("common='-o StrictHostKeyChecking", "common='-o HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256 -o PubkeyAcceptedAlgorithms=rsa-sha2-512,rsa-sha2-256 -o StrictHostKeyChecking")
HELPER_CODE = HELPER_CODE.replace("opts=['-o','BatchMode=yes',", "opts=['-o','HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256','-o','PubkeyAcceptedAlgorithms=rsa-sha2-512,rsa-sha2-256','-o','BatchMode=yes',")
HELPER_CODE = HELPER_CODE.replace("opts=['-o'", "opts=['-o','ControlMaster=auto','-o','ControlPersist=30','-o','ControlPath='+str(p/'control'),'-o'", 1)
HELPER_CODE = HELPER_CODE.replace("common='-o HostKeyAlgorithms", "common='-o ControlMaster=auto -o ControlPersist=30 -o ControlPath='+str(p/'control')+' -o HostKeyAlgorithms")
# Strip the baseline terminal line, not any underlying required operation.
HELPER_CODE = HELPER_CODE[:HELPER_CODE.rfind("print(json.dumps({'final_authentication':True")]
HELPER_CODE += r'''
def ssh(command,*,secret=False,seconds=60,binary=False):
 remaining=deadline-time.monotonic()
 if remaining<=0:raise RuntimeError('absolute deadline')
 r=subprocess.run(['ssh',*opts,'lab.service@'+c['address'],command],
     input=(password.read_text().encode() if binary else password.read_text()) if secret else None,
     capture_output=True,text=not binary,timeout=min(seconds,remaining))
 return r
r=ssh('sudo -k -n true')
if r.returncode==0:
 print(json.dumps({'stage':'password-required-sudo','returncode':1}));sys.exit(1)
print(json.dumps({'stage':'password-required-sudo','returncode':0}),flush=True)
r=ssh('sudo -S -p "" /usr/bin/python3 /usr/local/lib/wormhole/observe.py',secret=True)
print(json.dumps({'stage':'installed-observations','returncode':r.returncode,'output':r.stdout,'diagnostic':r.stderr}),flush=True)
if r.returncode:sys.exit(1)
r=ssh('sudo -S -p "" /bin/bash /usr/local/lib/wormhole/audit.sh',secret=True,seconds=650)
print(json.dumps({'stage':'real-assessment','returncode':r.returncode,'diagnostic':r.stderr}),flush=True)
if r.returncode:sys.exit(1)
r=ssh('sudo -S -p "" tar -C /var/lib/wormhole/assessment -czf - .',secret=True,seconds=60,binary=True)
if r.returncode or len(r.stdout)>24*1024**2:sys.exit(1)
import base64,hashlib
print(json.dumps({'stage':'assessment-artifacts','returncode':0,'sha256':hashlib.sha256(r.stdout).hexdigest(),
                  'archive_base64':base64.b64encode(r.stdout).decode()}),flush=True)
print(json.dumps({'final_authentication':True,'ansible_ready':True,'catalog_started':True,
 'outcome':'baseline-passed','lab_iso_qualified':False,'production_iso_eligible':False}),flush=True)
'''


def collect(run, result):
    """Persist native outputs BEFORE the existing lifecycle tears down the VM."""
    records = []
    archive = None
    with (run / 'ssh-ansible-inventory.log').open() as stream:
        for line in stream:
            if line.startswith('{'):
                item = json.loads(line)
                if item.get('stage') == 'assessment-artifacts':
                    require(len(item['archive_base64']) <= 32 * 1024**2, 'assessment_archive_size')
                    archive = base64.b64decode(item['archive_base64'], validate=True)
                    import hashlib
                    require(hashlib.sha256(archive).hexdigest() == item['sha256'], 'assessment_archive_identity')
                else:records.append(item)
    atomic_json(run / 'controller-records.json', records)
    observations = next((json.loads(r['output']) for r in records if r.get('stage') == 'installed-observations' and r.get('returncode') == 0), None)
    if observations is not None:
        require(observations.get('run_id') == result['run_id'], 'installed_observation_identity')
        atomic_json(run / 'installed-observations.json', observations)
    require(archive is not None, 'assessment_artifact_missing')
    out = run / 'assessment';out.mkdir(mode=0o700)
    names = set()
    allowed = {'xccdf.xml','arf.xml','report.html','scanner-version.txt','started-at.txt',
               'scanner-exit.txt','scanner-receipt.json','scanner.log','finalization.log','remediation-results.json'}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        total = 0
        for member in tar:
            if member.name in {'.','./'} and member.isdir():continue
            name = member.name.removeprefix('./')
            require(member.isfile() and name in allowed and name not in names and 0 <= member.size <= 64 * 1024**2, 'assessment_archive_member')
            total += member.size
            require(total <= 192 * 1024**2, 'assessment_archive_size')
            raw = tar.extractfile(member).read()
            (out / name).write_bytes(raw);names.add(name)
    require({'xccdf.xml','arf.xml','report.html','scanner-receipt.json'} <= names, 'assessment_native_files_missing')
    receipt = json.loads((out / 'scanner-receipt.json').read_text())
    policy = json.loads(POLICY.read_text())
    require(receipt['run_id'] == result['run_id'] and receipt['content_sha256'] == policy['content']['datastream_sha256']
            and receipt['boot_id'] != receipt['firstboot_id'] and receipt['remediation_during_assessment'] is False, 'assessment_receipt_identity')
    findings = read_results(run / 'inputs/payload/ssg-ubuntu2204-ds.xml', out / 'xccdf.xml',
                            expected_target=receipt['target'], scanner_exit=receipt['scanner_exit'])
    # Findings are larger than the old 256 KiB small-run-record limit.
    (out / 'findings.json').write_text(json.dumps(findings, indent=2))
    result.update(assessment={k:v for k,v in findings.items() if k != 'rules'},
                  capability='ubuntu-real-assessment-run', mode=result['build']['mode'])
    return findings


def report(run, result):
    from .ubuntu_reports import generate
    findings = json.loads((run / 'assessment/findings.json').read_text()) if (run / 'assessment/findings.json').exists() else None
    observations = read_json(run / 'installed-observations.json') if (run / 'installed-observations.json').exists() else None
    records = read_json(run / 'controller-records.json') if (run / 'controller-records.json').exists() else []
    return generate(run, result, findings=findings, observations=observations, controller_records=records)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    prep=sub.add_parser('prepare');prep.add_argument('--store',required=True)
    progress=sub.add_parser('progress');progress.add_argument('run_id')
    listing=sub.add_parser('catalog')
    comparison=sub.add_parser('compare');comparison.add_argument('previous');comparison.add_argument('current')
    reporting=sub.add_parser('report');reporting.add_argument('run_id')
    run=sub.add_parser('run');run.add_argument('--source',required=True);run.add_argument('--terraform',required=True)
    run.add_argument('--store',required=True);run.add_argument('--mode',choices=['stock-audit','hardened'],default='stock-audit')
    run.add_argument('--reuse-run',help='Verified immutable ISO from this reconciled run; new disk, identity and assessment are mandatory.')
    options=p.parse_args()
    if options.command=='catalog':
        from .ubuntu_catalog import catalog
        print(json.dumps(catalog(vm_baseline.ROOT/'vm-runs'),indent=2));return 0
    if options.command=='compare':
        from .ubuntu_catalog import compare
        value=compare(vm_baseline.ROOT/'vm-runs'/run_id(options.previous),vm_baseline.ROOT/'vm-runs'/run_id(options.current))
        print(json.dumps(value,indent=2));return 0
    if options.command=='report':
        run=vm_baseline.ROOT/'vm-runs'/run_id(options.run_id)
        value=report(run,read_json(run/'result.json'))
        print(json.dumps({'lab_status':value['lab_status'],'functional_counts':value['functional_counts']}));return 0
    if options.command=='progress':
        run=vm_baseline.ROOT/'vm-runs'/run_id(options.run_id)
        value=read_json(run/'result.json')
        print(json.dumps({k:value.get(k) for k in ['run_id','phase','last_progress_at','outcome','error_category','cleanup','stages']},indent=2))
        return 0
    if options.command=='prepare':
        from .ubuntu_inputs import prepare
        value=prepare(options.store);print(json.dumps({'packages':len(value['packages']),'snapshot':value['snapshot']}));return 0
    value=vm_baseline.execute(options.source,options.terraform,ubuntu_mode=options.mode,dependency_store=options.store,reuse_run=options.reuse_run)
    print(json.dumps(value,indent=2))
    return 0 if value.get('lab_iso_qualified') is True else 1


if __name__=='__main__':raise SystemExit(main())
