"""Pinned baseline or installation-hardened assessment; never qualification."""
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
print(json.dumps({'stage':'assessment-started'}),flush=True)
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
import hashlib,json,pathlib,socket,sys,platform
p=pathlib.Path('/var/lib/wormhole/assessment')
receipt={'run_id':pathlib.Path('/var/lib/wormhole/run-id').read_text().strip(),
 'content_sha256':hashlib.sha256((p/'datastream.xml').read_bytes()).hexdigest(),
 'profile_id':'@PROFILE@','target':socket.gethostname(),
 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'kernel':platform.release(),
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


HARDENED_CHECKS = ('password-required-sudo', 'fips-runtime-mode', 'selinux-enforcing',
    'post-install-reboot', 'encrypted-filesystems', 'encrypted-swap', 'luks-pbkdf2',
    'audit-service', 'time-source-synchronized', 'logging-service')
CRYPTO_OBSERVATIONS = ('openssl_providers', 'kernel_release', 'virtualization')
HARDENED_PROBE = r'''
import json,pathlib,resource,signal,subprocess,tempfile
def command(*args):
 return subprocess.run(args,capture_output=True,text=True,check=True,timeout=10).stdout.strip()
def service_active(unit):
 result=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=10)
 if result.returncode in (3,4):return False
 result.check_returncode()
 return result.stdout.strip()=='active'
def crypto_observe(args):
 with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
  status=None;error=None
  try:
   status=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=10,
    preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(8192,8192))).returncode
  except Exception as exc:error=type(exc).__name__
  out.seek(0);err.seek(0);stdout=out.read(8193);stderr=err.read(1025)
  truncated=len(stdout)>=8192 or len(stderr)>1024 or status==-signal.SIGXFSZ
  return {'status':'observed' if status==0 and stdout and not truncated else 'error',
   'returncode':status,'stdout':stdout[:8192].decode(errors='replace'),
   'stderr':stderr[:1024].decode(errors='replace'),'truncated':truncated,'error':error}
def encrypted(source):
 return 'crypt' in command('lsblk','-s','-n','-o','TYPE',source).splitlines()
def filesystems():
 sources=[]
 for mount,options in {'/':set(),'/home':{'nodev','nosuid'},'/tmp':{'nodev','nosuid','noexec'},
   '/var':{'nodev'},'/var/log':{'nodev','nosuid','noexec'},
   '/var/log/audit':{'nodev','nosuid','noexec'},'/var/tmp':{'nodev','nosuid','noexec'}}.items():
  target,source,actual=command('findmnt','-n','-o','TARGET,SOURCE,OPTIONS','--target',mount).split()
  if target!=mount or not options<=set(actual.split(',')) or not encrypted(source):return False
  sources.append(source)
 return len(set(sources))==len(sources)
def swap():
 sources=command('swapon','--show=NAME','--noheadings').splitlines()
 return bool(sources) and all(encrypted(source) for source in sources)
root=pathlib.Path('/var/lib/wormhole')
observations={
 'fips-runtime-mode':lambda:pathlib.Path('/proc/sys/crypto/fips_enabled').read_text().strip()=='1' and command('update-crypto-policies','--show').split(':')[0]=='FIPS',
 'selinux-enforcing':lambda:command('getenforce')=='Enforcing',
 'post-install-reboot':lambda:bool((root/'installation-boot-id').read_text().strip()) and (root/'installation-boot-id').read_text().strip()!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'encrypted-filesystems':filesystems,'encrypted-swap':swap,
 'luks-pbkdf2':lambda:'pbkdf2' in command('cryptsetup','luksDump','/dev/vda3').lower(),
 'audit-service':lambda:service_active('auditd'),
 'time-source-synchronized':lambda:service_active('chronyd') and any(line.split()[:2]==['^*','192.0.2.1'] for line in command('chronyc','-n','sources').splitlines()),
 'logging-service':lambda:service_active('rsyslog')}
checks={};errors={}
for name,observe in observations.items():
 try:checks[name]=bool(observe())
 except Exception as error:checks[name]=None;errors[name]=type(error).__name__
crypto_runtime={name:crypto_observe(args) for name,args in {
 'openssl_providers':['openssl','list','-providers','-verbose'],
 'kernel_release':['uname','-r'],'virtualization':['systemd-detect-virt','--vm']}.items()}
print(json.dumps({'checks':checks,'errors':errors,'crypto_runtime':crypto_runtime}))
'''


def hardened_audit_code():
    """Same native collector, fixed hardened content, stdin-only sudo secret."""
    from .rhel_hardening import CONTENT
    prefix = 'functional_probe=' + repr(HARDENED_PROBE) + '\nexpected_checks=' + repr(HARDENED_CHECKS) + '\n' + r'''
import shlex
password=c.pop('become_password')
checks=dict.fromkeys(expected_checks)
remaining=deadline-time.monotonic()
if remaining<=50:raise RuntimeError('assessment_deadline')
r=subprocess.run(['ssh',*opts,'lab.service@'+c['address'],'sudo -k -n true'],capture_output=True,timeout=min(15,remaining))
checks['password-required-sudo']=r.returncode==1
r=subprocess.run(['ssh',*opts,'lab.service@'+c['address'],'sudo -S -p "" /usr/bin/python3 -c '+shlex.quote(functional_probe)],
 input=(password+'\n').encode(),capture_output=True,timeout=min(180,max(1,deadline-time.monotonic()-35)))
errors={};crypto_runtime={}
if r.returncode==0:
 try:
  observed=json.loads(r.stdout)
  if set(observed['checks'])!=set(expected_checks)-{'password-required-sudo'}:raise ValueError('check inventory')
  checks.update(observed['checks']);errors=observed.get('errors',{});crypto_runtime=observed.get('crypto_runtime',{})
 except (ValueError,KeyError,TypeError):errors={'observer':'invalid-result'}
else:errors={'observer':'remote-observation-failed'}
functional_ok=all(value is True for value in checks.values())
print(json.dumps({'stage':'hardened-functional','returncode':0 if functional_ok else 1,
 'checks':checks,'errors':errors,'crypto_runtime':crypto_runtime}),flush=True)
'''
    code = RHEL_AUDIT_CODE.replace(CONTENT_SHA, CONTENT['sha256']).replace(
        '/usr/share/xml/scap/ssg/content/ssg-rhel10-ds.xml', '/usr/local/share/wormhole/ssg-rhel10-ds.xml')
    code = code.replace("'sudo -n /bin/bash -s'", "'sudo -S -p \"\" /bin/bash -c '+shlex.quote(audit.replace('@SECONDS@',str(int(remaining-30))))").replace(
        "input=audit.replace('@SECONDS@',str(int(remaining-30))).encode()",
        "input=(password+'\\n').encode()")
    code = code.replace("'outcome':'baseline-passed'", "'outcome':'assessment-evidence-collected' if functional_ok else 'hardened-functional-failed'")
    code = code.replace("'scanner_exit':int(sys.argv[1])", "'scanner_exit':int(sys.argv[1]),'remediation_during_assessment':False,'installation_boot_id':pathlib.Path('/var/lib/wormhole/installation-boot-id').read_text().strip()")
    return prefix + code + '\nif not functional_ok:sys.exit(1)\n'


HARDENED_AUDIT_CODE = hardened_audit_code()


def read_results(content, native, *, expected_target, scanner_exit, expected_hash=CONTENT_SHA, expected_rules=948, hardened=False):
    """Fixture overrides are explicit; live content selection is capability-bound."""
    if hardened:
        from .rhel_hardening import CONTENT
        expected_hash,expected_rules=CONTENT['sha256'],CONTENT['rules']
    require(0 < len(content) <= 64 * 1024**2 and 0 < len(native) <= 64 * 1024**2, 'assessment_size')
    require(hashlib.sha256(content).hexdigest() == expected_hash, 'assessment_content_mismatch')
    root = ET.fromstring(content)
    profiles = [p for p in root.iter(X + 'Profile') if p.get('id') == PROFILE]
    require(len(profiles) == 1 and profiles[0].get('extends') is None, 'assessment_profile_mismatch')
    if hardened:
        description=' '.join(' '.join(profiles[0].find(X+'description').itertext()).split()) if profiles[0].find(X+'description') is not None else ''
        require(any(b.findtext(X+'version')==CONTENT['release'] for b in root.iter(X+'Benchmark')) and
            profiles[0].findtext(X+'title')=='DISA STIG for Red Hat Enterprise Linux 10' and
            'Red Hat Enterprise Linux 10 V1R2' in description,'assessment_content_metadata')
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
    summary = {'schema_version': '1.0', 'capability': 'real-rhel-vendor-stig-baseline',
        'content_sha256': expected_hash, 'content_version': '0.1.76', 'content_status': 'draft',
        'profile_id': PROFILE, 'target': expected_target, 'scanner_exit': scanner_exit,
        'scanner_execution_completed': True, 'coverage_complete': True, 'upstream_rule_count': len(planned),
        'native_counts': dict(Counter(observed.values())),
        'rules': [{'rule_id': key, 'title': planned[key], 'native_status': status} for key, status in observed.items()],
        'lab_iso_qualified': False, 'production_iso_eligible': False,
        'limitation': 'DVD vendor draft anticipates RHEL 10 STIG; no released DISA benchmark alignment or hardening qualification.'}
    if hardened:
        require(sum(status!='notselected' for status in observed.values())==CONTENT['selected_rules'],'assessment_selected_coverage')
        summary.update(capability='real-rhel-hardened-assessment',content_version=CONTENT['release'],
            content_status='upstream-versioned-profile',benchmark=CONTENT['benchmark'],
            limitation='Pinned ComplianceAsCode V1R2 assessment after installation hardening; findings and manual controls remain visible. FIPS mode is not proof of module certification or operational-environment applicability. Lab qualification and eligible ISO publication remain unproven.')
    return summary


def collect(run, result, rows):
    """Persist the fixed native bundle before the existing VM teardown."""
    from .rhel_hardening import CAPABILITY, CONTENT
    build=result.get('build',{})
    hardened=build.get('capability')==CAPABILITY
    require(build.get('assessment_content')==CONTENT if hardened else 'assessment_content' not in build,
        'assessment_content_contract')
    expected_hash=CONTENT['sha256'] if hardened else CONTENT_SHA
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
            receipt.get('content_sha256') == expected_hash and receipt.get('profile_id') == PROFILE, 'assessment_receipt_identity')
    run_id(receipt.get('boot_id'))
    if hardened:
        run_id(receipt.get('installation_boot_id'))
        require(receipt.get('remediation_during_assessment') is False and
            receipt['installation_boot_id']!=receipt['boot_id'],'assessment_installed_reboot_unverified')
    content = (out / 'datastream.xml').read_bytes()
    summary = read_results(content, (out / 'xccdf.xml').read_bytes(), expected_target=target, scanner_exit=receipt.get('scanner_exit'),hardened=hardened)
    arf = read_results(content, (out / 'arf.xml').read_bytes(), expected_target=target, scanner_exit=receipt.get('scanner_exit'),hardened=hardened)
    require(arf['rules'] == summary['rules'] and (out / 'report.html').stat().st_size > 0 and
            (out / 'scanner-version.txt').stat().st_size > 0, 'assessment_native_files_inconsistent')
    summary.update(run_id=result['run_id'], boot_id=receipt['boot_id'],
                   native_hashes={name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in sorted(FILES)})
    write_svd(run, result, rows, receipt)
    if hardened:
        observations=[row for row in rows if row.get('stage')=='hardened-functional']
        checks=observations[0].get('checks',{}) if len(observations)==1 else {}
        summary['functional_results']=[{'id':name,'status':'pass' if checks.get(name) is True else
            'fail' if checks.get(name) is False else 'blocked'} for name in HARDENED_CHECKS]
        summary['functional_counts']=dict(Counter(row['status'] for row in summary['functional_results']))
        summary['all_functional_checks_pass']=len(observations)==1 and set(checks)==set(HARDENED_CHECKS) and observations[0].get('returncode')==0 and all(row['status']=='pass' for row in summary['functional_results'])
        crypto=observations[0].get('crypto_runtime',{}) if len(observations)==1 else {}
        summary['crypto_runtime']={name:crypto.get(name,{'status':'missing'}) for name in CRYPTO_OBSERVATIONS}
    atomic_json(Path(run) / 'assessment.json', summary)
    title='RHEL 10 installation-hardened assessment (ComplianceAsCode 0.1.82, V1R2)' if hardened else 'RHEL 10 DVD vendor-STIG baseline (draft 0.1.76)'
    (Path(run) / 'assessment.txt').write_text(title+'\n'
        + '\n'.join(f'{key}: {value}' for key, value in sorted(summary['native_counts'].items()))
        + f'\nAll {summary["upstream_rule_count"]} rules accounted for. Lab and production qualification: false.\n' + summary['limitation'] + '\n'
        + ''.join(row['id']+': '+row['status']+'\n' for row in summary.get('functional_results',[]))
        + ''.join('Crypto runtime '+name+': '+json.dumps(value,sort_keys=True)+'\n'
                  for name,value in summary.get('crypto_runtime',{}).items()))
    return summary


def write_svd(run, result, rows, receipt):
    """Render the actual Ansible RPM result; never scrape its decorated stdout."""
    records=[r for r in rows if r.get('stage')=='inventory']
    require(len(records)==1 and records[0].get('returncode')==0,'svd_inventory_missing')
    response=records[0].get('response',{})
    require(response.get('rc')==0 and not response.get('failed') and not response.get('unreachable'),
            'svd_inventory_failed')
    lines=response.get('stdout_lines')
    require(type(lines) is list and 0<len(lines)<=10000,'svd_inventory_incomplete')
    packages=[];keys=[];seen=set()
    for line in lines:
        require(type(line) is str and len(line)<=4096,'svd_rpm_row_invalid')
        fields=line.split('|')
        require(len(fields)==5 and all(fields) and fields[1].isdigit(),'svd_rpm_row_invalid')
        identity=tuple(fields)
        require(identity not in seen,'svd_rpm_duplicate');seen.add(identity)
        row=dict(zip(('name','epoch','version','release','architecture'),fields))
        if row['name']=='gpg-pubkey':
            row['architecture']=None if row['architecture']=='(none)' else row['architecture'];keys.append(row)
        else:packages.append(row)
    require(bool(packages) and type(receipt.get('kernel')) is str and bool(receipt['kernel']),
            'svd_inventory_incomplete')
    value={'schema_version':'1.0','kind':'observed-installed-software','run_id':result['run_id'],
        'source_revision':result['source_revision'],'candidate_sha256':result['build']['candidate_sha256'],
        'boot_id':receipt['boot_id'],'kernel':receipt['kernel'],'package_manager':'rpm',
        'packages':sorted(packages,key=lambda p:tuple(p.values())),
        'rpm_key_headers':sorted(keys,key=lambda p:(p['version'],p['release'])),
        'inventory_complete':True,'collector':'ansible-command-rpm-query',
        'production_iso_eligible':False}
    atomic_json(Path(run)/'installed-svd.json',value)
    text=['Observed installed RHEL software','Candidate: '+value['candidate_sha256'],
          'Kernel: '+value['kernel'],'RPM packages (name epoch version release architecture):']
    text += [' '.join(p.values()) for p in value['packages']]
    text += ['','RPM virtual key headers (not application packages):']
    text += [' '.join(str(v) for v in p.values()) for p in value['rpm_key_headers']]
    (Path(run)/'installed-svd.txt').write_text('\n'.join(text)+'\n')
    return value
