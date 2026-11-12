"""RHEL 10 lab release gate and exact-byte local publisher."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET

from .media_store import fingerprint
from .rhel_assessment import HARDENED_CHECKS
from .rhel_hardening import CAPABILITY, CONTENT, LAB_PROFILE, POLICY, SSSD_CERTMAP_RULE, installation_contract
from .rhel_manual import MANUAL_RULES
from .runs import RunError, atomic_json, read_json, run_id, workspace_path
from .vm_admission import require
from .vm_inputs import sha256

OE_REFERENCE = POLICY.parent / 'rhel10-crypto-operating-environment-2026-11-12.json'
NATIVE_FILES = ('datastream.xml', 'xccdf.xml', 'arf.xml', 'report.html',
    'scanner-version.txt', 'receipt.json')
SECRET_FILES = ('ssh-key', 'ssh-key.pub', 'sudo-password', 'boot-password', 'unlock-secret')
MODULE_PACKAGES = ('openssl-fips-provider', 'kernel-core', 'gnutls', 'nss')
MODULE_PACKAGE_NAMES = {'openssl':'openssl-fips-provider','kernel_crypto_api':'kernel-core',
    'gnutls':'gnutls','nss':'nss'}
INSTALLATION_FILES = ('result.json','qualification.json','qualification.txt','junit.xml',
    'assessment.json','assessment.txt','installed-svd.json','installed-svd.txt',
    'manual-evidence.json','crypto-operating-environment.json','installation-manifest.json')


def _public_json(path):
    return json.loads(Path(path).read_text())


def _json_once(path,value):
    path=Path(path)
    if path.exists():require(read_json(path)==value,'qualification_evidence_changed')
    else:atomic_json(path,value)


def _text_once(path,value):
    path=Path(path)
    if path.exists():require(path.read_text()==value,'qualification_evidence_changed')
    else:path.write_text(value)


def _nevra(row):
    return row['name']+'-'+row['version']+'-'+row['release']+'.'+row['architecture']


def _oe_verified(reference, observed):
    if reference.get('cryptographic_module_operational_environment_verified') is not True:return False
    modules=reference.get('modules',{})
    require(set(modules)==set(MODULE_PACKAGE_NAMES) and reference.get('decision')=='verified',
        'crypto_operating_environment_reference_invalid')
    declared=reference['declared_environment']
    for module,package in MODULE_PACKAGE_NAMES.items():
        row=modules[module];installed=observed.get(package)
        require(row.get('status')=='validated' and type(row.get('certificate')) is str and row['certificate']
            and row.get('package_name')==package and declared in row.get('operating_environments',[])
            and installed is not None and _nevra(installed) in row.get('allowed_nevras',[]),
            'crypto_operating_environment_reference_invalid')
    return True


def crypto_evidence(run):
    """Bind technical observations to the reviewed public OE status; never infer validation."""
    root=Path(run);result=read_json(root/'result.json');assessment=read_json(root/'assessment.json')
    svd=read_json(root/'installed-svd.json');reference=_public_json(OE_REFERENCE)
    packages={row['name']:row for row in svd.get('packages',[]) if type(row) is dict and 'name' in row}
    observed={name:packages.get(name) for name in MODULE_PACKAGES}
    runtime=assessment.get('crypto_runtime',{})
    runtime_complete=(result.get('hardened_checks',{}).get('fips-runtime-mode')=='pass' and
        set(runtime)=={'openssl_providers','kernel_release','virtualization'} and
        all(row.get('status')=='observed' for row in runtime.values()))
    verified=_oe_verified(reference,observed)
    value={'schema_version':'1.0','run_id':result['run_id'],
        'candidate_sha256':result['build']['candidate_sha256'],
        'policy_sha256':sha256(POLICY),'oe_reference_sha256':sha256(OE_REFERENCE),
        'declared_environment':reference['declared_environment'],
        'observed':{'fips_runtime_complete':runtime_complete,
            'module_package_identity_complete':all(observed.values()),
            'module_packages':observed,'runtime_probes':runtime},
        'authoritative_status':{'evidence_date':reference['evidence_date'],
            'sources':reference['sources'],'modules':reference['modules'],
            'certificate_5573':reference['certificate_5573']},
        'cryptographic_module_operational_environment_verified':verified,
        'decision':reference['decision'],'limitation':reference['limitation'],
        'lab_iso_qualified':False,'production_iso_eligible':False}
    path=root/'crypto-operating-environment.json'
    if path.exists():require(read_json(path)==value,'crypto_evidence_changed')
    else:atomic_json(path,value)
    return value


def _load(run):
    root=Path(run);policy=_public_json(POLICY);reference=_public_json(OE_REFERENCE)
    result=read_json(root/'result.json');assessment=read_json(root/'assessment.json')
    manual=read_json(root/'manual-evidence.json');svd=read_json(root/'installed-svd.json')
    receipt=read_json(root/'assessment/receipt.json');crypto=read_json(root/'crypto-operating-environment.json')
    build=result.get('build',{});contract=build.get('installation_contract',{})
    require(read_json(root/'inputs/build-manifest.json')==build,'release_build_manifest_mismatch')
    require(result.get('capability')=='real-iso-installation-baseline' and result.get('distribution')=='rhel10'
        and result.get('provisioner')=='terraform' and result.get('scenario')=='healthy'
        and result.get('outcome')=='baseline-passed' and result.get('installed') is True
        and result.get('final_authentication') is True and result.get('ansible_ready') is True
        and result.get('cold_start_verified') is True and result.get('cleanup')=='verified-absent-inputs-retained',
        'release_runtime_incomplete')
    require(build.get('capability')==CAPABILITY and build.get('mode')=='hardened'
        and build.get('assessment_content')==CONTENT and build.get('policy_sha256')==sha256(POLICY)
        and contract.get('policy_sha256')==sha256(POLICY)
        and contract.get('tailoring_sha256')==receipt.get('tailoring_sha256')
        and build.get('installed_input_fingerprint')==fingerprint(installation_contract()), 'stale_candidate')
    from .vm_baseline import controller_checks
    require(result.get('checks')==dict.fromkeys(controller_checks([],assessment=True),'pass')
        and result.get('hardened_checks')==dict.fromkeys(HARDENED_CHECKS,'pass'), 'release_functional_incomplete')
    offline=result.get('offline_encryption',{})
    require(all(offline.get(key) is True for key in ('powered_off_logical_read','luks_magic_verified',
        'correct_key_accepted','wrong_key_refused','missing_key_refused')) and offline.get('disk_modified') is False
        and offline.get('swap')=='encrypted-lvm' and all(not (root/name).exists() for name in SECRET_FILES),
        'release_encryption_incomplete')
    require(receipt.get('run_id')==result['run_id'] and receipt.get('target')=='vm-'+result['run_id'][:8]
        and receipt.get('content_sha256')==CONTENT['sha256'] and receipt.get('profile_id')==LAB_PROFILE
        and receipt.get('remediation_during_assessment') is False
        and receipt.get('installation_boot_id')!=receipt.get('boot_id'), 'release_receipt_mismatch')
    run_id(receipt.get('installation_boot_id'));run_id(receipt.get('boot_id'))
    native_hashes=assessment.get('native_hashes',{})
    require(all((root/'assessment'/name).is_file() and (root/'assessment'/name).stat().st_size>0
        and native_hashes.get(name)==sha256(root/'assessment'/name) for name in NATIVE_FILES),
        'release_native_assessment_missing')
    rows=assessment.get('rules',[]);native={row.get('rule_id'):row.get('native_status') for row in rows}
    require(len(rows)==len(native)==policy['content']['upstream_rules'] and
        Counter(native.values())==Counter(assessment.get('native_counts',{})) and
        sum(status!='notselected' for status in native.values())==policy['content']['selected_rules']
        and not ({'fail','error','unknown','fixed','missing'} & set(native.values()))
        and {rule for rule,status in native.items() if status=='notchecked'}==set(MANUAL_RULES)
        and native.get(SSSD_CERTMAP_RULE)=='notselected'
        and assessment.get('run_id')==result['run_id'] and assessment.get('boot_id')==receipt['boot_id']
        and assessment.get('content_sha256')==CONTENT['sha256'] and assessment.get('profile_id')==LAB_PROFILE
        and assessment.get('scanner_execution_completed') is True and assessment.get('coverage_complete') is True
        and assessment.get('all_functional_checks_pass') is True
        and assessment.get('functional_results')==[{'id':name,'status':'pass'} for name in HARDENED_CHECKS],
        'release_assessment_ineligible')
    from .rhel_assessment import read_results
    parsed=read_results((root/'assessment/datastream.xml').read_bytes(),
        (root/'assessment/xccdf.xml').read_bytes(),expected_target=receipt['target'],
        scanner_exit=receipt.get('scanner_exit'),hardened=True)
    parsed_arf=read_results((root/'assessment/datastream.xml').read_bytes(),
        (root/'assessment/arf.xml').read_bytes(),expected_target=receipt['target'],
        scanner_exit=receipt.get('scanner_exit'),hardened=True)
    require({row['rule_id']:row['native_status'] for row in parsed['rules']}==native
        and parsed['native_counts']==assessment['native_counts'] and parsed_arf['rules']==parsed['rules'],
        'release_native_assessment_mismatch')
    objective=manual.get('objective_results',{})
    require(manual.get('run_id')==result['run_id'] and manual.get('candidate_sha256')==build['candidate_sha256']
        and manual.get('policy_sha256')==sha256(POLICY) and manual.get('content_sha256')==CONTENT['sha256']
        and manual.get('tailoring_sha256')==contract['tailoring_sha256']
        and manual.get('native_statuses')=={rule:'notchecked' for rule in MANUAL_RULES}
        and manual.get('native_notchecked_statuses_preserved') is True
        and manual.get('all_required_manual_evidence_complete') is True
        and manual.get('exception_approved') is False and set(objective)==set(MANUAL_RULES)
        and all(row.get('observed_satisfied') is True and row.get('disposition') in {'satisfied','not-applicable'}
                for row in objective.values()), 'release_manual_requirements_pending')
    require(svd.get('run_id')==result['run_id'] and svd.get('source_revision')==result['source_revision']
        and svd.get('candidate_sha256')==build['candidate_sha256'] and svd.get('boot_id')==receipt['boot_id']
        and svd.get('package_manager')=='rpm' and svd.get('inventory_complete') is True
        and bool(svd.get('packages')) and type(svd.get('rpm_key_headers')) is list and bool(svd.get('kernel')),
        'release_svd_incomplete')
    packages={row['name']:row for row in svd['packages']}
    expected_packages={name:packages.get(name) for name in MODULE_PACKAGES}
    expected_authoritative={'evidence_date':reference['evidence_date'],'sources':reference['sources'],
        'modules':reference['modules'],'certificate_5573':reference['certificate_5573']}
    require(crypto.get('run_id')==result['run_id'] and crypto.get('candidate_sha256')==build['candidate_sha256']
        and crypto.get('policy_sha256')==sha256(POLICY) and crypto.get('oe_reference_sha256')==sha256(OE_REFERENCE)
        and crypto.get('declared_environment')==reference['declared_environment']
        and crypto.get('observed',{}).get('fips_runtime_complete') is True
        and crypto.get('observed',{}).get('module_package_identity_complete') is True
        and crypto.get('observed',{}).get('module_packages')==expected_packages
        and crypto.get('observed',{}).get('runtime_probes')==assessment.get('crypto_runtime')
        and crypto.get('authoritative_status')==expected_authoritative
        and crypto.get('decision')==reference['decision'] and crypto.get('limitation')==reference['limitation']
        and crypto.get('cryptographic_module_operational_environment_verified') is
            _oe_verified(reference,crypto.get('observed',{}).get('module_packages',{}))
        and crypto.get('production_iso_eligible') is False, 'release_crypto_evidence_invalid')
    require(result.get('lab_iso_qualified') is False and result.get('production_iso_eligible') is False,
        'release_scope_invalid')
    return {'root':root,'policy':policy,'result':result,'assessment':assessment,'manual':manual,
        'svd':svd,'receipt':receipt,'crypto':crypto,'native':native}


def evaluate(run):
    root=Path(run);crypto_evidence(root);value=_load(root)
    rows=[]
    for name,status in value['result']['checks'].items():rows.append({'id':'controller:'+name,'status':status})
    for name,status in value['result']['hardened_checks'].items():rows.append({'id':'hardened:'+name,'status':status})
    for rule,status in value['native'].items():
        rows.append({'id':'scap:'+rule,'status':'pass' if status=='pass' else 'skipped' if status in
            {'notapplicable','notselected','notchecked','informational'} else 'fail','native_status':status})
    for rule in MANUAL_RULES:rows.append({'id':'manual:'+rule,'status':'pass'})
    oe=value['crypto']['cryptographic_module_operational_environment_verified']
    rows.extend(({'id':'crypto:runtime-and-module-identity','status':'pass'},
        {'id':'crypto:validated-operating-environment','status':'pass' if oe else 'blocked'},
        {'id':'release:independent-same-candidate-pair','status':'blocked'},
        {'id':'release:exact-byte-publication-readback','status':'blocked'}))
    reasons=[]
    if not oe:reasons.append('cryptographic-module-operational-environment-unverified')
    reasons.extend(('two-independent-matching-installations-not-yet-verified','exact-byte-publication-not-yet-verified'))
    report={'schema_version':'1.0','capability':'rhel10-lab-evidence-report',
        'run_id':value['result']['run_id'],'source_revision':value['result']['source_revision'],
        'candidate_sha256':value['result']['build']['candidate_sha256'],
        'policy_id':value['policy']['policy_id'],'policy_sha256':sha256(POLICY),
        'native_counts':value['assessment']['native_counts'],
        'manual_counts':dict(Counter(row['disposition'] for row in value['manual']['objective_results'].values())),
        'results':rows,'counts':dict(Counter(row['status'] for row in rows)),
        'qualification_reasons':reasons,'lab_status':'LAB QUALIFICATION PENDING',
        'lab_iso_qualified':False,'production_iso_eligible':False}
    _json_once(root/'qualification.json',report)
    text=['RHEL 10 lab evidence',report['lab_status'],'Implementation: '+report['source_revision'],
        'Candidate SHA256: '+report['candidate_sha256'],'Native: '+json.dumps(report['native_counts'],sort_keys=True),
        'Manual: '+json.dumps(report['manual_counts'],sort_keys=True),'Cleanup: '+value['result']['cleanup'],'',
        'Qualification unresolved:',*reasons]
    _text_once(root/'qualification.txt','\n'.join(text)+'\n')
    suite=ET.Element('testsuite',name='rhel10-functional-assessment-and-release')
    for row in rows:
        case=ET.SubElement(suite,'testcase',classname=row['id'].split(':',1)[0],name=row['id'])
        if row['status']=='fail':ET.SubElement(case,'failure',message=row.get('native_status','failed'))
        elif row['status'] in {'blocked','skipped'}:ET.SubElement(case,'skipped',message=row.get('native_status',row['status']))
    suite.set('tests',str(len(rows)));suite.set('failures',str(len(suite.findall('./testcase/failure'))))
    suite.set('skipped',str(len(suite.findall('./testcase/skipped'))))
    junit=ET.tostring(suite,encoding='utf-8',xml_declaration=True)
    path=root/'junit.xml'
    if path.exists():require(path.read_bytes()==junit,'qualification_evidence_changed')
    else:path.write_bytes(junit)
    return report


def _identity(value):
    result=value['result'];receipt=value['receipt'];console=value['root']/'console.log'
    require(console.is_file() and console.stat().st_size<=64*1024**2, 'release_installation_identity_missing')
    from .vm_baseline import console_host_key
    key=console_host_key(console.read_text(errors='replace'),'ssh-rsa')
    require(key is not None and re.fullmatch(r'[0-9a-f]{64}',result['build'].get('seed_sha256','')),
        'release_installation_identity_missing')
    return result['build']['seed_sha256'],{receipt['installation_boot_id'],receipt['boot_id']},key


def compare(previous,current):
    a,b=_load(previous),_load(current);ai,bi=_identity(a),_identity(b)
    same=(a['result']['build']['candidate_sha256']==b['result']['build']['candidate_sha256'] and
        a['result']['source_revision']==b['result']['source_revision'] and
        a['result']['build']['installed_input_fingerprint']==b['result']['build']['installed_input_fingerprint'] and
        a['result']['build']['policy_sha256']==b['result']['build']['policy_sha256'] and
        a['receipt']['content_sha256']==b['receipt']['content_sha256'] and
        a['receipt']['tailoring_sha256']==b['receipt']['tailoring_sha256'] and
        a['result']['checks']==b['result']['checks'] and a['result']['hardened_checks']==b['result']['hardened_checks'] and
        a['native']==b['native'] and a['manual']['native_statuses']==b['manual']['native_statuses'] and
        a['manual']['objective_results']==b['manual']['objective_results'] and
        a['crypto']['oe_reference_sha256']==b['crypto']['oe_reference_sha256'] and
        a['crypto']['observed']==b['crypto']['observed'] and
        a['crypto']['cryptographic_module_operational_environment_verified']==
            b['crypto']['cryptographic_module_operational_environment_verified'] and
        a['svd']['kernel']==b['svd']['kernel'] and
        a['svd']['packages']==b['svd']['packages'] and a['svd']['rpm_key_headers']==b['svd']['rpm_key_headers'])
    independent=(a['result']['run_id']!=b['result']['run_id'] and ai[0]!=bi[0] and ai[1].isdisjoint(bi[1]) and ai[2]!=bi[2])
    return {'schema_version':'1.0','previous_run':a['result']['run_id'],'current_run':b['result']['run_id'],
        'same_tested_iso':a['result']['build']['candidate_sha256']==b['result']['build']['candidate_sha256'],
        'same_installation_contract':a['result']['build']['installed_input_fingerprint']==b['result']['build']['installed_input_fingerprint'],
        'independent_installation_identities':independent,'equivalent_fresh_installations':bool(same and independent),
        'lab_iso_qualified':False,'production_iso_eligible':False}


def eligible(current,previous,*,candidate):
    policy=_public_json(POLICY);require(not policy['unresolved_requirements'],'lab_policy_dependencies_pending')
    for run in (previous,current):
        value=_load(run)
        require(value['crypto']['cryptographic_module_operational_environment_verified'] is True,
            'cryptographic_operational_environment_unverified')
    delta=compare(previous,current);require(delta['equivalent_fresh_installations'],'release_repeatability_unproven')
    result=read_json(Path(current)/'result.json')
    require(sha256(candidate)==result['build']['candidate_sha256'],'release_candidate_changed')
    return result,delta


def publish(current,previous,*,candidate,destination,name):
    require(re.fullmatch(r'Jake-RHEL-10-LAB-QUALIFIED-[a-z0-9-]{1,60}',name) is not None,'release_name_invalid')
    require(not (workspace_path(destination)/name).exists(),'duplicate_publication')
    require(not _public_json(POLICY)['unresolved_requirements'],'lab_policy_dependencies_pending')
    from .storage import Store
    with Store().locked():return _publish(current,previous,candidate=candidate,destination=destination,name=name)


def _publish(current,previous,*,candidate,destination,name):
    root=workspace_path(destination);output=root/name
    require(not output.exists(),'duplicate_publication')
    result,delta=eligible(current,previous,candidate=candidate)
    output.mkdir(mode=0o700);iso=output/(name+'.iso');shutil.copyfile(candidate,iso)
    require(sha256(iso)==result['build']['candidate_sha256'],'publication_copy_changed')
    for label,run in (('installation-1',previous),('installation-2',current)):
        evidence=output/label;evidence.mkdir(mode=0o700)
        for source in ('result.json','qualification.json','qualification.txt','junit.xml','assessment.json',
                'assessment.txt','installed-svd.json','installed-svd.txt','manual-evidence.json',
                'crypto-operating-environment.json'):
            shutil.copyfile(Path(run)/source,evidence/source)
        shutil.copyfile(Path(run)/'inputs/build-manifest.json',evidence/'installation-manifest.json')
        native=evidence/'assessment';native.mkdir(mode=0o700)
        for source in NATIVE_FILES:shutil.copyfile(Path(run)/'assessment'/source,native/source)
    (output/'SHA256SUMS').write_text(result['build']['candidate_sha256']+'  '+iso.name+'\n')
    shutil.copyfile(POLICY,output/'policy.json');shutil.copyfile(OE_REFERENCE,output/'crypto-oe-reference.json')
    atomic_json(output/'comparison.json',delta)
    decision={'schema_version':'1.0','capability':'lab-qualified-rhel10-iso',
        'candidate_sha256':result['build']['candidate_sha256'],'installations':[delta['previous_run'],delta['current_run']],
        'policy_sha256':sha256(POLICY),'oe_reference_sha256':sha256(OE_REFERENCE),
        'lab_iso_qualified':True,'production_iso_eligible':False}
    atomic_json(output/'release-decision.json',decision)
    manifest={**decision,'native_reports':'restricted private local bundle; public export is not authorized'}
    files=[path for path in output.rglob('*') if path.is_file()]
    manifest['files']=[{'path':path.relative_to(output).as_posix(),'bytes':path.stat().st_size,'sha256':sha256(path)} for path in sorted(files)]
    for file in files:
        file.chmod(0o600)
        with file.open('rb') as stream:os.fsync(stream.fileno())
    atomic_json(output/'manifest.json',manifest)
    for directory in sorted([p for p in output.rglob('*') if p.is_dir()],key=lambda p:len(p.parts),reverse=True)+[output]:
        descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    atomic_json(output/'complete.json',{'manifest_sha256':sha256(output/'manifest.json')})
    for directory in (output,root):
        descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    verify(output)
    return manifest


def _verify_installation(folder,run,candidate,policy,reference):
    result=read_json(folder/'result.json');build=read_json(folder/'installation-manifest.json')
    qualification=read_json(folder/'qualification.json');assessment=read_json(folder/'assessment.json')
    manual=read_json(folder/'manual-evidence.json');svd=read_json(folder/'installed-svd.json')
    crypto=read_json(folder/'crypto-operating-environment.json');receipt=read_json(folder/'assessment/receipt.json')
    require(result.get('run_id')==run and result.get('build')==build and build.get('candidate_sha256')==candidate
        and build.get('policy_sha256')==sha256(folder.parent/'policy.json')
        and build.get('installation_contract',{}).get('policy_sha256')==sha256(folder.parent/'policy.json')
        and qualification.get('run_id')==run and qualification.get('source_revision')==result.get('source_revision')
        and qualification.get('candidate_sha256')==candidate
        and qualification.get('policy_sha256')==sha256(folder.parent/'policy.json')
        and qualification.get('lab_iso_qualified') is False and qualification.get('production_iso_eligible') is False,
        'publication_installation_evidence_invalid')
    require(assessment.get('run_id')==run and assessment.get('boot_id')==receipt.get('boot_id')
        and assessment.get('content_sha256')==policy['content']['datastream_sha256']
        and receipt.get('run_id')==run and receipt.get('content_sha256')==policy['content']['datastream_sha256']
        and receipt.get('tailoring_sha256')==build['installation_contract']['tailoring_sha256']
        and receipt.get('remediation_during_assessment') is False
        and svd.get('run_id')==run and svd.get('candidate_sha256')==candidate
        and svd.get('boot_id')==receipt.get('boot_id') and svd.get('inventory_complete') is True
        and manual.get('run_id')==run and manual.get('candidate_sha256')==candidate
        and manual.get('policy_sha256')==sha256(folder.parent/'policy.json')
        and manual.get('content_sha256')==policy['content']['datastream_sha256']
        and manual.get('tailoring_sha256')==receipt.get('tailoring_sha256')
        and manual.get('native_statuses')=={rule:'notchecked' for rule in MANUAL_RULES}
        and manual.get('all_required_manual_evidence_complete') is True and manual.get('exception_approved') is False,
        'publication_installation_evidence_invalid')
    packages={row['name']:row for row in svd.get('packages',[])}
    expected={name:packages.get(name) for name in MODULE_PACKAGES}
    authoritative={'evidence_date':reference['evidence_date'],'sources':reference['sources'],
        'modules':reference['modules'],'certificate_5573':reference['certificate_5573']}
    require(crypto.get('run_id')==run and crypto.get('candidate_sha256')==candidate
        and crypto.get('policy_sha256')==sha256(folder.parent/'policy.json')
        and crypto.get('oe_reference_sha256')==sha256(folder.parent/'crypto-oe-reference.json')
        and crypto.get('observed',{}).get('module_packages')==expected
        and crypto.get('observed',{}).get('runtime_probes')==assessment.get('crypto_runtime')
        and crypto.get('authoritative_status')==authoritative
        and crypto.get('cryptographic_module_operational_environment_verified') is True
        and _oe_verified(reference,expected),'publication_installation_evidence_invalid')
    require(all(assessment.get('native_hashes',{}).get(name)==sha256(folder/'assessment'/name)
        for name in NATIVE_FILES),'publication_native_evidence_changed')


def verify(directory):
    root=workspace_path(directory)
    require((root/'complete.json').is_file() and (root/'manifest.json').is_file(),'publication_incomplete')
    completion=read_json(root/'complete.json');manifest=read_json(root/'manifest.json')
    require(completion.get('manifest_sha256')==sha256(root/'manifest.json'),'publication_manifest_changed')
    require(manifest.get('capability')=='lab-qualified-rhel10-iso' and manifest.get('lab_iso_qualified') is True
        and manifest.get('production_iso_eligible') is False,'publication_scope_invalid')
    names=set()
    for row in manifest['files']:
        require(set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0,
            'publication_file_record_invalid')
        relative=Path(row['path'])
        require(not relative.is_absolute() and not relative.drive and '..' not in relative.parts
            and relative.as_posix()==row['path'] and row['path'] not in names
            and row['path'] not in {'manifest.json','complete.json'},'publication_path_invalid')
        target=root/relative
        require(target.is_file() and all(not path.is_symlink() for path in (target,*target.parents)),
            'publication_file_invalid')
        require(target.stat().st_size==row['bytes'] and sha256(target)==row['sha256'],'publication_file_changed')
        names.add(row['path'])
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    require(actual==names|{'manifest.json','complete.json'},'publication_file_set_changed')
    isos=[root/name for name in names if name.endswith('.iso')]
    require(len(isos)==1 and sha256(isos[0])==manifest['candidate_sha256'],'publication_iso_changed')
    top={'SHA256SUMS','policy.json','crypto-oe-reference.json','comparison.json','release-decision.json',isos[0].name}
    expected=top|{label+'/'+name for label in ('installation-1','installation-2')
        for name in (*INSTALLATION_FILES,*('assessment/'+item for item in NATIVE_FILES))}
    require(names==expected,'publication_structure_invalid')
    decision=read_json(root/'release-decision.json');comparison=read_json(root/'comparison.json')
    policy=_public_json(root/'policy.json');reference=_public_json(root/'crypto-oe-reference.json')
    require(decision=={key:manifest[key] for key in ('schema_version','capability','candidate_sha256',
        'installations','policy_sha256','oe_reference_sha256','lab_iso_qualified','production_iso_eligible')}
        and decision['policy_sha256']==sha256(root/'policy.json')
        and decision['oe_reference_sha256']==sha256(root/'crypto-oe-reference.json')
        and not policy.get('unresolved_requirements')
        and reference.get('cryptographic_module_operational_environment_verified') is True
        and comparison.get('previous_run')==decision['installations'][0]
        and comparison.get('current_run')==decision['installations'][1]
        and comparison.get('same_tested_iso') is True
        and comparison.get('same_installation_contract') is True
        and comparison.get('independent_installation_identities') is True
        and comparison.get('equivalent_fresh_installations') is True,
        'publication_decision_invalid')
    require((root/'SHA256SUMS').read_text()==manifest['candidate_sha256']+'  '+isos[0].name+'\n',
        'publication_checksum_invalid')
    for label,run in zip(('installation-1','installation-2'),decision['installations']):
        _verify_installation(root/label,run,manifest['candidate_sha256'],policy,reference)
    return {'complete':True,'candidate_sha256':manifest['candidate_sha256'],
        'files_verified':len(names),'production_iso_eligible':False}


def main(arguments=None):
    parser=argparse.ArgumentParser();commands=parser.add_subparsers(dest='operation',required=True)
    command=commands.add_parser('evaluate');command.add_argument('run')
    command=commands.add_parser('compare');command.add_argument('previous');command.add_argument('current')
    command=commands.add_parser('publish');command.add_argument('previous');command.add_argument('current')
    command.add_argument('--candidate',required=True);command.add_argument('--destination',required=True);command.add_argument('--name',required=True)
    command=commands.add_parser('verify');command.add_argument('directory')
    options=parser.parse_args(arguments)
    try:
        if options.operation=='evaluate':value=evaluate(options.run)
        elif options.operation=='compare':value=compare(options.previous,options.current)
        elif options.operation=='verify':value=verify(options.directory)
        else:value=publish(options.current,options.previous,candidate=options.candidate,destination=options.destination,name=options.name)
        print(json.dumps(value,sort_keys=True,indent=2));return 0
    except (RunError,OSError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({'error':{'code':getattr(error,'code','release_evidence_invalid'),
            'message':str(error)}},sort_keys=True));return 2


if __name__=='__main__':raise SystemExit(main())
