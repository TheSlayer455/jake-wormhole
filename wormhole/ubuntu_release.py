"""Strict local Ubuntu release boundary; pending policy never publishes."""
import json
import os
from pathlib import Path
import re
import shutil

from .runs import RunError, atomic_json, read_json, workspace_path
from .ubuntu_assessment import POLICY, read_results, require
from .ubuntu_catalog import compare, load
from .ubuntu_inputs import input_identity
from .vm_inputs import sha256


def eligible(current, previous, *, candidate, dependency_store):
    policy=json.loads(POLICY.read_text())
    require(not policy['unresolved_requirements'], 'lab_policy_dependencies_pending')
    from .ubuntu_tailoring import validate
    validate(policy)
    for path in (Path(current),Path(previous)):
        result, report, _, _ = load(path)
        build=result['build']
        require(build['mode']=='hardened' and result['outcome']=='assessment-complete'
                and result['installed'] is True and result['final_authentication'] is True
                and result['ansible_ready'] is True and result['cleanup']=='verified-absent-inputs-retained',
                'release_runtime_incomplete')
        require(build['policy_sha256']==sha256(POLICY) and
                build['installed_input_fingerprint']==input_identity(dependency_store,'hardened',sandbox=build.get('sandbox',False))[0],
                'stale_candidate')
        require(all(r['status']=='pass' for r in report['functional_results']) and
                {r['id'] for r in report['functional_results']}==set(policy['functional_checks']),
                'release_functional_incomplete')
        folder=path/'assessment'
        require(all((folder/name).is_file() and (folder/name).stat().st_size>0
                    for name in ('xccdf.xml','arf.xml','report.html','scanner-receipt.json')),
                'release_native_assessment_missing')
        receipt=read_json(folder/'scanner-receipt.json')
        require(receipt['run_id']==result['run_id'] and receipt['remediation_during_assessment'] is False
                and receipt['boot_id']!=receipt['firstboot_id']
                and receipt['content_sha256']==policy['content']['datastream_sha256'],'release_receipt_mismatch')
        findings=read_results(path/'inputs/payload/ssg-ubuntu2204-ds.xml',folder/'xccdf.xml',
                              expected_target=receipt['target'],scanner_exit=receipt['scanner_exit'])
        require(findings['coverage_complete'] and findings['all_selected_automated_clean']
                and findings['scanner_execution_completed'],'release_assessment_ineligible')
        from .ubuntu_manual import MANUAL_RULES
        records=read_json(path/'controller-records.json')
        manual=next((r for r in records if r.get('stage')=='manual-observations' and r.get('returncode')==0),None)
        require(manual is not None,'release_manual_evidence_missing')
        objectives=json.loads(manual['output']).get('objective_results',{})
        require(set(objectives)==MANUAL_RULES and all(x.get('observed_satisfied') is True for x in objectives.values()),'release_manual_requirements_pending')
        require(all(status in {'pass','notapplicable','notchecked'} for status in findings['manual_native_outcomes'].values()),'release_manual_native_failure')
        from .ubuntu_reports import benchmark_review
        require(benchmark_review(path,result,report['functional_results']),'release_benchmark_review_missing')
    delta=compare(previous,current)
    require(delta['equivalent_fresh_installations'],'release_repeatability_unproven')
    result=read_json(Path(current)/'result.json')
    require(sha256(candidate)==result['build']['candidate_sha256'],'release_candidate_changed')
    return result,delta


def publish(current,previous,*,candidate,dependency_store,destination,name):
    # Preserve existing input/duplicate/policy failures before taking the lock.
    require(re.fullmatch(r'Jake-Ubuntu-22[.]04-LAB-QUALIFIED-[a-z0-9-]{1,60}',name) is not None,'release_name_invalid')
    require(not (workspace_path(destination)/name).exists(),'duplicate_publication')
    require(not json.loads(POLICY.read_text())['unresolved_requirements'], 'lab_policy_dependencies_pending')
    from .storage import Store
    with Store().locked():
        return _publish(current,previous,candidate=candidate,dependency_store=dependency_store,destination=destination,name=name)


def _publish(current,previous,*,candidate,dependency_store,destination,name):
    require(re.fullmatch(r'Jake-Ubuntu-22[.]04-LAB-QUALIFIED-[a-z0-9-]{1,60}',name) is not None,'release_name_invalid')
    root=workspace_path(destination)
    output=root/name
    require(not output.exists(),'duplicate_publication')
    result,delta=eligible(current,previous,candidate=candidate,dependency_store=dependency_store)
    output.mkdir(mode=0o700)
    # A failure leaves an intentionally incomplete directory; no overwrite/retry takeover.
    iso=output/(name+'.iso')
    shutil.copyfile(candidate,iso)
    require(sha256(iso)==result['build']['candidate_sha256'],'publication_copy_changed')
    for label,run in [('installation-1',previous),('installation-2',current)]:
        evidence=output/label;evidence.mkdir(mode=0o700)
        for source in ['result.json','qualification.json','qualification.txt','junit.xml','assessment-coverage.json','installed-svd.json','installed-svd.txt',
                       'manual-evidence.json','encryption-evidence.json','timing.json']:
            shutil.copyfile(Path(run)/source,evidence/source)
        if result['build'].get('sandbox'):
            for source in ('support-health.json','support-verification.json','support-limits.json'):shutil.copyfile(Path(run)/source,evidence/source)
        for source in ('benchmark-reconciliation.json','artifact-secret-inspection.json'):
            if (Path(run)/source).is_file():shutil.copyfile(Path(run)/source,evidence/source)
        shutil.copyfile(Path(run)/'inputs/build-manifest.json',evidence/'installation-manifest.json')
        shutil.copytree(Path(run)/'build-svd',evidence/'build-svd')
        assessment=evidence/'assessments';assessment.mkdir(mode=0o700)
        # This destination is private local storage, never a public export.
        # Console captures, seed, credentials and Terraform state stay separate.
        for source in ['findings.json','xccdf.xml','arf.xml','report.html','scanner-version.txt','scanner-receipt.json']:
            shutil.copyfile(Path(run)/'assessment'/source,assessment/source)
        for source in ('upstream-xccdf.xml','upstream-exit.txt','upstream-scanner.log',
                       'legacy-encryption.xml','legacy-encryption-exit.txt','legacy-encryption.log'):
            if (Path(run)/'assessment'/source).is_file():shutil.copyfile(Path(run)/'assessment'/source,assessment/source)
    (output/'SHA256SUMS').write_text(result['build']['candidate_sha256']+'  '+iso.name+'\n')
    shutil.copyfile(POLICY,output/'policy.json')
    atomic_json(output/'comparison.json',delta)
    manifest={'schema_version':'1.0','capability':'lab-qualified-ubuntu-iso','candidate_sha256':sha256(iso),
              'lab_iso_qualified':True,'production_iso_eligible':False,
              'policy_sha256':sha256(POLICY),'installations':[delta['previous_run'],delta['current_run']],
              'native_reports':'restricted private local bundle; public export is not authorized'}
    files=[p for p in output.rglob('*') if p.is_file()]
    manifest['files']=[{'path':p.relative_to(output).as_posix(),'bytes':p.stat().st_size,'sha256':sha256(p)} for p in sorted(files)]
    for file in files:
        with file.open('rb') as stream:os.fsync(stream.fileno())
    atomic_json(output/'manifest.json',manifest)
    for directory in sorted([p for p in output.rglob('*') if p.is_dir()],key=lambda p:len(p.parts),reverse=True)+[output]:
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    atomic_json(output/'complete.json',{'manifest_sha256':sha256(output/'manifest.json')})
    for directory in (output,root):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    verify(output)
    return manifest


def verify(directory):
    """Consumer readback checks bytes/closure, not independent accreditation."""
    root=workspace_path(directory)
    require((root/'complete.json').is_file() and (root/'manifest.json').is_file(),'publication_incomplete')
    completion=read_json(root/'complete.json');manifest=read_json(root/'manifest.json')
    require(completion.get('manifest_sha256')==sha256(root/'manifest.json'),'publication_manifest_changed')
    require(manifest.get('capability')=='lab-qualified-ubuntu-iso' and manifest.get('lab_iso_qualified') is True
            and manifest.get('production_iso_eligible') is False,'publication_scope_invalid')
    names=set()
    for row in manifest['files']:
        require(set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0,'publication_file_record_invalid')
        relative=Path(row['path'])
        require(not relative.is_absolute() and not relative.drive and '..' not in relative.parts and relative.as_posix()==row['path']
                and row['path'] not in names and row['path'] not in {'manifest.json','complete.json'},'publication_path_invalid')
        target=root/relative
        require(target.is_file() and all(not p.is_symlink() for p in [target,*target.parents]),'publication_file_invalid')
        require(target.stat().st_size==row['bytes'] and sha256(target)==row['sha256'],'publication_file_changed')
        names.add(row['path'])
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    require(actual==names|{'manifest.json','complete.json'},'publication_file_set_changed')
    isos=[root/n for n in names if n.endswith('.iso')]
    require(len(isos)==1 and sha256(isos[0])==manifest['candidate_sha256'],'publication_iso_changed')
    return {'complete':True,'candidate_sha256':manifest['candidate_sha256'],'files_verified':len(names),'production_iso_eligible':False}
