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
    require(policy['tailoring']=={'excluded_rules':[], 'parameters':{}, 'owner_approved_exceptions':[]},
            'unreviewed_policy_tailoring')
    for path in (Path(current),Path(previous)):
        result, report, _, _ = load(path)
        build=result['build']
        require(build['mode']=='hardened' and result['outcome']=='assessment-complete'
                and result['installed'] is True and result['final_authentication'] is True
                and result['ansible_ready'] is True and result['cleanup']=='verified-absent-inputs-retained',
                'release_runtime_incomplete')
        require(build['policy_sha256']==sha256(POLICY) and
                build['installed_input_fingerprint']==input_identity(dependency_store,'hardened')[0],
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
    delta=compare(previous,current)
    require(delta['equivalent_fresh_installations'],'release_repeatability_unproven')
    result=read_json(Path(current)/'result.json')
    require(sha256(candidate)==result['build']['candidate_sha256'],'release_candidate_changed')
    return result,delta


def publish(current,previous,*,candidate,dependency_store,destination,name):
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
        for source in ['qualification.json','qualification.txt','junit.xml','installed-svd.json','installed-svd.txt']:
            shutil.copyfile(Path(run)/source,evidence/source)
        shutil.copyfile(Path(run)/'inputs/build-manifest.json',evidence/'installation-manifest.json')
        shutil.copytree(Path(run)/'build-svd',evidence/'build-svd')
        assessment=evidence/'assessments';assessment.mkdir(mode=0o700)
        # This destination is private local storage, never a public export.
        # Console captures, seed, credentials and Terraform state stay separate.
        for source in ['findings.json','xccdf.xml','arf.xml','report.html','scanner-version.txt','scanner-receipt.json']:
            shutil.copyfile(Path(run)/'assessment'/source,assessment/source)
    (output/'SHA256SUMS').write_text(result['build']['candidate_sha256']+'  '+iso.name+'\n')
    shutil.copyfile(POLICY,output/'policy.json')
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
    return manifest
