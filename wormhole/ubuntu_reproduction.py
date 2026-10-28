"""Closed-field, sanitized VM reproduction package; never exports raw evidence."""
import re
import subprocess
from pathlib import Path

from .runs import SOURCE_ROOT, atomic_json, read_json, workspace_path
from .ubuntu_assessment import require

REPOSITORY='https://github.com/TheSlayer455/jake-wormhole'


def sanitized(result):
    revision=result['source_revision']
    require(re.fullmatch('[a-f0-9]{40}',revision) is not None,'reproduction_source_invalid')
    known={'finalization_failed':'Installation-local finalization failed before final readiness.',
           'installation_failed':'The unattended installer reported failure.',
           'stale_candidate':'Installed inputs differed from the immutable candidate contract.',
           'bootloader_unattended_boot_blocked':'Installed boot requested unexpected authentication.',
           'required_reboot_progress_deadline':'Required reboot did not complete within its bounded observation stage.',
           'ssh-ansible-inventory_failed':'A controller operation failed; inspect the pinned observer and acceptance implementation.',
           'audit_archive_incomplete':'The sender completed but required durable receiver records were incomplete.',
           'audit_archive_receipt_mismatch':'The retained archive did not match the declared validation transfer.',
           'offline_encryption_absent':'Powered-off disk inspection did not establish the required encrypted header.',
           'support_guest_evidence_missing':'Required guest-origin receiver evidence was not retained.',
           'supervisor_interrupted_without_terminal_result':'Supervisor observation ended without a verified terminal result.'}
    code=result.get('error_category');sandbox=result.get('build',{}).get('sandbox') is True
    return {'schema_version':'1.0','capability':'sanitized-ubuntu-reproduction',
        'repository':REPOSITORY,'source_revision':revision,'source_url':REPOSITORY+'/tree/'+revision,
        'boundary':code if code in known else 'unclassified-or-assessment-pending',
        'failure_signature':known.get(code,'Assessment or execution remains ineligible; no success is asserted.'),
        'evidence_category':'real-vm-execution' if any(s.get('stage')=='terraform-apply' and s.get('returncode')==0 for s in result.get('stages',[])) else 'controller-preflight',
        'safe_inputs':{'os':'Ubuntu 22.04.5 amd64','firmware':'BIOS','memory_mib':8192,'vcpus':2,
                       'empty_disk_gib':64,'benchmark':'CaC 0.1.82 Ubuntu STIG V2R7'},
        'command_template':'python -m wormhole.ubuntu_runtime run --mode hardened'+(' --sandbox' if sandbox else '')+' --store PRIVATE_STAGED_INPUTS --source VERIFIED_STOCK_ISO --terraform PINNED_TERRAFORM',
        'sandbox':sandbox,
        'recovery':'Reconcile the exact run and preserve private evidence; recover only after the original supervisor and operation have stopped.',
        'raw_evidence_exported':False,'lab_iso_qualified':False,'production_iso_eligible':False}


def package(run,output):
    result=read_json(Path(run)/'result.json')
    value=sanitized(result)
    origin=subprocess.check_output(['git','-C',str(SOURCE_ROOT),'remote','get-url','origin'],text=True,timeout=5).strip()
    require(origin in {REPOSITORY,REPOSITORY+'.git'},'reproduction_public_source_unverified')
    refs=subprocess.check_output(['git','-C',str(SOURCE_ROOT),'for-each-ref','--contains',value['source_revision'],
                                  '--format=%(refname)','refs/remotes/origin'],text=True,timeout=5)
    require(bool(refs.strip()),'reproduction_public_source_unverified')
    output=workspace_path(output,create=True)
    require(not (output/'reproduction.json').exists(),'reproduction_output_exists')
    atomic_json(output/'reproduction.json',value)
    return value
