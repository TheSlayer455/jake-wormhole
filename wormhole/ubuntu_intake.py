"""Unchanged Wormhole Ubuntu media plus its declared, private per-run seed.

This adapter inspects existing bytes. It never calls the ISO builder, executes
remediation, or substitutes generated payloads for the delivered installation.
"""
import hashlib
import inspect
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from .media_store import SHA, fingerprint
from .runs import SOURCE_ROOT, atomic_json, read_json
from .ubuntu_assessment import POLICY, require
from .ubuntu_inputs import input_identity, seed_config
from .vm_inputs import UBUNTU, sha256


def installation_contract():
    return {'id':'wormhole-ubuntu2204-hardened-sandbox-bios-v1',
        'release':UBUNTU['release'],'architecture':UBUNTU['architecture'],'firmware':'bios',
        'seed_label':'CIDATA','seed_template_sha256':fingerprint(inspect.getsource(seed_config)),
        'policy_sha256':sha256(POLICY),'mode':'hardened','sandbox':True,
        'build_manifest_required':True,'guest_memory_mib':8192,'guest_vcpus':2,
        'guest_disk_bytes':64*1024**3,'host_trust':'installed-system-serial-host-key',
        'sudo':'password-required','required_services':'existing-ubuntu-sandbox'}


def validate_manifest(delivery, store):
    require(store is not None,'ubuntu_intake_store_required')
    require(delivery['contract_sha256']==fingerprint(installation_contract()),'unsupported_installation_contract')
    manifest=delivery['build']
    current,inputs=input_identity(store,'hardened',sandbox=True)
    require(manifest.get('capability')=='ubuntu-assessment-candidate-iso' and
        manifest.get('source')==UBUNTU and manifest.get('mode')=='hardened' and manifest.get('sandbox') is True and
        manifest.get('candidate_sha256')==delivery['sha256'] and
        manifest.get('installed_input_fingerprint')==current and manifest.get('installed_inputs')==inputs and
        manifest.get('policy_sha256')==sha256(POLICY) and
        manifest.get('dependency_manifest_sha256')==sha256(Path(store)/'bundle/manifest.json'),
        'stale_candidate')
    return manifest


def expected_payload(store):
    """Read-only hashes of declared input files; no build or remediation call."""
    store=Path(store);bundle=store/'bundle';manifest=read_json(bundle/'manifest.json')
    files={}
    for row in manifest['files']:
        name=row['path']
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*',name) and
            '..' not in Path(name).parts and name not in files and type(row['bytes']) is int and row['bytes']>=0 and
            type(row['sha256']) is str and SHA.fullmatch(row['sha256']),'ubuntu_bundle_manifest_invalid')
        files[name]=(row['bytes'],row['sha256'])
    require(len(files)<=1024 and sum(size for size,_ in files.values())<=4*1024**3,'ubuntu_intake_payload_bound')
    def content(name, raw):files[name]=(len(raw),hashlib.sha256(raw).hexdigest())
    content('manifest.json',(bundle/'manifest.json').read_bytes())
    for name in ('finalize.sh','audit.sh','observe.py','remediate.py','encryption-late.sh','sandbox.sh',
                 'entitlement.py','audit-offload.py','secret-audit.py','pkcs11-probe.py'):
        content(name,(SOURCE_ROOT/'ubuntu/guest'/name).read_bytes())
    content('policy.json',POLICY.read_bytes())
    from .ubuntu_tailoring import document
    tailoring=document(json.loads(POLICY.read_text()))
    if tailoring is not None:content('lab-tailoring.xml',tailoring)
    plan=json.loads((SOURCE_ROOT/'ubuntu/remediation-plan-v1.json').read_text())
    upstream=store/'ubuntu2204-script-stig.sh'
    require(sha256(upstream)==plan['upstream_script_sha256'],'remediation_content_mismatch')
    # Match the already reviewed upstream blocks; do not generate or run scripts.
    blocks=dict(re.findall(r"# BEGIN fix \(\d+ / \d+\) for 'xccdf_org.ssgproject.content_rule_([^']+)'(.*?)# END fix for 'xccdf_org.ssgproject.content_rule_\1'",
                           upstream.read_text(),re.S))
    require(set(plan['remediation_rules'])<=set(blocks),'remediation_rule_inventory')
    for name in plan['remediation_rules']:content('remediation/'+name+'.sh',blocks[name].encode())
    content('remediation-plan.json',json.dumps(plan,sort_keys=True).encode())
    content('offline-apt.conf',b'Dir::Etc::sourcelist "sources.list.d/wormhole-local.list";\nDir::Etc::sourceparts "-";\nAPT::Install-Recommends "false";\n')
    content('install-contract.json',json.dumps({'mode':'hardened','policy_sha256':sha256(POLICY),
        'dependency_manifest_sha256':sha256(bundle/'manifest.json'),'sandbox':True},sort_keys=True).encode())
    content('wormhole-finalize.service',b'[Unit]\nDescription=Wormhole installed-guest finalization\nAfter=local-fs.target cloud-config.service\nBefore=ssh.service ssh.socket\n[Service]\nType=oneshot\nRuntimeDirectory=sshd\nRuntimeDirectoryMode=0755\nExecStart=/bin/bash /usr/local/lib/wormhole/finalize.sh\nTimeoutStartSec=1000\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n')
    return files


def extract_files(source, root, files, command, *, prefix):
    args=['xorriso','-osirrox','on','-indev',str(source)]
    for name,(size,_) in files.items():
        target=root/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        args+=['-extract_cut',prefix+'/'+name,'0',str(size+1),str(target)]
    command(args)
    for name,(size,digest) in files.items():
        target=root/name
        require(not target.is_symlink() and target.is_file() and target.stat().st_size==size and
            sha256(target)==digest,'delivered_payload_mismatch')


def prepare_delivered(source,destination,seed_dir,identifier,public_key,address,mac,*,store,password_hash,boot_hash,delivery):
    source,destination,seed_dir=map(Path,(source,destination,seed_dir))
    manifest=dict(validate_manifest(delivery,store))
    require(not destination.exists() and not seed_dir.exists() and not destination.with_name('seed.iso').exists(),'build_output_exists')
    require(source.stat().st_size==delivery['bytes'] and sha256(source)==delivery['sha256'],'delivery_identity_changed')
    require(boot_hash is not None,'boot_credential_missing')
    config=seed_config(identifier,public_key,address,mac,password_hash,boot_hash,sandbox=True)
    seed_dir.mkdir(mode=0o700)
    def command(args, output=None):
        with (seed_dir/'intake.log').open('ab') as log:
            if output is None:subprocess.run(args,stdout=log,stderr=log,timeout=180,check=True)
            else:
                with output.open('xb') as stream:subprocess.run(args,stdout=stream,stderr=log,timeout=180,check=True)
    boot=seed_dir/'boot';boot.mkdir(mode=0o700)
    for name in ('grub.cfg','loopback.cfg'):
        target=boot/name
        command(['xorriso','-osirrox','on','-indev',str(source),'-extract_cut','/boot/grub/'+name,'0','65537',str(target)])
        require(not target.is_symlink() and target.is_file() and target.stat().st_size<=65536,'unsupported_installation_contract')
        entries=[line.split() for line in target.read_text().splitlines() if re.match(r'\s*linux\s+/casper/(?:hwe-)?vmlinuz\s',line)]
        require(entries and all(tokens.count('autoinstall')==1 and tokens.count('console=ttyS0,115200n8')==1 and
            not any(token.startswith(('ds=','autoinstall=','subiquity.autoinstallpath=','cloud-config-url=','url=','init=')) for token in tokens)
            for tokens in entries),'unsupported_installation_contract')
    payload=seed_dir/'payload'
    files=expected_payload(store)
    for name,extra in (('files',[]),('nonregular',['-not','-type','f'])):
        listing=seed_dir/('payload-'+name)
        command(['xorriso','-indev',str(source),'-find','/wormhole','-not','-type','d',*extra,'-exec','echo','--'],listing)
        require(listing.stat().st_size<=65536,'ubuntu_intake_payload_bound')
        paths=shlex.split(listing.read_text())
        expected={'/wormhole/'+p for p in files} if name=='files' else set()
        require(len(paths)==len(expected) and set(paths)==expected,'delivered_payload_mismatch')
    extract_files(source,payload,files,command,prefix='/wormhole')
    shutil.copyfile(source,destination)
    require(sha256(destination)==delivery['sha256'],'candidate_copy_mismatch')
    (seed_dir/'user-data').write_text(config)
    (seed_dir/'meta-data').write_text(json.dumps({'instance-id':identifier,'local-hostname':'wormhole-lab'}))
    identity=seed_dir/'wormhole-identity';identity.mkdir(mode=0o700)
    for name,raw in {'public-key':public_key+'\n','password':'lab.service:'+password_hash+'\n',
                     'run-id':identifier+'\n','boot-password-hash':boot_hash+'\n'}.items():
        (identity/name).write_text(raw);(identity/name).chmod(0o600)
    for name in ('ca.crt','ca.crl','active.crt','revoked.crt'):
        shutil.copyfile(seed_dir.parent/'support-private'/name,identity/('sandbox-'+name))
    seed=destination.with_name('seed.iso')
    command(['xorriso','-as','mkisofs','-V','CIDATA','-J','-r','-graft-points','-o',str(seed),
        'user-data='+str(seed_dir/'user-data'),'meta-data='+str(seed_dir/'meta-data'),'wormhole-identity='+str(identity)])
    extract_files(seed,seed_dir/'seed-layout-check',
        {p.name:(p.stat().st_size,sha256(p)) for p in identity.iterdir()},command,prefix='/wormhole-identity')
    manifest.update(candidate_sha256=sha256(destination),seed_sha256=sha256(seed),
        installation_input_sha256=sha256(seed_dir/'user-data'),candidate_reused=True,
        delivery={k:v for k,v in delivery.items() if k!='build'},installation_contract=installation_contract())
    atomic_json(seed_dir/'build-manifest.json',manifest)
    return manifest
