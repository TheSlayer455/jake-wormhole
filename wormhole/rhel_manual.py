"""Accountable RHEL manual-control evidence; native scanner results stay intact."""
import json
from pathlib import Path

from .runs import atomic_json
from .vm_admission import require
from .vm_inputs import sha256

PREFIX = 'xccdf_org.ssgproject.content_rule_'
SUFFIXES = (
    'crypto_policy_not_overridden',
    'encrypt_partitions',
    'account_temp_expire_date',
    'accounts_user_home_paths_only',
    'configure_firewalld_ports',
    'configured_firewalld_default_deny',
    'libreswan_approved_tunnels',
    'ssh_keys_passphrase_protected',
    'sssd_has_trust_anchor',
    'auditd_audispd_configure_sufficiently_large_partition')
MANUAL_RULES = tuple(PREFIX + suffix for suffix in SUFFIXES)

CODE = r'''
import json,os,pathlib,pwd,re,subprocess,time
def run(*args):
 try:r=subprocess.run(args,capture_output=True,text=True,timeout=10,env=dict(os.environ,LC_ALL='C'))
 except Exception as error:return {'returncode':None,'output':'','error':type(error).__name__}
 return {'returncode':r.returncode,'output':r.stdout[:8192],'error':None}
def path_safe(value):
 value=value.strip().strip('"').strip("'")
 entries=value.split(':')
 return bool(entries) and all(entry not in {'','.'} and (entry.startswith('/') or
  entry in {'$PATH','${PATH}'} or entry.startswith(('$HOME/','${HOME}/'))) for entry in entries)
accounts=[];client_keys=0
for item in pwd.getpwall():
 if not (1000<=item.pw_uid<65534) or item.pw_shell in {'/bin/false','/sbin/nologin','/usr/sbin/nologin'}:continue
 unsafe=[]
 for name in ('.bash_profile','.bash_login','.profile','.bashrc'):
  path=pathlib.Path(item.pw_dir)/name
  if not path.is_file():continue
  for line in path.read_text(errors='replace').splitlines():
   match=re.match(r'^\s*(?:export\s+)?PATH=(.*)$',line)
   if match and not path_safe(match.group(1)):unsafe.append(name)
 keydir=pathlib.Path(item.pw_dir)/'.ssh'
 if keydir.is_dir():
  for path in keydir.iterdir():
   if path.is_file() and not path.name.endswith('.pub') and path.name not in {'authorized_keys','known_hosts','config'}:
    with path.open('rb') as stream:header=stream.read(256)
    if b'PRIVATE KEY-----' in header:client_keys+=1
 aging=run('chage','-l',item.pw_name);shadow=run('getent','shadow',item.pw_name);remaining=None
 try:remaining=int(shadow['output'].strip().split(':')[7])-int(time.time()//86400)
 except (IndexError,TypeError,ValueError):pass
 accounts.append({'name':item.pw_name,'uid':item.pw_uid,'home':item.pw_dir,'shell':item.pw_shell,
  'account_aging':aging,'expiry_remaining_days':remaining,'unsafe_path_file_count':len(unsafe)})
active=run('firewall-cmd','--get-active-zones');zones={};current=None
if active['returncode']==0:
 for line in active['output'].splitlines():
  if line and not line[0].isspace():current=line.strip();zones[current]={'interfaces':[]}
  elif current and line.strip().startswith('interfaces:'):zones[current]['interfaces']=line.split(':',1)[1].split()
for zone in zones:
 zones[zone].update(target=run('firewall-cmd','--permanent','--zone='+zone,'--get-target'),
  services=run('firewall-cmd','--zone='+zone,'--list-services'),
  ports=run('firewall-cmd','--zone='+zone,'--list-ports'),
  protocols=run('firewall-cmd','--zone='+zone,'--list-protocols'),
  source_ports=run('firewall-cmd','--zone='+zone,'--list-source-ports'),
  forward_ports=run('firewall-cmd','--zone='+zone,'--list-forward-ports'),
  rich_rules=run('firewall-cmd','--zone='+zone,'--list-rich-rules'))
configs=[pathlib.Path('/etc/ipsec.conf'),*pathlib.Path('/etc/ipsec.d').glob('*.conf')]
connections=sum(len(re.findall(r'^\s*conn\s+\S+',p.read_text(errors='replace'),re.MULTILINE)) for p in configs if p.is_file())
sssd=[pathlib.Path('/etc/sssd/sssd.conf'),*pathlib.Path('/etc/sssd/conf.d').glob('*.conf')]
certmaps=sum(len(re.findall(r'^\s*\[certmap/[^/]+/[^]]+\]\s*$',p.read_text(errors='replace'),re.MULTILINE)) for p in sssd if p.is_file())
audit_source=run('findmnt','-n','-o','SOURCE','--target','/var/log/audit')
audit_size=run('lsblk','-b','-n','-o','SIZE',audit_source['output'].strip()) if audit_source['returncode']==0 else {'returncode':1,'output':'','error':None}
print(json.dumps({'schema_version':'1.0',
 'run_id':pathlib.Path('/var/lib/wormhole/run-id').read_text().strip(),
 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'facts':{
 'crypto_check':run('update-crypto-policies','--check'),'crypto_policy':run('update-crypto-policies','--show'),
 'interactive_accounts':accounts,'client_private_key_count':client_keys,
 'firewall':{'state':run('firewall-cmd','--state'),'default_zone':run('firewall-cmd','--get-default-zone'),'active_zones':zones},
 'ipsec_connection_count':connections,'sssd_certmap_count':certmaps,
 'audit_storage':{'source':audit_source,'size':audit_size}}}))
'''


def compile_evidence(run, result, assessment, raw):
    """Bind observed manual facts to this run without changing native statuses."""
    from .rhel_hardening import POLICY, SSSD_CERTMAP_RULE
    policy=json.loads(POLICY.read_text())
    require(set(raw)=={'schema_version','run_id','boot_id','facts'} and raw['schema_version']=='1.0' and
            type(raw['facts']) is dict, 'manual_observation_invalid')
    facts=raw['facts'];build=result['build'];checks=result['hardened_checks']
    policy_hash=sha256(POLICY)
    require(raw['run_id']==result['run_id'] and raw['boot_id']==assessment['boot_id'],
            'manual_observation_identity')
    require(build.get('policy_sha256')==policy_hash and
            build.get('installation_contract',{}).get('policy_sha256')==policy_hash,
            'manual_policy_identity')
    native={row['rule_id']:row['native_status'] for row in assessment['rules'] if row['rule_id'] in MANUAL_RULES}
    require(set(native)==set(MANUAL_RULES) and set(native.values())=={'notchecked'},
            'manual_native_status_changed')
    manual=policy['manual_controls']
    require(manual=={'final_service_identity':'lab.service','temporary_accounts':['lab.service'],
        'temporary_account_maximum_hours':72,'authorized_firewall_services':['ssh'],
        'audit_partition_minimum_bytes':10737418240,'pki_based_authentication':False,
        'government_or_production_approval_claimed':False}, 'manual_policy_invalid')
    accounts=facts.get('interactive_accounts',[])
    account_names={row.get('name') for row in accounts if type(row) is dict}
    account_ok=account_names=={'lab.service'} and all(row.get('unsafe_path_file_count')==0 for row in accounts)
    remaining=accounts[0].get('expiry_remaining_days') if account_ok else None
    expiry_ok=type(remaining) is int and 0<remaining<=manual['temporary_account_maximum_hours']//24
    firewall=facts.get('firewall',{});zones=firewall.get('active_zones',{})
    zone=zones.get('drop',{});state=firewall.get('state',{});default=firewall.get('default_zone',{})
    firewall_ok=(state.get('returncode')==0 and state.get('output','').strip()=='running' and
        default.get('returncode')==0 and default.get('output','').strip()=='drop' and set(zones)=={'drop'} and
        bool(zone.get('interfaces')) and zone.get('target',{}).get('output','').strip()=='DROP' and
        zone.get('target',{}).get('returncode')==0 and
        zone.get('services',{}).get('returncode')==0 and
        set(zone['services'].get('output','').split())=={'ssh'} and
        all(zone.get(name,{}).get('returncode')==0 and not zone[name].get('output','').strip()
            for name in ('ports','protocols','source_ports','forward_ports','rich_rules')))
    crypto_ok=(facts.get('crypto_check',{}).get('returncode')==0 and
        facts.get('crypto_policy',{}).get('output','').strip().split(':')[0]=='FIPS')
    encrypted_ok=(checks.get('encrypted-filesystems')=='pass' and checks.get('encrypted-swap')=='pass' and
        result.get('offline_encryption',{}).get('luks_magic_verified') is True and
        result['offline_encryption'].get('correct_key_accepted') is True and
        result['offline_encryption'].get('wrong_key_refused') is True)
    audit=facts.get('audit_storage',{});size=audit.get('size',{})
    try:audit_bytes=int(size.get('output','').strip())
    except (TypeError,ValueError):audit_bytes=0
    audit_ok=size.get('returncode')==0 and audit_bytes>=manual['audit_partition_minimum_bytes'] and encrypted_ok
    outcomes={
      'crypto_policy_not_overridden':('satisfied',crypto_ok,'Configured FIPS crypto policy matches its generated configuration.'),
      'encrypt_partitions':('satisfied',encrypted_ok,'Required filesystems and swap are LUKS-protected and offline key probes passed.'),
      'account_temp_expire_date':('satisfied',account_ok and expiry_ok,'The per-installation service identity expires within the declared 72-hour maximum.'),
      'accounts_user_home_paths_only':('satisfied',account_ok,'Interactive-account initialization contains no unsafe relative search path.'),
      'configure_firewalld_ports':('satisfied',firewall_ok,'The declared lab policy authorizes only SSH ingress.'),
      'configured_firewalld_default_deny':('satisfied',firewall_ok,'The sole active zone uses literal DROP with SSH as its only exception.'),
      'libreswan_approved_tunnels':('not-applicable',facts.get('ipsec_connection_count')==0,'No IPsec tunnel is configured.'),
      'ssh_keys_passphrase_protected':('not-applicable',facts.get('client_private_key_count')==0,'The guest stores no SSH client private key; host identity keys are not client credentials.'),
      'sssd_has_trust_anchor':('not-applicable',facts.get('sssd_certmap_count')==0 and SSSD_CERTMAP_RULE in policy['tailoring']['excluded_rules'],'The declared workload does not use PKI authentication.'),
      'auditd_audispd_configure_sufficiently_large_partition':('satisfied',audit_ok,'The dedicated encrypted audit volume meets the declared 10 GiB minimum.')}
    require(set(outcomes)==set(SUFFIXES), 'manual_rule_inventory_invalid')
    objective={PREFIX+name:{'disposition':disposition if observed else 'failed',
        'observed_satisfied':observed,'reason':reason} for name,(disposition,observed,reason) in outcomes.items()}
    evidence={'schema_version':'1.0','run_id':result['run_id'],
        'candidate_sha256':build['candidate_sha256'],'policy_sha256':policy_hash,
        'content_sha256':assessment['content_sha256'],
        'tailoring_sha256':build['installation_contract']['tailoring_sha256'],
        'native_statuses':native,'native_notchecked_statuses_preserved':True,
        'objective_results':objective,'all_required_manual_evidence_complete':all(row['observed_satisfied'] for row in objective.values()),
        'exception_approved':False,'government_or_production_approval_claimed':False,
        'facts':facts}
    atomic_json(Path(run)/'manual-evidence.json',evidence)
    return evidence
