"""Read-only objective observations; native manual outcomes are never rewritten."""
MANUAL_RULES={
    'account_temp_expire_date','ensure_sudo_group_restricted','ufw_only_required_services',
    'only_allow_dod_certs','auditd_audispd_configure_sufficiently_large_partition'}

CODE = r'''
import json,subprocess,pwd,os,datetime,shutil
from pathlib import Path
commands={
 'sudo-group':['getent','group','sudo'],
 'final-account-expiration':['chage','-l','lab.service'],
 'required-network-services':['ufw','status','verbose'],
 'audit-storage':['df','-Pk','/var/log/audit'],
}
facts={}
for key,args in commands.items():
 r=subprocess.run(args,capture_output=True,text=True,timeout=10,env=dict(os.environ,LC_ALL='C'))
 facts[key]={'returncode':r.returncode,'native_output':r.stdout}
facts['interactive-accounts']=[{'name':p.pw_name,'uid':p.pw_uid,'shell':p.pw_shell}
 for p in pwd.getpwall() if p.pw_uid>=1000 and p.pw_uid<65534 and p.pw_shell not in ('/bin/false','/usr/sbin/nologin')]
expiry=next((line.split(':',1)[1].strip() for line in facts['final-account-expiration']['native_output'].splitlines() if line.startswith('Account expires')), 'never')
try:
 expires=datetime.datetime.strptime(expiry,'%b %d, %Y').date()
 remaining=(expires-datetime.datetime.now(datetime.timezone.utc).date()).days
except ValueError:remaining=None
members=facts['sudo-group']['native_output'].strip().split(':')[-1].split(',')
listeners=subprocess.run(['ss','-H','-lntup'],capture_output=True,text=True,timeout=10).stdout
external=[]
for line in listeners.splitlines():
 fields=line.split()
 if len(fields)<5:continue
 address=fields[4]
 if address.startswith(('127.','[::1]:')):continue
 external.append(address)
audit_bytes=sum(p.stat().st_size for p in Path('/var/log/audit').glob('*') if p.is_file())
uptime=float(Path('/proc/uptime').read_text().split()[0])
required=int(max(1024,audit_bytes/max(1,uptime))*7*86400*2)
free=shutil.disk_usage('/var/log/audit').free
objective={
 'account_temp_expire_date':{'observed_satisfied':remaining is not None and 0<remaining<=2,'expires_in_days':remaining,'assumption':'disposable lab identities expire within 48 hours'},
 'ensure_sudo_group_restricted':{'observed_satisfied':set(members)<={'','lab.service'} and {x['name'] for x in facts['interactive-accounts']}=={'lab.service'},'assumption':'one declared final lab operator'},
 'ufw_only_required_services':{'observed_satisfied':bool(external) and all(x.endswith(':22') for x in external),'external_listeners':external,'assumption':'only SSH is a guest ingress service; mandatory NIC filter independently restricts peers'},
 'auditd_audispd_configure_sufficiently_large_partition':{'observed_satisfied':free>=max(8*1024**3,required),'available_bytes':free,'observed_audit_bytes':audit_bytes,'estimated_seven_days_with_double_margin':required,'assumption':'bounded disposable lab workload; observed-rate extrapolation is not a production retention guarantee'},
 'only_allow_dod_certs':{'observed_satisfied':False,'reason':'A private home-lab CA is not DoD PKI; no government trust evidence is supplied'}
}
print(json.dumps({'schema_version':'1.0','facts':facts,'disposition':'pending-accountable-review',
 'objective_results':objective,'native_notchecked_statuses_preserved':True,'exception_approved':False}))
'''
