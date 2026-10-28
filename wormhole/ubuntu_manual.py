"""Read-only facts for manual controls; collection is not owner disposition."""
CODE = r'''
import json,subprocess,pwd
commands={
 'sudo-group':['getent','group','sudo'],
 'final-account-expiration':['chage','-l','lab.service'],
 'required-network-services':['ufw','status','verbose'],
 'audit-storage':['df','-Pk','/var/log/audit'],
}
facts={}
for key,args in commands.items():
 r=subprocess.run(args,capture_output=True,text=True,timeout=10)
 facts[key]={'returncode':r.returncode,'native_output':r.stdout}
facts['interactive-accounts']=[{'name':p.pw_name,'uid':p.pw_uid,'shell':p.pw_shell}
 for p in pwd.getpwall() if p.pw_uid>=1000 and p.pw_uid<65534 and p.pw_shell not in ('/bin/false','/usr/sbin/nologin')]
print(json.dumps({'schema_version':'1.0','facts':facts,'disposition':'pending-accountable-review',
 'native_notchecked_statuses_preserved':True,'exception_approved':False}))
'''
