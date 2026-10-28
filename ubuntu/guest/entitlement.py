"""Explicit stdin-only guest delivery. Probe never contacts the vendor.

Real enrollment requires an owner-supplied entitlement and permitted vendor
connectivity; source tests/probes do not establish licensed USG/FIPS execution.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def execute(value,runner=subprocess.run):
    operation=value.get('operation')
    if operation not in {'probe','enroll','detach'}:raise ValueError('unsupported entitlement operation')
    if operation=='detach':
        p=runner(['pro','detach','--assume-yes'],capture_output=True,timeout=90)
        return {'operation':operation,'returncode':p.returncode,'vendor_cleanup_verified':p.returncode==0}
    token=value.get('token','')
    if not isinstance(token,str) or not 16<=len(token)<=4096 or any(ord(c)<33 or ord(c)>126 for c in token):raise ValueError('explicit private provider input required')
    with tempfile.TemporaryDirectory(prefix='wormhole-entitlement-',dir='/run') as directory:
        path=Path(directory)/'attach.json'
        descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,'w') as stream:json.dump({'token':token,'enable_services':[]},stream)
        permissions=stat.S_IMODE(path.stat().st_mode)==0o600 and stat.S_IMODE(Path(directory).stat().st_mode)==0o700
        if not permissions:raise RuntimeError('private delivery permissions failed')
        if operation=='probe':result={'operation':operation,'private_mode_verified':True,'vendor_contacted':False}
        else:
            help_result=runner(['pro','attach','--help'],capture_output=True,timeout=10)
            if b'--attach-config' not in help_result.stdout:raise RuntimeError('installed Pro client does not support private config attach')
            attached=runner(['pro','attach','--no-auto-enable','--attach-config',str(path),'--format','json'],capture_output=True,timeout=120)
            # Never echo vendor output; it may contain account or credential data.
            result={'operation':operation,'attach_returncode':attached.returncode,'vendor_contacted':True,
                    'usg_executed':False,'fips_verified':False,'next_stage':'freeze authorized packages/content before fresh installation'}
    result['ephemeral_config_removed']=not path.exists()
    return result


if __name__=='__main__':
    if os.geteuid()!=0 or not Path('/var/lib/wormhole/run-id').is_file() or subprocess.check_output(['systemd-detect-virt'],text=True).strip() not in {'kvm','qemu'}:
        raise RuntimeError('requires declared disposable guest')
    value=json.loads(sys.stdin.buffer.read(8193))
    result=execute(value)
    print(json.dumps(result))
    if result.get('attach_returncode',result.get('returncode',0))!=0:sys.exit(1)
