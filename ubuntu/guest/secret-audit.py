"""Read-only bounded retention check; secret values enter through stdin only."""
import json
import os
from pathlib import Path
import subprocess
import sys


def inspect(values):
    if not isinstance(values,list) or len(values)!=3 or any(not isinstance(v,str) or not 24<=len(v)<=512 for v in values):
        raise RuntimeError('invalid private inspection input')
    needles=[v.encode() for v in values];overlap=max(map(len,needles))-1
    total=0;files=0;leak=False
    for root in ('/etc','/var/log','/var/lib/cloud','/var/lib/wormhole'):
        for path in Path(root).rglob('*'):
            if path.is_symlink() or not path.is_file():continue
            files+=1;tail=b''
            with path.open('rb') as stream:
                while True:
                    block=stream.read(1024*1024)
                    if not block:break
                    total+=len(block)
                    if total>256*1024**2:raise RuntimeError('secret inspection budget exceeded')
                    data=tail+block;leak |= any(value in data for value in needles);tail=data[-overlap:]
    initrds=list(Path('/boot').glob('initrd.img-*'))
    if not initrds:raise RuntimeError('installed initramfs missing')
    for path in initrds:
        result=subprocess.run(['lsinitramfs',str(path)],capture_output=True,text=True,timeout=15)
        if result.returncode:raise RuntimeError('initramfs inspection failed')
        leak |= any('wormhole-unlock' in name or ('cryptroot/keyfiles/' in name and not name.endswith('/')) for name in result.stdout.splitlines())
    return {'files_inspected':files,'bytes_inspected':total,'initramfs_images_inspected':len(initrds),
            'plaintext_retained':leak,'secret_values_returned':False,'temporary_secret_file_created':False}


if __name__=='__main__':
    if os.geteuid()!=0 or not Path('/var/lib/wormhole/installation-complete').is_file() or subprocess.check_output(['systemd-detect-virt'],text=True).strip()!='kvm':
        raise RuntimeError('requires final installed lab guest')
    value=json.loads(sys.stdin.read(4097));result=inspect(value)
    print(json.dumps(result));sys.exit(1 if result['plaintext_retained'] else 0)
