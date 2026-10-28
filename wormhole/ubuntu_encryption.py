"""Installed disk contract and bounded out-of-band console secret delivery."""
import json
import re
import time
import struct
import subprocess
from pathlib import Path

from .runs import RunError


EARLY = r'''import os,termios
fd=os.open('/dev/ttyS0',os.O_RDWR|os.O_NOCTTY)
before=termios.tcgetattr(fd)
quiet=termios.tcgetattr(fd);quiet[3]&=~termios.ECHO
termios.tcsetattr(fd,termios.TCSANOW,quiet)
try:
 os.write(fd,b'\nWORMHOLE_INSTALL_UNLOCK_REQUEST\n')
 value=b''
 while not value.endswith(b'\n') and len(value)<=128:value+=os.read(fd,1)
 value=value.rstrip(b'\r\n')
 if len(value)<48 or len(value)>128 or not all(c in b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in value):raise RuntimeError('invalid console material')
 out=os.open('/run/wormhole-unlock',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 os.write(out,value);os.close(out)
 os.write(fd,b'WORMHOLE_INSTALL_UNLOCK_RECEIVED\n')
finally:
 termios.tcsetattr(fd,termios.TCSANOW,before);os.close(fd)
'''


def storage():
    """BIOS boot remains clear; all persistent OS data is inside one LUKS volume."""
    return {'swap':{'size':0},'config': [
        {'id':'disk','type':'disk','path':'/dev/vda','ptable':'gpt','wipe':'superblock-recursive','grub_device':True},
        {'id':'bios','type':'partition','device':'disk','number':1,'size':'1M','flag':'bios_grub'},
        {'id':'boot','type':'partition','device':'disk','number':2,'size':'2G'},
        {'id':'data','type':'partition','device':'disk','number':3,'size':-1},
        {'id':'crypt','type':'dm_crypt','volume':'data','dm_name':'wormhole-root','keyfile':'/run/wormhole-unlock'},
        {'id':'root-fs','type':'format','volume':'crypt','fstype':'ext4'},
        {'id':'boot-fs','type':'format','volume':'boot','fstype':'ext4'},
        {'id':'root-mount','type':'mount','device':'root-fs','path':'/'},
        {'id':'boot-mount','type':'mount','device':'boot-fs','path':'/boot'}]}


def configure(value):
    install=value['autoinstall']
    install['storage']=storage()
    install['early-commands']=[['python3','-c',EARLY]]
    # Runs in the installer, with the just-installed target mounted; no secret argv.
    install['late-commands'].insert(0,['bash','/cdrom/wormhole/encryption-late.sh'])
    return value


class ConsoleUnlock:
    """Only write to the already-owned console, after a recognized secret prompt."""
    def __init__(self, secret_file, *, probes=False):
        self.secret_file=Path(secret_file)
        self.installer_sent=False
        self.boot_prompts=0
        self.events=[]
        self.probes=probes
        self.wait_started=None
        self.wrong_sent=False

    def observe(self,text,stream):
        installer='WORMHOLE_INSTALL_UNLOCK_REQUEST' in text and not self.installer_sent
        prompts=len(re.findall(r'Please unlock disk [^\r\n:]+:',text))
        if not installer and prompts<=self.boot_prompts:return False
        if not self.secret_file.is_file():raise RunError('unlock_material_missing','Supply the run-owned private console unlock material.')
        info=self.secret_file.stat()
        if info.st_mode & 0o077:raise RunError('unlock_material_permissions','Unlock material must be owner-only.')
        secret=self.secret_file.read_bytes()
        if not re.fullmatch(rb'[A-Za-z0-9_-]{48,128}',secret):raise RunError('unlock_material_invalid','Invalid private console material.')
        if not installer and self.probes and not self.wrong_sent:
            if self.wait_started is None:self.wait_started=time.monotonic();return False
            if time.monotonic()-self.wait_started<10:return False
            stream.write(b'WORMHOLE-INTENTIONALLY-WRONG-KEY\n');stream.flush()
            self.wrong_sent=True;self.boot_prompts=prompts
            self.events.append({'kind':'missing-material-wait-and-wrong-secret-probe','wait_seconds':10,'prompt_number':prompts})
            return True
        if self.wrong_sent and not any(e['kind']=='wrong-secret-refused' for e in self.events):
            if 'No key available' not in text and 'cryptsetup: ERROR' not in text:raise RunError('wrong_unlock_not_confirmed','Expected a real rejected unlock before proceeding.')
            self.events.append({'kind':'wrong-secret-refused','prompt_number':prompts})
        stream.write(secret+b'\n');stream.flush()
        self.installer_sent |= installer
        self.boot_prompts=prompts
        self.events.append({'kind':'installer-delivery' if installer else 'boot-unlock','prompt_number':prompts})
        return True

    def check_capture(self,path):
        if self.secret_file.read_bytes() in Path(path).read_bytes():
            raise RunError('unlock_secret_capture','Secret entered a restricted diagnostic; withhold export and investigate.')


def offline_inspect(disk,run,secret_file):
    """Non-destructive logical reads of ONE already stopped owned qcow2 disk."""
    run=Path(run)
    def read_sectors(output,skip,count):
        subprocess.run(['qemu-img','dd','-f','qcow2','if='+str(disk),'of='+str(output),
                        'bs=512','skip='+str(skip),'count='+str(count)],
                       check=True,capture_output=True,timeout=30)
    gpt=run/'offline-gpt.bin';read_sectors(gpt,0,34)
    data=gpt.read_bytes()
    if data[512:520]!=b'EFI PART':raise RunError('offline_partition_table','Expected the declared GPT disk.')
    table,entries,size=struct.unpack_from('<QII',data,512+72)
    start,end=struct.unpack_from('<QQ',data,table*512+2*size+32)
    if not (entries>=3 and size>=128 and 2048<start<end):raise RunError('offline_partition_layout','Encrypted data partition does not match.')
    header=run/'offline-luks-header.bin';read_sectors(header,start,65536)
    if header.read_bytes()[:6]!=b'LUKS\xba\xbe':raise RunError('offline_encryption_absent','Real encrypted disk header missing.')
    key=Path(secret_file).read_bytes()
    args=['cryptsetup','open','--test-passphrase','--key-file=-',str(header)]
    good=subprocess.run(args,input=key,capture_output=True,timeout=30).returncode
    wrong=subprocess.run(args,input=b'WORMHOLE-INTENTIONALLY-WRONG-KEY',capture_output=True,timeout=30).returncode
    missing=subprocess.run(['cryptsetup','open','--test-passphrase','--key-file',str(run/'missing-key'),str(header)],
                           capture_output=True,timeout=10).returncode
    if good!=0 or wrong==0 or missing==0:raise RunError('offline_unlock_contract','Actual disk key acceptance/refusal failed.')
    header.unlink();gpt.unlink()
    return {'powered_off_logical_read':True,'luks_magic_verified':True,'correct_key_accepted':True,
            'wrong_key_refused':True,'missing_key_refused':True,'disk_modified':False,'clear_surfaces':['BIOS boot metadata','/boot'],
            'protected_surfaces':['root filesystem including home, logs and installed configuration'],'swap':'disabled'}
