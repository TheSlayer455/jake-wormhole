"""Installed disk contract and bounded out-of-band console secret delivery."""
import json
import re
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
    return {'config': [
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
    def __init__(self, secret_file):
        self.secret_file=Path(secret_file)
        self.installer_sent=False
        self.boot_prompts=0
        self.events=[]

    def observe(self,text,stream):
        installer='WORMHOLE_INSTALL_UNLOCK_REQUEST' in text and not self.installer_sent
        prompts=len(re.findall(r'Please unlock disk [^\r\n:]+:',text))
        if not installer and prompts<=self.boot_prompts:return False
        if not self.secret_file.is_file():raise RunError('unlock_material_missing','Supply the run-owned private console unlock material.')
        info=self.secret_file.stat()
        if info.st_mode & 0o077:raise RunError('unlock_material_permissions','Unlock material must be owner-only.')
        secret=self.secret_file.read_bytes()
        if not re.fullmatch(rb'[A-Za-z0-9_-]{48,128}',secret):raise RunError('unlock_material_invalid','Invalid private console material.')
        stream.write(secret+b'\n');stream.flush()
        self.installer_sent |= installer
        self.boot_prompts=prompts
        self.events.append({'kind':'installer-delivery' if installer else 'boot-unlock','prompt_number':prompts})
        return True

    def check_capture(self,path):
        if self.secret_file.read_bytes() in Path(path).read_bytes():
            raise RunError('unlock_secret_capture','Secret entered a restricted diagnostic; withhold export and investigate.')
