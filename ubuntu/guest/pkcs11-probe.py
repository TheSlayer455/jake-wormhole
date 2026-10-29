"""Temporary software-token PAM integration probe, never physical-token assurance.

Packages, PAM services and trust are installed by the candidate. Acceptance only
creates disposable credentials in /run, invokes the installed libraries and
removes its own probe objects. Secrets arrive on stdin, never argv or output.
"""
import ctypes as C
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

U = C.c_ulong


def der_integers(raw):
    def item(offset):
        tag=raw[offset];size=raw[offset+1];start=offset+2
        if size & 128:
            count=size & 127
            if not 1<=count<=4:raise ValueError('invalid DER length')
            size=int.from_bytes(raw[start:start+count],'big');start+=count
        end=start+size
        if end>len(raw):raise ValueError('truncated DER')
        return tag,start,end
    tag,start,end=item(0)
    if tag!=48 or end!=len(raw):raise ValueError('expected RSA sequence')
    values=[]
    while start<end:
        tag,begin,finish=item(start)
        if tag!=2:raise ValueError('expected RSA integer')
        values.append(raw[begin:finish].lstrip(b'\0') or b'\0');start=finish
    if len(values)!=9 or values[0]!=b'\0':raise ValueError('expected two-prime RSA key')
    return values[1:]


class Attribute(C.Structure):
    _fields_=[('type',U),('value',C.c_void_p),('length',U)]


def token(directory, certificate, private_key, pin):
    """Import using PKCS#11 directly: no secret-bearing command arguments/env."""
    directory=Path(directory);directory.mkdir(mode=0o700)
    objects=directory/'tokens';objects.mkdir(mode=0o700)
    config=directory/'softhsm2.conf'
    config.write_text('directories.tokendir = '+str(objects)+'\nobjectstore.backend = file\nlog.level = ERROR\n')
    os.environ['SOFTHSM2_CONF']=str(config)
    module=C.CDLL('/usr/lib/softhsm/libsofthsm2.so')
    def call(name,*args):
        function=getattr(module,name);function.restype=U
        result=function(*args)
        if result:raise RuntimeError(name+' failed with '+str(result))
    def slots():
        count=U();call('C_GetSlotList',C.c_ubyte(0),None,C.byref(count))
        values=(U*count.value)();call('C_GetSlotList',C.c_ubyte(0),values,C.byref(count))
        return list(values)
    call('C_Initialize',None)
    try:
        so=secrets.token_urlsafe(24).encode();label=b'wormhole-pam-probe'.ljust(32,b' ')
        call('C_InitToken',U(slots()[0]),C.c_char_p(so),U(len(so)),C.c_char_p(label))
        slot=None
        for number in slots():
            info=C.create_string_buffer(512);call('C_GetTokenInfo',U(number),info)
            if info.raw[:32]==label:slot=number;break
        if slot is None:raise RuntimeError('initialized software token unavailable')
        session=U();call('C_OpenSession',U(slot),U(6),None,None,C.byref(session))
        try:
            call('C_Login',session,U(0),C.c_char_p(so),U(len(so)))
            call('C_InitPIN',session,C.c_char_p(pin),U(len(pin)));call('C_Logout',session)
            call('C_Login',session,U(1),C.c_char_p(pin),U(len(pin)))
            def create(attributes):
                buffers=[C.create_string_buffer(value) for _,value in attributes]
                rows=(Attribute*len(attributes))(*(Attribute(kind,C.cast(buf,C.c_void_p),len(value))
                      for (kind,value),buf in zip(attributes,buffers)))
                obj=U();call('C_CreateObject',session,rows,U(len(rows)),C.byref(obj))
            def number(value):return bytes(U(value))
            key=subprocess.run(['openssl','rsa','-traditional','-outform','DER'],input=private_key.encode(),
                               capture_output=True,check=True,timeout=10).stdout
            values=der_integers(key)
            create([(0,number(3)),(0x100,number(0)),(1,b'\1'),(2,b'\1'),(0x103,b'\1'),
                    (0x108,b'\1'),(0x162,b'\0'),(0x102,b'\1')]+
                   list(zip((0x120,0x122,0x123,0x124,0x125,0x126,0x127,0x128),values)))
            cert=subprocess.run(['openssl','x509','-outform','DER'],input=certificate.encode(),
                                capture_output=True,check=True,timeout=10).stdout
            create([(0,number(1)),(0x80,number(0)),(1,b'\1'),(0x101,b''),(0x102,b'\1'),(0x11,cert)])
        finally:call('C_CloseSession',session)
    finally:call('C_Finalize',None)
    return config


def authenticate(pin):
    class Message(C.Structure):_fields_=[('style',C.c_int),('text',C.c_char_p)]
    class Response(C.Structure):_fields_=[('text',C.c_void_p),('code',C.c_int)]
    callback=C.CFUNCTYPE(C.c_int,C.c_int,C.POINTER(C.POINTER(Message)),C.POINTER(C.POINTER(Response)),C.c_void_p)
    class Conversation(C.Structure):_fields_=[('callback',callback),('data',C.c_void_p)]
    libc=C.CDLL('libc.so.6');libc.calloc.restype=C.c_void_p;libc.strdup.restype=C.c_void_p
    libc.calloc.argtypes=[C.c_size_t,C.c_size_t];libc.strdup.argtypes=[C.c_char_p]
    @callback
    def converse(count,messages,responses,data):
        if not 0<count<=16:return 19
        values=C.cast(libc.calloc(count,C.sizeof(Response)),C.POINTER(Response))
        for index in range(count):
            style=messages[index].contents.style
            if style in (1,2):values[index].text=libc.strdup(pin if style==1 else b'lab.service')
        responses[0]=values
        return 0
    pam=C.CDLL('libpam.so.0');handle=C.c_void_p();conversation=Conversation(converse,None)
    pam.pam_start.argtypes=[C.c_char_p,C.c_char_p,C.POINTER(Conversation),C.POINTER(C.c_void_p)]
    pam.pam_authenticate.argtypes=[C.c_void_p,C.c_int];pam.pam_end.argtypes=[C.c_void_p,C.c_int]
    code=pam.pam_start(b'wormhole-token-probe',b'lab.service',C.byref(conversation),C.byref(handle))
    if code==0:
        code=pam.pam_authenticate(handle,0);pam.pam_end(handle,code)
    return code


def parser_probe():
    source=Path('/etc/pam_pkcs11/pam_pkcs11.conf').read_text()
    def parse(path):
        # The module hides scconf symbols and its general inspector falls back
        # silently. Use the read-only harness linked to the SAME vendor parser.
        result=subprocess.run(['/usr/libexec/wormhole-pam-config-check',str(path)],stdin=subprocess.DEVNULL,
                              capture_output=True,text=True,timeout=10)
        if result.returncode not in (0,1):raise RuntimeError('vendor parser diagnostic unavailable')
        return result.returncode==0
    with tempfile.TemporaryDirectory(prefix='wormhole-parser-',dir='/run') as folder:
        # scconf tolerates an omitted semicolon with an internal warning. Use a
        # genuinely malformed assignment, not that tolerated syntax, as negative.
        invalid=Path(folder)/'invalid.conf';invalid.write_text(source.replace('use_mappers = pwent;','use_mappers == pwent;',1))
        return {'vendor_configuration_parses':parse('/etc/pam_pkcs11/pam_pkcs11.conf'),
                'malformed_assignment_refused':not parse(invalid),
                'pwent_with_required_semicolon':source.count('use_mappers = pwent;')==1}


def execute(value):
    pin=secrets.token_urlsafe(24).encode()
    outcomes={}
    with tempfile.TemporaryDirectory(prefix='wormhole-token-',dir='/run') as folder:
        root=Path(folder)
        for case in ('valid','wrong-pin','missing-token','revoked','untrusted','wrong-identity'):
            cert,key=value['token.crt'],value['token.key']
            if case=='revoked':cert,key=value['token-revoked.crt'],value['token-revoked.key']
            if case=='wrong-identity':cert,key=value['active.crt'],value['active.key']
            if case=='untrusted':
                cert=subprocess.run(['openssl','req','-new','-x509','-key','/dev/stdin','-subj','/CN=lab.service','-days','1'],
                                    input=key.encode(),capture_output=True,check=True,timeout=10).stdout.decode()
            config=token(root/case,cert,key,pin)
            if case=='missing-token':
                for child in (root/case/'tokens').iterdir():
                    import shutil
                    shutil.rmtree(child) if child.is_dir() else child.unlink()
            env=dict(os.environ,SOFTHSM2_CONF=str(config))
            result=subprocess.run([sys.executable,'-X','faulthandler',__file__,'authenticate'],input=(b'wrong-pin' if case=='wrong-pin' else pin),
                                  capture_output=True,timeout=20,env=env)
            records=[line for line in result.stdout.splitlines() if line.startswith(b'{')]
            if result.returncode or not records:
                raise RuntimeError('PAM probe child exited '+str(result.returncode)+': '+result.stderr[-800:].decode(errors='replace'))
            code=json.loads(records[-1])['pam_returncode']
            outcomes[case]={'pam_returncode':code,'expected_observed':code==0 if case=='valid' else code!=0}
    return {'schema_version':'1.0','evidence_category':'real installed libpam/pam_pkcs11 with disposable software PKCS11 objects',
            'cases':outcomes,'all_expected_observed':all(x['expected_observed'] for x in outcomes.values()),
            'temporary_objects_removed':not root.exists(),'parser':parser_probe(),
            'physical_token_tested':False,'government_pki_tested':False,'fips_verified':False}


if __name__=='__main__':
    os.umask(0o077)
    if os.geteuid()!=0 or not Path('/var/lib/wormhole/run-id').is_file() or subprocess.check_output(['systemd-detect-virt'],text=True).strip() not in {'kvm','qemu'}:
        raise RuntimeError('requires declared disposable guest')
    if sys.argv[1:]==['authenticate']:
        print(json.dumps({'pam_returncode':authenticate(sys.stdin.buffer.read(256))}))
    else:
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError('bounded private probe input required')
        result=execute(json.loads(raw))
        print(json.dumps(result))
        if not result['all_expected_observed'] or not all(result['parser'].values()):sys.exit(1)
