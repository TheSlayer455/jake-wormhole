"""Run-scoped support services and a mandatory per-VM network filter."""
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import time
import xml.etree.ElementTree as ET

from .runs import SOURCE_ROOT,atomic_json
from .ubuntu_assessment import require

BIND='192.0.2.1'
GUEST='192.0.2.10'
MEMORY=128*1024**2


def installer_probe(network):
    """Fail a broken VM route before disk formatting or a full OS extraction."""
    return '''import json,pathlib,subprocess,socket,ssl
network='''+repr(network)+'''
path=pathlib.Path('/etc/netplan/90-wormhole-probe.yaml')
path.write_text(json.dumps({'network':network}));path.chmod(0o600)
subprocess.run(['netplan','apply'],check=True,timeout=20)
seed=pathlib.Path('/run/wormhole-network-seed');seed.mkdir(mode=0o700)
subprocess.run(['mount','-o','ro','/dev/disk/by-label/CIDATA',str(seed)],check=True,timeout=5)
try:
 context=ssl.create_default_context(cafile=str(seed/'wormhole-identity/sandbox-ca.crt'))
 with socket.create_connection(('192.0.2.1',6514),timeout=5) as sock:
  with context.wrap_socket(sock,server_hostname='wormhole-sandbox') as tls:tls.sendall(b'installer-network-preflight\\n')
 with socket.create_connection(('192.0.2.1',6000),timeout=5):pass
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
  sock.settimeout(5);sock.sendto(bytes([0x23])+bytes(47),('192.0.2.1',12345));data,_=sock.recvfrom(512)
  if len(data)!=48:raise RuntimeError('invalid lab time response')
 blocked=False
 try:socket.create_connection(('192.0.2.1',22),timeout=3).close()
 except OSError:blocked=True
 if not blocked:raise RuntimeError('management plane reachable before guest hardening')
 pathlib.Path('/dev/ttyS0').write_text('WORMHOLE_INSTALL_NETWORK_READY\\n')
finally:subprocess.run(['umount',str(seed)],check=True,timeout=5)
'''


def network_filter(name):
    root=ET.Element('filter',name=name,chain='root')
    def rule(direction,protocol,**fields):
        r=ET.SubElement(root,'rule',action='accept',direction=direction,priority='100')
        ET.SubElement(r,protocol,**{k:str(v) for k,v in fields.items()})
    rule('inout','arp')
    # Ethernet and IP rules are enforced at separate hooks. Admit IPv4 frames
    # at L2, then constrain their connections with the IP rules below; otherwise
    # the terminal MAC drop also discards IP packets accepted at the IP hook.
    rule('inout','mac',protocolid='0x0800')
    rule('inout','all',state='ESTABLISHED,RELATED')
    rule('in','tcp',srcipaddr=BIND,dstipaddr=GUEST,dstportstart=22,state='NEW')
    for port in (6514,6000):rule('out','tcp',srcipaddr=GUEST,dstipaddr=BIND,dstportstart=port,state='NEW')
    rule('out','udp',srcipaddr=GUEST,dstipaddr=BIND,dstportstart=12345,state='NEW')
    ET.SubElement(ET.SubElement(root,'rule',action='drop',direction='inout',priority='1000'),'all')
    # all covers IP; also deny non-IP Ethernet traffic other than declared ARP.
    ET.SubElement(ET.SubElement(root,'rule',action='drop',direction='inout',priority='500'),'mac')
    return ET.tostring(root,encoding='unicode')


def attach_filter(config,name):
    domain=config['resource']['libvirt_domain']['run']
    xslt=domain['xml']['xslt']
    addition='<xsl:template match="/domain/devices/interface"><xsl:copy><xsl:apply-templates select="@*|node()"/><filterref filter="'+name+'"/></xsl:copy></xsl:template>'
    domain['xml']['xslt']=xslt.replace('</xsl:stylesheet>',addition+'</xsl:stylesheet>')
    return config


def certificates(run):
    private=Path(run)/'support-private';private.mkdir(mode=0o700)
    def command(*args):subprocess.run(['openssl',*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=15)
    command('req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','2','-subj','/CN=Wormhole disposable lab CA',
            '-keyout',str(private/'ca.key'),'-out',str(private/'ca.crt'),'-addext','basicConstraints=critical,CA:TRUE')
    command('req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=wormhole-sandbox',
            '-keyout',str(private/'server.key'),'-out',str(private/'server.csr'))
    ext=private/'server.ext';ext.write_text('subjectAltName=DNS:wormhole-sandbox,IP:'+BIND+'\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n')
    command('x509','-req','-in',str(private/'server.csr'),'-CA',str(private/'ca.crt'),'-CAkey',str(private/'ca.key'),
            '-CAcreateserial','-days','2','-sha256','-extfile',str(ext),'-out',str(private/'server.crt'))
    return private


def start(run,name,identifier,image,lease,command):
    private=Path(run)/'support-private'
    evidence=Path(run)/'support-evidence';evidence.mkdir(mode=0o700);os.chown(evidence,10001,10001)
    service=name+'-services'
    lease.intent('support_container',service)
    code=(SOURCE_ROOT/'ubuntu/support/receiver.py').read_text()
    command(['docker','create','-i','--name',service,'--label','application=jake-wormhole','--label','vm-run='+identifier,
             '--network','host','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','10001:10001',
             '--memory',str(MEMORY),'--memory-swap',str(MEMORY),'--cpus','0.5','--pids-limit','64',
             '--log-opt','max-size=1m','--log-opt','max-file=2',
             '--mount','type=bind,src='+str(evidence)+',dst=/evidence',
             '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=8m,mode=0700,uid=10001,gid=10001',
             '--entrypoint','/opt/wormhole/venv/bin/python',image,'-c',code],'support-create')
    actual=json.loads(subprocess.check_output(['docker','inspect',service],timeout=10))[0]
    limits=validate_service(actual,run,identifier,image)
    atomic_json(Path(run)/'support-limits.json',limits)
    payload={'bind':BIND,'guest':GUEST,'certificate':(private/'server.crt').read_text(),'key':(private/'server.key').read_text()}
    # A finite stdin payload closes after delivery; the receiver no longer reads it.
    with (Path(run)/'support-start.log').open('wb') as output:
        process=subprocess.Popen(['docker','start','-ai',service],stdin=subprocess.PIPE,stdout=output,stderr=output,start_new_session=True)
        process.stdin.write(json.dumps(payload).encode());process.stdin.close()
    return service,process


def validate_service(actual,run,identifier,image):
    host=actual['HostConfig'];config=actual['Config']
    require(config['Image']==image and config['Labels'].get('vm-run')==identifier,'support_identity_mismatch')
    require(host['Memory']==MEMORY and host['MemorySwap']==MEMORY and host['NanoCpus']==500_000_000
            and host['PidsLimit']==64,'support_limits_missing')
    require(config['User']=='10001:10001' and host['ReadonlyRootfs'] is True and host['Privileged'] is False
            and host['CapDrop']==['ALL'] and not host.get('CapAdd') and host['NetworkMode']=='host'
            and host.get('PidMode')!='host' and host.get('IpcMode')!='host'
            and any(x in host['SecurityOpt'] for x in ['no-new-privileges:true','no-new-privileges']), 'support_isolation_missing')
    binds=[m for m in actual['Mounts'] if m['Type']=='bind']
    require(len(binds)==1 and binds[0]['Source']==str(Path(run)/'support-evidence')
            and binds[0]['Destination']=='/evidence' and binds[0]['RW'] is True
            and all(m['Type'] in {'bind','tmpfs'} for m in actual['Mounts']), 'support_mounts_invalid')
    return {'memory_bytes':host['Memory'],'nano_cpus':host['NanoCpus'],'pids_limit':host['PidsLimit'],
            'read_only_root':True,'nonroot':True,'capabilities_dropped':True,'privileged':False,
            'sole_host_mount':'run-owned support evidence','network':'host namespace; listeners confined to the owned bridge address'}


def health(run):
    private=Path(run)/'support-private'
    context=ssl.create_default_context(cafile=str(private/'ca.crt'))
    last=None
    for _ in range(20):
        try:
            with socket.create_connection((BIND,6514),timeout=2) as sock:
                with context.wrap_socket(sock,server_hostname='wormhole-sandbox') as tls:tls.sendall(b'<14>support-health\n')
            break
        except OSError as error:last=error;time.sleep(.25)
    else:raise RuntimeError('support TLS unavailable') from last
    refused=False
    try:
        with socket.create_connection((BIND,6514),timeout=2) as sock:
            context.wrap_socket(sock,server_hostname='untrusted.invalid').close()
    except ssl.SSLCertVerificationError:refused=True
    require(refused,'support_untrusted_identity_accepted')
    untrusted=False
    try:
        with socket.create_connection((BIND,6514),timeout=2) as sock:
            ssl.create_default_context().wrap_socket(sock,server_hostname='wormhole-sandbox').close()
    except ssl.SSLCertVerificationError:untrusted=True
    require(untrusted,'support_untrusted_ca_accepted')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(2);sock.sendto(bytes([0x23])+bytes(47),(BIND,12345));data,_=sock.recvfrom(512)
    require(len(data)==48 and data[1]==10,'support_time_invalid')
    with socket.create_connection((BIND,6000),timeout=2) as sock:sock.sendall(b'support-health\n')
    with socket.create_connection((BIND,22),timeout=2):pass
    result={'tls_healthy':True,'invalid_identity_refused':True,'untrusted_ca_refused':True,'audit_tcp_healthy':True,'ntp_healthy':True,
            'time_source':'stratum-10 lab host UTC clock; no external trusted-time claim',
            'listeners':[BIND+':6514/tcp',BIND+':6000/tcp',BIND+':12345/udp'],
            'memory_limit_bytes':MEMORY,'cpu_limit':.5,'privileged':False}
    result['host_management_listener_available_for_isolation_negative']=True
    atomic_json(Path(run)/'support-health.json',result)
    return result


def evidence(run,identifier):
    result={}
    for kind in ('syslog','audit'):
        path=Path(run)/'support-evidence'/(kind+'.jsonl')
        rows=[json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        matches=[row for row in rows if row['peer']==GUEST and identifier in row['body']]
        result[kind+'_guest_event_received']=bool(matches)
    atomic_json(Path(run)/'support-verification.json',result)
    require(all(result.values()),'support_guest_evidence_missing')
    return result


def remove_filter(run,name):
    observed=subprocess.run(['virsh','-c','qemu:///system','nwfilter-dumpxml',name],capture_output=True,text=True,timeout=10)
    if observed.returncode==0:
        expected=ET.parse(Path(run)/'network-filter.xml').getroot();actual=ET.fromstring(observed.stdout)
        require(actual.get('name')==name and actual.get('chain')=='root','network_filter_ownership_mismatch')
        require(canonical_rules(actual)==canonical_rules(expected),'network_filter_changed')
        subprocess.run(['virsh','-c','qemu:///system','nwfilter-undefine',name],check=True,capture_output=True,timeout=10)
    require(subprocess.run(['virsh','-c','qemu:///system','nwfilter-dumpxml',name],capture_output=True,timeout=10).returncode!=0,'network_filter_remains')


def canonical_rules(root):
    """Normalize only libvirt's observed equivalent protocol/default spelling."""
    rules=[]
    for rule in root.findall('rule'):
        priority=int(rule.get('priority','500'))
        if not -1000<=priority<=1000:priority=500
        protocols=[]
        for element in rule:
            values=dict(element.attrib)
            if values.get('protocolid')=='ipv4':values['protocolid']='0x0800'
            protocols.append((element.tag,sorted(values.items())))
        rules.append((rule.get('action'),rule.get('direction'),priority,protocols))
    return rules
