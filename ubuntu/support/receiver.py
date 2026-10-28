"""Private bounded lab receivers: TLS syslog, ASCII audit and host-clock NTP.

Runs only in the pinned unprivileged support container. NTP is explicitly a
stratum-10 lab host-clock reference, not certified external time. ASCII audit
does not claim Kerberos/TLS protection; the separate syslog channel uses TLS.
"""
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import http.server
import tempfile
import subprocess

os.umask(0o077)
c=json.load(sys.stdin)
for name in ('certificate','key'):(Path('/tmp')/name).write_text(c.pop(name))
for name in ('ca.crt','responder.crt','responder.key','index'):(Path('/tmp')/name).write_text(c.pop(name))
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain('/tmp/certificate','/tmp/key')
lock=threading.Lock()


def retain(kind,peer,body):
    path=Path('/evidence')/(kind+'.jsonl')
    record=(json.dumps({'kind':kind,'peer':peer,'received_at':time.time(),
                       'body':body.decode('utf-8',errors='replace')})+'\n').encode()
    with lock:
        if (path.stat().st_size if path.exists() else 0)+len(record)>16*1024**2:os._exit(2)
        with path.open('ab') as stream:
            stream.write(record)
            stream.flush();os.fsync(stream.fileno())


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
    slots=threading.BoundedSemaphore(16)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):request.close();return
        super().process_request(request,address)
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()


class Lines(socketserver.StreamRequestHandler):
    def handle(self):
        if self.client_address[0] not in {c['guest'],c['bind']}:return
        self.connection.settimeout(1800)
        while True:
            value=self.rfile.readline(65537)
            if not value:return
            if len(value)>65536:return
            retain(self.server.kind,self.client_address[0],value)
            if value.startswith(b'WORMHOLE_AUDIT_ARCHIVE '):
                record=json.loads(value.split(b' ',1)[1])
                if record.get('kind')=='complete':
                    # retain() has flushed and fsynced every preceding record
                    # on this connection. The controller still verifies bytes.
                    self.connection.sendall((json.dumps({'run_id':record['run_id'],'archive_saved':record['archive_id']})+'\n').encode())


class TLS(TCP):
    def get_request(self):
        sock,address=super().get_request();sock.settimeout(5)
        try:return ctx.wrap_socket(sock,server_side=True),address
        except Exception:sock.close();raise


class NTP(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        if self.client_address[0] not in {c['guest'],c['bind']} or len(data)<48 or data[0]&7!=3:return
        stamp=time.time()+2208988800
        parts=(int(stamp),int((stamp%1)*2**32))
        packet=struct.pack('!BBBb11I',0x24,10,4,-20,0,0,0x4c4f434c,*parts,
                           *struct.unpack('!II',data[40:48]),*parts,*parts)
        sock.sendto(packet,self.client_address)


class OCSP(http.server.BaseHTTPRequestHandler):
    # Only the two declared disposable identities and CA index are served.
    # OpenSSL performs DER parsing, nonce handling and delegated response signing.
    def log_message(self,*args):pass
    def do_POST(self):
        self.connection.settimeout(3)
        try:size=int(self.headers.get('Content-Length','0'))
        except ValueError:size=0
        if self.client_address[0] not in {c['guest'],c['bind']} or not 0<size<=65536:
            self.send_error(400);return
        data=self.rfile.read(size)
        if len(data)!=size:self.send_error(400);return
        with tempfile.TemporaryDirectory(dir='/tmp',prefix='ocsp-') as directory:
            request=Path(directory)/'request';response=Path(directory)/'response';request.write_bytes(data)
            result=subprocess.run(['openssl','ocsp','-index','/tmp/index','-CA','/tmp/ca.crt','-rsigner','/tmp/responder.crt',
                '-rkey','/tmp/responder.key','-reqin',str(request),'-respout',str(response),'-rmd','sha256','-nmin','1'],
                capture_output=True,timeout=3)
            if result.returncode or not response.is_file() or response.stat().st_size>65536:self.send_error(400);return
            body=response.read_bytes()
        self.send_response(200);self.send_header('Content-Type','application/ocsp-response')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)


class OCSPServer(TCP):
    slots=threading.BoundedSemaphore(4)


servers=[]
for cls,port,kind in ((TLS,6514,'syslog'),(TCP,6000,'audit')):
    server=cls((c['bind'],port),Lines);server.kind=kind;servers.append(server)
server=socketserver.UDPServer((c['bind'],12345),NTP);servers.append(server)
server=OCSPServer((c['bind'],8080),OCSP);servers.append(server)
for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
print('WORMHOLE_SUPPORT_READY',flush=True)
deadline=time.monotonic()+1800
while time.monotonic()<deadline:time.sleep(1)
print('WORMHOLE_SUPPORT_DEADLINE',flush=True)
sys.exit(1)
