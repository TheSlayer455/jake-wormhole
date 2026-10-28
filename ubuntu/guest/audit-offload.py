#!/usr/bin/python3
"""Bounded TLS offload of observed audit-file prefixes; never removes local logs."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time
import zlib
import uuid


def offload():
    root=Path('/var/lib/wormhole')
    if os.geteuid()!=0 or not (root/'installation-complete').is_file():
        raise RuntimeError('requires the final installed guest')
    files=sorted(p for p in Path('/var/log/audit').iterdir() if re.fullmatch(r'audit[.]log(?:[.][0-9]+)?',p.name))
    if not files or any(p.is_symlink() or not p.is_file() for p in files):raise RuntimeError('invalid audit input')
    sizes={p.name:p.stat().st_size for p in files}
    if not 0<sum(sizes.values())<=8*1024**2:raise RuntimeError('audit snapshot exceeds declared receiver budget')
    identifier=(root/'run-id').read_text().strip()
    archive_id=str(uuid.uuid4())
    deadline=time.monotonic()+20
    context=ssl.create_default_context(cafile='/etc/wormhole-lab-ca.crt')
    manifest=[]
    with socket.create_connection(('192.0.2.1',6514),timeout=3) as raw:
        with context.wrap_socket(raw,server_hostname='wormhole-sandbox') as stream:
            def send(value):
                if time.monotonic()>=deadline:raise TimeoutError('audit offload deadline')
                stream.sendall(('WORMHOLE_AUDIT_ARCHIVE '+json.dumps(dict(value,run_id=identifier,archive_id=archive_id))+'\n').encode())
            for path in files:
                digest=hashlib.sha256();remaining=sizes[path.name];index=0
                compressor=zlib.compressobj()
                with path.open('rb') as source:
                    while remaining:
                        data=source.read(min(16384,remaining))
                        if not data:raise RuntimeError('audit source shortened during snapshot')
                        remaining-=len(data);digest.update(data)
                        block=compressor.compress(data)
                        if block:
                            send({'kind':'chunk','file':path.name,'index':index,'data':base64.b64encode(block).decode()});index+=1
                block=compressor.flush()
                send({'kind':'chunk','file':path.name,'index':index,'data':base64.b64encode(block).decode()})
                manifest.append({'file':path.name,'bytes':sizes[path.name],'sha256':digest.hexdigest(),'chunks':index+1})
            send({'kind':'complete','files':manifest,'snapshot_semantics':'file prefixes at start; local audit logs preserved'})
            # sendall proves only local delivery. Wait until the receiver has
            # persisted the final record before closing this TLS connection.
            acknowledged=b''
            while not acknowledged.endswith(b'\n') and len(acknowledged)<=1024:
                part=stream.recv(1024-len(acknowledged))
                if not part:raise RuntimeError('audit receiver closed without durable acknowledgment')
                acknowledged+=part
            confirm_ack(acknowledged,identifier,archive_id)
    receipt={'run_id':identifier,'archive_id':archive_id,'files':manifest,'transport':'TLS with lab CA and server identity verification',
             'receiver_acknowledged':True,'local_logs_removed':False}
    (root/'audit-offload-receipt.json').write_text(json.dumps(receipt))
    return receipt


def confirm_ack(raw,identifier,archive_id):
    if json.loads(raw)!={'run_id':identifier,'archive_saved':archive_id}:raise RuntimeError('audit acknowledgment identity mismatch')


if __name__=='__main__':offload()
