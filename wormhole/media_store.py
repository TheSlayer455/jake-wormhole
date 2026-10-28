"""Streaming local artifact-store approximation for real installation media.

Separate from the small synthetic chunk contract. No ISO is qualified here.
Licensed bytes and operation checkpoints belong outside source control.
"""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
from uuid import uuid4

from .runs import RunError, _owned, _path_chain, atomic_json, read_json, workspace_path

BLOCK = 1024 * 1024
MAX_BYTES = 32 * 1024**3
MAX_CHUNKS = 512
DEFAULT_CHUNK = 64 * BLOCK
RESERVE = 512 * BLOCK
SHA = re.compile(r'[a-f0-9]{64}\Z')
MARKER = {'application':'jake-wormhole','operation':'local-media-store-v1'}


def require(value, code):
    if not value: raise RunError(code,'Media operation refused; preserve original input and private checkpoints.')


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def fingerprint(value): return hashlib.sha256(canonical(value)).hexdigest()


def validate(value):
    require(type(value) is dict and set(value)=={'schema_version','capability','source_name','bytes','sha256',
        'chunk_bytes','chunks','lab_iso_qualified','production_iso_eligible'},'media_manifest_invalid')
    require(value['schema_version']=='2.0' and value['capability']=='iso-source-chunks' and
        value['lab_iso_qualified'] is False and value['production_iso_eligible'] is False,'media_scope_invalid')
    require(type(value['source_name']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.iso',value['source_name']) and
        type(value['bytes']) is int and 32774<=value['bytes']<=MAX_BYTES and
        type(value['sha256']) is str and SHA.fullmatch(value['sha256']) and
        type(value['chunk_bytes']) is int and 65536<=value['chunk_bytes']<=256*BLOCK,'media_manifest_invalid')
    chunks=value['chunks']
    require(type(chunks) is list and len(chunks)==math.ceil(value['bytes']/value['chunk_bytes']) and
        1<=len(chunks)<=MAX_CHUNKS,'media_chunk_count')
    offset=0
    for index,item in enumerate(chunks):
        require(type(item) is dict and set(item)=={'index','offset','bytes','sha256','object'},'media_chunk_invalid')
        require(type(item['index']) is int and item['index']==index and type(item['offset']) is int and item['offset']==offset and
            type(item['bytes']) is int and item['bytes']==min(value['chunk_bytes'],value['bytes']-offset) and
            type(item['sha256']) is str and SHA.fullmatch(item['sha256']) and
            item['object']=='objects/'+item['sha256']+'.chunk','media_chunk_order_or_identity')
        offset+=item['bytes']
    require(offset==value['bytes'],'media_chunk_count')
    return value


def load(path):
    path=Path(path);_owned(path)
    with path.open('rb') as stream:raw=stream.read(1024*1024+1)
    require(len(raw)<=1024*1024,'media_manifest_bound')
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'media_duplicate_key');result[key]=value
        return result
    try:return validate(json.loads(raw,object_pairs_hook=unique))
    except (ValueError,UnicodeError):raise RunError('media_manifest_invalid','Expected a bounded media manifest.') from None


@contextmanager
def file_lock(path):
    require(sys.platform.startswith('linux'),'media_linux_required')
    import fcntl
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        _owned(path);actual=os.fstat(fd);expected=path.stat()
        require((actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino),'media_lock_changed')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RunError('media_store_busy','Another media operation owns this store or destination.') from None
        yield fd
    finally:os.close(fd)


@contextmanager
def locked_store(value):
    require(sys.platform.startswith('linux'),'media_linux_required')
    root=workspace_path(value,create=True)
    marker=root/'owner.json'
    if marker.exists():require(read_json(marker)==MARKER,'media_store_owner')
    else:
        require(not any(root.iterdir()),'media_store_owner');atomic_json(marker,MARKER)
    _owned(marker)
    with file_lock(root/'operation.lock'):
        for name in ('objects','manifests'):
            (root/name).mkdir(mode=0o700,exist_ok=True);_owned(root/name,directory=True)
        yield root


def stream_chunk(stream,size,*,output=None,whole=None):
    digest=hashlib.sha256();remaining=size
    while remaining:
        raw=stream.read(min(BLOCK,remaining));require(bool(raw),'media_truncated')
        remaining-=len(raw);digest.update(raw)
        if output is not None:output.write(raw)
        if whole is not None:whole.update(raw)
    return digest.hexdigest()


def verify_object(path,item):
    _owned(path);require(path.stat().st_size==item['bytes'],'media_object_size')
    with path.open('rb') as stream:require(stream_chunk(stream,item['bytes'])==item['sha256'],'media_object_hash')


def split(source,store,expected_sha256,*,chunk_bytes=DEFAULT_CHUNK):
    source=Path(source)
    require(source.is_absolute() and type(expected_sha256) is str and SHA.fullmatch(expected_sha256),'media_input_invalid')
    _path_chain(source)
    require(source.is_file() and source.stat().st_nlink==1,'media_input_invalid')
    size=source.stat().st_size
    require(type(chunk_bytes) is int and 65536<=chunk_bytes<=256*BLOCK and
        32774<=size<=MAX_BYTES and math.ceil(size/chunk_bytes)<=MAX_CHUNKS,'media_input_bound')
    value={'schema_version':'2.0','capability':'iso-source-chunks','source_name':source.name,'bytes':size,
        'sha256':expected_sha256,'chunk_bytes':chunk_bytes,'chunks':[],
        'lab_iso_qualified':False,'production_iso_eligible':False}
    with locked_store(store) as root:
        require(shutil.disk_usage(root).free>=size+RESERVE,'media_disk_capacity')
        whole=hashlib.sha256();offset=0
        with source.open('rb') as input_stream:
            identity=os.fstat(input_stream.fileno())
            input_stream.seek(32769);require(input_stream.read(5)==b'CD001','media_not_iso9660');input_stream.seek(0)
            while offset<size:
                length=min(chunk_bytes,size-offset);temporary=root/'objects'/('.partial-'+str(uuid4()))
                with temporary.open('xb') as output:
                    temporary.chmod(0o600)
                    digest=stream_chunk(input_stream,length,output=output,whole=whole)
                    output.flush();os.fsync(output.fileno())
                item={'index':len(value['chunks']),'offset':offset,'bytes':length,'sha256':digest,'object':'objects/'+digest+'.chunk'}
                target=root/item['object']
                if target.exists():verify_object(target,item);temporary.unlink()
                else:os.replace(temporary,target)
                value['chunks'].append(item);offset+=length
            after=os.fstat(input_stream.fileno())
            require(not input_stream.read(1) and (identity.st_size,identity.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'media_source_changed')
        require(whole.hexdigest()==expected_sha256,'media_source_hash')
        validate(value);manifest=root/'manifests'/(expected_sha256+'.json')
        if manifest.exists():require(canonical(load(manifest))==canonical(value),'media_manifest_conflict')
        else:atomic_json(manifest,value)
        return {'manifest':str(manifest),'sha256':expected_sha256,'bytes':size,'chunks':len(value['chunks']),
            'capability':'iso-source-chunks','lab_iso_qualified':False,'production_iso_eligible':False}


def assemble(manifest,store,destination):
    value=load(manifest);destination=Path(destination)
    require(destination.is_absolute() and destination.suffix=='.iso','media_output_invalid')
    _path_chain(destination);workspace_path(destination.parent)
    require(not destination.exists(),'media_output_exists')
    partial=destination.with_name(destination.name+'.partial');checkpoint=destination.with_name(destination.name+'.reconstruction.json')
    identity={'operation':'iso-reconstruction-v1','manifest_sha256':fingerprint(value),'bytes':value['bytes']}
    with locked_store(store) as root,file_lock(destination.with_name(destination.name+'.reconstruction.lock')):
        for item in value['chunks']:
            path=root/item['object'];_owned(path);require(path.stat().st_size==item['bytes'],'media_object_size')
        require(partial.exists()==checkpoint.exists(),'media_checkpoint_incomplete')
        resumed=0;whole=hashlib.sha256()
        if checkpoint.exists():
            old=read_json(checkpoint)
            require(all(old.get(key)==entry for key,entry in identity.items()),'media_checkpoint_changed')
            _owned(partial);require(partial.stat().st_size<=value['bytes'],'media_checkpoint_changed')
            with partial.open('r+b') as output:
                size=partial.stat().st_size
                for item in value['chunks']:
                    if item['offset']+item['bytes']>size:break
                    require(stream_chunk(output,item['bytes'],whole=whole)==item['sha256'],'media_partial_hash')
                    resumed+=1
                output.truncate(output.tell());output.flush();os.fsync(output.fileno())
        else:
            require(shutil.disk_usage(destination.parent).free>=value['bytes']+RESERVE,'media_disk_capacity')
            with partial.open('xb'):partial.chmod(0o600)
            atomic_json(checkpoint,{**identity,'completed_chunks':0})
        require(shutil.disk_usage(destination.parent).free>=value['bytes']-partial.stat().st_size+RESERVE,'media_disk_capacity')
        with partial.open('ab') as output:
            for item in value['chunks'][resumed:]:
                with (root/item['object']).open('rb') as input_stream:
                    require(stream_chunk(input_stream,item['bytes'],output=output,whole=whole)==item['sha256'],'media_object_hash')
                output.flush();os.fsync(output.fileno())
                atomic_json(checkpoint,{**identity,'completed_chunks':item['index']+1})
        require(whole.hexdigest()==value['sha256'] and partial.stat().st_size==value['bytes'],'media_reconstruction_hash')
        require(not destination.exists(),'media_output_exists');os.replace(partial,destination)
        atomic_json(checkpoint,{**identity,'completed_chunks':len(value['chunks']),'status':'completed'})
        return {'sha256':value['sha256'],'bytes':value['bytes'],'resumed_chunks':resumed,
            'lab_iso_qualified':False,'production_iso_eligible':False}
