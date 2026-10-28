"""Small owner-only local provider. No credentials are discovered or printed."""
import argparse
import json
import os
from pathlib import Path
import stat

from .runs import RunError

KINDS={'ubuntu-pro'}


def protected(path,*,directory=False):
    path=Path(path)
    if path.is_symlink():raise RunError('secret_symlink','Use an ordinary private owner file.')
    info=path.stat()
    if info.st_uid!=os.geteuid() or info.st_mode & 0o077 or (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1)):
        raise RunError('secret_ownership','Private provider objects must belong to the effective operator and be owner-only.')
    return path


def status(store):
    root=protected(store,directory=True)
    path=root/'ubuntu-pro'
    if path.exists():protected(path)
    return {'provider':'owner-file-v1','ubuntu_pro_present':path.exists(),'vendor_entitlement_verified':False}


def put(store,kind,source):
    if kind not in KINDS:raise RunError('secret_kind','Unsupported explicit provider slot.')
    root=protected(store,directory=True);source=protected(source)
    value=source.read_bytes().strip()
    if not 16<=len(value)<=4096 or any(c<33 or c>126 for c in value):raise RunError('secret_format','Owner input must be one printable token, without whitespace.')
    fd=os.open(root/kind,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:os.write(fd,value);os.fsync(fd)
    finally:os.close(fd)
    return status(root)


def read(store,kind):
    if kind not in KINDS:raise RunError('secret_kind','Unsupported explicit provider slot.')
    root=protected(store,directory=True)
    if not (root/kind).exists():raise RunError('entitlement_input_missing','Owner must populate the explicit private Ubuntu Pro slot; never supply credentials in chat.')
    return protected(root/kind).read_bytes()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['status','put'])
    p.add_argument('--store',required=True);p.add_argument('--source-file');p.add_argument('--kind',choices=sorted(KINDS),default='ubuntu-pro')
    a=p.parse_args()
    if a.operation=='put' and not a.source_file:p.error('put requires an existing owner-only --source-file')
    print(json.dumps(status(a.store) if a.operation=='status' else put(a.store,a.kind,a.source_file)))


if __name__=='__main__':main()
