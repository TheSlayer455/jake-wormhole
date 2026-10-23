"""Fixed offline RPM assembly. Container PID1 supervises the fixed install child."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

REQUEST=Path('/request/assembly.json')
PACKAGES=Path('/packages')
INPUT=Path('/candidate-input')
KEY=Path('/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release')
MAX_CAPTURE=65536
BASE='sha256:3bd1aa8b49948633375021c22ef5601ae644f5c08c869751ac2b542884622ea1'


class AssemblyError(Exception):
    def __init__(self,code):self.code=code


def require(value,code='rpm_assembly_refused'):
    if not value:raise AssemblyError(code)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(value):return hashlib.sha256(value).hexdigest()


def read(path,maximum=262144):
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1 and 0<path.stat().st_size<=maximum)
    with path.open('rb') as stream:raw=stream.read(maximum+1)
    require(0<len(raw)<=maximum);return raw


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def command(arguments,seconds=30,allowed=(0,)):
    # The PID1 supervisor independently limits all children if this controller dies.
    process=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/tmp','LANG':'C','PYTHONDONTWRITEBYTECODE':'1'},close_fds=True,bufsize=0)
    end=time.monotonic()+seconds;data=bytearray();os.set_blocking(process.stdout.fileno(),False)
    try:
        eof=False
        while not eof or process.poll() is None:
            require(time.monotonic()<end)
            try:
                chunk=os.read(process.stdout.fileno(),4096)
                if chunk:data.extend(chunk);require(len(data)<=MAX_CAPTURE)
                else:eof=True
            except BlockingIOError:pass
            time.sleep(.005)
        require(process.returncode in allowed)
        return bytes(data),process.returncode
    finally:
        if process.poll() is None:process.kill()
        process.wait(timeout=2);process.stdout.close()


def nevra(package):
    return {'name':str(package.name),'epoch':int(package.epoch or 0),'version':str(package.version),'release':str(package.release),'arch':str(package.arch)}


def signature_output(raw):
    require(type(raw) is bytes and 0<len(raw)<=MAX_CAPTURE,'rpm_signature_unverified')
    text=raw.decode('utf-8')
    require(re.search(r'Signature[^\n]*: OK(?:\r?\n|$)',text) and
        not any(word in text.upper() for word in ('NOKEY','NOT OK','BAD SIGNATURE','NOTTRUSTED')),'rpm_signature_unverified')
    return sha(raw)


def checked_signatures(request):
    config=json.loads(read(Path('/recipe/assembly.json'),16384));observer=module('fixed_rpm_observer','/recipe/probe.py')
    key_raw=read(KEY,65536);fingerprints=observer.fingerprints(key_raw)
    require(sha(key_raw)==request['key_file']['sha256'] and fingerprints==request['key_file']['primary_fingerprints'] and
        fingerprints and set(fingerprints)<=set(config['trusted_primary_fingerprints']))
    database=Path('/tmp/wormhole-rpm-signature-db');database.mkdir(mode=0o700)
    command(['/usr/bin/rpm','--dbpath',str(database),'--initdb'])
    key_files=[KEY];records=[{'path':str(KEY),'sha256':sha(key_raw),'primary_fingerprints':fingerprints}]
    for key_file in key_files:command(['/usr/bin/rpm','--dbpath',str(database),'--import',str(key_file)])
    verified=[]
    for package in request['resolution']['packages']:
        name=Path(package['path']).name
        require(re.fullmatch(r'[A-Za-z0-9+_.~:-]+\.rpm',name))
        path=PACKAGES/name;raw=read(path,64*1024*1024)
        require(len(raw)==package['bytes'] and sha(raw)==package['sha256'])
        output,_=command(['/usr/bin/rpmkeys','--dbpath',str(database),'--checksig','--verbose',str(path)])
        digest=signature_output(output)
        verified.append({'filename':name,'sha256':package['sha256'],'signature':'verified','verification_output_sha256':digest})
    # DNF's own local-package signature checks use the same now-proven trust file.
    for key_file in key_files:command(['/usr/bin/rpm','--import',str(key_file)])
    return verified,records


def license_records(rpm):
    # A bounded read-only discovery, not a recursive filesystem scan or generic
    # GPL-license-as-UBI-EULA substitution.
    paths={Path('/licenses/ubi9-container')/name for name in ('LICENSE','LICENSE.txt','EULA')}
    transaction=rpm.TransactionSet('/')
    try:
        for name in ('redhat-release','redhat-release-eula','ubi-release'):
            for header in transaction.dbMatch('name',name):
                for value in header['filenames']:
                    require(type(value) is str and len(value)<=512)
                    path=Path(value)
                    if str(path).startswith(('/usr/share/doc/','/usr/share/licenses/')) and 'eula' in path.name.lower():paths.add(path)
    finally:transaction.closeDB()
    require(len(paths)<=64)
    records=[]
    for path in sorted(paths):
        if path.is_file():
            raw=read(path,65536);records.append({'path':str(path),'bytes':len(raw),'sha256':sha(raw)})
    return records


def retain_eula():
    config=json.loads(read(Path('/recipe/assembly.json'),16384));item=config['eula']
    raw=read(Path('/license/UBI-EULA-20190422.pdf'),262144)
    require(len(raw)==248785 and sha(raw)=='a07025b9f5b71a816febe6ac76f21c9f759c806fa0a66874af90a50c3293f1b6' and
        item['destination']=='/licenses/ubi9-container/UBI-EULA-20190422.pdf','rpm_license_retention_unverified')
    folder=Path('/licenses/ubi9-container');folder.mkdir(mode=0o755,parents=True,exist_ok=True);folder.chmod(0o755)
    destination=folder/'UBI-EULA-20190422.pdf'
    require(not destination.exists(),'rpm_license_retention_unverified')
    descriptor=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444);os.fchmod(descriptor,0o444)
    with os.fdopen(descriptor,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(read(destination,262144)==raw,'rpm_license_retention_unverified')
    return {'path':str(destination),'bytes':len(raw),'sha256':sha(raw)}


def install(request):
    import dnf,rpm
    signatures,trusted_keys=checked_signatures(request);licenses=license_records(rpm);licenses.append(retain_eula())
    expected=request['resolution']['packages'];paths=[str(PACKAGES/Path(item['path']).name) for item in expected]
    require(set(os.listdir(PACKAGES))=={Path(item['path']).name for item in expected})
    if paths:
        with dnf.Base() as base:
            base.conf.plugins=False;base.conf.install_weak_deps=False;base.conf.best=True;base.conf.strict=True
            base.conf.cachedir='/tmp/wormhole-rpm-cache';base.conf.persistdir='/tmp/wormhole-rpm-persist';base.conf.logdir='/tmp'
            base.conf.gpgcheck=True;base.conf.localpkg_gpgcheck=True;base.conf.reposdir=[]
            require(not list(base.repos.iter_enabled()))
            base.fill_sack(load_system_repo=True,load_available_repos=False)
            packages=base.add_remote_rpms(paths,strict=True)
            require(len(packages)==len(expected))
            for package in packages:base.package_install(package,strict=True)
            base.resolve(allow_erasing=False)
            require(base.transaction is not None and not list(base.transaction.remove_set))
            actual=sorted((nevra(package) for package in base.transaction.install_set),key=canonical)
            wanted=sorted(({key:item[key] for key in ('name','epoch','version','release','arch')} for item in expected),key=canonical)
            require(canonical(actual)==canonical(wanted))
            base.do_transaction()  # Local verified RPM files only; no download call/repositories/network.
    command(['/usr/bin/dnf','--noplugins','--disablerepo=*','--setopt=cachedir=/tmp/wormhole-rpm-check',
        '--setopt=persistdir=/tmp/wormhole-rpm-check-persist','--setopt=logdir=/tmp','check'],seconds=45)
    observer=module('fixed_postinstall_observer','/recipe/probe.py');installed=observer.packages(rpm)
    for name,version in request['manifest']['packages'].items():
        rows=[item for item in installed if item['name']==name]
        require(len(rows)==1 and canonical({k:rows[0][k] for k in version})==canonical(version))
    # Public-key-only account, no host key generation or systemd service start.
    _,code=command(['/usr/bin/getent','passwd','wormhole'],allowed=(0,2));require(code==2)
    command(['/usr/sbin/groupadd','--gid','10001','wormhole'])
    command(['/usr/sbin/useradd','--uid','10001','--gid','10001','--create-home','--shell','/bin/sh','wormhole'])
    command(['/usr/sbin/usermod','--password','x','wormhole']);Path('/home/wormhole').chmod(0o750)
    Path('/opt/wormhole').mkdir(mode=0o755);Path('/etc/wormhole').mkdir(mode=0o755)
    Path('/etc/wormhole/role').write_text('target\n');Path('/etc/wormhole/role').chmod(0o644)
    for source,destination in (('/recipe/runtime.py','/opt/wormhole/runtime.py'),('/recipe/sshd_config','/etc/ssh/sshd_config')):
        raw=read(Path(source),65536)
        with Path(destination).open('wb') as stream:stream.write(raw)
        Path(destination).chmod(0o644)
    installer=module('fixed_candidate_copy','/recipe/candidate-install.py')
    require(sha(read(INPUT/'manifest.json',32768))==request['candidate_sha256'])
    copied=installer.install_files()
    require(copied['candidate_sha256']==request['candidate_sha256'] and copied['files']==request['manifest']['files'])
    require(not list(Path('/etc/ssh').glob('ssh_host_*')) and not any(Path(path).exists() for path in ('/var/run/docker.sock','/run/docker.sock')))
    release=observer.os_release();require(release['ID']=='rhel' and release['VERSION_ID']=='9.8')
    key_headers=[record for record in installed if record['name']=='gpg-pubkey']
    record={'status':'installed','base_image_id':BASE,'candidate_sha256':request['candidate_sha256'],
        'content_sha256':request['manifest']['content_sha256'],'source_candidate_sha256':request['manifest']['source_candidate_sha256'],
        'installed_packages':installed,'signature_results':signatures,'key_files':trusted_keys,'key_records':key_headers,'os_release':release,'license_files':licenses,
        'dependency_check':'passed','hostkeys_absent':True,'runtime_sha256':sha(read(Path('/opt/wormhole/runtime.py'),65536)),
        'sshd_config_sha256':sha(read(Path('/etc/ssh/sshd_config'),16384)),
        'runtime_pipeline_complete':False,'production_iso_eligible':False}
    output=Path('/opt/wormhole/rpm-installed.json');raw=canonical(record);require(len(raw)<=49152)
    with output.open('xb') as stream:stream.write(raw)
    output.chmod(0o444)
    print('Fixed offline UBI candidate assembly completed; SSH/Ansible qualification remains separate.',flush=True)


def main():
    require(len(sys.argv)==1 and os.getpid()==1 and os.getuid()==0 and Path('/.dockerenv').is_file() and
        os.environ.get('WORMHOLE_ROLE')=='rpm-builder' and not any(Path(path).exists() for path in ('/var/run/docker.sock','/run/docker.sock')))
    request=json.loads(read(REQUEST));require(request['operation']=='ubi9-assembly-request-v1' and request['base_image_id']==BASE and
        request['run_id']==os.environ.get('WORMHOLE_RUN_ID') and request['manifest']['run_id']==request['run_id'])
    supervisor=module('fixed_image_supervisor','/recipe/runtime.py')
    def work():
        try:
            end=time.monotonic()+15
            while not Path('/run/wormhole-rpm-build.start').exists():require(time.monotonic()<end);time.sleep(.02)
            require(read(Path('/run/wormhole-rpm-build.start'),2)==b'1\n')
            install(request);return 0
        except Exception as error:
            print(json.dumps({'operation':'ubi9-offline-assembly','status':'failed','code':getattr(error,'code','rpm_assembly_refused')}),flush=True)
            return 2
    return supervisor.supervise(work,600)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('Fixed offline UBI candidate assembly refused.',flush=True);raise SystemExit(2)
