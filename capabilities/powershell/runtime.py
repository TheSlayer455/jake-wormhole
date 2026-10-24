"""Fixed optional container capability; never scanner or remoting validation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path('/opt/wormhole-capabilities/powershell')
PACKAGE = 'powershell=7.6.8-1.deb'
SCRIPT = "$ErrorActionPreference='Stop';[ordered]@{version=$PSVersionTable.PSVersion.ToString();edition=$PSVersionTable.PSEdition;platform=$PSVersionTable.Platform;dotnet=[System.Environment]::Version.ToString();result=(1+1)}|ConvertTo-Json -Compress"


def require(value):
    if not value: raise ValueError('Fixed optional capability refused')


def base_runtime():
    spec = importlib.util.spec_from_file_location('qualified_helper_runtime', '/opt/wormhole/runtime.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.guard('helper')
    return module


def environment():
    return {'PATH':'/opt/wormhole/venv/bin:/usr/bin:/bin','HOME':'/tmp/wormhole-powershell-home',
        'TMPDIR':'/tmp','LC_ALL':'C.UTF-8','LANG':'C.UTF-8','POWERSHELL_TELEMETRY_OPTOUT':'1',
        'POWERSHELL_UPDATECHECK':'Off','PSModuleAnalysisCachePath':'/dev/null',
        'XDG_CACHE_HOME':'/tmp/wormhole-powershell-cache','DOTNET_CLI_HOME':'/tmp/wormhole-powershell-home'}


def capture(arguments, timeout):
    process=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        env=environment(),start_new_session=True,bufsize=0)
    os.set_blocking(process.stdout.fileno(),False)
    raw=bytearray();deadline=time.monotonic()+timeout;expired=False;eof=False
    try:
        while True:
            try:
                block=os.read(process.stdout.fileno(),4096)
                if block:raw.extend(block)
                else:eof=True
            except BlockingIOError:pass
            if time.monotonic()>=deadline:expired=True;break
            if len(raw)>16384:break
            if eof and process.poll() is not None:break
            time.sleep(.01)
    finally:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait(timeout=2);process.stdout.close()
    require(not expired and len(raw)<=16384)
    return process.returncode,bytes(raw)


def query(package):
    code,raw=capture(['/usr/bin/dpkg-query','-W','-f=${db:Status-Abbrev}\t${Version}',package],3)
    require(code==0 and raw.startswith(b'ii \t') and len(raw)<=256)
    return raw.decode().split('\t',1)[1]


def doctor():
    module=base_runtime();normal=module.doctor('helper');require(normal['passed'] is True)
    lock=json.loads((ROOT/'lock.json').read_text())
    versions={name:query(name) for name in lock['dependency_packages']}
    require(versions['libicu74']==lock['icu_version'] and query('powershell')==lock['package_version'])
    for relative,expected in lock['installed_files'].items():
        path=Path('/opt/microsoft/powershell/7')/relative
        require(path.is_file() and not path.is_symlink() and path.stat().st_size<=1024*1024)
        require(hashlib.sha256(path.read_bytes()).hexdigest()==expected)
    code,raw=capture(['/opt/microsoft/powershell/7/pwsh','-NoLogo','-NoProfile','-NonInteractive','-Command',SCRIPT],20)
    require(code==0)
    value=json.loads(raw)
    require(type(value) is dict and set(value)=={'version','edition','platform','dotnet','result'} and
        value['version']=='7.6.8' and value['edition']=='Core' and value['platform']=='Unix' and
        type(value['result']) is int and value['result']==2 and type(value['dotnet']) is str and len(value['dotnet'])<=128)
    return {'operation':'optional-powershell-smoke','location':'optional-helper','status':'passed',
        'powershell':value,'dependency_versions':versions,'ordinary_helper_doctor':normal,
        'scanner_compatibility':'unavailable-no-authorized-package-or-documented-method',
        'production_iso_eligible':False,'runtime_pipeline_complete':False}


def missing_package():
    module=base_runtime();normal=module.doctor('helper')
    require(normal['passed'] is True)
    folder=Path('/tmp/wormhole-empty-package-source');folder.mkdir(mode=0o700)
    for directory in ('parts','lists','cache','apt-parts'):(folder/directory).mkdir(mode=0o700)
    for file in ('sources.list','status','apt.conf'):(folder/file).write_bytes(b'')
    arguments=['/usr/bin/apt-get','-s','-o','Debug::NoLocking=1','-o','Acquire::Retries=0',
        '-o','Dir::Etc::sourcelist='+str(folder/'sources.list'),'-o','Dir::Etc::sourceparts='+str(folder/'parts'),
        '-o','Dir::Etc::main='+str(folder/'apt.conf'),'-o','Dir::Etc::parts='+str(folder/'apt-parts'),
        '-o','Dir::State::status='+str(folder/'status'),'-o','Dir::State::lists='+str(folder/'lists'),
        '-o','Dir::Cache='+str(folder/'cache'),'install',PACKAGE]
    code,raw=capture(arguments,10)
    require(code==100 and b'Unable to locate package powershell' in raw)
    require((folder/'status').read_bytes()==b'' and not list((folder/'lists').iterdir()))
    return {'operation':'optional-powershell-missing-package','location':'optional-helper-package-source-fixture',
        'status':'failed','failure':{'code':'package_unavailable','package':'powershell','expected_version':'7.6.8-1.deb',
        'execution_location':'optional-helper-package-source-fixture','returncode':code},
        'source':'fixed-empty-local-APT-source-and-state','network':'none','ordinary_helper_doctor':normal,
        'independent_runtime_diagnostics':'Separate fresh Terraform/SSH/Ansible acceptance is required.',
        'scanner_compatibility':'unavailable-no-authorized-package-or-documented-method',
        'production_iso_eligible':False,'runtime_pipeline_complete':False}


def main():
    try:
        require(len(sys.argv)==2 and sys.argv[1] in {'doctor','smoke','missing'})
        module=base_runtime();operation=sys.argv[1]
        if operation=='doctor':value=doctor()
        else:
            module.identity();require(os.environ.get('WORMHOLE_CAPABILITY')=='powershell-explicit')
            def action():
                time.sleep(3) # Fixed cgroup observation window, within the60s lifetime.
                value=doctor() if operation=='smoke' else missing_package()
                print(json.dumps(value,sort_keys=True),flush=True)
                return 0 if value['status']=='passed' else 1
            require(os.getpid()==1)
            return module.supervise(action,60)
        print(json.dumps(value,sort_keys=True));return 0
    except Exception:
        print(json.dumps({'error':{'code':'optional_capability_refused','location':'optional-helper'},'production_iso_eligible':False}))
        return 2


if __name__=='__main__':raise SystemExit(main())
