"""Available ISO software inputs, explicitly separate from installed inventory."""
import json
from pathlib import Path
import subprocess
import re

from .vm_inputs import sha256
from .ubuntu_assessment import require

LAYERS = ('filesystem.manifest','ubuntu-server-minimal.manifest',
          'ubuntu-server-minimal.ubuntu-server.manifest',
          'ubuntu-server-minimal.ubuntu-server.installer.manifest',
          'ubuntu-server-minimal.ubuntu-server.installer.generic.manifest',
          'ubuntu-server-minimal.ubuntu-server.installer.generic-hwe.manifest')


def parse_manifest(text):
    lines=text.splitlines()
    delta=bool(lines and lines[0].startswith('--- '))
    if delta:
        require(len(lines)>1 and lines[1].startswith('+++ '),'build_svd_delta_header')
        lines=lines[2:]
    packages=[]
    for line in lines:
        if delta and re.fullmatch(r'@@ .* @@.*',line):continue
        operation='available'
        if delta:
            require(bool(line) and line[0] in '+- ','build_svd_delta_format')
            operation={'+':'added-to-layer','-':'removed-from-layer',' ':'context'}[line[0]]
            line=line[1:]
        values=line.split()
        require(len(values)==2 or (len(values)==3 and values[0].startswith('snap:')),'build_svd_manifest_format')
        packages.append({'name':values[0],'version':values[1] if len(values)==2 else None,'architecture':None,
                         'kind':'snap' if len(values)==3 else 'deb','operation':operation,
                         'channel':values[1] if len(values)==3 else None,'revision':values[2] if len(values)==3 else None})
    return {'format':'native-package-delta' if delta else 'native-package-snapshot','packages':packages}


def build_svd(run, candidate, manifest):
    run,candidate=Path(run),Path(candidate)
    require(sha256(candidate)==manifest['candidate_sha256'],'build_svd_candidate_mismatch')
    output=run/'build-svd'
    if (output/'svd.json').exists():
        return json.loads((output/'svd.json').read_text())
    output.mkdir(mode=0o700,exist_ok=True)
    layers=[]
    for name in LAYERS:
        file=output/name
        if not file.exists():
            subprocess.run(['xorriso','-osirrox','on','-indev',str(candidate),'-extract','/casper/'+name,str(file)],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        require(file.stat().st_size<=1024**2,'build_svd_manifest_size')
        layers.append({'media_path':'/casper/'+name,'sha256':sha256(file),**parse_manifest(file.read_text()),
                       'architecture_note':'Not recorded by this native media manifest; do not infer per-package architecture.'})
    bundle=json.loads((run/'inputs/payload/manifest.json').read_text())
    value={'schema_version':'1.0','kind':'available-iso-build-input-software','candidate_sha256':manifest['candidate_sha256'],
           'source_media':manifest['source'],'media_layers':layers,'offline_repository_packages':bundle['packages'],
           'package_snapshot':bundle['snapshot'],
           'scanner_toolchain':manifest.get('scanner_toolchain'),
           'pam_toolchain':manifest.get('pam_toolchain'),
           'meaning':'Media layers and available offline packages are non-additive build inputs, not proof of installed software.'}
    (output/'svd.json').write_text(json.dumps(value,indent=2))
    (output/'svd.txt').write_text(value['meaning']+'\n'+'\n'.join(
        layer['media_path']+': '+str(len(layer['packages']))+' native package/version rows' for layer in layers)+'\n'+
        'Offline repository: '+str(len(bundle['packages']))+' package/version/architecture rows\n')
    return value
