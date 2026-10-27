"""Verified synthetic source -> fixed bundle -> immutable derived Ubuntu image.

Caller holds the Run lock, Docker scope and shared admission for image operations.
No ISO processing, package installation, arbitrary Dockerfile or URL is accepted.
"""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time

from . import chunks, images
from .contracts import _COMMON, _bounded_json, _validate
from .runs import RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, common, now, read_json, source_identity

CONTEXT = SOURCE_ROOT / 'candidate'
VERSION = '1.0.0-reference'
CONFIG = {'format': 'wormhole-reference-v1', 'greeting': 'reference-ready'}
NAMES = ('source.synthetic.bin', 'payload.py', 'version.txt', 'config.json')
CHECKS = ('candidate-userland', 'candidate-source-sha256', 'candidate-manifest-sha256', 'candidate-payload-sha256',
          'candidate-version', 'candidate-configuration', 'candidate-function')
MAX_BUNDLE = chunks.MAX_TOTAL + 65536
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
IDENTIFIER = re.compile(r'[a-f0-9]{64}\Z')


class CandidateError(RunError):
    pass


def require(condition, code='candidate_invalid'):
    if not condition:
        raise CandidateError(code, 'Candidate operation refused; retain exact private state and bounded evidence.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw): return hashlib.sha256(raw).hexdigest()


def bound_common(value, manifest):
    try:
        _validate(obj(_COMMON), common(value), '$')
        return common(value) == common(manifest)
    except (ValueError, TypeError, KeyError): return False


def obj(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


SHA = {'type': 'string', 'minLength': 64, 'maxLength': 64, 'pattern': r'^[a-f0-9]{64}$(?![\s\S])'}
MANIFEST = obj({**_COMMON, 'operation': {'const': 'synthetic-reference-candidate', 'type': 'string'},
    'synthetic': {'const': True, 'type': 'boolean'}, 'version': {'const': VERSION, 'type': 'string'},
    'source_sha256': SHA, 'chunk_plan_sha256': SHA, 'chunk_manifest_sha256': SHA,
    'applicability': obj({'os_id': {'type': 'string', 'const': 'ubuntu'}, 'os_version': {'type': 'string', 'const': '24.04'},
                         'platform': {'type': 'string', 'const': 'linux/amd64'}}),
    'configuration': obj({key: {'type': 'string', 'const': value} for key, value in CONFIG.items()}),
    'files': {'type': 'array', 'minItems': 4, 'maxItems': 4, 'x-uniqueBy': ['path'], 'items': obj({
        'path': {'type': 'string', 'enum': list(NAMES)}, 'sha256': SHA,
        'size': {'type': 'integer', 'minimum': 1, 'maximum': chunks.MAX_TOTAL}})},
    'test_contract_sha256': SHA, 'production_iso_eligible': {'type': 'boolean', 'const': False}})


def schema():
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:jake-wormhole:candidate-manifest:1.0',
        'title': 'Wormhole fixed reference candidate manifest v1', **deepcopy(MANIFEST)}


def test_contract():
    return {'schema_version': '1.0', 'version': VERSION, 'configuration': CONFIG, 'checks': list(CHECKS),
            'collector': 'fixed-ssh-ansible-candidate-v1', 'iso_processing': 'none', 'production_iso_eligible': False}


def input_identity(source_sha256):
    """Content dependencies exclude controller/tests and attempt provenance.

    The immutable builder image identifies its installed tools. This key permits
    comparison of construction inputs; it does not authorize image reuse without
    the existing image, artifact and source-bound evidence verification.
    """
    from .provisioning import TARGET_IMAGE
    require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}', source_sha256), 'candidate_source_unverified')
    inputs = {'base_image': TARGET_IMAGE, 'source_sha256': source_sha256,
        'customization': {name: sha((CONTEXT / name).read_bytes()) for name in ('payload.py', 'install.py')},
        'configuration': deepcopy(CONFIG), 'version': VERSION,
        'build_tool_identity': {'image_id': TARGET_IMAGE, 'entrypoint': 'python3-fixed-installer-v1'}}
    return {'build_inputs': inputs, 'input_sha256': sha(canonical(inputs))}


def input_record(run, manifest):
    return {**common(run.manifest()), 'operation': 'candidate-construction-inputs-v1',
        **input_identity(manifest['source_sha256']), 'generation_attempt': run.id,
        'candidate_sha256': sha(canonical(manifest)), 'production_iso_eligible': False}


def compare_inputs(previous, current):
    """A reuse *decision input*, not a cache hit or qualification decision."""
    for value in (previous, current):
        require(type(value) is dict and set(value) == {'build_inputs', 'input_sha256'} and
            type(value['build_inputs']) is dict and value['input_sha256'] == sha(canonical(value['build_inputs'])),
            'candidate_inputs_invalid')
    changed = sorted(key for key in set(previous['build_inputs']) | set(current['build_inputs'])
        if canonical(previous['build_inputs'].get(key)) != canonical(current['build_inputs'].get(key)))
    return {'content_reusable': not changed, 'changed_dependencies': changed,
        'artifact_verification_required': True, 'qualification_reuse_authorized': False}


def validate_manifest(value):
    try:
        _bounded_json(value); _validate(MANIFEST, value, '$')
        require([item['path'] for item in value['files']] == list(NAMES) and
            value['test_contract_sha256'] == sha(canonical(test_contract())) and
            sum(item['size'] for item in value['files']) <= MAX_BUNDLE and value['source_dirty'] is False and
            value['mode'] == 'container-reference' and value['files'][0]['sha256'] == value['source_sha256'])
    except (ValueError, TypeError, KeyError, RecursionError):
        raise CandidateError('candidate_manifest_invalid', 'Fixed candidate manifest is invalid.') from None
    return value


def bounded_file(path, maximum=MAX_BUNDLE):
    _owned(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 1 <= info.st_size <= maximum, 'candidate_file_invalid')
    with path.open('rb') as stream: raw = stream.read(maximum + 1)
    require(len(raw) == info.st_size and len(raw) <= maximum, 'candidate_file_invalid')
    return raw


def prepare_candidate(run):
    """Caller holds Run lock;012 execute_fixture itself must run before that lock."""
    manifest = run.manifest()
    require(source_identity() == (manifest['source_revision'], False) and manifest['source_dirty'] is False and
        manifest['mode'] == 'container-reference', 'candidate_source_changed')
    report = chunks.report_chunks(run); source = chunks.verified_source(run)
    require(report['result']['status'] == 'passed' and report['plan']['scenario'] == 'healthy', 'candidate_source_unverified')
    folder = run.file('private/candidate'); folder.mkdir(mode=0o700)
    source_bytes = bounded_file(source, chunks.MAX_TOTAL)
    values = {'source.synthetic.bin': source_bytes, 'payload.py': (CONTEXT / 'payload.py').read_bytes(),
        'version.txt': (VERSION + '\n').encode(), 'config.json': canonical(CONFIG)}
    require(1 <= len(values['payload.py']) <= 16384, 'candidate_recipe_invalid')
    files = []
    for name in NAMES:
        atomic_bytes(folder / name, values[name], limit=MAX_BUNDLE)
        files.append({'path': name, 'sha256': sha(values[name]), 'size': len(values[name])})
    value = validate_manifest({**common(manifest), 'operation': 'synthetic-reference-candidate', 'synthetic': True,
        'version': VERSION, 'source_sha256': sha(source_bytes), 'chunk_plan_sha256': report['result']['plan_sha256'],
        'applicability': {'os_id': 'ubuntu', 'os_version': '24.04', 'platform': 'linux/amd64'},
        'chunk_manifest_sha256': report['result']['manifest_sha256'], 'configuration': deepcopy(CONFIG), 'files': files,
        'test_contract_sha256': sha(canonical(test_contract())), 'production_iso_eligible': False})
    atomic_bytes(folder / 'manifest.json', canonical(value), limit=16384)
    atomic_json(run.file('evidence/candidate-manifest.json'), value)
    atomic_json(run.file('evidence/candidate-inputs.json'), input_record(run, value))
    return validate_bundle(run)


def validate_bundle(run):
    value = validate_manifest(read_json(run.file('evidence/candidate-manifest.json')))
    require(bound_common(value, run.manifest()), 'candidate_source_changed')
    inputs_path = run.file('evidence/candidate-inputs.json')
    if inputs_path.exists():
        require(canonical(read_json(inputs_path)) == canonical(input_record(run, value)), 'candidate_inputs_changed')
    folder = run.file('private/candidate'); _owned(folder, directory=True)
    require(set(os.listdir(folder)) == set(NAMES) | {'manifest.json'}, 'candidate_file_set')
    require(bounded_file(folder / 'manifest.json', 16384) == canonical(value), 'candidate_manifest_changed')
    report = chunks.report_chunks(run); source = chunks.verified_source(run)
    require(value['chunk_plan_sha256'] == report['result']['plan_sha256'] and
        value['chunk_manifest_sha256'] == report['result']['manifest_sha256'] and
        value['source_sha256'] == sha(bounded_file(source, chunks.MAX_TOTAL)), 'candidate_source_unverified')
    for item in value['files']:
        raw = bounded_file(folder / item['path'])
        require((len(raw), sha(raw)) == (item['size'], item['sha256']), 'candidate_file_changed')
    require(bounded_file(folder / 'payload.py') == (CONTEXT / 'payload.py').read_bytes() and
        bounded_file(folder / 'version.txt') == (VERSION + '\n').encode() and
        bounded_file(folder / 'config.json') == canonical(CONFIG), 'candidate_recipe_changed')
    return {'manifest': value, 'candidate_sha256': sha(canonical(value)), 'directory': folder}


def binding_labels(run, candidate_sha256, base_labels):
    return {**base_labels, images.LABEL + '.role': 'target', images.LABEL + '.run_id': run.id,
        images.LABEL + '.source_revision': run.manifest()['source_revision'],
        images.LABEL + '.candidate_sha256': candidate_sha256}


def qualified_base_labels():
    # Fixed existing005 provenance, not labels supplied in a candidate receipt.
    from .validation import TARGET_BUILD, TARGET_BUILD_SOURCE
    recipe, files = images.recipe_identity()
    # The exact pinned stock image also inherits this observed Ubuntu OCI label.
    # Extra or changed labels still fail the complete comparison; receipts cannot add them.
    return {'org.opencontainers.image.version': '24.04', images.LABEL + '.role': 'target', images.LABEL + '.run_id': TARGET_BUILD,
        images.LABEL + '.source_revision': TARGET_BUILD_SOURCE, images.LABEL + '.recipe_sha256': recipe,
        images.LABEL + '.lock_sha256': files['images.lock.json']}


def validate_binding(run, value=None, *, artifacts=True):
    saved = read_json(run.file('evidence/candidate-binding.json'))
    try: _bounded_json(saved)
    except (ValueError, TypeError, RecursionError):
        raise CandidateError('candidate_binding_invalid', 'Candidate binding exceeds the fixed data contract.') from None
    if type(saved) is dict and 'reuse' in saved:
        from .candidate_cache import validate_binding as validate_reuse
        require(value is None or canonical(value)==canonical(saved),'candidate_binding_invalid')
        return validate_reuse(run,saved)
    fields = set(common(run.manifest())) | {'operation', 'status', 'candidate_sha256', 'manifest', 'base_image',
        'image_id', 'image_labels', 'installer_sha256', 'test_contract_sha256', 'runtime_pipeline_complete', 'production_iso_eligible'}
    require(type(saved) is dict and set(saved) == fields and bound_common(saved, run.manifest()) and
        saved['operation'] == 'candidate-image-binding' and saved['status'] == 'built' and
        type(saved['image_id']) is str and IMAGE.fullmatch(saved['image_id']) and
        type(saved['base_image']) is str and IMAGE.fullmatch(saved['base_image']) and
        type(saved['image_labels']) is dict and saved['runtime_pipeline_complete'] is False and saved['production_iso_eligible'] is False,
        'candidate_binding_invalid')
    manifest = validate_manifest(saved['manifest'])
    require(bound_common(manifest, run.manifest()) and sha(canonical(manifest)) == saved['candidate_sha256'] and
        saved['test_contract_sha256'] == manifest['test_contract_sha256'] and
        saved['installer_sha256'] == sha((CONTEXT / 'install.py').read_bytes()) and
        saved['image_labels'] == binding_labels(run, saved['candidate_sha256'], qualified_base_labels()) and
        (value is None or type(value) is dict and canonical(value) == canonical(saved)), 'candidate_binding_invalid')
    from .provisioning import TARGET_IMAGE
    require(saved['base_image'] == TARGET_IMAGE and saved['image_id'] != TARGET_IMAGE, 'candidate_binding_invalid')
    built = read_json(run.file('evidence/candidate-build.json'))
    require(bound_common(built, run.manifest()) and built.get('operation') == 'candidate-image-build' and
        built.get('status') == 'built' and built.get('unknown_outcome') is False and
        built.get('image_id') == saved['image_id'] and built.get('candidate_sha256') == saved['candidate_sha256'] and
        type(built.get('builder_id')) is str and IDENTIFIER.fullmatch(built['builder_id']), 'candidate_binding_invalid')
    if artifacts: require(validate_bundle(run)['candidate_sha256'] == saved['candidate_sha256'], 'candidate_binding_invalid')
    return deepcopy(saved)


def verify_image(actual, binding):
    require(actual.get('Id') == binding['image_id'] and actual.get('Parent') == binding['base_image'] and
        actual.get('Os') == 'linux' and actual.get('Architecture') == 'amd64' and
        actual['Config'].get('Labels') == binding['image_labels'] and actual['Config'].get('User') == '0:0' and
        actual['Config'].get('Entrypoint') == ['/usr/bin/python3', '/opt/wormhole/runtime.py', 'target'] and
        actual['Config'].get('Cmd') in ([], None) and not actual['Config'].get('Volumes'), 'candidate_image_mismatch')


def verify_builder(value, run, identifier, labels, limits, mounts, *, stopped=False):
    from .provisioning import TARGET_IMAGE
    host, config = value['HostConfig'], value['Config']; expected = limits['docker_create']
    require(value.get('Id') == identifier and value.get('Image') == TARGET_IMAGE and config.get('Labels') == labels and config.get('User') == '0:0' and
        config.get('Entrypoint') == ['/usr/bin/python3'] and config.get('Cmd') == ['/recipe/install.py'] and
        not any(item.startswith('WORMHOLE_') for item in config.get('Env', [])), 'candidate_builder_identity')
    require(host.get('NetworkMode') == 'none' and host.get('Privileged') is False and host.get('ReadonlyRootfs') is False and
        host.get('Memory') == expected['memory_bytes'] and host.get('MemorySwap') == expected['memory_swap_bytes'] and
        host.get('NanoCpus') == expected['nano_cpus'] and host.get('PidsLimit') == expected['pids_limit'] and
        host.get('LogConfig') == {'Type': expected['log_driver'], 'Config': expected['log_opts']} and
        images.capability_names(host.get('CapDrop')) == {'ALL'} and not host.get('CapAdd') and
        host.get('PidMode', '') == '' and host.get('IpcMode') in ('', 'private') and host.get('UTSMode', '') == '' and
        not host.get('PortBindings') and not host.get('PublishAllPorts') and host.get('RestartPolicy', {}).get('Name') == 'no' and
        set(host.get('SecurityOpt') or []) in ({'no-new-privileges:true'}, {'no-new-privileges=true'}, {'no-new-privileges'}), 'candidate_builder_limits')
    binds = value.get('Mounts', [])
    require(len(binds) == len(mounts) and all(item['Type'] == 'bind' and item['RW'] is False and
        mounts.get(item['Destination']) == item['Source'] for item in binds) and not host.get('Tmpfs'), 'candidate_builder_mounts')
    if stopped: require(value['State']['Status'] == 'created' and value['State']['Running'] is False and
        value['State']['StartedAt'] == '0001-01-01T00:00:00Z', 'candidate_builder_started')


def installed_record(container):
    response = images.docker(('cp', container + ':/opt/wormhole/candidate-installed.json', '-'))
    require(not response['log_truncated'], 'candidate_install_invalid')
    with tarfile.open(fileobj=io.BytesIO(response['log']), mode='r:*') as archive:
        members = archive.getmembers()
        require(len(members) == 1 and members[0].name == 'candidate-installed.json' and members[0].isfile() and
            members[0].size <= 16384, 'candidate_install_invalid')
        return json.loads(archive.extractfile(members[0]).read(16385))


def build_candidate(run, lease, bundle=None):
    """Existing caller lease stays held through image reconciliation and later TF."""
    from .provisioning import TARGET_IMAGE
    lease._active(); revision, dirty = source_identity(); manifest = run.manifest()
    require(os.name == 'posix' and run.workspace == images.RUNS_ROOT and revision == manifest['source_revision'] and
        dirty is False and manifest['source_dirty'] is False and manifest['profile'] == 'smoke' and
        lease.run_id == run.id and lease.source_revision == revision and lease.plan['synthetic'] is False and
        not lease._reconciliation_only and lease.plan['profile'] == 'smoke', 'candidate_scope')
    actual_bundle = validate_bundle(run)
    require(bundle is None or bundle == actual_bundle, 'candidate_bundle_mismatch')
    bundle = actual_bundle; candidate_sha = bundle['candidate_sha256']
    installer_sha = sha((CONTEXT / 'install.py').read_bytes())
    def check_source():
        require(source_identity() == (revision, False) and sha((CONTEXT / 'install.py').read_bytes()) == installer_sha and
            validate_bundle(run)['candidate_sha256'] == candidate_sha, 'candidate_source_changed')
    path = run.file('evidence/candidate-build.json'); require(not path.exists(), 'candidate_attempt_reused')
    receipt = {**common(manifest), 'operation': 'candidate-image-build', 'status': 'pending', 'candidate_sha256': candidate_sha,
        'builder_id': None, 'image_id': None, 'unknown_outcome': False, 'primary_failure': None,
        'daemon_materialization_cgroup_capped': False, 'runtime_pipeline_complete': False, 'production_iso_eligible': False}
    def save(): receipt['updated_at'] = now(); atomic_json(path, receipt)
    def intent(): receipt['unknown_outcome'] = True; save()
    save(); container = None; labels = None; mounts = None
    try:
        base = images.inspect('image', TARGET_IMAGE)
        require(base['Id'] == TARGET_IMAGE and base.get('Os') == 'linux' and base.get('Architecture') == 'amd64' and
            not base['Config'].get('Volumes') and base['Config'].get('Labels') == qualified_base_labels(), 'candidate_base_invalid')
        bundle = validate_bundle(run); limits = lease.plan['limits']['build']; lease.set_phase('assembling')
        labels = {**base['Config'].get('Labels', {}), images.LABEL + '.run_id': run.id,
            images.LABEL + '.source_revision': revision, images.LABEL + '.role': 'candidate-builder', images.LABEL + '.candidate_sha256': candidate_sha}
        mounts = {'/candidate-input': str(images.safe_bind(bundle['directory'])), '/recipe/install.py': str(images.safe_bind(CONTEXT / 'install.py'))}
        args = ['create', '--name', 'wormhole-' + run.id + '-candidate-build', '--network', 'none', '--user', '0:0',
            '--entrypoint', '/usr/bin/python3', *images.limits_arguments(limits)]
        for key, value in labels.items(): args.extend(('--label', key + '=' + value))
        for destination, source in mounts.items(): args.extend(('--mount', 'type=bind,source=' + source + ',target=' + destination + ',readonly'))
        args.extend((TARGET_IMAGE, '/recipe/install.py')); check_source(); intent()
        result = images.docker(tuple(args)); container = result['log'].decode('ascii').strip()
        require(not result['log_truncated'] and IDENTIFIER.fullmatch(container), 'candidate_create_unknown')
        lease.register_resource('container', container); receipt['builder_id'] = container; receipt['unknown_outcome'] = False; save()
        verify_builder(images.inspect('container', container), run, container, labels, limits, mounts, stopped=True)
        intent(); images.docker(('start', container)); receipt['unknown_outcome'] = False; save()
        deadline = time.monotonic() + min(60, limits['timeout_seconds']); observed = None
        while True:
            require(time.monotonic() < deadline, 'candidate_build_timeout')
            current = images.inspect('container', container); verify_builder(current, run, container, labels, limits, mounts)
            if current['State']['Running']:
                if observed is None: observed = images.cgroup_limits(current['State']['Pid'], limits['docker_create'])
            else: break
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
        logs = images.docker(('logs', '--tail', '1000', container)); atomic_bytes(run.file('private/candidate-build.log'), logs['log'], limit=65536)
        require(current['State']['Status'] == 'exited' and current['State']['ExitCode'] == 0 and observed is not None, 'candidate_install_failed')
        require(installed_record(container) == {'status': 'installed', 'candidate_sha256': candidate_sha, 'files': bundle['manifest']['files']}, 'candidate_install_invalid')
        sized = images.inspect('container', container, size=True)
        storage = Path(images.docker(('info', '--format', '{{.DockerRootDir}}'))['log'].decode().strip())
        require(storage.is_absolute() and storage.is_dir(), 'candidate_storage_unverified')
        check_source(); images.assembly_storage_guard(lease.plan, storage, sized); lease.set_phase('materializing')
        tag = 'jake-wormhole-candidate:run-' + run.id
        require(images.inspect('image', tag, missing=True) is None, 'candidate_tag_exists')
        final_labels = binding_labels(run, candidate_sha, base['Config'].get('Labels', {}))
        changes = ['USER 0:0', 'WORKDIR /home/wormhole', 'ENTRYPOINT ["/usr/bin/python3","/opt/wormhole/runtime.py","target"]', 'CMD []']
        changes += ['LABEL ' + key + '=' + value for key, value in final_labels.items()]
        command = ['commit', '--no-pause']
        for change in changes: command.extend(('--change', change))
        command.extend((container, tag)); intent()
        result = images.docker(tuple(command), timeout=lease.plan['materialization']['client_timeout_seconds'])
        require(not result['log_truncated'], 'candidate_commit_unknown'); image = images.inspect('image', tag)
        binding = {**common(manifest), 'operation': 'candidate-image-binding', 'status': 'built', 'candidate_sha256': candidate_sha,
            'manifest': bundle['manifest'], 'base_image': TARGET_IMAGE, 'image_id': image['Id'], 'image_labels': final_labels,
            'installer_sha256': installer_sha, 'test_contract_sha256': bundle['manifest']['test_contract_sha256'],
            'runtime_pipeline_complete': False, 'production_iso_eligible': False}
        verify_image(image, binding); lease.register_resource('image', image['Id'])
        lease.reconcile_resource('image', image['Id'], outcome='retained', size_bytes=image['Size'])
        receipt.update(image_id=image['Id'], unknown_outcome=False, builder_cgroups=observed,
            sampled_writable_layer_bytes=sized['SizeRw']); save()
        verify_builder(images.inspect('container', container), run, container, labels, limits, mounts)
        intent(); images.docker(('rm', container)); require(images.inspect('container', container, missing=True) is None, 'candidate_cleanup_unknown')
        lease.reconcile_resource('container', container); receipt.update(status='built', unknown_outcome=False); save()
        check_source(); atomic_json(run.file('evidence/candidate-binding.json'), binding)
        return validate_binding(run)
    except BaseException as error:
        receipt['status'] = 'failed'; receipt['primary_failure'] = {'code': getattr(error, 'code', 'candidate_build_failed'), 'recorded_at': now()}; save()
        # Known builder failures can be stopped exactly; uncertain create/commit work remains untouched.
        if container is not None and not receipt['unknown_outcome']:
            try:
                current = images.inspect('container', container, missing=True)
                if current is None:
                    require(any(item['kind'] == 'container' and item['id'] == container and item['outcome'] == 'absent'
                        for item in lease.record['resources']), 'candidate_cleanup_unknown')
                else:
                    verify_builder(current, run, container, labels, limits, mounts)
                    if current['State']['Running']:
                        intent(); images.docker(('stop', '--time', '2', container)); receipt['unknown_outcome'] = False; save()
                    verify_builder(images.inspect('container', container), run, container, labels, limits, mounts)
                    intent(); images.docker(('rm', container)); require(images.inspect('container', container, missing=True) is None, 'candidate_cleanup_unknown')
                    lease.reconcile_resource('container', container); receipt['unknown_outcome'] = False; save()
            except Exception:
                receipt['unknown_outcome'] = True; save()
        raise
