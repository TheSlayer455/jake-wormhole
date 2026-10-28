"""Private, manifest-bound transient cleanup under the shared infrastructure lock.

No resource destruction, age-based eviction, Docker pruning or release deletion.
Unknown paths remain protected. Physical accounting uses allocated filesystem blocks.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import xml.etree.ElementTree as ET

from .admission import CANONICAL_INFRASTRUCTURE_ROOT
from .media_store import file_lock
from .runs import RunError, atomic_json, now, read_json, run_id, workspace_path
from .vm_inputs import sha256

GIB = 1024**3
ARTIFACT_BUDGET = 100 * GIB
CANDIDATE_BUDGET = 32 * GIB
ROOT = CANONICAL_INFRASTRUCTURE_ROOT.parent
SHARED = ROOT.parent.parent / 'jake-wormhole-vm'


def require(condition, code='storage_proof_incomplete'):
    if not condition:
        raise RunError(code, 'Storage proof is incomplete; preserve the affected artifacts.')


def signature(path):
    info = path.lstat()
    return [info.st_dev, info.st_ino, info.st_size, info.st_blocks * 512,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink, info.st_mode]


def filesystem(path):
    value = os.statvfs(path)
    used = (value.f_blocks - value.f_bfree) * value.f_frsize
    available = value.f_bavail * value.f_frsize
    return {'used_bytes': used, 'available_bytes': available,
            'usage_percent': round(100 * used / (used + available), 3),
            'warning':used*5 >= (used+available)*4}


def admission(path, required_bytes, *, managed_bytes=0, candidate_bytes=0):
    """Project peak: sources already present + extraction/remaster + disk + evidence."""
    require(type(required_bytes) is int and required_bytes >= 0)
    value = filesystem(path)
    value.update(required_bytes=required_bytes, warning=value['usage_percent'] >= 80,
                 projected_usage_percent=round(100 * (value['used_bytes'] + required_bytes) /
                     (value['used_bytes'] + value['available_bytes']), 3))
    require(required_bytes <= value['available_bytes'] and
            (value['used_bytes'] + required_bytes) * 10 <=
            (value['used_bytes'] + value['available_bytes']) * 9, 'storage_projected_critical')
    require(managed_bytes <= ARTIFACT_BUDGET and candidate_bytes <= CANDIDATE_BUDGET,
            'storage_retention_budget')
    return value


class Store:
    def __init__(self, root=ROOT, shared=SHARED):
        self.root, self.shared = Path(root), Path(shared)
        self.infrastructure = self.root / 'infrastructure'
        self.runs = self.root / 'vm-runs'
        cache=self.infrastructure/'storage-hashes.json'
        self.hashes=read_json(cache) if cache.exists() else {}
        self.descriptor=None

    def digest(self, path):
        """Reuse only owner-private hash receipts with identical inode metadata.

        Changes to bytes, links, ownership, mode or timestamps invalidate the
        receipt. Normal candidate reuse still runs the builder's integrity check.
        """
        key=str(path);info=signature(path)
        cached=self.hashes.get(key)
        if cached and cached['signature']==info:return cached['sha256']
        value=sha256(path)
        require(signature(path)==info,'storage_file_changed_during_hash')
        self.hashes[key]={'signature':info,'sha256':value}
        return value

    @contextmanager
    def locked(self):
        workspace_path(self.infrastructure)
        require(read_json(self.infrastructure / 'owner.json') == {
            'application': 'jake-wormhole', 'schema_version': '1.0', 'kind': 'shared-infrastructure-root'})
        with file_lock(self.infrastructure / 'infrastructure.lock') as descriptor:
            self.descriptor=descriptor
            try:yield
            finally:self.descriptor=None

    def check_lock(self, lease):
        if lease is not None:
            from .vm_admission import VMLease
            from .admission import AdmissionLease
            require(isinstance(lease,(VMLease,AdmissionLease)) and lease.root==self.infrastructure,
                    'storage_lock_required')
            require(getattr(lease,'pid',getattr(lease,'_lease_pid',None))==os.getpid(),'storage_lock_required')
            descriptor=lease.descriptor
        else:descriptor=self.descriptor
        require(descriptor is not None,'storage_lock_required')
        held=os.fstat(descriptor);actual=(self.infrastructure/'infrastructure.lock').lstat()
        require(stat.S_ISREG(actual.st_mode) and (held.st_dev,held.st_ino)==(actual.st_dev,actual.st_ino),
                'storage_lock_changed')

    def status(self):
        totals = {key: 0 for key in ('candidates', 'temporary_builds', 'vm_disks',
                  'retained_evidence', 'qualified_releases', 'protected_other')}
        seen = set()
        # Fixed project roots only. Do not follow links or cross filesystem mounts.
        for base in (self.root.parent, self.shared):
            if not base.exists():
                continue
            device = base.stat().st_dev
            for directory, folders, files in os.walk(base, followlinks=False):
                folders[:] = [n for n in folders if not (Path(directory)/n).is_symlink()
                              and (Path(directory)/n).stat().st_dev == device]
                for name in [*files, '.']:
                    path = Path(directory) if name == '.' else Path(directory)/name
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) in seen:
                        continue
                    seen.add((info.st_dev, info.st_ino))
                    parts = path.relative_to(base).parts
                    if any(n in {'releases','ubuntu-releases','iso-lab-releases'} for n in parts):
                        category = 'qualified_releases'
                    elif base == self.shared:
                        category = 'candidates' if path.name == 'candidate.iso' else 'vm_disks' if 'disk' in parts else 'temporary_builds'
                    elif 'vm-runs' in parts and any(n in {'repository','boot','wormhole-identity','seed-layout-check'} for n in parts):
                        category = 'temporary_builds'
                    elif any(n in {'vm-runs','runs','scanner-builds','iso-preflight'} for n in parts):
                        category = 'retained_evidence'
                    else:
                        category = 'protected_other'
                    totals[category] += info.st_blocks * 512
        return {'schema_version':'1.0', 'allocated_bytes':totals,
                'total_allocated_bytes':sum(totals.values()), 'filesystem':filesystem(self.root),
                'artifact_budget_bytes':ARTIFACT_BUDGET, 'candidate_budget_bytes':CANDIDATE_BUDGET,
                'over_artifact_budget':sum(totals.values()) > ARTIFACT_BUDGET,
                'accounting':'unique (device,inode) allocated blocks; Docker shared layers excluded'}

    def observe(self, *, lease=None):
        """Read all domain/pool/mount references, not only running project names."""
        from .vm_admission import validate_record
        from .admission import _journal
        for filename, history, validate in [('admission.json','history',_journal),
                                          ('vm-admission.json','vm-history',validate_record)]:
            path = self.infrastructure / filename
            if not path.exists() and filename == 'vm-admission.json':
                continue
            record = validate(read_json(path))
            if record['state'] != 'finished':
                # Only the actual in-process VM lease may clean BEFORE allocation.
                require(lease is not None and lease.pid == os.getpid() and lease.lock is not None and
                        record == lease.record and not record['resources'], 'storage_active_run')
                lease._check()
            else:
                require(read_json(self.infrastructure/history/(record['run_id']+'.json')) == record)
        def call(args):
            return subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=15).decode()
        references = []
        self.live = {}
        for kind, query in [('domain','list'),('network','net-list'),('pool','pool-list')]:
            self.live[kind]=set(call(['virsh','-c','qemu:///system',query,'--all','--name']).split())
        self.live['network_filter']={line.split()[-1] for line in
            call(['virsh','-c','qemu:///system','nwfilter-list']).splitlines() if line.split()}
        self.live['controller_container']=self.live['support_container']=set(
            call(['docker','ps','-a','--format','{{.Names}}']).split())
        for domain in self.live['domain']:
            xml = ET.fromstring(call(['virsh','-c','qemu:///system','dumpxml',domain]))
            for source in xml.findall('.//disk//source'):
                references.extend(source.get(k) for k in ('file','dev') if source.get(k))
        for pool in self.live['pool']:
            xml = ET.fromstring(call(['virsh','-c','qemu:///system','pool-dumpxml',pool]))
            target = xml.findtext('target/path')
            if target: references.append(target)
        containers = call(['docker','ps','-aq']).split()
        self.live['container']=set(containers)
        for identifier in containers:
            mounts = json.loads(call(['docker','inspect','--format','{{json .Mounts}}',identifier]))
            references.extend(m['Source'] for m in mounts if m.get('Source'))
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            references.append(re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),line.split()[4]))
        # Tools operating outside their coordinator also prevent cleanup.
        for directory in Path('/proc').iterdir():
            if not directory.name.isdigit() or int(directory.name) == os.getpid(): continue
            try:
                argv = (directory/'cmdline').read_bytes().split(b'\0')
                executable = Path(os.fsdecode(argv[0])).name if argv else ''
                if executable in {'terraform','xorriso','oscap','qemu-img','qemu-system-x86_64'}:
                    relevant = any(str(root).encode() in b' '.join(argv) for root in (self.root,self.shared))
                    cwd=os.readlink(directory/'cwd')
                    relevant=relevant or any(cwd.startswith(str(root)+'/') for root in (self.root,self.shared))
                    require(not relevant, 'storage_active_tool')
                for fd in (directory/'fd').iterdir():
                    try: target = os.readlink(fd)
                    except FileNotFoundError: continue
                    if any(target.startswith(str(root)+'/') for root in (self.shared,self.runs)):
                        references.append(target.removesuffix(' (deleted)'))
            except (FileNotFoundError, ProcessLookupError): continue
        return references

    def checked(self, path, references):
        """Reject symlink ancestors, hardlinks, mounts, unexpected owners and open inputs."""
        path = Path(path)
        require(path.is_relative_to(self.root) or path.is_relative_to(self.shared), 'storage_outside_scope')
        base = self.root if path.is_relative_to(self.root) else self.shared
        for parent in [*reversed(path.parents),path]:
            if parent == base or parent.is_relative_to(base):
                info = parent.lstat()
                require(not stat.S_ISLNK(info.st_mode), 'storage_unsafe_link')
                require(info.st_uid in {0, self.qemu_uid()}, 'storage_owner_mismatch')
                require(not info.st_mode & 0o022, 'storage_unsafe_permissions')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'storage_unsafe_file')
        for value in references:
            ref = Path(value)
            require(not (path == ref or ref.is_relative_to(path)), 'storage_referenced')
            # Mounts/pools protect subtrees, but ordinary ancestor mounts such as / do not.
            require(not (ref.is_relative_to(base) and path.is_relative_to(ref)), 'storage_referenced')
        return signature(path)

    @staticmethod
    def qemu_uid():
        import pwd
        return pwd.getpwnam('libvirt-qemu').pw_uid

    def proof(self, identifier, references, *, current=None):
        from .vm_admission import validate_record
        run = self.runs / run_id(identifier)
        value = read_json(run/'result.json')
        journal = validate_record(read_json(self.infrastructure/'vm-history'/(identifier+'.json')))
        require(journal['state']=='finished' and value['run_id']==identifier and
                journal['source_revision']==value['source_revision'])
        require(value['outcome']!='running' and (value.get('finished_at') or
                value.get('recovery',{}).get('state')=='stopped-and-cleaned'), 'storage_unfinished_evidence')
        for key in ('supervisor','active_command'):
            process=value.get(key)
            if process and not (identifier==current and process['pid']==os.getpid()):
                from .vm_baseline import process_identity
                require(process_identity(process['pid'])!=process, 'storage_active_supervisor')
        for item in journal['resources']:
            if item['kind']=='disk': require(not Path(item['identity']).exists(), 'storage_disk_unreconciled')
            elif item['kind'] not in {'installer_iso','seed_iso'}:
                require(item['identity'] not in self.live.get(item['kind'],set()), 'storage_resource_present')
        manifest = read_json(run/'inputs/build-manifest.json')
        require(value.get('build')==manifest, 'storage_manifest_mismatch')
        require(re.fullmatch('[a-f0-9]{64}',manifest['candidate_sha256']) is not None)
        # The journal binds this exact ISO, not a guessed directory name.
        candidate = self.shared/identifier/'candidate.iso'
        require(any(x['kind']=='installer_iso' and x['identity']==str(candidate) for x in journal['resources']))
        return run, value, manifest

    def preview(self, references, *, current=None):
        groups, actions, blocked, pinned = {}, [], [], set()
        for run in sorted(self.runs.iterdir() if self.runs.exists() else []):
            if not run.is_dir(): continue
            try:
                _, result, manifest = self.proof(run.name,references,current=current)
                candidate = self.shared/run.name/'candidate.iso'
                if candidate.exists():
                    self.checked(candidate,references)
                    require(self.digest(candidate)==manifest['candidate_sha256'], 'storage_candidate_changed')
                    groups.setdefault(manifest['candidate_sha256'],[]).append((run,manifest,candidate))
                else:
                    # A missing unaccounted candidate cannot authorize staging removal.
                    self.resolve(run.name)
            except (RunError,OSError,KeyError,ValueError) as error:
                # Only new builds have an intent written BEFORE construction.
                # Legacy unknown partial files stay protected for manual recovery.
                try:
                    partial=self.partial(run,references,current=current)
                    actions.extend(partial)
                    if partial: continue
                except (RunError,OSError,KeyError,ValueError): pass
                blocked.append({'run_id':run.name,'reason':getattr(error,'code',type(error).__name__)})
                try:
                    digest=read_json(run/'result.json').get('build',{}).get('candidate_sha256')
                    if digest:pinned.add(digest)
                except (RunError,OSError):pass
                continue
            payload=run/'inputs/payload'
            if (payload/'manifest.json').exists():
                try:
                    require(sha256(payload/'manifest.json')==manifest['dependency_manifest_sha256'])
                    files=read_json(payload/'manifest.json')['files']
                    for entry in files:
                        relative=Path(entry['path'])
                        require(not relative.is_absolute() and '..' not in relative.parts)
                        if not (relative.parts[0]=='repository' or str(relative)=='openscap-lab.tar.gz'): continue
                        path=payload/relative
                        if path.exists():
                            info=self.checked(path,references)
                            require(path.stat().st_size==entry['bytes'] and self.digest(path)==entry['sha256'], 'storage_staging_changed')
                            actions.append({'path':str(path),'signature':info,'reason':'verified-installation-staging','run_id':run.name})
                    # Extracted boot files are diagnostic inputs, not the report,
                    # native assessment, SVD or installation contract. Record their
                    # identities before unlinking the fixed builder outputs.
                    for name in ('grub.cfg','loopback.cfg','md5sum.txt','reused-grub.cfg','reused-loopback.cfg'):
                        path=run/'inputs/boot'/name
                        if path.exists():
                            actions.append({'path':str(path),'signature':self.checked(path,references),
                                'sha256':sha256(path),'reason':'verified-boot-extraction','run_id':run.name})
                except (RunError,OSError,KeyError,ValueError) as error:
                    # Fail the whole run's proposed staging cleanup on any mismatch.
                    actions=[a for a in actions if a['run_id']!=run.name]
                    pinned.add(manifest['candidate_sha256'])
                    blocked.append({'run_id':run.name,'reason':getattr(error,'code',type(error).__name__)})
                    continue
            seed=self.shared/run.name/'seed.iso'
            seed_receipt=run/'storage-seed.json'
            if seed.exists() or seed_receipt.exists():
                try:
                    if seed.exists():
                        info=self.checked(seed,references)
                        require(sha256(seed)==manifest['seed_sha256'],'storage_seed_changed')
                        actions.append({'path':str(seed),'signature':info,'reason':'verified-detached-seed',
                                        'sha256':manifest['seed_sha256'],'run_id':run.name})
                    else:require(read_json(seed_receipt)['sha256']==manifest['seed_sha256'])
                    if result['outcome']!='unknown':
                        # Logical unlink is not a physical-erasure claim on SSD/CoW.
                        # No guest disk remains; these ephemeral credentials no
                        # longer provide a recovery path. Keep nonsecret contracts.
                        for name in ('ssh-key','ssh-key.pub','sudo-password','boot-password','unlock-secret'):
                            path=run/name
                            if path.exists():actions.append({'path':str(path),'signature':self.checked(path,references),
                                'reason':'expired-private-credential','run_id':run.name})
                        for folder in ('wormhole-identity','seed-layout-check'):
                            directory=run/'inputs'/folder
                            if directory.exists():
                                require(not directory.is_symlink(),'storage_unsafe_link')
                                allowed={'public-key','password','run-id','boot-password-hash',
                                         'sandbox-ca.crt','sandbox-ca.crl','sandbox-active.crt','sandbox-revoked.crt'}
                                require(all(p.name in allowed for p in directory.iterdir()))
                                for path in directory.iterdir():actions.append({'path':str(path),
                                    'signature':self.checked(path,references),'reason':'expired-private-seed-staging','run_id':run.name})
                except RunError as error:
                    pinned.add(manifest['candidate_sha256'])
                    blocked.append({'run_id':run.name,'reason':error.code})
        unique=0
        for digest, members in groups.items():
            canonical=members[0][2]
            invalidated=[self.invalidated(manifest) for _,manifest,_ in members]
            if digest not in pinned and all(invalidated) and not any(m.get('lab_iso_qualified') for _,m,_ in members):
                for (run, manifest, candidate), changed in zip(members,invalidated):
                    actions.append({'path':str(candidate),'signature':signature(candidate),
                        'reason':'obsolete-installed-inputs','run_id':run.name,'sha256':digest,
                        'invalidated_inputs':changed})
                continue
            unique+=signature(canonical)[3]
            for run, manifest, candidate in members[1:]:
                actions.append({'path':str(candidate),'signature':signature(candidate),'reason':'identical-candidate',
                    'run_id':run.name,'canonical_run':canonical.parent.name,'sha256':digest})
        self.scanner_staging(actions,blocked,references)
        reserved=self.status()['allocated_bytes']['candidates']-sum(a['signature'][3] for a in actions
                    if Path(a['path']).name=='candidate.iso')
        return {'actions':actions,'blocked':blocked,'unique_candidate_allocated_bytes':unique,
                'candidate_budget_allocated_bytes':reserved,
                'estimated_reclaim_allocated_bytes':sum(a['signature'][3] for a in actions),
                'cache_budget_exceeded':reserved>CANDIDATE_BUDGET,
                'cache_policy':'32 GiB verified reusable ISO cache; deduplicate identical bytes and evict source-proven stale installed inputs; pin unresolved and qualified runs; preserve evidence; refuse builds if protected retention exceeds budget'}

    def invalidated(self, manifest):
        """Evict by input mismatch, never by timestamps or a guessed filename."""
        from .runs import SOURCE_ROOT, source_identity
        if not manifest.get('installed_inputs',{}).get('files'):return []
        try:_, dirty=source_identity()
        except RunError:return []
        if dirty:return []
        changed=[]
        for name, expected in manifest.get('installed_inputs',{}).get('files',{}).items():
            path=Path(name)
            if path.is_absolute() or '..' in path.parts: return []
            # Virtual inputs (offline snapshot and sandbox contract) are not
            # filesystem paths. Their mismatch alone does not authorize eviction.
            if len(path.parts)<2:continue
            source=SOURCE_ROOT/path
            if source.is_file() and sha256(source)!=expected:changed.append(name)
        return changed

    def scanner_staging(self, actions, blocked, references):
        from .admission import _journal
        directory=self.root/'scanner-builds'
        if not directory.exists():return
        for run in sorted(directory.iterdir()):
            try:
                identifier=run_id(run.name)
                receipt=read_json(run/'result.json')
                journal=_journal(read_json(self.infrastructure/'history'/(identifier+'.json')))
                require(journal['state']=='finished' and journal['source_revision']==receipt['source_revision']
                        and receipt['state'] in {'complete','failed'} and (run/'build.log').is_file())
                require(all(r['kind']!='container' or r['id'] not in self.live.get('container',set()) for r in journal['resources']))
                if receipt['state']=='complete':
                    artifact=run/'work/openscap-lab.tar.gz'
                    self.checked(artifact,references)
                    require(sha256(artifact)==receipt['artifact_sha256'])
                proposed=[]
                for name in ('source','build','stage'):
                    tree=run/'work'/name
                    if not tree.exists():continue
                    require(not tree.is_symlink(),'storage_unsafe_link')
                    for folder, dirs, files in os.walk(tree,followlinks=False):
                        require(not any((Path(folder)/n).is_symlink() for n in dirs),'storage_unsafe_link')
                        for filename in files:
                            path=Path(folder)/filename
                            # CMake installs legitimate library symlinks. Preserve
                            # them rather than following them into any backing data.
                            if path.is_symlink():continue
                            proposed.append({'path':str(path),'signature':self.checked(path,references),
                                             'reason':'reconciled-scanner-build-staging','run_id':identifier})
                actions.extend(proposed)
            except (RunError,OSError,KeyError,ValueError) as error:
                blocked.append({'run_id':run.name,'reason':getattr(error,'code',type(error).__name__)})

    def partial(self, run, references, *, current=None):
        from .vm_admission import validate_record
        from .vm_baseline import process_identity
        value=read_json(run/'result.json')
        require(not value.get('build'))
        intent=read_json(run/'storage-build-intent.json')
        journal=validate_record(read_json(self.infrastructure/'vm-history'/(run_id(run.name)+'.json')))
        candidate=self.shared/run.name/'candidate.iso'
        require(intent=={'schema_version':'1.0','run_id':run.name,'source_revision':value['source_revision'],
                         'candidate':str(candidate),'seed':str(candidate.with_name('seed.iso'))})
        require(journal['state']=='finished' and journal['source_revision']==value['source_revision'] and
                all(r['kind'] in {'installer_iso','seed_iso'} for r in journal['resources']))
        require((value['outcome']=='failed' or value['outcome']=='unknown' and
                 value.get('recovery',{}).get('state')=='stopped-and-cleaned') and value.get('finished_at'))
        for field in ('supervisor','active_command'):
            process=value.get(field)
            require(not process or (run.name==current and process['pid']==os.getpid()) or
                    process_identity(process['pid'])!=process,'storage_active_supervisor')
        require(any(x['kind']=='installer_iso' and x['identity']==str(candidate) for x in journal['resources']))
        actions=[]
        for name in ('candidate.iso','final-candidate.iso','seed.iso'):
            path=candidate.with_name(name)
            if path.exists():actions.append({'path':str(path),'signature':self.checked(path,references),
                'sha256':sha256(path),'reason':'reconciled-incomplete-build','run_id':run.name})
        return actions

    def resolve(self, identifier):
        """Follow bounded durable aliases; every reuse verifies the actual retained bytes."""
        original=read_json(self.runs/run_id(identifier)/'inputs/build-manifest.json')
        digest=original['candidate_sha256'];visited=set()
        while identifier not in visited and len(visited)<64:
            visited.add(identifier)
            candidate=self.shared/run_id(identifier)/'candidate.iso'
            if candidate.exists():
                self.checked(candidate,[])
                require(self.digest(candidate)==digest,'storage_candidate_changed')
                return candidate
            run=self.runs/identifier
            receipt=run/'storage-candidate.json'
            if receipt.exists():
                record=read_json(receipt)
                require(record['sha256']==digest)
                require(record.get('disposition')!='evicted-stale-installed-inputs','stale_candidate')
                identifier=run_id(record['canonical_run'])
            else:
                record=read_json(run/'candidate-retention-disposition.json')
                require(record['state']=='duplicate-removed-equivalent-bytes-retained' and record['candidate_sha256']==digest)
                identifier=run_id(record['identical_copy_retained_in_run'])
        raise RunError('storage_candidate_alias_invalid','Candidate retention alias is cyclic or incomplete.')

    def clean_held(self, *, lease=None, current=None):
        """Caller already holds the SAME admission lock; never a nested flock."""
        self.check_lock(lease)
        references=self.observe(lease=lease)
        plan=self.preview(references,current=current)
        before=self.status()
        # Durable intent before unlink; interruption preserves source proofs and aliases.
        operations=self.infrastructure/'storage-operations'
        workspace_path(operations,create=True)
        from uuid import uuid4
        operation=operations/(str(uuid4())+'.json')
        receipt={'schema_version':'1.0','state':'prepared','at':now(),'actions':plan['actions'],
                 'before':before,'blocked':plan['blocked']}
        # Bounded batches retain durable intent without thousands of fsyncs.
        atomic_json(operation,{**receipt,'actions':len(plan['actions'])})
        reclaimed=0
        for start in range(0,len(plan['actions']),128):
            batch=plan['actions'][start:start+128]
            entry=operations/(operation.stem+'-batch-'+str(start)+'.json')
            atomic_json(entry,{'state':'prepared','actions':batch})
            parents=set()
            for action in batch:
                self.check_lock(lease)
                parents.add(self.unlink(action,references))
                reclaimed+=action['signature'][3]
            for parent in parents:
                fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(fd)
                finally:os.close(fd)
            atomic_json(entry,{'state':'unlinked','actions':batch})
        after=self.status()
        receipt={**receipt,'state':'complete','actions':len(plan['actions']), 'after':after,
                 'unlinked_allocated_bytes':reclaimed,
                 'filesystem_available_delta_bytes':after['filesystem']['available_bytes']-before['filesystem']['available_bytes'],
                 'unique_candidate_allocated_bytes':plan['unique_candidate_allocated_bytes'],
                 'candidate_budget_allocated_bytes':plan['candidate_budget_allocated_bytes'],
                 'cache_budget_exceeded':plan['cache_budget_exceeded']}
        atomic_json(operation,receipt)
        atomic_json(self.infrastructure/'storage-hashes.json',{
            p:v for p,v in self.hashes.items() if Path(p).name=='candidate.iso' and Path(p).exists()})
        return receipt

    def unlink(self, action, references):
        path=Path(action['path'])
        require(self.checked(path,references)==action['signature'],'storage_file_changed')
        if action['reason']=='identical-candidate':
            canonical=self.shared/action['canonical_run']/'candidate.iso'
            self.checked(canonical,references)
            require(canonical!=path and self.digest(canonical)==action['sha256'])
            atomic_json(self.runs/action['run_id']/'storage-candidate.json',{
                'schema_version':'1.0','sha256':action['sha256'],'canonical_run':action['canonical_run'],
                'original_run':action['run_id'],'at':now()})
        if action['reason']=='verified-detached-seed':
            atomic_json(self.runs/action['run_id']/'storage-seed.json',{
                'schema_version':'1.0','sha256':action['sha256'],'at':now(),
                'disposition':'detached after archived teardown and live-reference verification; logical unlink only'})
        if action['reason']=='obsolete-installed-inputs':
            atomic_json(self.runs/action['run_id']/'storage-candidate.json',{
                'schema_version':'1.0','sha256':action['sha256'],'disposition':'evicted-stale-installed-inputs',
                'invalidated_inputs':action['invalidated_inputs'],'at':now()})
        path.unlink()
        return path.parent


def operate(command):
    import sys
    require(sys.platform.startswith('linux'),'linux_required')
    require(os.geteuid()==0,'runtime_owner_required')
    store=Store()
    with store.locked():
        if command=='status': return store.status()
        if command=='preview': return store.preview(store.observe())
        return store.clean_held()


def lifecycle(lease, identifier=None):
    store=Store()
    return store.clean_held(lease=lease,current=identifier)
