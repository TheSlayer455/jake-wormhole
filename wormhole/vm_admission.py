"""Separate VM ownership journal, coordinated with the existing Docker lock.

No journal or expired process authorizes cleanup. The libvirt adapter must prove
exact ownership and absence before calling finish. Unknown work remains active.
"""
from copy import deepcopy
import os
import re
from pathlib import Path

from . import admission as docker
from .media_store import file_lock
from .runs import RunError, _owned, now, read_json, run_id, workspace_path

KINDS = {'domain', 'network', 'pool', 'disk', 'installer_iso', 'seed_iso', 'controller_container'}


def require(value, code):
    if not value:
        raise RunError(code, 'VM admission or ownership proof is incomplete; preserve state for reconciliation.')


def validate_record(value):
    require(type(value) is dict and set(value) == {'schema_version', 'backend', 'run_id', 'source_revision',
        'state', 'created_at', 'updated_at', 'resources', 'production_iso_eligible'}, 'invalid_vm_journal')
    require(value['schema_version'] == '1.0' and value['backend'] == 'libvirt-iso' and
            value['state'] in {'active', 'finished'} and value['production_iso_eligible'] is False,
            'invalid_vm_journal')
    run_id(value['run_id'])
    require(type(value['source_revision']) is str and re.fullmatch('[a-f0-9]{40}', value['source_revision']), 'invalid_vm_journal')
    require(all(type(value[k]) is str and len(value[k]) <= 40 for k in ('created_at', 'updated_at')), 'invalid_vm_journal')
    require(type(value['resources']) is list and len(value['resources']) <= 16, 'invalid_vm_journal')
    identities = set()
    for item in value['resources']:
        require(type(item) is dict and set(item) == {'kind', 'identity', 'outcome'}, 'invalid_vm_journal')
        require(item['kind'] in KINDS and item['outcome'] in {'pending', 'absent', 'retained-input'} and
                type(item['identity']) is str and 0 < len(item['identity']) <= 512, 'invalid_vm_journal')
        require((item['kind'], item['identity']) not in identities, 'invalid_vm_journal')
        require(item['outcome'] != 'retained-input' or item['kind'] in {'installer_iso', 'seed_iso'}, 'invalid_vm_journal')
        identities.add((item['kind'], item['identity']))
    require(value['state'] != 'finished' or all(x['outcome'] != 'pending' for x in value['resources']), 'invalid_vm_journal')
    return value


def require_vm_reconciled(root):
    """Called under the shared lock by BOTH backend admission paths."""
    path = Path(root) / 'vm-admission.json'
    if path.exists() or path.is_symlink():
        value = validate_record(read_json(path))
        require(value['state'] == 'finished', 'unreconciled_vm_run')
        archive = Path(root) / 'vm-history' / (value['run_id'] + '.json')
        require(read_json(archive) == value, 'invalid_vm_archive')


class VMLease:
    def __init__(self, root, identifier, revision):
        self.root = Path(root)
        require(self.root == docker.CANONICAL_INFRASTRUCTURE_ROOT, 'noncanonical_root')
        self.id, self.revision = run_id(identifier), revision
        require(type(revision) is str and re.fullmatch('[a-f0-9]{40}', revision), 'invalid_source')
        self.record = None
        self.pid = os.getpid()
        self.lock = None

    def __enter__(self):
        self.root = workspace_path(self.root)
        self.lock = file_lock(self.root / 'infrastructure.lock')
        self.lock.__enter__()
        info = (self.root / 'infrastructure.lock').stat()
        self.lock_identity = info.st_dev, info.st_ino
        try:
            require(read_json(self.root / 'owner.json') == {'application': docker.PROJECT,
                'schema_version': '1.0', 'kind': 'shared-infrastructure-root'}, 'ownership_mismatch')
            previous = docker._journal(read_json(self.root / 'admission.json'))
            require(previous['state'] == 'finished' and read_json(self.root / 'history' /
                    (previous['run_id'] + '.json')) == previous, 'unreconciled_container_run')
            require_vm_reconciled(self.root)
            history = self.root / 'vm-history'
            workspace_path(history, create=True)
            require(not (history / (self.id + '.json')).exists(), 'run_id_reused')
            stamp = now()
            self.record = {'schema_version': '1.0', 'backend': 'libvirt-iso', 'run_id': self.id,
                'source_revision': self.revision, 'state': 'active', 'created_at': stamp, 'updated_at': stamp,
                'resources': [], 'production_iso_eligible': False}
            self._save()
            return self
        except BaseException:
            self.lock.__exit__(None, None, None)
            self.lock = None
            raise

    def _check(self):
        require(self.lock is not None and self.pid == os.getpid() and self.record is not None and
                self.record['state'] == 'active', 'vm_lease_inactive')
        path = self.root / 'infrastructure.lock'
        _owned(path)
        info = path.stat()
        require((info.st_dev, info.st_ino) == self.lock_identity, 'vm_lock_changed')
        require(read_json(self.root / 'vm-admission.json') == self.record, 'vm_journal_changed')

    def _save(self):
        self.record['updated_at'] = now()
        docker._sync_json(self.root / 'vm-admission.json', validate_record(self.record))

    def intent(self, kind, identity):
        self._check()
        self.record['resources'].append({'kind': kind, 'identity': identity, 'outcome': 'pending'})
        self._save()

    def reconciled(self, kind, identity, *, retained_input=False):
        self._check()
        found = [x for x in self.record['resources'] if x['kind'] == kind and x['identity'] == identity]
        require(len(found) == 1 and found[0]['outcome'] == 'pending', 'ownership_mismatch')
        found[0]['outcome'] = 'retained-input' if retained_input else 'absent'
        self._save()

    def finish(self):
        self._check()
        require(all(x['outcome'] != 'pending' for x in self.record['resources']), 'unreconciled_vm_resources')
        completed = deepcopy(self.record)
        completed.update(state='finished', updated_at=now())
        validate_record(completed)
        docker._sync_json(self.root / 'vm-history' / (self.id + '.json'), completed)
        docker._sync_json(self.root / 'vm-admission.json', completed)
        self.record = completed

    def __exit__(self, *args):
        if self.lock is not None:
            self.lock.__exit__(*args)
            self.lock = None
        return False
