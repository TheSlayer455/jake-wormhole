"""Disposable local fixtures only: no Docker, Terraform or host operations."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from wormhole import provisioning as p, provisioning_acceptance as a
from wormhole.runs import atomic_bytes, create_run, read_json

SHA, TARGET, NETWORK, CONTROLLER, SENTINEL = 'a' * 40, 'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64


class AcceptancePolicy(unittest.TestCase):
    def session(self):
        session = p.ProvisioningSession.__new__(p.ProvisioningSession)
        session.run = SimpleNamespace(id='12345678-1234-4234-9234-123456789abc')
        session.provisioner = CONTROLLER
        session.owned = {'docker_container.target': TARGET, 'docker_network.run': NETWORK}
        session.receipt = {'operations': [], 'unknown_outcome': False, 'primary_failure': None, 'secondary_failures': []}
        session.held = lambda: None  # Synthetic held-lease fixture; no Docker or Terraform execution.
        session.save = lambda: None
        def operation(name):
            self.assertEqual(name, 'show-state', 'The actual destroy guard must reject before any destructive plan.')
            session.receipt['operations'].append({'operation': name})
            return {'values': {'root_module': {'resources': [
                {'address': key, 'mode': 'managed', 'provider_name': p.PROVIDER, 'values': {'id': value}}
                for key, value in (('docker_container.target', TARGET), ('docker_network.run', NETWORK))]}}}
        session.operation = operation
        return session

    def test_actual_destroy_guard_refuses_wrong_expected_id_before_plan_and_restores_only_memory(self):
        session = self.session()
        original = deepcopy(session.owned)
        with patch.object(a, 'snapshot', side_effect=lambda kind, identifier, **_: kind + identifier):
            result = a.ownership_negative(session, SENTINEL)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(session.owned, original)
        self.assertEqual(session.receipt['primary_failure']['code'], 'ownership_mismatch')
        self.assertEqual(session.receipt['status'], 'failed')
        self.assertFalse(session.receipt['unknown_outcome'])
        self.assertFalse(result['terraform_state_modified'])
        self.assertEqual([x['operation'] for x in session.receipt['operations']], ['show-state'])

    def test_negative_rejects_sentinel_change_or_unexpected_delete_attempt_and_still_restores_memory(self):
        session = self.session()
        values = ['target', 'network', 'sentinel', 'target', 'network', 'changed']
        with patch.object(a, 'snapshot', side_effect=values), self.assertRaises(a.AcceptanceError) as error:
            a.ownership_negative(session, SENTINEL)
        self.assertEqual(error.exception.code, 'ownership_negative_changed_resources')
        self.assertEqual(session.owned['docker_container.target'], TARGET)
        session = self.session()
        def unsafe():
            session.receipt['operations'].append({'operation': 'destroy-plan'})
            session.receipt['primary_failure'] = {'code': 'ownership_mismatch'}
            raise p.ProvisioningError('ownership_mismatch', 'Synthetic late failure')
        session.destroy = unsafe
        with patch.object(a, 'snapshot', return_value='stable'), self.assertRaises(a.AcceptanceError) as error:
            a.ownership_negative(session, SENTINEL)
        self.assertEqual(error.exception.code, 'destructive_operation_ran')
        self.assertEqual(session.owned['docker_container.target'], TARGET)

    def test_snapshot_ignores_env_health_stats_but_detects_identity_state_and_rejects_owned_sentinel(self):
        value = {'Id': SENTINEL, 'Name': '/synthetic-existing', 'Image': 'sha256:' + 'f' * 64,
                 'Config': {'Env': ['SYNTHETIC_SECRET=not-a-real-secret'], 'Labels': {}},
                 'State': {'Status': 'running', 'Running': True, 'Health': {'Status': 'starting'}}, 'RestartCount': 0}
        with patch.object(a.images, 'inspect', return_value=value):
            before = a.snapshot('container', SENTINEL, unrelated=True)
            value['Config']['Env'] = ['changed-not-part-of-snapshot']
            value['State']['Health'] = {'Status': 'healthy'}
            self.assertEqual(before, a.snapshot('container', SENTINEL, unrelated=True))
            value['State']['Running'] = False
            self.assertNotEqual(before, a.snapshot('container', SENTINEL, unrelated=True))
            value['Config']['Labels'] = {a.images.LABEL + '.run_id': 'another-run'}
            with self.assertRaises(a.AcceptanceError): a.snapshot('container', SENTINEL, unrelated=True)

    def test_isolation_allows_same_endpoint_reuse_but_requires_disjoint_identity_state_names_and_ids(self):
        def identity(n):
            return {'source_revision': SHA, 'run_id': str(n), 'state_path': '/synthetic/' + str(n),
                'public_input': '/synthetic/public/' + str(n), 'target_name': 'target-' + str(n),
                'network_name': 'network-' + str(n), 'provisioner_id': str(n) * 64,
                'resources': {'target': str(n + 2) * 64, 'network': str(n + 4) * 64},
                'inventory': {'run_id': str(n), 'targets': [{'resource_id': str(n + 2) * 64, 'host': '172.31.77.2'}]}}
        first, second = identity(1), identity(2)
        self.assertEqual(a.isolation(first, second)['status'], 'pass')
        for key in ('state_path', 'public_input', 'target_name', 'network_name', 'provisioner_id'):
            changed = deepcopy(second); changed[key] = first[key]
            with self.subTest(key=key), self.assertRaises(a.AcceptanceError): a.isolation(first, changed)
        changed = deepcopy(second); changed['resources']['target'] = first['resources']['target']
        with self.assertRaises(a.AcceptanceError): a.isolation(first, changed)


@unittest.skipUnless(os.name == 'posix', 'Private file permissions require POSIX')
class PrivateEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wormhole-acceptance-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.run = create_run(Path(self.temp.name) / 'runs', fixture=False, identity=(SHA, False))
        self.secret = b'-----BEGIN ' + b'OPENSSH PRIVATE KEY-----\n' + b'A' * 70 + b'\n-----END OPENSSH PRIVATE KEY-----\n'
        atomic_bytes(self.run.file('private/credentials/id_ed25519'), self.secret)
        self.run.file('private/target-input').mkdir(mode=0o700)
        key = self.run.file('private/target-input/authorized_keys')
        atomic_bytes(key, b'ssh-ed25519 ' + b'B' * 64 + b' synthetic\n'); key.chmod(0o644)
        key.parent.chmod(0o755)
        self.output = self.run.file('private/terraform/terraform.tfstate')
        atomic_bytes(self.output, b'{"synthetic":"no credentials"}')

    def test_streaming_scan_and_samples_do_not_export_secret_or_walk_provider_cache(self):
        result = a.scan_private_material(self.run)
        self.assertEqual(result['status'], 'pass')
        self.assertFalse(result['secret_contents_exported'])
        data = self.run.file('private/terraform/.terraform'); data.mkdir(mode=0o700)
        (data / 'provider-synthetic-link').symlink_to('/no-such-path')
        self.assertEqual(a.scan_private_material(self.run)['status'], 'pass')
        sample = a.disk_sample(self.run, 'synthetic-sample')
        self.assertEqual(sample['unfollowed_links'], 1)
        self.assertFalse(sample['hard_quota'])
        self.assertGreater(sample['logical_file_bytes'], 0)
        self.assertNotIn(self.secret.decode(), json.dumps(result))

    def test_cross_chunk_key_body_private_path_and_public_key_content_are_rejected_without_match_export(self):
        public = self.run.file('private/target-input/authorized_keys').read_bytes().strip()
        needles = [b'A' * 70, str(self.run.file('private/credentials/id_ed25519')).encode(), public,
                   b'-----BEGIN ' + b'EC PRIVATE KEY-----']
        for needle in needles:
            with self.subTest(pattern_bytes=len(needle)):
                atomic_bytes(self.output, b'x' * (a.CHUNK - 20) + needle + b'x')
                with self.assertRaises(a.AcceptanceError) as error: a.scan_private_material(self.run)
                self.assertEqual(error.exception.code, 'credential_material_exposed')
                self.assertNotIn(needle.decode(), str(error.exception))

    def test_scan_limits_symlink_and_oversized_file_fail_closed(self):
        self.output.unlink(); self.output.symlink_to('/no-such-secret')
        with self.assertRaises(a.AcceptanceError): a.scan_private_material(self.run)
        self.output.unlink(); atomic_bytes(self.output, b'x' * 100)
        with patch.object(a, 'MAX_SCAN_FILE', 99), self.assertRaises(a.AcceptanceError): a.scan_private_material(self.run)

    def test_negative_persists_restored_real_ids_and_primary_error_without_changing_state_bytes(self):
        session = AcceptancePolicy.session(self)
        session.run, session.state = self.run, self.run.file('private/terraform')
        session.uid, session.gid, session.socket_groups = os.getuid(), os.getgid(), []
        session.mounts, session.image_labels, session.inputs = {}, {}, {}
        session.variables, session.scenario = {'source_revision': SHA}, 'healthy'
        del session.save  # Exercise the normal core failure/save and finally-save, not a receipt substitute.
        before = hashlib.sha256(self.output.read_bytes()).hexdigest()
        with patch.object(a, 'snapshot', side_effect=lambda kind, identifier, **_: kind + identifier):
            a.ownership_negative(session, SENTINEL)
        record = read_json(self.run.file('evidence/provisioning.json'))
        self.assertEqual({x['address']: x['id'] for x in record['resources']},
            {'docker_container.target': TARGET, 'docker_network.run': NETWORK})
        self.assertEqual(record['primary_failure']['code'], 'ownership_mismatch')
        self.assertEqual(record['status'], 'failed')
        self.assertEqual(hashlib.sha256(self.output.read_bytes()).hexdigest(), before)

    def test_pre_init_failure_is_preserved_no_destroy_or_lease_finish_is_claimed(self):
        session = SimpleNamespace()
        session.provision = unittest.mock.Mock(side_effect=p.ProvisioningError('terraform_failed', 'Synthetic init failure'))
        session.destroy = unittest.mock.Mock(side_effect=AssertionError('No invented cleanup'))
        lease = SimpleNamespace(finish=unittest.mock.Mock())
        @contextmanager
        def admission(*_): yield lease
        with patch.object(a, 'create_run', return_value=self.run), patch.object(a, 'execute_run'), \
             patch.object(a.images, 'create_auth'), patch.object(a.images, 'docker_scope', return_value=admission()), \
             patch.object(a, 'AdmissionLease', side_effect=admission), patch.object(a, 'snapshot', return_value='stable'), \
             patch.object(a, 'ProvisioningSession', return_value=session):
            with self.assertRaises(p.ProvisioningError) as error: a._case('healthy', SENTINEL)
        self.assertEqual(error.exception.run_id, self.run.id)
        session.destroy.assert_not_called(); lease.finish.assert_not_called()
        result = read_json(self.run.file('evidence/provisioning-acceptance.json'))
        self.assertEqual(result['status'], 'fail')
        self.assertFalse(result['cleanup_claimed'])
        self.assertEqual(result['error']['code'], 'terraform_failed')

    def provider_fixture(self, proof_change=None):
        receipt = {'primary_failure': {'code': 'terraform_failed'}, 'unknown_outcome': True,
                   'status': 'failed', 'operations': [], 'cleanup': 'not-started'}
        session = SimpleNamespace(owned={}, receipt=receipt, inputs={'main.tf': 'f' * 64})
        session.provision = unittest.mock.Mock(side_effect=p.ProvisioningError('terraform_failed', 'Synthetic missing endpoint'))
        def prove():
            receipt['unknown_outcome'] = False
            value = {'scenario': 'provider-unavailable', 'status': 'proved-zero-contact',
                'endpoint': 'unix:///run/wormhole/provider-unavailable.sock', 'before_and_after_enoent': True,
                'actual_saved_apply_failed': True, 'terraform_state_empty': True,
                'run_resources': [{'kind': 'container', 'count': 1}, {'kind': 'network', 'count': 0}],
                'source_sha256': 'f' * 64, 'recorded_at': '2026-10-23T16:00:00.000Z'}
            if proof_change: proof_change(value)
            return value
        session.prove_provider_unavailable = unittest.mock.Mock(side_effect=prove)
        def destroy():
            self.assertFalse(receipt['unknown_outcome'])
            receipt['cleanup'] = 'completed'
            return deepcopy(receipt)
        session.destroy = unittest.mock.Mock(side_effect=destroy)
        return session

    def run_provider_fixture(self, session):
        lease = SimpleNamespace(finish=unittest.mock.Mock())
        @contextmanager
        def admission(*_): yield lease
        with patch.object(a, 'create_run', return_value=self.run), patch.object(a, 'execute_run'), \
             patch.object(a.images, 'create_auth'), patch.object(a.images, 'docker_scope', return_value=admission()), \
             patch.object(a, 'AdmissionLease', side_effect=admission), patch.object(a, 'snapshot', return_value='stable'), \
             patch.object(a, 'ProvisioningSession', return_value=session):
            result = a._case('provider-unavailable', SENTINEL)
        return result, lease

    def test_provider_expected_failure_requires_proof_before_normal_cleanup_and_retains_failed_operation(self):
        session = self.provider_fixture()
        (result, identity), lease = self.run_provider_fixture(session)
        self.assertEqual(result['status'], 'pass')
        self.assertIsNone(identity)
        self.assertEqual(result['checks']['cleanup']['underlying_operation_status'], 'failed')
        self.assertEqual(result['checks']['cleanup']['primary_error'], 'terraform_failed')
        session.prove_provider_unavailable.assert_called_once()
        session.destroy.assert_called_once()
        lease.finish.assert_called_once_with(reconciliation_complete=True)

    def test_provider_wrong_source_or_missing_enoent_proof_never_authorizes_cleanup(self):
        for change in (lambda x: x.update(source_sha256='1' * 64), lambda x: x.update(before_and_after_enoent=False)):
            session = self.provider_fixture(change)
            with self.assertRaises(a.AcceptanceError) as error: self.run_provider_fixture(session)
            self.assertEqual(error.exception.code, 'provider_failure_unproven')
            session.destroy.assert_not_called()


if __name__ == '__main__': unittest.main()
