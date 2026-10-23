"""Synthetic fleet policy/lifecycle fixtures. Every Docker/Terraform call mocked."""
from copy import deepcopy
import os
import unittest
from unittest.mock import patch

import test_provisioning as base
from wormhole import provisioning as p, images
from wormhole.targets import TargetPlan
from wormhole.runs import RunError, read_json, atomic_json


class FleetPlanPolicy(unittest.TestCase):
    def test_exact_indexed_graph_create_refresh_destroy(self):
        for profile in ('smoke', 'five-targets', 'twenty-targets'):
            layout = TargetPlan(profile)
            variables = base.inputs(); variables['target_ids'] = list(layout.target_ids)
            owned = {'docker_network.run': base.NET, **{layout.address_for(identifier): base.CID if n == 1 else format(n, '064x')
                for n, identifier in enumerate(layout.target_ids, 1)}}
            for operation in ('create', 'refresh', 'destroy'):
                with self.subTest(profile=profile, operation=operation):
                    p.validate_plan(base.plan(variables, operation), variables, operation=operation,
                        owned=owned if operation != 'create' else None, target_plan=layout)

    def test_omission_extra_target_substituted_identity_and_unsafe_target_are_rejected(self):
        layout = TargetPlan('five-targets'); variables = base.inputs(); variables['target_ids'] = list(layout.target_ids)
        for mutate in (
            lambda x: x['resource_changes'].pop(),
            lambda x: x['resource_changes'].append(deepcopy(x['resource_changes'][-1])),
            lambda x: x['resource_changes'][-1].update(address='docker_container.target["target-006"]'),
            lambda x: x['resource_changes'][-1].update(type='docker_image'),
            lambda x: x['planned_values']['root_module']['resources'][-1].update(index='target-002'),
            lambda x: x['planned_values']['root_module']['resources'][-1]['values'].update(privileged=True),
            lambda x: x['resource_changes'][-1]['change']['after_unknown'].update(command=True),
            lambda x: x['variables']['target_ids'].update(value=['target-001']),
        ):
            value = base.plan(variables); mutate(value)
            with self.assertRaises(p.ProvisioningError): p.validate_plan(value, variables, target_plan=layout)

    def test_fixed_terraform_parallelism_is_independent_of_ansible(self):
        from provisioning.runtime import OPERATIONS
        for name in ('plan', 'apply', 'refresh-plan', 'refresh-apply', 'destroy-plan', 'destroy'):
            self.assertIn('-parallelism=1', OPERATIONS[name])


@unittest.skipUnless(os.name == 'posix', 'Linux owned-state fleet fixtures; all Docker/Terraform calls mocked')
class FleetLifecycle(unittest.TestCase):
    fixture_profile = 'five-targets'

    def setUp(self):
        base.Controller.setUp(self)
        self.identities = {identifier: base.CID if n == 1 else format(n, '064x')
            for n, identifier in enumerate(self.session.target_plan.target_ids, 1)}
        self.running.update({identifier: False for identifier in self.identities.values()})
        self.pid_limits = {identifier: None for identifier in self.identities.values()}

    def container(self, identifier):
        if identifier == base.CONTROLLER: return base.Controller.container(self, identifier)
        target_id = next(key for key, value in self.identities.items() if value == identifier)
        original = self.session.labels
        with patch.object(self.session, 'labels', side_effect=lambda role, selected=None: original(role, target_id if role == 'target' else selected)):
            value = base.Controller.container(self, identifier)
        value['Name'] = '/wormhole-' + self.run.id + '-' + target_id
        value['HostConfig']['PidsLimit'] = self.pid_limits[identifier]
        endpoint = value['NetworkSettings']['Networks']['wormhole-' + self.run.id + '-network']
        endpoint['IPAddress'] = '172.31.77.' + str(list(self.identities).index(target_id) + 2) if self.running[identifier] else ''
        return value

    def inspect(self, kind, identifier, **options):
        return base.Controller.inspect(self, kind, identifier, **options)

    def docker(self, arguments, **options):
        if arguments[0] == 'update': self.pid_limits[arguments[-1]] = int(arguments[2])
        return base.Controller.docker(self, arguments, **options)

    def operation(self, name):
        if name == 'output':
            self.calls.append(('operation', name))
            network = 'wormhole-' + self.run.id + '-network'
            return {'run': {'sensitive': False, 'value': {'network_id': base.NET, 'network_name': network,
                'targets': {target_id: {'resource_id': identifier, 'image': p.TARGET_IMAGE, 'network_data': [
                    {'network_name': network, 'ip_address': self.container(identifier)['NetworkSettings']['Networks'][network]['IPAddress']}]}
                    for target_id, identifier in self.identities.items()}}}}
        if name == 'destroy': self.removed.update(self.identities.values())
        return base.Controller.operation(self, name)

    def patches(self): return base.Controller.patches(self)

    def test_all_targets_capped_before_first_start_and_exact_five_inventory_destroy(self):
        with self.patches():
            self.session.create_stopped()
            self.assertEqual(self.session.target_resources, self.identities)
            self.assertEqual(len(self.session.owned), 6)
            self.assertIsNone(self.session.target_inventory('target-005'))
            self.assertFalse(any(self.running[x] for x in self.identities.values()))
            inventory = self.session.start_and_inventory()
            self.assertEqual(inventory['status'], 'pass')
            self.assertEqual([x['target_id'] for x in inventory['targets']], list(self.identities))
            result = self.session.destroy()
        first_start = min(i for i, call in enumerate(self.calls) if call[:2] == ('docker', 'start') and call[-1] in self.identities.values())
        for identifier in self.identities.values():
            update = self.calls.index(('docker', 'update', '--pids-limit', '64', identifier))
            self.assertLess(update, first_start)
            self.assertIn(('inspect', 'container', identifier), self.calls[update+1:first_start])
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(len(result['resources']), 6)
        self.assertFalse(any(call[:2] == ('docker', 'rm') and call[-1] in self.identities.values() for call in self.calls))
        self.assertTrue(all(x['outcome'] == 'absent' for x in self.lease.record['resources']))

    def test_four_then_one_start_has_no_fabricated_pending_ip_and_no_repeat(self):
        with self.patches():
            self.session.create_stopped()
            inventory = self.session.start_and_inventory(list(self.identities)[:4])
            self.assertEqual(inventory['status'], 'unverified'); self.assertEqual(len(inventory['targets']), 4)
            self.assertEqual(self.session.receipt['pending_target_ids'], ['target-005'])
            self.assertIsNone(self.session.target_inventory('target-005'))
            inventory = self.session.start_and_inventory(['target-005'])
            self.assertEqual(inventory['status'], 'pass'); self.assertEqual(len(inventory['targets']), 5)
            with self.assertRaises(p.ProvisioningError): self.session.start_targets(['target-005'])
        self.assertEqual(self.calls.count(('docker', 'start', self.identities['target-005'])), 1)

    def test_ambiguous_verification_and_bad_start_identity_never_start(self):
        with self.patches():
            self.session.create_stopped()
            with self.assertRaises(Exception): self.session.verify_target(self.container(base.CID), stopped=True)
            for values in ([], ['target-006'], ['target-001', 'target-001'], '../target-001'):
                with self.assertRaises(p.ProvisioningError): self.session.start_targets(values)
        self.assertFalse(any(call[:2] == ('docker', 'start') and call[-1] in self.identities.values() for call in self.calls))

    def test_lost_pid_update_remains_unknown_and_blocks_every_start_and_destroy(self):
        original = self.docker
        def incomplete(arguments, **options):
            if arguments[0] == 'update': raise p.ProvisioningError('synthetic_lost_response', 'Synthetic Docker fixture')
            return original(arguments, **options)
        with self.patches(), patch.object(images, 'docker', side_effect=incomplete):
            with self.assertRaises(p.ProvisioningError): self.session.create_stopped()
            self.assertTrue(self.session.receipt['unknown_outcome'])
            with self.assertRaises(p.ProvisioningError): self.session.destroy()
        self.assertFalse(any(call[:2] == ('docker', 'start') and call[-1] in self.identities.values() for call in self.calls))
        self.assertFalse(any(call[:2] == ('operation', 'destroy-plan') for call in self.calls))

    def test_recovery_role_projection_keeps_all_five_historical_targets(self):
        from wormhole.recovery import _resources
        with self.patches(): self.session.create_stopped()
        rows = _resources(self.session, self.lease)
        self.assertEqual(sum(row['role'] == 'terraform-target' for row in rows), 5)
        self.assertEqual(sum(row['role'] == 'terraform-network' for row in rows), 1)
        self.assertEqual(sum(row['role'] == 'provisioner' for row in rows), 1)

    def test_retained_five_target_recovery_uses_exact_layout_and_terraform_destroy(self):
        with self.patches(): self.session.provision()
        (self.session.state / 'operations').mkdir(mode=0o700)
        self.lease._reconciliation_only = True
        original = deepcopy(self.session.owned)
        with self.patches():
            retained = p.ProvisioningSession.resume_destroy(self.run, self.lease)
            self.assertEqual(retained.target_plan, TargetPlan('five-targets'))
            self.assertEqual(retained.owned, original)
            with patch.object(retained, 'operation', side_effect=self.operation): result = retained.destroy()
        self.assertEqual(result['cleanup'], 'completed')
        self.assertEqual(retained.owned, original)
        self.assertEqual(len(result['resources']), 6)
        self.assertFalse(any(call[:2] == ('docker', 'rm') and call[-1] in self.identities.values() for call in self.calls))

    def test_changed_controller_layout_cannot_start_retained_recovery(self):
        with self.patches(): self.session.provision()
        context = self.session.state / 'controller.json'
        record = read_json(context); record['target_plan']['target_ids'].reverse(); atomic_json(context, record)
        self.lease._reconciliation_only = True
        with self.patches(), patch.object(images, 'inspect') as inspect:
            with self.assertRaises(RunError): p.ProvisioningSession.resume_destroy(self.run, self.lease)
        inspect.assert_not_called()

    def test_duplicate_observed_ids_refuse_before_register_or_inspect(self):
        value = base.plan(self.session.variables, 'refresh')['prior_state']
        value['values']['root_module']['resources'][-1]['values']['id'] = base.CID
        with patch.object(images, 'inspect') as inspect:
            with self.assertRaises(p.ProvisioningError): self.session.record_state(value, complete=True)
        inspect.assert_not_called()
        self.assertEqual(self.lease.record['resources'], [])

    def test_twenty_target_plan_does_not_authorize_runtime_allocation(self):
        from wormhole.admission import build_plan
        from test_admission import observed
        self.lease.plan = build_plan('twenty-targets', observed()); self.lease.plan['synthetic'] = False
        with patch.object(images, 'docker') as docker:
            with self.assertRaises(p.ProvisioningError): p.ProvisioningSession(self.run, self.lease)
        docker.assert_not_called()


if __name__ == '__main__': unittest.main()
