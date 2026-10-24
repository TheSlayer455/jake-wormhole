"""Pure layout fixtures; no Docker, Terraform or allocation."""
from dataclasses import FrozenInstanceError
import unittest
from types import SimpleNamespace

from wormhole.targets import TargetPlan, TargetPlanError


class TargetPlans(unittest.TestCase):
    def test_exact_bounded_layouts_and_roundtrip(self):
        for profile, count in [('smoke', 1), ('five-targets', 5), ('twenty-targets', 20)]:
            with self.subTest(profile=profile):
                plan = TargetPlan(profile)
                self.assertEqual(len(plan.target_ids), count)
                self.assertEqual(len(plan.expected_addresses), count + 1)
                self.assertEqual(TargetPlan.from_record(plan.record()), plan)
                for target_id in plan.target_ids:
                    self.assertEqual(plan.id_for_address(plan.address_for(target_id)), target_id)
                record = plan.record(); record['target_ids'].reverse()
                if count > 1:
                    with self.assertRaises(TargetPlanError): TargetPlan.from_record(record)

    def test_missing_target_is_only_resolved_for_one_target(self):
        self.assertEqual(TargetPlan('smoke').resolve(), 'target-001')
        with self.assertRaises(TargetPlanError): TargetPlan('five-targets').resolve()
        for invalid in ['target-000', 'target-006', '../target-001', 'target-001";x', '', 1]:
            with self.subTest(invalid=invalid), self.assertRaises(TargetPlanError):
                TargetPlan('five-targets').address_for(invalid)

    def test_plan_is_immutable_and_record_is_independent(self):
        plan = TargetPlan('five-targets')
        with self.assertRaises(FrozenInstanceError): plan.profile = 'twenty-targets'
        record = plan.record(); record['target_ids'].clear()
        self.assertEqual(len(plan.target_ids), 5)
        for value in [{**plan.record(), 'unknown': True}, {**plan.record(), 'schema_version': '2.0'},
                      {**plan.record(), 'target_count': True}, {**plan.record(), 'target_ids': ['target-001']}, None]:
            with self.assertRaises(TargetPlanError): TargetPlan.from_record(value)

    def test_lease_count_must_match_profile(self):
        called = []
        lease = SimpleNamespace(_active=lambda: called.append(True), plan={'profile': 'five-targets', 'target_count': 5})
        self.assertEqual(TargetPlan.from_lease(lease), TargetPlan('five-targets'))
        self.assertEqual(called, [True])
        lease.plan['target_count'] = 1
        with self.assertRaises(TargetPlanError): TargetPlan.from_lease(lease)


if __name__ == '__main__':
    unittest.main()
