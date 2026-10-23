"""Capacity check is evidence only, never a new allocation or ownership proof."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from wormhole import admission as a
from test_admission import observed


@unittest.skipUnless(sys.platform.startswith('linux'), 'Admission fixtures require Linux')
class RetainedDestroyCapacity(unittest.TestCase):
    def test_exact_pending_controller_remeasurement_preserves_plan_and_forbids_new_allocation(self):
        with tempfile.TemporaryDirectory() as folder:
            root, identifier, sha, controller = Path(folder) / 'infrastructure', str(uuid4()), 'a' * 40, 'b' * 64
            with a.AdmissionLease(root, identifier, sha, collector=lambda _: observed(), allow_synthetic=True) as lease:
                lease.set_phase('provisioning'); lease.register_resource('container', controller)
                with self.assertRaises(a.AdmissionError): lease.check_destroy_recovery_capacity(controller)
            resumed = a.AdmissionLease.resume(root, identifier, sha, allow_synthetic=True)
            resumed.collector = lambda _: observed()
            with resumed as lease:
                with self.assertRaises(a.AdmissionError): lease.check_destroy_recovery_capacity(controller)
                lease.set_phase('reconciling')
                previous, original_plan = deepcopy(lease.record), deepcopy(lease.plan)
                result = lease.check_destroy_recovery_capacity(controller)
                self.assertEqual(result['container_id'], controller)
                self.assertEqual(result['limits'], original_plan['limits']['provisioner'])
                self.assertFalse(result['allocation_permitted'])
                self.assertTrue(result['ownership_and_command_proof_required'])
                self.assertEqual(lease.record, previous)
                self.assertEqual(lease.plan, original_plan)
                with self.assertRaises(a.AdmissionError): lease.register_resource('container', 'c' * 64)
                with self.assertRaises(a.AdmissionError): lease.refresh()
                with self.assertRaises(a.AdmissionError): lease.set_phase('provisioning')
                with self.assertRaises(a.AdmissionError): lease.check_destroy_recovery_capacity('c' * 64)
                low = observed(); low['memory_available_bytes'] = 1
                lease.collector = lambda _: low
                with self.assertRaises(a.AdmissionError) as denied: lease.check_destroy_recovery_capacity(controller)
                self.assertEqual(denied.exception.code, 'capacity_refused')
                lease.collector = lambda _: observed()
                changed = deepcopy(original_plan); changed['limits']['provisioner']['timeout_seconds'] += 1
                with patch.object(a, 'build_plan', return_value=changed), self.assertRaises(a.AdmissionError) as denied:
                    lease.check_destroy_recovery_capacity(controller)
                self.assertEqual(denied.exception.code, 'profile_changed')
                self.assertEqual(lease.record, previous)
                lease.reconcile_resource('container', controller)
                with self.assertRaises(a.AdmissionError): lease.check_destroy_recovery_capacity(controller)
                lease.finish(reconciliation_complete=True)


if __name__ == '__main__': unittest.main()
