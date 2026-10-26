"""Twenty-target mixed-readiness fixtures, explicitly not an actual scale run."""
import unittest
from unittest.mock import patch

from wormhole import fleet_validation as v, readiness as r
import test_fleet_helper as helper_fixtures


class TwentyTargetAdmission(unittest.TestCase):
    def test_one_unready_target_blocks_whole_catalog_but_retains_all_two_hundred_rows(self):
        fixture = helper_fixtures.FleetHelper('test_one_helper_five_independent_ready_records_and_fifty_batch_rows')
        fixture.fixture_profile = 'twenty-targets'
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        fixture.failures['target-020'] = 'ssh_key_rejected'
        fixture.session.start_helper()
        with patch.object(r, '_run_process', side_effect=fixture.probe), self.assertRaises(r.ReadinessError):
            fixture.session.wait_ready()
        validation = v.BatchValidationSession(fixture.session)
        with patch.object(v, '_run_process') as execute, self.assertRaises(v.v.ValidationError):
            validation.validate()
        execute.assert_not_called()
        report = v.report_batch_validation(fixture.run)
        self.assertEqual(len(report['result']['checks']), 200)
        self.assertEqual(len(report['result']['blocked_targets']), 20)
        self.assertEqual(report['result']['attempted_targets'], [])
        self.assertEqual(report['progress']['summary']['targets_ansible_ready'], 19)
        self.assertEqual(report['progress']['summary']['tests_blocked'], 200)
        self.assertEqual(report['result']['primary_failure']['code'], 'ssh_key_rejected')


if __name__ == '__main__': unittest.main()
