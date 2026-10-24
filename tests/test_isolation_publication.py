"""Fixed crash-checkpoint identity checks; no actual pipeline credit."""
import os
import unittest

from wormhole.isolation_publication import validate_checkpoint
from wormhole.runs import RunError

RUN = 'ef0d8347-d232-4f99-900c-717d6aac694a'
ATTEMPT = 'ce2849a2-451a-4ad0-b39a-8f9ca435cf65'


def observation():
    return {'event': 'before-complete', 'publisher_pid': os.getpid() + 100,
        'metadata': {'run_id': RUN, 'attempt_id': ATTEMPT, 'release_id': 'reference-' + RUN}}


class PublicationInterruptionIdentity(unittest.TestCase):
    def test_exact_owned_child_observation(self):
        value = observation()
        self.assertEqual(validate_checkpoint(value, RUN), value)

    def test_wrong_window_parent_or_foreign_run_cannot_prove_interruption(self):
        for key, wrong in (('event', 'marker-linked'), ('publisher_pid', True),
                ('publisher_pid', os.getpid()), ('publisher_pid', 1)):
            value = observation(); value[key] = wrong
            with self.subTest(key=key, wrong=wrong), self.assertRaises(RunError):
                validate_checkpoint(value, RUN)
        for key, wrong in (('run_id', ATTEMPT), ('release_id', 'reference-' + ATTEMPT),
                ('attempt_id', 'not-a-uuid')):
            value = observation(); value['metadata'][key] = wrong
            with self.subTest(key=key), self.assertRaises(RunError):
                validate_checkpoint(value, RUN)

    def test_unknown_fields_and_missing_identity_refuse(self):
        for section in ('root', 'metadata'):
            value = observation(); target = value if section == 'root' else value['metadata']
            target['extra'] = 'untrusted'
            with self.subTest(section=section), self.assertRaises(RunError):
                validate_checkpoint(value, RUN)
        value = observation(); del value['metadata']['attempt_id']
        with self.assertRaises(RunError): validate_checkpoint(value, RUN)


if __name__ == '__main__':
    unittest.main()
