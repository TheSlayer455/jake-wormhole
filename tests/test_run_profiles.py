"""Profile metadata never allocates infrastructure or substitutes for admission."""
from pathlib import Path
import tempfile
import unittest

from wormhole.runs import RunError, create_run


class RunProfiles(unittest.TestCase):
    def test_default_and_explicit_profiles_survive_normal_manifest_reads(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-synthetic-profiles-') as folder:
            space = Path(folder) / 'runs'
            for fixture, profile in ((True, None), (False, None), (True, 'fixture'),
                                     (False, 'smoke'), (False, 'five-targets'), (False, 'twenty-targets')):
                run = create_run(space, fixture=fixture, profile=profile, identity=('a' * 40, False))
                manifest = run.manifest()
                self.assertEqual(manifest['profile'], profile or ('fixture' if fixture else 'smoke'))
                self.assertIs(manifest['runtime_pipeline_complete'], False)
                self.assertIs(manifest['production_iso_eligible'], False)
                self.assertEqual(list(run.file('private/terraform').iterdir()), [])

    def test_invalid_mode_profile_pairs_refuse_before_creating_workspace(self):
        with tempfile.TemporaryDirectory(prefix='wormhole-synthetic-profiles-') as folder:
            space = Path(folder) / 'never-created'
            for fixture, profile in ((True, 'smoke'), (False, 'fixture'), (False, 'unbounded'),
                                     (False, True), (False, []), (1, None)):
                with self.assertRaises(RunError):
                    create_run(space, fixture=fixture, profile=profile, identity=('a' * 40, False))
                self.assertFalse(space.exists())
