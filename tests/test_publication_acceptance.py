"""Real local filesystem proof-reader fixtures; not publication runtime proof."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from wormhole import publication_acceptance as acceptance
from wormhole.runs import RunError


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux private publication proof reader')
class PublicationProofReaders(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='wormhole-publication-proof-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def write(self, name, raw=b'exact'):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def test_original_reader_rejects_a_hard_link_instead_of_crediting_its_hash(self):
        path = self.write('original')
        os.link(path, self.root / 'alias')
        with self.assertRaises(RunError):
            acceptance.file_bytes(path)

    def test_release_reader_rejects_world_readable_files_and_oversized_records(self):
        path = self.write('record', b'123456789')
        path.chmod(0o644)
        with self.assertRaises(RunError):
            acceptance.release_files(self.root)
        path.chmod(0o600)
        with patch.object(acceptance, 'MAX_BYTES', 8), self.assertRaises(RunError):
            acceptance.release_files(self.root)

    def test_only_marker_names_can_retain_two_links_at_the_crash_window(self):
        pending = self.write('.COMPLETE.pending')
        os.link(pending, self.root / 'COMPLETE.json')
        table = acceptance.release_files(self.root)
        self.assertEqual(table['COMPLETE.json'], table['.COMPLETE.pending'])
        self.assertEqual(table['COMPLETE.json']['links'], 2)
        ordinary = self.write('record')
        os.link(ordinary, self.root / 'alias')
        with self.assertRaises(RunError):
            acceptance.release_files(self.root)

    def test_symlinks_are_refused_without_reading_the_target(self):
        target = self.write('ordinary')
        (self.root / 'alias').symlink_to(target)
        with self.assertRaises(RunError):
            acceptance.release_files(self.root)


if __name__ == '__main__':
    unittest.main()
