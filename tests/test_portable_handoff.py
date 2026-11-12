"""Focused portable-document hygiene; synthetic values are never credentials."""
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('repository_hygiene', ROOT / 'scripts/verify_repository.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
NAME = 'handoff/WORMHOLE-SANITIZED-REFERENCE.md'
PRIMARY = 'handoff/LIGHTSPEED-CROSS-REFERENCE.md'
REPO = 'https://github.com/TheSlayer455/jake-wormhole'
REVISION = 'a' * 40


class PortableHandoff(unittest.TestCase):
    def test_primary_brief_is_self_contained_and_source_pinned(self):
        document = (ROOT / PRIMARY).read_text()
        for revision in (
            '21fb946831a451a93c970346855e2c2aec781fb0',
            '31093e4c556081f4654af9e8d28b65255b33fe98',
            '59fb4392e187efa08509abc6492bfe800564680e',
        ):
            self.assertIn(revision, document)
        for heading in (
            '## Embedded Wormhole implementation capsule',
            '## Native outcomes and unresolved qualification',
            '## Terra\'s required comparison and response',
            '## Portable-sharing checklist',
        ):
            self.assertIn(heading, document)
        lowered = document.lower()
        for phrase in ('follow-up paste', 'ask the owner for one relevant excerpt',
                       'request the next excerpt'):
            self.assertNotIn(phrase, lowered)
        local_links = re.findall(r'\[[^]]+\]\((?!https://github\.com/TheSlayer455/jake-wormhole)[^)]+\)', document)
        self.assertEqual(local_links, [])
        source_references = set(re.findall(r'`((?:tests|wormhole)/[A-Za-z0-9_./-]+\.py)`', document))
        self.assertTrue(source_references)
        for reference in source_references:
            self.assertTrue((ROOT / reference).is_file(), reference)

    def test_primary_brief_contains_required_terra_contract(self):
        document = (ROOT / PRIMARY).read_text()
        required = (
            '## Current owner directive for Lightspeed',
            '## Verify one change before running the pipeline',
            '## Current case: the missing console marker',
            '## Time budget and failure behavior',
            '## Live GitLab output is required',
            '### Candidate, installation and readiness contracts',
            '### Complete results and cascading-failure containment',
            '### Intake, recovery, cleanup and storage',
            '### Assessment and SVD',
            '### Exact current RHEL qualification blockers',
            '### Exact current Ubuntu qualification blockers',
            '### Current cleanup and retained-storage state',
            '### I. Next executable chat step',
            '### J. Sanitized external update',
        )
        for value in required:
            self.assertIn(value, document)
        self.assertIn('20 minutes total', document)
        self.assertIn('primary failure', document)
        self.assertIn('blocked', document)
        self.assertEqual(CHECK.portable_errors(PRIMARY, document), [])

    def test_generic_facts_and_public_pinned_references_are_allowed(self):
        document = '\n'.join([
            '# Ubuntu 22.04 and RHEL 10',
            'The ansible control node verifies final authentication and reports 40/40.',
            'No passwords, certificates or private keys are included.',
            '[local reference](WORMHOLE-SANITIZED-REFERENCE.md)',
            REPO,
            f'[implementation]({REPO}/blob/{REVISION}/wormhole/ubuntu_runtime.py#L20-L35)',
            f'{REPO}/commit/{REVISION}',
            f'{REPO}/pull/46',
            f'{REPO}/actions/runs/41257949098',
        ])
        self.assertEqual(CHECK.portable_errors(NAME, document), [])
        self.assertEqual(CHECK.PORTABLE, {
            'handoff/LIGHTSPEED-CROSS-REFERENCE.md', NAME,
        })
        self.assertTrue(CHECK.PORTABLE <= CHECK.REQUIRED)

    def test_network_and_unpinned_reference_refusals_do_not_echo_values(self):
        fixtures = [
            ('192.0.2.35', 'literal address'),
            ('2001:db8::35', 'literal address'),
            ('::1', 'literal address'),
            ('node.internal', 'internal name'),
            ('gitlab.example.org', 'internal name'),
            ('operator@example.invalid', 'internal name'),
            ('https://gitlab.example.invalid/project', 'nonallowlisted or unpinned URL'),
            ('//gitlab.example.invalid/project', 'nonallowlisted or unpinned URL'),
            (REPO + '/blob/main/README.md', 'nonallowlisted or unpinned URL'),
            (REPO + '/blob/' + REVISION + '/README.md?token=not-a-credential',
             'nonallowlisted or unpinned URL'),
        ]
        for value, category in fixtures:
            with self.subTest(category=category):
                errors = CHECK.portable_errors(NAME, 'Safe heading\n' + value)
                self.assertIn(f'Portable handoff {NAME}:2: {category}', errors)
                self.assertNotIn(value, '\n'.join(errors))

    def test_secret_configuration_key_material_and_private_paths_are_refused(self):
        fixtures = [
            ('password: not-a-credential', 'credential assignment'),
            ('ansible_password: not-a-credential', 'credential assignment'),
            ('ansible_become_password: not-a-credential', 'credential assignment'),
            ('UBUNTU_PRO_TOKEN=not-a-credential', 'credential assignment'),
            ('"api_key" = "not-a-credential"', 'credential assignment'),
            ('ansible_host: hidden-node', 'internal name'),
            ('-----BEGIN ' + 'PRIVATE KEY-----', 'private material'),
            ('-----BEGIN ' + 'CERTIFICATE-----', 'private material'),
            ('SHA256:' + 'A' * 43, 'private material'),
            ('ssh-ed25519 ' + 'AAAA' + 'A' * 40, 'private material'),
            ('C:\\Users\\fictional\\private.txt', 'private path'),
            ('/home/fictional/private.txt', 'private path'),
            ('/srv/example/private.json', 'private path'),
            ('\\\\example\\private\\secret.txt', 'private path'),
        ]
        for value, category in fixtures:
            with self.subTest(category=category):
                errors = CHECK.portable_errors(NAME, value)
                self.assertIn(f'Portable handoff {NAME}:1: {category}', errors)
                self.assertNotIn(value, '\n'.join(errors))


if __name__ == '__main__':
    unittest.main()
