"""Read-only, in-memory ISO manifest negatives; no media or runtime workspace."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

from wormhole import cli, media_store as m
from wormhole.runs import RunError


MANIFEST = 'synthetic-manifest.json'
STORE = '/synthetic-media/store'
OUTPUT = '/synthetic-media/restored.iso'
LIMIT = 1024 * 1024
SOURCE_ROOT = Path(__file__).resolve().parents[1]


def recursive_payload():
    return b'[' * 10000 + b'0' + b']' * 10000


def valid_manifest():
    return {
        'schema_version': '2.0', 'capability': 'iso-source-chunks',
        'source_name': 'synthetic.iso', 'bytes': 65536, 'sha256': 'a' * 64,
        'chunk_bytes': 65536,
        'chunks': [{'index': 0, 'offset': 0, 'bytes': 65536,
                    'sha256': 'b' * 64, 'object': 'objects/' + 'b' * 64 + '.chunk'}],
        'lab_iso_qualified': False, 'production_iso_eligible': False,
    }


def malformed_payloads():
    return (
        ('duplicate-root', b'{"chunks":[],"chunks":[]}', 'media_duplicate_key'),
        ('duplicate-chunk', b'{"chunks":[{"index":0,"index":1}]}', 'media_duplicate_key'),
        ('truncated', b'{"chunks":[', 'media_manifest_invalid'),
        ('invalid-utf8', b'{"source_name":"\xff"}', 'media_manifest_invalid'),
        ('at-byte-limit', b'{}' + b' ' * (LIMIT - 2), 'media_manifest_invalid'),
        ('over-byte-limit', b' ' * (LIMIT + 1), 'media_manifest_bound'),
    )


class MemoryManifest:
    """Only the input file API is virtual; production ownership checks still run."""
    parents = ()

    def __init__(self, raw, *, mode=stat.S_IFREG | 0o600, links=1, symlink=False):
        self.raw, self.mode, self.links, self.symlink = raw, mode, links, symlink
        self.opens = []

    def is_symlink(self):
        return self.symlink

    def is_junction(self):
        return False

    def stat(self):
        return SimpleNamespace(st_mode=self.mode, st_uid=getattr(os, 'getuid', lambda: 0)(),
                               st_nlink=self.links)

    def open(self, mode):
        if mode != 'rb':
            raise AssertionError('The synthetic manifest must never be opened for writing.')
        self.opens.append(mode)
        return io.BytesIO(self.raw)


@contextmanager
def read_only_manifest(raw, **metadata):
    path = MemoryManifest(raw, **metadata)

    def convert(value):
        if value != MANIFEST:
            raise AssertionError('Reconstruction must refuse before touching any output path.')
        return path

    def no_runtime(*args, **kwargs):
        raise AssertionError('A refused manifest must not enter runtime storage or reconstruction.')

    with patch.object(m, 'Path', side_effect=convert) as converted, \
            patch.object(m, 'workspace_path', side_effect=no_runtime) as workspace, \
            patch.object(m, 'locked_store', side_effect=no_runtime) as store, \
            patch.object(m, 'file_lock', side_effect=no_runtime) as lock, \
            patch.object(m, 'atomic_json', side_effect=no_runtime) as checkpoint:
        try:
            yield path
        finally:
            if path.raw != raw:
                raise AssertionError('The original synthetic input changed.')
            if converted.call_args_list != [call(MANIFEST)]:
                raise AssertionError('Only the manifest path may be accessed.')
            for boundary in (workspace, store, lock, checkpoint):
                boundary.assert_not_called()


class MediaManifestValidation(unittest.TestCase):
    def test_deep_json_below_byte_bound_is_a_controlled_refusal(self):
        raw = recursive_payload()
        self.assertLess(len(raw), LIMIT)
        with self.assertRaises(RecursionError):
            json.loads(raw)
        with read_only_manifest(raw) as path, self.assertRaises(RunError) as error:
            m.load(MANIFEST)
        self.assertEqual(error.exception.code, 'media_manifest_invalid')
        self.assertEqual(path.opens, ['rb'])

    def test_parser_boundary_codes_are_preserved(self):
        for name, raw, code in malformed_payloads():
            with self.subTest(name=name):
                with read_only_manifest(raw) as path, self.assertRaises(RunError) as error:
                    m.load(MANIFEST)
                self.assertEqual(error.exception.code, code)
                self.assertEqual(path.opens, ['rb'])

    def test_valid_synthetic_manifest_keeps_both_qualification_flags_false(self):
        value = valid_manifest()
        with read_only_manifest(json.dumps(value).encode()):
            actual = m.load(MANIFEST)
        self.assertEqual(actual, value)
        self.assertIs(actual['lab_iso_qualified'], False)
        self.assertIs(actual['production_iso_eligible'], False)

    def test_closed_schema_and_order_negatives_refuse_before_reconstruction(self):
        missing = object()
        changes = (
            (('extra',), True, 'media_manifest_invalid'),
            (('sha256',), missing, 'media_manifest_invalid'),
            (('bytes',), True, 'media_manifest_invalid'),
            (('chunk_bytes',), True, 'media_manifest_invalid'),
            (('chunks',), [], 'media_chunk_count'),
            (('chunks', 0, 'extra'), True, 'media_chunk_invalid'),
            (('chunks', 0, 'object'), missing, 'media_chunk_invalid'),
            (('chunks', 0, 'index'), True, 'media_chunk_order_or_identity'),
            (('chunks', 0, 'index'), 1, 'media_chunk_order_or_identity'),
            (('chunks', 0, 'offset'), True, 'media_chunk_order_or_identity'),
            (('chunks', 0, 'offset'), 1, 'media_chunk_order_or_identity'),
            (('chunks', 0, 'bytes'), True, 'media_chunk_order_or_identity'),
            (('chunks', 0, 'object'), 'objects/' + 'c' * 64 + '.chunk', 'media_chunk_order_or_identity'),
            (('chunks', 0, 'object'), '../outside.chunk', 'media_chunk_order_or_identity'),
            (('lab_iso_qualified',), True, 'media_scope_invalid'),
            (('production_iso_eligible',), True, 'media_scope_invalid'),
        )
        for fields, changed, code in changes:
            with self.subTest(fields=fields, changed=changed):
                value = deepcopy(valid_manifest())
                node = value
                for field in fields[:-1]:
                    node = node[field]
                if changed is missing:
                    del node[fields[-1]]
                else:
                    node[fields[-1]] = changed
                with read_only_manifest(json.dumps(value).encode()), self.assertRaises(RunError) as error:
                    m.assemble(MANIFEST, STORE, OUTPUT)
                self.assertEqual(error.exception.code, code)

    def test_ownership_guards_remain_active_on_the_memory_file(self):
        cases = [({'symlink': True}, 'unsafe_path'), ({'links': 2}, 'unsafe_path')]
        if os.name == 'posix':
            cases.append(({'mode': stat.S_IFREG | 0o644}, 'unsafe_permissions'))
        for metadata, code in cases:
            with self.subTest(metadata=metadata):
                with read_only_manifest(b'{}', **metadata) as path, self.assertRaises(RunError) as error:
                    m.load(MANIFEST)
                self.assertEqual(error.exception.code, code)
                self.assertEqual(path.opens, [])

    def test_cli_parser_refusals_are_json_without_reconstruction_or_input_writes(self):
        cases = (('recursive', recursive_payload(), 'media_manifest_invalid'), *malformed_payloads())
        for name, raw, code in cases:
            with self.subTest(name=name):
                output, errors = io.StringIO(), io.StringIO()
                with read_only_manifest(raw) as path, redirect_stdout(output), redirect_stderr(errors):
                    status = cli.main(['media-assemble', MANIFEST, '--store', STORE, '--output', OUTPUT])
                self.assertEqual(status, 2)
                self.assertEqual(json.loads(output.getvalue())['error']['code'], code)
                self.assertEqual(errors.getvalue(), '')
                self.assertEqual(path.opens, ['rb'])

    def test_cli_process_returns_two_for_recursive_json_without_traceback(self):
        # The child imports only this source fixture and runs the real CLI entrypoint.
        # Its input and output-boundary sentinels remain entirely in memory.
        code = '''
import runpy
import sys
sys.path.insert(0, 'tests')
from test_media_manifest_validation import (MANIFEST, STORE, OUTPUT,
    read_only_manifest, recursive_payload)
sys.argv = ['wormhole', 'media-assemble', MANIFEST, '--store', STORE, '--output', OUTPUT]
with read_only_manifest(recursive_payload()):
    runpy.run_module('wormhole', run_name='__main__')
'''
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=SOURCE_ROOT,
                                capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['error']['code'], 'media_manifest_invalid')
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
