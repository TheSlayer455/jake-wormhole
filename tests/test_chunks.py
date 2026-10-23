"""Generated private binary/local-loopback fixtures; no Docker or external calls."""
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
import socket
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from wormhole import chunks as c
from wormhole.runs import RunError, atomic_json, create_run, read_json

SHA = 'a' * 40


class SyntheticChunks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='wormhole-chunks-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.identity = patch.object(c, 'source_identity', return_value=(SHA, False))
        self.identity.start(); self.addCleanup(self.identity.stop)

    def run_new(self):
        return create_run(self.workspace, fixture=False, identity=(SHA, False))

    def successful(self, **options):
        run = self.run_new()
        result = c.execute_fixture(run, size=2051, chunk_size=512, **options)
        self.assertEqual(result['status'], 'passed', result)
        return run, result

    def test_streamed_roundtrip_both_transports_order_sizes_and_actual_hashes(self):
        for transport in c.TRANSPORTS:
            with self.subTest(transport=transport):
                run, result = self.successful(transport=transport)
                original = run.file('private/chunks/source.synthetic.bin').read_bytes()
                restored = c.verified_source(run).read_bytes()
                self.assertEqual(original, restored)
                manifest = read_json(run.file('evidence/chunk-manifest.json'))
                self.assertEqual([x['index'] for x in manifest['chunks']], list(range(5)))
                self.assertEqual([x['offset'] for x in manifest['chunks']], [0, 512, 1024, 1536, 2048])
                self.assertEqual(manifest['chunks'][-1]['size'], 3)
                self.assertEqual(manifest['whole_sha256'], hashlib.sha256(original).hexdigest())
                for item in manifest['chunks']:
                    raw = run.file('private/chunks/parts/' + item['name']).read_bytes()
                    self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (item['size'], item['sha256']))
                self.assertEqual(len(result['checked_chunks']), 5)
                self.assertFalse(result['production_iso_eligible']); self.assertFalse(result['runtime_pipeline_complete'])
                self.assertEqual(run.manifest()['stages'], [])
                self.assertEqual(c.report_chunks(run)['result'], result)

    def test_all_listed_corruptions_stop_before_verified_candidate_boundary(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/chunk-cases.json').read_text())
        self.assertEqual(fixture['transports'], list(c.TRANSPORTS))
        self.assertEqual([x['scenario'] for x in fixture['cases']], list(c.SCENARIOS))
        for transport in c.TRANSPORTS:
            for case in fixture['cases'][1:]:
                with self.subTest(transport=transport, scenario=case['scenario']):
                    run = self.run_new()
                    result = c.execute_fixture(run, transport=transport, scenario=case['scenario'])
                    expected = case.get('code', case.get('http_code' if transport == 'http-loopback' else 'local_code'))
                    self.assertEqual((result['status'], result['failure']['code']), ('failed', expected))
                    self.assertIsNone(result['verified_output'])
                    self.assertFalse(run.file('private/chunks/reconstructed.synthetic.bin').exists())
                    self.assertFalse(run.file('private/chunks/.reconstructed.partial').exists())
                    with self.assertRaises(c.ChunkError) as error: c.verified_source(run)
                    self.assertEqual(error.exception.code, 'chunk_not_verified')

    def test_manifest_rejects_unknown_nonfinite_wrong_indices_offsets_names_and_totals(self):
        run, _ = self.successful()
        original = read_json(run.file('evidence/chunk-manifest.json'))
        for mutate in (lambda x: x.update(extra='untrusted'), lambda x: x.update(total_size=True),
            lambda x: x.update(total_size=float('nan')), lambda x: x.update(synthetic=False),
            lambda x: x['chunks'][0].update(index=1), lambda x: x['chunks'][1].update(offset=1),
            lambda x: x['chunks'][0].update(name='../outside'), lambda x: x.update(total_size=x['total_size'] + 1),
            lambda x: x['chunks'].reverse(), lambda x: x['chunks'].append(deepcopy(x['chunks'][0]))):
            value = deepcopy(original); mutate(value)
            with self.assertRaises(c.ChunkError): c.validate_manifest(value)

    def test_repeated_hashes_are_valid_but_manifest_digest_and_whole_hash_bind_bytes(self):
        run, _ = self.successful()
        original = read_json(run.file('evidence/chunk-manifest.json'))
        self.assertEqual(original['chunks'][0]['sha256'], original['chunks'][1]['sha256'])
        for fault in ('manifest', 'whole'):
            with self.subTest(fault=fault):
                manifest = deepcopy(original)
                if fault == 'whole': manifest['whole_sha256'] = 'f' * 64
                expected = 'f' * 64 if fault == 'manifest' else c.sha(c.canonical(manifest))
                run.file('private/chunks/reconstructed.synthetic.bin').unlink(missing_ok=True)
                with self.assertRaises(c.ChunkError) as error:
                    c.reconstruct(run, manifest, expected, c.LocalChunks(run.file('private/chunks/parts')), time.monotonic()+5, [])
                self.assertEqual(error.exception.code, 'chunk_manifest_identity' if fault == 'manifest' else 'chunk_whole_mismatch')
                self.assertFalse(run.file('private/chunks/reconstructed.synthetic.bin').exists())

    def test_extra_files_truncated_and_oversized_content_never_accepted(self):
        for fault in ('extra', 'empty', 'oversize'):
            run, _ = self.successful()
            manifest = read_json(run.file('evidence/chunk-manifest.json'))
            run.file('private/chunks/reconstructed.synthetic.bin').unlink()
            path = run.file('private/chunks/parts/' + manifest['chunks'][0]['name'])
            if fault == 'extra': run.file('private/chunks/parts/chunk-999999.bin').write_bytes(b'X')
            else: path.write_bytes(b'' if fault == 'empty' else b'X' * 513)
            with self.assertRaises(c.ChunkError):
                c.reconstruct(run, manifest, c.sha(c.canonical(manifest)), c.LocalChunks(path.parent), time.monotonic()+5, [])
            self.assertFalse(run.file('private/chunks/reconstructed.synthetic.bin').exists())

    def test_source_dirty_changed_identity_repeat_and_invalid_options_are_refused(self):
        run = self.run_new()
        for value in ((SHA, True), ('b'*40, False)):
            with patch.object(c, 'source_identity', return_value=value), self.assertRaises(c.ChunkError): c.execute_fixture(run)
        c.execute_fixture(run)
        with self.assertRaises(c.ChunkError): c.execute_fixture(run)
        for options in ({'transport': 'https://example.invalid'}, {'scenario': 'repair'}, {'size': 0}, {'size': True},
            {'chunk_size': 0}, {'size': c.MAX_TOTAL, 'chunk_size': 1}, {'timeout': float('nan')}):
            with self.assertRaises(c.ChunkError): c.execute_fixture(self.run_new(), **options)
        with self.assertRaises(c.ChunkError) as error: c.FutureRegistryAdapter('https://example.invalid')
        self.assertEqual(error.exception.code, 'registry_unsupported')

    def test_same_run_competing_operation_and_existing_main_fixture_are_not_repurposed(self):
        run = self.run_new()
        with run.locked(), self.assertRaises(RunError) as error: c.execute_fixture(run)
        self.assertEqual(error.exception.code, 'run_busy')
        self.assertFalse(run.file('private/chunks').exists())
        fixture = create_run(self.workspace, fixture=True, identity=(SHA,False))
        before = fixture.file('manifest.json').read_bytes()
        with self.assertRaises(c.ChunkError): c.execute_fixture(fixture)
        self.assertEqual(fixture.file('manifest.json').read_bytes(), before)
        self.assertFalse(fixture.file('private/chunks').exists())

    def test_deadline_interrupted_write_and_late_source_change_never_promote(self):
        for fault in ('timeout', 'io', 'changed'):
            run = self.run_new()
            if fault == 'timeout':
                context = patch.object(c, 'deadline_check', side_effect=c.ChunkError('chunk_timeout', 'synthetic'))
            elif fault == 'io': context = patch.object(c.LocalChunks, 'open', side_effect=OSError('synthetic'))
            else: context = patch.object(c, 'source_identity', side_effect=[(SHA,False), ('b'*40,False)])
            with context: result = c.execute_fixture(run)
            self.assertEqual(result['status'], 'failed'); self.assertIsNone(result['verified_output'])
            self.assertFalse(run.file('private/chunks/reconstructed.synthetic.bin').exists())
            self.assertFalse(run.file('private/chunks/.reconstructed.partial').exists())

    def test_verified_output_and_saved_manifest_tampering_refuse_report(self):
        for fault in ('bytes', 'manifest', 'receipt', 'unknown', 'missing'):
            run, receipt = self.successful()
            if fault == 'bytes': c.verified_source(run).write_bytes(b'changed')
            elif fault == 'manifest':
                value = read_json(run.file('evidence/chunk-manifest.json')); value['total_size'] += 1
                atomic_json(run.file('evidence/chunk-manifest.json'), value)
            elif fault == 'receipt':
                receipt['checked_chunks'].pop(); atomic_json(run.file('evidence/chunks.json'), receipt)
            else:
                if fault == 'unknown': receipt['unexpected'] = 'refused'
                else: del receipt['checked_chunks']
                atomic_json(run.file('evidence/chunks.json'), receipt)
            with self.assertRaises(c.ChunkError): c.report_chunks(run)

    def test_actual_loopback_redirect_duplicate_length_and_dripping_response_are_bounded_refusals(self):
        for fault in ('redirect', 'duplicate-length', 'drip'):
            with self.subTest(fault=fault):
                run, _ = self.successful()
                manifest = read_json(run.file('evidence/chunk-manifest.json'))
                run.file('private/chunks/reconstructed.synthetic.bin').unlink()
                local = c.LocalChunks(run.file('private/chunks/parts'))
                deadline = time.monotonic() + (.15 if fault == 'drip' else 3)
                class Handler(BaseHTTPRequestHandler):
                    def log_message(self, *_): pass
                    def do_GET(self):
                        if fault == 'redirect':
                            self.send_response(302); self.send_header('Location', 'https://example.invalid/never-contacted'); self.end_headers(); return
                        self.send_response(200); self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Content-Length', str(manifest['chunks'][0]['size']))
                        if fault == 'duplicate-length': self.send_header('content-length', '1')
                        self.end_headers()
                        if fault == 'drip':
                            self.wfile.write(b'X'); self.wfile.flush(); time.sleep(.25)
                began = time.monotonic()
                with c.LoopbackFixture(local, [x['name'] for x in manifest['chunks']], deadline) as adapter:
                    adapter.server.RequestHandlerClass = Handler
                    with self.assertRaises(c.ChunkError):
                        c.reconstruct(run, manifest, c.sha(c.canonical(manifest)), adapter, deadline, [])
                self.assertLess(time.monotonic() - began, 2)
                self.assertFalse(run.file('private/chunks/reconstructed.synthetic.bin').exists())
                self.assertFalse(run.file('private/chunks/.reconstructed.partial').exists())

    def test_midstream_http_shutdown_and_failed_record_do_not_expose_partial_candidate(self):
        run = self.run_new()
        with patch.object(c.LoopbackFixture, 'open', side_effect=c.ChunkError('chunk_http_transport', 'synthetic interruption')):
            result = c.execute_fixture(run, transport='http-loopback')
        self.assertEqual(result['failure']['code'], 'chunk_http_transport')
        self.assertEqual(c.report_chunks(run)['result']['status'], 'failed')
        self.assertFalse(run.file('private/chunks/.reconstructed.partial').exists())
        self.assertFalse(run.file('private/chunks/reconstructed.synthetic.bin').exists())

    def test_incomplete_incoming_headers_cannot_hold_server_shutdown_open(self):
        run, _ = self.successful()
        manifest = read_json(run.file('evidence/chunk-manifest.json'))
        local = c.LocalChunks(run.file('private/chunks/parts'))
        fixture = c.LoopbackFixture(local, [x['name'] for x in manifest['chunks']], time.monotonic()+5)
        with fixture:
            connection = socket.create_connection(('127.0.0.1', fixture.server.server_port), timeout=1)
            self.addCleanup(connection.close)
            connection.sendall(b'GET /chunk-000000.bin HTTP/1.0\r\nX-Incomplete: ')
            end = time.monotonic()+1
            while not fixture.server.active and time.monotonic() < end: time.sleep(.005)
            self.assertTrue(fixture.server.active, 'Actual accepted socket must be stuck before do_GET')
            began = time.monotonic()
        self.assertLess(time.monotonic()-began, 1)
        self.assertFalse(fixture.thread.is_alive()); self.assertFalse(fixture.watchdog.is_alive())

    def test_actual_dripping_response_headers_obey_absolute_deadline(self):
        run, _ = self.successful()
        manifest = read_json(run.file('evidence/chunk-manifest.json'))
        run.file('private/chunks/reconstructed.synthetic.bin').unlink()
        local = c.LocalChunks(run.file('private/chunks/parts'))
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                try:
                    self.wfile.write(b'HTTP/1.0 200 OK\r\nX-Dripping: '); self.wfile.flush()
                    # Each byte arrives faster than the per-receive socket
                    # timeout, while the full header would take five seconds.
                    for _ in range(100):
                        self.wfile.write(b'x'); self.wfile.flush(); time.sleep(.05)
                except OSError: pass
        began = time.monotonic(); deadline = began+.2
        with c.LoopbackFixture(local, [x['name'] for x in manifest['chunks']], deadline) as adapter:
            adapter.server.RequestHandlerClass = Handler
            with self.assertRaises(c.ChunkError):
                c.reconstruct(run, manifest, c.sha(c.canonical(manifest)), adapter, deadline, [])
        self.assertLess(time.monotonic()-began, 1.5)
        self.assertFalse(run.file('private/chunks/reconstructed.synthetic.bin').exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions/link guarantees require Linux')
    def test_linked_and_public_inputs_and_existing_output_refuse_without_overwrite(self):
        for fault in ('symlink', 'hardlink', 'public', 'output'):
            run, _ = self.successful()
            manifest = read_json(run.file('evidence/chunk-manifest.json'))
            output = run.file('private/chunks/reconstructed.synthetic.bin')
            original_output = output.read_bytes()
            path = run.file('private/chunks/parts/' + manifest['chunks'][0]['name'])
            if fault != 'output': output.unlink()
            if fault == 'symlink':
                path.unlink(); path.symlink_to(run.file('private/chunks/source.synthetic.bin'))
            elif fault == 'hardlink': os.link(path, path.with_name('hardlink.bin'))
            elif fault == 'public': path.chmod(0o644)
            with self.assertRaises(RunError):
                c.reconstruct(run, manifest, c.sha(c.canonical(manifest)), c.LocalChunks(path.parent), time.monotonic()+5, [])
            if fault == 'output': self.assertEqual(output.read_bytes(), original_output)

    def test_schema_matches_published_definition_and_registry_boundary_is_closed(self):
        path = Path(__file__).resolve().parents[1] / 'schemas/chunk-manifest-v1.schema.json'
        self.assertEqual(json.loads(path.read_text()), c.schema())
        run, _ = self.successful()
        original = read_json(run.file('evidence/chunk-manifest.json'))
        foreign = deepcopy(original); foreign['run_id'] = self.run_new().id
        run.file('private/chunks/reconstructed.synthetic.bin').unlink()
        with self.assertRaises(c.ChunkError) as error:
            c.reconstruct(run, foreign, c.sha(c.canonical(foreign)), c.LocalChunks(run.file('private/chunks/parts')), time.monotonic()+5, [])
        self.assertEqual(error.exception.code, 'chunk_run_identity')


if __name__ == '__main__':
    unittest.main()
