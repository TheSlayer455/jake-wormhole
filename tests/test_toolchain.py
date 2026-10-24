"""Synthetic archives only. No Terraform/provider binary or Docker is executed."""
from copy import deepcopy
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request
import warnings
import zipfile

from wormhole import toolchain as t
from wormhole.runs import RunError, atomic_json, create_run, read_json


def package(kind, *, change=None):
    names = ["LICENSE.txt", "terraform"] if kind == "terraform" else ["CHANGELOG.md", "LICENSE", "README.md", "terraform-provider-docker_v4.6.0"]
    members, contents = [], {}
    for name in names:
        content = ("synthetic fixture bytes: " + name).encode()
        executable = name in {"terraform", "terraform-provider-docker_v4.6.0"}
        members.append({"name": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                        "archive_mode": stat.S_IFREG | (0o755 if executable else 0o644), "mode": 0o500 if executable else 0o400})
        contents[name] = content
    output = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        warnings.simplefilter("ignore", UserWarning)
        entries = [(m["name"], contents[m["name"]], m["archive_mode"]) for m in members]
        if change: entries = change(entries)
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    raw = output.getvalue()
    return {"kind": kind, "url": t.URLS[kind], "filename": t.URLS[kind].rsplit("/", 1)[1],
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "destination": "bin" if kind == "terraform" else t.PROVIDER_DIRECTORY,
            "members": members, "signed_metadata": {"synthetic": True}}, raw


class Policy(unittest.TestCase):
    def test_committed_pins_cover_complete_archive_members_and_prior_signature_provenance(self):
        lock = t.load_lock()
        self.assertEqual(len(lock["artifacts"]), 2)
        self.assertEqual(sum(len(i["members"]) for i in lock["artifacts"]), 6)
        self.assertEqual([i["sha256"] for i in lock["artifacts"]], [
            "c168cab7c637a8769fdb90089ddd19de701bc6ff8aca64dc2e2185fe46f59f67",
            "866046fa4938ac1ed5cc58b3c4d36e27433dac1aae50256911e6f28184dcf82e"])
        for item in lock["artifacts"]:
            self.assertTrue(item["signed_metadata"]["verified"])
            self.assertEqual(len(item["signed_metadata"]["signer_fingerprint"]), 40)
        self.assertFalse(lock["downloaded_binaries_executed"])
        self.assertIn("pending", lock["provider_h1"]["status"])

    def test_exact_single_provider_redirect_drops_original_headers_and_rejects_others(self):
        policy = t.RedirectPolicy(t.URLS["docker-provider"])
        request = urllib.request.Request(t.URLS["docker-provider"], headers={"Authorization": "synthetic-not-a-secret", "Cookie": "synthetic"})
        redirected = policy.redirect_request(request, None, 302, "", {}, "https://release-assets.githubusercontent.com/fixed?synthetic=signed")
        self.assertEqual(redirected.header_items(), [])
        with self.assertRaises(t.ToolchainError): policy.redirect_request(request, None, 302, "", {}, redirected.full_url)
        for target in ("http://release-assets.githubusercontent.com/file", "https://other.invalid/file",
                       "https://user@release-assets.githubusercontent.com/file", "https://release-assets.githubusercontent.com:444/file",
                       "https://release-assets.githubusercontent.com/file#fragment"):
            with self.subTest(target=target), self.assertRaises(t.ToolchainError):
                t.RedirectPolicy(t.URLS["docker-provider"]).redirect_request(request, None, 302, "", {}, target)
        with self.assertRaises(t.ToolchainError):
            t.RedirectPolicy(t.URLS["terraform"]).redirect_request(urllib.request.Request(t.URLS["terraform"]), None, 302, "", {}, redirected.full_url)


@unittest.skipUnless(os.name == "posix", "Actual private-mode/O_NOFOLLOW fixtures require POSIX; no host tools are installed")
class PrivateArchivePreparation(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def archive(self, item, raw):
        path = self.root / "source.zip"
        if path.exists(): path.chmod(0o600)
        path.write_bytes(raw); path.chmod(0o400)
        return path

    def test_stream_download_rejects_wrong_hash_size_origin_and_preserves_private_partial(self):
        item, raw = package("terraform")
        class Response(io.BytesIO):
            status = 200
            def geturl(self): return item["url"]
        class Opener:
            def open(self, *_args, **_kwargs): return Response(raw)
        target = self.root / "archive.zip"
        budget = t.Budget()
        t.download(item, target, budget, opener=Opener())
        self.assertEqual(target.read_bytes(), raw)
        self.assertEqual(target.stat().st_mode & 0o777, 0o400)
        target.unlink()
        for field, value in (("sha256", "f" * 64), ("bytes", len(raw) - 1)):
            candidate = {**item, field: value}
            with self.subTest(field=field), self.assertRaises(t.ToolchainError): t.download(candidate, target, t.Budget(), opener=Opener())
            self.assertFalse(target.exists())
            partial = target.with_name(target.name + ".part")
            self.assertEqual(partial.stat().st_mode & 0o777, 0o600)
            partial.unlink()
        class Foreign(Response):
            def geturl(self): return "https://untrusted.invalid/artifact"
        class ForeignOpener:
            def open(self, *_args, **_kwargs): return Foreign(raw)
        with self.assertRaises(t.ToolchainError): t.download(item, target, t.Budget(), opener=ForeignOpener())

    def test_stream_extracts_exact_complete_files_with_private_modes_and_hashes(self):
        item, raw = package("docker-provider")
        cache = self.root / "cache"; cache.mkdir(mode=0o700)
        t.extract(item, self.archive(item, raw), cache, t.Budget())
        destination = cache / t.PROVIDER_DIRECTORY
        self.assertEqual({p.name for p in destination.iterdir()}, {m["name"] for m in item["members"]})
        for member in item["members"]:
            path = destination / member["name"]
            self.assertEqual(path.stat().st_mode & 0o777, member["mode"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), member["sha256"])
        with self.assertRaises(FileExistsError): t.extract(item, self.root / "source.zip", cache, t.Budget())

    def test_traversal_links_duplicate_entries_and_declared_zip_bomb_are_rejected_before_write(self):
        changes = [lambda e: [("../terraform", e[0][1], e[0][2]), *e[1:]],
                   lambda e: [(*e[0][:2], stat.S_IFLNK | 0o777), *e[1:]],
                   lambda e: [*e, e[0]],
                   lambda e: [(e[0][0], b"x" * 20000, e[0][2]), *e[1:]]]
        for index, change in enumerate(changes):
            item, raw = package("terraform", change=change)
            cache = self.root / ("cache" + str(index)); cache.mkdir(mode=0o700)
            with self.subTest(index=index), self.assertRaises(t.ToolchainError):
                t.extract(item, self.archive(item, raw), cache, t.Budget())
            self.assertFalse(any(p.is_file() for p in cache.rglob("*")))

    def test_member_hash_expansion_budget_and_symlink_destination_fail_closed(self):
        item, raw = package("terraform")
        cache = self.root / "cache"; cache.mkdir(mode=0o700)
        item["members"][0]["sha256"] = "f" * 64
        with self.assertRaises(t.ToolchainError): t.extract(item, self.archive(item, raw), cache, t.Budget())
        item, raw = package("terraform")
        other = self.root / "other"; other.mkdir(mode=0o700)
        with patch.object(t, "MAX_EXPANDED", 1), self.assertRaises(t.ToolchainError):
            t.extract(item, self.archive(item, raw), other, t.Budget())
        linked = self.root / "linked"; linked.mkdir(mode=0o700)
        outside = self.root / "outside"; outside.mkdir(mode=0o700)
        (linked / "bin").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RunError): t.extract(item, self.archive(item, raw), linked, t.Budget())
        self.assertFalse(list(outside.iterdir()))

    def test_parent_validates_exact_cache_bytes_receipt_and_original_pins(self):
        run = create_run(self.root / "runs", fixture=False, identity=("a" * 40, False))
        items, raw_by_url = [], {}
        for kind in ("terraform", "docker-provider"):
            item, raw = package(kind); items.append(item); raw_by_url[item["url"]] = raw
        lock = {"artifacts": items, "provider_h1": {"status": "synthetic pending"}}
        class Response(io.BytesIO):
            status = 200
            def __init__(self, url): super().__init__(raw_by_url[url]); self.url = url
            def geturl(self): return self.url
        class Opener:
            def open(self, url, **_kwargs): return Response(url)
        with patch.object(t, "load_lock", return_value=lock), patch.object(t.urllib.request, "build_opener", return_value=Opener()):
            t._prepare_worker(run)
        prepared = t.validate_cache(run, lock)
        self.assertTrue(prepared["terraform"].is_file())
        self.assertTrue(prepared["mirror"].is_dir())
        self.assertEqual(len(prepared["archives"]), 2)
        self.assertFalse(prepared["receipt"]["downloaded_binaries_executed"])
        receipt_path = prepared["root"] / "receipt.json"
        bad = deepcopy(prepared["receipt"]); bad["operation"] = "invented-runtime-success"
        atomic_json(receipt_path, bad)
        with self.assertRaises(t.ToolchainError): t.validate_cache(run, lock)
        atomic_json(receipt_path, prepared["receipt"])
        extra = prepared["root"] / "unapproved"; extra.mkdir(mode=0o700)
        with self.assertRaises(t.ToolchainError): t.validate_cache(run, lock)
        extra.rmdir()
        path = prepared["terraform"]
        path.chmod(0o600); path.write_bytes(b"tamper"); path.chmod(0o500)
        with self.assertRaises(t.ToolchainError): t.validate_cache(run, lock)

    def test_absolute_worker_deadline_and_old_cache_refusal_prevent_acceptance(self):
        run = create_run(self.root / "runs", fixture=False, identity=("a" * 40, False))
        worker = '''import sys,time
from pathlib import Path
root=Path(sys.argv[1])/sys.argv[2]/"private"
(root/"worker-entered").touch(mode=0o600)
time.sleep(5)
'''
        started = time.monotonic()
        lock = t.load_lock()
        with patch.object(t, "source_identity", return_value=("a" * 40, False)), patch.object(t, "load_lock", return_value=lock), patch.object(t, "WORKER", worker), patch.object(t, "TIMEOUT", .5), self.assertRaises(t.ToolchainError) as error:
            t.prepare_toolchain(run)
        self.assertEqual(error.exception.code, "tool_preparation_timeout")
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(run.file("private/worker-entered").exists())
        run.file("private/toolchain").mkdir(mode=0o700)
        with patch.object(t, "source_identity", return_value=("a" * 40, False)), patch.object(t, "_run_process") as process, self.assertRaises(t.ToolchainError): t.prepare_toolchain(run)
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
