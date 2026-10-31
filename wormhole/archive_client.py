"""Workstation-owned age storage; remote eviction follows verified readback only."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time

from .media_store import SHA
from .runs import RunError, _no_duplicates, _owned, _path_chain, now, read_json, run_id


class ArchiveError(RunError):
    pass


def require(condition, code="archive_invalid", message="Archive configuration or evidence is invalid."):
    if not condition:
        raise ArchiveError(code, message)


def ordinary(path, directory=False):
    """NTFS privacy is its externally provisioned Windows ACL, not chmod."""
    _path_chain(path)
    value = path.stat()
    require(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode) and value.st_nlink == 1)
    return value.st_dev, value.st_ino


def record(path):
    ordinary(path)
    with path.open("rb") as stream:
        raw = stream.read(256 * 1024 + 1)
    require(len(raw) <= 256 * 1024)
    try:
        return json.loads(raw, object_pairs_hook=_no_duplicates)
    except (ValueError, UnicodeError):
        raise ArchiveError("archive_invalid", "Archive JSON is invalid.") from None


def durable(path, value):
    if path.exists() or path.is_symlink():
        ordinary(path)
    descriptor, name = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(value, sort_keys=True) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def lock(path):
    import fcntl
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        require(ordinary(path) == (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ArchiveError("archive_busy", "Another workstation archive operation holds the lock.") from None
        yield
    finally:
        os.close(descriptor)


class Client:
    def __init__(self, config):
        require(os.name == "posix", message="The archive client runs in Linux/WSL.")
        self.config = read_json(Path(config))
        self.archive_id = run_id(self.config["archive_id"])
        self.root = Path(self.config["root"])
        self.identity = Path(self.config["identity"])
        require(self.root.is_absolute() and self.identity.is_absolute() and ".." not in self.root.parts)
        require(self.root != Path(self.root.anchor) and not self.identity.is_relative_to(self.root))
        _owned(self.identity)
        self.root_identity = ordinary(self.root, True)
        self.owner_identity = ordinary(self.root / "owner.json")
        self.guard()
        self.objects = self.root / "objects"
        self.objects.mkdir(exist_ok=True)
        self.objects_identity = ordinary(self.objects, True)
        self.reserve = self.config["reserve_bytes"]
        self.timeout = self.config["timeout_seconds"]
        require(type(self.reserve) is int and self.reserve >= 0 and type(self.timeout) is int and 1 <= self.timeout <= 86400)
        require(isinstance(self.config["recipient"], str) and self.config["recipient"].startswith("age1"))
        ssh = self.config["ssh"]
        require(isinstance(ssh, list) and len(ssh) >= 2 and all(isinstance(v, str) and v for v in ssh))
        require(Path(ssh[0]).name == "ssh" and isinstance(self.config["command"], str) and bool(self.config["command"]))
        self.ssh = [ssh[0], "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=15",
                    "-oServerAliveInterval=15", "-oServerAliveCountMax=2", *ssh[1:]]
        self.deadline = time.monotonic() + self.timeout

    def guard(self):
        require(ordinary(self.root, True) == self.root_identity and ordinary(self.root / "owner.json") == self.owner_identity,
                "archive_owner_changed", "The archive root or owner record changed.")
        require(record(self.root / "owner.json") == {"schema_version": "1.0", "archive_id": self.archive_id},
                "archive_owner_changed", "The archive owner does not match this workstation configuration.")
        if hasattr(self, "objects_identity"):
            require(ordinary(self.objects, True) == self.objects_identity, "archive_owner_changed", "The archive objects directory changed.")

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "archive_timeout", "The archive operation exceeded its absolute deadline.")
        return remaining

    @contextmanager
    def process(self, argv, **kwargs):
        process = subprocess.Popen(argv, stderr=subprocess.DEVNULL, start_new_session=True, **kwargs)
        try:
            yield process
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            for stream in (process.stdin, process.stdout):
                if stream:
                    stream.close()

    def wait(self, process):
        try:
            code = process.wait(timeout=self.remaining())
        except subprocess.TimeoutExpired:
            raise ArchiveError("archive_timeout", "The archive subprocess exceeded its deadline.") from None
        require(code == 0, "archive_transfer_failed", "The archive subprocess failed; no unverified object was acknowledged.")

    def remote(self, operation, digest=None):
        return [*self.ssh, self.config["command"] + " " + operation + (" " + digest if digest else "")]

    def response(self, output):
        output.seek(0); raw = output.read(256 * 1024 + 1)
        require(len(raw) <= 256 * 1024, "archive_remote_invalid", "The remote response exceeds its limit.")
        try:
            value = json.loads(raw, object_pairs_hook=_no_duplicates)
        except (ValueError, UnicodeError):
            raise ArchiveError("archive_remote_invalid", "The remote archive response is not valid JSON.") from None
        require(isinstance(value, dict))
        return value

    def request(self, operation, digest=None, value=None):
        with tempfile.TemporaryFile() as output:
            with self.process(self.remote(operation, digest), stdin=subprocess.PIPE, stdout=output) as remote:
                try:
                    remote.communicate(json.dumps(value).encode() if value is not None else b"", timeout=self.remaining())
                except subprocess.TimeoutExpired:
                    raise ArchiveError("archive_timeout", "The remote archive operation exceeded its deadline.") from None
                self.wait(remote)
            return self.response(output)

    def ciphertext(self, path):
        ordinary(path); digest = hashlib.sha256(); count = 0
        with path.open("rb") as stream:
            while data := stream.read(1024 * 1024):
                self.remaining(); digest.update(data); count += len(data)
        return digest.hexdigest(), count

    def verify(self, digest, size, path, receipt=None):
        self.guard()
        ciphertext, cipher_size = self.ciphertext(path)
        if receipt is not None:
            require(receipt == {"archive_id": self.archive_id, "sha256": digest, "bytes": size,
                "ciphertext_sha256": ciphertext, "ciphertext_bytes": cipher_size, "verified": True},
                "destination_verification_failed", "Stored ciphertext or its receipt no longer matches.")
        actual = hashlib.sha256(); count = 0
        with self.process(["age", "--decrypt", "--identity", str(self.identity), str(path)], stdout=subprocess.PIPE) as decrypt:
            with selectors.DefaultSelector() as selector:
                selector.register(decrypt.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    for key, _ in selector.select(timeout=min(self.remaining(), 1)):
                        data = os.read(key.fd, 1024 * 1024)
                        if not data:
                            selector.unregister(key.fileobj); break
                        count += len(data); actual.update(data)
                        require(count <= size, "destination_verification_failed", "Decrypted bytes exceed the expected object size.")
            self.wait(decrypt)
        require(count == size and actual.hexdigest() == digest, "destination_verification_failed", "Decrypted stored bytes do not match the original object.")
        self.guard()
        return {"archive_id": self.archive_id, "sha256": digest, "bytes": size,
            "ciphertext_sha256": ciphertext, "ciphertext_bytes": cipher_size, "verified": True}

    def sync(self, digest=None):
        listing = self.request("archive-list")
        require(listing.get("archive_id") == self.archive_id and isinstance(listing.get("objects"), list))
        objects = [item for item in listing["objects"] if item.get("sha256") == digest] if digest else [
            item for item in listing["objects"] if item.get("needs_sync",item.get("state") != "committed")]
        require(digest is None or bool(objects), "archive_missing", "The requested object is not available remotely.")
        results = []
        for item in objects:
            sha, size = item["sha256"], item["bytes"]
            require(isinstance(sha, str) and SHA.fullmatch(sha) and type(size) is int and size > 0)
            with lock(self.objects / (sha + ".lock")):
                path = self.objects / (sha + ".age"); receipt_path = self.objects / (sha + ".json")
                if not path.exists():
                    require(not path.is_symlink() and not receipt_path.exists())
                    require(shutil.disk_usage(self.root).free >= self.reserve + size + size // 100 + 1024 * 1024,
                            "archive_capacity", "Workstation archive headroom is insufficient.")
                    partial = path.with_suffix(".age.part")
                    if partial.exists():
                        ordinary(partial); partial.unlink()
                    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(descriptor, "wb") as output:
                        with self.process(self.remote("archive-export", sha), stdout=subprocess.PIPE) as remote:
                            with self.process(["age", "--encrypt", "--recipient", self.config["recipient"]], stdin=remote.stdout, stdout=output) as encrypt:
                                remote.stdout.close(); self.wait(encrypt); self.wait(remote)
                        output.flush(); os.fsync(output.fileno())
                    receipt = self.verify(sha, size, partial)
                    self.guard(); os.rename(partial, path)
                else:
                    receipt = self.verify(sha, size, path, record(receipt_path) if receipt_path.exists() else None)
                self.guard(); durable(receipt_path, receipt)
                results.append({"sha256": sha, "remote": self.request("archive-commit", sha, receipt)})
        return results

    def local(self, operation, digest=None):
        paths = [self.objects / (digest + ".json")] if digest else sorted(self.objects.glob("*.json"))
        require(operation != "restore" or digest is not None, message="Restore requires one explicit digest.")
        results = []
        for receipt_path in paths:
            sha = receipt_path.stem
            require(SHA.fullmatch(sha))
            with lock(self.objects / (sha + ".lock")):
                path = self.objects / (sha + ".age")
                try:
                    receipt = record(receipt_path); size = receipt.get("bytes")
                    require(type(size) is int and size > 0)
                    self.verify(sha, size, path, receipt)
                except (RunError, OSError):
                    # Failure notification cannot turn corrupt bytes into an acknowledgment.
                    try:
                        self.request("archive-failed", sha, {"archive_id": self.archive_id, "error_category": "destination_verification_failed"})
                    except (RunError, OSError):
                        pass
                    raise
                if operation == "restore":
                    with tempfile.TemporaryFile() as output:
                        with self.process(["age", "--decrypt", "--identity", str(self.identity), str(path)], stdout=subprocess.PIPE) as decrypt:
                            with self.process(self.remote("archive-import", sha), stdin=decrypt.stdout, stdout=output) as remote:
                                decrypt.stdout.close(); self.wait(remote); self.wait(decrypt)
                        response = self.response(output)
                    results.append({"sha256": sha, "remote": response})
                else:
                    results.append({"sha256": sha, "verified": True})
        return results


def run(operation, config_path, digest=None):
    """Called by the normal CLI; safe status is retained even when a transfer fails."""
    require(operation in {"sync", "verify", "restore"})
    require(digest is None or isinstance(digest, str) and SHA.fullmatch(digest))
    try:
        client = Client(config_path)
        with lock(client.root / "archive.lock"):
            client.guard()
            try:
                results = client.sync(digest) if operation == "sync" else client.local(operation, digest)
                status = {"operation": operation, "outcome": "complete", "objects": results, "completed_at": now()}
            except (RunError, OSError, KeyError, TypeError) as error:
                status = {"operation": operation, "outcome": "failed", "error_category": getattr(error, "code", "archive_io_failed"), "completed_at": now()}
                client.guard(); durable(client.root / "status.json", status)
                raise
            client.guard(); durable(client.root / "status.json", status)
            return status
    except (OSError, KeyError, TypeError):
        raise ArchiveError("archive_io_failed", "Archive configuration, local storage, or transport is unavailable; no unverified object was acknowledged.") from None
