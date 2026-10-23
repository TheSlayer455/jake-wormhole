"""Exact-run local storage. No infrastructure or credential provisioning occurs here."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
from uuid import UUID, uuid4

from .contracts import ContractError, validate_artifact

SOURCE_ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 256 * 1024
ARTIFACTS = {
    "inventory": "inventory.json", "test-results": "test-results.json",
    "svd": "svd.json", "assessment": "assessment.json",
    "release-decision": "release-decision.json",
}


class RunError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


_LOCK_ISSUER = object()


class HeldRunGuard:
    """In-process proof for narrow adapters; never permits nested acquisition."""
    def __init__(self, run, descriptor, path, *, _issuer=None):
        if _issuer is not _LOCK_ISSUER:
            raise RunError('run_lock_required', 'Only an acquired Run lock issues a held adapter guard.')
        self.run_path, self.run_id = run.path, run.id
        self.descriptor, self.path = descriptor, path
        self.pid, self.thread = os.getpid(), threading.get_ident()
        value = os.fstat(descriptor)
        self.identity = value.st_dev, value.st_ino
        self.active = True

    def check(self, run):
        if not self.active or self.pid != os.getpid() or self.thread != threading.get_ident() or (run.path, run.id) != (self.run_path, self.run_id):
            raise RunError('run_lock_required', 'This adapter requires the current exact in-process Run lock.')
        try:
            _owned(self.path)
            held, path = os.fstat(self.descriptor), self.path.stat()
            if (held.st_dev, held.st_ino) != self.identity or (path.st_dev, path.st_ino) != self.identity:
                raise OSError('lock identity changed')
        except OSError:
            raise RunError('run_lock_required', 'The held Run lock descriptor or inode changed.') from None
        return True


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run_id(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise RunError("invalid_run_id", "Use the exact canonical UUID returned by run.") from None
    return value


def _linked(path):
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def _path_chain(path):
    for part in [*reversed(path.parents), path]:
        if _linked(part):
            raise RunError("unsafe_path", "Symlinks and junctions are not supported in run paths.")


def _owned(path, *, directory=False):
    _path_chain(path)
    info = path.stat()
    if directory and not stat.S_ISDIR(info.st_mode) or not directory and not stat.S_ISREG(info.st_mode):
        raise RunError("unsafe_path", "Run paths must be ordinary files and directories.")
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise RunError("unsafe_permissions", "Run storage must be owned by this user and private (0700/0600).")
    if not directory and info.st_nlink != 1:
        raise RunError("unsafe_path", "Hard-linked run files are not supported.")


def workspace_path(value, *, create=False):
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts or path == Path(path.anchor):
        raise RunError("unsafe_workspace", "Choose a dedicated absolute workspace outside checkouts and vaults.")
    _path_chain(path)
    for parent in [path, *path.parents]:
        if (parent / ".git").exists() or (parent / ".obsidian").exists():
            raise RunError("unsafe_workspace", "Run state cannot be inside a Git checkout or Obsidian vault.")
    path = path.resolve()
    if path == SOURCE_ROOT or path.is_relative_to(SOURCE_ROOT):
        raise RunError("unsafe_workspace", "Run state must remain outside the source checkout.")
    if create and not path.exists():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        _owned(path, directory=True)
    elif not create:
        raise RunError("workspace_missing", "The selected run workspace does not exist.")
    return path


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def read_json(path):
    _owned(path)
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise RunError("record_too_large", "A run record exceeds the supported byte limit.")
    try:
        return json.loads(raw, object_pairs_hook=_no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise RunError("invalid_json", "A run record is malformed or has duplicate/nonfinite values.") from None


def atomic_bytes(path, raw, *, limit=MAX_JSON_BYTES):
    if len(raw) > limit:
        raise RunError("record_too_large", "A run record exceeds the supported byte limit.")
    _owned(path.parent, directory=True)
    if path.exists() or _linked(path):
        _owned(path)
    temporary = path.with_name("." + path.name + "." + str(uuid4()) + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _path_chain(path)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path, value):
    try:
        raw = (json.dumps(value, allow_nan=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise RunError("invalid_json", "The run record cannot be represented as bounded JSON.") from None
    atomic_bytes(path, raw)


def source_identity():
    try:
        def git(*arguments):
            result = subprocess.run(["git", "-C", str(SOURCE_ROOT), *arguments],
                                    capture_output=True, timeout=10, check=True)
            return result.stdout.decode("utf-8").strip()
        revision, dirty = git("rev-parse", "HEAD"), bool(git("status", "--porcelain"))
        if not re.fullmatch("[a-f0-9]{40}", revision):
            raise ValueError
        return revision, dirty
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        raise RunError("source_unavailable", "A readable Git source revision is required.") from None


class Run:
    def __init__(self, workspace, identifier):
        self.workspace = workspace_path(workspace)
        self.id = run_id(identifier)
        self.path = self.workspace / self.id
        _owned(self.path, directory=True)
        marker = read_json(self.path / "owner.json")
        if marker != {"application": "jake-wormhole", "format": 1, "run_id": self.id}:
            raise RunError("ownership_mismatch", "The selected directory is not owned by this Wormhole run.")
        self.manifest()  # Validate before allowing any operation.

    def file(self, relative):
        part = Path(relative)
        if part.is_absolute() or not part.parts or any(p in {".", ".."} for p in part.parts) or "\\" in str(relative):
            raise RunError("unsafe_path", "Run paths must be fixed relative paths.")
        path = self.path / part
        _path_chain(path)
        if not path.resolve().is_relative_to(self.path):
            raise RunError("unsafe_path", "Run paths cannot leave their exact run directory.")
        return path

    def manifest(self):
        value = read_json(self.file("manifest.json"))
        validate_artifact("run-manifest", value)
        if value["run_id"] != self.id:
            raise RunError("identity_mismatch", "The manifest does not belong to the selected run.")
        return value

    def save_manifest(self, value):
        validate_artifact("run-manifest", value)
        if value["run_id"] != self.id:
            raise RunError("identity_mismatch", "A manifest cannot change the run identity.")
        atomic_json(self.file("manifest.json"), value)

    def artifact(self, kind):
        if kind not in ARTIFACTS:
            raise RunError("unsupported_artifact", "That artifact kind is not supported.")
        value = read_json(self.file("evidence/" + ARTIFACTS[kind]))
        validate_artifact(kind, value)
        return value

    def save_artifact(self, kind, value):
        if kind not in ARTIFACTS:
            raise RunError("unsupported_artifact", "That artifact kind is not supported.")
        validate_artifact(kind, value)
        atomic_json(self.file("evidence/" + ARTIFACTS[kind]), value)

    @contextmanager
    def locked(self):
        policy = self.file("lock-policy.json")
        if policy.exists():
            expected = {"schema_version": "1.0", "run_id": self.id, "kind": "linux-flock"}
            if read_json(policy) != expected or self.manifest()["mode"] != "container-reference":
                raise RunError("invalid_lock_policy", "The run's immutable lock policy is invalid.")
            with self._kernel_locked() as guard:
                yield guard
            return
        # Legacy fixtures/runs retain their original policy. A stale legacy
        # PID file is never deleted or converted merely because its PID died.
        if self.file("operation.lock").exists():
            raise RunError("invalid_lock_policy", "A stable run lock exists without its policy; preserve it for reviewed recovery.")
        path = self.file(".lock")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise RunError("run_busy", "This exact run is already locked; no stale-lock takeover is automatic.") from None
        guard = HeldRunGuard(self, descriptor, path, _issuer=_LOCK_ISSUER)
        try:
            os.write(descriptor, str(os.getpid()).encode('ascii')); os.fsync(descriptor)
            yield guard
        finally:
            guard.active = False
            os.close(descriptor)
            path.unlink()

    @contextmanager
    def _kernel_locked(self):
        if not sys.platform.startswith("linux"):
            raise RunError("linux_required", "This real run requires Linux kernel flock semantics.")
        import fcntl
        legacy = self.file(".lock")
        if legacy.exists():
            raise RunError("run_busy", "A legacy lock remains; explicit reviewed recovery is required.")
        path = self.file("operation.lock")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            _owned(path)
            identity = os.fstat(descriptor)
            if (identity.st_dev, identity.st_ino) != (path.stat().st_dev, path.stat().st_ino):
                raise RunError("unsafe_lock", "The stable run lock inode changed.")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RunError("run_busy", "Another process holds this run's kernel lock.") from None
            if legacy.exists() or (identity.st_dev, identity.st_ino) != (path.stat().st_dev, path.stat().st_ino):
                raise RunError("unsafe_lock", "Run lock ownership changed during acquisition.")
            guard = HeldRunGuard(self, descriptor, path, _issuer=_LOCK_ISSUER)
            try:
                yield guard
            finally:
                guard.active = False
        finally:
            os.close(descriptor)  # Persistent inode; kernel releases after crash.


def create_run(workspace, *, fixture, identity=None, kernel_lock=False, profile=None):
    if type(fixture) is not bool:
        raise RunError("invalid_profile", "The fixture flag must be explicit.")
    profile = ("fixture" if fixture else "smoke") if profile is None else profile
    if type(profile) is not str or (profile != "fixture" if fixture else profile not in {"smoke", "five-targets", "twenty-targets"}):
        raise RunError("invalid_profile", "Use a declared profile consistent with the run mode.")
    if type(kernel_lock) is not bool or kernel_lock and (fixture or not sys.platform.startswith("linux")):
        raise RunError("invalid_lock_policy", "Kernel locking is supported only for new real Linux runs.")
    base = workspace_path(workspace, create=True)
    revision, dirty = source_identity() if identity is None else identity
    identifier = str(uuid4())
    path = base / identifier
    path.mkdir(mode=0o700)
    for relative in ("private", "private/logs", "private/terraform", "private/inventory", "private/credentials", "evidence"):
        (path / relative).mkdir(mode=0o700)
    atomic_json(path / "owner.json", {"application": "jake-wormhole", "format": 1, "run_id": identifier})
    if kernel_lock:
        atomic_json(path / "lock-policy.json", {"schema_version": "1.0", "run_id": identifier, "kind": "linux-flock"})
    timestamp = now()
    manifest = {"schema_version": "1.0", "run_id": identifier, "source_revision": revision,
                "source_dirty": dirty, "mode": "fixture" if fixture else "container-reference",
                "profile": profile, "outcome": "running", "created_at": timestamp,
                "updated_at": timestamp, "stages": [], "expected_checks": ["fixture-sha256"] if fixture else [],
                "runtime_pipeline_complete": False, "production_iso_eligible": False}
    validate_artifact("run-manifest", manifest)
    atomic_json(path / "manifest.json", manifest)
    return Run(base, identifier)


def common(manifest):
    return {key: manifest[key] for key in ("schema_version", "run_id", "source_revision", "source_dirty", "mode")}


def _validate_cleanup(value, identifier):
    fields = {"run_id", "status", "private_state_removed", "infrastructure_removed", "error", "created_at"}
    valid = isinstance(value, dict) and set(value) == fields
    if valid:
        valid = (value["run_id"] == identifier and type(value["status"]) is str
                 and value["status"] in {"completed", "failed"}
                 and type(value["private_state_removed"]) is bool
                 and value["infrastructure_removed"] is False)
    if valid:
        stamp = value["created_at"]
        try:
            valid = (isinstance(stamp, str) and len(stamp) <= 32
                     and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", stamp) is not None
                     and datetime.fromisoformat(stamp.replace("Z", "+00:00")).utcoffset() is not None)
        except ValueError:
            valid = False
    if valid and value["status"] == "completed":
        valid = value["private_state_removed"] is True and value["error"] is None
    elif valid:
        valid = (value["private_state_removed"] is False and isinstance(value["error"], str)
                 and 1 <= len(value["error"]) <= 2000)
    if not valid:
        raise RunError("invalid_cleanup", "The cleanup receipt is malformed.")


def report_run(run):
    manifest = run.manifest()
    records = {kind: run.artifact(kind) for kind in ARTIFACTS}
    for record in records.values():
        if common(record) != common(manifest):
            raise RunError("identity_mismatch", "Evidence identity does not match this run and source.")
    result = {"manifest": manifest, "artifacts": records}
    receipt = run.file("cleanup.json")
    if receipt.exists():
        value = read_json(receipt)
        _validate_cleanup(value, run.id)
        result["cleanup"] = value
    return result


def cleanup_run(run):
    """Remove only this fixture's private subtree; preserve evidence and primary outcome."""
    manifest = run.manifest()
    if manifest["mode"] != "fixture" or manifest["profile"] != "fixture" or manifest["outcome"] == "running":
        raise RunError("cleanup_refused", "Only completed fixture-owned local state can be removed; no infrastructure cleanup is implemented.")
    private = run.file("private")
    receipt = {"run_id": run.id, "status": "completed", "private_state_removed": True,
               "infrastructure_removed": False, "error": None, "created_at": now()}
    if private.exists():
        _owned(private, directory=True)
        root_device = private.stat().st_dev
        for folder, directories, files in os.walk(private, followlinks=False):
            for name in [*directories, *files]:
                child = Path(folder) / name
                _owned(child, directory=child.is_dir())
                if child.stat().st_dev != root_device:
                    raise RunError("unsafe_path", "Cleanup cannot cross a mounted filesystem.")
        # The resolved absolute target has been checked within this exact owned run.
        if private.resolve() != run.path / "private":
            raise RunError("unsafe_path", "Cleanup target changed.")
        try:
            shutil.rmtree(private)
        except OSError:
            receipt.update(status="failed", private_state_removed=False, error="Private local cleanup failed; primary run outcome is unchanged.")
            atomic_json(run.file("cleanup.json"), receipt)
            raise RunError("cleanup_failed", receipt["error"]) from None
    atomic_json(run.file("cleanup.json"), receipt)
    return receipt
