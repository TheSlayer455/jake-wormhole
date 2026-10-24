"""Pinned public archives, prepared privately without executing downloaded code."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import urllib.request
from urllib.parse import urlsplit
import zipfile

from .runs import (Run, RunError, SOURCE_ROOT, _owned, _path_chain, atomic_bytes, atomic_json,
                   now, read_json, source_identity)
from .stages import _run_process

LOCK = SOURCE_ROOT / "provisioning/tools.lock.json"
CHUNK = 65536
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_ARCHIVES = 96 * 1024 * 1024
MAX_CACHE = MAX_EXPANDED = 512 * 1024 * 1024
MAX_RECEIPT = 262144
TIMEOUT = 180
PROVIDER_DIRECTORY = "mirror/registry.terraform.io/kreuzwerker/docker/4.6.0/linux_amd64"
URLS = {
    "terraform": "https://releases.hashicorp.com/terraform/1.17.0/terraform_1.17.0_linux_amd64.zip",
    "docker-provider": "https://github.com/kreuzwerker/terraform-provider-docker/releases/download/v4.6.0/terraform-provider-docker_4.6.0_linux_amd64.zip",
}
WORKER = """import json,sys
from wormhole.runs import Run
from wormhole.toolchain import _prepare_worker
try:
    _prepare_worker(Run(sys.argv[1], sys.argv[2]))
except Exception as error:
    print(json.dumps({'code':getattr(error,'code','toolchain_preparation_failed')}))
    raise SystemExit(2)
"""


class ToolchainError(RunError):
    pass


def require(condition, code, message):
    if not condition:
        raise ToolchainError(code, message)


def load_lock():
    with LOCK.open("rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, "invalid_tool_lock", "Toolchain lock exceeds its source byte bound.")
    value = json.loads(raw)
    require(value["schema_version"] == "1.0" and value["platform"] == "linux_amd64", "invalid_tool_lock", "Unsupported toolchain lock.")
    items = value["artifacts"]
    require(all(type(value["policy"].get(k)) is int and value["policy"][k] == v for k, v in {
        "download_bytes_per_file": MAX_ARCHIVE, "archive_bytes_total": MAX_ARCHIVES,
        "cache_bytes_total": MAX_CACHE, "expanded_bytes_total": MAX_EXPANDED,
        "preparation_timeout_seconds": TIMEOUT}.items()), "invalid_tool_lock", "Committed tool policy differs from the reviewed code bounds.")
    require(len(items) == 2 and {i["kind"] for i in items} == set(URLS), "invalid_tool_lock", "Exactly the reviewed Terraform and provider archives are required.")
    for item in items:
        kind = item["kind"]
        require(item["version"] == ("1.17.0" if kind == "terraform" else "4.6.0")
                and item["url"] == URLS[kind] and item["filename"] == URLS[kind].rsplit("/", 1)[1]
                and re.fullmatch(r"[a-f0-9]{64}", item["sha256"]) and type(item["bytes"]) is int
                and 0 < item["bytes"] <= MAX_ARCHIVE,
                "invalid_tool_lock", "Archive URL, name, hash or size is not a reviewed pin.")
        require(item["destination"] == ("bin" if kind == "terraform" else PROVIDER_DIRECTORY), "invalid_tool_lock", "Tool destinations are fixed.")
        names = set()
        for member in item["members"]:
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", member["name"]) and member["name"] not in {".", ".."}
                    and member["name"] not in names and re.fullmatch(r"[a-f0-9]{64}", member["sha256"])
                    and type(member["bytes"]) is int and 0 < member["bytes"] <= 256 * 1024 * 1024
                    and member["archive_mode"] in {stat.S_IFREG | 0o644, stat.S_IFREG | 0o755}
                    and member["mode"] == (0o500 if member["archive_mode"] & 0o111 else 0o400),
                    "invalid_tool_lock", "Every ordinary archive member needs an exact bounded pin and private mode.")
            names.add(member["name"])
        require(names == ({"terraform", "LICENSE.txt"} if kind == "terraform" else
                          {"terraform-provider-docker_v4.6.0", "LICENSE", "README.md", "CHANGELOG.md"}),
                "invalid_tool_lock", "The complete reviewed archive member set is required.")
    return value


def hash_file(path, *, limit, size=None):
    _owned(path)
    total, digest = 0, hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(CHUNK), b""):
            total += len(raw)
            require(total <= limit and (size is None or total <= size), "tool_size_exceeded", "Tool bytes exceed their reviewed size bound.")
            digest.update(raw)
    require(size is None or total == size, "tool_size_mismatch", "Tool bytes do not match their reviewed size.")
    return digest.hexdigest(), total


class RedirectPolicy(urllib.request.HTTPRedirectHandler):
    def __init__(self, initial):
        super().__init__()
        self.initial, self.count = initial, 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        require(self.initial == URLS["docker-provider"] and req.full_url == self.initial and self.count == 0
                and target.scheme == "https" and target.hostname == "release-assets.githubusercontent.com"
                and not target.username and not target.password and target.port in (None, 443) and not target.fragment,
                "tool_redirect_refused", "Public tool redirect is outside the one reviewed release-asset hop.")
        self.count += 1
        # No original headers, authorization or cookies follow this hop. Signed
        # target query is temporary request data and is never logged/persisted.
        return urllib.request.Request(newurl, method="GET")


class Budget:
    def __init__(self):
        self.archives = self.expanded = 0

    def add(self, amount, *, expanded=False):
        if expanded:
            self.expanded += amount
        else:
            self.archives += amount
        require(self.archives <= MAX_ARCHIVES and self.expanded <= MAX_EXPANDED
                and self.archives + self.expanded + MAX_RECEIPT <= MAX_CACHE,
                "tool_cache_exceeded", "Tool preparation exceeds the reviewed private cache budget.")


def download(item, destination, budget, *, opener=None):
    require(item["url"] == URLS.get(item["kind"]), "tool_url_refused", "Only the fixed public tool URLs are supported.")
    policy = RedirectPolicy(item["url"])
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), policy)
    temporary = destination.with_name(destination.name + ".part")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    count, digest = 0, hashlib.sha256()
    try:
        with os.fdopen(descriptor, "wb") as output, opener.open(item["url"], timeout=30) as response:
            final = urlsplit(response.geturl())
            require(response.status == 200 and (response.geturl() == item["url"] or
                    policy.count == 1 and final.scheme == "https" and final.hostname == "release-assets.githubusercontent.com"
                    and final.port in (None, 443) and not final.username and not final.password and not final.fragment),
                    "tool_origin_refused", "Public tool response does not match the reviewed origin policy.")
            while True:
                raw = response.read(CHUNK)
                if not raw:
                    break
                count += len(raw)
                require(count <= item["bytes"] and count <= MAX_ARCHIVE, "tool_size_exceeded", "Downloaded archive exceeds its pinned byte count.")
                budget.add(len(raw))
                digest.update(raw)
                output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        require(count == item["bytes"] and digest.hexdigest() == item["sha256"], "tool_hash_mismatch", "Downloaded archive does not match its signed checksum pin.")
        require(not destination.exists(), "tool_cache_exists", "Tool archives cannot overwrite a prior attempt.")
        os.rename(temporary, destination)
        destination.chmod(0o400)
    except ToolchainError:
        raise
    except Exception:
        # Do not expose redirect Location/query in urllib exception messages.
        raise ToolchainError("tool_download_failed", "Fixed public tool download failed; private partial cache remains unaccepted.") from None


def zip_preflight(path):
    """Bound the central directory before ZipFile allocates its member objects."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    require(position >= 0 and len(tail) - position >= 22, "unsafe_tool_zip", "ZIP end record is missing.")
    _, disk, directory_disk, disk_count, count, directory_size, offset, comment = struct.unpack("<4s4H2IH", tail[position:position + 22])
    absolute = max(0, size - 65557) + position
    require(disk == directory_disk == 0 and disk_count == count and 0 < count <= 16
            and comment == 0 and absolute + 22 == size and directory_size <= 65536
            and offset + directory_size == absolute,
            "unsafe_tool_zip", "ZIP64, multidisk, oversized directory, comments and trailing data are unsupported.")


def extract(item, archive, root, budget):
    require(item["destination"] in {"bin", PROVIDER_DIRECTORY}, "unsafe_tool_path", "Tool destinations are fixed reviewed directories.")
    digest, _ = hash_file(archive, limit=MAX_ARCHIVE, size=item["bytes"])
    require(digest == item["sha256"], "tool_hash_mismatch", "Archive checksum changed before extraction.")
    zip_preflight(archive)
    expected = {m["name"]: m for m in item["members"]}
    destination = root / item["destination"]
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    # mkdir(parents=True) uses default modes for intermediate paths: make this
    # fresh owned subtree private, checking every component before file writes.
    for part in (destination, *destination.parents):
        if part == root.parent:
            break
        _path_chain(part)
        part.chmod(0o700)
        _owned(part, directory=True)
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        require(len(members) == len(expected) and {m.filename for m in members} == set(expected),
                "unsafe_tool_zip", "Archive contains missing, duplicate or unapproved files.")
        for info in members:
            pin = expected[info.filename]
            require(info.create_system == 3 and info.external_attr >> 16 == pin["archive_mode"]
                    and not info.flag_bits & 1 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    and info.file_size == pin["bytes"],
                    "unsafe_tool_zip", "Archive member type, mode, compression or size differs from its pin.")
        for info in members:
            pin = expected[info.filename]
            path = destination / info.filename
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            count, digest = 0, hashlib.sha256()
            with os.fdopen(descriptor, "wb") as output, package.open(info) as source:
                for raw in iter(lambda: source.read(CHUNK), b""):
                    count += len(raw)
                    require(count <= pin["bytes"], "tool_expansion_exceeded", "Expanded member exceeds its pinned byte count.")
                    budget.add(len(raw), expanded=True)
                    digest.update(raw)
                    output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            require(count == pin["bytes"] and digest.hexdigest() == pin["sha256"], "tool_member_mismatch", "Expanded member does not match its reviewed hash/size.")
            path.chmod(pin["mode"])


def _prepare_worker(run):
    lock = load_lock()
    root = run.file("private/toolchain")
    require(not root.exists(), "tool_cache_exists", "Tool preparation requires a fresh run-owned cache.")
    root.mkdir(mode=0o700)
    (root / "archives").mkdir(mode=0o700)
    budget = Budget()
    for item in lock["artifacts"]:
        archive = root / "archives" / item["filename"]
        download(item, archive, budget)
        extract(item, archive, root, budget)
    manifest = run.manifest()
    receipt = {"schema_version": "1.0", "operation": "terraform-toolchain-preparation", "status": "prepared",
        "run_id": run.id, "source_revision": manifest["source_revision"], "source_dirty": manifest["source_dirty"],
        "lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(), "prepared_at": now(),
        "archive_bytes": budget.archives, "expanded_bytes": budget.expanded,
        "cache_bytes": budget.archives + budget.expanded, "cache_bytes_excludes_bounded_receipt": True,
        "archives": [{"path": "archives/" + i["filename"], "sha256": i["sha256"], "bytes": i["bytes"]} for i in lock["artifacts"]],
        "members": [{"path": i["destination"] + "/" + m["name"], "sha256": m["sha256"], "bytes": m["bytes"], "mode": m["mode"]}
                    for i in lock["artifacts"] for m in i["members"]],
        "verification": {i["kind"]: i["signed_metadata"] for i in lock["artifacts"]},
        "provider_h1": lock["provider_h1"], "downloaded_binaries_executed": False, "host_tools_installed": False}
    atomic_json(root / "receipt.json", receipt)


def validate_cache(run, lock):
    root = run.file("private/toolchain")
    _owned(root, directory=True)
    expected = {"receipt.json": None}
    for item in lock["artifacts"]:
        expected["archives/" + item["filename"]] = {**item, "mode": 0o400}
        for member in item["members"]:
            expected[item["destination"] + "/" + member["name"]] = member
    actual, directories, total = set(), set(), 0
    expected_directories = {p.as_posix() for name in expected for p in Path(name).parents if p != Path('.')}
    for folder, dirs, files in os.walk(root, followlinks=False):
        _owned(Path(folder), directory=True)
        for name in dirs:
            _owned(Path(folder) / name, directory=True)
            directories.add((Path(folder) / name).relative_to(root).as_posix())
        for name in files:
            path = Path(folder) / name
            relative = path.relative_to(root).as_posix()
            require(relative in expected, "unsafe_tool_cache", "Prepared cache contains an unexpected file.")
            actual.add(relative)
            pin = expected[relative]
            if pin is None:
                _owned(path)
                require(path.stat().st_size <= MAX_RECEIPT, "unsafe_tool_cache", "Tool receipt exceeds its byte bound.")
                total += path.stat().st_size
                continue
            require(os.name != "posix" or stat.S_IMODE(path.stat().st_mode) == pin["mode"], "unsafe_tool_cache", "Prepared tool mode differs from its private reviewed mode.")
            digest, size = hash_file(path, limit=MAX_CACHE, size=pin["bytes"])
            require(digest == pin["sha256"], "tool_hash_mismatch", "Prepared tool bytes do not match the parent's original lock.")
            total += size
    require(actual == set(expected) and directories == expected_directories and total <= MAX_CACHE,
            "unsafe_tool_cache", "Prepared cache is incomplete, has extra directories, or exceeds its disk policy.")
    receipt = read_json(root / "receipt.json")
    archive_bytes = sum(i["bytes"] for i in lock["artifacts"])
    expanded = sum(m["bytes"] for i in lock["artifacts"] for m in i["members"])
    manifest = run.manifest()
    require(set(receipt) == {"schema_version", "operation", "status", "run_id", "source_revision", "source_dirty",
            "lock_sha256", "prepared_at", "archive_bytes", "expanded_bytes", "cache_bytes", "cache_bytes_excludes_bounded_receipt",
            "archives", "members", "verification", "provider_h1", "downloaded_binaries_executed", "host_tools_installed"}
            and manifest["mode"] == "container-reference" and manifest["source_dirty"] is False
            and receipt["schema_version"] == "1.0" and receipt["status"] == "prepared"
            and receipt["operation"] == "terraform-toolchain-preparation"
            and receipt["run_id"] == run.id and receipt["source_revision"] == run.manifest()["source_revision"]
            and receipt["source_dirty"] is False and receipt["lock_sha256"] == hashlib.sha256(LOCK.read_bytes()).hexdigest()
            and receipt["archive_bytes"] == archive_bytes and receipt["expanded_bytes"] == expanded
            and receipt["cache_bytes"] == archive_bytes + expanded
            and receipt["cache_bytes_excludes_bounded_receipt"] is True
            and receipt["archives"] == [{"path": "archives/" + i["filename"], "sha256": i["sha256"], "bytes": i["bytes"]} for i in lock["artifacts"]]
            and receipt["members"] == [{"path": i["destination"] + "/" + m["name"], "sha256": m["sha256"], "bytes": m["bytes"], "mode": m["mode"]}
                    for i in lock["artifacts"] for m in i["members"]]
            and receipt["verification"] == {i["kind"]: i["signed_metadata"] for i in lock["artifacts"]}
            and receipt["provider_h1"] == lock["provider_h1"]
            and receipt["downloaded_binaries_executed"] is False and receipt["host_tools_installed"] is False,
            "invalid_tool_receipt", "Prepared tool receipt does not match this run and verified payload.")
    return {"root": root, "terraform": root / "bin/terraform", "mirror": root / "mirror",
            "archives": tuple(root / "archives" / i["filename"] for i in lock["artifacts"]), "receipt": receipt}


def prepare_toolchain(run):
    require(sys.platform.startswith("linux"), "linux_required", "Tool preparation supports the approved Linux provisioner host.")
    revision, dirty = source_identity()
    manifest = run.manifest()
    require(not dirty and manifest["mode"] == "container-reference" and manifest["source_revision"] == revision
            and manifest["source_dirty"] is False, "source_not_clean", "Tool preparation needs this exact clean real run source.")
    require(not run.file("private/toolchain").exists(), "tool_cache_exists", "Never retry opaquely into an old tool cache; preserve it and use a fresh run.")
    lock = load_lock()
    result = _run_process((sys.executable, "-c", WORKER, str(run.workspace), run.id), cwd=SOURCE_ROOT, timeout=TIMEOUT)
    atomic_bytes(run.file("private/toolchain-preparation.log"), result["log"], limit=65536)
    require(result["status"] != "timeout", "tool_preparation_timeout", "Absolute tool preparation deadline expired; partial private cache remains unaccepted.")
    require(result["status"] == "pass" and not result["log_truncated"], "tool_preparation_failed", "Bounded tool preparation failed; inspect its private diagnostic code.")
    require(source_identity() == (revision, False), "source_not_clean", "Tool source changed during preparation; cache remains unaccepted.")
    return validate_cache(run, lock)
