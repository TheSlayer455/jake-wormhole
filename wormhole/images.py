"""Reviewed Ubuntu image assembly; Docker is controlled only on the trusted host.

No Dockerfile/BuildKit resource-limit equivalence is claimed. Assembly workloads
use capped ordinary containers. Pull/commit work in the existing shared daemon is
admitted overhead with finite client requests, not a hard-cgroup-capped daemon.
Unknown request outcomes deliberately retain the shared admission journal.
"""
import argparse
import base64
from contextlib import contextmanager
from contextvars import ContextVar
from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit

from .runs import (Run, RunError, SOURCE_ROOT, _owned, atomic_bytes, atomic_json, now,
                   read_json, source_identity)
from .stages import _run_process

INFRASTRUCTURE = Path("/srv/homelab/jake-wormhole/runtime/infrastructure")
RUNS_ROOT = Path("/srv/homelab/jake-wormhole/runtime/runs")
CONTEXT = SOURCE_ROOT / "images"
FILES = ("images.lock.json", "assemble.sh", "runtime.py", "sshd_config", "ssh_config",
         "apt-packages.lock", "helper-requirements.lock")
SOCKET = "unix:///var/run/docker.sock"
LABEL = "io.jake-wormhole"
BUILD_CAPS = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID")
TARGET_CAPS = ("SETGID", "SETUID", "SYS_CHROOT")
MAX_DOWNLOAD = 16 * 1024 * 1024
MAX_CACHE = 64 * 1024 * 1024
ARTIFACT_PREPARATION_TIMEOUT = 180
DOCKER_CONFIG = ContextVar("wormhole_image_docker_config", default=None)
_PREPARE_WORKER = """import sys
from wormhole.runs import Run
from wormhole.images import load_lock, _prepare_artifacts_worker
run = Run(sys.argv[1], sys.argv[2])
_prepare_artifacts_worker(run, load_lock(), sys.argv[3])
"""


class ImageError(RunError):
    pass


def require(value, code, message):
    if not value:
        raise ImageError(code, message)


def capability_names(value):
    """Docker may report either CHOWN or its equivalent CAP_CHOWN spelling."""
    require(value is None or type(value) is list and len(value) <= 64
            and all(type(v) is str and re.fullmatch(r'(?:CAP_)?[A-Z][A-Z_]*', v) for v in value),
            'unsafe_capabilities', 'Docker capabilities have an unsupported representation.')
    return {v.removeprefix('CAP_') for v in value or []}


def safe_bind(path):
    path = Path(path)
    require(path.is_absolute() and not any(x in str(path) for x in (",", "\n", "\r")),
            "unsafe_bind", "Image mounts need canonical absolute paths without CSV/control characters.")
    require(not any(item.is_symlink() for item in (path, *path.parents)), "unsafe_bind", "Image mounts cannot traverse symlinks.")
    return path.resolve()


def load_lock():
    value = json.loads((CONTEXT / "images.lock.json").read_text("utf-8"))
    require(value["schema_version"] == "1.0" and value["platform"] == "linux/amd64", "invalid_image_lock", "Unsupported image lock/platform.")
    require(re.fullmatch(r"docker.io/library/ubuntu@sha256:[a-f0-9]{64}", value["base"]["reference"]), "invalid_image_lock", "The base must be a pinned official Ubuntu platform manifest.")
    require(re.fullmatch(r"\d{8}T\d{6}Z", value["apt"]["snapshot"]), "invalid_image_lock", "An immutable Ubuntu snapshot is required.")
    return value


def recipe_identity():
    safe_bind(CONTEXT)
    records = {}
    for name in FILES:
        path = CONTEXT / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024,
                "unsafe_recipe", "The complete bounded reviewed recipe is required.")
        records[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return digest, records


def fetch_artifact(item, destination, *, opener=urllib.request.urlopen):
    parsed = urlsplit(item["url"])
    require(parsed.scheme == "https" and parsed.hostname in {"snapshot.ubuntu.com", "files.pythonhosted.org"}
            and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            "unsafe_artifact_url", "Only locked official Ubuntu/PyPI HTTPS artifacts are allowed.")
    require(re.fullmatch(r"[a-f0-9]{64}", item["sha256"]), "invalid_image_lock", "Artifact SHA256 is missing.")
    if destination.exists():
        require(not destination.is_symlink() and destination.stat().st_size <= MAX_DOWNLOAD,
                "unsafe_artifact", "The cached artifact is unsafe or oversized.")
        raw = destination.read_bytes()
    else:
        with opener(item["url"], timeout=30) as response:
            final = urlsplit(response.geturl())
            require(final.scheme == "https" and final.hostname == parsed.hostname,
                    "unsafe_artifact_url", "Artifact redirects cannot change the trusted origin.")
            raw = response.read(MAX_DOWNLOAD + 1)
        require(len(raw) <= MAX_DOWNLOAD, "artifact_too_large", "A locked artifact exceeds the download bound.")
        require(hashlib.sha256(raw).hexdigest() == item["sha256"], "artifact_hash_mismatch", "A downloaded artifact does not match its lock.")
        atomic_bytes(destination, raw, limit=MAX_DOWNLOAD)
    require(hashlib.sha256(raw).hexdigest() == item["sha256"], "artifact_hash_mismatch", "A cached artifact does not match its lock.")
    return len(raw)


def _prepare_artifacts_worker(run, lock, role):
    require(role in {"target", "helper"}, "invalid_image_role", "Only the two reviewed image roles are supported.")
    cache = run.file("private/image-artifacts")
    require(not cache.exists(), "artifact_cache_exists", "Each image attempt needs a fresh private artifact cache.")
    cache.mkdir(mode=0o700)
    total = fetch_artifact(lock["apt"]["bootstrap_ca"], cache / "bootstrap-ca.deb")
    (cache / "wheels").mkdir(mode=0o700)
    if role == "helper":
        for item in lock["helper_wheels"]:
            require(Path(item["filename"]).name == item["filename"] and re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", item["filename"]), "invalid_image_lock", "Wheel filenames must be plain locked basenames.")
            total += fetch_artifact(item, cache / "wheels" / item["filename"])
            require(total <= MAX_CACHE, "artifact_cache_too_large", "The locked artifact cache exceeds its total bound.")
    return cache


def prepare_artifacts(run, lock, role):
    """One absolute whole-cache deadline also bounds slow-progress HTTP reads.

    urllib's per-operation socket timeout is supplementary. The owned worker
    group is killed/reaped by the existing bounded process executor on expiry.
    Public artifact bytes stay in private bounded files, never captured stdout.
    """
    require(role in {"target", "helper"}, "invalid_image_role", "Only the two reviewed image roles are supported.")
    cache = run.file("private/image-artifacts")
    require(not cache.exists(), "artifact_cache_exists", "Each image attempt needs a fresh private artifact cache.")
    result = _run_process((sys.executable, "-c", _PREPARE_WORKER, str(run.workspace), run.id, role),
                          cwd=SOURCE_ROOT, timeout=ARTIFACT_PREPARATION_TIMEOUT)
    atomic_bytes(run.file("private/image-artifacts-preparation.log"), result["log"], limit=65536)
    require(result["status"] != "timeout", "artifact_preparation_timeout", "The absolute whole-cache preparation deadline expired; no Docker allocation is authorized.")
    require(result["status"] == "pass" and not result["log_truncated"], "artifact_preparation_failed", "Bounded artifact preparation failed; preserve partial private cache and use a fresh attempt.")
    _owned(cache, directory=True)
    wheels = cache / "wheels"
    _owned(wheels, directory=True)
    items = [(lock["apt"]["bootstrap_ca"], cache / "bootstrap-ca.deb")]
    if role == "helper":
        items.extend((item, wheels / item["filename"]) for item in lock["helper_wheels"])
    require({p.name for p in cache.iterdir()} == {"bootstrap-ca.deb", "wheels"}
            and {p.name for p in wheels.iterdir()} == {path.name for _, path in items[1:]},
            "unsafe_artifact_cache", "Prepared cache contains missing or unexpected files.")
    total = 0
    for item, path in items:
        _owned(path)
        with path.open("rb") as stream:
            raw = stream.read(MAX_DOWNLOAD + 1)
        require(len(raw) <= MAX_DOWNLOAD and hashlib.sha256(raw).hexdigest() == item["sha256"],
                "artifact_hash_mismatch", "Prepared artifact bytes do not match the parent's original lock/bounds.")
        total += len(raw)
    require(total <= MAX_CACHE, "artifact_cache_too_large", "Prepared cache exceeds its total bound.")
    return cache


@contextmanager
def docker_scope(run):
    """Empty run-owned config, never the operator's registry credentials/context."""
    folder = run.file("private/docker-config")
    if not folder.exists():
        folder.mkdir(mode=0o700)
        atomic_json(folder / "config.json", {"auths": {}})
    _owned(folder, directory=True)
    require(read_json(folder / "config.json") == {"auths": {}} and {p.name for p in folder.iterdir()} == {"config.json"},
            "unsafe_docker_config", "Docker needs an empty run-owned configuration without credentials or contexts.")
    token = DOCKER_CONFIG.set(str(safe_bind(folder)))
    try:
        yield
    finally:
        DOCKER_CONFIG.reset(token)


def docker_configuration():
    config = DOCKER_CONFIG.get()
    require(config is not None, "docker_config_missing", "Docker calls require an explicit private run-owned empty configuration scope.")
    return config


def docker(arguments, *, timeout=20, allow_missing=False):
    config = docker_configuration()
    result = _run_process(("docker", "--config", config, "--host", SOCKET, *arguments), cwd=SOURCE_ROOT, timeout=timeout)
    require(result["status"] != "timeout", "docker_request_unknown", "A Docker request exceeded its deadline; daemon outcome is unknown and admission must remain blocked.")
    if result["status"] != "pass":
        raw = result["log"]
        exact_missing_network = (len(arguments) == 3 and tuple(arguments[:2]) == ('network', 'inspect')
            and re.fullmatch(r'[a-f0-9]{64}', arguments[2]) is not None
            and re.search(rb'(?:^|\n)Error response from daemon: network ' + arguments[2].encode('ascii')
                          + rb' not found\r?\n?$', raw) is not None)
        if allow_missing and result["returncode"] == 1 and (exact_missing_network or any(message in raw for message in (b"No such image", b"No such container", b"No such network", b"No such object"))):
            return None
        raise ImageError("docker_api_failed", "A bounded local Docker request failed; inspect private evidence and reconcile exact owned resources.")
    return result


def inspect(kind, identifier, *, size=False, missing=False, timeout=20):
    arguments = [kind, "inspect"] + (["--size"] if size else []) + [identifier]
    result = docker(arguments, allow_missing=missing, timeout=timeout)
    if result is None:
        return None
    require(not result["log_truncated"], "docker_response_too_large", "Docker inspection exceeded its bounded response.")
    value = json.loads(result["log"])
    require(isinstance(value, list) and len(value) == 1, "invalid_docker_response", "Expected one exact Docker object.")
    return value[0]


def limits_arguments(limits):
    config = limits["docker_create"]
    return ["--memory", str(config["memory_bytes"]), "--memory-swap", str(config["memory_swap_bytes"]),
            "--cpus", format(config["nano_cpus"] / 1_000_000_000, ".6g"), "--pids-limit", str(config["pids_limit"]),
            "--log-driver", config["log_driver"], "--log-opt", "max-size=" + config["log_opts"]["max-size"],
            "--log-opt", "max-file=" + config["log_opts"]["max-file"], "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges=true", "--restart", "no"]


def runtime_arguments(run, role, image, network, limits, *, helper_wait=300):
    """Reviewed stopped-container projection for image qualification, not allocation.

    The trusted caller must journal intent, create stopped, inspect actual limits,
    then start. Runtime limits are never inherited from a committed image.
    """
    require(role in {"target", "helper"} and re.fullmatch(r"sha256:[a-f0-9]{64}", image)
            and re.fullmatch(r"[a-f0-9]{64}", network), "invalid_runtime_spec", "Exact image/network identities and a supported role are required.")
    user = "10001:10001" if role == "helper" else "0:0"
    ttl = limits["timeout_seconds"]
    require(type(ttl) is int and 1 <= ttl <= (300 if role == "target" else 600),
            "invalid_runtime_spec", "Runtime lifetime must stay inside its admitted role bound.")
    arguments = ["create", "--name", "wormhole-" + run.id + "-" + role, "--network", network,
                 "--user", user, "--read-only", *limits_arguments(limits),
                 "--env", "WORMHOLE_RUN_ID=" + run.id, "--env", "WORMHOLE_RUNTIME_TTL_SECONDS=" + str(ttl),
                 "--label", LABEL + ".run_id=" + run.id,
                 "--label", LABEL + ".role=" + role]
    uid = "10001" if role == "helper" else "0"
    arguments.extend(("--tmpfs", "/run:rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=" + uid + ",gid=" + uid,
                      "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777"))
    if role == "target":
        target_input = safe_bind(run.file("private/target-input"))
        require(target_input.is_dir() and {x.name for x in target_input.iterdir()} == {"authorized_keys"},
                "unsafe_auth_input", "Only the per-run public authorized key may be mounted into a target.")
        arguments.extend(("--mount", "type=bind,source=" + str(target_input) + ",target=/run/input,readonly,bind-propagation=rprivate"))
        for capability in TARGET_CAPS:
            arguments.extend(("--cap-add", capability))
    else:
        require(type(helper_wait) is int and 1 <= helper_wait <= 600, "invalid_runtime_spec", "Helper diagnostic lifetime must be bounded.")
        arguments.extend(("--tmpfs", "/run/input:rw,nosuid,nodev,noexec,size=64k,mode=0700,uid=10001,gid=10001"))
    arguments.append(image)
    if role == "helper":
        arguments.extend(("wait", str(helper_wait)))
    return arguments


def create_auth(run):
    """Generate fresh run-owned client credentials; never print their contents."""
    require(os.name == "posix", "private_acl_unverified", "Private image-auth generation currently requires verified POSIX0700/0600 storage.")
    require(run.manifest()["mode"] == "container-reference", "run_scope_mismatch", "Real image authentication cannot use a synthetic fixture run.")
    with run.locked():
        folder = run.file("private/credentials")
        _owned(folder, directory=True)
        key = folder / "id_ed25519"
        require(not any(folder.iterdir()) and not run.file("private/target-input").exists(),
                "auth_exists", "Authentication cannot overwrite or reuse a prior run's private material.")
        require(shutil.which("ssh-keygen") is not None, "dependency_missing", "location=host-auth: existing ssh-keygen is required; no host installation is performed.")
        result = _run_process(("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "wormhole-" + run.id, "-f", str(key)), cwd=folder, timeout=10)
        require(result["status"] == "pass", "auth_generation_failed", "location=host-auth: per-run key generation failed; preserve partial private state.")
        key.chmod(0o600)
        public = key.with_name(key.name + ".pub")
        public.chmod(0o600)
        from images.runtime import public_key, RuntimeFailure
        with public.open("rb") as stream:
            raw = stream.read(513)
        try:
            safe_public = public_key(raw.decode("ascii"))
        except (RuntimeFailure, UnicodeError):
            raise ImageError("auth_generation_failed", "Generated public authentication did not pass its bounded Ed25519 validation.") from None
        digest = hashlib.sha256(base64.b64decode(safe_public.split()[1])).digest()
        fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
        target_input = run.file("private/target-input")
        target_input.mkdir(mode=0o700)
        atomic_bytes(target_input / "authorized_keys", (safe_public + "\n").encode())
        # This directory contains public material only. A container root with
        # all DAC capabilities dropped must also read keys owned by host UID1000.
        (target_input / "authorized_keys").chmod(0o644)
        target_input.chmod(0o755)
        record = {"run_id": run.id, "algorithm": "ed25519", "fingerprint": fingerprint,
                  "created_at": now(), "private_key_exported": False}
        atomic_json(folder / "auth.json", record)
        return record


def expected_labels(run, role, recipe, lock_sha):
    return {LABEL + ".run_id": run.id, LABEL + ".source_revision": run.manifest()["source_revision"],
            LABEL + ".role": role, LABEL + ".recipe_sha256": recipe, LABEL + ".lock_sha256": lock_sha}


def verify_builder(value, *, identifier, labels, limits, mounts, network):
    host, config = value["HostConfig"], value["Config"]
    expected = limits["docker_create"]
    require(value["Id"] == identifier and all(config.get("Labels", {}).get(k) == v for k, v in labels.items()), "ownership_mismatch", "Builder identity/labels differ from this exact run.")
    require(host["Memory"] == expected["memory_bytes"] and host["MemorySwap"] == expected["memory_swap_bytes"]
            and host["NanoCpus"] == expected["nano_cpus"] and host["PidsLimit"] == expected["pids_limit"],
            "limits_not_enforced", "Docker did not retain the admitted CPU/memory/swap/PID limits.")
    require(host["LogConfig"] == {"Type": expected["log_driver"], "Config": expected["log_opts"]}, "limits_not_enforced", "Rotated Docker log bounds differ from the admitted plan.")
    require(host["Privileged"] is False and host["ReadonlyRootfs"] is False and config["User"] == "0:0"
            and capability_names(host["CapDrop"]) == {"ALL"} and capability_names(host["CapAdd"]) == set(BUILD_CAPS)
            and host["PidMode"] == "" and host["NetworkMode"] == network
            and host.get("IpcMode") in ("", "private") and host.get("UTSMode", "") == "",
            "unsafe_builder", "Builder privilege or namespace settings differ from the reviewed recipe.")
    require(config["Entrypoint"] == ["/bin/sh"] and config["Cmd"] == ["/recipe/assemble.sh", labels[LABEL + ".role"]],
            "unsafe_builder", "The builder must execute only the reviewed fixed role recipe.")
    require(set(host.get("SecurityOpt") or []) in ({"no-new-privileges:true"}, {"no-new-privileges=true"}, {"no-new-privileges"}), "unsafe_builder", "Builder security confinement was changed.")
    actual = value["Mounts"]
    require(len(actual) == len(mounts) and all(item["Type"] == "bind" and item["RW"] is False and mounts.get(item["Destination"]) == item["Source"] for item in actual), "unsafe_builder", "Only the exact reviewed read-only recipe/artifact mounts are permitted.")


def cgroup_limits(pid, expected):
    require(type(pid) is int and pid > 0, "cgroup_unverified", "A live owned builder PID is needed for actual cgroup observation.")
    lines = (Path("/proc") / str(pid) / "cgroup").read_text().splitlines()
    unified = [line[3:] for line in lines if line.startswith("0::")]
    require(len(unified) == 1 and unified[0].startswith("/") and ".." not in Path(unified[0]).parts,
            "cgroup_unverified", "The owned builder has no supported unified cgroup path.")
    root = Path("/sys/fs/cgroup") / unified[0].lstrip("/")
    observed = {name: (root / name).read_text().strip() for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    quota, period = observed["cpu.max"].split()
    require(observed["memory.max"] == str(expected["memory_bytes"]) and observed["memory.swap.max"] == "0"
            and observed["pids.max"] == str(expected["pids_limit"]) and quota.isdigit() and period.isdigit()
            and int(period) > 0 and Fraction(int(quota), int(period)) == Fraction(expected["nano_cpus"], 1_000_000_000),
            "cgroup_unverified", "Actual builder cgroup bounds do not match the admitted limits.")
    return observed


def assembly_storage_guard(plan, storage, sized):
    """Sampled stop guard, not a Docker writable-layer quota or disk reservation."""
    reserve = plan["headroom"]["disk_mib"] * 1024 * 1024 + plan["materialization"]["extra_disk_reserve_bytes"]
    available = min(shutil.disk_usage(RUNS_ROOT).free, shutil.disk_usage(storage).free)
    require(available >= reserve, "disk_headroom_lost", "Shared disk headroom plus the materialization reserve is no longer available.")
    require(type(sized["SizeRw"]) is int and 0 <= sized["SizeRw"] <= plan["materialization"]["writable_layer_limit_bytes"],
            "writable_layer_too_large", "Sampled builder layer exceeds the admitted materialization ceiling.")


def installed_record(container):
    result = docker(("cp", container + ":/opt/wormhole/installed.json", "-"))
    require(not result["log_truncated"], "image_inspection_failed", "Installed tool identity record exceeded its bound.")
    with tarfile.open(fileobj=io.BytesIO(result["log"]), mode="r:*") as archive:
        members = archive.getmembers()
        require(len(members) == 1 and members[0].isfile() and members[0].name == "installed.json" and members[0].size <= 16384,
                "image_inspection_failed", "The installed tool identity record is not the expected bounded file.")
        value = json.loads(archive.extractfile(members[0]).read(16385))
    require(value.get("passed") is True and value.get("production_iso_eligible") is False,
            "image_dependency_failed", "Image-local dependency doctor failed; inspect its execution location.")
    return value


def build_image(run, role):
    with run.locked(), docker_scope(run):
        return _build_image_locked(run, role)


@contextmanager
def recorded_admission(lease_type, run, revision, receipt, destination):
    entered = False
    try:
        with lease_type(INFRASTRUCTURE, run.id, revision, "smoke") as lease:
            entered = True
            yield lease
    except BaseException as failure:
        if not entered:
            receipt.update(status="failed-before-allocation", failure_code=getattr(failure, "code", "admission_unavailable"),
                           finished_at=now(), resources_reconciled=False)
            atomic_json(destination, receipt)
        raise


def _build_image_locked(run, role):
    require(os.name == "posix" and role in {"target", "helper"}, "linux_required", "Real image assembly supports the reviewed Linux host and two fixed roles only.")
    require(run.workspace == RUNS_ROOT and run.manifest()["mode"] == "container-reference", "run_scope_mismatch", "Real image assembly needs its own canonical nonfixture run.")
    revision, dirty = source_identity()
    require(not dirty and run.manifest()["source_revision"] == revision and run.manifest()["source_dirty"] is False,
            "source_not_clean", "Build from the exact clean source revision recorded for this run.")
    try:
        from .admission import AdmissionLease
    except ImportError:
        raise ImageError("admission_unavailable", "Measured shared admission is unavailable; no Docker allocation is authorized.") from None
    lock = load_lock()
    recipe, hashes = recipe_identity()
    labels = expected_labels(run, role, recipe, hashes["images.lock.json"])
    receipt = {"schema_version": "1.0", "operation": "ubuntu-image-assembly", "role": role,
               "run_id": run.id, "source_revision": revision, "started_at": now(), "status": "pending",
               "base_reference": lock["base"]["reference"], "recipe_sha256": recipe, "source_files": hashes,
               "daemon_materialization_cgroup_capped": False, "production_iso_eligible": False,
               "runtime_pipeline_complete": False, "runtime_ssh_qualification": "pending"}
    destination = run.file("evidence/image-build-" + role + ".json")
    require(not destination.exists(), "image_attempt_exists", "Image attempts cannot overwrite their earlier evidence; use a fresh run UUID.")
    atomic_json(destination, receipt)
    allocation_requested = False
    container = None
    labels = expected_labels(run, role, recipe, hashes["images.lock.json"])
    with recorded_admission(AdmissionLease, run, revision, receipt, destination) as lease:
        try:
            require(lease.plan["synthetic"] is False and lease.plan["admitted"] is True, "synthetic_plan", "Synthetic plans never authorize real Docker allocation.")
            receipt.update(admission_observed_at=lease.plan["observations"]["observed_at"],
                           docker_server_version=lease.plan["observations"]["docker"]["server_version"],
                           docker_cgroup_version=lease.plan["observations"]["docker"]["cgroup_version"])
            cache = prepare_artifacts(run, lock, role)
            lease.set_phase("assembling")
            base = inspect("image", lock["base"]["reference"], missing=True)
            if base is None:
                # Pulls, like commits, run in the shared daemon; unknown completion
                # remains an active materialization intent, not automatic cleanup.
                lease.set_phase("materializing")
                allocation_requested = True
                docker(("pull", "--platform", "linux/amd64", lock["base"]["reference"]), timeout=lease.plan["materialization"]["client_timeout_seconds"])
                base = inspect("image", lock["base"]["reference"])
                lease.register_resource("image", base["Id"])
                lease.reconcile_resource("image", base["Id"], outcome="retained", size_bytes=base["Size"])
                lease.set_phase("assembling")
            require(base["Architecture"] == "amd64" and base["Os"] == "linux" and re.fullmatch(r"sha256:[a-f0-9]{64}", base["Id"]), "base_image_mismatch", "The pinned base is not the expected Linux amd64 image.")
            require(not base["Config"].get("Volumes"), "base_image_mismatch", "The base cannot allocate implicit anonymous volumes.")
            receipt["base_image_id"] = base["Id"]
            root_result = docker(("info", "--format", "{{.DockerRootDir}}"))
            storage = Path(root_result["log"].decode().strip())
            require(storage.is_absolute() and ".." not in storage.parts and storage.is_dir(), "disk_unverified", "The actual local Docker storage filesystem is unavailable.")
            network_name = "wormhole-" + run.id + "-image"
            allocation_requested = True
            result = docker(("network", "create", "--driver", "bridge", "--label", LABEL + ".run_id=" + run.id, network_name))
            network = result["log"].decode().strip()
            require(re.fullmatch(r"[a-f0-9]{64}", network), "unknown_allocation", "Network creation did not return one exact ID; preserve the journal.")
            lease.register_resource("network", network)
            lease.refresh()  # Network creation can consume time; remeasure before the next allocation.
            limits = lease.plan["limits"]["build"]
            mounts = {"/recipe": str(safe_bind(CONTEXT)), "/artifacts": str(safe_bind(cache))}
            arguments = ["create", "--name", "wormhole-" + run.id + "-" + role + "-build", "--network", network,
                         "--user", "0:0", "--entrypoint", "/bin/sh",
                         *limits_arguments(limits)]
            for capability in BUILD_CAPS:
                arguments.extend(("--cap-add", capability))
            for key, value in labels.items():
                arguments.extend(("--label", key + "=" + value))
            for target, source in mounts.items():
                arguments.extend(("--mount", "type=bind,source=" + source + ",target=" + target + ",readonly,bind-propagation=rprivate"))
            arguments.extend((lock["base"]["reference"], "/recipe/assemble.sh", role))
            result = docker(arguments)
            container = result["log"].decode().strip()
            require(re.fullmatch(r"[a-f0-9]{64}", container), "unknown_allocation", "Container creation did not return one exact ID; preserve the journal.")
            lease.register_resource("container", container)
            value = inspect("container", container)
            verify_builder(value, identifier=container, labels=labels, limits=limits, mounts=mounts, network=network)
            require(value["State"]["Status"] == "created" and not value["State"]["Running"], "unsafe_builder", "Builder must remain stopped until its settings are verified.")
            receipt.update(build_container_id=container, build_network_id=network, limits=limits)
            atomic_json(destination, receipt)
            deadline = time.monotonic() + limits["timeout_seconds"]
            docker(("start", container), timeout=min(20, limits["timeout_seconds"]))
            observed = None
            storage_checked_at = float("-inf")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    docker(("kill", container), timeout=10)
                    raise ImageError("assembly_timeout", "Owned assembly deadline exceeded; inspect/reconcile the stopped exact container before further allocation.")
                value = inspect("container", container, timeout=min(20, remaining))
                verify_builder(value, identifier=container, labels=labels, limits=limits, mounts=mounts, network=network)
                if not value["State"]["Running"]:
                    break
                if observed is None:
                    observed = cgroup_limits(value["State"]["Pid"], limits["docker_create"])
                    require(inspect("container", container)["State"]["Pid"] == value["State"]["Pid"], "cgroup_unverified", "Builder PID changed during cgroup observation.")
                if time.monotonic() >= deadline:
                    docker(("kill", container), timeout=10)
                    raise ImageError("assembly_timeout", "Owned assembly deadline exceeded; inspect/reconcile the stopped exact container before further allocation.")
                if time.monotonic() - storage_checked_at >= 2:
                    assembly_storage_guard(lease.plan, storage, inspect("container", container, size=True,
                        timeout=min(20, max(0.01, deadline - time.monotonic()))))
                    storage_checked_at = time.monotonic()
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            logs = docker(("logs", "--tail", "1000", container))
            atomic_bytes(run.file("private/image-build-" + role + ".log"), logs["log"], limit=65536)
            require(value["State"]["Status"] == "exited" and value["State"]["ExitCode"] == 0 and observed is not None,
                    "assembly_failed", "Image assembly failed or its actual cgroup bounds were not observed; inspect private builder logs.")
            receipt["tools"] = installed_record(container)
            sized = inspect("container", container, size=True)
            require(type(sized["SizeRw"]) is int and 0 <= sized["SizeRw"] <= lease.plan["materialization"]["writable_layer_limit_bytes"], "writable_layer_too_large", "Stopped builder layer exceeds the admitted materialization ceiling.")
            lease.set_phase("materializing")  # Refreshes actual shared headroom under the same lock.
            tag = "jake-wormhole-" + role + ":run-" + run.id
            python = "/opt/wormhole/venv/bin/python" if role == "helper" else "/usr/bin/python3"
            changes = ["USER " + ("10001:10001" if role == "helper" else "0:0"), "WORKDIR /home/wormhole",
                       "ENTRYPOINT " + json.dumps([python, "/opt/wormhole/runtime.py", role]), "CMD []",
                       'ENV PATH=/opt/wormhole/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                       'ENV PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1']
            command = ["commit", "--pause=false"]
            for change in changes:
                command.extend(("--change", change))
            command.extend((container, tag))
            committed = docker(command, timeout=lease.plan["materialization"]["client_timeout_seconds"])
            image = committed["log"].decode().strip()
            require(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "materialization_unknown", "Commit did not identify an exact image; keep the active journal for reconciliation.")
            lease.register_resource("image", image)
            result = inspect("image", image)
            require(all(result["Config"].get("Labels", {}).get(k) == v for k, v in labels.items())
                    and result["Architecture"] == "amd64" and result["Os"] == "linux"
                    and result["Config"]["Entrypoint"] == [python, "/opt/wormhole/runtime.py", role]
                    and result["Config"]["User"] == ("10001:10001" if role == "helper" else "0:0"),
                    "image_identity_mismatch", "Committed image configuration/provenance differs from the reviewed role.")
            lease.reconcile_resource("image", image, outcome="retained", size_bytes=result["Size"])
            lease.set_phase("reconciling")
            # Reinspect exact owned objects before deletion; never prune by prefix.
            verify_builder(inspect("container", container), identifier=container, labels=labels, limits=limits, mounts=mounts, network=network)
            docker(("rm", container))
            require(inspect("container", container, missing=True) is None, "cleanup_unverified", "Owned builder absence is unverified.")
            lease.reconcile_resource("container", container)
            net = inspect("network", network)
            require(net["Id"] == network and net.get("Labels", {}).get(LABEL + ".run_id") == run.id and not net["Containers"], "ownership_mismatch", "Owned build network labels or empty membership changed.")
            docker(("network", "rm", network))
            require(inspect("network", network, missing=True) is None, "cleanup_unverified", "Owned build network absence is unverified.")
            lease.reconcile_resource("network", network)
            leftovers = docker(("ps", "-a", "--no-trunc", "--filter", "label=" + LABEL + ".run_id=" + run.id, "--format", "{{.ID}}"))
            require(not leftovers["log"].strip(), "cleanup_unverified", "Run-labeled containers remain; preserve admission for reconciliation.")
            lease.finish(reconciliation_complete=True)
            receipt.update(status="completed", image_id=image, local_tag=tag, image_size_bytes=result["Size"],
                           writable_layer_bytes=sized["SizeRw"], builder_cgroups=observed,
                           assembly_log_truncated=logs["log_truncated"], finished_at=now(), resources_reconciled=True)
            atomic_json(destination, receipt)
            return receipt
        except BaseException as failure:
            # A known started builder must not keep executing after supervision
            # fails. Preserve its stopped state/logs for explicit recovery; never
            # infer that a timed-out commit/pull stopped inside the daemon.
            receipt["failure_code"] = getattr(failure, "code", "image_operation_interrupted")
            if container is not None:
                try:
                    current = inspect("container", container)
                    require(current["Id"] == container and all(current["Config"].get("Labels", {}).get(k) == v for k, v in labels.items()), "ownership_mismatch", "Failure cleanup cannot act on changed ownership.")
                    if current["State"]["Running"]:
                        docker(("kill", container), timeout=10)
                    receipt["builder_stopped_after_failure"] = inspect("container", container)["State"]["Running"] is False
                    failure_logs = docker(("logs", "--tail", "1000", container))
                    atomic_bytes(run.file("private/image-build-" + role + ".log"), failure_logs["log"], limit=65536)
                except (RunError, OSError, ValueError, KeyError):
                    receipt["builder_stopped_after_failure"] = "unverified"
            receipt.update(status="unresolved" if allocation_requested else "failed-before-allocation", finished_at=now(), resources_reconciled=False)
            atomic_json(destination, receipt)
            if not allocation_requested:
                lease.finish(reconciliation_complete=True)
            raise


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Admitted Ubuntu image assembly only; no runtime pipeline or public publication.")
    parser.add_argument("operation", choices=["build", "auth"])
    parser.add_argument("role", choices=["target", "helper"], nargs="?")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--workspace", default=str(RUNS_ROOT))
    options = parser.parse_args(arguments)
    try:
        if options.operation == "build" and options.role is None or options.operation == "auth" and options.role is not None:
            parser.error("build requires a role; auth does not take a role")
        run = Run(options.workspace, options.run_id)
        result = build_image(run, options.role) if options.operation == "build" else create_auth(run)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except Exception as error:
        print(json.dumps({"error": {"location": "host-image-assembly", "code": getattr(error, "code", "image_build_refused"), "message": str(error) if isinstance(error, RunError) else "Image assembly inputs/state failed validation; preserve the admission journal."}}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
