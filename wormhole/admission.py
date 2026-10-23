"""Linux-local measured admission and durable shared infrastructure ownership.

No operation in this module creates, starts, updates or deletes Docker resources.
Plans contain desired settings, not a claim that those settings were enforced.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys

from .runs import (RunError, _owned, _path_chain, atomic_json, now, read_json,
                   run_id as validate_run_id, workspace_path)
from .stages import _run_process

MIB = 1024 * 1024
PROJECT = "jake-wormhole"
MAX_RESOURCES = 256
PHASES = {"reserved", "assembling", "materializing", "provisioning", "validating", "reconciling"}
CONFIG = Path(__file__).resolve().parents[1] / "profiles" / "admission-v1.json"
CANONICAL_INFRASTRUCTURE_ROOT = Path("/srv/homelab/jake-wormhole/runtime/infrastructure")


class AdmissionError(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _require(condition, code="invalid_observation", message="Incomplete or invalid admission data."):
    if not condition:
        raise AdmissionError(code, message)


def _number(value, *, minimum=0, maximum=2**63 - 1, integer=False):
    return (type(value) is int if integer else type(value) in (int, float)) and minimum <= value <= maximum and math.isfinite(value)


def _keys(value, keys):
    return type(value) is dict and set(value) == set(keys)


def _load_config():
    value = json.loads(CONFIG.read_text("utf-8"))
    _require(_keys(value, {"schema_version", "planning_hypotheses", "headroom", "project_ceiling", "materialization", "profiles", "limits"}), "invalid_profile")
    _require(value["schema_version"] == "1.0" and value["planning_hypotheses"] is True, "invalid_profile")
    for key, fields in (("headroom", {"memory_mib", "disk_mib", "cpus"}),
                        ("project_ceiling", {"memory_mib", "disk_mib", "cpus", "pids"})):
        _require(_keys(value[key], fields) and all(_number(x, minimum=1, maximum=65536, integer=name != "cpus")
                                                  for name, x in value[key].items()), "invalid_profile")
    _require(set(value["profiles"]) == {"smoke", "five-targets", "twenty-targets"}, "invalid_profile")
    for name, count in (("smoke", 1), ("five-targets", 5), ("twenty-targets", 20)):
        profile = value["profiles"][name]
        _require(_keys(profile, {"target_count", "controller_concurrency", "build_concurrency"}), "invalid_profile")
        _require(type(profile["target_count"]) is int and profile["target_count"] == count and
                 _number(profile["controller_concurrency"], minimum=1, maximum=count, integer=True) and
                 type(profile["build_concurrency"]) is int and profile["build_concurrency"] == 1, "invalid_profile")
    _require(set(value["limits"]) == {"target", "helper", "provisioner", "build", "overhead"}, "invalid_profile")
    _require(_keys(value["materialization"], {"writable_layer_limit_mib", "extra_disk_reserve_mib", "shared_daemon_memory_reserve_mib", "client_timeout_seconds"}) and
             all(_number(x, minimum=1, maximum=4096, integer=True) for x in value["materialization"].values()), "invalid_profile")
    _require(value["materialization"]["client_timeout_seconds"] <= 600, "invalid_profile")
    fields = {"memory_mib", "disk_mib", "cpus", "pids_limit", "log_max_size_bytes", "log_max_files", "timeout_seconds"}
    for limits in value["limits"].values():
        _require(_keys(limits, fields), "invalid_profile")
        for key, number in limits.items():
            _require(_number(number, minimum=0.01 if key == "cpus" else 1,
                             maximum=65536 if key in {"memory_mib", "disk_mib", "pids_limit"} else 16 * MIB,
                             integer=key != "cpus"), "invalid_profile")
        _require(limits["timeout_seconds"] <= 3600 and limits["log_max_files"] <= 10, "invalid_profile")
    return value


def load_profile(name):
    config = _load_config()
    _require(type(name) is str and name in config["profiles"], "unknown_profile", "Choose smoke, five-targets or twenty-targets.")
    return {"profile": name, **deepcopy(config["profiles"][name]),
            "headroom": deepcopy(config["headroom"]), "project_ceiling": deepcopy(config["project_ceiling"]),
            "limits": deepcopy(config["limits"]), "materialization": deepcopy(config["materialization"])}


def _validate_observations(value):
    fields = {"schema_version", "synthetic", "observed_at", "boot_id", "memory_total_bytes", "memory_available_bytes",
              "runtime_disk_free_bytes", "docker_disk_free_bytes", "cpu_count", "load1", "docker", "workloads"}
    _require(_keys(value, fields) and value["schema_version"] == "1.0" and type(value["synthetic"]) is bool)
    validate_run_id(value["boot_id"])
    try:
        stamp = value["observed_at"]
        _require(type(stamp) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", stamp) is not None)
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(stamp.replace("Z", "+00:00"))).total_seconds()
        _require(-2 <= age <= 30, "stale_observation", "Refresh admission observations; they must be no more than 30 seconds old.")
    except (ValueError, TypeError):
        raise AdmissionError("invalid_observation", "The observation timestamp is invalid.") from None
    for name in ("memory_total_bytes", "memory_available_bytes", "runtime_disk_free_bytes", "docker_disk_free_bytes", "cpu_count"):
        _require(_number(value[name], minimum=1, integer=True))
    _require(value["memory_available_bytes"] <= value["memory_total_bytes"] and _number(value["load1"]))
    docker = value["docker"]
    _require(_keys(docker, {"server_version", "cgroup_version", "cgroup_driver", "controllers", "memory_limit", "swap_limit", "cpu_quota", "pids_limit"}))
    _require(type(docker["server_version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+.][A-Za-z0-9.-]+)?", docker["server_version"]) is not None)
    _require(docker["cgroup_version"] == "2" and type(docker["cgroup_driver"]) is str and docker["cgroup_driver"] in {"systemd", "cgroupfs"},
             "unsupported_cgroup", "This slice requires observed Docker cgroup v2 support.")
    _require(type(docker["controllers"]) is list and len(docker["controllers"]) <= 32 and
             all(type(x) is str for x in docker["controllers"]) and {"cpu", "memory", "pids"} <= set(docker["controllers"]))
    _require(all(docker[key] is True for key in ("memory_limit", "swap_limit", "cpu_quota", "pids_limit")),
             "unsupported_limits", "Required memory, swap, CPU and PID controls were not positively observed.")
    workloads = value["workloads"]
    _require(_keys(workloads, {"running_count", "cpu_cores", "memory_bytes"}) and
             _number(workloads["running_count"], integer=True, maximum=2000) and
             _number(workloads["memory_bytes"], integer=True) and _number(workloads["cpu_cores"]))


def _projection(value):
    memory = value["memory_mib"]
    cpus = format(value["cpus"], ".6g")
    logs = {"max-size": str(value["log_max_size_bytes"]), "max-file": str(value["log_max_files"])}
    return {**value,
        "docker_create": {"memory_bytes": memory * MIB, "memory_swap_bytes": memory * MIB,
            "nano_cpus": round(value["cpus"] * 1_000_000_000), "pids_limit": value["pids_limit"],
            "log_driver": "json-file", "log_opts": logs, "cap_drop": ["ALL"],
            "no_new_privileges": True, "read_only": True,
            "tmpfs": {"/run": "rw,nosuid,nodev,noexec,size=16m", "/tmp": "rw,nosuid,nodev,noexec,size=16m"}},
        "terraform": {"memory": memory, "memory_swap": memory, "cpus": cpus,
            "log_driver": "json-file", "log_opts": logs, "start": False, "must_run": False},
        "require_stopped_before_pid_enforcement": True}


def build_plan(profile, observations):
    """Pure capacity decision; this function reserves or allocates nothing."""
    name = profile if type(profile) is str else profile.get("profile") if type(profile) is dict else None
    selected = load_profile(name)
    try:
        unchanged = type(profile) is str or json.dumps(selected, sort_keys=True, allow_nan=False) == json.dumps(profile, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        unchanged = False
    _require(unchanged, "invalid_profile", "Use an unchanged reviewed profile.")
    _validate_observations(observations)
    limits, count = selected["limits"], selected["target_count"]
    runtime_counts = {"target": count, "helper": 1, "provisioner": 1, "overhead": 1}
    build_counts = {"build": selected["build_concurrency"], "provisioner": 1, "overhead": 1}
    def total(counts, field):
        return sum(limits[kind][field] * number for kind, number in counts.items())
    runtime_memory, build_memory = total(runtime_counts, "memory_mib"), total(build_counts, "memory_mib")
    runtime_cpu, build_cpu = total(runtime_counts, "cpus"), total(build_counts, "cpus")
    # Build outputs/cache can persist during target execution; disk is cumulative.
    materialization = selected["materialization"]
    _require(materialization["shared_daemon_memory_reserve_mib"] <= limits["overhead"]["memory_mib"], "invalid_profile")
    disk = total(runtime_counts, "disk_mib") + total(build_counts, "disk_mib") + materialization["extra_disk_reserve_mib"]
    requirements = {"runtime_memory_bytes": runtime_memory * MIB, "build_memory_bytes": build_memory * MIB,
        "peak_memory_bytes": max(runtime_memory, build_memory) * MIB,
        "runtime_cpus": runtime_cpu, "build_cpus": build_cpu, "peak_cpus": max(runtime_cpu, build_cpu),
        "disk_bytes": disk * MIB, "pids_peak": max(total(runtime_counts, "pids_limit"), total(build_counts, "pids_limit"))}
    ceiling, headroom = selected["project_ceiling"], selected["headroom"]
    failures = []
    checks = (
        (requirements["peak_memory_bytes"] <= ceiling["memory_mib"] * MIB, "project_memory_ceiling"),
        (requirements["disk_bytes"] <= ceiling["disk_mib"] * MIB, "project_disk_ceiling"),
        (requirements["peak_cpus"] <= ceiling["cpus"], "project_cpu_ceiling"),
        (requirements["pids_peak"] <= ceiling["pids"], "project_pid_ceiling"),
        (observations["memory_available_bytes"] >= requirements["peak_memory_bytes"] + headroom["memory_mib"] * MIB, "host_memory_headroom"),
        (min(observations["runtime_disk_free_bytes"], observations["docker_disk_free_bytes"]) >= requirements["disk_bytes"] + headroom["disk_mib"] * MIB, "host_disk_headroom"),
        (observations["cpu_count"] - max(observations["load1"], observations["workloads"]["cpu_cores"]) >= requirements["peak_cpus"] + headroom["cpus"], "host_cpu_headroom"),
    )
    failures.extend(code for passed, code in checks if not passed)
    return {"schema_version": "1.0", "profile": name, "target_count": count,
        "controller_concurrency": selected["controller_concurrency"], "build_concurrency": selected["build_concurrency"],
        "synthetic": observations["synthetic"], "observations": deepcopy(observations),
        "admitted": not failures, "refusal_reasons": failures, "requirements": requirements,
        "limits": {kind: _projection(value) for kind, value in limits.items()},
        "headroom": deepcopy(headroom), "planning_hypotheses": True, "limits_enforced": False,
        "materialization": {"writable_layer_limit_bytes": materialization["writable_layer_limit_mib"] * MIB,
            "extra_disk_reserve_bytes": materialization["extra_disk_reserve_mib"] * MIB,
            "shared_daemon_memory_reserve_bytes": materialization["shared_daemon_memory_reserve_mib"] * MIB,
            "client_timeout_seconds": materialization["client_timeout_seconds"],
            "daemon_operation_cgroup_capped": False, "unknown_result_blocks_admission": True},
        "builds_overlap_target_execution": False, "allocation_performed": False,
        "production_iso_eligible": False}


def _storage_path(value):
    path = Path(value).expanduser()
    _require(path.is_absolute() and ".." not in path.parts and path != Path(path.anchor), "unsafe_root", "Choose a dedicated absolute external infrastructure root.")
    _path_chain(path)
    for parent in (path, *path.parents):
        _require(not (parent / ".git").exists() and not (parent / ".obsidian").exists(), "unsafe_root", "Infrastructure state cannot be inside a checkout or vault.")
    return path.resolve()


def _read_command(arguments, cwd):
    result = _run_process(tuple(arguments), cwd=str(cwd), timeout=5)
    _require(result["status"] == "pass" and not result["log_truncated"], "observation_unavailable", "A bounded read-only Docker observation failed or exceeded its output bound.")
    try:
        return result["log"].decode("utf-8")
    except UnicodeError:
        raise AdmissionError("observation_unavailable", "Docker returned invalid observation text.") from None


def _memory_size(text):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*(B|kB|KB|KiB|MB|MiB|GB|GiB|TB|TiB)", text.strip())
    _require(match is not None, "observation_unavailable", "A workload memory observation could not be interpreted.")
    factors = {"B": 1, "kB": 1000, "KB": 1000, "KiB": 1024, "MB": 1000**2, "MiB": 1024**2,
               "GB": 1000**3, "GiB": 1024**3, "TB": 1000**4, "TiB": 1024**4}
    return round(float(match[1]) * factors[match[2]])


def collect_observations(infrastructure_root):
    """Read host and fixed local Docker metadata only; never return raw output."""
    _require(sys.platform.startswith("linux"), "linux_required", "Measured admission requires the Linux execution host.")
    path = _storage_path(infrastructure_root)
    while not path.exists():
        path = path.parent  # Disk for a proposed root, without creating it.
    fields = ("ServerVersion", "DockerRootDir", "OSType", "NCPU", "CgroupDriver", "CgroupVersion", "MemoryLimit", "SwapLimit", "CPUCfsQuota", "CPUCfsPeriod", "PidsLimit")
    template = "{" + ",".join(json.dumps(key) + ":{{json ." + key + "}}" for key in fields) + "}"
    docker = ("docker", "--host", "unix:///var/run/docker.sock")
    try:
        info = json.loads(_read_command((*docker, "info", "--format", template), path))
        _require(info["OSType"] == "linux" and _number(info["NCPU"], minimum=1, integer=True), "observation_unavailable")
        running = _read_command((*docker, "ps", "--no-trunc", "--format", "{{.ID}}"), path).splitlines()
        _require(len(running) <= 2000 and len(set(running)) == len(running) and all(re.fullmatch(r"[a-f0-9]{64}", x) for x in running), "observation_unavailable")
        records = []
        if running:
            text = _read_command((*docker, "stats", "--no-stream", "--no-trunc", "--format",
                '{"id":{{json .ID}},"cpu":{{json .CPUPerc}},"memory":{{json .MemUsage}}}'), path)
            records = [json.loads(line) for line in text.splitlines()]
        _require(len(records) == len(running) and {item["id"] for item in records} == set(running), "observation_changed", "Workloads changed during measurement; refresh before admission.")
        cpu, used_memory = 0.0, 0
        for item in records:
            _require(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?%", item["cpu"]) is not None, "observation_unavailable")
            cpu += float(item["cpu"][:-1]) / 100
            used_memory += _memory_size(item["memory"].split("/")[0])
        memory = {}
        for line in Path("/proc/meminfo").read_text("ascii").splitlines():
            match = re.fullmatch(r"(MemTotal|MemAvailable):\s+([0-9]+) kB", line)
            if match:
                memory[match[1]] = int(match[2]) * 1024
        storage = Path(info["DockerRootDir"])
        _require(storage.is_absolute() and ".." not in storage.parts, "observation_unavailable")
        result = {"schema_version": "1.0", "synthetic": False, "observed_at": now(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text("ascii").strip(),
            "memory_total_bytes": memory["MemTotal"], "memory_available_bytes": memory["MemAvailable"],
            "runtime_disk_free_bytes": shutil.disk_usage(path).free, "docker_disk_free_bytes": shutil.disk_usage(storage).free,
            "cpu_count": min(len(os.sched_getaffinity(0)), info["NCPU"]), "load1": os.getloadavg()[0],
            "docker": {"server_version": info["ServerVersion"], "cgroup_version": info["CgroupVersion"],
                "cgroup_driver": info["CgroupDriver"], "controllers": sorted(Path("/sys/fs/cgroup/cgroup.controllers").read_text("ascii").split()),
                "memory_limit": info["MemoryLimit"], "swap_limit": info["SwapLimit"],
                "cpu_quota": info["CPUCfsQuota"] is True and info["CPUCfsPeriod"] is True, "pids_limit": info["PidsLimit"]},
            "workloads": {"running_count": len(running), "cpu_cores": cpu, "memory_bytes": used_memory}}
        _validate_observations(result)
        return result
    except (KeyError, TypeError, ValueError, OSError, OverflowError):
        raise AdmissionError("observation_unavailable", "Required local host/Docker measurements are unavailable or malformed.") from None


def _sync_json(path, value):
    atomic_json(path, value)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _journal(value):
    _require(_keys(value, {"schema_version", "application", "run_id", "source_revision", "boot_id", "owner_pid", "state", "phase", "created_at", "updated_at", "plan", "resources"}), "invalid_journal")
    _require(value["schema_version"] == "1.0" and value["application"] == PROJECT and
             type(value["state"]) is str and value["state"] in {"active", "finished"} and
             type(value["phase"]) is str and value["phase"] in PHASES and
             _number(value["owner_pid"], minimum=1, integer=True), "invalid_journal")
    validate_run_id(value["run_id"])
    validate_run_id(value["boot_id"])
    _require(type(value["source_revision"]) is str and re.fullmatch(r"[a-f0-9]{40}", value["source_revision"]) is not None, "invalid_journal")
    _require(type(value["plan"]) is dict and value["plan"].get("admitted") is True and
             type(value["resources"]) is list and len(value["resources"]) <= MAX_RESOURCES, "invalid_journal")
    seen = set()
    for item in value["resources"]:
        _require(_keys(item, {"kind", "id", "outcome", "size_bytes"}), "invalid_journal")
        _resource_identity(item["kind"], item["id"])
        _require(type(item["outcome"]) is str and item["outcome"] in {"pending", "absent", "retained"} and _number(item["size_bytes"], integer=True), "invalid_journal")
        _require(item["outcome"] != "retained" or item["kind"] == "image", "invalid_journal")
        identity = (item["kind"], item["id"])
        _require(identity not in seen, "invalid_journal")
        seen.add(identity)
    _require(value["state"] != "finished" or all(x["outcome"] != "pending" for x in value["resources"]), "invalid_journal")
    return value


def _resource_identity(kind, identifier):
    _require(type(kind) is str and kind in {"container", "network", "image", "volume"} and type(identifier) is str,
             "invalid_resource", "Use an exact owned Docker resource identity.")
    pattern = r"sha256:[a-f0-9]{64}" if kind == "image" else r"[a-f0-9]{64}" if kind in {"container", "network"} else r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}"
    _require(re.fullmatch(pattern, identifier) is not None, "invalid_resource", "Use an exact owned Docker resource identity.")


class AdmissionLease:
    """One host-wide slot; caller must journal intent BEFORE any allocation.

    A trusted adapter must establish exact ID/labels and actual absence or retained
    image size before recording reconciliation. This library cannot infer Docker
    cleanup from caller exit, PID death, time passing or an empty recorded ID list.
    """
    def __init__(self, infrastructure_root, run_id, source_revision, profile="smoke", *, collector=collect_observations, allow_synthetic=False):
        self.root = _storage_path(infrastructure_root)
        self.run_id = validate_run_id(run_id)
        _require(type(source_revision) is str and re.fullmatch(r"[a-f0-9]{40}", source_revision) is not None, "invalid_source")
        self.source_revision, self.profile, self.collector = source_revision, profile, collector
        self.allow_synthetic = allow_synthetic is True
        _require(self.allow_synthetic or self.root == CANONICAL_INFRASTRUCTURE_ROOT,
                 "noncanonical_root", "Real infrastructure admission requires the fixed host-wide Wormhole runtime root.")
        self.descriptor = None
        self.plan = None
        self.record = None
        self.finished = False
        self._reconciliation_only = False
        self._lease_pid = None
        self._completion_archive = None

    @classmethod
    def resume(cls, infrastructure_root, run_id, source_revision, profile="smoke", *, allow_synthetic=False):
        """Reopen exactly one existing admission for adapter-proven cleanup only.

        This never refreshes capacity, initializes storage, adopts unknown IDs or
        clears uncertain daemon work. The caller still owes the same exact-ID,
        ownership and complete-outcome proof required by ordinary reconciliation.
        """
        lease = cls(infrastructure_root, run_id, source_revision, profile,
                    allow_synthetic=allow_synthetic)
        lease._reconciliation_only = True
        return lease

    def __enter__(self):
        _require(sys.platform.startswith("linux"), "linux_required", "Shared infrastructure leases require Linux flock.")
        import fcntl
        self.root = workspace_path(self.root, create=not self._reconciliation_only)
        lock = self.root / "infrastructure.lock"
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        self.descriptor = os.open(lock, flags if self._reconciliation_only else flags | os.O_CREAT, 0o600)
        try:
            _owned(lock)
            identity = os.fstat(self.descriptor)
            _require((identity.st_dev, identity.st_ino) == (lock.stat().st_dev, lock.stat().st_ino), "unsafe_lock")
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AdmissionError("infrastructure_busy", "Another process holds the infrastructure lock; no takeover is permitted.") from None
            _require((identity.st_dev, identity.st_ino) == (lock.stat().st_dev, lock.stat().st_ino), "unsafe_lock")
            self._lease_pid = os.getpid()
            marker = self.root / "owner.json"
            expected = {"application": PROJECT, "schema_version": "1.0", "kind": "shared-infrastructure-root"}
            if marker.exists():
                _require(read_json(marker) == expected, "ownership_mismatch")
            else:
                _require(not self._reconciliation_only, "ownership_mismatch", "Reconciliation requires an existing owned infrastructure root.")
                _require(all(x.name == "infrastructure.lock" for x in self.root.iterdir()), "ownership_mismatch", "Refusing an existing unowned infrastructure directory.")
                _sync_json(marker, expected)
            history = self.root / "history"
            if not history.exists():
                _require(not self._reconciliation_only, "invalid_archive", "Reconciliation requires the existing history directory.")
                history.mkdir(mode=0o700)
            _owned(history, directory=True)
            journal = self.root / "admission.json"
            if self._reconciliation_only:
                self.record = _journal(read_json(journal))
                self.plan = deepcopy(self.record["plan"])
                selected = load_profile(self.profile)
                _require(self.record["run_id"] == self.run_id and self.record["source_revision"] == self.source_revision and
                         self.plan.get("profile") == selected["profile"] and self.plan.get("synthetic") is self.allow_synthetic,
                         "resume_mismatch", "Reconciliation requires the exact current run, source, profile and real/synthetic mode.")
                _require(type(self.plan.get("requirements")) is dict and
                         _number(self.plan["requirements"].get("disk_bytes"), minimum=1, integer=True), "invalid_journal")
                archive = history / (self.run_id + ".json")
                if archive.exists():
                    self._completion_archive = self._matching_archive(read_json(archive))
                else:
                    _require(self.record["state"] == "active", "invalid_archive", "Finished admission requires its exact durable archive.")
                return self
            if journal.exists():
                previous = _journal(read_json(journal))
                _require(previous["run_id"] != self.run_id, "run_id_reused", "A previous admission run ID cannot be reused.")
                _require(previous["state"] == "finished", "unreconciled_run", "A previous run remains active or unreconciled. Explicit owned-resource recovery is required; expiry or PID death grants no takeover.")
                _require(read_json(history / (previous["run_id"] + ".json")) == previous,
                         "invalid_archive", "Completed admission requires its exact durable archive; preserve state for recovery.")
            _require(not (history / (self.run_id + ".json")).exists(), "run_id_reused", "A completed admission run ID cannot be reused.")
            observations = self.collector(self.root)
            self.plan = build_plan(self.profile, observations)
            _require(self.plan["synthetic"] is self.allow_synthetic, "synthetic_observation", "Synthetic leases require synthetic observations and cannot authorize real allocation.")
            _require(self.plan["admitted"], "capacity_refused", "The reviewed profile exceeds measured capacity or configured headroom; no resources were allocated.")
            timestamp = now()
            self.record = {"schema_version": "1.0", "application": PROJECT, "run_id": self.run_id,
                "source_revision": self.source_revision, "boot_id": observations["boot_id"], "owner_pid": os.getpid(),
                "state": "active", "phase": "reserved", "created_at": timestamp, "updated_at": timestamp,
                "plan": self.plan, "resources": []}
            self._save()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _active(self, *, finalizing=False):
        _require(self.descriptor is not None and self.record is not None and not self.finished,
                 "lease_inactive", "An active owned infrastructure lease is required.")
        _require(os.getpid() == self._lease_pid, "lease_owner_changed", "A forked or different process cannot use another process's lease.")
        lock = self.root / "infrastructure.lock"
        _owned(lock)
        identity = os.fstat(self.descriptor)
        _require((identity.st_dev, identity.st_ino) == (lock.stat().st_dev, lock.stat().st_ino), "unsafe_lock", "The stable infrastructure lock inode changed.")
        current = _journal(read_json(self.root / "admission.json"))
        _require(current == self.record, "journal_changed", "The active journal changed; preserve it and stop allocation.")
        archive = self.root / "history" / (self.run_id + ".json")
        if archive.exists():
            completed = self._matching_archive(read_json(archive))
            _require(self._completion_archive is None or self._completion_archive == completed, "invalid_archive", "The durable completion archive changed; preserve state for reviewed recovery.")
            self._completion_archive = completed
        else:
            _require(self._completion_archive is None, "invalid_archive", "The durable completion archive disappeared; preserve state for reviewed recovery.")
        _require(finalizing or self._completion_archive is None, "finalization_pending", "An archived completion can only be explicitly finalized.")

    def _save(self):
        self.record["updated_at"] = now()
        _journal(self.record)
        _sync_json(self.root / "admission.json", self.record)

    def set_phase(self, phase):
        self._active()
        _require(not self._reconciliation_only or phase == "reconciling", "reconciliation_only", "A resumed lease cannot enter an allocation or execution phase.")
        _require(type(phase) is str and phase in PHASES and phase != "reserved", "invalid_phase")
        current = self.record["phase"]
        allowed = {"reserved": {"assembling", "provisioning", "reconciling"},
                   "assembling": {"assembling", "materializing", "reconciling"},
                   "materializing": {"assembling", "materializing", "provisioning", "reconciling"},
                   "provisioning": {"provisioning", "validating", "reconciling"},
                   "validating": {"validating", "reconciling"}, "reconciling": {"reconciling"}}
        _require(phase in allowed[current], "invalid_phase", "Build and target phases cannot overlap or move backwards.")
        if phase == "assembling" or phase == "provisioning" and current != "provisioning":
            _require(not any(x["outcome"] == "pending" for x in self.record["resources"]),
                     "phase_resources_pending", "Reconcile the preceding phase's exact resources before starting another phase.")
        if phase in {"assembling", "materializing", "provisioning"}:
            self.refresh()
        self.record["phase"] = phase
        self._save()

    def refresh(self):
        """Remeasure before allocation; refusal keeps existing resources journaled."""
        self._active()
        _require(not self._reconciliation_only, "reconciliation_only", "A resumed lease cannot refresh or alter its admitted plan.")
        refreshed = build_plan(self.profile, self.collector(self.root))
        _require(refreshed["synthetic"] is self.allow_synthetic, "synthetic_observation")
        unchanged = ("profile", "target_count", "controller_concurrency", "build_concurrency", "requirements", "limits", "headroom", "materialization")
        _require(all(refreshed[key] == self.plan[key] for key in unchanged), "profile_changed", "The admitted profile changed during the run; stop new allocation.")
        _require(refreshed["admitted"], "capacity_refused", "Shared host capacity changed; stop new allocation and reconcile the existing owned resources.")
        self.plan = refreshed
        self.record["plan"] = refreshed
        self._save()
        return deepcopy(refreshed)

    def register_resource(self, kind, resource_id):
        self._active()
        _require(not self._reconciliation_only, "reconciliation_only", "A resumed lease cannot allocate or register additional resources.")
        phase = self.record["phase"]
        _require(phase in {"assembling", "materializing", "provisioning"}, "intent_required", "Journal the allocation phase before creating any resource.")
        _resource_identity(kind, resource_id)
        resources = self.record["resources"]
        _require(kind != "image" or phase == "materializing", "invalid_phase", "Record a materialization intent before committing an image.")
        if kind == "container":
            _require(phase in {"assembling", "provisioning"}, "invalid_phase")
            pending = sum(x["kind"] == "container" and x["outcome"] == "pending" for x in resources)
            bound = self.plan["build_concurrency"] if phase == "assembling" else self.plan["target_count"] + 2
            _require(pending < bound, "container_budget", "The phase container-count budget is exhausted.")
        _require(len(resources) < MAX_RESOURCES and not any(x["kind"] == kind and x["id"] == resource_id for x in resources), "resource_conflict")
        resources.append({"kind": kind, "id": resource_id, "outcome": "pending", "size_bytes": 0})
        self._save()

    def check_destroy_recovery_capacity(self, container_id):
        """Remeasure a retained controller's destroy-only recovery budget.

        This returns evidence, not allocation permission. The trusted Terraform
        adapter must separately verify this exact pending container's role,
        immutable image, complete mounts/configuration and bounded destroy-only
        command before restarting it. No new controller, phase, resource, plan or
        uncertain daemon result is adopted or changed by this check.
        """
        self._active()
        _require(self._reconciliation_only and self.record["phase"] == "reconciling",
                 "reconciliation_only", "Retained destroy recovery requires a resumed reconciling lease.")
        _resource_identity("container", container_id)
        _require(any(x["kind"] == "container" and x["id"] == container_id and x["outcome"] == "pending"
                     for x in self.record["resources"]), "ownership_mismatch",
                 "Only an existing exact pending controller can be considered for destroy recovery.")
        refreshed = build_plan(self.profile, self.collector(self.root))
        _require(refreshed["synthetic"] is self.allow_synthetic, "synthetic_observation")
        unchanged = ("profile", "target_count", "controller_concurrency", "build_concurrency",
                     "requirements", "limits", "headroom", "materialization")
        _require(all(refreshed[key] == self.plan[key] for key in unchanged), "profile_changed",
                 "Recovery must retain the original reviewed profile and limits.")
        _require(refreshed["admitted"], "capacity_refused",
                 "Insufficient current capacity to restart the retained bounded destroy controller.")
        return {"schema_version": "1.0", "operation": "retained-terraform-destroy-capacity",
                "run_id": self.run_id, "source_revision": self.source_revision,
                "container_id": container_id, "checked_at": now(), "plan": deepcopy(refreshed),
                "limits": deepcopy(self.plan["limits"]["provisioner"]),
                "allocation_permitted": False, "ownership_and_command_proof_required": True}

    def reconcile_resource(self, kind, resource_id, *, outcome="absent", size_bytes=0):
        self._active()
        _resource_identity(kind, resource_id)
        _require(type(outcome) is str and outcome in {"absent", "retained"} and _number(size_bytes, integer=True) and
                 (outcome != "retained" or kind == "image"), "invalid_reconciliation")
        found = [x for x in self.record["resources"] if x["kind"] == kind and x["id"] == resource_id]
        _require(len(found) == 1 and found[0]["outcome"] == "pending", "invalid_reconciliation")
        _require(outcome != "absent" or size_bytes == 0, "invalid_reconciliation")
        retained = sum(x["size_bytes"] for x in self.record["resources"] if x["outcome"] == "retained")
        _require(outcome != "retained" or 0 < size_bytes <= self.plan["requirements"]["disk_bytes"] - retained, "retained_image_budget")
        found[0].update(outcome=outcome, size_bytes=size_bytes)
        self._save()

    def _matching_archive(self, value):
        """Accept only this record's already-durable, complete final projection."""
        archive = _journal(value)
        expected = deepcopy(self.record)
        expected.update(state="finished", phase="reconciling", updated_at=archive["updated_at"])
        try:
            stamps = [datetime.fromisoformat(x.replace("Z", "+00:00")) for x in
                      (self.record["updated_at"], archive["updated_at"])]
            chronological = all(x.tzinfo is not None for x in stamps) and stamps[1] >= stamps[0]
        except (AttributeError, TypeError, ValueError):
            chronological = False
        _require(archive == expected and chronological and
                 (self.record["state"] != "finished" or archive == self.record),
                 "invalid_archive", "The completion archive does not exactly match this admission; preserve it for reviewed recovery.")
        return archive

    def finish(self, *, reconciliation_complete=False):
        self._active(finalizing=True)
        _require(reconciliation_complete is True, "reconciliation_required", "Explicit completed reconciliation is required; context exit never implies cleanup.")
        _require(all(x["outcome"] != "pending" for x in self.record["resources"]), "unreconciled_resources")
        archive = self.root / "history" / (self.run_id + ".json")
        if archive.exists():
            completed = self._matching_archive(read_json(archive))
        else:
            _require(self._completion_archive is None, "invalid_archive", "The durable completion archive disappeared; preserve state for reviewed recovery.")
            completed = deepcopy(self.record)
            completed.update(state="finished", phase="reconciling", updated_at=now())
            _journal(completed)
            _sync_json(archive, completed)
        _sync_json(self.root / "admission.json", completed)
        self.record = completed
        self.finished = True

    def __exit__(self, exc_type, exc, traceback):
        if self.descriptor is not None:
            os.close(self.descriptor)  # Stable inode remains; kernel releases flock.
            self.descriptor = None
        return False


def infrastructure_status(infrastructure_root):
    root = workspace_path(_storage_path(infrastructure_root))
    marker = read_json(root / "owner.json")
    _require(marker == {"application": PROJECT, "schema_version": "1.0", "kind": "shared-infrastructure-root"}, "ownership_mismatch")
    path = root / "admission.json"
    value = _journal(read_json(path)) if path.exists() else None
    return {"application": PROJECT, "admission": value, "allocation_performed": False, "production_iso_eligible": False}


def main(arguments=None):
    parser = argparse.ArgumentParser(prog="python -m wormhole.admission", description="Read-only measured capacity plans and shared-run journal status; never allocate Docker resources.")
    parser.add_argument("command", choices=("inspect", "plan", "status"))
    parser.add_argument("--infrastructure-root", required=True)
    parser.add_argument("--profile", choices=("smoke", "five-targets", "twenty-targets"), default="smoke")
    options = parser.parse_args(arguments)
    try:
        if options.command == "status":
            result = infrastructure_status(options.infrastructure_root)
        else:
            observed = collect_observations(options.infrastructure_root)
            result = observed if options.command == "inspect" else build_plan(options.profile, observed)
        print(json.dumps(result, allow_nan=False, sort_keys=True, indent=2))
        return 1 if result.get("admitted") is False else 0
    except (AdmissionError, RunError) as error:
        print(json.dumps({"error": {"code": error.code, "message": str(error)}}))
        return 2
    except (OSError, ValueError, TypeError):
        print(json.dumps({"error": {"code": "observation_unavailable", "message": "Admission state or required observations could not be read safely."}}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
