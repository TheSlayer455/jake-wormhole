"""Container-only entrypoints. Keys exist only in per-run private tmpfs/mounts."""
import base64
import importlib.metadata
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time
from uuid import UUID

LOCK = Path("/opt/wormhole/images.lock.json")
RUNTIME = Path("/run/wormhole")
INPUT = Path("/run/input")


class RuntimeFailure(Exception):
    pass


def public_key(value):
    """One plain Ed25519 key, no authorized_keys options, commands or multiline input."""
    if not isinstance(value, str) or len(value) > 512 or "\n" in value.strip():
        raise RuntimeFailure("Invalid public-key input.")
    parts = value.strip().split()
    if len(parts) not in (2, 3) or parts[0] != "ssh-ed25519":
        raise RuntimeFailure("Only a plain Ed25519 public key is supported.")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise RuntimeFailure("Invalid public-key encoding.") from None
    expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
    if len(blob) != 51 or not blob.startswith(expected):
        raise RuntimeFailure("Invalid Ed25519 public-key structure.")
    return "ssh-ed25519 " + parts[1]


def guard(role):
    if not Path("/.dockerenv").is_file() or Path("/etc/wormhole/role").read_text().strip() != role:
        raise RuntimeFailure("Container role guard refused this execution location.")
    if any(Path(path).exists() for path in ("/var/run/docker.sock", "/run/docker.sock")):
        raise RuntimeFailure("Docker sockets are forbidden in validation/target containers.")
    if os.geteuid() != (10001 if role == "helper" else 0):
        raise RuntimeFailure("The image is running with the wrong configured user.")


def identity():
    value = os.environ.get("WORMHOLE_RUN_ID", "")
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except ValueError:
        raise RuntimeFailure("A canonical per-run identity is required.") from None
    return value


def ordinary(path, *, private=False):
    if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.is_file():
        raise RuntimeFailure("Runtime input must be an ordinary provisioned file with no symlink traversal.")
    info = path.stat()
    if info.st_nlink != 1 or (private and (info.st_uid != 10001 or stat.S_IMODE(info.st_mode) & 0o077)):
        raise RuntimeFailure("Private helper input needs UID10001 ownership and mode0600.")
    return path


def bounded_input(path, *, private=False, limit=16384):
    ordinary(path, private=private)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 1 <= len(raw) <= limit:
        raise RuntimeFailure("Runtime authentication input is empty or exceeds its byte bound.")
    return raw


def write_private(path, raw):
    if path.exists() or path.is_symlink():
        raise RuntimeFailure("Refusing to overwrite previous runtime state.")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def doctor(role):
    lock = json.loads(LOCK.read_text())
    checks, failures = {}, []
    checks["python"] = {"observed": sys.version.split()[0], "expected_series": "3.12", "passed": sys.version_info[:2] == (3, 12)}
    release = Path("/etc/os-release").read_text()
    checks["ubuntu"] = {"observed": "24.04" if 'VERSION_ID="24.04"' in release and "ID=ubuntu\n" in release else "unexpected", "passed": 'VERSION_ID="24.04"' in release and "ID=ubuntu\n" in release}
    packages = {**lock["apt"]["packages"]["common"], **lock["apt"]["packages"][role]}
    for name, expected in packages.items():
        result = subprocess.run(["dpkg-query", "--show", "--showformat=${Version}", name], capture_output=True, timeout=5)
        observed = result.stdout.decode("utf-8", errors="replace").strip()[:128]
        checks[name] = {"expected": expected, "observed": observed, "passed": result.returncode == 0 and observed == expected}
    if role == "helper":
        for wheel in lock["helper_wheels"]:
            name = wheel["project"]
            try:
                observed = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                observed = "missing"
            checks[name] = {"expected": wheel["version"], "observed": observed, "passed": observed == wheel["version"]}
    for name, check in checks.items():
        if not check["passed"]:
            failures.append({"location": role, "component": name, "code": "dependency_missing_or_mismatched"})
    resources = {}
    for field in ("memory.max", "cpu.max", "pids.max"):
        try:
            resources[field] = (Path("/sys/fs/cgroup") / field).read_text()[:128].strip()
        except OSError:
            resources[field] = "unverified"
    return {"role": role, "location": role, "uid": os.geteuid(), "checks": checks,
            "resources_observed": resources, "failures": failures, "passed": not failures,
            "production_iso_eligible": False, "runtime_pipeline_complete": False}


def target():
    identifier = identity()
    key = public_key(bounded_input(INPUT / "authorized_keys", limit=512).decode("ascii"))
    if RUNTIME.exists() or RUNTIME.is_symlink():
        raise RuntimeFailure("Target runtime directory must be fresh private tmpfs.")
    RUNTIME.mkdir(mode=0o755)
    (RUNTIME / "hostkeys").mkdir(mode=0o700)
    (RUNTIME / "auth").mkdir(mode=0o755)
    auth = RUNTIME / "auth" / "authorized_keys"
    write_private(auth, ("restrict " + key + "\n").encode())
    auth.chmod(0o644)  # Public material, readable during sshd's user privilege drop.
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
    hostkey = RUNTIME / "hostkeys" / "ssh_host_ed25519_key"
    result = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)], capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeFailure("Target runtime host-key generation failed.")
    fingerprint = subprocess.run(["ssh-keygen", "-l", "-f", str(hostkey) + ".pub"], capture_output=True, check=True, timeout=5).stdout.decode().split()[1]
    print(json.dumps({"location": "target", "run_id": identifier, "hostkey_fingerprint": fingerprint}), flush=True)
    os.execv("/usr/sbin/sshd", ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"])


def helper(arguments):
    if not arguments or arguments == ["doctor"]:
        result = doctor("helper")
        print(json.dumps(result, sort_keys=True))
        return 0 if result["passed"] else 1
    identity()
    if arguments[0] == "wait":
        if len(arguments) != 2 or not arguments[1].isdigit() or not 1 <= int(arguments[1]) <= 600:
            raise RuntimeFailure("Helper wait must have an explicit bounded 1..600-second duration.")
        # Explicit operator-owned diagnostic lifetime, not an agent scheduler.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        time.sleep(int(arguments[1]))
        return 0
    if arguments[0] not in {"ssh", "ansible", "ansible-playbook"}:
        raise RuntimeFailure("This entrypoint supports doctor, bounded wait, SSH and Ansible tooling only.")
    if RUNTIME.is_symlink():
        raise RuntimeFailure("Helper runtime storage cannot be a symlink.")
    if not RUNTIME.exists():
        RUNTIME.mkdir(mode=0o700)
    for name, private in (("id_ed25519", True), ("known_hosts", False)):
        raw = bounded_input(INPUT / name, private=private)
        destination = RUNTIME / name
        if destination.exists() or destination.is_symlink():
            if bounded_input(destination, private=True) != raw:
                raise RuntimeFailure("Existing helper authentication differs from this run's provisioned input.")
        else:
            write_private(destination, raw)
    os.environ.update(HOME=str(RUNTIME), ANSIBLE_LOCAL_TEMP=str(RUNTIME / "ansible"),
                      ANSIBLE_REMOTE_TEMP="/tmp/wormhole-ansible", TMPDIR="/tmp")
    os.execvp(arguments[0], arguments)


def main(arguments=None):
    args = list(sys.argv[1:] if arguments is None else arguments)
    role = args.pop(0) if args else ""
    try:
        if role not in {"target", "helper"}:
            raise RuntimeFailure("A supported image role is required.")
        guard(role)
        if args == ["doctor"]:
            value = doctor(role); print(json.dumps(value, sort_keys=True)); return 0 if value["passed"] else 1
        if role == "target":
            if args:
                raise RuntimeFailure("Target entrypoint arguments are unsupported.")
            target()
            return 0
        return helper(args)
    except (RuntimeFailure, OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"error": {"location": role, "code": "image_runtime_refused", "message": "Image runtime inputs, identity, dependencies or execution location failed validation."}}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
