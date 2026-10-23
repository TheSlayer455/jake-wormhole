"""Credential-free recipe/policy tests; Docker allocations are mocked throughout."""
import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from images import runtime
from wormhole import admission, images
from wormhole.runs import create_run, read_json

SHA = "a" * 40
CONTAINER, NETWORK, IMAGE = "b" * 64, "c" * 64, "sha256:" + "d" * 64


def plan():
    mib = 1024 * 1024
    observation = {"schema_version": "1.0", "synthetic": True, "observed_at": admission.now(),
        "boot_id": "12345678-1234-4234-9234-123456789abc", "memory_total_bytes": 32 * 1024 * mib,
        "memory_available_bytes": 24 * 1024 * mib, "runtime_disk_free_bytes": 100 * 1024 * mib,
        "docker_disk_free_bytes": 100 * 1024 * mib, "cpu_count": 16, "load1": 1,
        "docker": {"server_version": "29.6.0", "cgroup_version": "2", "cgroup_driver": "systemd",
            "controllers": ["cpu", "memory", "pids"], "memory_limit": True, "swap_limit": True,
            "cpu_quota": True, "pids_limit": True},
        "workloads": {"running_count": 7, "cpu_cores": 0.75, "memory_bytes": 2 * 1024 * mib}}
    return admission.build_plan("smoke", observation)


def builder(labels, limits, mounts):
    c = limits["docker_create"]
    return {"Id": CONTAINER, "Config": {"Labels": labels, "User": "0:0", "Entrypoint": ["/bin/sh"],
            "Cmd": ["/recipe/assemble.sh", "target"]},
        "HostConfig": {"Memory": c["memory_bytes"], "MemorySwap": c["memory_swap_bytes"],
            "NanoCpus": c["nano_cpus"], "PidsLimit": c["pids_limit"],
            "LogConfig": {"Type": c["log_driver"], "Config": c["log_opts"]}, "Privileged": False,
            # Actual allowed-host Docker29 inspection uses CAP_ and '=' spellings.
            "ReadonlyRootfs": False, "CapDrop": ["ALL"], "CapAdd": ["CAP_" + x for x in images.BUILD_CAPS],
            "PidMode": "", "NetworkMode": NETWORK, "IpcMode": "private", "UTSMode": "",
            "SecurityOpt": ["no-new-privileges=true"]},
        "Mounts": [{"Type": "bind", "RW": False, "Destination": k, "Source": v} for k, v in mounts.items()],
        "State": {"Status": "created", "Running": False, "ExitCode": 0, "Pid": 1234}, "SizeRw": 12345}


class ImagePolicy(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_actual_docker29_absent_network_message_requires_exact_identity(self):
        run = create_run(self.root / 'runs', fixture=False, identity=(SHA, False))
        result = {'status': 'fail', 'returncode': 1, 'log_truncated': False,
                  'log': ('[]\nError response from daemon: network ' + NETWORK + ' not found\n').encode()}
        with images.docker_scope(run), patch.object(images, '_run_process', return_value=result):
            self.assertIsNone(images.inspect('network', NETWORK, missing=True))
            with self.assertRaises(images.ImageError): images.inspect('network', 'e' * 64, missing=True)
        result['log'] = b'Cannot connect to Docker daemon: network not found'
        with images.docker_scope(run), patch.object(images, '_run_process', return_value=result):
            with self.assertRaises(images.ImageError): images.inspect('network', NETWORK, missing=True)

    def test_api_failure_keeps_first_private_bounded_diagnostic_without_printing(self):
        run = create_run(self.root / 'runs', fixture=False, identity=(SHA, False))
        result = {'status': 'fail', 'returncode': 1, 'log_truncated': False,
                  'log': b'synthetic primary API diagnostic'}
        with images.docker_scope(run), patch.object(images, '_run_process', return_value=result):
            with self.assertRaises(images.ImageError): images.docker(('container', 'inspect', CONTAINER))
            result['log'] = b'synthetic secondary cleanup diagnostic'
            with self.assertRaises(images.ImageError): images.docker(('container', 'inspect', CONTAINER))
        self.assertEqual(run.file('private/docker-primary-failure.log').read_bytes(), b'synthetic primary API diagnostic')
        self.assertEqual(read_json(run.file('private/docker-primary-failure.json'))['command'], 'container')

    def test_pins_and_generated_inputs_are_consistent_and_bounded(self):
        lock = images.load_lock()
        expected = []
        for group, packages in lock["apt"]["packages"].items():
            expected.extend(f"{group} {name} {version}" for name, version in sorted(packages.items()))
        lines = (images.CONTEXT / "apt-packages.lock").read_text().splitlines()
        self.assertCountEqual([x for x in lines if x and not x.startswith("#")], expected)
        expected = [f'{w["project"]}=={w["version"]} --hash=sha256:{w["sha256"]}' for w in lock["helper_wheels"]]
        lines = (images.CONTEXT / "helper-requirements.lock").read_text().splitlines()
        self.assertCountEqual([x for x in lines if x and not x.startswith("#")], expected)
        self.assertEqual(len(expected), 9)
        self.assertEqual(lock["base"]["reference"].split("@", 1)[1], lock["base"]["platform_digest"])
        self.assertIn(lock["apt"]["base_url"], (images.CONTEXT / "assemble.sh").read_text())
        digest, files = images.recipe_identity()
        self.assertEqual(len(digest), 64)
        self.assertEqual(set(files), set(images.FILES))
        self.assertIn("not built", lock["execution_qualification"].lower())

    def test_download_hash_size_and_redirect_guards_do_not_write_rejected_bytes(self):
        raw = b"synthetic artifact"
        item = {"url": "https://files.pythonhosted.org/a.whl", "sha256": hashlib.sha256(raw).hexdigest()}
        class Response(io.BytesIO):
            def geturl(self):
                return item["url"]
        target = self.root / "wheel"
        self.assertEqual(images.fetch_artifact(item, target, opener=lambda *_a, **_k: Response(raw)), len(raw))
        self.assertEqual(target.read_bytes(), raw)
        target.unlink()
        with self.assertRaisesRegex(images.ImageError, "does not match"):
            images.fetch_artifact(item, target, opener=lambda *_a, **_k: Response(b"tampered"))
        self.assertFalse(target.exists())
        with patch.object(images, "MAX_DOWNLOAD", 4), self.assertRaises(images.ImageError):
            images.fetch_artifact(item, target, opener=lambda *_a, **_k: Response(raw))
        class Redirect(Response):
            def geturl(self):
                return "https://untrusted.invalid/a.whl"
        with self.assertRaises(images.ImageError):
            images.fetch_artifact(item, target, opener=lambda *_a, **_k: Redirect(raw))
        self.assertFalse(target.exists())

    def test_preparation_has_fixed_whole_worker_deadline_and_revalidates_parent_hash(self):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        lock = images.load_lock()
        raw = b"synthetic CA fixture"
        lock["apt"]["bootstrap_ca"]["sha256"] = hashlib.sha256(raw).hexdigest()
        def successful_worker(argv, **kwargs):
            self.assertEqual(argv[0], images.sys.executable)
            self.assertEqual(argv[-3:], (str(run.workspace), run.id, "target"))
            self.assertEqual(kwargs["cwd"], images.SOURCE_ROOT)
            self.assertEqual(kwargs["timeout"], 180)
            cache = run.file("private/image-artifacts"); cache.mkdir(mode=0o700)
            (cache / "wheels").mkdir(mode=0o700)
            images.atomic_bytes(cache / "bootstrap-ca.deb", raw)
            return {"status": "pass", "log": b"", "log_truncated": False}
        with patch.object(images, "_run_process", side_effect=successful_worker):
            cache = images.prepare_artifacts(run, lock, "target")
        self.assertEqual((cache / "bootstrap-ca.deb").read_bytes(), raw)
        other = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        def tampered_worker(*_args, **_kwargs):
            cache = other.file("private/image-artifacts"); cache.mkdir(mode=0o700)
            (cache / "wheels").mkdir(mode=0o700)
            images.atomic_bytes(cache / "bootstrap-ca.deb", b"tampered")
            return {"status": "pass", "log": b"", "log_truncated": False}
        with patch.object(images, "_run_process", side_effect=tampered_worker), self.assertRaises(images.ImageError) as caught:
            images.prepare_artifacts(other, lock, "target")
        self.assertEqual(caught.exception.code, "artifact_hash_mismatch")

    def test_preparation_timeout_never_accepts_worker_cache(self):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        with patch.object(images, "_run_process", return_value={"status": "timeout", "log": b"synthetic timeout", "log_truncated": False}), self.assertRaises(images.ImageError) as caught:
            images.prepare_artifacts(run, images.load_lock(), "target")
        self.assertEqual(caught.exception.code, "artifact_preparation_timeout")
        self.assertFalse(run.file("private/image-artifacts").exists())

    def test_only_plain_bounded_ed25519_public_input_is_accepted(self):
        blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
        key = "ssh-ed25519 " + base64.b64encode(blob).decode()
        self.assertEqual(runtime.public_key(key + " synthetic-comment\n"), key)
        for value in ('command="id" ' + key, key + "\n" + key, "ssh-rsa AAAA", "x" * 513,
                      "ssh-ed25519 AAAA", "ssh-ed25519 ###", key + " too many comments", None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(runtime.RuntimeFailure):
                runtime.public_key(value)

    def test_runtime_auth_input_is_bounded_and_refuses_symlinks(self):
        source = self.root / "input"
        source.write_bytes(b"x" * 513)
        with self.assertRaises(runtime.RuntimeFailure):
            runtime.bounded_input(source, limit=512)
        source.write_bytes(b"public")
        self.assertEqual(runtime.bounded_input(source, limit=512), b"public")
        if os.name == "posix":
            alias = self.root / "alias"
            alias.symlink_to(source)
            with self.assertRaises(runtime.RuntimeFailure):
                runtime.bounded_input(alias)

    def test_helper_doctor_names_missing_dependency_and_location(self):
        lock = images.load_lock()
        packages = {**lock["apt"]["packages"]["common"], **lock["apt"]["packages"]["helper"]}
        wheels = {w["project"]: w["version"] for w in lock["helper_wheels"]}
        original = Path.read_text
        def read(path, *args, **kwargs):
            if str(path).replace("\\", "/") == "/etc/os-release":
                return 'ID=ubuntu\nVERSION_ID="24.04"\n'
            if "cgroup" in str(path): raise OSError("synthetic unverified cgroup")
            return original(path, *args, **kwargs)
        def version(name):
            if name == "ansible-core": raise runtime.importlib.metadata.PackageNotFoundError(name)
            return wheels[name]
        def query(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, packages[argv[-1]].encode(), b"")
        with patch.object(runtime, "LOCK", images.CONTEXT / "images.lock.json"), patch.object(Path, "read_text", read), \
             patch.object(runtime.subprocess, "run", side_effect=query), patch.object(runtime.importlib.metadata, "version", side_effect=version), \
             patch.object(runtime.os, "geteuid", return_value=10001, create=True):
            result = runtime.doctor("helper")
        self.assertFalse(result["passed"])
        self.assertIn({"location": "helper", "component": "ansible-core", "code": "dependency_missing_or_mismatched"}, result["failures"])
        self.assertFalse(result["production_iso_eligible"])

    def test_builder_inspection_rejects_weakened_limits_privilege_and_mounts(self):
        limits = plan()["limits"]["build"]
        labels = {images.LABEL + ".role": "target", images.LABEL + ".run_id": "synthetic"}
        mounts = {"/recipe": "/owned/source/images", "/artifacts": "/owned/private/cache"}
        value = builder(labels, limits, mounts)
        def verify(candidate):
            images.verify_builder(candidate, identifier=CONTAINER, labels=labels, limits=limits, mounts=mounts, network=NETWORK)
        verify(value)
        changes = [("HostConfig", "Privileged", True), ("HostConfig", "MemorySwap", -1),
                   ("HostConfig", "NanoCpus", 0), ("HostConfig", "PidsLimit", 0),
                   ("HostConfig", "NetworkMode", "host"), ("HostConfig", "PidMode", "host"),
                   ("HostConfig", "CapAdd", ["SYS_ADMIN"]), ("Config", "User", ""),
                   ("Config", "Cmd", ["/unreviewed.sh"])]
        for section, key, new in changes:
            candidate = deepcopy(value); candidate[section][key] = new
            with self.subTest(key=key), self.assertRaises(images.ImageError):
                verify(candidate)
        candidate = deepcopy(value); candidate["Mounts"][0]["RW"] = True
        with self.assertRaises(images.ImageError):
            verify(candidate)
        candidate = deepcopy(value); candidate["Id"] = "e" * 64
        with self.assertRaises(images.ImageError):
            verify(candidate)

    def test_runtime_projections_are_readonly_scoped_and_have_no_host_ports(self):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        folder = run.file("private/target-input"); folder.mkdir(mode=0o700)
        (folder / "authorized_keys").write_text("synthetic public input")
        for role in ("target", "helper"):
            args = images.runtime_arguments(run, role, IMAGE, NETWORK, plan()["limits"][role])
            self.assertIn("--read-only", args)
            self.assertEqual(args[args.index("--network") + 1], NETWORK)
            self.assertEqual(args[args.index("--user") + 1], "0:0" if role == "target" else "10001:10001")
            self.assertNotIn("--privileged", args)
            self.assertNotIn("--publish", args)
            self.assertNotIn("--pid", args)
            self.assertNotIn("docker.sock", " ".join(args))
            self.assertNotIn("credentials", " ".join(args))
            self.assertIn("WORMHOLE_RUNTIME_TTL_SECONDS=" + str(plan()["limits"][role]["timeout_seconds"]), args)
        (folder / "private-key").write_text("not a real key")
        with self.assertRaises(images.ImageError):
            images.runtime_arguments(run, "target", IMAGE, NETWORK, plan()["limits"]["target"])

    def test_runtime_ttl_defaults_and_limits_and_non_pid1_dispatch(self):
        with patch.dict(runtime.os.environ, {}, clear=True):
            self.assertEqual(runtime.runtime_ttl("target"), 300)
            self.assertEqual(runtime.runtime_ttl("helper"), 600)
        for role, value in (("target", "301"), ("helper", "601"), ("target", "0"), ("helper", "-1"), ("helper", "NaN")):
            with patch.dict(runtime.os.environ, {"WORMHOLE_RUNTIME_TTL_SECONDS": value}), self.assertRaises(runtime.RuntimeFailure):
                runtime.runtime_ttl(role)
        with patch.object(runtime, "guard"), patch.object(runtime.os, "getpid", return_value=2), \
             patch.object(runtime, "execute_role", return_value=0) as execute, patch.object(runtime, "supervise") as supervise:
            self.assertEqual(runtime.main(["helper", "doctor"]), 0)
        execute.assert_called_once_with("helper", ["doctor"])
        supervise.assert_not_called()

    @unittest.skipUnless(os.name == "posix" and shutil.which("ssh-keygen"), "Requires existing POSIX ssh-keygen; never installed by tests")
    def test_auth_is_unique_per_run_private_and_not_exported(self):
        first = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        second = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        receipts = [images.create_auth(run) for run in (first, second)]
        self.assertNotEqual(receipts[0]["fingerprint"], receipts[1]["fingerprint"])
        for run, receipt in zip((first, second), receipts):
            key = run.file("private/credentials/id_ed25519")
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(run.file("private/credentials").stat().st_mode & 0o777, 0o700)
            self.assertEqual(run.file("private/target-input").stat().st_mode & 0o777, 0o755)
            self.assertEqual(run.file("private/target-input/authorized_keys").stat().st_mode & 0o777, 0o644)
            self.assertEqual({x.name for x in run.file("private/target-input").iterdir()}, {"authorized_keys"})
            self.assertNotIn("PRIVATE KEY", json.dumps(receipt))
            self.assertFalse(receipt["private_key_exported"])
            with self.assertRaises(images.ImageError):
                images.create_auth(run)

    def test_daemon_timeout_is_unknown_and_not_a_successful_client_kill(self):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        with images.docker_scope(run), patch.object(images, "_run_process", return_value={"status": "timeout"}), self.assertRaises(images.ImageError) as caught:
            images.docker(("commit", CONTAINER, "synthetic-local-tag"))
        self.assertEqual(caught.exception.code, "docker_request_unknown")

    def test_docker_uses_empty_run_config_fixed_socket_and_no_ambient_credentials(self):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        with self.assertRaises(images.ImageError): images.docker(("version",))
        result = {"status": "pass", "log": b"synthetic", "returncode": 0}
        with images.docker_scope(run), patch.object(images, "_run_process", return_value=result) as execute:
            images.docker(("version",))
        args = execute.call_args.args[0]
        self.assertEqual(args[:2], ("docker", "--config"))
        self.assertEqual(args[3:5], ("--host", images.SOCKET))
        self.assertEqual(read_json(Path(args[2]) / "config.json"), {"auths": {}})
        self.assertIsNone(images.DOCKER_CONFIG.get())

    def test_sampled_disk_guard_preserves_headroom_and_rejects_oversized_layers(self):
        config = plan()
        required = config["headroom"]["disk_mib"] * 1024 * 1024 + config["materialization"]["extra_disk_reserve_bytes"]
        with patch.object(images.shutil, "disk_usage", return_value=type("Usage", (), {"free": required})()):
            images.assembly_storage_guard(config, self.root, {"SizeRw": 1})
        with patch.object(images.shutil, "disk_usage", return_value=type("Usage", (), {"free": required - 1})()), self.assertRaises(images.ImageError) as caught:
            images.assembly_storage_guard(config, self.root, {"SizeRw": 1})
        self.assertEqual(caught.exception.code, "disk_headroom_lost")
        with patch.object(images.shutil, "disk_usage", return_value=type("Usage", (), {"free": required})()), self.assertRaises(images.ImageError):
            images.assembly_storage_guard(config, self.root, {"SizeRw": config["materialization"]["writable_layer_limit_bytes"] + 1})


@unittest.skipUnless(os.name == "posix", "Linux-only driver; all Docker operations mocked")
class BuildOrchestration(unittest.TestCase):
    setUp = ImagePolicy.setUp

    def test_actual_supervisor_timeout_terminates_and_reaps_fixed_child(self):
        marker = self.root / "timeout-child"
        script = '''import os, sys, time
from pathlib import Path
from images.runtime import supervise
def child():
    Path(sys.argv[1]).write_text(str(os.getpid()))
    time.sleep(10)
    return 0
raise SystemExit(supervise(child, .2, grace_seconds=.05))
'''
        result = subprocess.run([images.sys.executable, "-c", script, str(marker)], cwd=images.SOURCE_ROOT, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 124)
        with self.assertRaises(ProcessLookupError): os.kill(int(marker.read_text()), 0)

    def test_actual_supervisor_term_retains_143_and_reaps_fixed_child(self):
        marker = self.root / "term-child"
        script = '''import os, sys, time
from pathlib import Path
from images.runtime import supervise
def child():
    Path(sys.argv[1]).write_text(str(os.getpid()))
    time.sleep(10)
    return 0
raise SystemExit(supervise(child, 10, grace_seconds=.05))
'''
        process = subprocess.Popen([images.sys.executable, "-c", script, str(marker)], cwd=images.SOURCE_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < deadline: time.sleep(.01)
            self.assertTrue(marker.exists())
            process.terminate()
            process.communicate(timeout=3)
            self.assertEqual(process.returncode, 143)
            with self.assertRaises(ProcessLookupError): os.kill(int(marker.read_text()), 0)
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=2)

    def test_slow_progress_read_is_terminated_by_real_parent_deadline(self):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        # Only this test child's opener is replaced. No HTTP request is made.
        worker = '''import sys, time
from pathlib import Path
from wormhole import images
class Slow:
    def __init__(self, url): self.url = url
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def geturl(self): return self.url
    def read(self, limit):
        (Path(sys.argv[1]) / sys.argv[2] / "private" / "slow-read-entered").touch(mode=0o600)
        time.sleep(5)
        return b"synthetic unfinished download"
images.fetch_artifact.__kwdefaults__["opener"] = lambda url, **kwargs: Slow(url)
exec(images._PREPARE_WORKER)
'''
        started = time.monotonic()
        with patch.object(images, "_PREPARE_WORKER", worker), patch.object(images, "ARTIFACT_PREPARATION_TIMEOUT", 0.5), self.assertRaises(images.ImageError) as caught:
            images.prepare_artifacts(run, images.load_lock(), "target")
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(caught.exception.code, "artifact_preparation_timeout")
        self.assertTrue(run.file("private/slow-read-entered").is_file())
        self.assertFalse(run.file("private/image-artifacts/bootstrap-ca.deb").exists())

    def test_admission_entry_refusal_records_no_running_or_allocated_attempt(self):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        class Refusal:
            def __init__(self, *_args): pass
            def __enter__(self):
                raise admission.AdmissionError("capacity_refused", "Synthetic capacity refusal")
            def __exit__(self, *_args): pass
        with patch.object(images, "RUNS_ROOT", run.workspace), patch.object(images, "source_identity", return_value=(SHA, False)), \
             patch.object(admission, "AdmissionLease", Refusal), patch.object(images, "docker") as docker:
            with self.assertRaises(admission.AdmissionError): images.build_image(run, "target")
        docker.assert_not_called()
        receipt = read_json(run.file("evidence/image-build-target.json"))
        self.assertEqual(receipt["status"], "failed-before-allocation")
        self.assertEqual(receipt["failure_code"], "capacity_refused")

    def exercise(self, *, commit_timeout=False):
        run = create_run(self.root / "runs", fixture=False, identity=(SHA, False))
        cache = run.file("private/image-artifacts"); cache.mkdir(mode=0o700)
        config = plan(); config["synthetic"] = False
        recipe, hashes = images.recipe_identity()
        labels = images.expected_labels(run, "target", recipe, hashes["images.lock.json"])
        mounts = {"/recipe": str(images.CONTEXT.resolve()), "/artifacts": str(cache.resolve())}
        value = builder(labels, config["limits"]["build"], mounts)
        state = {"started": False, "polls": 0, "removed": False, "network_removed": False, "verified_stopped": False, 'committed': False}
        calls = []
        class Lease:
            def __init__(self, *_args):
                self.plan, self.finished, self.resources = config, False, []
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def set_phase(self, phase):
                calls.append(("phase", phase))
            def refresh(self):
                calls.append(("refresh",))
            def register_resource(self, *args):
                self.resources.append(args)
            def reconcile_resource(self, *args, **kwargs):
                calls.append(("reconcile", *args))
            def finish(self, **kwargs):
                self.finished = True
        lease = Lease()
        def inspect(kind, identifier, **kwargs):
            calls.append(("inspect", kind))
            if kind == "image":
                tag = 'jake-wormhole-target:run-' + run.id
                if identifier == tag and not state['committed']: return None
                if identifier in (IMAGE, tag):
                    return {"Id": IMAGE, "Size": 300000, "Architecture": "amd64", "Os": "linux",
                        'RepoTags': [tag], 'Parent': 'sha256:' + 'e' * 64,
                        "Config": {"Labels": labels, "User": "0:0", "Entrypoint": ["/usr/bin/python3", "/opt/wormhole/runtime.py", "target"]}}
                return {"Id": "sha256:" + "e" * 64, "Size": 100000, "Architecture": "amd64", "Os": "linux", "Config": {}}
            if kind == "network":
                return None if state["network_removed"] else {"Id": NETWORK, "Labels": {images.LABEL + ".run_id": run.id}, "Containers": {}}
            if state["removed"]:
                return None
            answer = deepcopy(value)
            if not state["started"]:
                state["verified_stopped"] = True
            else:
                state["polls"] += 1
                answer["State"].update(Status="running" if state["polls"] < 3 else "exited", Running=state["polls"] < 3)
            return answer
        def docker(args, **kwargs):
            args = list(args); calls.append(tuple(args[:2]))
            raw = b""
            if args[0] == "info": raw = str(self.root).encode()
            elif args[:2] == ["network", "create"]: raw = NETWORK.encode()
            elif args[0] == "create": raw = CONTAINER.encode()
            elif args[0] == "start":
                self.assertTrue(state["verified_stopped"])
                self.assertIn(("container", CONTAINER), lease.resources)
                state["started"] = True
            elif args[0] == "commit":
                if commit_timeout:
                    raise images.ImageError("docker_request_unknown", "Synthetic unknown commit outcome.")
                self.assertIn('--no-pause', args)
                state['committed'] = True
                raw = b'non-authoritative CLI diagnostic\n' + IMAGE.encode()
            elif args[0] == "rm": state["removed"] = True
            elif args[:2] == ["network", "rm"]: state["network_removed"] = True
            elif args[0] == "logs": raw = b"synthetic bounded assembly log"
            return {"status": "pass", "returncode": 0, "log": raw, "log_truncated": False}
        with patch.object(images, "RUNS_ROOT", run.workspace), patch.object(images, "source_identity", return_value=(SHA, False)), \
             patch.object(admission, "AdmissionLease", return_value=lease), patch.object(images, "prepare_artifacts", return_value=cache), \
             patch.object(images, "inspect", side_effect=inspect), patch.object(images, "docker", side_effect=docker), \
             patch.object(images, "cgroup_limits", return_value={"memory.max": "2147483648"}), \
             patch.object(images, "installed_record", return_value={"passed": True, "production_iso_eligible": False}), \
             patch.object(images.time, "sleep"):
            if commit_timeout:
                with self.assertRaises(images.ImageError): images.build_image(run, "target")
                result = read_json(run.file("evidence/image-build-target.json"))
            else:
                result = images.build_image(run, "target")
        return result, lease, state, calls

    def test_success_inspects_before_start_and_reconciles_exact_objects(self):
        result, lease, state, calls = self.exercise()
        self.assertTrue(lease.finished)
        self.assertTrue(state["removed"] and state["network_removed"])
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["daemon_materialization_cgroup_capped"])
        self.assertEqual(result["runtime_ssh_qualification"], "pending")
        self.assertFalse(result["production_iso_eligible"])
        self.assertIn(("image", IMAGE), lease.resources)

    def test_unknown_commit_keeps_admission_and_owned_state_for_reconciliation(self):
        result, lease, state, calls = self.exercise(commit_timeout=True)
        self.assertFalse(lease.finished)
        self.assertFalse(state["removed"] or state["network_removed"])
        self.assertEqual(result["status"], "unresolved")
        self.assertEqual(result["failure_code"], "docker_request_unknown")
        self.assertFalse(result["resources_reconciled"])
        self.assertTrue(result["builder_stopped_after_failure"])


if __name__ == "__main__":
    unittest.main()
