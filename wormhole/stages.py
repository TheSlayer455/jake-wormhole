"""Developer-defined stages; imported records never select executable commands."""
from dataclasses import dataclass
import hashlib
import math
import os
import signal
import subprocess
import sys
import time

from .runs import ARTIFACTS, RunError, atomic_bytes, common, now, report_run

LOG_LIMIT = 65536
PAYLOAD = b"Wormhole synthetic fixture v1\n"
FIXTURE_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


@dataclass(frozen=True)
class Stage:
    name: str
    inputs: tuple
    outputs: tuple
    location: str
    timeout_seconds: float


STAGES = {name: Stage(name, (), (), location, 30) for name, location in (
    ("preflight", "local"), ("integrity", "local"), ("candidate", "local"),
    ("provisioning", "provisioner"), ("readiness", "helper"), ("tests", "helper"),
    ("svd", "helper"), ("assessment", "local"), ("evidence", "local"),
    ("gate", "local"), ("cleanup", "provisioner"), ("finalized-result", "local"))}
STAGES.update({
    "fixture-preflight": Stage("fixture-preflight", (), ("private/logs/fixture-preflight.log",), "local", 5),
    "fixture-integrity": Stage("fixture-integrity", (), ("private/logs/fixture-integrity.log", "evidence/test-results.json"), "local", 5),
})
_ADAPTERS = {
    "fixture-preflight": (sys.executable, "-I", "-c", "print('Synthetic fixture preflight; no runtime targets.')"),
    "fixture-integrity": (sys.executable, "-I", "-c", "import hashlib; assert hashlib.sha256(b'Wormhole synthetic fixture v1\\n').hexdigest() == '" + FIXTURE_SHA256 + "'; print('Synthetic fixture SHA256 passed.')"),
}
# Windows has no general process-tree executor here. Only these reviewed leaf
# Python adapters are supported; extending the mutable registry cannot opt in.
_WINDOWS_LEAF_ADAPTERS = frozenset(_ADAPTERS.values())


def stage_catalog():
    return [{"name": stage.name, "inputs": list(stage.inputs), "outputs": list(stage.outputs),
             "location": stage.location, "timeout_seconds": stage.timeout_seconds,
             "implemented": stage.name in _ADAPTERS, "synthetic": stage.name.startswith("fixture-")}
            for stage in STAGES.values()]


def _run_process(arguments, *, cwd, timeout, log_limit=LOG_LIMIT):
    """Absolute parent/pipe deadline; POSIX group ownership, Windows fixed leaves.

    This is not a sandbox for untrusted commands. Imported data never supplies argv.
    """
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or not 0.01 <= timeout <= 3600:
        raise RunError("invalid_timeout", "Stage timeouts must be finite and bounded.")
    if type(log_limit) is not int or not 0 <= log_limit <= LOG_LIMIT:
        raise RunError("invalid_log_bound", "The stage log bound is unsupported.")
    if os.name == "nt" and tuple(arguments) not in _WINDOWS_LEAF_ADAPTERS:
        return {"status": "unsupported", "returncode": None, "duration_seconds": 0,
                "error": "Windows supports only the two reviewed leaf fixture adapters; general process trees are unsupported.",
                "log": b"", "log_truncated": False}
    captured = bytearray()
    seen = 0
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "PATH") if key in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    started = time.monotonic()
    try:
        process = subprocess.Popen(arguments, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=os.name == "posix", close_fds=True, bufsize=0)
    except OSError:
        return {"status": "error", "returncode": None, "duration_seconds": time.monotonic() - started,
                "error": "The fixed stage adapter could not start.", "log": b"", "log_truncated": False}

    deadline = started + timeout
    timed_out, leftover_group = False, False
    error = None

    def terminate():
        # Reap our parent, and on POSIX terminate its group even when that parent
        # already exited while a descendant still holds the output pipe open.
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.wait(timeout=5)

    try:
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        eof = False
        while True:
            try:
                chunk = os.read(descriptor, 4096)
                if chunk:
                    seen += len(chunk)
                    captured.extend(chunk[:max(0, log_limit - len(captured))])
                else:
                    eof = True
            except BlockingIOError:
                chunk = None
            if time.monotonic() >= deadline:
                timed_out = True
                terminate()
                break
            if process.poll() is not None and eof:
                break
            if not chunk:
                time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        if os.name == "posix":
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                leftover_group = not timed_out
                terminate()
    except (OSError, subprocess.SubprocessError):
        error = "Stage output/deadline handling failed; owned adapter termination was requested."
        terminate()
    finally:
        # Unbuffered, nonblocking capture has no blocked reader thread or close lock.
        process.stdout.close()
    status = "timeout" if timed_out else "error" if error or leftover_group else "pass" if process.returncode == 0 else "fail"
    return {"status": status, "returncode": process.returncode,
            "duration_seconds": time.monotonic() - started,
            "error": "Stage deadline exceeded; owned adapter/process group terminated." if timed_out else error or ("Stage left an owned process group running; it was terminated." if leftover_group else None if status == "pass" else "The fixed stage adapter returned a nonzero exit status."),
            "log": bytes(captured), "log_truncated": seen > log_limit}


def execute_stage(name, run):
    if name not in STAGES:
        raise RunError("unsupported_stage", "The named stage is not registered.")
    stage = STAGES[name]
    record = {"name": name, "inputs": list(stage.inputs), "outputs": list(stage.outputs),
              "location": stage.location, "timeout_seconds": stage.timeout_seconds,
              "status": "unsupported", "duration_seconds": 0, "returncode": None,
              "log_bytes": 0, "log_truncated": False,
              "error": "This pipeline stage is not implemented by WORM-003."}
    if name not in _ADAPTERS:
        return record
    result = _run_process(_ADAPTERS[name], cwd=run.file("private"), timeout=stage.timeout_seconds)
    raw = result.pop("log")
    atomic_bytes(run.file("private/logs/" + name + ".log"), raw, limit=LOG_LIMIT)
    record.update(result, log_bytes=len(raw))
    return record


def execute_run(run):
    """Synthetic subset only, or one durable unsupported real-pipeline attempt."""
    manifest = run.manifest()
    if manifest["outcome"] != "running" or manifest["stages"]:
        raise RunError("run_not_fresh", "An attempt cannot be rerun or overwrite its recorded primary outcome.")
    base = common(manifest)
    records = {
        "inventory": {**base, "status": "unsupported", "targets": []},
        "test-results": {**base, "status": "unverified", "checks": []},
        "svd": {**base, "status": "unsupported", "targets": []},
        "assessment": {**base, "status": "unsupported", "synthetic": True, "policy_id": "fixture.reference-only", "findings": []},
        "release-decision": {**base, "status": "unsupported", "reference_eligible": False,
                             "production_iso_eligible": False, "reasons": ["Runtime pipeline and reference publication are not implemented."]},
    }
    try:
        names = ("fixture-preflight", "fixture-integrity") if manifest["mode"] == "fixture" else ("preflight",)
        for name in names:
            result = execute_stage(name, run)
            manifest["stages"].append(result)
            manifest["updated_at"] = now()
            run.save_manifest(manifest)
            if name == "fixture-integrity":
                records["test-results"].update(status="pass" if result["status"] == "pass" else "error", checks=[{
                    "check_id": "fixture-sha256", "target_id": None,
                    "status": "pass" if result["status"] == "pass" else "error", "required": True,
                    "expected": FIXTURE_SHA256, "observed": FIXTURE_SHA256 if result["status"] == "pass" else "not verified",
                    "evidence": [],
                }])
            if result["status"] != "pass":
                break
        manifest["outcome"] = "passed" if names and len(manifest["stages"]) == len(names) and all(item["status"] == "pass" for item in manifest["stages"]) else "failed"
    except (OSError, RunError):
        manifest["outcome"] = "failed"
        raise
    finally:
        for kind, value in records.items():
            run.save_artifact(kind, value)
        manifest["updated_at"] = now()
        run.save_manifest(manifest)
    return manifest


def verify_run(run):
    report = report_run(run)
    manifest, tests = report["manifest"], report["artifacts"]["test-results"]
    checks = tests["checks"]
    expected, actual = manifest["expected_checks"], [check["check_id"] for check in checks]
    if len(set(actual)) != len(actual) or set(expected) != set(actual):
        raise RunError("incomplete_checks", "Expected fixture check IDs do not match the recorded results.")
    if manifest["mode"] == "fixture":
        if manifest["profile"] != "fixture" or expected != ["fixture-sha256"] or [stage["name"] for stage in manifest["stages"]] != ["fixture-preflight", "fixture-integrity"]:
            raise RunError("incomplete_stages", "The declared fixture subset is incomplete.")
        for stage in manifest["stages"]:
            registered = STAGES.get(stage["name"])
            if registered is None or any(stage[key] != getattr(registered, key) for key in ("location", "timeout_seconds")) or stage["inputs"] != list(registered.inputs) or stage["outputs"] != list(registered.outputs):
                raise RunError("invalid_stage", "A stage contract differs from the fixed developer adapter.")
            if stage["status"] == "pass" and (stage["returncode"] != 0 or stage["error"] is not None):
                raise RunError("invalid_stage", "A passing fixture stage must have exit status zero and no error.")
        for check in checks:
            if check["check_id"] != "fixture-sha256" or check["target_id"] is not None or check["required"] is not True or check["expected"] != FIXTURE_SHA256 or check["evidence"] or check["status"] == "pass" and check["observed"] != FIXTURE_SHA256:
                raise RunError("invalid_fixture_result", "A fixture result differs from its declared synthetic check.")
        check_status = checks[0]["status"]
        if check_status not in {"pass", "error"} or tests["status"] != check_status or (manifest["stages"][-1]["status"] == "pass") != (check_status == "pass"):
            raise RunError("inconsistent_outcome", "The fixture check status contradicts its adapter or result summary.")
        artifacts = report["artifacts"]
        for kind in ("inventory", "svd"):
            if artifacts[kind]["status"] != "unsupported" or artifacts[kind]["targets"]:
                raise RunError("unsupported_claim", "The fixture cannot establish runtime inventory or SVD results.")
        assessment = artifacts["assessment"]
        if assessment["status"] != "unsupported" or assessment["synthetic"] is not True or assessment["policy_id"] != "fixture.reference-only" or assessment["findings"]:
            raise RunError("unsupported_claim", "The fixture cannot establish an assessment result.")
        decision = artifacts["release-decision"]
        if decision["status"] != "unsupported" or decision["reference_eligible"] is not False or decision["production_iso_eligible"] is not False:
            raise RunError("unsupported_claim", "The fixture cannot establish publication eligibility.")
    fixture_results_pass = tests["status"] == "pass" and all(check["status"] == "pass" and check["required"] for check in checks) and all(stage["status"] == "pass" for stage in manifest["stages"])
    if manifest["mode"] == "fixture" and (manifest["outcome"] not in {"passed", "failed"} or (manifest["outcome"] == "passed") != fixture_results_pass):
        raise RunError("inconsistent_outcome", "The fixture outcome contradicts its stage/check results.")
    if manifest["mode"] == "container-reference":
        if manifest["profile"] != "smoke" or expected or checks or manifest["outcome"] != "failed" or len(manifest["stages"]) != 1 or manifest["stages"][0]["name"] != "preflight" or manifest["stages"][0]["status"] != "unsupported":
            raise RunError("unsupported_claim", "No complete container-reference stage or profile is implemented.")
    fixture_passed = manifest["mode"] == "fixture" and manifest["outcome"] == "passed" and fixture_results_pass
    return {"run_id": run.id, "contracts_valid": True, "fixture_subset_passed": fixture_passed,
            "run_outcome": manifest["outcome"], "runtime_pipeline_complete": False,
            "reference_eligible": False, "production_iso_eligible": False}
