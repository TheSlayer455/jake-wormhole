"""Local fixtures and explicitly scoped real-run recovery; no imported execution."""
import argparse
import json
from pathlib import Path
import shutil
import sys

from . import __version__
from .contracts import ContractError
from .runs import Run, RunError, cleanup_run, create_run, report_run, source_identity
from .stages import execute_run, stage_catalog, verify_run


def doctor():
    revision, dirty = source_identity()
    return {"application": "jake-wormhole", "version": __version__, "python": sys.version.split()[0],
            "source_revision": revision, "source_dirty": dirty,
            "private_permissions": "posix-0700-0600" if sys.platform != "win32" else "inherited-windows-acls-not-verified",
            "subprocess_scope": "posix-owned-process-group" if sys.platform != "win32" else "two-reviewed-leaf-fixture-adapters-only",
            "tools_found": {name: shutil.which(name) is not None for name in ("git", "docker", "terraform", "ssh", "ansible")},
            "mode": "local-discovery", "stages": stage_catalog(), "runtime_pipeline_complete": False,
            "reference_eligible": False, "production_iso_eligible": False}


def parser():
    root = argparse.ArgumentParser(prog="python -m wormhole", description="Private container reference automation and explicitly labeled local fixtures.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Read local source/tool presence without provisioning or network calls.")
    workspace = str(Path.home() / ".wormhole-runs")
    run = commands.add_parser("run", help="Persist an attempt; --fixture runs only the synthetic fixture subset.")
    run.add_argument("--workspace", default=workspace, help="Dedicated absolute storage outside Git and vaults.")
    run.add_argument("--fixture", action="store_true", help="Run only the labeled synthetic preflight/SHA256 subset.")
    for name, help_text in (
        ("report", "Read validated portable records; never export private logs/state."),
        ("verify", "Validate artifact identity and the declared fixture subset, not runtime eligibility."),
        ("cleanup", "Clean a completed fixture, or reconcile exact real-run infrastructure; retain evidence."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("run_id", help="Exact UUID returned by run.")
        command.add_argument("--workspace", default=workspace)
    from .images import RUNS_ROOT
    isolation = commands.add_parser("isolation-check", help="Run the fixed approved Linux isolation and interrupted-recovery acceptance cases.")
    isolation.add_argument("--sentinel-id", required=True, help="Exact already-approved unrelated container ID, inspected read-only.")
    commands.add_parser("publication-init", help="Initialize the fixed owned private local release store; refuse unrelated existing data.")
    publication = commands.add_parser("publish-reference", help="Publish exact eligible tested reference bytes to the fixed private local release store.")
    publication.add_argument("run_id", help="Exact eligible reference Run UUID.")
    publication.add_argument("--workspace", default=str(RUNS_ROOT), help="Only the fixed approved real-run storage is supported for publication.")
    inspection = commands.add_parser("publication-status", help="Verify an existing local reference release without repairing or rewriting it.")
    inspection.add_argument("run_id", help="Exact published reference Run UUID.")
    reference = commands.add_parser("reference-run", help="Run the bounded one-target container reference pipeline on approved Linux storage.")
    reference.add_argument("--platform", choices=("ubuntu", "ubi"), default="ubuntu")
    reference.add_argument("--scenario", choices=("healthy", "version-expectation-mismatch"), default="healthy")
    reference.add_argument("--base-run", help="Existing qualified public UBI base-probe UUID; required only for UBI.")
    for name in ("reference-report", "reference-gate"):
        command = commands.add_parser(name, help="Replay original reference evidence and retain explicit completeness failures.")
        command.add_argument("run_id", help="Exact existing reference Run UUID.")
        command.add_argument("--workspace", default=str(RUNS_ROOT))
        if name == "reference-report":
            command.add_argument("--format", choices=("json", "text", "junit"), default="json")
    for name, help_text in (
        ("cancel", "Request cooperative cancellation; the active coordinator acknowledges at a safe checkpoint."),
        ("recover", "Resume only exact owned real-run teardown, without new allocation."),
        ("cleanup-status", "Read the real run's recovery and pending-resource observations."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("run_id", help="Exact existing run UUID.")
        command.add_argument("--workspace", default=str(RUNS_ROOT))
    return root


def main(arguments=None):
    options = parser().parse_args(arguments)
    rendered = None
    try:
        if options.command == "doctor":
            value, status = doctor(), 0
        elif options.command == "run":
            run = create_run(options.workspace, fixture=options.fixture)
            with run.locked():
                value = execute_run(run)
            status = 0 if value["outcome"] == "passed" else 1
        elif options.command == "reference-run":
            from .images import RUNS_ROOT
            from .pipeline import PipelineSession, make_request
            run = create_run(RUNS_ROOT, fixture=False, kernel_lock=True)
            request = make_request(run, platform=options.platform, scenario=options.scenario, base_run_id=options.base_run)
            value = PipelineSession(run, request).execute()
            status = 0 if value.get("reference_eligible") is True else 1
        elif options.command == "isolation-check":
            from .isolation_acceptance import acceptance
            value = acceptance(options.sentinel_id)
            status = 0 if value.get("status") == "passed" else 1
        elif options.command == "publication-init":
            from .publication import initialize_publication_root
            value = initialize_publication_root()
            status = 0
        elif options.command == "publish-reference":
            from .images import RUNS_ROOT
            if Path(options.workspace) != RUNS_ROOT:
                raise RunError("publication_unsupported", "Publication supports only the approved real-run storage; synthetic fixtures cannot publish.")
            from .publication import publish_reference
            value = publish_reference(Run(RUNS_ROOT, options.run_id))
            status = 0
        elif options.command == "publication-status":
            from .publication import inspect_publication
            value = inspect_publication(options.run_id)
            status = 0 if value.get("status") == "complete" else 1
        elif options.command in {"reference-report", "reference-gate"}:
            from .pipeline import gate_pipeline, report_pipeline
            run = Run(options.workspace, options.run_id)
            with run.locked():
                if options.command == "reference-gate":
                    value = gate_pipeline(run)
                else:
                    report = report_pipeline(run)
                    value = report["record"]
                    rendered = report[options.format]
                    if isinstance(rendered, bytes):
                        rendered = rendered.decode("utf-8")
                status = 0 if value.get("reference_eligible") is True else 1
        else:
            run = Run(options.workspace, options.run_id)
            if options.command in {"cancel", "recover", "cleanup-status"} or (
                    options.command == "cleanup" and run.manifest()["mode"] == "container-reference"):
                from .recovery import inspect_recovery, recover_run, request_cancel
                # Cancellation must remain available while the coordinator owns
                # the Run lock. Recovery itself acquires the exact normal locks.
                if options.command == "cancel":
                    value, status = request_cancel(run), 0
                elif options.command == "cleanup-status":
                    value, status = inspect_recovery(run), 0
                else:
                    value = recover_run(run)
                    status = 0 if value["status"] == "completed" else 2 if value["status"] == "blocked" else 1
            else:
                with run.locked():
                    if options.command == "report":
                        value, status = report_run(run), 0
                    elif options.command == "verify":
                        value = verify_run(run)
                        status = 0 if value["fixture_subset_passed"] else 1
                    elif options.command == "cleanup":
                        value, status = cleanup_run(run), 0
                    else:
                        raise RunError("publication_unsupported", "Reference qualification/publication is not implemented; no bytes were published.")
        if rendered is None:
            print(json.dumps(value, allow_nan=False, sort_keys=True, indent=2))
        else:
            sys.stdout.write(rendered)
            if not rendered.endswith("\n"):
                sys.stdout.write("\n")
        return status
    except (RunError, ContractError) as error:
        failure = {"error": {"code": getattr(error, "code", "invalid_contract"), "message": str(error)}}
        if getattr(error, "run_id", None) is not None:
            failure["run_id"] = error.run_id
        print(json.dumps(failure, sort_keys=True))
        return 2
    except OSError:
        print(json.dumps({"error": {"code": "local_io_error", "message": "Local state could not be accessed safely; preserve the run and inspect its cleanup record before retrying."}}))
        return 2
