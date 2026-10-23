"""Local CLI. No command provisions targets, publishes bytes or executes imported text."""
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
    root = argparse.ArgumentParser(prog="python -m wormhole", description="Local contracts and an explicit synthetic fixture subset. The runtime pipeline is unfinished.")
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
        ("cleanup", "Remove only completed fixture-owned private local state; retain evidence."),
        ("publish-reference", "Refuse publication: qualification/publication are not implemented."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("run_id", help="Exact UUID returned by run.")
        command.add_argument("--workspace", default=workspace)
    return root


def main(arguments=None):
    options = parser().parse_args(arguments)
    try:
        if options.command == "doctor":
            value, status = doctor(), 0
        elif options.command == "run":
            run = create_run(options.workspace, fixture=options.fixture)
            with run.locked():
                value = execute_run(run)
            status = 0 if value["outcome"] == "passed" else 1
        else:
            run = Run(options.workspace, options.run_id)
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
        print(json.dumps(value, allow_nan=False, sort_keys=True, indent=2))
        return status
    except (RunError, ContractError) as error:
        print(json.dumps({"error": {"code": getattr(error, "code", "invalid_contract"), "message": str(error)}}, sort_keys=True))
        return 2
    except OSError:
        print(json.dumps({"error": {"code": "local_io_error", "message": "Local state could not be accessed safely; no infrastructure action occurred."}}))
        return 2
