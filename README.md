# Jake Wormhole

Private, container-only reference automation for source integrity, Terraform-managed targets, SSH/Ansible checks and attributable engineering evidence.

Minx tracks the work under [WORM-001](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-001). The local Python CLI, measured Linux admission, pinned Ubuntu target/helper images and strict SSH image qualification work. The Terraform adapter has performed an actual one-target apply and scoped destroy; its full acceptance suite is still being qualified. Functional Ansible checks and the candidate pipeline remain unfinished. A complete container pipeline is not yet available.

Start with [AGENTS.md](AGENTS.md), [current state](docs/STATE.md) and [handoff](handoff/CURRENT.md). The [fidelity record](docs/FIDELITY.md) separates actual behavior from planned or simulated capabilities. [Repository controls](docs/REPOSITORY.md) records publication and CI observations.

Use CPython 3.12.14, selected in `.python-version`, and Git. There are no third-party Python packages to install for this slice; [the lockfile](dependencies.lock.json) records selected dependencies and CI action revisions. Run these commands from this checkout with a real Python executable. On Windows, replace a Store alias with the installed Python executable if necessary.

```text
python -m wormhole doctor
python -m unittest discover -s tests -v
```

Create an explicitly synthetic local run in dedicated storage outside every Git checkout and vault synchronization path. For example, choose an absolute directory under your application-data storage. Replace `WORKSPACE` below with that path and `RUN_UUID` with the `run_id` printed by the run command:

```text
python -m wormhole run --workspace WORKSPACE --fixture
python -m wormhole report RUN_UUID --workspace WORKSPACE
python -m wormhole verify RUN_UUID --workspace WORKSPACE
python -m wormhole cleanup RUN_UUID --workspace WORKSPACE
```

The fixture executes fixed local stage adapters and records their actual outcomes. It does not provision targets or validate a candidate image. Its report remains labeled synthetic with production ISO eligibility false. `run` without `--fixture` records an unsupported attempt and returns nonzero until the required real stages exist. `publish-reference RUN_UUID --workspace WORKSPACE` also returns nonzero: publication is not implemented by this ticket. A fixture success cannot make publication eligible.

Cleanup retains the manifest and evidence and removes only private local state owned by the selected fixture run. It refuses unsupported resource ownership; it does not remove containers, other runs or a whole workspace. See [CLI and contract details](docs/CLI.md) for bounds and failure behavior.

Verify portable context and selected accidental private-state patterns separately:

```text
python scripts/verify_repository.py
```

This repository check is not a complete secret scanner or a Terraform/SSH/Ansible test.

Approved Linux image operations and their limits are documented in [IMAGES](docs/IMAGES.md) and [ADMISSION](docs/ADMISSION.md). Two fresh actual homelab SSH qualifications, version observations, negative trust/authentication checks and cleanup results are recorded in [WORM-005 evidence](handoff/evidence/WORM-005.json). These image checks do not establish Terraform or Ansible execution.

Container tests cannot establish that an ISO boots or installs, passes an operating-system STIG, or repairs another system. Production ISO eligibility remains false.
