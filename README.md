Current WORM-019 qualification proves overlapping live coordinators with serialized
resource graphs, exact-source interrupted recovery and a publication interrupted
before both completion markers. All four declared cases passed at clean runtime
`973c24a4b9e196d8d3117a3b91d372bd0397394a`; actual twenty-target execution remains
WORM-020. See the [isolation checkpoint](handoff/WORM-019-checkpoint.md) and
[qualification operation](docs/ISOLATION.md). Refresh Minx for review decisions.

<!-- WORM-017 actual qualification 753b67d7e550218f28e2f765d3e3abf254c31656 -->
Current source-bound WORM-017 evidence qualifies the explicit one-container
Ubuntu/UBI generated/synthetic reference pipeline. The actual wrong expected
version remains failed/ineligible, while all three cases finished scoped cleanup.
See [current pipeline evidence](handoff/evidence/WORM-017.json). Earlier status
descriptions below are historical and may be superseded. Tested-byte publication,
twenty-target candidate execution and production ISO eligibility remain separate.

# Jake Wormhole

Private, container-only reference automation for source integrity, Terraform-managed targets, SSH/Ansible checks and attributable engineering evidence.

Minx tracks work under WORM-001. Completed components cover the CLI, Linux admission, real Terraform lifecycle, strict SSH/Ansible, scoped recovery, functional checks, five-target coordination, verified chunks, candidate binding, optional PowerShell, synthetic assessments, UBI/RPM containers, observed software inventories and the bounded combined reference pipeline. WORM-018 now has actual private tested-byte publication qualification for fresh Ubuntu and UBI runs, including duplicate refusal, truthful interrupted output and failed-run refusal. See [the publication checkpoint](handoff/WORM-018-checkpoint.md). WORM-002 through WORM-017 were completed under Jake's delegated Owner workflow; refresh Minx for later decisions. Twenty-target execution is unfinished. Production ISO eligibility remains false.

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

The fixture executes fixed local stage adapters and records their actual outcomes. It does not provision targets or validate a candidate image. Its report remains labeled synthetic with production ISO eligibility false. `run` without `--fixture` records an unsupported attempt and returns nonzero; the actual reference pipeline uses its separate documented entrypoint. `publish-reference RUN_UUID --workspace WORKSPACE` refuses a fixture workspace. Only an eligible actual reference Run on the fixed approved storage may publish through the [private publication operation](docs/PUBLICATION.md).

Cleanup retains the manifest and evidence and removes only private local state owned by the selected fixture run. It refuses unsupported resource ownership; it does not remove containers, other runs or a whole workspace. See [CLI and contract details](docs/CLI.md) for bounds and failure behavior.

Verify portable context and selected accidental private-state patterns separately:

```text
python scripts/verify_repository.py
```

This repository check is not a complete secret scanner or a Terraform/SSH/Ansible test.

Approved Linux image operations and their limits are documented in [IMAGES](docs/IMAGES.md) and [ADMISSION](docs/ADMISSION.md). Two fresh actual homelab SSH qualifications, version observations, negative trust/authentication checks and cleanup results are recorded in [WORM-005 evidence](handoff/evidence/WORM-005.json). These image checks do not establish Terraform or Ansible execution.

Container tests cannot establish that an ISO boots or installs, passes an operating-system STIG, or repairs another system. Production ISO eligibility remains false.
