# Jake Wormhole

Private, container-only reference automation for verified source chunks, candidate-bound images, Terraform-managed targets, strict SSH/Ansible checks, native software inventories and attributable evidence.

WORM-002 through WORM-020 are Done under Jake's explicitly delegated normal Owner workflow. WORM-021 is In Progress; parent WORM-001 acceptance follows its completion. Refresh Minx before mutations: this source snapshot is not a claim lease. Engineering review and Owner-directed automated decisions are distinct from independent human review.

Latest actual scale qualification: twenty simultaneous stock Ubuntu targets at `825a594862b816401d4b963329e6242bd8ed8aeb`, Run `290ad14a-e6ec-4822-ae36-258d336ecc38`, 160 readiness pairs, 200 functional rows, 200 inventory rows and twenty full 123-package inventories. All 23 transient resources were removed, admission finished with no pending resources and the unrelated sentinel unchanged. Two point samples/CPU deltas are not guaranteed peaks. See [WORM-020](handoff/WORM-020-checkpoint.md).

Start with [AGENTS](AGENTS.md), [state](docs/STATE.md), [handoff](handoff/CURRENT.md), [architecture](docs/ARCHITECTURE.md) and [fidelity](docs/FIDELITY.md). The [historical matrix](docs/acceptance-matrix.md) indexes original tested commits/evidence hashes; it does not relabel earlier homelab results as final-source CI parity.

## Local verification

Use CPython 3.12.14 and Git. Application dependencies are standard-library-only; no pip installation is needed. Run from this checkout with an installed Python executable:

```text
python -m wormhole doctor
python scripts/verify_repository.py
python scripts/verify_acceptance_matrix.py
python -m unittest discover -s tests -v
```

These commands do not provision homelab resources. Platform skips stay explicit. Repository hygiene checks selected patterns/links, not every possible secret.

The [controlled parity runner](docs/CI-PARITY.md) adds a fixed seventeen-case
synthetic operation with safe diagnostics and explicit process failure. Use a
fresh clean checkout per mode; this is separate from actual container runs.

The legacy synthetic fixture is a separate limited operation. Use dedicated absolute storage outside Git/vault sync, substituting an actual workspace and returned UUID:

```text
python -m wormhole run --workspace WORKSPACE --fixture
python -m wormhole report RUN_UUID --workspace WORKSPACE
python -m wormhole verify RUN_UUID --workspace WORKSPACE
python -m wormhole cleanup RUN_UUID --workspace WORKSPACE
```

`run` without `--fixture` records an unsupported attempt and returns nonzero. Actual Linux operations use the [runtime CLI](docs/CLI.md), [pipeline](docs/PIPELINE.md), [private publisher](docs/PUBLICATION.md), [isolation](docs/ISOLATION.md) and [twenty-target operation](docs/TWENTY-TARGETS.md). Resource-allocating commands require the approved environment and current authority; documentation does not authorize arbitrary-machine execution.

Actual component records cover Ubuntu/UBI, separate optional PowerShell, one/five/twenty-target paths, candidate identity, native inventories, recovery and private local tested-byte publication. Generated inputs and synthetic assessment remain labeled. [WORM-021 evidence](handoff/WORM-021-checkpoint.md) records actual matching manual/GitHub parity and safe diagnostics from genuinely failed jobs. GitLab authorship is not execution. [Repository controls](docs/REPOSITORY.md) separates pushes, CI and unmerged draft PRs.

Production ISO eligibility is always false. No VM/ISO boot/install, scanner/STIG support, proprietary infrastructure repair, remote release or external-model orchestration is claimed.
