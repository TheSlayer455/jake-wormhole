# CLI and versioned operations

The separate [controlled parity CLI](CI-PARITY.md) documents the fixed manual/CI
runner, seventeen synthetic cases, fresh-output requirements and failure controls.

Use CPython 3.12.14 and Git. `python -m wormhole --help` describes this checkout. No pip dependencies are required. Commands/exits remain source-bound; a readable report can describe a failed gate.

## Local operations

| Command | Scope |
| --- | --- |
| `doctor` | Read-only local discovery; no provisioning/network |
| `run --workspace WORKSPACE --fixture` | Fresh UUID and bounded local synthetic preflight/SHA adapters |
| `run --workspace WORKSPACE` | Persist failed unsupported legacy attempt; does not select the real pipeline |
| `report RUN_UUID --workspace WORKSPACE` | Validate/read legacy fixture records |
| `verify RUN_UUID --workspace WORKSPACE` | Verify legacy identity/contracts/hashes |
| `cleanup RUN_UUID --workspace WORKSPACE` | Exact fixture private state only; retain manifest/evidence |

Use dedicated absolute storage outside Git/vault sync. Replace parameters with actual paths/UUIDs; never export a whole workspace. Windows permits reviewed fixture leaf adapters, not a generic process sandbox. POSIX adapters enforce process-group and absolute output-drain deadlines.

## Approved Linux operations

These commands can allocate resources or mutate the fixed private release store. They require current Minx authority, approved host/storage, measured admission and exact ownership. They are not arbitrary-machine quick-start steps.

```text
python -m wormhole reference-run --platform ubuntu
python -m wormhole reference-run --platform ubi --base-run QUALIFIED_BASE_RUN_UUID
python -m wormhole reference-report RUN_UUID --format json
python -m wormhole reference-report RUN_UUID --format text
python -m wormhole reference-report RUN_UUID --format junit
python -m wormhole reference-gate RUN_UUID
python -m wormhole publication-init
python -m wormhole publish-reference RUN_UUID
python -m wormhole publication-status RUN_UUID
python -m wormhole twenty-check --sentinel-id APPROVED_SENTINEL_ID --concurrency 4
python -m wormhole twenty-report RUN_UUID
python -m wormhole twenty-gate RUN_UUID
```

Reference smoke uses one candidate-bound Ubuntu/UBI target. UBI requires a qualified original base-probe Run. Controlled Ubuntu `--scenario version-expectation-mismatch` stays failed/ineligible. Twenty-check instead uses twenty stock targets with forks one through four, full native inventories and bounded resource samples; it does not publish a candidate reference.

`cancel`, `recover`, real `cleanup` and read-only `cleanup-status` delegate locking to their modules and require exact-source recovery proof. Cancellation is cooperative; expiry does not imply cleanup. Unknown outcomes block unsafe mutation. See [recovery](RECOVERY.md); do not silently reinterpret an old failed Run with a new controller.

Reference/twenty report and gate acquire the selected Run lock and replay original evidence without target allocation. Publication separately rechecks eligible source/bytes and consumers. Duplicate/incomplete destinations are not repaired or overwritten. Negative gates return nonzero; negative acceptance success does not make failed underlying work successful.

See [pipeline](PIPELINE.md), [publication](PUBLICATION.md), [twenty-targets](TWENTY-TARGETS.md), [native SVD](SOFTWARE-INVENTORY.md) and [historical matrix](acceptance-matrix.md). Component commands remain documented with their contracts. Legacy v1 flags retain their original meaning; limited reference scope has a separate complete-grid gate. Production ISO eligibility stays false.

## Verification and CI

```text
python scripts/verify_repository.py
python scripts/verify_acceptance_matrix.py
python -m unittest discover -s tests -v
```

Disposable tests require no Docker daemon or homelab credentials; platform skips are explicit. Original-source fixtures need Git history, so hosted checkout uses `fetch-depth: 0` with disabled credential persistence. WORM-021 controlled parity/wiring is being implemented and needs final evidence; historical CI success is not its result.
