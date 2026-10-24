# Twenty-target stock inventory contract

WORM-020 extends the existing stock Ubuntu fleet path. This document describes
the new pure inventory records. Actual twenty-container execution, resource
measurements and cleanup need their own source-bound runtime evidence. The
records are not proof that those operations have happened.

The scope is one graph with `target-001` through `target-020`. Configured
controller concurrency is a separate integer from one through four. Twenty
serial smoke runs do not establish this scope. The qualified stock target image
and its original build Run/source remain explicit; no candidate hash or candidate
version is invented. The existing candidate SVD and reference pipeline contracts
remain separate.

## Frozen per-target records

[fleet_inventory_records.py](../wormhole/fleet_inventory_records.py) validates a
stock-only observation and result, then renders JSON and text from that same
validated record. Its public APIs are `validate_observation`, `observed_values`,
`validate_record`, `render_json`, `render_text` and `validate_index`; schema
functions return independent copies of the corresponding definitions.

Each record carries the current Run/source/plan identity, target namespace,
independently observed resource and image identity, original stock build Run and
source, recipe/runtime hashes, collector/helper/readiness source hashes, and the
complete native package observation. Debian full versions retain epochs,
revisions and architecture. Multiarch names remain native names. Package rows
must be sorted and unique by name/architecture. An inventory exceeding 32 KiB or
2,048 package rows is refused, never truncated into a complete-looking record.

Helper Python/Ansible and provisioner Terraform/provider versions are execution
provenance. They are not added to target packages. The kernel release is labeled
host-shared. Every JSON and text report retains those distinctions, full package
rows, failures and unverified checks.

Ten required checks remain present for every target: actual identity, userland,
complete package inventory, baked runtime hash and six pinned native packages.
The collector domain freezes the expected versions before execution. A missing
or ambiguous required package, wrong userland or runtime hash cannot pass.
Failed collection retains explicit unverified dependent rows; an unavailable
target identity cannot become a passing identity check.

## Capture and export boundaries

Five sequential batches of at most four target packets share the one live
twenty-target graph. A packet is bounded to 32 KiB; each complete batch response
is bounded to 256 KiB by the runtime/domain adapter. Per-target record metadata
binds the original complete capture hash/size and the canonical packet hash/size.
Logical references `captures/stock-inventory/batch-001` through `batch-005` are
not copied raw log files. The domain resolves them to fixed private captures.
Reports contain no raw capture, private key, Terraform state, environment or host
filesystem path. Pure validation performs no file reads or resource inspection.
The helper selects a fixed quiet stdout callback so native packets are not
duplicated into its 4 KiB diagnostic console. The aggregate callback's complete
target events and the actual Ansible exit status still decide success. Console
truncation, missing events and nonzero execution cannot become passing evidence.
Closed fields and narrow path/private-key-marker checks protect printable free
text as well; this is not a comprehensive secret scanner. Unexpected data is
refused rather than silently removed from an apparently complete inventory.

The domain writes each namespace as:

```text
evidence/fleet-inventory/targets/target-001/svd.json
evidence/fleet-inventory/targets/target-001/svd.txt
```

The compact index retains all twenty ordered namespaces, ten statuses per target,
literal JSON/text hashes and byte sizes, target count and configured concurrency.
It does not duplicate native packet contents. Any missing target/check, failed
target or unverified required row prevents a passing index. The domain must
replay original plans/captures and compare the actual exported bytes; an index
with structurally valid hashes is not itself an execution or replay proof.

The generated schemas describe the
[packet](../schemas/fleet-software-observation-v1.schema.json),
[per-target record](../schemas/fleet-software-inventory-v1.schema.json), and
[compact index](../schemas/fleet-software-inventory-index-v1.schema.json).
Complete pipeline and production ISO eligibility remain false. These records
do not establish VM boot/install, scanner/STIG acceptance, RPM applicability,
candidate-derived twenty-target validation or tested-byte publication.

## Verification

The focused synthetic contracts run without Docker, SSH or host changes:

```text
python -B -m unittest tests.test_fleet_inventory_records -v
python scripts/verify_repository.py
```

They verify same-record JSON/text, complete native values, packet/hash binding,
fixed target/check grids, explicit failed/unverified outcomes, typed flags,
bounds and namespace refusal. The actual Linux operator is explicit:

```text
python -B -m wormhole twenty-check --sentinel-id EXACT_APPROVED_CONTAINER_ID --concurrency 4
python -B -m wormhole twenty-report EXACT_RETURNED_RUN_UUID
python -B -m wormhole twenty-gate EXACT_RETURNED_RUN_UUID
```

Only the fixed approved Run/infrastructure stores are supported. The sentinel is
inspected read-only. Concurrency is an integer from one through four, independent
of the fixed twenty target count. One measured canonical admission owns the
twenty targets, network, provisioner and helper through exact cleanup. A refusal
or failed check returns nonzero and leaves actual scale qualification outstanding.
Preserve its returned Run UUID and original failure; do not retry an unknown
operation or overwrite its files.

The twenty-target readiness context is version 5 and records a shared 120-second
deadline. Creation, cleanup resume and offline replay bind that same policy in
both context and receipt. Smoke and five-target profiles retain their existing
90-second policy. Individual probe caps, target lifetime of 300 seconds, helper
wait of 300 seconds with its 600-second supervisor lifetime, and provisioner
lifetime of 600 seconds are unchanged. A shared deadline exhausted
before a target is attempted is distinct from observing a target never started.

After readiness, the first resource sample precedes full native inventory, then
functional validation and the second sample. Inventory requires more remaining
target lifetime, so it runs first. Existing per-stage deadlines and remaining
lifetime guards still refuse unsafe work; this order and the readiness budget
do not guarantee that a real graph will pass within its fixed lifetimes.

The operator retains full private stopped/live resource observations, original
Terraform plans/outputs, readiness packets and Ansible captures. Reporting
replays those originals after cleanup, including all 160 readiness pairs, 200
functional rows and 200 inventory rows. Exported per-target JSON/text must match
the replayed inventory bytes. A passing stock scale decision continues to set
reference and production ISO eligibility false.

Two identity-bound point samples span the checks for all 22 owned containers.
Cgroup usage/limits and CPU counter deltas, writable layer sizes, bounded log-tail
byte counts, Run logical file bytes and stage timings are observations. They do
not establish a guaranteed peak, disk quota or complete historical log size.
Finished admission must account for all 23 transient resources as absent before
the operator can pass. Actual execution evidence belongs in the ticket checkpoint;
source and fixture success alone do not establish that execution occurred.
