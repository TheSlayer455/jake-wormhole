# Scoped cleanup and cancellation (WORM-008)

These are normal product operations over one exact run. Source tests use
temporary owned state and mocked Docker/Terraform; live acceptance is a separate
operator record. No complete pipeline or production eligibility follows from
successful cleanup.

```text
python -m wormhole cancel EXACT_RUN_UUID
python -m wormhole cleanup-status EXACT_RUN_UUID
python -m wormhole recover EXACT_RUN_UUID
python -m wormhole cleanup EXACT_RUN_UUID
```

Use the original clean immutable checkout and canonical real run storage.
`recover` and real `cleanup` use the same recovery function and acquire the run's
existing kernel lock, empty Docker configuration scope and canonical
reconciliation-only admission lease. A busy lock refuses; PID death, lease age or
an empty list of returned IDs does not authorize takeover or journal reset.
Fixture cleanup keeps its older local-only semantics.

`cancel` atomically publishes one immutable request in that owned run without
taking its held run lock, sending PID signals or touching infrastructure. An
identical retry returns the same request. This is a request, not proof that the
coordinator acknowledged it or stopped a remote operation. The coordinator checks
`cancellation_requested(run)` at safe polling/stage boundaries. It records
cancellation, stops the exact helper through its adapter, then performs normal
Terraform cleanup. Generic process-group cancellation is not wired into mutating
Docker/Terraform requests: terminating a client cannot prove daemon completion.
A separate stable kernel publication lock serializes publishers; atomic rename
exposes a complete single-link file to readers. It never relaxes the global
hard-link check or unlinks the lock inode. Busy publication has a bounded retry.

`cleanup_session(session, lease, reason=..., helper=...)` is the integration API
when a coordinator already holds all three scopes. Reasons are `success`,
`failure` and `cancelled`. A helper adapter must belong to this run/lease and
expose its own ownership-checked `cleanup()`; it runs before Terraform removes the
target and network. Recovery lazily loads the readiness cleanup adapter only when
its private context exists; it never creates a replacement helper or controller.

Cleanup records preserve historical Terraform IDs separately from current state
and journal dispositions. Current state may only contain the same recorded IDs.
Already absent resources are independently inspected; only pending journal
entries are acknowledged. Surviving resources omitted from Terraform state refuse
cleanup rather than being adopted or deleted natively. A saved destroy plan is
validated for the remaining actual managed resources. Terraform owns target and
network deletion; no native deletion is a fallback.

A known successful destroy followed by interruption before absence acknowledgement
can be retried. The next attempt observes empty state, applies a validated empty
saved destroy and reconciles the original IDs. Interruption after controller
removal is also recoverable without restarting or replacing it: the adapter needs
the durable removal intent, bound successful last destroy and empty final-state
captures, exact resource absence and clean run-label sweeps. Missing or changed
captures refuse. Admission is finished only after every pending resource is
accounted for; interrupted archive-first finalization can complete explicitly.

Uncertain create/apply/refresh/destroy, pull or commit outcomes remain blocked.
Elapsed time, process death, an empty sweep or a confirmation flag cannot clear
them. The separate fixed unavailable-provider zero-contact proof remains narrow.
This version does not adopt orphan resources, edit Terraform state, force-unlock
it, migrate legacy run locks or execute a newer checkout against an older run.
A source-specific unsupported case stays visibly unresolved. Empty reservations
can finish only before any allocation intent or runtime operation; an empty
resource list in an allocation phase does not establish safety.
Reserved preallocation recovery can also finish without a controller context
only when there are no journaled resources, runtime operations, plans or state
and matching evidence records no allocation. An allocation-phase missing
controller instead produces a blocked uncertain cleanup receipt.

Versioned receipts are written to `evidence/cleanup.json` and per-attempt files in
`evidence/cleanup-attempts/`. Terminal attempts are retained. JSON and
`readable_cleanup()` use the same records: primary failure, secondary cleanup
errors, exact IDs/dispositions, uncertainty and retained-state flags. Unknown
error messages and raw logs are not copied into portable records. A cancelled or
failed underlying run stays failed after cleanup. CLI exit status describes the
cleanup operation: completed 0, failed 1, blocked 2. Inspect the primary result
separately; no cleanup result accepts a deliverable.

Terraform state/plans, keys, contexts and bounded diagnostics remain private and
retained by default. No private subtree is deleted by real cleanup. The
[cleanup schema](../schemas/cleanup-v1.schema.json) is generated from
`cleanup_schema()`; its bounded Python validator additionally checks unique
resource identities and completed-outcome consistency. This is a specific
contract validator, not a general JSON Schema implementation.

Run source tests with `python -m unittest discover -s tests -p 'test_recovery*.py'`.
Required live acceptance remains: happy, known failed and cancelled cleanup;
interruption after known terminal teardown followed by normal recovery; primary
failure surviving secondary cleanup failure; exact ownership refusal; and stable
before/after fingerprints of an unrelated sentinel. Test only Wormhole-owned
resources. Global prune, ambiguous prefix removal, reboot, host security changes
and unrelated service mutation are outside these operations.
