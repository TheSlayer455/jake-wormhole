# WORM-010 shared helper and complete target/check results

This increment supports the `smoke` and `five-targets` profiles. It does not
qualify twenty targets, candidate-derived images, the complete pipeline or
production ISO eligibility. The original qualified target/helper images and
the WORM-009 collector/check semantics remain unchanged.

The caller holds the existing Run lock, Docker scope and AdmissionLease.
`BatchReadinessSession(provisioning, scenarios=None, validation=True)` consumes
the immutable TargetPlan and the exact observed target-resource map. It creates
one capped, Docker-free helper with the existing two fixed, hash-bound read-only
runtime source files. It never starts or allocates a target. The caller first
uses `create_stopped()` and then starts an exact admitted subset or all targets.

`start_helper()` and `wait_ready(on_poll=None)` retain the shared 90-second
readiness deadline. `on_poll` is a trusted in-process coordinator callback, not
serialized input. It can start one delayed owned target under the same lease.
`require_ready(target_id)` revalidates a selected established snapshot;
`require_ready()` revalidates all planned targets within one inspection budget.
`target_state(target_id)` returns a copy and `ready_target_ids` identifies the
actually ready subset. Foreign IDs and changed resource maps are refused.

Each target has its own write-once known-host pin, private authentication input,
attempt names and eight ordered readiness checks. The helper receives each
target's three fixed input files through the bounded exclusive receiver into
its private target directory. No private-key data enters portable evidence.
The controller records pending stopped targets without inventing an IP address.
One known failure does not prevent the remaining planned targets from being
checked. An unknown helper mutation or exec outcome blocks further progression
and normal cleanup. The absolute deadline still applies to inspections,
public-key reads, input injection and accepting new readiness.

`BatchValidationSession(readiness, scenarios=None).validate(before_probe=None)`
freezes ten required functional checks for every planned target before probing.
Five targets therefore require fifty rows. Readiness-blocked targets receive ten
explicit nonpassing precondition rows; these are not claimed as Ansible attempts.
The ready subset is tested in one genuine SSH/Ansible invocation with at most two
forks. Target count and configured concurrency are separate plan fields. The
validation window is 60 seconds, the outer helper exec at most45 seconds and its
inner collector two seconds shorter. Actual target/helper StartedAt values must
leave that budget plus20 seconds before their existing finite lifetimes expire.

The fixed aggregate callback records exactly one authenticated structured event
per attempted target, including skipped/failed/unreachable events, plus a final
completion record. Missing, duplicate, foreign, censored, truncated or malformed
events cannot pass. A complete CLI2 mixed result may retain four observed passing
targets, while the failed target and aggregate remain nonpassing. Console text
is not a source of structured acceptance. The batch writes and verifies the
fixed private Ansible configuration; strict SSH host-key checking, explicit
interpreter, noTTY and piped transfer remain enabled.

`report_batch_validation(run)` validates the immutable plan, complete target/check
grid and the bounded private response's hash/size/path against the strict parser
before emitting matching JSON and text. Per-target expected values, observed
values, status and evidence references remain visible. A known validation failure
is persisted to the exact provisioning primary-outcome sink before its terminal
component receipt; established readiness is not relabeled as failed.

The helper context uses schema1.0, `context_version:3` and
`resource_layout:indexed-targets-v1`, with the exact TargetPlan and
`target_resource_ids` map. Original single-target contexts keep their original
layout and source. `ReadinessSession.resume_cleanup(run, lease)` dispatches the
new context to the fixed batch adapter, validates all nested identity/outcome
records, source-copy identities, saved provisioning IDs and journal membership,
then permits only exact helper cleanup. It allocates or adopts nothing. A known
pre-helper failure is recoverable only with a complete known-resource proof and
no helper found by the run/role sweep. Terraform cleanup follows helper cleanup
through the existing WORM-008 coordinator. Private receipts and primary failures
are retained.

`tests/test_fleet_helper.py` and `tests/test_fleet_runtime.py` are scoped synthetic
policy/protocol/filesystem fixtures, not real SSH/Ansible acceptance. They cover
one helper, independent trust, delayed and failed targets, complete/mixed/missing
results, capture tampering, exact recovery and malformed child refusal. Real
one-target and five-target qualification belongs to the separate reviewed
acceptance coordinator and its fresh measured Runs.
