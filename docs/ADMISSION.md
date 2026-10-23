# Shared resource admission (WORM-004)

The admission library and read-only commands are implemented. Actual Docker allocation,
image assembly and target execution are later integrations. Passing a synthetic
capacity test does not establish host headroom, applied limits or a twenty-target run.
Minx [WORM-004](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-004) owns this
contract; [architecture](ARCHITECTURE.md) and [fidelity](FIDELITY.md) explain the
larger reference-only boundary.

From the checkout, with Python 3.12+:

```text
python -m wormhole.admission inspect --infrastructure-root /absolute/external/runtime
python -m wormhole.admission plan --infrastructure-root /absolute/external/runtime --profile smoke
python -m wormhole.admission status --infrastructure-root /absolute/external/runtime
python -m unittest discover -s tests -p test_admission.py -v
```

`inspect` and `plan` require the Linux execution host and the existing authorized
local Docker socket. They allocate nothing and do not create the proposed root.
For a missing proposed root they measure its nearest existing ancestor's disk.
`status` reads a previously initialized owned root. Commands emit JSON; a refusal
returns nonzero. No CLI accepts an arbitrary Docker endpoint, shell command or
synthetic observation file. There is no automatic journal-clear/recovery command.

## Measured decisions and reviewed hypotheses

[The versioned policy](../profiles/admission-v1.json) declares separate 1/5/20
target counts, controller concurrency 1/2/4, and build concurrency one. The
256 MiB target and 8 GiB project RAM ceiling are planning hypotheses. All helper,
provisioner, overhead and build components have explicit memory, CPU, PID, disk,
log and timeout budgets. Memory/CPU/PID capacity uses the greater of the build
and runtime phases; phase guards prevent a return to building while runtime
resources remain. Disk accounts for both phases' persistent bytes plus a separate
materialization reserve. Four GiB each of memory/disk headroom and one CPU are
the reviewed initial policy, not measured spare capacity.

Fresh observations require MemTotal/MemAvailable, free bytes on runtime and
Docker storage, allowed CPU count/load, Docker cgroup v2 CPU/memory/PID support,
and a consistent running-container/statistics snapshot. Observation commands use
the fixed local Unix socket, five-second subprocess deadlines and bounded output.
Only selected metadata and aggregate workload usage are returned. Missing,
inconsistent, unsupported, nonfinite or more-than-30-second-old data refuses
admission. Existing workload memory is already reflected in MemAvailable; it is
reported without subtracting it twice. CPU admission conservatively uses the
greater of load average and measured Docker CPU consumption.

`build_plan(load_profile(name), observations)` is pure and returns desired
Docker/native and Terraform settings, measured context and refusal reasons.
It does not reserve capacity. The resulting `limits_enforced` and
`allocation_performed` are false. An oversized refusal creates no targets and
does not count as a successful twenty-target demonstration. Source policy
changes require review; callers cannot silently override a loaded profile.

## One canonical root and durable ownership

Real admission is pinned in source to `/srv/homelab/jake-wormhole/runtime/infrastructure` so every
process/worktree uses one host-wide lock. The proposed location must be verified
and initialized by the authorized operator; this change creates no host root.
Alternate roots require the explicit nonproduction `allow_synthetic=True` library
option and synthetic observations; those leases cannot authorize real allocation.
Read-only inspect/plan commands can measure another proposed external location.
All state remains outside Git and vault synchronization. Linux ownership and 0700/0600 permissions,
ordinary files, and no symlink/junction traversal are required. The library refuses
an existing unowned populated directory. The stable `infrastructure.lock` inode
is never unlinked. A nonblocking exclusive Linux flock serializes the whole
admission, operation and reconciliation interval, including image commits.

```python
from wormhole.admission import AdmissionLease

with AdmissionLease(root, run_id, source_revision, profile="smoke") as lease:
    plan = lease.plan  # Fresh measurement and decision occurred under the lock.
    # A trusted adapter must persist intent BEFORE creating anything:
    lease.set_phase("assembling")
    # Create stopped, ownership-check, inspect limits, then start via later adapter.
    lease.register_resource("container", exact_container_id)
    lease.set_phase("materializing")  # Before the image commit request.
    lease.register_resource("image", exact_image_sha256_id)
    # Only after actual exact-ID/label inspection and a complete run-label sweep:
    lease.reconcile_resource("container", exact_container_id, outcome="absent")
    lease.reconcile_resource("image", exact_image_sha256_id,
                             outcome="retained", size_bytes=observed_image_size)
    lease.finish(reconciliation_complete=True)
```

The example describes the trusted adapter protocol; it is not an implemented
Docker build command. Registration/reconciliation records are not a substitute
for that adapter's actual Docker inspection. Allocation phases are journaled
before an operation can lose its returned ID. Containers cannot be retained as
completed cleanup. Retained image IDs and measured size remain in the archive;
their occupied bytes remain visible in subsequent disk observations. Runtime
phase container counts and assembly concurrency are bounded by the admitted plan.
Every assembling/materializing/provisioning phase entry remeasures under the
same held lock and rechecks the unchanged profile before new allocation. Call
`lease.refresh()` for an additional pre-operation check. Capacity refusal leaves
existing resources and the active journal intact; reconciliation and finalization
remain possible without a fresh capacity observation. Register a returned ID even
when an operation was slow; fresh capacity must never prevent accounting for an
already-created resource. Adapters enter the phase before every allocation.

Context exit never declares success or cleanup. Cancellation, failed operations,
unknown commit results, stale owner PIDs and reboot do not clear the active
journal. Although the kernel releases flock on process death, the next admission
refuses unreconciled state, including an empty resource list after an uncertain
create. Explicit owned-resource reconciliation is a trusted adapter's
responsibility; do not delete a journal or guess that expiry makes resources safe.
No PID killing, broad cleanup or daemon setting changes are implemented here.

Finalization requires explicit confirmation and every registered resource
accounted for. The immutable run-ID archive is durably written before the active
journal becomes finished. A missing/mismatched archive or reused run ID blocks
admission. Interrupted finalization therefore remains a visible recovery boundary.
Application records are not tamper-proof against the host administrator.

## Reconciliation-only resume (WORM-005)

`AdmissionLease.resume(root, run_id, source_revision, profile="smoke")` reopens
only the current exact run/source/profile under the same exclusive flock. It
requires the existing owned root, stable lock, marker, history and journal; it
initializes none of them. Real mode remains pinned to the canonical root.
Synthetic resume requires `allow_synthetic=True` and an already synthetic plan.
The original PID, source and immutable admitted plan remain provenance; a resumed
descriptor belongs to the process that acquired it. No PID takeover occurs.

The resumed context permits `set_phase("reconciling")`, reconciliation of exact
already-recorded resources, and `finish(reconciliation_complete=True)`. Allocation
or execution phases, registration of additional/adopted resources and capacity
refresh refuse. Stale measurements or current headroom do not obstruct cleanup.
The library performs no Docker operation and cannot supply the adapter's proof.
Before finalization the adapter must inspect exact IDs/ownership and establish
the complete daemon outcome, including a run-scoped sweep for any uncertain
create, pull or commit. An empty resource list is not that proof. Unknown outcomes
remain active even after context exit. General recovery is outside this slice.

If interruption left a durable completion archive and the old active journal,
resume accepts only the archive's exact completed projection, preserving every
resource, plan and identity field. Only an explicit `finish` may commit that
archive to the current journal; allocation/reconciliation mutations remain
blocked. A matching already-finished record can also be explicitly finalized
idempotently. The existing archive is never replaced. Missing, changed or
mismatched archives fail closed, and completed run IDs cannot be reused for new
admission. This is a supported adapter boundary, not a journal-edit workaround.

## Applied-limit and materialization boundaries

Desired native settings include memory+swap, NanoCPUs, PID cap, rotated logs,
read-only root, private tmpfs, no-new-privileges and dropped capabilities. Target
SSH capability/user compatibility must be qualified by the image ticket rather
than silently loosening these settings. A future adapter verifies actual exact-ID
HostConfig/cgroup values before execution; these plans alone prove no enforcement.

Docker provider 4.6.0 lacks a PID-cap property. Terraform projections explicitly
create stopped containers with `start=false` and `must_run=false`; the trusted
provisioner must apply a bounded exact-ID Docker PID update and inspect all
required limits before starting. `pid_mode` and `ulimit nproc` do not substitute
for that cap. Terraform retains lifecycle/state ownership and destroys its exact
resources. Failed update/inspection must leave stopped resources accounted for.

Ordinary image assembly can be container-capped. Shared Docker daemon image
materialization cannot be given a per-operation hard cgroup limit here. The plan
instead declares a 1 GiB writable-layer ceiling, 2 GiB extra disk reserve, the
already-counted 512 MiB shared overhead allowance and a 120-second client deadline.
These are initial ceilings to test. Unknown/timed-out daemon outcomes keep the
journal active; a client timeout does not prove that daemon work stopped.

Primary references: [provider schema](https://github.com/kreuzwerker/terraform-provider-docker/blob/v4.6.0/internal/provider/resource_docker_container.go),
[provider HostConfig mapping](https://github.com/kreuzwerker/terraform-provider-docker/blob/v4.6.0/internal/provider/resource_docker_container_funcs.go#L354-L420),
[Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/),
[exact-ID PID update](https://docs.docker.com/reference/cli/docker/container/update/),
[rotated logs](https://docs.docker.com/engine/logging/drivers/json-file/), and
[Linux flock semantics](https://man7.org/linux/man-pages/man2/flock.2.html).
