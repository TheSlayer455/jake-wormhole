# Minx work index

Current owner-authorized extension: [home ISO foundation](../handoff/ISO-FOUNDATION.md).
Implement and verify one RHEL 9 and one Ubuntu 22.04 real installation path while
preserving the container baseline. This is a new assignment; historical Done
contracts below are not reopened or reused as claim authority.
The Ubuntu baseline is verified at `55bb2fb` and delivered through [PR 29](https://github.com/TheSlayer455/jake-wormhole/pull/29).
RHEL media/installation, hardening, real assessment, the lab gate/publication and
remaining VM negatives are still outstanding; no original Minx ticket is
reopened or marked complete by this checkpoint.

Runtime recovery is verified at `f8e5f0e` on `codex/WORM-001-runtime-recovery`; [PR 28](https://github.com/TheSlayer455/jake-wormhole/pull/28) is the delivery record. See [actual runtime acceptance](../handoff/RUNTIME-ACCEPTANCE.md) for Ubuntu/UBI, faults, reuse, mixed/twenty-target, recovery and publication execution. Operator access is recovered, admission is reconciled and no temporary resources remain. Original Done tickets retain their historical authority and attribution; this checkpoint does not mutate Minx completion or claim independent review.

## Historical follow-up checkpoints

Active owner-authorized follow-up: [architecture and failure reproduction](FAILURE-REPRODUCTION.md).
Original Done contracts below remain historical; this assignment has not been
marked approved/completed in Minx. Work in bounded review branches, retain exact
tested revisions and continue the remaining runtime/fault-adapter work from that
checkpoint. Do not reopen or claim a completed ticket as a new authorization.

The first increment is in [draft PR 27](https://github.com/TheSlayer455/jake-wormhole/pull/27),
tested at `ba9d1a23ac591a122c0d0b3017d5c5a80afc31db` with 805 tests on Windows
and Linux (explicit skips) and matching manual/hosted semantic records. The next
source increment implements observed initialization/configuration lifecycle,
container fault adapters, pre-authentication restart recovery, verified Ubuntu/UBI
image reuse and contained initialization recovery after coordinator interruption.
The latest implementation is `492aa10`, with 862 source tests on Windows and
Linux root/nonroot and successful CI. Remaining work includes fresh runtime/fleet
and publication acceptance, performance measurements and independent review. Runtime
operator access is unresolved. This source increment does not complete that list.

Minx WORM-001 is the parent Epic and authority for current contracts, dependencies, claims and review state. This is navigation, not a second ticket database.

Snapshot October24: all20children WORM-002 through WORM-021 Done at approved revision2 with66current passes and solution comments. Parent acceptance is separate in live Minx; no approved child implementation remains. Refresh before writes; this snapshot never grants a lease. See [parent closeout](../handoff/WORM-001-checkpoint.md), [state](STATE.md), [historical matrix](acceptance-matrix.md) and [continuation](../handoff/CURRENT.md).

| Ticket | Bounded work |
|---|---|
| WORM-002 | Private repository and durable engineering baseline |
| WORM-003 | Versioned CLI and isolated run contracts |
| WORM-004 | Resource admission and shared run ownership |
| WORM-005 | Minimal SSH targets and pinned validation helper |
| WORM-006 | Terraform Docker target lifecycle |
| WORM-007 | Endpoint, SSH trust and Ansible readiness |
| WORM-008 | Scoped cleanup, cancellation and leftover recovery |
| WORM-009 | First real one-target Terraform to SSH to Ansible path |
| WORM-010 | Five-target execution and readiness failures |
| WORM-011 | Optional PowerShell and missing-package diagnostics |
| WORM-012 | Chunk integrity and reconstruction |
| WORM-013 | Candidate identity tied to the tested image |
| WORM-014 | Legally usable RPM-userland target coverage |
| WORM-015 | Observed Software Version Description |
| WORM-016 | Synthetic assessments and reference-only policy |
| WORM-017 | Complete evidence, reports and strict gates |
| WORM-018 | Atomic private reference publication |
| WORM-019 | Overlapping-run isolation and interrupted recovery |
| WORM-020 | Measured twenty-target demonstration |
| WORM-021 | Manual/CI parity, failure matrix and final handoff |

The source attachment's WORM-001 through WORM-007 milestone labels are illustrative, not these real keys. Current server scope/revision/claim guards remain authoritative. Use one writer per worktree and one owner per task; renew/checkpoint explicitly. Expiry does not authorize overwriting work.

Each increment needs criterion evidence, solution comment, actual source/commands/results, reviewer limits and cleanup/leftovers. Agent review submission releases the claim. Record authorized normal Owner actions as delegated automation rather than independent human examination. Verify actual deployed capabilities; never extract credentials or elevate roles. Production ISO eligibility stays false.
