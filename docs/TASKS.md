# Minx work index

Current increment: `codex/WORM-001-archive-svd-evidence`, [PR 45](https://github.com/TheSlayer455/jake-wormhole/pull/45).
Extend the existing encrypted archive selection to immutable SVDs/build manifests,
retain their local originals and avoid deletion scans for retained-only objects.
No new transport, receipt, cleanup engine or installer change.
At `f2a3d5c`, 298 real workstation objects are committed, zero pending/failed;
both fresh OS SVDs/manifests passed additional decrypt/readback with local originals
unchanged. Focused storage 28/28; CI 969 pass/12 skips; independent code review.

Completed increment: `codex/WORM-001-two-os-svd`, [PR 44](https://github.com/TheSlayer455/jake-wormhole/pull/44),
merged at `1a8d412` with passing post-merge CI and SVD/archive readback.
At `77e6e16`, real RHEL 10 and encrypted Ubuntu 22.04 runs passed their functional
contracts, SVD readback, actual OpenSCAP coverage and cleanup. RHEL's existing
structured inventory now produces readable/JSON SVDs. Evaluate-STIG remains
unexecuted pending an authorized package and supported invocation documentation.
See [current results](STATE.md); no qualification or scanner substitution claimed.

Completed increment: `codex/WORM-001-archive-tier`. Existing storage receipts,
cleanup and CLI now support encrypted workstation retention, explicit restore and
offline preservation. Real 6 MiB and historical Ubuntu ISO archive/delete/restore,
interruption/retry and corruption rejection passed. Scheduled reconciliation
completed 194 objects, then repeated without duplicate transfers; the measured
net allocated reduction is 5.978 GiB. [PR 43](https://github.com/TheSlayer455/jake-wormhole/pull/43)
merged at `6a78d39` with passing post-merge CI/readback. See [storage](STORAGE.md).
No installer changes or new VM acceptance are required for storage-only changes.

Completed increment: `codex/WORM-001-directory-intake`, [PR 42](https://github.com/TheSlayer455/jake-wormhole/pull/42).
Completed delivery registration, protected staging/reuse and shared manual/scan
dispatch are verified at `0a6acb5`: real healthy intake, periodic completion,
duplicate/restart and blocked-readiness failure with cleanup. See [handoff](../handoff/solutions/directory-intake.md).
Seven focused tests and the 968-test suite passed with three explicit skips.
Private Lightspeed integration, Ubuntu intake and qualification are not claimed.

Previous increment: `codex/WORM-001-ansible-execution`, [PR 41](https://github.com/TheSlayer455/jake-wormhole/pull/41).
Fixed the confirmed Ubuntu helper regression from shared readiness changes;
one fresh encrypted VM at `e8fdaa6` passed 40/40 functional checks, real native
assessment and cleanup. Qualification remains pending; see [state](STATE.md).
No Runner dependency was added: existing structured Ansible paths remain, with
an optional bounded trial described in [integration guidance](EXTERNAL-INTEGRATION.md).
Private build-contract discovery and scanner entitlement/support cannot be
established by this public repository. No work-environment execution is claimed.

Completed lifecycle increment: `codex/WORM-001-lifecycle-comparison`. The same-media native
experiment passed; Terraform remains the smaller maintained solution. Real
acknowledgment/progress, marker-readiness failure and supervisor interruption/
exact-owned recovery are verified at `63a130a`. Deliver the [Luna integration
handoff](../handoff/solutions/lifecycle-comparison.md); do not expand RHEL hardening,
encryption or publication during this recovery window. Qualification stays false.

[Ubuntu policy v2](UBUNTU-LAB-POLICY.md) removes physical hardware as a home-lab
requirement and delegates trust-anchor review to Codex. That review remains an
engineering task; legitimate Pro input remains external. Historical native
results and Minx contracts are unchanged.

## Previous increments

RHEL increment: `codex/WORM-001-rhel10-baseline`, [PR 39](https://github.com/TheSlayer455/jake-wormhole/pull/39). The owner explicitly
activated RHEL 10.0 using supplied official media. Preserve Ubuntu's completed
engineering and unresolved qualification dependencies. The first RHEL installation
exposed a completion-marker traversal defect; the corrected same-ISO fresh retry
at `d39f7a0` passed final SSH/Ansible, RPM inventory, complete native vendor-draft
audit and exact-owned cleanup. Reproducible hardening, current benchmark mapping
and eventual qualified publication remain deferred requirements; this baseline
does not satisfy them.
See [current state](STATE.md) and [RHEL baseline](../handoff/solutions/rhel10-install-baseline.md).
This increment does not claim hardening or reopen historical Minx contracts.

Repeatability follow-up: `codex/WORM-001-repeatability-evidence`, [PR 38](https://github.com/TheSlayer455/jake-wormhole/pull/38).
Existing comparison now requires independent recorded installation identities;
retained real-pair replay and focused refusal tests passed. See [state](STATE.md).

Ubuntu PAM closure: `codex/WORM-001-ubuntu-qualification-closure`, tested at
`3e1e00bc64d6d7c3fb4d3f2d846188626db8eace`. Two matching fresh installations passed
40/40 checks; real PAM, native assessment, inventory, encryption and cleanup are
verified. [Continuation and exact external dependencies](../handoff/CURRENT.md)
remain separate from qualification, publication and historical Minx review state.

Storage increment: `codex/WORM-001-storage-lifecycle`, [PR 36](https://github.com/TheSlayer455/jake-wormhole/pull/36).
Shared-lock lifecycle cleanup, bounded candidate retention, preview/status and
projected disk admission are implemented and exercised; see [measured state](STATE.md).
Preserve unmanifested legacy fragments and qualification evidence. This delivery
does not change historical Minx review state or complete Ubuntu qualification.

Earlier sandbox increment: `codex/WORM-001-ubuntu-sandbox`. The owner authorized
project-owned time/log receivers, private CA/test identities, protected local
secret delivery and encrypted installation. These are implementation tasks;
RHEL was paused during that increment; vendor entitlements/certification cannot be fabricated.
The earlier partial results below retain their original source attribution.
Two fresh same-ISO encrypted installations passed 34/34 checks each, with matching
inventories/assessments and cleanup. See [current continuation](../handoff/CURRENT.md)
and [PR 34](https://github.com/TheSlayer455/jake-wormhole/pull/34). Qualification is
pending explicit external/content requirements; no qualified release is claimed.
Do not start a second runtime while the shared lease is active.

Ubuntu 22.04 qualification and exact-byte qualified publication remain pending
USG/FIPS and required manual/external-control evidence; no engineer waiver is
allowed. RHEL 10's newly authorized baseline is separate from those dependencies
and preserves the container regression layer.
See [current continuation](../handoff/CURRENT.md). Historical Done contracts below
are not reopened or reused as claim authority.
## Historical baseline delivery

The Ubuntu baseline was delivered through [PR 29](https://github.com/TheSlayer455/jake-wormhole/pull/29).
The hardened increment is [PR 31](https://github.com/TheSlayer455/jake-wormhole/pull/31),
merged as `63d3aa1`: three real fresh installs (including merged source),
14/14 functional checks each, full native rule accounting,
verified reuse, recovery and refused pending publication. Eighteen findings,
five manual checks, entitlement/coverage and qualified release remain open.
No original Minx ticket is reopened or marked complete by this checkpoint.
Implementation merge `63d3aa1` passed a fresh post-merge Ubuntu VM run, the
901-test Linux/Windows suites with explicit skips, and main CI. Continue from
current main; merged feature branches are historical. Next independent work is
installation-time encryption and its private unlock contract. Entitlement,
external-service evidence, accountable manual dispositions and positive qualified
publication remain outstanding; these requirements were not waived.

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
