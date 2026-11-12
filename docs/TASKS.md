# Minx work index

RHEL release-gate increment: `618d89f` implements the existing-contract evaluator,
pair comparison, exact-byte publisher and strict consumer readback. It binds
native reports to their hashes and parser results, the executed build manifest,
manual/SVD/boot identities and an internally consistent cryptographic OE record.
Four focused release cases plus 33 adjacent cases pass; actual evaluation of the
retained `239aad0` run also passed. The real candidate remains ineligible for
exactly three reasons: authoritative RHEL 10 OE verification, a final matching
pair after converged inputs, and positive exact-byte publication/readback. The
publisher refused before creating output. `692b10d` adds the new safe evidence
files to the existing archive lifecycle. The first pass safely stopped because
the established operational checkout used the older allowlist; updating that
clean checkout allowed normal recovery/commit. All 695 objects are committed,
all nine expected records from the evaluated run are verified, and pending/
failure counts are zero. Managed/candidate/free storage is 76.968/29.880/137.403
GiB; no VM/controller/disk remains.
Do not run the final pair until the OE/policy input can remain stable across it.
Delivery verification at `d8c9ef3` passed repository/matrix checks, 1,030 source
tests with 12 declared skips, and the complete 17-case parity/readback path in a
fresh full-history Linux checkout. The next delivery action is the normal PR and
post-merge main verification; it does not change the three qualification blockers.

Current qualification-closure increment:
`codex/WORM-001-rhel-chrony-closure`. Runtime source
`e3208237884acc53fb4821cdbc6dcb5e867e49e1` completed one fresh encrypted RHEL
10 installation after adding the pinned client-only and no-network-management
chrony settings to the post-remediation final configuration. Both targeted rules
now pass; the native delta is 427 pass/seven fail with all 1,073 outcomes
accounted. Time synchronization, 10/10 hardened checks, 6/6 controller checks,
trusted SSH/Ansible, SVD, no-remediation assessment, evidence retention and
cleanup passed. A focused recovery correction also preserved an interrupted
historical run as unknown while reclaiming 8,487,432,192 duplicate allocated
bytes through the existing storage engine. That checkpoint retained seven
native failures for the follow-on work below. No release is eligible yet.

Follow-on runtime source `da63dc0a79b6b545f4fe7ef9c55cf9d9ac0b2be0`
completed a fresh 517.715-second RHEL installation after the retained ARF proved
the final kdump unit was unmasked and the SSH banner paths conflicted. Both
targeted rules now pass; hardened/controller checks, synchronization, 449-RPM
SVD, no-remediation assessment, evidence and cleanup also pass. Native totals
are 428 pass/six fail/29 not applicable/ten not checked/600 not selected. The
accurate home-lab notice exposed the separate `banner_etc_issue` default-value
mismatch. This established the need for bounded tailoring rather than an
inaccurate government-system banner.

Runtime source `03d29868184bb711c78932eb1eea78e3f18b0ac3` completed that
fresh installation in 513.436 seconds. The receipt binds the one-value XCCDF
tailoring and records no assessment remediation. `banner_etc_issue` passes;
both chrony rules, kdump, SSH banner, synchronized time, all hardened/controller
checks, 449-RPM SVD, evidence and cleanup remain passing. Native totals are 429
pass/five fail/29 not applicable/ten not checked/600 not selected. The existing
encrypted archive verified the new candidate/evidence set and reclaimed
8,487,366,656 allocated bytes, leaving no VM or pending archive object. That
checkpoint retained five selected findings for the follow-on work below. No
release is eligible.

Runtime source `c944a8668e86979e38af673c5d81a9bf54d270a6` completed a fresh
519.709-second installation of source change `ff881b1`. The account rule now
passes without deleting accounts, excluding rules or changing selection. Native
totals are 430 pass/four fail/29 not applicable/ten not checked/600 not selected;
all hardened/controller checks, SVD, read-only assessment and cleanup pass. The
archive verified ten objects and reclaimed 8,487,362,560 allocated bytes.

Runtime source `77498b3a5934e3ee7cc538e30194e39b74e9eba1` completed a fresh
525.220-second installation of source change `2b3c16b`. The pinned rule's
local-only branch now passes without inventing a second DNS service:
NetworkManager uses `dns=none`, NSS has no `dns` token and the resolver file is
empty. `networkmanager_dns_mode`, synchronized time, lab logging/audit, all
hardened/controller checks, trusted SSH/Ansible, 449-RPM SVD, read-only
assessment and cleanup remain passing. Native totals are 431 pass/three fail/29
not applicable/ten not checked/600 not selected. The encrypted archive verified
ten objects and cleanup reclaimed 8,487,366,656 allocated bytes. No VM, pending
archive byte or failed archive receipt remains.

Source `518691acacf909c0e01624af2a31a561d7a33c28` is the next focused
candidate-input change. Independent source review caught that the first draft
expected a literal PBKDF2 hash in the GRUB generator, while RHEL stores the hash
in `user.cfg` and references `${GRUB2_PASSWORD}`. The corrected transform changes
only the username, verifies the separate hash, rebuilds the BIOS configuration
and verifies that `wormhole_boot_admin` is not an OS account. A realistic
transform regression and all 13 focused tests pass. Fresh installation proof
remains required.

The already-launched diagnostic attempt at source `f611d95` confirmed that the
first draft fails in hardening after all 449 packages install. The console
retained `WORMHOLE_INSTALLATION_FAILED`; all readiness/validation results were
blocked, Terraform/support cleanup completed and 405,504 transient allocated
bytes were reclaimed. It remains failed and is not proof of `518691a`.

Runtime source `7bfa09def373c32d2177d223fcf6d97b35289d28` then completed a
fresh 533.296-second installation of the corrected input. The native GRUB rule,
actual boot, encrypted cold start, trusted SSH/Ansible, all hardened/controller
checks, 449-RPM SVD, complete read-only assessment and exact cleanup pass. Native
totals are 432 pass/two fail/29 not applicable/ten not checked/600 not selected;
only the SELinux sudo-transition and SSSD certificate-map rules remain selected
failures. Assessment performed no repair and cleanup reclaimed 405,504 transient
allocated bytes. The encrypted archive verified ten objects and cleanup reclaimed
8,487,362,560 additional allocated bytes. No VM, pending archive byte or failed
receipt remains.

Source `8d825f66c261d1d11e82f17c5f53377436650e3a` is the next focused
installed-input change. It maps the final administrator to `staff_u`, replaces
the unrestricted per-user sudo line with a password-required wheel transition
to `sysadm_r:sysadm_t`, restores labels and validates the full sudo policy. The
helper requires both the unprivileged `staff_r:staff_t` login context and the
privileged `sysadm_r:sysadm_t` execution context. Fourteen focused cases pass.
Production +12/-2; tests +16/-3. Fresh installation proof remains required.

Runtime source `3f128cb81d0139ac2584b86898753d79a8bd5ed4` completed that fresh
installation in 527.472 seconds. Actual SSH entered `staff_r:staff_t` and
password-backed sudo/Ansible entered `sysadm_r:sysadm_t`; the native SELinux
rule now passes. All 11 hardened/six controller checks, 449-RPM SVD, full native
accounting, read-only assessment and cleanup pass. Native totals are 433 pass/
one fail/29 not applicable/ten not checked/600 not selected. Cleanup reclaimed
405,504 transient allocated bytes. The archive subsequently verified ten objects and exact-file cleanup reclaimed
8,487,362,560 allocated bytes. Storage now records 76.446 GiB managed, 29.880
GiB candidates, 137.927 GiB free, 482 verified archive objects, no pending
archive bytes and no VM disks.

Current source `85bfd5722e6f4e72f363ca8db9ee33aa7b51b5a8` makes the declared
authentication contract explicit and deselects only `sssd_enable_certmap` as
inapplicable because the lab does not use PKI authentication. No owner-approved
exception is added. The hardened reader requires this exact rule to be native
`notselected`, with 472 selected and all 1,073 rules accounted. A functional
observation rejects an installed certificate-map section. Twenty focused cases
pass. Production/policy +30/-11; tests +29/-9. Fresh installation proof is next.

Runtime source `4ac320ddb2d21ff3172d04b4cf33547c425c9490` completed that proof
in 493.897 seconds. The installed guest passed the final non-PKI observation,
all 12 hardened/six controller checks, encrypted cold start, trusted SSH/Ansible,
449-RPM SVD and exact teardown. Native totals are 433 pass/zero fail/29 not
applicable/ten not checked/601 not selected; `sssd_enable_certmap` is the exact
native `notselected` result, all 472 selected outcomes pass or are accounted,
and assessment performed no remediation. Immediate cleanup reclaimed 405,504
allocated bytes. The archive verified ten objects and exact-file cleanup
reclaimed another 8,487,362,560 allocated bytes. Storage now records 76.565 GiB
managed, 29.880 GiB candidates, 137.812 GiB free, 492 verified archive objects,
no pending archive bytes and no VM disks.

Current source `a8263e900e10f04eab3f6e4f98e4a6d9fa26842b` implements the
ten-rule manual evidence contract. The collector is read-only and preserves
native `notchecked`; it binds objective/governed dispositions to the exact run
and rejects missing or changed native statuses. Installation now sets the
per-run identity to expire in 48 hours and configures an active `DROP` zone with
only SSH allowed. Independent read-only review added strict run/boot/policy
identity checks and rejection of undeclared firewall rule classes. Twenty-one
focused cases pass. Production/policy +200/-13; tests +63/-10. A fresh
installation is required before these controls are closed.

That first fresh attempt, at source `9ee8c4f`, reached 449/449 packages and
`hardening-complete`, then failed final installed-system readiness before SSH.
The console shows firewalld started; it does not show the exact assertion under
the old marker. All dependent checks were blocked, assessment did not run,
Terraform cleanup passed, 405,504 transient allocated bytes were reclaimed and
no VM/controller remains. Diagnostic source `4552360` adds a static stage name
to the existing failure marker without exposing observed values or changing the
qualification gate. Fifteen focused input tests pass. Next: run one fresh guest,
identify the actual failed assertion group, then correct only that condition.

The first diagnostic allocation was correctly refused by the retention budget.
Archive readback and exact-file cleanup reclaimed 8,487,243,776 allocated bytes;
the unchanged retry then reached the retained `firewall-policy` marker after
449 packages and completed hardening. Assessment remained blocked, exact-owned
teardown passed and transient cleanup reclaimed 405,504 bytes. Source `5ed8d6c`
splits only that static marker into default-zone, active-zone, interface, target,
services and ports while leaving the checks and policy unchanged. Fifteen
focused tests pass. Next: one fresh diagnostic installation, then the smallest
correction to the named condition.

The fresh source `1ecefaf` attempt narrowed the boundary again: default zone,
active zone and interface binding pass; `firewall-target` is the first failed
assertion. Package installation/hardening completed, dependent checks and
assessment stayed blocked, teardown passed and transient cleanup reclaimed
405,504 bytes. Source `705c3c1` emits only an allowlisted documented target enum
(`default`, `ACCEPT`, `DROP`, `REJECT`) or `unexpected`; it changes no policy.
Fifteen focused tests pass. Next: record that enum in one fresh run, then patch
the owning installed configuration or expectation from evidence.

Source `7d638ef` recorded `firewall-target-query`, proving the command itself
failed before a target value existed. The supported target lookup is a permanent
configuration query; both observers omitted `--permanent`. Source `6489604`
corrects the existing readiness and manual collectors while retaining separate
live daemon, active-zone, interface, services and undeclared-rule checks. It
changes no firewall setting or policy. Sixteen focused cases pass. Next: archive
the diagnostic candidate, run one fresh installation, and verify complete manual
evidence plus unchanged native assessment/accounting.

Runtime source `8ba4274` then completed a fresh 501.958-second installation:
readiness, SSH/Ansible, all hardened/controller checks, encryption, 449-RPM SVD,
read-only assessment and teardown passed. Native totals remain 433 pass/zero
fail/29 not applicable/ten not checked/601 not selected. Manual evidence closed
eight rows; both firewall rows were false because the observer parsed the real
`drop (default)` display label as an invalid zone name. Source `0cbb4c1`
normalizes the annotation and has an executable exact-output regression. Sixteen
focused cases pass. Next: reuse the unchanged candidate for one fresh install,
verify all ten manual rows, archive evidence and record final storage state.

Runtime source `239aad0` completed the fresh collector proof in 489.836 seconds.
All ten manual rows now close (seven satisfied, three governed N/A) while their
native `notchecked` statuses remain unchanged. All lifecycle, SSH/Ansible,
hardened/controller, encryption, SVD and read-only assessment checks pass; native
totals remain 433/zero/29/10/601. VM cleanup reclaimed 405,504 bytes. Encrypted
archival reclaimed another 8,487,362,560 bytes; storage is 76.967 GiB managed,
29.880 GiB candidates, 137.404 GiB free, zero pending/failures and no VM disk.
Next: implement the existing-contract RHEL evaluator/publisher; keep it refusing
until cryptographic operating-environment evidence satisfies the frozen policy,
then require a final independent same-candidate pair before positive publication.

Completed increment: `codex/WORM-001-terra-tool-decisions`,
[PR 55](https://github.com/TheSlayer455/jake-wormhole/pull/55). Tested content at
`205835d` adds the bounded tool-adoption decision to the existing single Terra
paste and links it from integration guidance. One focused test keeps all eight
decisions present and preserves the rule that no optional tool is a prerequisite
for the current installation repair. Clean-checkout repository/matrix checks,
1,017 source tests with 12 skips and 17 parity cases passed at `5d58869`.
Independent review found no blocking issue and its corrections are applied.
Merge `b8c1c1469febf809eaf9da5906e7d9f37457568a` and its post-merge main
workflow passed. No runtime allocation or optional-tool installation belongs to
this completed increment.

Current increment is `codex/WORM-001-terra-single-file-bundle`, [PR 54](https://github.com/TheSlayer455/jake-wormhole/pull/54).
The existing Terra brief is now the complete initial copy/paste bundle. It
contains the owner directive, fast causal workflow, current console case,
20-minute budget, live logging, expected-result accounting, verified runtime
reference, implementation capsule, exact qualification/storage state and a
sanitized response schema. Terra no longer needs routine follow-up Wormhole
file pastes. This is a documentation and focused structural-test increment;
no runtime code, installed input or qualification policy changed.

Completed execution-report increment was `codex/WORM-001-two-os-cleanup-acceptance`.
The fresh
RHEL/Ubuntu executions at main `21fb946`, per-run cleanup, archive readback,
repeatability and final reconciliation are complete. Preserve the
[current measured results and remaining qualification work](../handoff/CURRENT.md#fresh-two-os-acceptance-with-automatic-cleanup).
This increment records execution evidence with no production/test code changes.

Completed storage increment is `codex/WORM-001-run-storage-cleanup`. Fix abandoned
transfer and restore staging in the existing cleanup paths, with real workstation
and host verification at `461b113`. Existing archive scheduling and shared
admission continue to govern retention. Preserve all required evidence.

Previous handoff increment is the [single Terra paste](../handoff/LIGHTSPEED-CROSS-REFERENCE.md).
It combines the work-side directive, fast component checks and verified evidence.
The latest comparison adds work-side inspection tasks for the effective remaining
deadline, expected results in the existing receipt, and authoritative product-case
mapping. Installer proof and release coverage remain separate tracker items.
This increment changes documentation only and adds no private runtime evidence.

Two-OS assignment: `codex/WORM-001-two-os-completion`. Follow the single
[completion checklist](STATE.md), preserving PRs 43-47. RHEL hardening is now
authorized; Ubuntu vendor work depends only on the explicit owner-populated
provider. One implementation/runtime owner coordinates isolated source worktrees.
Do not add another controller, backend, scheduler or archive system.

Completed engineering increment in [PR 48](https://github.com/TheSlayer455/jake-wormhole/pull/48).
The engineering pair passed at `d6dfaf3` and `4980aa0`. Native RHEL findings,
manual evidence and vendor module/environment verification remain open.
Ubuntu unchanged intake passed at `9a19b53`. Archive readback and comparison
confirmed independent non-Pro installations. Pro-dependent qualification is pending.

Completed increment: `codex/WORM-001-lightspeed-cross-reference`, [PR 47](https://github.com/TheSlayer455/jake-wormhole/pull/47). Delivered the
[copy-ready comparison prompt](../handoff/LIGHTSPEED-CROSS-REFERENCE.md),
[sanitized verified reference](../handoff/WORMHOLE-SANITIZED-REFERENCE.md) and small
existing-verifier extension. Reconcile original evidence, obtain independent
engineering review, run source/CI checks and record the reviewable delivery.
No runtime implementation, installation inputs or qualification policy changes.

Completed increment: `codex/WORM-001-evaluate-stig-closure`, [PR 46](https://github.com/TheSlayer455/jake-wormhole/pull/46), merged at `56ca6fd` with passing main CI.
Official Evaluate-STIG distribution is authentication/network blocked; no package
or supported Linux invocation has been obtained. Non-Pro work closes guest trust
and the frozen manual benchmark delta. First fresh Ubuntu installation at `2a0fc82`
passed 40/40; `134e1e1` corrects the observed oversized terminal storage record.
A subsequent real failure verified blocked validation/cleanup and exposed an
asynchronous Postfix restart race. `a705e2b` uses the packaged instance restart;
two fresh rebuilt-candidate installations passed 40/40 each with matching software,
findings and independent identities. Pending publication was refused. Source CI:
974 pass/12 explicit skips, plus parity. Keep Pro/FIPS and actual Evaluate-STIG separate and
unverified; neither a source test nor OpenSCAP supplies those capabilities.

Completed increment: `codex/WORM-001-archive-svd-evidence`, [PR 45](https://github.com/TheSlayer455/jake-wormhole/pull/45), merged at `aa777a5` with passing main CI.
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
