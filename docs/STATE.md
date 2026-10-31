# Current engineering state

## Encrypted workstation retention in progress

Implementation at `b881127` adds selective age archival and explicit restore using
the existing storage cleanup/ownership contracts. A real 6 MiB SSH pull, stored
decrypt/hash verification, source reclamation and exact-byte restore passed.
The roughly 2 GiB historical Ubuntu transfer is underway; its completion,
scheduled execution, final integration verification and delivery remain pending.
Budgets and protected local evidence remain unchanged. See [storage](STORAGE.md).

## Completed ISO intake

[PR 42](https://github.com/TheSlayer455/jake-wormhole/pull/42) adds one manual/scan
intake path to the existing controller. Tested `0a6acb5754a943562a9e425288704cae928afa60`:
a delivered RHEL 10 BIOS ISO passed fresh Terraform/KVM installation, all six
controller checks, trusted SSH/Ansible, 413 RPM records and native assessment in
247.755 seconds. The actual attached hash matches delivery; no builder/remaster
ran. Only the contract's fresh seed was generated. Qualification remains false.

A real ext4-backed periodic timer ignored an incomplete delivery, dispatched
after completion, retained one supervisor across a duplicate scan/timer restart,
then reconciled the same terminal failure without a duplicate run. The deliberate
marker-access fault failed in 236.396 seconds: authentication passed, readiness
failed and four dependents were blocked. Both attempts cleaned up. Native healthy
results retain 172 pass/261 fail/56 not applicable/nine not checked/450 not selected.
Same-name byte changes, new assessment context and explicit retry are focused
filesystem proofs, not additional VM runs. See the [source-pinned handoff](../handoff/solutions/directory-intake.md).
Final timer journal: five service invocations, one launch, four terminal outputs
of the same failed request. The test timer is removed, both admission journals
are finished and no domains remain. Exact-owned test-copy cleanup and existing
run-media deduplication retained canonical inputs/evidence. Project storage is
69.441 GiB/100 GiB; candidate cache 27.945 GiB/40 GiB; available space 115.630 GiB.
Docker/K3s remain active. These measurements do not authorize a later allocation.

Seven focused tests (157 added lines) cover distinct intake boundaries. Full
Linux verification: 965 passed/three explicit skips (968 total), 85.514 seconds;
[implementation CI passed](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40997798804).
Independent code/evidence review found no remaining blocking findings. Required
work-environment installation/scanner/release contracts remain unverified; an
undiscovered source-build contract does not block validating a delivered ISO.

## Ubuntu helper compatibility after the readiness split

[PR 41](https://github.com/TheSlayer455/jake-wormhole/pull/41) repairs two stale
substitutions in the Ubuntu adapter after PR 40 changed shared readiness: private
become-password creation was lost and the RHEL passwordless-sudo prerequisite
remained. Tested implementation `e8fdaa62b831eef071daa6eedff3bd808a196e96` restores
password-required Ansible access without changing the builder, hardening, scanner
content or shared RHEL helper. Production +4/-2; one regression adds 29 test lines.
It exercises generated helper dispatch and private password delivery; actual
execution is separately established by the fresh encrypted Ubuntu VM below.

One fresh BIOS/8 GiB/two-vCPU/64 GiB installation under prospective policy v2
passed all 40 functional checks in 644.915 seconds. Real final SSH, Ansible,
password-required sudo, native inventory, PAM probes, support services, wrong/
missing unlock refusal and cold-start access passed. Build took 17.266 seconds;
installation-to-host-key 477.383; offline inspection/cold-start 63.879; controller
validation/assessment 55.515. Nested stage timings must not be summed twice.
Native selected results: 210 pass, one fail, 14 not applicable, five manual;
409 upstream rules remain not selected. Original upstream results remain 207
pass/four fail. Assessment completed, but CLI exit 1 and both qualification flags
stay false: entitlement/USG/FIPS, content reconciliation, delegated trust review
and a matching second v2 installation remain outstanding. This compatibility
test does not replace the historical v1 repeatability pair below.

Cleanup verified no owned temporary resources; journals reconcile, the shared
lock is available and Docker/K3s remain active. An earlier storage refusal was
resolved by existing locked cleanup of four hash-bound, terminal, obsolete
assessment ISOs and one identical reconstructed source copy: 10.115 GiB of actual
allocated blocks reclaimed. Reports, reusable sources/candidates and unknown
runs were preserved. This was scoped maintenance, not new cleanup code. Retained
project storage is 69.337 GiB/100 GiB; another full cold build currently needs
1.848 GiB additional admission headroom. No storage ceiling was weakened.

Linux source suite: 958 pass, three explicit skips (961 total), 89.409 seconds.
Three helper tests and independent engineering-agent review passed; implementation
[CI passed](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40990828486).
PR records distinguish tested, delivery and merge revisions. The
[research integration guidance](EXTERNAL-INTEGRATION.md) keeps Terraform and
existing structured Ansible paths; Runner remains optional and unexecuted.

## Lifecycle decision and current scope

Delivery: [PR 40](https://github.com/TheSlayer455/jake-wormhole/pull/40). Its final
head/merge and CI records are separate from the runtime-tested sources below.

Keep Terraform. The same RHEL ISO/guest/check contract passed native libvirt at
`7b59975c81debc1832929f02aa87d64769a310b3` in 278.225 seconds versus the original
Terraform control's 272.246 seconds. Packages and all 948 rule-level outcomes
match. Native lifecycle commands took 2.377 seconds versus Terraform's 5.631;
one sample each does not establish a reliability or performance advantage.
The experimental adapter was removed from the normal source rather than adding
another maintained lifecycle. The ISO builder is unchanged.

Retained implementation `63a130a249111fc10c229a66922a51895b87e40e` adds durable
launch acknowledgment, observed progress/read-only status and distinct readiness
failure accounting. A real controlled marker-access failure preserved successful
SSH, failed readiness and four blocked dependents; no Ansible/catalog started.
It failed in 238.174 seconds overall, with the helper detecting the fault in
0.672 seconds, and cleanup succeeded. Killing the recorded supervisor during
another installation produced unknown state and refused admission. Existing
recovery verified ownership, removed the resources and orphan console, preserved
unknown outcome and all six blocked checks, then reconciled admission. No VM
domains remain; Docker and K3s are active. Private evidence is retained under
the existing budget (77.28 GiB allocated against 100 GiB at final audit).

Linux source verification: 957 pass/three explicit skips (960 total), 84.318
seconds; 17/17 controlled parity cases passed with fresh outputs. The skipped
qemu-img test is not new runtime evidence; two skips are Windows-specific.
[Implementation CI passed](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40986252266).
Independent engineering-agent review found no blocking final-code findings.
See the [source-pinned Luna handoff](../handoff/solutions/lifecycle-comparison.md).
RHEL hardening, encryption and qualified publication are deferred; both
qualification flags remain false. This does not diagnose an uninspected work run.

[Ubuntu lab policy v2](UBUNTU-LAB-POLICY.md) is prospective. Physical-token hardware
is not required for home acceptance; physical assurance remains unverified.
Trust-anchor review is delegated Codex engineering work, still pending actual
review. The owner input is legitimate Pro entitlement through the protected
provider; actual USG/FIPS execution and content reconciliation remain required.
Earlier evidence below retains its original v1 policy and source attribution.

## Previous RHEL baseline delivery

RHEL delivery: [PR 39](https://github.com/TheSlayer455/jake-wormhole/pull/39).
Its head/merge records are separate from the tested runtime revision below.

RHEL 10.0 is now owner-authorized as the next target. The separate BIOS baseline
uses the official x86_64 DVD, 8 GiB RAM, two vCPUs and a 32 GiB empty disk; the
smaller disk is a measured lab choice, not the Ubuntu 64 GiB profile. The first
attempt at `28b23ad` installed and allowed diagnostic final-user SSH with SELinux
enforcing, but a root-owned `0700` completion-marker directory blocked normal
readiness and prevented the catalog. It remains failed and was cleaned up.
Implementation `d39f7a0bc6c10e200fff44fa26bf866bef9ab517` changes that directory to
`0755`, preserves protected account/key paths, and adds a pinned native audit.
Its fresh retry reuses identical ISO bytes with a corrected, declared seed;
it passed real final SSH, Ansible ping, privileged smoke and 413-package RPM
inventory in 272.246 seconds. Native audit accounts for all 948 rules: 172 pass,
261 fail, 56 not applicable, nine not checked and 450 not selected. XCCDF, ARF,
HTML and receipt agree; exit 2 preserves findings. Exact-owned cleanup completed
without errors, no VM domains remain and K3s stayed active.
Final audit found reconciled journals, an available shared lock and no owned
temporary containers, networks or filters. Project storage is 77.17 GiB against
the unchanged 100 GiB budget, with 107.9 GiB filesystem space available. Unrelated
resources were excluded from cleanup; broad bytewise immutability is not proven.
See [RHEL evidence and commands](../handoff/solutions/rhel10-install-baseline.md).
No RHEL hardening, encryption, FIPS, qualification or publication is claimed.
Linux source checks passed 953/956 tests with three explicit skips in 93.513
seconds; 17/17 parity cases passed. The skipped qemu-img integration also passed
separately on the homelab; two remaining skips are Windows-specific. Source
[CI passed](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40970024592).
An independent engineering-agent review found no blocking code findings.

Repeatability comparison repair: [PR 38](https://github.com/TheSlayer455/jake-wormhole/pull/38),
tested implementation `7fdf05be546b8c13af519d4310355079b5a0a8fe`. Different run
UUIDs alone previously allowed copied/missing guest identity evidence to count
as fresh installations. The existing comparator now checks bound scanner
receipts, distinct seeds/host keys and disjoint first/final boot identities.
Seven focused tests and independent engineering-agent review passed. Replay
accepts the real pair below and rejects private copies with reused identities
or missing receipts. Pending publication is still refused. No guest/input code
changed and no additional VM was needed; historical installation attribution
remains intact. Full-suite, delivery and merge results are recorded in the PR.

Delivery: [PR 37](https://github.com/TheSlayer455/jake-wormhole/pull/37).
Its head and merge records distinguish documentation delivery from the runtime
revision below. Final resource audit found no owned temporary resources or
pending journal entries; the admission lock was available, the unrelated sentinel
was unchanged and K3s remained active. Private media, native evidence and failure
records are intentionally retained within the storage budget.

Ubuntu PAM closure tested `3e1e00bc64d6d7c3fb4d3f2d846188626db8eace`:
two independent fresh encrypted installations of identical ISO bytes passed
40/40 checks each in 651/638 seconds. Host keys, seeds and boot identities differ;
638 package versions, three Snap entries, kernel, payloads and findings match.
Real installed PAM accepts the valid software credential and rejects five invalid
cases with OCSP/CRL enabled. Native lab results are 210 pass, one FIPS failure,
14 not applicable, five manual and 409 unselected; unmodified upstream remains
207 pass/four fail. Cleanup, stale refusal, missing-result rejection and actual
pending-publication refusal are verified. This is not a qualified ISO release.
See the [source-pinned PAM solution](../handoff/solutions/ubuntu-pam-crl.md).
Owner dependencies: legitimate Pro input/USG-FIPS execution and content checks,
physical-token assurance, and accountable disposition of all 141 trust anchors.
RHEL was paused at that Ubuntu checkpoint; its new baseline is tracked above.
Production eligibility remains false. That checkpoint recorded self-review only.
The complete source suite at that runtime revision passed 947 tests on Linux:
945 pass/two platform skips, 158 seconds. Hosted CI passed the same 947 tests
with 12 explicit skips; its controlled parity job also passed. Windows at the
earlier controller checkpoint passed 947 tests with 321 platform skips; focused
Ubuntu checks cover the later source changes without relabeling that full run.

## Previous storage delivery

Storage delivery: [PR 36](https://github.com/TheSlayer455/jake-wormhole/pull/36).
Project allocation fell from 108.9 to 70.5 GiB; receipts verify 40.6 GiB unlinked
blocks, including new acceptance intermediates. Filesystem availability grew by
51.9 GiB; that shared-filesystem delta is not wholly attributed to Wormhole.
Retained: 28.2 GiB candidates, 33.9 GiB evidence, 8.5 GiB protected sources/inputs,
3.8 MiB releases and 1.3 MiB legacy staging/directory metadata. No VM disks remain.
Fresh execution at `254161b9ed822be350ec691689c8846c95dbfc7a` passed 34/34 checks in
650 seconds; its post-run hook reclaimed 2.1 GiB. Guards at
`d5a9e7c757a1fb805a8e530c22606710f4d6f3ae` passed 21 focused Linux tests and
[CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40787533279).
Warm cleanup found zero actions in 12 seconds. Active refusal, interruption
reconciliation and failed-run retention were exercised; 121 original evidence
and 156 release-file hashes match. Journals are finished, temporary resources
absent, sentinel unchanged and K3s active. The excluded live media image retains
its inode, size and blocks; its timestamp changed, so bytewise immutability is
not claimed. Self-review only. See [storage policy](STORAGE.md) and
[continuation](../handoff/CURRENT.md). Ubuntu qualification remains pending.

[PR 34](https://github.com/TheSlayer455/jake-wormhole/pull/34) merged as
`564cfc5f02cdaf348b15fe788a62987b7d156b2a` with
[passing main CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40716620271).
A fresh run from that exact merge reproduced all 34 functional passes, matching
inventories/native results and verified cleanup in 622 seconds. Three independent
same-ISO installations now have matching substantive outcomes and distinct host
keys/credentials. Final audit found zero transient resources or pending journal
entries, available admission lock, 34 retained images present, unchanged unrelated
sentinel and active K3s. Qualification remains pending; no ISO release was promoted.

Ubuntu sandbox implementation is verified at `deda43f7100fb8aec42285fc941e2eecffcdb795`
and repeated through `8e510ce023aeb2196f3d637c69b7e50ee81a9520`: two fresh installations
of identical encrypted ISO bytes, 34/34 functional checks each, matching complete
inventories and native assessment outcomes, and verified cleanup. Runs took
616/617 seconds. Source verification at `deda43f`: 918 tests, Linux 916 pass/two
skips and Windows 618 pass/300 skips; hosted CI passed. See
[PR 34](https://github.com/TheSlayer455/jake-wormhole/pull/34) for delivery/merge records
and the [current solution](../handoff/solutions/ubuntu-install-hardening.md) for
actual service, encryption, failure and evidence boundaries. Self-review only.

OpenSCAP 1.4.6/CaC V2R7: 208 pass, three fail, 14 not applicable, five native
manual outcomes and 409 upstream unselected. An additional unmodified upstream
audit retains 206 pass/five fail; only declared lab endpoint/banner values differ.
Four objective manual conditions are met. Entitlement/FIPS, physical-token and
government-PKI assurance, a vendor-syntax/benchmark mismatch and unverified USG
content equivalence prevent qualification. Actual pending publication is refused;
there is no qualified Ubuntu ISO. RHEL remains paused; production eligibility is false.

## Previous Ubuntu hardening delivery (historical)

Ubuntu-only hardening is the active milestone. RHEL development and media work
are paused by the owner, while existing RHEL/UBI code and regression evidence
remain preserved. USG enrollment/FIPS requirements are pending, not waived.
See [current continuation](../handoff/CURRENT.md) and the versioned Ubuntu policy.
Hardened Ubuntu execution at `be1aac0` and verified reuse at `109efdc` passed
14/14 functional checks each and completed real OpenSCAP: 191 pass, 18 fail,
16 not applicable, five not checked and 409 upstream not selected (639 total,
230 selected). Inventories, kernel and required outcomes matched across fresh
disks with distinct credentials/boot IDs. Native reports, 630-package/three-Snap
inventories and cleanup are verified. This is LAB QUALIFICATION PENDING, not a
completed Ubuntu release. See [proven hardening](../handoff/solutions/ubuntu-install-hardening.md).

[PR 31](https://github.com/TheSlayer455/jake-wormhole/pull/31) merged the verified
increment at `63d3aa1fb90cdc478f7e50d76384d944130bfbff`, with
[passing main CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40626679451).
A third fresh installation of the same ISO from that merged implementation
reproduced all 14 functional passes, native assessment counts and complete
inventories in 566 seconds. Final source verification: 901 tests on each platform,
899 pass/two skips on Linux and 607 pass/294 skips on Windows. Cleanup and shared
admission reconciliation were verified; the unrelated sentinel was unchanged
and K3s stayed active. Raw captures remain private. Required entitlement,
encryption/unlock implementation, external-control inputs, manual dispositions,
coverage mapping and eligible publication remain outstanding; no qualified ISO
was published. The [current handoff](../handoff/CURRENT.md) distinguishes tested
implementation from documentation delivery. No independent review is claimed.

## Historical home ISO foundation

The owner authorized home KVM/libvirt and real RHEL 9 / Ubuntu 22.04 installation
profiles, superseding the earlier container-only scope restriction. The container
baseline below remains accepted at its original source. See the concise
[ISO checkpoint](../handoff/ISO-FOUNDATION.md) for new implementation, actual
execution and remaining media/assessment/qualification work. No lab or production
ISO qualification is currently established.

Ubuntu 22.04.5 BIOS VM baseline passed at `31eca5832db3225ca7c10a5c4147c03ec8612e9f`
and was repeated at `55bb2fb1ba657149d836a916dfc6be318b43a430`:
fresh disk installation, final dotted identity, trusted SSH, actual Ansible,
610 package/version records and verified cleanup in 205 / 201 seconds. This is an
installation baseline with no hardening/assessment claim. The 883-test source
suite and hosted CI passed at `8cce6674eae525944a62d05cc2d453e475e856eb`.
Authorized RHEL media remains unavailable. See the checkpoint for exact limits
and [proven solutions](../handoff/solutions/README.md).
PR 29 merged as `44f33f8dccfec0f7806524cb229674e5f4b08336`; fresh post-merge VM
acceptance passed in 201.816 seconds, with complete inventory, verified cleanup
and [green main CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40604686004).

## Final runtime recovery checkpoint

Container reference runtime acceptance is verified. [PR 28](https://github.com/TheSlayer455/jake-wormhole/pull/28) delivers the repairs and [execution checkpoint](../handoff/RUNTIME-ACCEPTANCE.md).
Tested implementation: `f8e5f0ef8f3764617516f5716840fcbb751589f6`.
The established service-operator connection was recovered from prior records; owner-context admission succeeds without changing permissions or credentials.

Real Ubuntu acceptance passed 43 checks; fresh and reused UBI passed 46 each. Immutable image reuse, changed-installed-input refusal, all nineteen fixed scenarios, interrupted initialization, isolation and local publication were exercised with original evidence retained. The stock twenty-target run passed 160 readiness, 200 functional and 200 inventory checks. A mixed twenty-target run retained 200 blocked rows and launched no catalog.

867 source tests passed with explicit skips: Windows 585 passed/282 skipped; Linux runtime owner 865 passed/two skipped. [Implementation CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40455121591) passed. Final audit: 140 finished admission archives, zero project containers or networks, zero pending resources, 33 verified retained images and an unchanged unrelated sentinel. Failed attempts and deliberately incomplete publications remain private and preserved. No independent review is claimed. Production ISO eligibility remains false; stock fleet and candidate-single acceptance remain distinct.

## Historical engineering checkpoints

The owner-authorized [failure-reproduction follow-up](FAILURE-REPRODUCTION.md) is
in progress. It adds strict fleet readiness admission, shared observation
projections, explicit diagnostic scope, inherited deadline support and candidate
input fingerprints. Fresh runtime acceptance is blocked by operator access to
retained project state. The original qualification below is not evidence for the
new source. Current test/review status is recorded in the follow-up checkpoint.

Implementation `ba9d1a23ac591a122c0d0b3017d5c5a80afc31db` passed 805 tests on
Windows (273 skips) and Linux nonroot (10 skips), plus hosted CI. Manual controlled
parity observed 0/1/1; all three mode-all semantic files matched hosted output byte
for byte. [Draft PR 27](https://github.com/TheSlayer455/jake-wormhole/pull/27)
contains the increment. Runtime acceptance, additional fault adapters and actual
image reuse were outstanding at that checkpoint; no independent review or full rebuild completion
is claimed. See the checkpoint for commands, timings and the retained failed
test-fixture predecessor.

The current implementation adds observed initialization/configuration, an explicit
lifecycle with separate terminal outcomes, nineteen fixed fault scenarios,
bounded contained-exec reconciliation, per-target reports and verified immutable
Ubuntu and UBI image reuse. New complete-reference and stock-twenty paths require
initialization before SSH/Ansible. Reference publication preserves original
tested bytes on reuse. Current source verification and runtime limitations are
tracked in the same checkpoint. The existing recovery command now reconciles
contained initialization after coordinator interruption while preserving unknown
Terraform/create/commit refusals. Actual Docker execution, benchmarks and
independent review remain outstanding.

Earlier tested implementation `6a8f7bf46b45f07332d0ca4bb1570aab74149839` passed
840 tests: Windows 564 passed/276 skips; Linux nonroot 830 passed/10 skips.
Its hosted PR workflow passed. Manual/hosted semantic parity matched at the
separately recorded predecessor `a6d5109`. No new Docker acceptance or runtime
performance result is established by those source checks.

Latest tested implementation `492aa1051d3c298bd8ac71d602803f035d3f6501` passed
862 tests: Windows 581 passed/281 skips; Linux nonroot 852 passed/10 skips; local
WSL Linux root 860 passed/two skips. Hosted CI passed. Manual controlled parity
at that source returned 0/1/1 with validated diagnostics. The final source checks
include collector-only reuse, original UBI package/license replay, interrupted
initialization proof and no-catalog admission regressions. No new homelab
containers were allocated and no independent review has occurred.

Post-merge verification, October 24, 2026. All 21 original delivery PRs are merged. The qualified main source is `c3d440a3c7eee9691f30315b49146eb72998d2df`, tree `f5a69b447b224840c66229c00f0fd2e102812449`. See [merged verification](../handoff/MERGED-VERIFICATION.md). Original ticket evidence and tested revisions remain unchanged.

| Fact | Recorded scope |
| --- | --- |
| Implemented | Fixture CLI, admission, pinned images, real Terraform/SSH/Ansible, recovery, functional checks, chunks/candidates, optional PowerShell, UBI, observed SVD, reference reports/gate, local publisher, isolation and stock twenty-target operation |
| Repository | PR21 merged at 19:50:33 UTC; all 21 original delivery PRs recorded merged by 19:50:35 UTC. The qualified tree equals the accepted parent closeout tree |
| Source checks at merged main | Windows: 788 total, 515 passed/273 skips, CPython 3.12.14, 121.747 s. Linux nonroot: 778 passed/10 skips, 76.733 s. Linux root: 786 passed/two Windows-only skips, 78.403 s. Both Linux runs used CPython 3.12.3; this difference is explicit |
| Hygiene/discovery | Repository baseline, original acceptance matrix and local doctor passed on all three environments |
| Controlled parity | Same-source Linux nonroot manual/GitHub modes observed 0/1/1; first three semantic files matched byte for byte, 102 distinct component Runs. Both red jobs failed intentionally and retained validated uploaded diagnostics |
| Latest actual runtime | Merged-source Ubuntu Run `8f14b817-486f-4340-87fd-85fe53a9aa6b`: all 43 required rows passed; separate report/gate agreed; cleanup completed, canonical admission finished with no pending resources, unrelated sentinel unchanged |
| Latest actual twenty-target qualification | Source `825a594862b816401d4b963329e6242bd8ed8aeb`, Run `290ad14a-e6ec-4822-ae36-258d336ecc38`: 160/200/200 rows, twenty 123-package inventories, 22-container interval, all 23 transient resources absent |
| Historical acceptance | [Matrix](acceptance-matrix.md): 83 original scenarios across 11 categories and 16 evidence files; these remain original-source observations |
| Minx | Original child completion/criterion/solution records remain in the [parent ledger](../handoff/evidence/WORM-001.json). Refresh live Minx before mutations; source snapshots are not leases |

The fresh Ubuntu reference run retained its candidate image; its four containers and network are absent. Earlier retained images/private Run state and intentionally incomplete publications remain preserved. No cleanup, source reinterpretation or marker repair is implied by merging.

[WORM-020 evidence](../handoff/evidence/WORM-020.json) retains all four failed actual predecessors. Historical WORM-021 source `3f7e3cf3` parity, source checks and red jobs remain in its [checkpoint](../handoff/WORM-021-checkpoint.md). New merged-source results supplement those facts; they do not replace their hashes or attribution.

The documentation-only follow-up has its own PR/main CI. A later documentation commit does not become the source of the `c3d440a3` runtime or parity observations. Built, merged, source-tested, hosted-CI-tested, homelab-executed, locally reference-published and accepted remain separate facts. GitLab runner execution, VM/ISO/scanner compatibility and production ISO eligibility remain unverified or excluded.
