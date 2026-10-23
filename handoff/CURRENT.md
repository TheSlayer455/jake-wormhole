# Current continuation: WORM-014 delivery

<!-- WORM-014 actual qualification db5d8e74f54483a909faaed963c752962785653c -->
## WORM-014 actual RPM reference qualification

Exact source `db5d8e74f54483a909faaed963c752962785653c` completed four fresh actual UBI9.8-derived cases,
observed at 2026-10-23T19:09:20.242487+00:00. The healthy case retained twelve passing
checks. Missing optional openssh-clients retained twelve pass/one fail; the wrong
version expectation retained eleven pass/one fail; unsupported Ubuntu applicability
retained seven pass/one fail/four unverified RPM checks. These negative harnesses
passed by observing the intended failed underlying operation.

| Scenario | Run | Underlying operation | Primary failure | Cleanup |
| --- | --- | --- | --- | --- |
| healthy | `d473d988-f7d7-469f-95a1-2689295311fb` | passed | none | completed |
| missing-optional-package | `2948e601-9239-40f8-b681-8afd4b3c9903` | failed | rpm_missing_package | completed |
| version-expectation-mismatch | `86a24145-481c-4c96-aab0-7c8bccc37621` | failed | rpm_version_mismatch | completed |
| unsupported-os | `0274e785-d0f9-4382-8186-3d7326c61e22` | failed | rpm_applicability_mismatch | completed |

The fixed public BaseOS solve selected two RPMs. Actual isolated RPM verification
retained both original successful signature outputs and hashes; offline installation,
dependency checks, full package NEVRAs and the exact unmodified UBI EULA were
observed. The same four candidate file bytes retain one content identity across
separate UBI manifests/images. The stock helper and trusted provisioner remain
separate. The validated UBI binding selects exactly SETGID, SETUID, SYS_CHROOT and
AUDIT_WRITE; this permits owned authentication audit records in the shared kernel
audit log. No audit read/control, KILL, PAM or host-setting change is established.
Ordinary Ubuntu keeps its original three-capability policy. Ordinary Ubuntu regression Run `f623e6ca-858b-4f10-9311-0bfbe2a1028c` passed all ten
functional checks with readiness, normal cleanup and unchanged unrelated sentinel.

Source fixtures: Windows 454 cases, 276 pass/178 explicit skips
in 35.432 seconds; homelab Linux 454 cases, 452 pass/2 skips
in 33.834 seconds; native Linux 454 cases, 452 pass/2 skips
in 25.661 seconds. Source fixtures are separate from actual runtime acceptance.

Earlier failed image/probe, resolver and target-environment attempts remain failed
in history. Their cleanup/reconciliation does not rewrite their original outcomes.
The initial unknown pull receipt stayed unchanged; its separate positive-image
reconciliation did not mutate Docker or adopt resources. The 718 build had genuine
signature/EULA success but failed provision. The 66 retry passed provision/TCP
and then refused SSH authentication. The ce3 diagnostic retry also failed SSH;
its original bounded server log recorded audit-write EPERM. Successful diagnostic
capture does not turn that failed SSH result into a pass. All remain failed.

Exact owned containers/networks are absent, base/derived images and private evidence
are retained, and unrelated sentinel checks passed. Actual cgroups bound project
processes; daemon materialization and sampled storage are stated separately.
No full RHEL VM, ISO boot/install, scanner/STIG, complete pipeline, production
eligibility or owner acceptance is established. Publication and hosted CI remain
separate observations. Refresh Minx for current requirements and decisions.

See [evidence](evidence/WORM-014.json), [history](evidence/WORM-014-initial-attempts.json) and [engineering review](reviews/WORM-014.md).

## Preserved historical checkpoints

# Current: WORM-014 implementation, October23 at18:01UTC

WORM-002 through WORM-013 and WORM-016 are Done in Minx through explicit
owner-directed delegated normal UI decisions, with source-bound evidence and
solution comments. WORM-014 revision2 is approved and claimed for the bounded
RPM derivative container extension. Its runtime qualification is not yet done.
This isolated branch normally merges completed candidate57978e20,
fleet06540879 and optional PowerShell68c30b08; all earlier checkpoints below
retain their original times and may describe work subsequently completed.
No PR is merged or production deployment/ISO eligibility implied. Refresh Minx
for current claim expiry and requirements before continuing.

## Preserved historical checkpoints

# Current continuation: WORM-013 delivery

<!-- WORM-013 actual qualification dfff72bec8bbea050bae73e6bba846e388f449e9 -->
## WORM-013 actual candidate qualification

Exact source `dfff72bec8bbea050bae73e6bba846e388f449e9` completed four fresh, serial actual candidate acceptance
cases observed at 2026-10-23T17:56:51.036437+00:00. The healthy case retained seven passing read-only
SSH/Ansible checks. The controlled version-expectation negative retained six pass
and one fail; it changed the expected version, not the actual target. Wrong
candidate and image identities refused before Terraform/helper allocation.

| Scenario | Run | Underlying operation | Primary failure | Cleanup |
| --- | --- | --- | --- | --- |
| healthy | `c912efb0-a63b-439a-b4cb-b028ac74cbec` | passed | none | completed |
| wrong-candidate | `1ff477b0-d748-4e9b-9da3-82b8ac5391e9` | failed | candidate_binding_invalid | completed |
| wrong-image | `9e67de2c-11f0-4411-9aa7-7aa65491e449` | failed | candidate_image_mismatch | completed |
| version-expectation-mismatch | `297cece7-858c-4d45-977f-3bb19ea4429e` | failed | candidate_required_check_mismatch | completed |

Each case bound reconstructed source, candidate manifest, a distinct derived
image and the fixed test contract. Cleanup removed exact owned containers and
networks, retained each derived image and private evidence, and preserved the
existing unrelated sentinel. The stock qualified helper/provisioner stayed
unchanged. No candidate ISO or proprietary input was used.

Exact-source fixtures: Windows CPython3.12.14, 330 tests, 195 pass and 135 explicit
skips in 24.651s; nonroot WSL CPython3.12.3, 330 tests, 327 pass and three skips
in 18.731s; actual homelab CPython3.12.3, 330 tests, 328 pass and two skips in
24.693s. The repository baseline passed with 148 tracked files and 129 local link
targets. Source fixtures are separate from the real runtime cases.

The earlier `baaf2f6` attempt remains failed with `candidate_base_invalid`.
Its reviewed private original-source operator proved zero allocation and finalized
the admission journal through `AdmissionLease.resume/finish`, preserving original
receipt hashes and failure. It made no Docker mutation, adoption or unknown-result
clear. The new public recovery adapter has fixture coverage; it was not the
operator exercised for that historical failure.

Portable [evidence](evidence/WORM-013.json) and [review](reviews/WORM-013.md) contain sanitized Run,
binding, check and cleanup details. Private captures, keys, Terraform state and
generated source remain outside Git. Production ISO eligibility and complete
runtime-pipeline flags remain false. Publication, hosted CI and Minx review or
acceptance are not established by this checkpoint. Refresh Minx before continuing.

## Earlier checkpoint history

The following entries retain their original observation times and may be superseded above.

# Current continuation: WORM-012 delivery

## WORM-012 component qualified, October23 at17:10UTC

Exact72d3e6ded014d3d2b40e70f836e8dfe1dea8bef3 passed independent source review
and twelve actual generated local/loopback HTTP cases on Windows and Linux.
Ten negative operations per environment remain failed and block candidate
consumption. Missing/duplicate/reordered/truncated/corrupted chunks, unsafe paths,
partial outputs and absolute HTTP header/body/shutdown bounds are tested.
Windows252cases145pass/107platform skips11.886s; nonrootWSL Linux252cases249pass/
three explicit skips10.250s. [Evidence](evidence/WORM-012.json) records
exact Runs and limits. No Docker infrastructure or proprietary access occurred.

Final private publication, hosted exact-source CI and normal delegated Owner
completion are next. Source reconstruction does not establish candidate-image
binding (013), complete pipeline, ISO boot or production eligibility. Private
generated files remain outside Git. Retrieve Minx for current claims/status.

# Current continuation: WORM-016 delivery

## WORM-016 component qualified, October23 at17:10UTC

Exact3e11548a253fbd7799606dc978d69f5965c5cea0 passed independent source review after the typed-evidence alias
correction. Actual five generated local cases and new-process report replay all
passed. Linux253cases251pass/two Windows-only skips10.953s; Windows253cases
146pass/107platform skips8.402s. Both release flags remain false for every policy
verdict. [Evidence](evidence/WORM-016.json) and
[review](reviews/WORM-016.md) identify actual Runs, hashes and limits.

Final private publication, exact-source hosted CI and normal delegated Owner
completion are next. WORM-002 through009 are Done;010/011/012/016 are approved
and active. Retrieve Minx for current versions/claims. No new Docker resources,
scanner, host package, service, routing or storage change occurred in016.

# Current continuation: WORM-010/012/016

## Current: WORM-010/012/016, October23 at17:02UTC

Minx confirms WORM-002 through009 Done. WORM-009 is v23/r2 with no claim;
all six real cases passed atde745a6, final privatePR8 delivery1979e7e passed
hosted push39990286859 and PR39990291097. Its six AC records and solution
comment are saved. Decisions are owner-directed automation under Jake's explicit
delegation, not independent human examination. All009 owned containers/networks
are reconciled; original failed skip attempt stays historical. Private state,
keys, cache and qualified images remain intentionally retained.

WORM-010,012 and016 are approved r2 and claimed with distinct session IDs.
Refresh Minx rather than relying on these expiring checkpoint observations:

-010: codex-WORM-010-20261023-scale. Contracts owns indexed Terraform/provisioning/
recovery in jake-wormhole-provisioner; UI owns one-helper fleet readiness and
validation in jake-wormhole-validation. Root owns jake-wormhole-scale-integration
and actual qualification. Reviewed API agreement uses exact target maps and an
explicit TargetPlan. New metadata profile commitc45f7bc has two passing fixtures.
No five-target execution is claimed yet; twenty-target runtime remains020.
-012: codex-WORM-012-20261023-chunks. Brief/research agent owns chunks worktree.
First sourceaa07117 is under review; absolute HTTP header/shutdown deadline
findings require correction before qualification/completion.
-016: codex-WORM-016-20261023-assessments. Root owns jake-wormhole-cli on
codex/WORM-016-assessments. Source9360014 passed actual five local generated
checklist cases and identical separate-process reports. Linux252cases250pass/
two Windows-only skips10.833s; Windows252cases145pass/107platformskips8.521s.
Independent engineering source review and final publication remain pending.

016 freezes complete expected IDs/applicability, preserves original bytes/hash,
strictly parses four statuses and replays counts/policy from the original.
Policy pass/reject is separate from release eligibility; both flags remain
false. Existing fixture records and v1 gates are unchanged. No scanner, VM/ISO,
production threshold or Lightspeed compatibility is claimed. Full candidate
pipeline, scale, SVD, complete gate and publication remain unfinished.


# Current continuation point: WORM-010 delivery

<!-- WORM-010 actual qualification 1920c9621017190a8756affab36e5d25e6102978 -->

## WORM-010 actual fleet acceptance passed, October 23, 2026

Clean source `1920c9621017190a8756affab36e5d25e6102978` passed staged one-target and five-target healthy checks, then ten fresh five-target cases. Every fleet case retained fifty required functional rows, per-target readiness/endpoint identity, two configured Ansible forks, original capture binding and readable/JSON agreement. Healthy and delayed-start cases passed all fifty rows. Each negative retained forty passing rows and ten explicit nonpassing rows; its underlying operation remains failed.

The cases cover delayed and never-started targets, wrong authentication key/user, changed host key, configured readiness/validation interpreter failures, and expected endpoint/network identity faults. Configured missing interpreter tests do not remove installed packages. Expected metadata faults do not change unrelated networking. Every case completed exact scoped cleanup and kept the unrelated sentinel unchanged. Private state, keys and captures remain outside Git.

Linux: 277 cases, 275 passed, 2 Windows-only skips, 19.359 seconds. Windows: 277 cases, 161 passed, 116 platform skips, 17.542 seconds. These source fixtures are separate from actual runtime acceptance. Independent engineering source reviews are recorded with their exact commits. [Criterion evidence](evidence/WORM-010.json) retains all twelve distinct Run IDs and sanitized result counts.

Twenty-target runtime remains unverified. This ticket does not qualify candidate binding, a complete pipeline, VM/ISO boot/install, STIG or scanner compatibility. Full-pipeline and production ISO eligibility remain false. Publishing, exact final-source hosted CI and the delegated normal Owner decision still require separate observation; this generator claims none of them.


# Current continuation point: WORM-011 delivery

<!-- WORM-011 actual capability 88c8df01c38986fb909b3cfe231a97081f790bc1 -->

## WORM-011 actual optional PowerShell acceptance passed, October 23, 2026

Clean source `88c8df01c38986fb909b3cfe231a97081f790bc1` passed four serial fresh operations: actual missing-package failure, independent ordinary Terraform/SSH/Ansible diagnostics, offline optional image build and a fresh optional PowerShell smoke. The missing operation remains failed with `package_unavailable`, expected `powershell=7.6.8-1.deb`, exit 100 and its exact helper location. A separate ordinary Run passed all ten actual functional checks and normal Terraform/helper cleanup.

Retained optional image: `sha256:7cbb64abd73f3a91b4d8d17a5f825902302e0fa772b88a1c3d66ec8aaa56b737`. Actual PowerShell was 7.6.8 Core/Unix with .NET 10.0.13 and fixed result 2. All dependency versions and the unchanged ordinary helper doctor passed. Actual builder cgroups were 2 GiB/2 CPU/256 PIDs and probe 512 MiB/1 CPU/128 PIDs, with zero extra swap. The stopped builder writable layer was 225,894,400 bytes; this is a sample, not a quota. Known owned containers were reconciled, the optional image intentionally retained and the unrelated sentinel unchanged.

Linux homelab source fixtures: 258 cases, 256 passed, two Windows-only skips, 11.361 seconds. Windows writer fixtures: 258 cases, 149 passed, 109 platform skips, 8.346 seconds. Source fixtures are separate from actual runtime evidence. Independent engineering review closed commit-response, immutable image-provenance and interrupted known-cleanup gaps at the tested source. The original failed inode fixture record remains private; deterministic test correction and final exact-source verification passed.

[Criterion evidence](evidence/WORM-011.json) records actual Run IDs, package versions, cgroups and hashes without raw logs or credentials. Scanner compatibility remains explicitly unavailable: no authorized scanner package or documented compatible method was supplied. Host PowerShell, remoting/STIG/controller/transport/target compatibility, the complete pipeline and production ISO eligibility are not established. Publication, final-source hosted CI and the delegated normal Owner decision remain separate unverified steps here.

# Current continuation point: WORM-009 delivery

## WORM-009 actual acceptance passed, October 23

Cleande745a6ee7f80cddb2007ced380e2f67f79395f5 passed six real one-target cases:
healthy, controlled version/function expectation mismatch, configured interpreter
unavailable, unexpected Ansible skip and stopped-target unreachable. Ten frozen
checks per case retain actual observations, original raw-capture binding and
readable/JSON agreement. Each fresh Run used the same Terraform inventory,
strict SSH, Docker-free Ansible helper and exact scoped cleanup. Negative
underlying operations remain failed. The unrelated sentinel stayed unchanged.

Actual homelab source fixtures:237 cases,235pass/2 Windows-only skips,10.592s.
Windows:237 cases,131pass/106platform skips,8.497s. Independent source review
found no remaining material blocker. [Evidence](evidence/WORM-009.json)
records exact run IDs, timings, checks and resource samples. Private state, keys
and captures remain outside Git; owned qualification containers/networks are
reconciled. Qualified images and public tool cache remain intentionally retained.

Final private publication, exact-source hosted CI and delegated normal Owner
completion are next. Retrieve Minx/GitHub for their current state. Candidate
binding remains013; complete pipeline and production ISO eligibility remain
false. No independent human examination or PR merge is claimed.

# Current continuation point: WORM-009 runtime correction

## WORM-009 first actual acceptance, October 23 at16:42UTC

Source9756277 passed233 Linux fixtures (two Windows-only skips) and132 Windows
fixtures (103platform skips). Actual healthy, controlled version/function and
configured missing-interpreter cases passed. Unexpected-skip failed its category
check: the pinned Ansible tree callback omits skipped events, so actual SKIPPED
stdout had no structured tree result. The suite correctly stopped and retained
ansible_result_invalid instead of claiming the expected rejection was proved.

All five attempted Runs completed normal exact cleanup with the unrelated
sentinel unchanged. Canonical admission is finished and every recorded owned
resource absent. [Historical evidence](evidence/WORM-009-initial-attempts.json)
retains that failed suite; it cannot qualify delivery. A bounded original
structured callback correction and six fresh cases are required. WORM-009 is
still In Progress r2 under codex-WORM-009-20261023-functional. Refresh its claim
and current source before mutation. No completed full pipeline is claimed.

# Current continuation point: WORM-009, October 23 at 16:19 UTC

WORM-002 through WORM-008 are Done in Minx, with passing evidence and solution
comments. WORM-007 is v23, WORM-008 v21, both revision2 and no active claim.
Jake's explicit delegation authorizes normal Owner browser decisions; keep their
automated nature visible and never claim independent human examination.

- WORM-007: all nine real readiness cases passed at9db5f24. Final private PR6
  d1f81615 passed both exact-source hosted checks. [Evidence](evidence/WORM-007.json).
- WORM-008: all four real cleanup/recovery cases passed at68bd82d. Private PR7
  b4c021a8 passed both checks. [Evidence](evidence/WORM-008.json).
- Exact containers/networks from those qualifications and earlier failed attempts
  are reconciled. Private state/keys/evidence, images and public tool cache remain.
  Do not delete retained state or treat failed historical attempts as passing.
- WORM-009 is approved r2 and claimed under
  `codex-WORM-009-20261023-functional`, initially expiry16:33:43 UTC. Refresh it
  through the scoped API before work. Root jake-wormhole-cli is on
  `codex/WORM-009-integration`; UI jake-wormhole-validation is on
  `codex/WORM-009-validation`. Both started at combined1d6bda5.
- UI owns the fixed read-only functional helper, plan/result policy, tests and
  docs. Root owns CLI, actual acceptance, publishing and delegated Owner controls.
  Do not concurrently edit provisioning/recovery/readiness or overwrite worktrees.
- Next: freeze a source-bound package/configuration/runtime smoke payload check
  plan; execute real SSH Ansible observations; prove fresh negative attempts and
  strict completeness; perform normal scoped cleanup. The baked runtime SHA is
  the smoke payload revision, with candidate-derived binding explicitly left013.
  No WORM-009 acceptance has been tested yet.

Read [STATE](../docs/STATE.md), [009's current Minx contract](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-009),
[readiness](../docs/READINESS.md), [recovery](../docs/RECOVERY.md) and the source
before continuing. The full pipeline, five/twenty-target runs, SVD/assessment and
publication remain unfinished. Production ISO eligibility is always false.

## Historical continuation point, October23: WORM-007/008

Minx: WORM-002 through006 Done;007 and008 revision2 approved and claimed under
distinct sessions. Parent001 remains Draft. Jake delegated normal Owner workflow
clicks in this chat; preserve the explicit automated decision record and never
claim independent human examination. No further per-ticket click request is needed
while the existing authorized Owner session is available.

- Root worktree jake-wormhole-cli: codex/WORM-007-integration. Reviewed thin
  provisioning split f17a9eb+a54c3be passed actual Linux149 tests (147pass,two
  Windows-only skips). Root owns orchestration and source integration.
- UI worktree jake-wormhole-tools: codex/WORM-007-readiness. Owns readiness module,
  fixed helper runtime, focused tests and documentation. Genuine SSH/Ansible
  acceptance, strict trust and accurate failure categories remain required.
- Contracts worktree jake-wormhole-provisioner: codex/WORM-008-recovery. Owns recovery
  module/schema/tests/docs and provisioning destroy/resume idempotence. It has
  received the root's thin split before editing the shared file.
- Root auxiliary jake-wormhole-recovery-cli: codex/WORM-008-cli, commitd548b78.
  CLI dispatch fixtures pass; the actual recovery module is still required for
  integrated operation. Cancellation requests take no coordinator Run lock;
  normal cleanup/recovery owns its exact locks and preserves primary outcomes.

Retrieve the actual claim/version through the scoped API before mutation. Claim
sessions are codex-WORM-007-20261023-readiness and codex-WORM-008-20261023-recovery.
Renew/checkpoint explicitly. Do not read Owner credentials, configure new hooks,
reset another worktree, silently clear daemon uncertainty, or allocate outside
the canonical bounded plan. No007/008 acceptance or complete pipeline is claimed.

Completed006: private PR5 at c58c1a17; both hosted checks39978416986/39978424524
passed. Actual three-case qualification source06c19f16, criterion evidence and
solution comments are in Minx. [Evidence](evidence/WORM-006.json) and
[review](reviews/WORM-006.md) separate actual runtime from fixture tests and
historical failures. Images/private cache/state remain intentionally retained;
all owned006 qualification containers/networks were reconciled. Continue the
dependency graph through every remaining child and then parent001.

## Historical continuation point, October23 at15:25UTC

WORM-006 actual qualification passed at exact clean source
06c19f16d45fe66cd0ebde0432372b2d060f7226. See [evidence](evidence/WORM-006.json),
[review](reviews/WORM-006.md), [state](../docs/STATE.md) and
[Terraform operations](../docs/TERRAFORM.md). All three fresh acceptance cases
passed, with exact cleanup and an unchanged unrelated sentinel. Negative partial
operations and earlier failed attempts retain their failed status. No active
target/network/provisioner remains from these qualifications. Images, public base,
private cache/state/keys/evidence remain intentionally retained outside Git.

1. Retrieve Minx's actual006 status/version/claim before a mutation. WORM-002
   through005 are Done. At this checkpoint006 remains In Progress pending final
   source publication, hosted CI, evidence/comment and delegated normal Owner
   decisions. The source commit containing this record adds documentation and
   sanitized evidence; actual runtime source is recorded separately above.
2. Publish final006 branch/PR5, verify exact hosted CI, attach all three criterion
   results and a solution comment, submit In Review/release, then use Jake's
   delegated Owner controls on passing evidence. Record automated delegation,
   never independent human examination. No security policy or role grant changes.
3. After006 is Done, approve/claim007 and008 with distinct session IDs and isolated
   worktrees.007 owns genuine SSH/Ansible readiness;008 owns scoped cleanup,
   cancellation and interrupted teardown recovery. Serialize shared provisioning
   refactors and assign one writer per file. Discovery plans are not implementations.
4. Keep one held Run lock, Docker scope and canonical admission lease across a
   lifecycle. Existing exact-source recovery never allocates a replacement or
   clears unknown daemon work from elapsed time/empty sweeps. The fixed missing
   endpoint proof is specific; no general reviewed flag exists.
5. Continue the recorded dependency graph through all remaining child tickets and
   parent001. A complete pipeline, candidate binding, functional Ansible, scale,
   SVD/assessment and publication remain unfinished. Production ISO eligibility
   stays false. No PR has been merged or remote image/release published.

## Historical continuation point, October23 at14:52UTC

Read [AGENTS](../AGENTS.md), [STATE](../docs/STATE.md),
[architecture](../docs/ARCHITECTURE.md), [fidelity](../docs/FIDELITY.md),
[admission](../docs/ADMISSION.md), [images](../docs/IMAGES.md),
[tool preparation](../docs/TOOLCHAIN.md) and [delegation](../docs/decisions/0002-owner-delegated-workflow.md).

October23,2026,14:52UTC: WORM-002/003/004/005 are Done in Minx. WORM-006 r2 is
approved/claimed and In Progress. Root branch codex/WORM-006-integration is stacked
on005; private draft PR5 is open. Separate active writer codex/WORM-006-provisioner
has unfinished source. Coordinate before changing that worktree; never reset it.
Retrieve current Minx version/claim before mutations; do not borrow another
session's identifier or reuse an expired claim.

1. Exact prerequisite/tool source fc9ccf81e26ec83c11560f2f5579ab8ec316871e passed
   actual homelab106 tests (104pass/two Windows-only skips,5.208s) and Windows106
   (66pass/40platformskips,4.667s). Separate source review found no material blocker.
   New real provisioning runs explicitly use kernel_lock=True. Existing legacy
   locks are preserved; missing policy cannot downgrade a persistent kernel lock.
2. Actual [tool preparation](evidence/WORM-006-tool-preparation.json) passed at
   that source in3.007s, cache265,992,159 file bytes. Its no-allocation canonical
   lease finished. Terraform1.17.0/provider4.6.0 are verified/extracted but have
   not executed. Recorded GPG verification is prior provenance; SHA/TLS checks
   are repeated by preparation. Runtime h1 verification remains pending.
3. Integrate/review the separately authored ProvisioningSession and fixed bounded
   provisioner runtime/tests. Use the existing authorized state owner (actual host
   UID0), explicit group only if needed for its fixed Docker socket, dropALL/NNP/
   readonlyroot/networknone/finiteTTL and exact four-mount allowlist. Docker socket
   access remains host-authority trust regardless UID; no host user/chown/auth change.
4. Actual acceptance requires two disjoint one-target Terraform plan/savedapply/
   refresh/output/destroy runs, inspected stopped targets/PID limits before start,
   provider-derived endpoints, actual controller/target cgroups and private state.
   Prove provider/create failure accounting, no key contents/unintended SSH ports,
   ownership refusal and exact destruction. Do not substitute native target creation
   or guessed IPs. Preserve primary diagnostics, state and all uncertain outcomes.
5. Retain the exact provisioner until Terraform destroy. Resume cannot allocate a
   replacement. Its capacity check is evidence only; the adapter must prove exact
   retained identity/configuration and bounded destroy-only operation. A bare flag
   cannot establish an unknown daemon request's completion. No journal edits/prune.
6. Publish final006 source and observe exact hosted CI; attach criterion results and
   solution comment, submit In Review/release. Use delegated normal Owner decisions
   for solved work. Then007 readiness and008 scoped cleanup/recovery become eligible;
   009 is first functional Ansible integration. Keep partial receipts separate from
   the unsupported complete pipeline; production ISO eligibility remains false.

WORM-005 [evidence](evidence/WORM-005.json) records two actual strict SSH runs,
negative trust/authentication, distinct keys and exact cleanup. Its original image
IDs/build revisions remain intact. Images/public base and private tool/run evidence
are intentionally retained. No unrelated workload, host install, routing, security,
storage, external model or other chat changed. No PR merged or remote image/release
published. Minx owns current review state; engineering review is not independent
human examination.
