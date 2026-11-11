# Terra's Lightspeed execution brief and Wormhole evidence

Copy this entire file into Terra in the authorized work chat. It includes the
owner directive, the immediate recovery task, and the verified Wormhole reference.
The source links and file list are for optional follow-up pastes.

## Current owner directive for Lightspeed

The owner administers Lightspeed's code, repositories and systems. This directive
supersedes earlier Lightspeed workflow preferences. Routine implementation,
commits, direct pushes to main, focused testing, disposable acceptance guests
and cleanup of exactly identified run-owned resources are authorized. Reviews
can find concrete defects. Proceed without a conversational approval, pull
request or review gate for these authorized actions. If a tool, server or
organization actually enforces a restriction, give the specific restriction
and affected action. Label a recommendation as a recommendation.

Work through chat. The owner runs commands in work WSL and returns results.
After each result, give one coherent runnable command group or patch. Specify
the working directory, expected result, done-check and smallest useful output
to paste back. Use paths, options and services established by the supplied
evidence. Ask only for facts needed to run the next step. Maintain the existing
tracker with the first confirmed failure, current disposition and next step.

Keep Terraform, the existing controller, candidate identity, the team's
installation contract and strict host trust. Fix the smallest component that
owns the observed defect. Preserve the existing authorized access and cleanup
mechanisms. Keep review and reporting work proportional to the immediate repair.

## Verify one change before running the pipeline

Name one failing behavior, the boundary that owns it and the smallest check
that can disprove the proposed cause. Freeze the case and change one input or
behavior at a time. Reuse the closest existing test or invoke the actual
component with a small fixture. Give the owner one bounded command group with
the expected result and the useful output to return.

| Change | Fastest useful check |
| --- | --- |
| Code or script | Run the actual function or entry point with the same failing input before and after the change. Assert on output, status or the expected side effect. |
| Configuration | Use the real loader or command that consumes the config. Check the effective value and its effect, including any override relevant to the failure. |
| Generated installer input or deployed script | Run the normal render or staging step in isolation. Inspect the resulting input or script where its consumer reads it. Record the identity of the file actually used, separately from the source revision. |

Show the original failure and the corrected behavior with the same test. If
the original does not reproduce, check the input, execution context and timing
before choosing another fix. Syntax checks and rendered-file inspection give
useful intermediate evidence. Label what actually ran and what still requires
integration. Record the observed before/after result and elapsed time in the
existing tracker. Once the fast check answers the question, use only the next
runtime boundary the check cannot reach.

## Current case: the missing console marker

Use the latest attempt to establish the current failure. A history of repairs
and clean worktrees do not establish the remote runtime state. If current
evidence already proves the marker boundary, preserve that result and move to
the first unresolved installer transition.

1. Start with one read-only inspection in work WSL. Locate the owning collector,
   preflight reader, remote relay and latest attempt. Freeze that attempt's
   controller revision, actual remote script, exact ISO and effective
   installation inputs, and the console evidence file. Keep the work records
   private. Correlate the observer, remote process, guest and files to the same
   attempt. A CI timeout or disconnected relay leaves remote termination
   unverified. Reconcile active or uncertain ownership before mutation, retry
   or cleanup. A prior manual console observation belongs to its own attempt.
2. Trace one marker from reader attachment to emission, collector receipt,
   incremental write and preflight read. Establish which events the latest
   evidence supports, including whether collector and preflight used the same
   file and whether bytes were visible before evaluation. Find the first
   missing transition. Keep repeated short attachments as a hypothesis until
   the trace or a reproducing test supports it.
3. Without a VM, feed a timed, one-shot marker into the actual collector
   through a disposable stream or fixture at the console boundary. Reuse the
   observed timing that triggers the problem and keep the producer open
   through preflight. Use an observed event or bounded wait to coordinate the
   test. Run unchanged preflight against the actual output file while the
   collector is active. Keep separate fresh
   evidence files for both variants. Verify the original fails as observed,
   then run the identical case with the smallest collector correction. A
   marker appended by the test to the evidence file can test the parser alone.
   The collector regression needs the bytes to travel through the collector.
   If the collector has no usable input seam, report the exact boundary the
   cheap check can reach and keep the rest unverified.
4. Before the focused run, prove live transport with a short remote probe over
   the existing authenticated route. Reuse a recorded probe for the same relay
   if its path and behavior are unchanged. Check that distinct nonsecret
   messages appear in GitLab before producer exit, with usable ordering,
   timestamps and correct exit status. Test redaction with synthetic input. Keep one
   early collector per guest. The relay follows that collector's evidence
   without a second attachment or remote restart.
5. After the cheap regression passes and prior resources are reconciled,
   run one focused RHEL 9 installation. Verify the executing revision and
   effective deployed inputs against the corrected test, with the candidate
   and unrelated inputs unchanged. The checkpoint is the intended collector
   capturing the marker, the same file containing it before evaluation, and
   the unchanged preflight accepting it while the collector is active.
   Continue through installed-disk boot, trusted final SSH, Ansible and
   dependent checks as their prerequisites pass within the run budget. Inspect
   existing installer, generated-input and storage evidence for the actual
   error or wait if installation stops. Verify generated inputs were consumed.
   A marker alone cannot prove target-disk installation. A preinstall generator
   must not wait for disk changes performed later by the installer. Preserve
   installed inventory and required assessment results when reached. Keep a
   terminal receipt for this attempt with any first failure, blocked checks
   and cleanup disposition.

| Result | Meaning |
| --- | --- |
| Preflight still misses the marker | The boundary remains open. Revisit the trace and the evidence for the proposed cause. |
| Preflight accepts the marker, then final SSH fails | Record the verified repair and investigate final SSH as a separate boundary. |
| Logging disconnects after a recorded failure | Preserve the original failure. Record the logging failure separately and reconcile the attempt. |

## Time budget and failure behavior

Use **20 minutes total** for the first focused attempt, including evidence and
cleanup. Set the existing focused GitLab job timeout to 20 minutes where the
configuration permits. If the inherited job ceiling is still 90 minutes, use
the same 20-minute operational deadline in the controller and relay while
reporting that outer limit accurately. The earlier 90-minute wording is
historical context, not this attempt's wait budget.

Set the focused command's absolute cutoff once, including its setup and staging.
At remote launch, inspect the actual job, runner and script limits and use the
earliest applicable cutoff. Compute the remaining execution allowance from the
time still available, less the remaining evidence-finalization, cleanup,
transport/upload and safety reserves. Count each operation once, including
reserves already inside another stage's allowance. A setup stage or retry never
resets the original budget.

For an otherwise unused 20-minute window, about 16 minutes of work and four
minutes of reserve is a starting allocation. Reduce work time for elapsed setup,
a shorter effective cutoff or a larger measured reserve. Keep the relay
available through collection. Bound existing subprocesses by their remaining
stage allowance. Use the existing timeout and receipt mechanisms. Record the
effective cutoff and reserves before remote mutation. If the time cannot
support the next stage and its remaining reserve, finalize the current result.

Stop dependent work after a definitive prerequisite failure. Preserve existing
reconciliation for runner or transport loss. Leave other job profiles outside
this focused change. Raise the focused budget when measured progress warrants
it and the owner chooses to do so.

| Observation | Required outcome |
| --- | --- |
| Definitive failure | Persist the earliest confirmed boundary and its evidence promptly. Stop waiting for it to succeed. |
| Failed prerequisite | Record dependent checks as blocked with that cause. Failed readiness blocks full validation and assessment. |
| Independent diagnostics and teardown | Preserve available evidence and reconcile exactly identified run-owned resources. Record secondary failures separately. |
| Deadline, cancellation or lost observation | Record the actual outcome. Keep remote state unknown when termination is unverified and reconcile it before retrying. |
| Collection or cleanup succeeds after deployment fails | Keep the deployment failure and its nonzero result. A successful relay, evidence job or teardown cannot change it. |

## Account for results inside the existing receipt

Inspect the existing plan and receipt first. Freeze expected lifecycle and
test rows before execution. Reuse shared run, source, candidate, contract,
profile and catalog identity in the enclosing record. Each row needs its
stage or case, status, reason, expected and observed behavior, and evidence
reference. Extend the owning record only where the required information is
missing. Preserve the first failure and explicit blocked, missing or error
rows, with evidence transfer and cleanup outcomes recorded separately.

Resolve product test coverage independently from installer diagnosis. Inspect
the current catalog and map the existing authoritative test definitions and
assertions to stable case IDs, applicable OS/profiles, implementation references,
expected outcomes and policy-required or optional status. Record unmapped
requirements as coverage gaps. An empty catalog cannot establish complete
release functional acceptance. A lifecycle summary such as functional checks
passed needs the individual required results behind it. Keep catalog mapping
and unavailable scanner dependencies on separate tracker items while continuing
the focused installation repair.

Use unique guest/profile/case identities in reports. The existing evaluator
must enforce required-result completeness and return failure when required
checks fail or are absent. JUnit display alone cannot make that decision.

Retain automatic acceptance and the common execution implementation. Record
whether an attempt is a focused diagnostic, an instrumented derivative,
unchanged-media acceptance or full release acceptance, and what it exercised.
A successful diagnostic proves its declared boundary. Full release eligibility
requires the actual product catalog, required assessments and existing release
policy. Reuse local ownership records for resource reconciliation and the
existing release chain for promotion authority.

## Live GitLab output is required

The existing work GitLab job is the authorized destination for relevant
runtime logs from the rhel kvm host. Stream actual controller messages,
installer progress, console observations, errors and exit codes during
execution. Retain timestamps, run identifiers and diagnostic paths when they
help correlate the attempt. Generic liveness lines can supplement this output.

Protect actual secrets at the source or relay boundary. Inspect console and
process output for credentials, tokens, private keys and unlock material.
Prevent echo where possible and redact secret-bearing fields or lines. Keep
the surrounding diagnostic context, including failures. Preserve incremental
durable evidence separately so a relay disconnect cannot erase it. Internal
operational output can retain nonsecret context that a portable report omits.

## Compare by responsibility

Use Wormhole's evidence below as a control for candidate identity, early
observation, trusted installed-system readiness, first-failure accounting and
exact-owned cleanup. Inspect Lightspeed's actual equivalent before proposing a
change. A source difference is a hypothesis until a real observation explains
the failing transition. Distinguish the original delivered ISO, an approved
source build and any instrumented derivative with its own identity. A fresh
acceptance run must follow the actual team's deployment inputs. Diagnostic
guest repairs do not qualify the original installation.

Wormhole's real ISO evidence is for RHEL 10 and Ubuntu 22.04. It does not establish
RHEL 9 install behavior, work routing, private build behavior or qualification.
Use the work controller and original contract to verify the receiving path.

If Terra needs more public source, ask the owner for one relevant excerpt with
its surrounding function and nearest test. Use the public Wormhole checkout
and exact revision below. For example, run this in that checkout and paste the
relevant excerpt.

```sh
git show 204720bc9047b4909c0b70cc15040bca4414ec5d:wormhole/vm_baseline.py
```

Use the source map to request the next excerpt only as needed. The owner can
supply it even when chat cannot fetch public links.

| Need | Public source and nearby tests |
| --- | --- |
| Collector, readiness, terminal result and cleanup | wormhole/vm_baseline.py, wormhole/vm_admission.py, wormhole/ubuntu_recovery.py and tests/test_vm_foundation.py |
| RHEL installer and console unlock | wormhole/rhel_inputs.py, wormhole/rhel_hardening.py, wormhole/ubuntu_encryption.py, tests/test_rhel_hardening.py and tests/test_ubuntu_encryption.py |
| Completed ISO intake and identity | wormhole/intake.py, wormhole/ubuntu_intake.py and tests/test_intake.py |
| Installed inventory and assessment | wormhole/rhel_assessment.py, wormhole/ubuntu_runtime.py, tests/test_vm_foundation.py and tests/test_ubuntu_helper.py |
| More context | docs/STATE.md, docs/ARCHITECTURE.md, docs/FIDELITY.md and handoff/CURRENT.md |

For quick public examples, run these from the Wormhole checkout at the pinned
revision. The first exercises the real console frame parser. The second calls
the real candidate reuse check with changed boot inputs. Both are no-VM tests.

```sh
python3 -B -m unittest discover -s tests -p test_vm_foundation.py -k console_key_frame
python3 -B -m unittest discover -s tests -p test_vm_foundation.py -k valid_old_hash
```

## External update, only when requested

Prepare the portable update read-only from one attributable attempt. It does
not replace live internal logging or the next executable chat step. Include
current disposition and stage counts from the actual plan, the earliest
confirmed boundary, evidence type, confidence, smallest repair, verification,
elapsed stages, cleanup and next action. Keep deployment, assessment coverage,
qualification and publication separate. When comparing the two systems, name
the corresponding mechanism, observed difference and why it matters. Label
hypotheses and unknowns, and distinguish source tests from real installations.

Use general roles such as **ansible control node** and **rhel kvm host**.
Compose it from safe facts. Retain public OS/tool names, nonidentifying counts,
rounded elapsed times, observed outcomes and approved public Wormhole source
references. Exclude private names, addresses, paths, URLs, accounts, exact
timestamps, private identifiers or hashes, commands, source and raw logs.
Review the resulting text for restricted content and keep the original evidence
and private mapping inside work.

## Verified Wormhole reference

This evidence snapshot carries forward the verified [two-OS delivery](https://github.com/TheSlayer455/jake-wormhole/pull/48).
The public source pin for follow-up pastes is [204720bc9047b4909c0b70cc15040bca4414ec5d](https://github.com/TheSlayer455/jake-wormhole/commit/204720bc9047b4909c0b70cc15040bca4414ec5d).
Each installation retains its own runtime revision. Engineering proof,
lab qualification and work integration are separate outcomes.

## Evidence index

Runtime receipts and sanitized public checkpoints have different roles. Public
checkpoints record observed results; native proof remains private. Source tests
can be rerun publicly but cannot reproduce licensed media or private execution.
Dates marked "checkpoint" are recorded public source/evidence dates, not an
assertion of the precise execution time.

| Label / evidence date | Actual tested source and public record | Observed scope |
| --- | --- | --- |
| U / 2026-11-01, runtime receipt date | [Ubuntu controller at a705e2b](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_runtime.py); [recorded final pair](https://github.com/TheSlayer455/jake-wormhole/blob/65b8e8ffde4a1a43c34cbc5ab8578e50cbabc980/handoff/solutions/ubuntu-install-hardening.md) | Two fresh encrypted installations of identical ISO bytes; 40/40 functional checks and five objective manual observations each; SVD, actual assessment, terminal records and cleanup. |
| R / 2026-10-31, runtime receipt date | [RHEL SVD/assessment at 77e6e16](https://github.com/TheSlayer455/jake-wormhole/blob/77e6e1611d478fcc1a713d40e66907a80c3207c5/wormhole/rhel_assessment.py); [recorded execution](https://github.com/TheSlayer455/jake-wormhole/blob/65b8e8ffde4a1a43c34cbc5ab8578e50cbabc980/docs/STATE.md) | Fresh installation, six controller checks, trusted SSH/Ansible, 413 RPM rows, actual assessment and cleanup. Unhardened baseline. |
| H / 2026-11-09, local runtime date | [Hardened RHEL inputs](https://github.com/TheSlayer455/jake-wormhole/blob/d6dfaf396e458bba7745e3541980c1879b5b434c/wormhole/rhel_hardening.py), [controller](https://github.com/TheSlayer455/jake-wormhole/blob/d6dfaf396e458bba7745e3541980c1879b5b434c/wormhole/vm_baseline.py) and [native collector](https://github.com/TheSlayer455/jake-wormhole/blob/d6dfaf396e458bba7745e3541980c1879b5b434c/wormhole/rhel_assessment.py) at d6dfaf3, repeated at [4980aa0](https://github.com/TheSlayer455/jake-wormhole/commit/4980aa0718e6860c45728aa00cbf9f825397419e) | Two independent fresh encrypted installations of identical ISO bytes, 10/10 each, matching 449 RPM rows and native outcomes. Both verified cold boot, trusted SSH/Ansible, audit receiver delivery and cleanup. |
| L / 2026-10-29 checkpoint | [Controller at 63a130a](https://github.com/TheSlayer455/jake-wormhole/blob/63a130a249111fc10c229a66922a51895b87e40e/wormhole/vm_baseline.py); [comparison and fault evidence](https://github.com/TheSlayer455/jake-wormhole/blob/56ca6fdb9f174c7649c27e2b778c67ca94849962/handoff/solutions/lifecycle-comparison.md) | Same-candidate lifecycle comparison; actual readiness failure and interrupted-supervisor recovery. Terraform retained. |
| I / 2026-10-29 checkpoint | [Intake at 0a6acb5](https://github.com/TheSlayer455/jake-wormhole/blob/0a6acb5754a943562a9e425288704cae928afa60/wormhole/intake.py); [delivery experiment](https://github.com/TheSlayer455/jake-wormhole/blob/56ca6fdb9f174c7649c27e2b778c67ca94849962/handoff/solutions/directory-intake.md) | Completed RHEL delivery installed without building/remastering; periodic incomplete-delivery, duplicate/restart and failed-readiness cases exercised. |
| D / 2026-11-07, runtime receipt date | [Ubuntu intake at 9a19b53](https://github.com/TheSlayer455/jake-wormhole/blob/9a19b537b0897fad5e649f7b9292f3e2102cacfa/wormhole/ubuntu_intake.py) and [focused tests](https://github.com/TheSlayer455/jake-wormhole/blob/9a19b537b0897fad5e649f7b9292f3e2102cacfa/tests/test_intake.py) | One fresh encrypted Ubuntu installation used unchanged delivered bytes and a fresh private seed. It passed 40/40, cold start, trusted SSH/Ansible, native assessment and cleanup. Terminal request replay returned the same result. |
| A / 2026-10-31 checkpoint | [Archive client at b881127](https://github.com/TheSlayer455/jake-wormhole/blob/b881127296ea9b2bc23dbde523b1c0a8b9021842/wormhole/archive_client.py); [failure-test revision](https://github.com/TheSlayer455/jake-wormhole/commit/61f91d9d29c4ceec5ec75e782bf0e6ecb4185668); [recorded storage proof](https://github.com/TheSlayer455/jake-wormhole/blob/56ca6fdb9f174c7649c27e2b778c67ca94849962/docs/STATE.md) | Real workstation archive, destination readback, eligible local deletion and exact-byte restore of a probe and historical ISO; actual unavailable/interrupted/corrupt transfer refusal. |
| E / 2026-11-10, runtime test date | [Runtime at 21fb946](https://github.com/TheSlayer455/jake-wormhole/commit/21fb946831a451a93c970346855e2c2aec781fb0) | One new fresh encrypted installation per OS using verified reused media. RHEL passed 10 hardened and six controller checks with 449 RPMs; Ubuntu passed 40 with 638 packages, three Snaps and two payloads. Native totals matched H and U/D. Automatic file cleanup reclaimed 7.905/2.130 GiB respectively, separately from disk destruction. Archived evidence reconciled, no owned resources, no qualified ISO. |
| T / 2026-11-10, runtime test date | [Client cleanup](https://github.com/TheSlayer455/jake-wormhole/blob/461b113cfe91b261eb65a69e3779680203f1ad8e/wormhole/archive_client.py) and [restore staging](https://github.com/TheSlayer455/jake-wormhole/blob/461b113cfe91b261eb65a69e3779680203f1ad8e/wormhole/storage_archive.py) | Existing workstation and host cleanup reclaimed 32 MiB temporary files on each system. An existing 6 MiB archived probe restored exactly and was reclaimed after verified readback; no new encrypted object or VM. Repeat host cleanup reclaimed zero and unrelated containers were preserved. |
| S / 2026-10-31 checkpoint | [Retained SVD archival at f2a3d5c](https://github.com/TheSlayer455/jake-wormhole/blob/f2a3d5ca383a1fea9230a9d1225406ae1f9bde26/wormhole/storage_archive.py); [PR 45](https://github.com/TheSlayer455/jake-wormhole/pull/45) | 298 verified encrypted objects at that checkpoint; six additional SVD/build-manifest readbacks; local originals retained. This is not a live backlog count. |

## Verified mechanisms and boundaries

| Lifecycle | Implementation and actual proof | Transfer limitation |
| --- | --- | --- |
| Media and candidates | Streaming chunk reconstruction verifies source integrity. Installed-input fingerprints govern candidate reuse; unchanged bytes can serve new attempts without rebuilding. U verifies identical candidate/contract across two independent installations. | Hash identity alone does not prove freshness, qualification or team intent. Controller/report-only changes differ from installed-input changes. |
| RHEL installer | R preserves the DVD BIOS boot machinery and uses a separate Kickstart seed. H applies pinned hardening during installation and validates the resulting system after reboot. The powered-off check verified LUKS acceptance of the correct key and refusal of wrong and missing keys. | BIOS lab profiles. The receiving team owns its installation contract. H still has open assessment findings and cryptographic validation requirements. |
| Ubuntu installer | [Ubuntu inputs](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_inputs.py) bind versioned offline payloads and hardening with a declared private NoCloud seed. U installs Ubuntu 22.04.5 x86_64, completes first-boot finalization/hardening and required reboot. | Neither path is a universally self-contained ISO. Separate secrets/endpoints are declared dependencies; acceptance does not repair the guest into compliance. |
| VM provisioning | [Shared VM lifecycle](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/vm_baseline.py) uses Terraform/libvirt/KVM, empty disks, serial evidence and exact resource journals. One live acceptance guest; 8 GiB RAM/two vCPUs, RHEL 32 GiB disk or Ubuntu 64 GiB disk. | Ubuntu virtualization host, BIOS only. No UEFI/Secure Boot, enterprise scale, remote work-runner routing or arbitrary host compatibility claim. |
| Readiness and trust | Controlled serial evidence supplies the installed guest's unique host key. Strict SSH verifies host identity and the intended final account, completed installation marker, OS and mounted root. Real Ansible verifies interpreter/privilege access from the designated helper. U also proves encrypted reboot/cold-start and wrong/missing unlock refusal. | Port-open or installer SSH cannot satisfy readiness. RHEL baseline privilege policy differs from Ubuntu's required password-based escalation; preserve each contract. |
| Functional validation | U: 40/40 checks each, including real lab logging/audit/time, scoped trust/PAM, encryption and access probes. R: six controller checks, including Ansible and basic privileged smoke. L: authenticated but inaccessible completion marker immediately blocks four dependent checks. | R's six checks are not a full hardening catalog. Lab time/PKI/software-token tests do not establish external trusted time, government identity or physical-token assurance. |
| SVD | Structured native Ansible inventory feeds readable and JSON SVDs. R: 413 RPM rows with native version/release/epoch/architecture; key headers separate. U: 638 packages, three Snaps and two payload entries. Build inventory remains distinct from installed inventory. Original row/readable-output readback passed. | Counts do not establish equivalent proprietary packages or business behavior. No package list is exported here. |
| Assessment | Both OSes retain actual OpenSCAP machine-readable and readable reports, scanner/content identity and every native outcome. Ubuntu supplements manual observations without rewriting scanner statuses. | Findings must satisfy the declared policy. Evaluate-STIG, Nessus and Ubuntu USG/FIPS execution remain unproven. |
| Execution and recovery | L acknowledges actual admission/start, records observed phase/progress separately from liveness, and persists failure/unknown outcomes. Controlled interruption retained unknown state until stopped-process/ownership reconciliation. U's final pair finished automatically; compact terminal storage summaries reference full durable receipts. | Missing acknowledgment or observer loss requires reconciliation, not automatic duplicate launch. A recovered unknown attempt remains unknown, never successful. |
| Cleanup | Terraform destroys exactly recorded resources after evidence collection; storage uses the shared admission/ownership lock. U/R/L verified temporary resource absence. Original operation errors survive cleanup errors. | No global prune, ambiguous-prefix deletion or deletion of unresolved evidence. Historical absence is not evidence of current host availability. |
| Completed-ISO intake | I and D verify an explicit completion manifest, protected bytes, actual size/hash and a declared contract. They use the same dispatcher and fresh seed. D also binds the build manifest and verifies the embedded Ubuntu payload. | Evidence covers RHEL 10 BIOS baseline and Ubuntu 22.04 hardened sandbox. Periodic monitoring was exercised on RHEL and removed afterward. Other producer contracts need their own evidence. |
| Intake identity and retries | I proves no second active VM on duplicate notification/restart. Real-file source fixtures prove same filename/new bytes, changed assessment identity and explicit retry create distinct requests. | Those identity fixtures are not additional VM experiments. Deduplication must not permanently prevent legitimate requalification. |
| Storage/archive | A/S/T extend existing storage receipts: workstation-initiated strict SSH, age encryption, actual decrypted destination hash/size verification, durable commit before eligible local reclamation, explicit verified restore. Active disks/state/credentials/journals stay local. Offline/pending data is retained; admission can refuse new work. | Real archive/restore and failure tests, not a proposal or localhost-only copy. A limited periodic task was installed and exercised at the checkpoint; current availability is not asserted. Retention is not a proven independent backup or key-loss recovery policy. |
| Gates/publication | [Ubuntu gate/publisher](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_release.py) requires complete bound results, matching independent installations and declared policy. U's normal publication attempt was refused for pending dependencies with no release created. | Positive ISO-publication integrity fixtures are source tests only. No lab-qualified ISO publication is proven. Historical container-reference publication is a separate capability. Production eligibility remains false. |

## Native outcomes and unresolved qualification

| Native result | RHEL baseline R | Hardened RHEL H | Ubuntu U and D, each |
| --- | ---: | ---: | ---: |
| Pass | 172 | 425 | 210 |
| Fail | 261 | 9 | 1 |
| Not applicable | 56 | 29 | 14 |
| Not checked | 9 | 10 | 5 |
| Not selected | 450 | 600 | 409 |
| Total | 948 | 1,073 | 639 |

R uses the DVD's pinned SCAP Security Guide 0.1.76 vendor-draft content; it does
not prove alignment with a current released DISA benchmark. U uses OpenSCAP 1.4.6
and ComplianceAsCode 0.1.82 identifying V2R7, with declared lab values and a
documented mapper correction. The unchanged upstream Ubuntu audit remains
207 pass/four fail; do not confuse it with the declared lab result above.

All 188 controls of the frozen V2R8 manual target were mapped, including seven
changed check/fix records supported by actual probes/native results. The 409
upstream-unselected rules carry no Ubuntu STIG identifiers; they are not passes
or hidden failures. Five native manual statuses remain unchanged despite five
objective supplemental observations. The newer V2R10 manual is a separate,
unqualified target. This mapping is not USG execution or scanner equivalence.

Ubuntu's remaining native failure is FIPS. Legitimate Pro entitlement and actual
USG/FIPS enrollment, package/module/runtime verification, reboot and assessment
remain required. The private provider interface does not supply entitlement.
Delegated lab trust review is complete; physical-token hardware is not required
by the prospective lab policy, while physical/government assurance remains
unverified. Historical policy/results have not been rewritten.

Evaluate-STIG has not run on either OS: an authorized official package, included
support documentation and permitted invocation remain unavailable. Nessus has no
verified runtime execution here. No alternative scan can satisfy those claims.
H uses ComplianceAsCode 0.1.82 and its pinned RHEL V1R2 profile. The native
findings, unresolved manual evidence and verification of cryptographic modules
and their operating environment keep qualification pending. The different
content in R and H prevents a direct finding-count comparison.

## Measurements and engineering lessons

- U: about 666/669 seconds for each complete CLI, including about 26/28 seconds
  of final storage/reporting; VM-through-teardown about 639/642 seconds. First
  installation-to-host-key stage: 465 seconds; offline encryption/cold-start: 63;
  SSH/Ansible/inventory/assessment: 56. Nested stages must not be added twice.
- R: 308 seconds for the fresh SVD run. I: completed delivered-ISO run 248 seconds;
  controlled failed-readiness intake 236 seconds. Different contracts/sample
  populations prevent treating these as a cross-OS performance ranking.
- H: about 536 and 496 seconds through guest teardown. Installation to host key
  took about 345 and 327 seconds, offline inspection and cold start about 35 each,
  and controller validation through assessment about 40 each. Archive transfer
  is a separate operation.
- L: one Terraform control took 272 seconds versus 278 for native libvirt; lifecycle
  commands about 5.6 versus 2.4 seconds. The alternative added another ownership/
  recovery path without an established overall advantage and was removed. The
  0.672-second readiness-failure detection starts after authentication, not VM launch.
- A: a roughly 2.14 GB historical ISO archived/reclaimed in 77 seconds and restored
  in 64 seconds. Subsequent scheduled reconciliation measured 5.978 GiB net local
  allocated-block reduction. This is a historical measurement, not live capacity.
  Budgets remain 100 GiB managed/40 GiB candidate cache, with 80% warning and 90%
  projected filesystem admission ceiling.

The final U pair follows two preserved failures: an oversized embedded terminal
storage receipt and an asynchronous guest mail-service stop/start race. Small
corrections reused durable receipt references and the packaged service-manager
restart. Source tests alone did not close either runtime claim.

H follows preserved failures in scanner exit handling, boot unlock observation,
audit startup and host-key framing. The installation treats a scanner findings
exit separately from an execution error. It preserves the vendor's early audit
ordering and labels the isolated receiver port inside the guest. The controller
accepts one unambiguous key in the bounded frame despite concurrent boot messages.
Actual boot and transport observations establish those corrections.

Historical source CI at `56ca6fd` passed 974 tests with 12 explicit skips and
controlled parity. Source CI at `4980aa0` passed 997 with 12 explicit skips
and controlled parity. Work-environment integration and proprietary-image acceptance
require separate work-side evidence. Production eligibility is false.
[Historical source CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/41257949098)
[PR 48 source CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/42726826330)

## Start here in Terra

Return one read-only command group for work WSL to inspect the checkout and
latest attempt. Use the returned evidence to choose the first no-VM check.
