# Terra's complete Lightspeed execution brief and Wormhole reference

Copy this entire file into Terra in the authorized work chat. This is the one
portable Wormhole paste for the current Lightspeed investigation. It includes
the owner's operating directive, the fast causal-debugging procedure, the
current recovery task, the verified Wormhole control case, implementation and
test contracts, exact qualification limits, and the response Terra must return.
Terra should begin from this file without asking the owner to paste routine
Wormhole documentation or source files.

The public links are verification aids. They are not prerequisites for using
the brief. If a later work-side question depends on a source detail that is not
represented here, Terra must name the single missing function, contract or
bounded private observation. It must not request a bulk repository export.

## Bundle provenance and contents

This bundle reconciles the latest fresh two-OS evidence recorded on public main.
The implementation used for those actual runs is
[21fb946831a451a93c970346855e2c2aec781fb0](https://github.com/TheSlayer455/jake-wormhole/commit/21fb946831a451a93c970346855e2c2aec781fb0).
The later focused RHEL chrony/recovery runtime used
[e3208237884acc53fb4821cdbc6dcb5e867e49e1](https://github.com/TheSlayer455/jake-wormhole/commit/e3208237884acc53fb4821cdbc6dcb5e867e49e1);
delivery and merge revisions are pending. It does not relabel the earlier Ubuntu
or two-OS receipts.
The public report was tested at
[31093e4c556081f4654af9e8d28b65255b33fe98](https://github.com/TheSlayer455/jake-wormhole/commit/31093e4c556081f4654af9e8d28b65255b33fe98)
and merged as
[59fb4392e187efa08509abc6492bfe800564680e](https://github.com/TheSlayer455/jake-wormhole/commit/59fb4392e187efa08509abc6492bfe800564680e).
[Post-merge source CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/42956234469)
passed 1,002 tests with 12 explicit platform skips. Documentation changes after
a runtime do not become that runtime's tested implementation.

| Included here | Purpose |
| --- | --- |
| Owner directive | Removes agent-created approval and review gates while preserving actual enforced controls |
| Fast verification loop | Tests one code, configuration or generated-input explanation before a full run |
| Current Lightspeed case | Narrows the console-marker investigation and defines its real-run done-check |
| Runtime behavior | Sets the 20-minute focused budget, live logging and first-failure rules |
| Receipt contract | Prevents missing, blocked or secondary failures from disappearing |
| Wormhole control case | Supplies source-pinned mechanisms, actual runtime outcomes and limits |
| Implementation capsule | Describes the owning APIs, invariants, outputs and closest source regressions |
| Qualification and storage state | Separates engineering success from release eligibility and records current cleanup proof |
| Terra response contract | Produces one causal, sanitized work-side diagnosis and the next executable step |

Terra must treat this as a technical reference, not authority to copy private
work source into Wormhole or to replace the team's intended ISO behavior.

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

## Development simplicity and authority

Do not add another controller, scheduler, state database, approval workflow,
attestation service, generalized authentication subsystem, or defensive wrapper
for this repair. Reuse Lightspeed's existing receipt, controller, Terraform
ownership, remote relay, test catalog and release chain. A new layer is justified
only after a demonstrated requirement cannot be met by the existing component.

Direct work on main is the owner's chosen development workflow. Routine edits,
focused tests, commits, pushes, disposable guests and exact-owned cleanup do not
need a new conversational approval or pull request. A repository or server may
still enforce a control. If it does, report the exact enforcement point and the
blocked action instead of presenting an agent preference as policy.

The next change must answer one causal question. Start from the first confirmed
bad transition, change the component that owns that transition, and keep all
unrelated inputs fixed. Extend the closest test. A normal repair usually needs a
few distinct checks rather than a broad matrix. Run a full pipeline only after
the cheap component proof passes and the next unresolved boundary requires it.

Keep the following separations explicit throughout development.

| Separate facts | Why they cannot be collapsed |
| --- | --- |
| Source is corrected / deployed input is corrected | The executing remote script, generated seed or embedded media may differ from the checkout |
| Port is open / final identity is ready | An installer or restarting guest can expose a temporary service |
| SSH authenticates / finalization is complete | A usable account can exist before the product state or hardening contract is complete |
| Process is alive / operation is progressing | Liveness alone cannot reset a deadline or prove useful work |
| Cleanup passes / deployment passes | Teardown is secondary evidence and cannot overwrite the original failure |
| Scanner ran / findings are acceptable | Execution, coverage, policy acceptance and qualification are different decisions |
| Artifact hash matches / artifact is current | Byte identity does not prove the intended inputs or policy revision |
| Source tests pass / real installation passes | Fixtures cannot prove firmware boot, installer behavior, guest access or exact cleanup |

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

## Supplied Lightspeed comparison findings

The owner supplied a prior source comparison. Treat it as a work-side analysis,
not as a fresh diagnosis of the latest attempt. It established these durable
directions.

- Historical failures accumulated at interfaces between media, installer,
  Terraform inputs, guest identity, readiness, remote supervision, deadlines,
  evidence and cleanup. The next defect still needs current attributable proof.
- Terraform provisioning has worked. Wormhole's same-candidate native-libvirt
  experiment did not justify another maintained backend. Keep Terraform and
  repair the observed boundary around it.
- Identity and bootstrap contracts have previously diverged. The final account,
  host trust, privilege behavior and Ansible inputs must derive from the same
  declared installation contract.
- Installer identity can exist in several boot surfaces. Correct source text is
  insufficient until the attached media or declared seed actually contains and
  consumes the rendered change.
- A source-level Terraform field mismatch can prevent allocation even when broad
  syntax checks pass. Exercise the exact focused module path with the effective
  input object.
- Remote execution and the enclosing job previously had incompatible deadlines.
  The current repair uses the effective remaining cutoff and one total budget.
- Evidence transport is an independent boundary. Relay, archive, retrieval and
  cleanup errors must remain secondary to an earlier deployment failure.
- The supplied formal product catalog was empty. Map the team's existing approved
  test definitions into stable cases. Do not invent replacement tests, and do
  not let catalog work delay observation of the installer failure.
- The approved assessment runtime and its inputs remain a separate downstream
  dependency. Source-side integration code does not prove that assessment ran.

The transferable Wormhole behavior is causal state and complete accounting.
Its home topology, exact checks and local release authority are not replacements
for the receiving system's distributed controls or product requirements.

## Tool adoption decisions for Lightspeed

These are bounded investigation decisions, not verified Wormhole runtime
evidence and not new Lightspeed prerequisites. Keep Terraform/libvirt, the
existing controller, approved build behavior, GitLab and Ansible. Adopt another
tool only when one measured experiment shows that it removes a demonstrated
failure source or more maintained custom code than it introduces.

| Technology | Decision | Bounded purpose | Adoption boundary |
| --- | --- | --- | --- |
| Native libvirt serial/VNC | Use now | Extend the existing early installer observation so one collector preserves Anaconda and boot evidence before SSH | Keep one reader and the current controller. Prove that capture starts early, is durable and feeds the existing receipt. |
| Cockpit Machines | Inspect conditionally | Give an authorized operator a graphical or serial view of the same libvirt guest when visual state answers a question the retained console cannot | Use only if the web console, VM plug-in, access and network exposure are already approved. Do not enable a new management listener, change host policy or make Cockpit another execution authority. |
| Goss | Bounded pilot after one stable installation | Express a handful of existing approved package, service, account, port, mount, file and command checks with structured JSON/JUnit output | Preserve stable product case IDs and the controller's exit decision. Keep Goss only if it replaces bespoke checks and reduces maintained code. It does not replace the product catalog, Ansible readiness, Evaluate-STIG or Nessus. |
| Lorax `mkksiso` | Bounded source-build experiment | Test whether a pinned release can replace fragile custom Kickstart injection and boot-media edits | It creates modified media with a new digest. Use it only for an approved source build or clearly labeled diagnostic derivative. Match host/media architecture, verify privilege requirements and exercise the actual BIOS/EFI paths before claiming an advantage. Never alter a completed customer ISO and attribute the result to the original. |
| KVM Pilot | Optional read-only research | Inspect physical-server console, firmware, boot and BMC state when a real host boundary is otherwise opaque | Upstream is write-capable across KVM, BMC and SSH. A trial must use its explicit read-only mode and withhold power, keyboard, virtual-media and mutating SSH access. It does not replace libvirt guest-console capture or authorize agent control of the physical host. |
| S3-compatible artifact storage | Evaluate later | Retain immutable candidate references, completed evidence and readback after the installation lifecycle is reliable | S3 is not inherently immutable. Require digest identity, versioning or approved retention controls, partial-object isolation, completion-last publication, exact readback and scoped credentials. Keep active state, seeds and live guest disks out of artifact storage. |
| Packer QEMU | Defer | Reconsider only for a separately required preinstalled VM-disk deliverable | Its normal QEMU result is a qcow2 or raw disk image. That path would not replace Forge or prove that the customer installer ISO boots and installs correctly. |
| openQA | Defer | Reconsider only if graphical installer interaction or screen regression becomes a measured requirement that serial/VNC evidence cannot meet | It introduces a web UI, workers and maintained test/needle assets. Do not add that platform for the current unattended installer repair. |

The fastest current sequence is:

1. Improve the existing serial/VNC evidence and complete the console-marker
   component proof.
2. Inspect Cockpit only when it is already available and authorized; otherwise
   continue with native console evidence.
3. Complete one focused existing-candidate installation through installed boot,
   trusted SSH, Ansible, attributable evidence and exact cleanup.
4. Populate the authoritative product catalog from tests the team already owns.
5. Pilot Goss against a small set of those existing cases only if it can delete
   bespoke implementation.
6. Evaluate `mkksiso` against one approved source-build operation, keeping the
   current customer candidate and installation inputs unchanged.
7. Evaluate S3 after the lifecycle and release bundle are reliable.
8. Use KVM Pilot only for a proven physical-host/BMC visibility gap. Keep Packer
   and openQA deferred until their separate deliverables exist.

Every optional-tool experiment must name the defect or custom code it would
remove, verify the supported interface and least required privileges, freeze the
existing candidate and contracts, and compare one old/new case. It must preserve
first-failure accounting, live evidence, cancellation, ownership and cleanup.
Delete superseded code only after the replacement is proven. Reject a tool that
adds another execution authority, duplicates an existing path or fails to reduce
maintained complexity. **No optional tool is a prerequisite for the current
focused installation.**

## Embedded Wormhole implementation capsule

This capsule is the source context Terra needs for the first comparison. It is a
behavioral projection of public code, not a second implementation. Function and
class names are included so the receiving code can be compared by responsibility
even when names differ.

### Run, ownership and observable execution

| Public component | Inputs and output | Invariant and failure behavior | Closest regression |
| --- | --- | --- | --- |
| `runs.Run` and atomic record helpers | A bounded workspace, immutable source identity and one run identifier produce private atomic records | Linked, misplaced, oversized, duplicate-key or source-mismatched state is refused. A document is never authority for an unobserved runtime mutation. | `test_runs.py` |
| `vm_admission.VMLease` | Canonical shared root, run identifier and 40-character source revision produce an active VM ownership journal | Intent is persisted before mutation. Every domain, network, pool, disk, installer, seed, controller and filter has one exact identity. Finish is refused while any recorded resource remains pending. | `test_vm_foundation.py` |
| `vm_baseline.status` | Existing run identifier returns durable phase, latest progress, checks, first failure, outcome, cleanup and observed supervisor state | Process liveness and progress age are reported separately. A stopped supervisor with no terminal record is unknown, not success. | `test_vm_foundation.py` |
| `vm_baseline.execute` | Verified media, pinned Terraform, declared OS profile and optional reuse origin run the existing one-guest lifecycle | Launch acknowledgment precedes long work. Installed readiness, validation, evidence and teardown update the same bounded result. First failure and cleanup failure occupy separate fields. | `test_vm_foundation.py`, `test_rhel_hardening.py`, `test_ubuntu_helper.py` |
| `execution_state.project` | Frozen plan plus observed initialization, readiness, lifecycle and validation records produce a progress projection | Current phase, last progress, readiness and terminal outcome are projections of evidence. They do not execute or repair a target. | `test_execution_state.py` |

### Candidate, installation and readiness contracts

| Public component | Contract Terra should compare | Failure meaning |
| --- | --- | --- |
| `candidate.input_identity`, `compare_inputs`, `validate_binding` | Base source, installed customization, configuration, packages or payloads, build tool and artifact bytes have distinct identities. Controller/test changes do not masquerade as installed-input changes. | A stale or mismatched candidate is refused before provisioning. A matching hash alone cannot prove current intended inputs. |
| `rhel_inputs` and `rhel_hardening` | Preserve the real DVD boot path and volume identity, use a declared separate installation seed, generate installation-time hardening, create the final identity and completion evidence, then reboot from the installed disk. | Generated output is not proof of installer consumption. Failure before account setup remains an installer/finalization failure rather than an SSH defect. |
| `ubuntu_inputs`, `ubuntu_encryption`, `ubuntu_sandbox` | Bind the pinned offline payload and hardening template while keeping per-installation identity and unlock material outside published media. | A missing runtime dependency or unlock input is explicit. Acceptance cannot repair the guest into a pass. |
| `vm_baseline.console_host_key` | Accept one complete final-host-key line inside a bounded installed-guest frame, tolerating unrelated concurrent boot output. | Missing or ambiguous framed identity blocks strict SSH. Unauthenticated key scanning is not a trust source. |
| Helper readiness chain | Verify final account, installed-system completion, OS identity, mounted root, readiness-critical security state, interpreter and privilege contract before Ansible readiness. Later functional and assessment checks retain their own gates. | Port-open, installer SSH or authentication alone cannot start the full catalog. The first definitive readiness reason blocks dependent rows. |

The readiness algorithm is equivalent to this sanitized pseudocode.

```text
while absolute deadline has useful work time:
    observe strict SSH with the framed final host identity
    if transport is temporarily unavailable:
        wait within the remaining allowance
        continue
    record final authentication
    check final identity, completed installation, installed OS and root disk
    check the OS-specific readiness and privilege contract
    if a definitive check fails:
        record that first failure
        block Ansible and the full catalog
        stop readiness waiting
    run a real Ansible ping with the declared interpreter and privilege inputs
    if it succeeds:
        admit the frozen validation plan
        break
```

### Complete results and cascading-failure containment

| Public component | Contract Terra should preserve |
| --- | --- |
| `lifecycle.Lifecycle` | The container/reference path records observed provisioning, creation, initialization, configuration, hardening, reachability, host identity, final identity, interpreter, privilege and Ansible transitions. A failure keeps the earliest cause and blocks dependent checks. The VM controller has corresponding phase/check records rather than reusing this storage format. |
| `pipeline_records.grid` and `validate_record` | The container/reference path freezes every required component/case tuple before execution. Every tuple has a status, expected result, observed result, reason and evidence references. Missing output remains visible. Transfer the accounting semantics into the receiving receipt, not the file format. |
| `pipeline_records.decision` | Eligibility is derived only after structural completeness. Required nonpass rows, unknown outcomes, incomplete cleanup or absent evidence refuse the limited reference gate. Production eligibility remains false. |
| JSON, text and JUnit renderers | Derive all views from the same canonical record. JUnit presentation does not determine the command's return value. Unique component/target/case identities prevent hidden duplicates. |

Use this failure propagation model inside Lightspeed's existing receipt.

```text
freeze expected rows
execute the next admitted stage
on its first definitive failure:
    retain that stage, reason and evidence as the primary failure
    mark every dependent expected row blocked with that dependency
continue only independent evidence preservation and exact-owned teardown
record relay, collection and teardown problems as secondary failures
return the original failed outcome even when cleanup succeeds
```

A fixed release catalog and a lifecycle grid solve different problems. The grid
shows whether the execution boundaries completed. The product catalog shows
which required product behaviors were actually tested. Both must be complete for
release acceptance, and neither should become a new orchestration framework.

### Intake, recovery, cleanup and storage

| Public component | Contract Terra should compare | Refusal behavior |
| --- | --- | --- |
| `intake.completed_delivery` | A bounded completion manifest appears last and names exact ISO bytes plus the declared installation contract. Ubuntu also binds its build manifest. | A filename alone, in-progress copy, changed bytes or unsupported contract is refused. |
| `intake.register` | Independently copy and verify delivered bytes. Request identity covers ISO, contract, implementation, assessment content, policy, generation and scenario. | Duplicate notifications observe the existing request. Same filename with different bytes and explicit requalification form new identities. |
| `intake.submit` and `scan` | Persist dispatch intent before calling the same foreground acceptance engine. Manual and periodic paths share registration and submission. | A terminal request returns its existing result. An unknown launch remains unknown. Prelaunch refusal can retry the same identity after its cause clears. |
| `recovery.inspect_recovery` and `recover_run` | Use the original run, source, journal and lock after proving the old controller's state. Recovery allocates nothing new. | Missing evidence, source mismatch or unknown ownership blocks mutation. A recovered unknown run remains an unknown historical outcome. |
| `storage.Store.observe`, preview, clean and lifecycle | Reconcile run manifests, active references, current candidates, evidence and exact filesystem allocation under the shared lock. | Active or unresolved references, uncertain evidence and required local inputs remain protected. Cleanup uses the same engine as preview. |
| `storage_archive.preview`, queue, commit and restore | Archive only completed eligible content by cryptographic identity. Commit follows destination readback. Restore verifies exact bytes and local protections. | Offline or corrupt destination preserves the only local copy. No committed receipt means no local reclamation. |
| `archive_client.Client` | Pull through the established private route, encrypt locally, verify decrypted stored bytes, commit receipt, and remove only abandoned exact staging files. | An interrupted transfer stays incomplete. Original transfer errors survive cleanup errors. Unrelated files and handles visible to the Linux/WSL client are protected. |
| `publication.publish_reference` | Snapshot a closed eligible file table, copy the exact tested bytes into a unique private release, verify it, and write completion last. | Failed, incomplete, changed, duplicate, wrong-scope or falsely production-eligible input is refused without overwriting a release. |

### Assessment and SVD

`rhel_assessment.collect` validates the expected target, scanner execution,
content identity and complete native coverage before writing the installed RPM
SVD. `ubuntu_runtime.collect` retains the original XCCDF, ARF and readable report,
then emits the bound observed inventory and qualification inputs. Native scanner
statuses are never rewritten by supplemental manual evidence. Build inventory,
installed inventory, scanner execution, coverage, policy acceptance and release
qualification remain separate facts.

The source map below is optional verification context. This bundle supplies the
behavioral contract without another paste.

| Responsibility | Public implementation | Focused source tests |
| --- | --- | --- |
| Run identity and bounded records | `wormhole/runs.py` | `tests/test_runs.py` |
| Shared admission and exact VM ownership | `wormhole/admission.py`, `wormhole/vm_admission.py` | `tests/test_admission.py`, `tests/test_vm_foundation.py` |
| One-guest execution, host-key framing and readiness | `wormhole/vm_baseline.py` | `tests/test_vm_foundation.py` |
| Lifecycle projection and complete result grid | `wormhole/lifecycle.py`, `wormhole/execution_state.py`, `wormhole/pipeline_records.py` | `tests/test_lifecycle.py`, `tests/test_execution_state.py`, `tests/test_pipeline_records.py` |
| RHEL installation and hardening | `wormhole/rhel_inputs.py`, `wormhole/rhel_hardening.py`, `wormhole/rhel_assessment.py` | `tests/test_rhel_hardening.py`, `tests/test_vm_foundation.py` |
| Ubuntu installation and qualification | `wormhole/ubuntu_inputs.py`, `wormhole/ubuntu_runtime.py`, `wormhole/ubuntu_release.py` | `tests/test_ubuntu_helper.py`, `tests/test_ubuntu_reports.py`, `tests/test_ubuntu_release_readback.py` |
| Completed-media intake | `wormhole/intake.py`, `wormhole/ubuntu_intake.py` | `tests/test_intake.py` |
| Recovery and cleanup | `wormhole/recovery.py`, `wormhole/ubuntu_recovery.py`, `wormhole/storage.py` | `tests/test_recovery.py`, `tests/test_storage.py` |
| Archive and exact restore | `wormhole/storage_archive.py`, `wormhole/archive_client.py` | `tests/test_storage.py`, `tests/test_archive_client.py` |
| Publication | `wormhole/publication.py`, `wormhole/ubuntu_release.py` | `tests/test_publication.py`, `tests/test_ubuntu_reports.py`, `tests/test_ubuntu_release_readback.py` |

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

This snapshot reconciles the verified [two-OS delivery](https://github.com/TheSlayer455/jake-wormhole/pull/48),
the automatic-cleanup implementation at
[21fb946831a451a93c970346855e2c2aec781fb0](https://github.com/TheSlayer455/jake-wormhole/commit/21fb946831a451a93c970346855e2c2aec781fb0)
and the fresh acceptance report in [PR 53](https://github.com/TheSlayer455/jake-wormhole/pull/53).
The report is on public main at
[59fb4392e187efa08509abc6492bfe800564680e](https://github.com/TheSlayer455/jake-wormhole/commit/59fb4392e187efa08509abc6492bfe800564680e).
Each installation retains its own runtime revision. Engineering proof, lab
qualification and work integration are separate outcomes.

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
| C / 2026-11-11, runtime receipt date | [Chrony and recovery correction at e320823](https://github.com/TheSlayer455/jake-wormhole/commit/e3208237884acc53fb4821cdbc6dcb5e867e49e1) | One fresh encrypted RHEL 10 installation preserved the declared lab time source and synchronization while the selected client-only and no-network-management rules passed. All 1,073 native outcomes were accounted for; assessment performed no remediation; hardened/controller checks, evidence retention and exact-owned cleanup passed. A finished-journal recovery retained an interrupted workload as unknown and reclaimed only duplicate candidate storage. |
| K / 2026-11-12, runtime receipt date | [Kdump and banner-path runtime at da63dc0](https://github.com/TheSlayer455/jake-wormhole/commit/da63dc0a79b6b545f4fe7ef9c55cf9d9ac0b2be0) | One fresh encrypted RHEL 10 installation passed the final masked-kdump and SSH banner-path rules, every hardened/controller check, SVD, full native accounting, no-remediation assessment and cleanup. The honest local banner exposed a separate upstream-default value mismatch, so eligibility remains false. |
| B / 2026-11-12, runtime receipt date | [Declared banner tailoring runtime at 03d2986](https://github.com/TheSlayer455/jake-wormhole/commit/03d29868184bb711c78932eb1eea78e3f18b0ac3) | One fresh encrypted RHEL 10 installation used a one-value XCCDF tailoring for the truthful lab banner. The receipt binds those exact tailoring bytes; the banner rule and all previously closed chrony/kdump/SSH-banner rules pass, assessment performed no remediation, all hardened/controller checks and cleanup passed, and all 1,073 native outcomes remain accounted. |
| AC / 2026-11-12, runtime receipt date | [Authorized-account runtime at c944a86](https://github.com/TheSlayer455/jake-wormhole/commit/c944a8668e86979e38af673c5d81a9bf54d270a6) | One fresh encrypted RHEL 10 installation declared only the three locked package service identities and final Wormhole identity omitted by the pinned default. The native account rule passed without deleting accounts or excluding rules; all 1,073 outcomes, hardened/controller checks, read-only assessment and cleanup passed. |
| NR / 2026-11-12, runtime receipt date | [Local-only name-resolution runtime at 77498b3](https://github.com/TheSlayer455/jake-wormhole/commit/77498b3a5934e3ee7cc538e30194e39b74e9eba1) | One fresh encrypted RHEL 10 installation used the pinned rule's truthful local-only branch rather than inventing a second DNS service. The name-resolution and NetworkManager rules, time/log/audit services, all hardened/controller checks, SVD, read-only assessment and cleanup passed; all 1,073 outcomes remain accounted. The encrypted archive verified ten objects and exact-file cleanup reclaimed 8,487,366,656 allocated bytes. |
| G0 / 2026-11-12, failed diagnostic | [First GRUB draft at f611d95](https://github.com/TheSlayer455/jake-wormhole/commit/f611d951fb78059fc0cd25c27c049cd10a8378db) | The actual attempt installed all 449 packages, then failed in hardening because the draft expected PBKDF2 material in the wrong GRUB file shape. Readiness and dependent checks were blocked; exact-owned teardown completed and cleanup reclaimed 405,504 transient allocated bytes. This failed attempt is preserved and is not proof of the corrected input. |
| GA / 2026-11-12, runtime receipt date | [GRUB generator correction at 518691a](https://github.com/TheSlayer455/jake-wormhole/commit/518691acacf909c0e01624af2a31a561d7a33c28), [executed source at 7bfa09d](https://github.com/TheSlayer455/jake-wormhole/commit/7bfa09def373c32d2177d223fcf6d97b35289d28) | A fresh encrypted installation proved the corrected generator, preserved PBKDF2 material, actual boot, trusted SSH/Ansible, all hardened/controller checks, SVD and read-only assessment. The GRUB rule passes; 432 native passes/two failures remain, assessment performed no repair and exact-owned cleanup passed. |
| S / 2026-10-31 checkpoint | [Retained SVD archival at f2a3d5c](https://github.com/TheSlayer455/jake-wormhole/blob/f2a3d5ca383a1fea9230a9d1225406ae1f9bde26/wormhole/storage_archive.py); [PR 45](https://github.com/TheSlayer455/jake-wormhole/pull/45) | 298 verified encrypted objects at that checkpoint; six additional SVD/build-manifest readbacks; local originals retained. This is not a live backlog count. |

## Verified mechanisms and boundaries

| Lifecycle | Implementation and actual proof | Transfer limitation |
| --- | --- | --- |
| Media and candidates | Streaming chunk reconstruction verifies source integrity. Installed-input fingerprints govern candidate reuse; unchanged bytes can serve new attempts without rebuilding. U verifies identical candidate/contract across two independent installations. | Hash identity alone does not prove freshness, qualification or team intent. Controller/report-only changes differ from installed-input changes. |
| RHEL installer | R preserves the DVD BIOS boot machinery and uses a separate Kickstart seed. H applies pinned hardening during installation and validates the resulting system after reboot. The powered-off check verified LUKS acceptance of the correct key and refusal of wrong and missing keys. | BIOS lab profiles. The receiving team owns its installation contract. H still has open assessment findings and cryptographic validation requirements. |
| Ubuntu installer | [Ubuntu inputs](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_inputs.py) bind versioned offline payloads and hardening with a declared private NoCloud seed. U installs Ubuntu 22.04.5 x86_64, completes first-boot finalization/hardening and required reboot. | Neither path is a universally self-contained ISO. Separate secrets/endpoints are declared dependencies; acceptance does not repair the guest into compliance. |
| VM provisioning | [Shared VM lifecycle](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/vm_baseline.py) uses Terraform/libvirt/KVM, empty disks, serial evidence and exact resource journals. One live acceptance guest; 8 GiB RAM/two vCPUs, RHEL 32 GiB disk or Ubuntu 64 GiB disk. | Ubuntu virtualization host, BIOS only. No UEFI/Secure Boot, enterprise scale, remote work-runner routing or arbitrary host compatibility claim. |
| Readiness and trust | Controlled serial evidence supplies the installed guest's unique host key. Strict SSH verifies host identity and the intended final account, completed installation marker, OS and mounted root. Real Ansible verifies interpreter/privilege access from the designated helper. U also proves encrypted reboot/cold-start and wrong/missing unlock refusal. | Port-open or installer SSH cannot satisfy readiness. RHEL baseline privilege policy differs from Ubuntu's required password-based escalation; preserve each contract. |
| Functional validation | U: 40/40 checks each, including real lab logging/audit/time, scoped trust/PAM, encryption and access probes. H/E: 10/10 hardened and 6/6 controller checks, including encryption, FIPS mode, SELinux, audit, logging, time, reboot and Ansible. L: authenticated but inaccessible completion evidence immediately blocks dependent checks. | These are declared lab catalogs, not a proprietary product catalog. Lab time/PKI/software-token tests do not establish external trusted time, government identity or physical-token assurance. |
| SVD | Structured native Ansible inventory feeds readable and JSON SVDs. H/E: 449 RPM rows with native version/release/epoch/architecture; key headers separate. U/E: 638 packages, three Snaps and two payload entries. Build inventory remains distinct from installed inventory. Original row/readable-output readback passed. | Counts do not establish equivalent proprietary packages or business behavior. No package list is exported here. |
| Assessment | Both OSes retain actual OpenSCAP machine-readable and readable reports, scanner/content identity and every native outcome. Ubuntu supplements manual observations without rewriting scanner statuses. | Findings must satisfy the declared policy. Evaluate-STIG, Nessus and Ubuntu USG/FIPS execution remain unproven. |
| Execution and recovery | L acknowledges actual admission/start, records observed phase/progress separately from liveness, and persists failure/unknown outcomes. Controlled interruption retained unknown state until stopped-process/ownership reconciliation. C also proves recovery when the immutable resource journal finished before the terminal result was written: exact absence was reobserved and the workload stayed unknown. U's final pair finished automatically; compact terminal storage summaries reference full durable receipts. | Missing acknowledgment or observer loss requires reconciliation, not automatic duplicate launch. A recovered unknown attempt remains unknown, never successful. |
| Cleanup | Terraform destroys exactly recorded resources after evidence collection; storage uses the shared admission/ownership lock. U/R/L verified temporary resource absence. Original operation errors survive cleanup errors. | No global prune, ambiguous-prefix deletion or deletion of unresolved evidence. Historical absence is not evidence of current host availability. |
| Completed-ISO intake | I and D verify an explicit completion manifest, protected bytes, actual size/hash and a declared contract. They use the same dispatcher and fresh seed. D also binds the build manifest and verifies the embedded Ubuntu payload. | Evidence covers RHEL 10 BIOS baseline and Ubuntu 22.04 hardened sandbox. Periodic monitoring was exercised on RHEL and removed afterward. Other producer contracts need their own evidence. |
| Intake identity and retries | I proves no second active VM on duplicate notification/restart. Real-file source fixtures prove same filename/new bytes, changed assessment identity and explicit retry create distinct requests. | Those identity fixtures are not additional VM experiments. Deduplication must not permanently prevent legitimate requalification. |
| Storage/archive | A/S/T extend existing storage receipts: workstation-initiated strict SSH, age encryption, actual decrypted destination hash/size verification, durable commit before eligible local reclamation, explicit verified restore. Active disks/state/credentials/journals stay local. Offline/pending data is retained; admission can refuse new work. | Real archive/restore and failure tests, not a proposal or localhost-only copy. A limited periodic task was installed and exercised at the checkpoint; current availability is not asserted. Retention is not a proven independent backup or key-loss recovery policy. |
| Gates/publication | [Ubuntu gate/publisher](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_release.py) requires complete bound results, matching independent installations and declared policy. U's normal publication attempt was refused for pending dependencies with no release created. | Positive ISO-publication integrity fixtures are source tests only. No lab-qualified ISO publication is proven. Historical container-reference publication is a separate capability. Production eligibility remains false. |

## Native outcomes and unresolved qualification

| Native result | RHEL baseline R | Hardened H/E | Chrony C | Kdump/banner K | Banner B | Accounts AC | DNS NR | GRUB GA | Ubuntu U/D, each |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Pass | 172 | 425 | 427 | 428 | 429 | 430 | 431 | 432 | 210 |
| Fail | 261 | 9 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
| Not applicable | 56 | 29 | 29 | 29 | 29 | 29 | 29 | 29 | 14 |
| Not checked | 9 | 10 | 10 | 10 | 10 | 10 | 10 | 10 | 5 |
| Not selected | 450 | 600 | 600 | 600 | 600 | 600 | 600 | 600 | 409 |
| Total | 948 | 1,073 | 1,073 | 1,073 | 1,073 | 1,073 | 1,073 | 1,073 | 639 |

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

### Exact current RHEL qualification blockers

The fresh C run closed the two historical chrony failures while preserving time
synchronization. K then closed kdump and the SSH banner path, while exposing the
separate declared-banner-value mismatch. B closed that value mismatch through a
single declared XCCDF value, without changing rule selection. AC then closed the
authorized-account mismatch, NR closed the name-resolution finding without
adding a fictitious resolver and GA closed the GRUB administrator finding in a
fresh booted installation. These two selected automated failures remain. The
names are public rule suffixes, not private configuration values.

| Rule suffix | Open requirement |
| --- | --- |
| `selinux_context_elevation_for_sudo` | SELinux context elevation through sudo |
| `sssd_enable_certmap` | SSSD certificate mapping |

The retained B objects showed that the account rule's RHEL 10 default allowlist
omits three locked service identities belonging to installed packages and the
declared final Wormhole service identity. Source
[ff881b1](https://github.com/TheSlayer455/jake-wormhole/commit/ff881b11cbb6184adbdb398d787979c06912edee)
adds only those four identities to the existing XCCDF value; it does not delete
accounts, exclude the rule or change rule selection. Focused generated-input
tests passed. AC's fresh installation proved the native result while preserving
authentication, inventory, assessment and cleanup.

The isolated guest enabled DNS lookup but had no second resolver or declared
DNS dependency. Source
[2b3c16b](https://github.com/TheSlayer455/jake-wormhole/commit/2b3c16ba476c5d0c5f03467030b37c0422531923)
implements the pinned rule's documented local-only branch using NetworkManager
`dns=none`, NSS without the `dns` token and an empty resolver file. It does not
invent duplicate DNS servers. NR proved the native rule and unchanged
post-reboot lab-service behavior in a fresh installation.

The retained GRUB OVAL evidence found Anaconda's default `root` boot-loader
administrator even though a valid per-installation PBKDF2 secret existed.
[518691a](https://github.com/TheSlayer455/jake-wormhole/commit/518691acacf909c0e01624af2a31a561d7a33c28)
changes the generator username independent of its password expression, verifies
the separately stored PBKDF2 secret, uses the non-login
`wormhole_boot_admin` and regenerates the installed BIOS configuration. Focused
source tests pass. GA proved the native rule, actual boot, final access and
unchanged hardened/controller behavior in a fresh installation.

The retained native objects established that the final kdump unit was inactive
but loaded rather than masked, and that the post-remediation SSH drop-in used a
different banner path. [a947977](https://github.com/TheSlayer455/jake-wormhole/commit/a947977c541adc6309c436803cfb992f5da18e75)
corrected both installation inputs, and K proved both native rules pass. K also
proved that hard-coding the accurate lab notice after remediation cannot satisfy
the upstream profile's different default banner expression. That distinct rule
was addressed in source at
[e28b6bf](https://github.com/TheSlayer455/jake-wormhole/commit/e28b6bfa2e1dd765240b36f47b836bdb924894fe)
by a single declared XCCDF value used for both installation remediation and the
read-only audit. It changes no rule selection and grants no exception. The rule
passed in B's fresh empty-disk installation; its receipt binds the tailoring
bytes and records no assessment remediation.

Ten native not-checked rules still need accountable rule-level evidence and
disposition: `crypto_policy_not_overridden`, `encrypt_partitions`,
`account_temp_expire_date`, `accounts_user_home_paths_only`,
`configure_firewalld_ports`, `configured_firewalld_default_deny`,
`libreswan_approved_tunnels`, `ssh_keys_passphrase_protected`,
`sssd_has_trust_anchor` and
`auditd_audispd_configure_sufficiently_large_partition`. Encryption and FIPS
functional checks provide bounded supplemental observations without rewriting
native statuses. Cryptographic module identity, certification scope and the
applicable operating environment remain unverified. Wormhole also lacks a
completed RHEL lab release evaluator and exact-byte publisher. These are
engineering tasks, not new owner approval requests.

### Exact current Ubuntu qualification blockers

The only selected automated failure is `is_fips_mode_enabled`. The explicit
protected provider slot is empty. The minimum owner action is to place a
legitimate Ubuntu Pro entitlement into that existing private owner-file provider
using its documented local provisioning procedure. Do not put the value in chat.
After that input exists, supported enrollment, package/content pinning, actual
USG/FIPS execution, reboot, LUKS unlock, runtime verification, reassessment and
a final matching installation pair remain engineering work.

All five objective supplemental manual observations passed, while native
not-checked statuses remain intact. Delegated trust review and frozen V2R7/V2R8
mapping are complete. Physical-token hardware and another owner certificate
review are not required home-lab actions. The publisher correctly returned
`lab_policy_dependencies_pending` and created no release. Its prospective static
policy/gate reconciliation remains engineering after vendor execution.

Evaluate-STIG and Nessus have not run. An authorized supported package/interface
is unavailable. They remain separate work-equivalence limitations under the
current lab policies and cannot be represented by renaming OpenSCAP output.

### Current cleanup and retained-storage state

Fresh E execution reclaimed 7.905 GiB after RHEL and 2.130 GiB after Ubuntu
through automatic exact-file cleanup. Verified archive reconciliation reclaimed
another 964 KiB. Terraform separately destroyed both guest disks. The largest
sampled physical disk allocations before teardown were 2.276 GiB and 5.353 GiB;
those are lower-bound observations and are not added to the file-cleanup total.

Final reconciliation found zero run-owned VM resources and stopped supervisors.
All 66 unrelated running containers matched the pre-run set. Repeating cleanup
reclaimed zero. Current retained managed storage is 83.473 GiB: 37.784 GiB of
candidate cache, 9.874 GiB of source media, 22.402 GiB of required evidence,
13.354 GiB of other protected state, 55.676 MiB of protected staging and
3.820 MiB of historical reference-release bundles. Host filesystem availability
was 131.340 GiB. The workstation archive held 407 encrypted objects occupying
68.794 GiB, with no pending bytes, failed receipts or transfer staging.

C later recovered a finished-journal/missing-result inconsistency without
inventing success. The normal storage engine reclaimed 8,487,432,192 allocated
duplicate bytes while retaining a canonical local candidate and verified archive.
Its fresh RHEL run reclaimed another 405,504 transient allocated bytes. Current
managed storage is 83.594 GiB, including a 37.784 GiB candidate cache, with
130.785 GiB host filesystem availability. All 66 unrelated running containers
matched the pre-run set.

NR's archive then verified ten additional encrypted objects and exact-file
cleanup reclaimed 8,487,366,656 allocated bytes. Current allocation is 76.167
GiB managed, 29.880 GiB candidates and 138.207 GiB available, with 457 committed
archive objects, zero pending bytes, zero failed receipts and no VM disk.

Managed retention grew about 200.7 MiB because the new native evidence is kept.
That growth does not negate temporary cleanup. Protected active inputs, required
evidence and uncertain historical state must remain. An archive receipt is not a
qualification decision, and an unavailable archive tier cannot authorize deletion
of the only verified local copy.

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

## Terra's required comparison and response

Inspect the actual Lightspeed source and latest runtime evidence inside its
authorized environment. Compare equivalent responsibilities rather than file
names. Do not assume a Wormhole mechanism is missing until the receiving source
and runtime prove that. Produce this matrix for the first unresolved boundary.

| Field | Required content |
| --- | --- |
| Lifecycle stage | Candidate, media, installer, VM, readiness, validation, evidence, cleanup or release |
| Wormhole mechanism | The verified method in this bundle |
| Wormhole evidence | Runtime/source label from the evidence index and its scope |
| Lightspeed mechanism | Actual observed equivalent in the authorized environment |
| Lightspeed evidence | Source observation, cheap reproduction or current runtime fact |
| Difference | The concrete functional mismatch, without ranking the projects |
| Failure relevance | Proven cause, probable contributor or unrelated to the observed failure |
| Recommended action | Keep, adapt, replace or investigate, preserving the owning contract |
| Acceptance proof | The smallest cheap proof followed by the next real boundary it cannot cover |
| Confidence | Proven, probable or unknown |

Then return the following work-side response. Keep private operational evidence
inside the work environment.

### A. Executive finding

Classify the current blocker as media/build, installer configuration, VM
provisioning, final guest readiness, remote orchestration, evidence handling,
release coverage or unknown pending evidence. State the classification in one
sentence and cite the observed boundary.

### B. Frozen case

Record the controller revision, candidate identity, declared installation-input
identity, attempt identity, evidence-file identity and current resource
disposition. Keep useful nonsecret run identifiers, candidate identity,
diagnostic paths, timestamps and exit status in the authorized work chat so the
owner can correlate execution. Protect actual credentials, private keys, tokens
and unlock material. Apply generalized identities only to the external update in
section J.

### C. First confirmed failing transition

Name the last successful state, next expected state, observed result and the
evidence category that proves the gap. Separate a current fact from a hypothesis.

### D. Cheap causal reproduction

Show the same component and input failing before the correction and succeeding
after it. State what the test reaches and what it cannot prove. For the console
case, confirm collector attachment, byte receipt, durable write and unchanged
preflight read against the same evidence file.

### E. Minimal repair

Identify the smallest existing component and change. Explain which contract is
preserved, which unrelated inputs stay frozen and why another abstraction is not
needed.

### F. Real acceptance proof

Specify the one focused real run, its effective 20-minute total cutoff, evidence
and cleanup reserve, expected first new boundary, live output and terminal
done-check. Stop promptly on a definitive prerequisite failure.

### G. Result accounting and resource disposition

List expected, passed, failed, blocked, missing and error rows. Preserve primary
and secondary failures. State whether the controller is active, stopped,
terminal or unknown; report exact-owned guest cleanup separately. Never infer
remote termination from an observer exit.

### H. Product coverage and downstream blockers

State whether the authoritative catalog has real cases and maps every required
product check. List unavailable scanner or release dependencies separately.
Do not treat unproven downstream work as another cause of the current installer
failure.

### I. Next executable chat step

Give one coherent command group or patch for work WSL. Include working directory,
read-only or mutating classification, preconditions, expected result, done-check
and the smallest useful nonsecret output to paste back. Do not bundle speculative
repairs.

### J. Sanitized external update

Only when the owner requests a portable update, replace private identifiers with
functional roles such as **ansible control node** and **rhel kvm host**. Include
the first boundary, generalized evidence, material change, observed result,
timings where measured, resource disposition and next action. Exclude private
names, addresses, accounts, paths, URLs, identifiers, exact timestamps, hashes,
commands, source and raw logs. Confirm that the sanitized report contains none
of those restricted details.

## Portable-sharing checklist

The Wormhole material in this file is selected from an explicit safe-fact set.
It contains public code names and commits, public OS/tool names, aggregate
outcomes, generalized role names and rounded or nonidentifying measurements.
It intentionally excludes licensed media, credentials, reusable identity
material, private runtime paths, private resource names, private network details,
raw logs, package lists and work source.

Before bringing a Lightspeed update back outside the authorized environment,
read the report itself. Check headings, tables, captions and copied diagnostic
text, not only prose. Heuristic pattern checks can catch obvious leaks but do not
replace this review. If a restricted detail is technically important, explain
its function generically and keep the original evidence private.

## Start here in Terra

This bundle is sufficient Wormhole context for the initial diagnosis. Do not ask
the owner for another Wormhole file. Return one read-only command group for work
WSL to inspect the current checkout, effective deployed collector/preflight code,
latest attempt and exact resource disposition. The done-check is one correlated
attempt with a known controller revision, candidate and installation-input
identity, evidence file and active, terminal or unknown ownership state. Use that
returned evidence to select the first no-VM causal check.
