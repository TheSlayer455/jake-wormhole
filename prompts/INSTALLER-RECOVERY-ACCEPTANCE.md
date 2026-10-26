# Prompt 1: Installer Recovery and End-to-End Acceptance

## Mission

Continue work in the existing authorized repository and GitLab environment. Repair the Linux installation and acceptance path, then complete the existing qualification workflow with evidence from real executions.

This is an execution assignment. Preserve working functionality and make focused, reviewable changes. Do not produce another architecture proposal, perform a broad rewrite, or add an orchestration framework.

The immediate objective is to prove that the intended current candidates install correctly, that all 13 planned guests become genuinely Ansible-ready, and that the supervisor produces a complete terminal result within the CI budget.

Use these infrastructure role names in this assignment and in summaries:

* rhel kvm host: The RHEL/KVM system hosting temporary guests.
* ansible control node: The system hosting the RKE2 GitLab runners, pipeline helper environment, Ansible control functions, and persistent evidence destination.

Resolve real identities from the authorized environment internally. Never substitute guessed names, addresses, accounts, paths, or credentials.

## 1. Preserve scope and distinguish facts from assumptions

The existing implementation uses Bash, Python, YAML, and some PowerShell. Keep this stack. Preserve Forge, candidate construction, chunked source handling, hashing, manifests, existing test definitions, and working staging behavior.

The active Linux scope is RHEL 8, RHEL 9, RHEL 10, and Ubuntu 22. The current acceptance plan contains 13 guests, including a RHEL 10 container profile. Read the exact assignments and settings from the actual plan. Do not expand to 20 guests, add Windows, or add MDT.

The latest handover reports:

| Reported observation | Engineering implication to verify |
| --- | --- |
| All 13 guests were created. | Creation is established for that attempt, not successful installation. |
| At least one RHEL guest entered an installer emergency environment with missing installation-source/runtime information. | Inspect the actual boot path before changing SSH logic. |
| Ubuntu stopped in its final-configuration/update script before final account and SSH setup. | Diagnose the first failing command, not the downstream authentication symptom. |
| The controller waited through readiness failure and then launched the full Ansible playbook. | Correct dependency enforcement and terminal-result handling. |
| The targeted retry reused older candidates for several OS families. | That retry cannot prove current installer repairs. |
| The CI observer stopped while remote work remained active. | Reconcile the existing run before retrying or cleaning up. |
| Functional results and downstream qualification are incomplete. | Do not declare acceptance or release success. |

Treat these as the starting evidence, not proof that every defect is still present. Inspect the latest actual state and avoid reapplying repairs already verified.

## 2. Inspect and reconcile the current run first

Before changing infrastructure, retrieve the latest job, supervisor state, fleet plan, candidate identities, progress records, and existing results. Determine whether the run is active, terminal-successful, terminal-failed, or unknown.

Correlate the observer, supervisor, guests, and evidence to the same attempt. Do not combine success from one attempt with repaired source or candidates from another.

A timed-out CI job does not prove remote execution stopped. An existing supervisor process does not prove progress. An old status file does not establish a current terminal state.

If remote work remains active, inspect its actual stage and last progress. Do not start a competing acceptance run or destroy its resources. Do not modify files being consumed by the active run. Independent regression work may proceed in a separate checkout that cannot change the running attempt.

If the run is failed or stuck and its ownership and state are known, collect available diagnostics and use the existing bounded stop procedure where appropriate. Preserve the original failure, persist evidence on the ansible control node, then perform exact-ownership cleanup.

If state is unknown, perform bounded read-only reconciliation. Record the specific observation or access that prevents classification. Do not leave an unowned mystery fleet indefinitely, but do not treat elapsed time as permission to delete uncertain resources.

## 3. Correct the supervisor before another expensive fleet retry

The full fleet functional playbook must not start unless every required guest has passed the declared readiness contract.

Implement this behavior in the existing supervisor/controller, not in another parallel wrapper:

| Condition | Required action |
| --- | --- |
| All required guests are Ansible-ready. | Start the full functional catalog. |
| A definitive installation failure is observed. | Record that guest’s installation failure immediately and collect diagnostics. |
| Readiness expires with unresolved guests. | Preserve per-guest outcomes, mark dependent checks blocked, skip the full fleet playbook, and write a terminal failed result. |
| A safe diagnostic operation on a ready subset is useful. | Run it only as an explicitly scoped diagnostic operation. It cannot count as full fleet acceptance. |
| Remote state cannot be established. | Report unknown state and reconcile it. Do not fabricate a terminal remote outcome. |

The observer, supervisor, subprocesses, and evidence collection need compatible absolute deadlines. Do not allow each retry or stage to reset the total budget. Stop starting dependent work when its prerequisites or remaining time cannot support it.

The reported CI limit is 90 minutes, with approximately ten minutes intended for evidence collection. Verify current settings. Do not increase timeouts as the first repair. Preserve a usable evidence margin at both the CI and remote-execution layers.

Bound status reads, SSH operations, subprocess waits, and evidence transfer. Preserve the original error separately from collection or cleanup errors. Use the existing durable result mechanism to write the aggregate result before normal supervisor exit. The controller must distinguish an actual failed terminal result from loss of observation.

Add regressions proving that incomplete readiness never invokes the full playbook, that an exception cannot be converted to success, and that deadline exhaustion still produces the best available persistent failure evidence.

## 4. Repair the actual RHEL boot and installation path

For each distinct RHEL installation path in the plan, inspect the actual attached media and guest console. A metadata check or a powered-on VM is not proof of a valid installation.

Correlate:

1. Candidate and final attached-media identity.
2. Actual virtual CD/DVD attachment and storage backing.
3. Configured firmware and selected boot entry.
4. Actual installer kernel and initramfs arguments.
5. The installation runtime/source referenced by those arguments.
6. Guest-visible media, filesystem labels, and source availability.
7. The earliest console or installer failure.

Check whether the customization updates the boot entry the firmware actually selects. Cover BIOS/UEFI differences only where those paths are part of the plan. Do not assume the RHEL 10 metadata correction fixes RHEL 8 or RHEL 9.

Determine whether the installation runtime/source is missing, incorrectly referenced, inaccessible, or never selected. Inspect evidence before choosing a fix. Use release-appropriate supported behavior. Do not copy boot parameters between releases without validation.

After installation, verify boot from the installed disk rather than a repeated boot into the installer. Preserve bounded console and installer diagnostics even when guest networking never becomes available.

Required proof: A fresh installation using the current candidate completes, the installed system boots, and its final identity and configuration are observed. An ISO that merely opens successfully does not satisfy this proof.

## 5. Repair the first Ubuntu final-configuration failure

Locate the failing final-configuration/update step internally. Capture its complete relevant output and identify the earliest failing command, its exit status, and the state immediately before it failed.

Inspect its execution context: installer versus installed system, target root, working directory, privileges, mounted filesystems, package sources, dependencies, and ordering. Treat package availability, network access, locks, script logic, and target-context errors as hypotheses until the evidence supports one.

Use bounded diagnostic capture with secret-aware handling. Do not enable indiscriminate shell tracing that exposes credentials or put raw output in portable reports.

Fix the underlying error. Do not append success, broadly ignore the exit status, or move SSH setup earlier merely to make the guest appear ready.

Verify that successful final configuration is followed by creation of the intended final service account, installation of the correct authorized key, required access and sudo policy, completion of hardening, and the intended reboot.

The final dotted service identity remains a requirement. Do not silently replace it with a simpler username or count successful access through a temporary bootstrap account as final readiness. Handle bootstrap access according to the approved baseline.

A focused script test can shorten diagnosis, but qualification requires a fresh installation through the actual installer path. Record any manually modified guest as diagnostic, not qualification evidence.

## 6. Rebuild the affected candidates and prove media freshness

The handover identifies stale RHEL 8, RHEL 9, and Ubuntu candidates in a mixed retry. Produce fresh candidates for all four affected OS families from the intended current installer, account, hardening, and payload inputs, unless the latest inspected evidence already proves those exact rebuilt candidates exist.

Do not rebuild the same current bytes again just to produce a new attempt number. Do not reuse older bytes merely because their checksum is valid.

Use the existing manifests to bind:

* Approved base media identity.
* Relevant Forge and installation-input revisions.
* Payload and hardening inputs.
* Candidate output hash.
* Any subsequent remastering and its output hash.
* The exact media attached to each expected guest.
* The attempt, guest profile, installed build identity, and resulting evidence.

A retry-generation change is not proof that cached installation content was refreshed. Inspect the actual generated inputs and attached bytes.

Public-key injection or another remastering step may change the ISO. Determine whether this occurs after the candidate was hashed. If it does, record the final hash and do not qualify earlier, untested bytes using results from different media.

The customer artifact must match the tested artifact under the approved acceptance design. Do not solve a hash mismatch by shipping unintended temporary access or by editing the ISO after qualification. If the present design cannot establish tested-byte fidelity, identify that specific release blocker and make the smallest consistent correction.

For future retries, preserve valid candidate reuse when only controller, test, reporting, or observation code changes. Rebuild when installed content changes. Make this dependency distinction explicit without creating another build framework.

## 7. Define readiness as usable final-system access

Use the existing per-guest state mechanism, extending it only where needed. Record installation, observed port availability, authentication, hardening, reboot, Ansible readiness, failure, and completion as distinct observations.

Do not force those observations into an incorrect universal order. Early authentication can disappear during reboot. Record the current phase and a deliberate return to not-ready where appropriate.

Each guest needs a last transition, last progress observation, and current error category. Liveness alone must not be reported as progress.

Ansible readiness requires evidence that:

* The expected installed OS is running, not the installer environment.
* Required final configuration and hardening completed.
* The required final reboot completed where applicable.
* The intended final account exists with a usable home and shell.
* Parent-directory access, ownership, SSH permissions, and applicable security labels permit the intended login.
* The installed authorized key matches the expected controller key.
* Host identity is verified through the established trust mechanism.
* The actual controller/helper execution path can authenticate.
* The required Ansible interpreter and privilege escalation work.

Do not use a successful administrator-shell connection as a substitute for the actual execution path. Do not disable host-key verification, SELinux, or required hardening to satisfy readiness.

Recheck the RHEL access repair after the complete hardening sequence and reboot. A temporary permission or label change that later disappears is not a fix.

## 8. Execute the smallest useful verification, then the complete fleet

After current-run reconciliation and focused regressions:

1. Test the repaired RHEL boot path and Ubuntu final-configuration path with current candidates.
2. Cover the smallest set of guests that exercises every distinct required installation path.
3. Demonstrate fresh installation, final reboot, authenticated access, and Ansible readiness for those paths.
4. Execute the complete current 13-guest acceptance plan using the same verified candidates and current test/controller implementation.
5. Verify every planned functional result, the aggregate receipt, and the supervisor/controller terminal outcome.

These focused checks shorten diagnosis. They do not replace full acceptance. Use existing entry points where possible. Avoid building a second runner just for a one-guest experiment.

Provisioning, readiness, and test execution must have separate measured durations. Use bounded concurrency based on actual resource and I/O behavior. Do not infer that more simultaneous installations are faster.

Do not repeat an unchanged full-fleet failure without new evidence or a specific corrective hypothesis. Preserve failed attempts rather than overwriting their results.

## 9. Complete downstream work only at valid boundaries

A required failure, blocked check, missing guest, or incomplete result prevents a passing functional fleet receipt. Test counts must match the frozen plan, not merely the subset that returned results.

For the RHEL 10 container profile, retain explicit checks for its required container payload and the applicable Podman, Buildah, and Skopeo capabilities. Package presence alone is not proof of the required behavior. Use approved local inputs and the existing acceptance catalog.

Preserve build-time SVD generation. Where the workflow requires observed installed inventory, compare and retain it without confusing media contents with installed software.

Once functional acceptance is valid, execute supported Evaluate-STIG and Nessus stages and preserve native results, readable summaries, tool/content identity, and target attribution. A PowerShell smoke test is not a scanner result. A completed scan is not automatically an acceptable finding set.

Resolve the reported PowerShell dependency using the actual approved tool documentation and existing execution environments. Do not default to installing it on the hypervisor or bypassing internal package controls. Independent dependency investigation may proceed without holding up installer repairs.

Read the authoritative release policy. Do not invent STIG or vulnerability thresholds. If policy remains undefined, report completed evidence separately from qualification pending policy. Do not erase successful functional work or publish an unqualified release.

Apply final release naming and publication only to the exact candidate satisfying the complete required policy. Keep customer publication separate from diagnostics and reference success.

## 10. Make feedback fast without removing meaningful protections

Run cheap prerequisites before expensive jobs: required protected-variable availability, input usability, tool availability, source/media identity, necessary access, and measured capacity.

Use an authorized protected execution reference when protected credentials are needed. Do not expose credentials to an unprotected branch or make them unprotected to force execution. Report unavailable required variables by category without printing their values.

Routine authorized temporary provisioning, testing, evidence collection, and exact-owned cleanup do not require repeated conversational approval. Correct an unnecessary agent-created confirmation if it blocks these operations. Preserve system-enforced and organizational controls.

No broad guardrail audit, extra approval system, redundant validation framework, or new dashboard is part of this assignment. Correct the concrete blockers and consolidate duplication only where necessary for the repair.

Keep artifacts persistent outside ephemeral runner filesystems. Prefer available immutable media and tool images over repeated transfers or installations where integrity is preserved. Measure the actual critical path before claiming a speed improvement.

## 11. Required completion evidence

Report these milestones separately:

| Milestone | Required proof |
| --- | --- |
| Installation repair | Each required current installation path completes from fresh media and boots its installed system. |
| Guest readiness | All 13 planned guests satisfy final-system authentication and Ansible readiness from the actual execution path. |
| Functional acceptance | Complete required results, passing fleet receipt, and consistent terminal outcomes. |
| Assessment completion | Actual supported scanner execution and complete attributed outputs. |
| Qualification | Required findings policy, tests, inventory, and evidence integrity all satisfied. |
| Publication | Exact qualified bytes and required documentation published through the existing mechanism. |
| Resource disposition | Owned resources removed or explicitly retained with a reason and accountable state. |

Include focused regressions for incomplete readiness, installation failure, missing results, and terminal reporting. Expected-negative tests pass by observing a genuine underlying failure. They must not turn that failed acceptance attempt into a success.

Run applicable repository validation. Record actual commands and evidence internally, with executed, skipped, synthetic, and unverified checks distinguished. A green repository gate is not installation proof.

Work incrementally with reviewable commits. Do not alter requirements, remove failing required tests, fabricate results, or suppress exit statuses to obtain green CI.

## 12. Final response and stopping conditions

Provide a concise internal completion report covering the inspected attempt, verified root causes, changes, tests actually executed, per-OS counts, timing breakdown, evidence locations, terminal state, remaining resources, and qualification status.

If a genuine external dependency prevents further progress, identify the exact blocked boundary and continue independent useful work. Do not claim future background work or call an unverified retry successful.

Do not automatically upload source, logs, or reports to external services. A separate sanitized-report request will define what can be prepared for outside review.

Start by inspecting the existing run. The priority is a correct installation, an honest readiness decision, and a complete terminal result, followed by full qualification. Do not substitute another timeout increase, another permission prompt, or another planning document for measured progress.
