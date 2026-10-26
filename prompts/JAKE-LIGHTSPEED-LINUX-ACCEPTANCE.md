# Jake Lightspeed: Verify the Current Retry, Repair Remaining Defects, and Complete Linux Acceptance

## Mission

Work in the existing Jake Lightspeed repository and authorized GitLab environment. Complete the Linux acceptance workflow using evidence from real executions.

This is an execution assignment, not a request for another architecture proposal, project-wide audit, or rewrite. Preserve the working implementation. Make focused repairs where observations establish that a repair is needed.

The immediate objective is:

Verify the current post-repair attempt, get all 13 expected guests through authenticated SSH and Ansible readiness, complete the functional catalog, and produce an accurate terminal result with complete evidence.

After that boundary is proven, continue through the existing SVD, Evaluate-STIG, Nessus, qualification, and publication workflow where dependencies and acceptance policies permit.

Do not declare success merely because a GitLab job turns green.

## 1. Preserve the actual architecture and current scope

The project primarily uses Bash, Python, YAML, and some PowerShell. Preserve that stack and the current division of responsibilities. Do not introduce another orchestration framework or translate working code between languages for style.

* GitLab Package Registry holds chunked stock RHEL 8, RHEL 9, RHEL 10, and Ubuntu media.
* Forge produces custom candidate ISOs, manifests, and hashes.
* jakeboom1 hosts RKE2 GitLab runners and the pipeline helper image. It is the automation control node and persistent evidence destination.
* jakeboom7 is the RHEL/KVM host for the temporary guest fleet.
* Terraform provisions guests. Ansible operates from the designated control environment.
* The current acceptance plan contains 13 guests. Read their actual OS/profile assignments from that plan. Do not infer the distribution or expand to 20 guests during this repair.
* The RHEL 10 candidate includes a custom container. Preserve its existing acceptance requirements.
* Windows and MDT are out of scope.

Identify the real execution location of each command. A successful SSH test from the hypervisor or an administrator shell does not establish connectivity from the actual runner/helper or delegated Ansible execution environment.

## 2. Begin with the current retry, not another change

The latest report states that the acceptance job staged four hash-bound candidates, passed the read-only host/Foreman/control-node gate, created 13 VMs, injected the expected public key, and started the remote supervisor.

The reported failures were downstream:

* Ubuntu did not create the intended final dotted service-account identity in the installed system.
* RHEL created the account, but later hardening made its home inaccessible.
* The supervisor remained in deployment while waiting for manageable guests, and the controller exhausted its observation window.

Repairs reportedly added a valid Ubuntu bootstrap identity and late creation of the final identity, reapplied RHEL ownership/permission/security-context corrections after hardening, and improved observation deadlines and bounded status reads.

These repairs are implemented claims, not proof of successful acceptance. A post-repair retry was started and its result remains unverified.

Your first activity must be read-only inspection of that attempt. Identify:

* Pipeline/job identity, source revision, retry generation, and candidate hashes.
* The remote run identity and its mapping to the expected fleet.
* Current CI state, supervisor state, and per-guest readiness state.
* Whether the repaired source and freshly generated installation configuration were actually used.
* Existing receipts, test results, diagnostics, and evidence collection status.

Classify the attempt as running, successful with verified evidence, terminal failure, or unknown because evidence is insufficient.

Do not modify the code under test, start another fleet, rebuild candidates, clean up the current fleet, or launch an overlapping retry until this attempt’s state and resource ownership are understood.

A CI timeout does not prove the remote supervisor stopped. A stale status file does not prove the guest failed. A supervisor process that exists does not prove progress.

If state is unknown, reconcile the existing supervisor, heartbeat, guest state, and partial evidence through bounded read-only checks. Preserve the run. If the available access cannot resolve its state, report the exact missing evidence instead of guessing or repeatedly launching replacements.

## 3. Execute authorized work without unnecessary permission prompts

Routine project operations are authorized within the established lab scope: inspecting the repository and logs, making repair-branch changes, running regression tests, building required candidates, provisioning the configured temporary fleet, testing it, collecting evidence, and cleaning up positively identified project-owned resources.

Do not repeatedly ask for conversational permission to run Stage 2 or another ordinary step in an authorized acceptance attempt. Existing active-run reconciliation must happen first.

Remove or correct an unnecessary agent-created confirmation only where it obstructs the current authorized workflow. Do not turn this task into a broad guardrail-removal campaign.

Preserve actual organizational controls, scoped credentials, host security, resource limits, SSH identity verification, evidence integrity, and ownership-safe cleanup. Do not use blanket permissions, disable SELinux, bypass required hardening, or suppress failures to obtain progress.

Keep runtime operations tied to their recorded revision. If a repair requires a new revision, preserve the previous attempt and use a new, attributable attempt rather than changing the meaning of old evidence.

## 4. Diagnose the first failing transition

If the current retry failed, use its evidence to identify the earliest failed transition for each affected guest:

| Transition | Required evidence |
| --- | --- |
| Created to installing | Correct guest definition, installation media, disk, and installer activity |
| Installing to installed | Installation completion and boot from the installed disk |
| Installed to reachable | Expected endpoint and reachability from the actual controller environment |
| Reachable to SSH authenticated | Intended account, expected host identity, and intended key pair |
| SSH authenticated to Ansible ready | Correct inventory, usable connection, required interpreter, and required privilege escalation |
| Ansible ready to tests complete | Complete planned test results with actual execution status |
| Tests complete to terminal result | Persisted aggregate results, valid receipt, and consistent supervisor/controller outcome |

Distinguish confirmed causes from hypotheses. Do not attribute a guest account failure to Terraform or hardware capacity without evidence. Do not interpret a short-lived authentication failure during an unfinished installation as a permanent defect.

### Ubuntu verification

Check the installed system, not just the generated installer configuration. Establish that the late command actually ran in the intended target context, the final dotted identity exists exactly as required, and its home, shell, group membership, authorized key, and access policy support the intended connection.

Confirm the controller uses the final identity rather than accidentally succeeding through the temporary bootstrap account. Handle that bootstrap account according to the approved baseline. Do not leave an unintended alternate administrative path.

Do not silently rename the required account or remove its dots merely to make a test pass.

### RHEL verification

Verify account state, home and parent-directory traversal, ownership, SSH-directory/key permissions, applicable ACLs, and SELinux labels after the complete hardening sequence and reboot.

Identify the exact hardening operation that changes accessibility. Correct the ordering or policy-consistent implementation rather than adding another unexplained repair wrapper.

The final state must satisfy both intended SSH access and required hardening. Use persistent, policy-consistent labeling where needed. Do not treat permissive SELinux or broad filesystem access as a fix.

### Connection verification

Compare the expected public-key fingerprint with the installed authorized key and the key actually selected by the controller. Do not print private keys or secret values.

Inspect inventory, remote user, endpoint, host-key handling, proxy/delegation configuration, interpreter, and privilege escalation as applicable. Test from the actual Ansible execution path, not a more privileged substitute.

If all guests authenticate but the run still hangs, stop changing installer identities. Investigate test dispatch, subprocess completion, pending result queues, receipt generation, terminal-state writes, and controller observation.

## 5. Repair narrowly and verify through fresh installation

For a confirmed defect:

1. Preserve the failure evidence and write a short, testable explanation.
2. Make the smallest repository-owned correction on a repair branch.
3. Add a focused regression test for the actual failure.
4. Exercise the affected path before spending another full fleet run.
5. Validate the correction through a fresh installation, then execute the complete 13-guest plan.

Use an existing focused entry point where available. Do not build a second execution framework to run one guest. For shared installer changes, cover every affected OS profile before claiming the fleet is repaired.

If investigating requires a controlled change to a preserved guest, record it as diagnostic intervention. That guest cannot establish that the original candidate installs correctly. Qualification requires a fresh, unmodified acceptance installation from the corrected inputs.

Do not repeatedly rerun unchanged failures without new evidence. When a proposed fix fails, update the diagnosis before another expensive attempt.

## 6. Replace silent waiting with useful progress

Reported attempts spent approximately 61 to 80 minutes observing terminal status. The current CI timeout is 90 minutes, with approximately 10 minutes reserved for evidence collection.

Do not increase the timeout as the default repair. Preserve the existing observation and evidence budgets unless measured successful execution demonstrates a justified need to change them.

Within the existing supervisor and controller, expose bounded per-guest progress sufficient to answer:

* Which stage is each of the 13 guests in?
* When did it last make progress?
* Is it installing, rebooting, unreachable, failing authentication, running tests, or finished?
* What is the latest meaningful error category?
* Which expected results remain outstanding?

Record stage timings and distinguish liveness from progress. A heartbeat alone must not imply productive work.

Use the existing absolute deadline correctly so individual retries cannot continually reset the overall observation budget. Bound remote status reads, SSH commands, subprocess waits, and evidence retrieval.

After installation completes, a confirmed persistent account or permission defect should produce a specific failure rather than consume the entire fleet observation window. Continue safe, independent work and evidence collection for other guests when appropriate, while preserving the fleet’s failing result.

Differentiate deployment failure, incomplete assessment, supervisor failure, observation timeout, and unknown remote state. Do not collapse them into one generic timeout.

Implement only the visibility needed to operate and diagnose the pipeline. No new dashboard or monitoring platform is required.

## 7. Shorten the feedback loop without weakening validation

Use existing immutable candidates when a change affects only controller logic, inventory, test execution, observation, or reporting and does not alter installation inputs.

Rebuild affected candidates when Forge content, unattended configuration, account creation, hardening, or other installed content changes. Do not rebuild unrelated OS candidates without a dependency reason.

Confirm what the retry generation actually invalidates. A newer retry identifier alone does not prove that corrected installation content was regenerated or used.

Check identity across the whole path:

Source media → Forge revision → candidate hash → installation inputs → actual guest → test plan → evidence.

The report mentions public-key injection into installation media. Determine whether that operation changes the ISO after its candidate hash is recorded. If it does, record the actual tested media hash and transformation, and prevent an untested original ISO from being qualified under evidence for different bytes. If credentials are supplied separately, record that relationship accurately without exposing secrets.

Retain the distinction between candidate SVD and observed installed software. Installation-time changes must not be hidden merely because candidate and release filenames differ.

Once readiness works, measure installation, SSH, Ansible, scanning, aggregation, and transfer times. Tune concurrency against observed CPU, memory, storage, and scanner constraints. Do not assume maximum concurrency gives minimum runtime, and do not promise an unmeasured speedup.

## 8. Complete evidence and terminal-state handling

Every expected guest must have a result. Failed, blocked, missing, and unverified outcomes must remain visible. Zero failures among an incomplete set is not success.

Preserve a clear failure chain: the original operation failure, any later evidence-collection issue, and cleanup outcome. Cleanup must not replace the primary error or turn a failed job green.

Before removing guests, collect and verify the relevant diagnostics and result files in persistent storage on the automation control node. Evidence existing only inside an ephemeral runner pod is insufficient.

Once the run is understood and evidence is secured, clean up its positively identified resources. If a guest must be retained for diagnosis, explicitly record ownership, reason, and resource cost. Do not preserve an abandoned fleet indefinitely or delete a fleet merely because the CI observer timed out.

Verify that the fleet receipt matches the original plan, candidates, run identity, expected guests, and actual results. Confirm that the remote supervisor persists its terminal outcome and the controller retrieves and interprets it correctly.

If result aggregation is broken, repair aggregation. Do not compensate by changing successful guests or falsifying completion records.

## 9. Distinguish readiness, acceptance, and qualification

Use these milestones accurately:

Guest readiness proven: All 13 planned guests from the intended installation inputs reach authenticated SSH and Ansible readiness using the required identity and key pair.

Functional acceptance proven: The full required catalog completes for every planned guest; expected results are accounted for; the fleet receipt validates; the supervisor and controller report consistent terminal outcomes.

Full qualification proven: Required functional tests, software-version checks, Evaluate-STIG, Nessus, evidence integrity, and approved release policy are satisfied for the exact candidate being promoted.

After functional acceptance passes, continue through the existing assessment implementation. Verify actual scanner execution and preserve native results and readable findings summaries. PowerShell availability alone is not proof of Evaluate-STIG execution, and scanner completion alone is not proof that findings satisfy release policy.

If a supported scanner dependency remains unavailable, report it as a specific independent blocker. Do not pretend earlier provisioning success depends on resolving it, and do not bypass approved package controls.

The STIG and Nessus findings acceptance rules have not been confirmed in this conversation. Inspect the authoritative repository/work policy. Do not invent thresholds. If policy remains undefined, complete collection and report qualification pending policy without undoing successful development or functional acceptance.

Apply the final release naming convention and allow customer publication only when actual qualification requirements are met. Publish the same tested ISO bytes, with verified hashes and supporting documentation. Never modify a qualified ISO without new validation.

## 10. Verification and completion report

Run the relevant repository checks and focused regressions after changes. Exercise real runtime paths where required. Separate unit-test success, simulated checks, actual guest execution, and unexecuted tests.

Demonstrate that a required failure or missing result remains nonzero and prevents acceptance. Use regression tests or an isolated disposable negative case rather than deliberately damaging an otherwise successful full fleet.

Keep the detailed internal report, logs, identifiers, and evidence inside the authorized work environment. Produce a concise sanitized update for independent review using generic roles and guest labels.

The sanitized update must state:

* Current attempt state and whether its result was actually inspected.
* Expected, created, installed, SSH-ready, Ansible-ready, and functionally completed guest counts.
* Which of the Ubuntu and RHEL repairs were verified through fresh installation.
* The first remaining failure, supporting evidence, and confidence level.
* Changes made and the tests that verified each change.
* Time spent installing, waiting for readiness, testing, assessing, collecting evidence, and cleaning up.
* Supervisor/receipt status, resources still active, and qualification eligibility.
* One next action or the exact external blocker.

Remove real hostnames, addresses, account names, internal URLs, sensitive paths, credentials, and proprietary code from the external summary. Use consistent generic identifiers without destroying the relationships needed to understand the problem. Do not upload private source or raw logs to the public Wormhole repository.

Do not report an attempt as green until its actual artifacts support that conclusion. Do not call unverified code a completed fix.

## Start now

Inspect the current post-repair acceptance attempt before changing anything.

If it is successful, verify the evidence and advance through the existing remaining stages. If it failed, repair the first confirmed defect and prove the correction. If it remains active, inspect its actual progress before deciding whether intervention is warranted. If its state cannot be established, preserve it and resolve that uncertainty rather than creating another unknown run.

The goal is a reliable, fast Linux qualification pipeline, not another layer of approvals, another timeout increase, or another architecture document.
