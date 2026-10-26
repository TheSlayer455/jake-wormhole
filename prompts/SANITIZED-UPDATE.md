# Prompt 2: Reusable Sanitized Update

## Task

Inspect the latest relevant Linux pipeline attempt and produce a concise, plain-language engineering update for independent review.

This request is read-only. Do not modify code, launch a pipeline, start or stop guests, change permissions, or clean up resources just to prepare the report. Do not send or upload the report anywhere automatically.

Use inspected evidence where available. Distinguish directly observed results, earlier reported results, hypotheses, and unknowns. Do not claim a retry succeeded without checking its actual outcome and artifacts.

The report must contain no identifying infrastructure details, proprietary nomenclature, source code, commands, or raw diagnostic output.

## 1. Required role names and generic terminology

Refer to the virtualization system only as rhel kvm host.

Refer to the automation/control system only as ansible control node.

Do not mention their real hostnames, hardware models, serial numbers, or internal aliases. Do not include an original-to-generic mapping.

Use these generic terms where needed:

* Linux image pipeline
* integration engine
* stock ISO
* candidate ISO
* custom VM
* pipeline helper image
* internal package source
* final service account
* temporary bootstrap account
* remote supervisor
* customer portal

Public technology names such as RHEL, Ubuntu, GitLab, Terraform, Ansible, KVM, Podman, Buildah, Skopeo, PowerShell, Evaluate-STIG, and Nessus may be used when relevant. OS versions and nonidentifying counts may be retained.

If individual guests must be distinguished, assign report-local labels such as Guest 01 and Guest 02. Use them consistently within this report. Do not derive them from real names or expose their private mapping.

## 2. Exclude all identifying material and code

Do not include:

* Personal, organization, customer, project, product, or proprietary payload names.
* Real hostnames, domain names, addresses, subnets, network identifiers, MAC addresses, or topology details beyond the generic roles needed for diagnosis.
* Internal URLs, repository URLs, registry endpoints, links, usernames, email addresses, account names, or the exact dotted service identity.
* Real VM/resource names, job IDs, pipeline IDs, run UUIDs, ticket IDs, commit identifiers, hashes, digests, fingerprints, or identifiers copied from internal artifacts.
* Filesystem paths, exact script names, proprietary function names, variable names, environment-variable names, configuration keys, or package names that identify internal software.
* Tokens, passwords, keys, certificates, credentials, secret values, or reversible encodings of them.
* Source code, pseudocode, shell commands, diffs, configuration fragments, regular expressions, code fences, copied log lines, stack traces, screenshots, or raw tool output.
* Exact calendar dates, wall-clock timestamps, time zones, or other unnecessary identifying metadata.
* Attachments, raw evidence archives, or copied internal manifests.

Describe failure mechanisms in newly written ordinary language. For example, explain that the installer could not locate its runtime source rather than copying a console error. Explain that a final-configuration step failed before account creation rather than naming the internal script.

Report identity checks as matched, mismatched, not checked, or unknown without including the underlying value. Report tool execution exit statuses numerically when useful, but do not include the command that produced them.

Use relative elapsed times, rounded to useful seconds or minutes. Preserve diagnostic meaning, not unnecessary precision. Do not invent numbers or replace real identifiers with plausible-looking addresses or account names.

If a useful fact cannot be safely expressed, mark that detail withheld and state the diagnostic limitation at a generic level. Do not enumerate the removed values. Redaction is not a claim of formal release approval.

## 3. Inspect one attributable attempt

Identify the latest relevant attempt internally and keep its records separate from earlier attempts. Do not stitch together creation from one run, readiness from another, and tests from a third.

If comparing with an earlier attempt, label it only as the previous inspected attempt and describe the change. Keep the principal status tables tied to the current inspected attempt.

If the latest attempt is active, report the current observed state. If the result or evidence is unavailable, say unknown or not inspected. Unknown counts must not become zero.

## 4. Required report format

Aim for approximately 600 to 900 words, using compact tables and short paragraphs. Use this structure. Omit inapplicable detail rather than inventing it.

### A. Current outcome

State whether the inspected attempt is running, terminal-successful, terminal-failed, or unknown.

Summarize the first blocking boundary in one or two sentences. State separately whether functional acceptance, assessment completion, and final qualification are proven, incomplete, failed, or pending policy.

### B. Fleet progress

Provide a table by OS/profile with:

| OS/profile | Planned | Created | Installed | Final SSH ready | Ansible ready | Functional pass | Failed or blocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |

Include a total. Use the actual plan, currently expected to contain 13 guests, unless inspected evidence establishes otherwise. Separate the RHEL 10 container profile if it has distinct required checks.

Explain that these are per-stage counts and are not additive across columns. Do not equate a powered-on VM or an open port with an installed, ready system. Mark unproven stages explicitly.

### C. Candidate and installation evidence

Briefly report the following as verified, failed, or not yet established:

* Relevant installer changes are included in the current candidates.
* Fresh or valid reused candidates are attributable to the intended inputs.
* Final attached-media identity matches the guest/run evidence.
* Actual RHEL firmware/boot-entry behavior was inspected where relevant.
* Ubuntu final configuration completed.
* The installed system, rather than installer environment, was observed.
* Final service-account access and the intended key relationship work after hardening and required reboot.

Do not print hashes, keys, account names, script names, or boot configuration.

### D. First confirmed failure and remaining hypotheses

For the first failing boundary, state:

* Expected behavior.
* Actual observed behavior.
* Evidence type inspected, such as guest console, installer result, controller receipt, or functional report.
* Confirmed cause, or the specific unresolved hypothesis.
* Dependent work blocked by that failure.

Prioritize installation failures over downstream SSH symptoms. If guests are ready but reporting hangs, identify aggregation or supervisor completion as the failing boundary rather than blaming installation.

### E. Changes and verification

Summarize only material changes since the previous inspected attempt. For each, describe what changed, whether it was exercised through a fresh installation or focused regression, and the observed result.

Clearly distinguish implemented, tested, and proven in the full fleet. Record no code changes when that is the actual situation.

### F. Runtime and wasted waiting

Provide available elapsed durations for media preparation, provisioning, installation, readiness, functional tests, assessments, and evidence/cleanup. Mark unmeasured or unexecuted stages.

Identify the measured critical path. Do not sum overlapping stage durations as though they were sequential.

Explicitly state whether incomplete readiness prevented the full playbook from starting and whether a terminal supervisor result was written within the available budget.

### G. Evidence and resource disposition

State whether evidence is persisted on the ansible control node, whether the fleet receipt is complete and passing, and whether remote execution is active, stopped, terminal, or unknown.

Report counts of remaining owned guests where known. Explain whether cleanup completed, is pending evidence collection, or is blocked by uncertain ownership/state. Do not include resource names or storage paths.

State the SVD, Evaluate-STIG, Nessus, container-profile checks, qualification, and publication status without implying downstream success from an earlier-stage pass.

### H. Next action

End with one concrete next engineering action, why it follows from the evidence, and the observation that would establish success. If an external dependency is the blocker, describe it generically and identify what remains independently actionable.

## 5. Final review before returning the report

Read the generated report itself and remove identifying details that may have survived paraphrasing. Check headings, tables, captions, filenames, identifiers, and copied terminology, not only prose.

Verify that only rhel kvm host and ansible control node identify the two infrastructure roles. No real hostname or project-specific name may remain.

Verify that the report contains no source code, commands, configuration snippets, raw logs, links, exact timestamps, hashes, or secret material. Do not include a list of removed values or a private mapping.

Preserve uncertainty and actual failures. Do not turn missing evidence into success or make unverified repairs sound complete.

Return only the sanitized report. Keep supporting raw evidence inside the authorized environment. The report remains subject to the organization’s normal external-sharing process.
