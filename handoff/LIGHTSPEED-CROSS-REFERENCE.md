# Luna: compare the verified reference with the actual Linux ISO pipeline

Copy this entire prompt into the authorized engineering session. This is a
failure-first comparison assignment, not authorization to transfer private source
or operate infrastructure outside that session's existing permissions.

## Inputs and objective

Public reference repository: https://github.com/TheSlayer455/jake-wormhole

Read [WORMHOLE-SANITIZED-REFERENCE.md](WORMHOLE-SANITIZED-REFERENCE.md) from the
same immutable public revision as this prompt. Resolve and record that public
revision; inspect the reference's pinned implementation, tests and evidence
checkpoints. Distinguish its public baseline from each actual runtime revision.
Reconcile newer claims against their own evidence. If an identity record is
archived, retrieve and verify it before using it to establish repeatability.

Inside the authorized work environment, inspect the actual Jake Lightspeed
repository, original Jake ISO team repositories, integration engine, Bash build
scripts, configuration, GitLab CI definitions and available runtime evidence.
These private sources stay there. Wormhole must not acquire access to them.
If an input is inaccessible, name its functional role and the missing observation;
do not invent its contents, resource identity, path, supported OS or fleet size.

Find the earliest confirmed boundary preventing one complete Linux installation
and validation attempt. Compare equivalent responsibilities, not matching filenames.
Identify a missing, duplicated or different mechanism only when inspected evidence
supports it. A successful generic Wormhole installation does not prove a proprietary
image installs, satisfies team intent or meets the work release policy.

## Reconcile the current attempt first

1. Identify one current attempt internally. Correlate its source, exact candidate,
   installation inputs, plan, controller, guests, progress and original evidence.
2. Classify it as running with progress, running without observed progress,
   terminal-successful, terminal-failed, confirmed cancelled, or unknown. Separate
   observer state, remote process state, guest state and the durable terminal result.
3. If active or uncertain, inspect read-only using bounded checks. A CI timeout,
   missing launch acknowledgment, stale status file or existing process alone does
   not establish the guest's outcome. Reconcile ownership before another runtime
   operation. Do not launch a competing retry, edit consumed inputs or delete
   uncertain resources merely to prepare this comparison.
4. Preserve the first failure and later collection/cleanup failures separately.
   Keep raw logs, exact private identifiers and their evidence mapping internally.
   Use report-local evidence labels in the portable response.

This assignment requests a diagnosis and minimal repair recommendation. Execute a
repair or experiment only within the existing authorized engineering scope, after
active-run reconciliation. Do not manufacture a completed repair from a proposal.

## Preserve the intended ISO and installation contract

Determine which path is being tested:

| Path | Contract to preserve |
| --- | --- |
| Original completed ISO | Verify delivery completion and exact bytes; use only its supported installation inputs. A filename or quiet copy interval alone is insufficient. |
| Approved source build | Original team Bash scripts, configuration and integration engine define intended customization. Resolve actual media, engine and effective dependencies before building. |
| Explicitly instrumented derivative | Record the transformation and new identity internally. Evidence for the derivative cannot automatically qualify the original ISO. |

A missing source-build contract does not block validation of a completed ISO
whose installation contract is known. Conversely, a separate seed must not
override team customization or introduce untracked remediation. If installation
is legitimately interactive, failure of an unsupported unattended recipe is not
proof that the original ISO is defective. A diagnostic manual guest repair is
not fresh-installation acceptance. Fold required installed changes into approved
inputs, then test a new attributable installation.

Preserve each OS's final account, privilege-escalation, security and reboot
requirements. Do not copy the reference's simpler baseline policy over a hardened
contract. Do not disable host trust, authentication, guest security enforcement,
required tests or resource ownership to achieve a passing run.

## Compare the lifecycle, failure first

Trace these boundaries in order; stop causal diagnosis at the earliest confirmed
failure while listing downstream stages as blocked or unproven:

1. Correct completed ISO and installation-input identity, freshness and attachment.
2. Actual firmware/ISO boot entry and available installer runtime/source.
3. Installation onto the intended fresh target disk.
4. Final configuration, required hardening, installed-disk boot and reboot.
5. Intended final account and its usable home, key and access policy.
6. Trusted SSH identity and actual authentication from the designated controller.
7. Required interpreter, privilege escalation and a real Ansible operation.
8. Complete declared functional validation and observed installed inventory/SVD.
9. Persisted, attributable expected results and consistent terminal outcome.
10. Evidence preservation, exact-owned teardown and reconciled resources.

Identity observation and authentication may be combined by the actual transport;
never weaken trust to force the ordering above. Port-open, installer SSH and an
administrator-shell connection are not final-system controller readiness.
Inspect whether readiness itself is defective before blaming installation or
Terraform. An inaccessible completion marker can fail readiness after valid SSH.

Do not implement downstream scanner integration, release automation or another OS
profile while the basic guest lifecycle remains unproven. Inventory existing
scanner/policy constraints without turning them into speculative causes of an
earlier failure. Distinguish assessment execution, coverage, acceptable findings,
qualification and publication. OpenSCAP cannot establish Evaluate-STIG, USG/FIPS
or Nessus execution. Verify actual supported/licensed interfaces internally.

Use this matrix in the response. Include material differences and necessary
matching controls; do not enumerate unrelated feature parity:

| Lifecycle stage | Wormhole mechanism | Wormhole evidence | Lightspeed mechanism | Lightspeed evidence | Difference | Failure relevance | Recommended action | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| One observed boundary per row | Verified functional method | Public pinned source and evidence category | Actual equivalent, or unknown | Report-local label and observed evidence type/outcome | Specific mismatch or none | Confirmed cause, supported hypothesis, unrelated, or unknown | Keep, adapt, replace, or investigate | Proven, probable, or unknown |

"Proven" requires direct observations establishing the stated conclusion;
"probable" is a supported but untested explanation; "unknown" lacks sufficient
evidence. A code difference alone does not prove causality. Keep a private mapping
from report-local evidence labels to the actual attempt and records. Do not include
that mapping, private commits, digests, timestamps or identifiers in the report.

For each proposed replacement, name the contract it preserves, the smallest owning
component to change, the actual failing observation it addresses, the focused
regression, one real installation test and rollback/recovery conditions. Keep
working Terraform and structured Ansible paths unless a measured comparison
establishes a simpler reliable replacement. No new scheduler, wrapper hierarchy,
authentication subsystem or parallel ownership mechanism for hypothetical needs.

Account for real transfer constraints: lab versus work host OS, firmware, remote
runner-to-hypervisor-to-guest routing, permissions, installation seeds, approved
packages, scanner entitlement, durable storage and release policy. Generalize
these constraints in the report; do not export their topology or configuration.

## Portable response: construct from safe facts only

Write new prose from this explicit allowlist: public technology/OS versions,
generalized lifecycle mechanisms, nonidentifying counts, rounded elapsed durations,
observed outcomes, evidence categories, public Wormhole source references,
confidence, contract-preserving actions and generalized unresolved dependencies.
Use only functional roles such as **ansible control node**, **rhel kvm host**,
**source repository**, **ISO integration engine**, **package repository server**,
**artifact storage** and **validation controller**. Use report-local Guest A or
Attempt A only where needed; do not derive labels from private identifiers.

Do not paste restricted material and then redact it. Exclude real hostnames,
addresses, domains, internal URLs/repository names, usernames, account identities,
personal information, private paths, credentials, certificate/key material or
fingerprints, private job/run/commit IDs, media hashes, proprietary package lists,
configuration values, source excerpts, commands, diffs, screenshots and raw logs.
Public Wormhole file/commit/PR references are the only link/identifier exception.
Describe a restricted detail's mechanism and diagnostic limitation in ordinary
language rather than dropping the finding. Do not invent substitute identifiers.

Return these sections, with the comparison matrix under C:

- **A. Executive finding:** primary blocker category: ISO build/media construction,
  installer configuration, VM provisioning, guest readiness, remote orchestration,
  evidence handling, or unknown. State the inspected attempt's current state.
- **B. First confirmed failing boundary:** expected transition, actual observation,
  evidence label/type, cause or unresolved hypothesis, and confidence.
- **C. Wormhole comparison:** matrix, corresponding actual proof and limits of
  transfer. Separate source tests, simulated faults and real installations.
- **D. Minimal repair:** smallest correction and preserved contracts. Clearly label
  proposed, implemented, source-tested and runtime-proven work.
- **E. Acceptance proof:** test from the real work controller through a fresh
  installed system, expected results/failure behavior, complete terminal evidence
  and exact-owned cleanup. Include a bounded negative test where relevant.
- **F. Simplification opportunities:** only demonstrated safe consolidation;
  otherwise say none established. State what can be removed after replacement proof.
- **G. Remaining blockers:** downstream unproven stages separately from confirmed
  defects; one next action or exact generalized external dependency.
- **H. Sanitization result:** actual review performed and remaining limitations.
  Confirm absence of prohibited material only after reviewing the complete output.

Review headings, tables and links as well as prose. Obtain an independent review
of the portable report before sharing when available; otherwise label self-review
and leave external sharing pending the normal authorized review process. Pattern
checks alone never certify sanitization or permission to disclose. Keep supporting
evidence private. Return the sanitized report only; do not automatically upload it,
modify Wormhole, contact another agent or transfer work data to an external service.
