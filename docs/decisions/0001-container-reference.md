# 0001: Container-only reference pipeline

Status: baseline design recorded under WORM-002; runtime qualification is pending.

## Context

Wormhole must demonstrate attributable automation on shared infrastructure without
accessing the proprietary implementation or claiming VM/ISO installation fidelity.
The repository currently contains a baseline, not an implemented pipeline. Saved
[discovery](../DISCOVERY.md) does not establish available execution capacity.

## Decision

Plan one small Python CLI/library with reusable bounded stages and versioned JSON
contracts. Use Terraform's Docker provider for real target lifecycle, a separate
SSH/Ansible helper for validation, observed-target SVD collection, synthetic
assessment fixtures and a strict reference-only gate. Pin versions when the
relevant implementation contracts select and test them; none is selected here.

Keep provisioning authority with the trusted provisioner. The validation helper
does not receive Docker control. Isolate run state, network, credentials and
evidence; enforce measured admission and a shared execution lock. Detect target
faults instead of silently repairing them during tests.

Publish only tested, identity-checked bytes through a separate operation. Preserve
private runtime material outside Git and exportable evidence. Record primary and
cleanup errors independently. Production ISO eligibility remains false.

## Consequences

The first execution proof must include one actual Terraform-created container,
trusted SSH, real Ansible, evidence and scoped cleanup. Mocks and document checks
cannot complete that proof. Five/twenty-target capacity, CI parity, PowerShell
capability and scanner compatibility require their own evidence.

No VM/KVM adapter, service platform, Kubernetes deployment, dashboard or autonomous
model orchestration is part of this baseline. Model-neutral repository context
supports later implementers and reviewers without invoking or messaging them.
Private repository visibility does not automatically establish private image or
release publication.

Revisit a consequential choice through a small follow-on decision record linked
to the current Minx requirements, source and tests. Do not erase prior failures or
treat a decision document as human requirements or deliverable acceptance.

See [architecture](../ARCHITECTURE.md), [fidelity](../FIDELITY.md),
[agent instructions](../../AGENTS.md) and [current handoff](../../handoff/CURRENT.md).
