# Architecture

WORM-002 establishes the repository baseline. WORM-003 adds a standard-library
Python CLI and isolated local fixture runs, bounded fixed stage adapters and six
versioned artifact contracts. There is no Terraform configuration, target image,
Ansible playbook or complete runtime pipeline yet. Minx owns requirements,
assignment and review. The [owner-delegated workflow decision](decisions/0002-owner-delegated-workflow.md)
describes authorized browser operations without changing Minx permissions.

Start with [README](../README.md), [agent instructions](../AGENTS.md) and the
[current handoff](../handoff/CURRENT.md). See [discovery](DISCOVERY.md),
[fidelity](FIDELITY.md) and [decision 0001](decisions/0001-container-reference.md).

## Implemented local foundation

The `wormhole` package is invoked as `python -m wormhole`. Its CLI calls the same
run, contract and stage library exercised by tests. Run directories use UUIDs,
explicit ownership markers and separate private/runtime and portable-evidence
locations outside Git and vault paths. Atomic bounded JSON writes, symlink and
junction refusal, per-run locks and fixed subprocess adapters protect this local
path. They are not a Docker admission mechanism; shared resource admission is
WORM-004.

The synthetic fixture runs actual fixed local subprocesses for preflight and
SHA256 checking. Declared real pipeline stages remain unsupported. Reports and
verification cannot convert that subset into runtime or publication eligibility.
See [CLI behavior](CLI.md) and the selected [dependency lock](../dependencies.lock.json).

## Planned runtime components

| Component | Responsibility | Boundary |
| --- | --- | --- |
| Python CLI and library | Invoke reusable bounded stages and produce structured results | One code path for manual and CI execution; no resident service or agent scheduler |
| Trusted provisioner | Run pinned Terraform with the Docker provider | Own Docker control; keep private key contents out of Terraform configuration, state and plans |
| Validation helper | SSH, Ansible, collection and reporting | Run on the run network without Docker control |
| Target containers | Exercise known payloads and package inventories | Minimal privilege; no host networking/PID namespace, privileged mode or Docker socket |
| Evidence and gate | Check completeness, identity and reference eligibility | No production ISO approval; no automatic repair during validation |
| Reference publisher | Publish the already tested bytes after rechecking evidence | Separate operation, unique destination and final completion manifest |

Runtime dependencies and image versions remain unselected. Future implementation must pin
mutually compatible versions and check their actual documentation. The observed
host has no Terraform or Ansible executable in its discovered tool paths; this
baseline does not install either. No dashboard, Kubernetes deployment, database,
broker or inference provider is needed.

## Planned run contracts

The intended sequence is preflight, source integrity, candidate build,
provisioning, readiness, Ansible checks, observed SVD, synthetic assessment,
evidence, gate, scoped cleanup and finalization. Publication follows separately.
Each stage declares inputs, timeout, outputs, expected checks and failure category.
Versioned JSON contracts are published under `schemas/` for these record families:

- Run manifest and plan: run identity, source commit, profile, expected targets,
  checks, predeclared applicability and resource/concurrency limits.
- Inventory and readiness: actual provisioned IDs/endpoints, trusted host-key
  references and separate process, TCP, SSH trust/authentication and Ansible states.
- Test results: expected/observed values, pass/fail/error/unreachable/skip status,
  timings and bounded sanitized evidence references.
- SVD and assessment: observed target contents, collector provenance, candidate
  and image identity, plus explicit synthetic assessment/policy labels.
- Decision and cleanup: completeness failures, reference eligibility, production
  ineligibility, primary error, owned resources and separate cleanup outcomes.

The initial schemas and validators cover current local records. Runtime candidate,
image, readiness, SVD, assessment and publication implementations remain separate
tickets; schema availability is not evidence that those operations ran. A real
run must bind candidate hash, derived image, test plan and evidence; validating an
unrelated stock image cannot validate the candidate. Text, JSON and JUnit reports
must share result records. Missing checks, unexpected skips, stale/malformed
evidence and wrong identity must not pass merely because no failures were recorded.

## Planned execution and isolation

Begin with one real target. Later profiles cover five and twenty, independently
of Ansible concurrency. A measured admission check and actual shared run lock
must account for builds, helpers, targets and host headroom before allocation.
Planning budgets are not demonstrated capacity.

Each run needs its own work directory, Terraform state, network, inventory,
authentication, known-hosts file and owned resource IDs. Private runtime material
stays outside Git and exportable evidence. A trusted provisioning channel must
establish host-key identity; disabling host verification is not a fallback.
Acceptance must use real SSH and Ansible from the validation environment.
Runtime inspection may assist diagnostics, but cannot replace that path.

Validation detects faults rather than repairing targets. Corrections require a
new attributable attempt with fresh targets. Cancellation preserves bounded
diagnostics before scoped teardown; state remains until owned infrastructure is
accounted for. Cleanup must neither affect unrelated resources nor overwrite the
primary failure.

No real scanner package or compatible Evaluate-STIG invocation is established.
Any optional PowerShell capability belongs in a separately qualified helper,
not the host. Production policy is undecided; container and synthetic evidence
must always leave production ISO eligibility false.
