# Architecture

The current bounded source now includes the one-container Ubuntu/UBI reference
pipeline and a separate [private exact-byte publisher](PUBLICATION.md). The
publisher replays original evidence under the Run lock, then uses its own stable
release-store lock, a closed file table and a final non-overwriting completion
marker. Original source/candidate/evidence identity, consumer completeness,
producer fsync acknowledgement and observed local privacy are separate facts.
See [current state](STATE.md) for actual source and qualification; the foundation
narrative below preserves earlier component decisions and may describe later
completed work as planned. Minx remains the authority for contract/review state.

WORM-002 establishes the repository baseline. WORM-003 adds a standard-library
Python CLI and isolated local fixture runs, bounded fixed stage adapters and six
versioned artifact contracts. WORM-004 adds [measured admission](ADMISSION.md),
reviewed profiles and a canonical Linux shared lock/durable journal.
WORM-005 adds [qualified Ubuntu target/helper images](IMAGES.md), per-run keys,
strict SSH qualification, actual cgroup inspection and exact owned cleanup.
WORM-006 adds the [Terraform adapter](TERRAFORM.md), fixed provisioner and bounded
acceptance operator. WORM-007 provides strict SSH/Ansible readiness; WORM-008
provides cancellation and exact-source recovery. WORM-009 adds actual read-only
SSH/Ansible functional observations with frozen checks and capture-backed results.
Their actual acceptance records are linked in the current checkpoint. Candidate
binding, multi-target execution and the complete runtime pipeline remain unfinished. Minx owns requirements,
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
path. Real Docker allocation adapters must hold the separate admission lease and
verify applied limits before starting owned resources.

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

Image dependencies are pinned in images/images.lock.json: Ubuntu24.04,
OpenSSH9.6p1, Python3.12.3 and Ansible Core2.21.5 with hash-pinned helper wheels.
Actual installation and SSH observations are in the WORM-005 evidence. Future
components must pin compatible dependencies and inspect their documentation. The observed
host has no Terraform or Ansible executable in its discovered tool paths; this
implementation does not install either on the host. No dashboard, Kubernetes deployment, database,
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

The initial schemas and validators cover current local records. Images,
Terraform, readiness, recovery and functional observations have actual one-target
acceptance. Candidate binding, SVD, assessment and publication remain separate
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
