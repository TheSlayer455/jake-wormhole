# External integration: start here

**Immediate Luna handoff: [completed-directory intake into existing acceptance](../handoff/solutions/directory-intake.md).**
Validate team-delivered ISO bytes using their declared installation contract;
the private build/Forge contract is needed for later source builds, not this
intake path. Completion, immutable identity, required tests, scanner rights and
release policy still need authoritative definitions in the receiving environment.
Keep [Terraform and observable execution](../handoff/solutions/lifecycle-comparison.md).
The same-candidate native experiment passed, but did not justify replacing the
existing lifecycle. Adapt the acknowledged run identity, observed progress,
separate final-account/readiness checks and exact stopped-run recovery. Verify
one guest from the actual **ansible control node** against the **rhel kvm host**;
keep the receiving pipeline's hardening, scanners, tests and release policy.
This is an actionable home control case, not a diagnosis of an uninspected work run.

## Apply the research to existing code

Keep approved build behavior, Terraform and Ansible. Resolve the receiving team's
actual source/media/engine/dependency contract before automating source builds;
verify installed scanner support and licensed automation separately. Neither fact
can be established from this public reference. GitLab/RKE2 integration here is
illustrative, not evidence of execution in a private runner.

Wormhole's container readiness already uses Ansible tree results; validation and
inventory use structured callbacks with complete-result checks. The VM helper
has three ad-hoc calls, not a substantial terminal-output parser to delete.
Runner therefore remains an optional replacement experiment, not a new dependency
or an additional layer around those callbacks. An actual trial must retain strict
host trust, the frozen result grid and four outcomes: healthy, unreachable, failed
requirement and cancelled. No Runner runtime result is claimed here.

For a trial, inspect [Runner 2.4.3 configuration](https://github.com/ansible/ansible-runner/blob/2.4.3/src/ansible_runner/config/_base.py)
and [execution](https://github.com/ansible/ansible-runner/blob/2.4.3/src/ansible_runner/runner.py),
not only its high-level API: explicitly enable host-key checking, bound pexpect
and job timeouts, retain command/environment artifacts privately, and verify
remote state after cancellation. Runner process success cannot replace required
event/result coverage or a qualification decision.

Existing lost-controller admission/recovery and partial-publication tests remain
useful evidence. There is no mutable current-release pointer to race today.
Exact-revision queued builds and new component-to-test mapping are separate,
unimplemented integration increments; source-drift refusal is not proof that a
request for A builds A after main advances. Do not add a scheduler, pointer or
plugin framework merely to create another test case.

## Current implementation evidence

The [Ubuntu helper correction](https://github.com/TheSlayer455/jake-wormhole/blob/e8fdaa62b831eef071daa6eedff3bd808a196e96/wormhole/ubuntu_runtime.py)
and [generated-helper regression](https://github.com/TheSlayer455/jake-wormhole/blob/e8fdaa62b831eef071daa6eedff3bd808a196e96/tests/test_ubuntu_helper.py)
restore password-required Ansible access after the readiness split. One fresh
encrypted Ubuntu installation passed 40/40 functional checks with real assessment
and cleanup; qualification remains pending. See [current evidence](STATE.md).

The [prospective Ubuntu policy correction](UBUNTU-LAB-POLICY.md) removes the stale
physical-hardware owner dependency and assigns lab trust review to Codex. Only
legitimate Pro entitlement is currently identified as required owner input;
actual FIPS/USG execution, content reconciliation and trust review remain work.

RHEL 10.0 is newly active: [installation baseline and readiness defect](../handoff/solutions/rhel10-install-baseline.md).
The first real install exposed inaccessible completion evidence despite working
diagnostic SSH. The corrected fresh retry passed normal final SSH/Ansible, RPM
inventory and complete native vendor-draft audit. It remains an unqualified
installation baseline with security findings, not a hardened release.

Current Ubuntu result: [source-pinned PAM solution](../handoff/solutions/ubuntu-pam-crl.md).
Two fresh encrypted installations passed 40/40 checks each with matching native
results and inventories. The repaired OpenSSL/CRL path and quiet PAM conversation
are proven; qualification remains pending the exact external inputs listed there.

[Storage lifecycle](STORAGE.md) provides shared-lock cleanup, verified ISO
retention and projected disk admission; [current state](STATE.md) pins actual
execution. Adapt only relevant behavior to the **rhel kvm host** and **ansible
control node**. Home results do not prove work compatibility or authorize deleting
unresolved/qualified artifacts.

Luna and other engineering agents can use Wormhole's proven container reference and the separately tracked [home ISO extension](../handoff/ISO-FOUNDATION.md). Start with the [proven solution index](../handoff/solutions/README.md); only entries with actual evidence are listed. The [source repository](https://github.com/TheSlayer455/jake-wormhole) is intentionally public; credentials, Terraform state, runtime inputs and raw logs remain private. Public access supplies neither runtime credentials nor authority to change another environment.

Container runtime acceptance is established at the sources in the current checkpoint. The real-ISO extension is incomplete; Ubuntu qualification and the newly activated RHEL 10 baseline have separate evidence. A [real Ubuntu stock audit](../handoff/solutions/ubuntu-real-assessment.md) completed with full rule accounting, while USG/FIPS and manual/external-control requirements remain pending. Start with the modules below, adapt only what fits the receiving pipeline, and measure its actual critical path. Production ISO eligibility remains false. For external mappings use only **rhel kvm host** and **ansible control node**; home Ubuntu-host results do not prove RHEL-host or work-runner compatibility.

## Capability boundary

| Area | Demonstrated in Wormhole | Not demonstrated by Wormhole |
| --- | --- | --- |
| Provisioning | Terraform-managed Docker targets; candidate-bound Ubuntu/UBI; 20 coexisting stock targets; two fresh hardened Ubuntu 22.04.5 BIOS installations of the same ISO bytes and declared seed template; RHEL 10.0 BIOS baseline with final SSH/Ansible and complete native audit | Hardened RHEL qualification, UEFI/Secure Boot, work-host compatibility |
| Validation | Real Ubuntu final SSH/Ansible, two encrypted installs with 40/40 checks, six native PAM cases, isolated service/PKI integration, cold-start unlock and native OpenSCAP/CaC V2R7 reports with all 639 outcomes | Zero-finding security acceptance, USG V2R8 equivalence, FIPS evidence, physical-token/government-PKI assurance, production ISO qualification |
| Delivery | Source-bound reference qualification and exact-tested-byte private filesystem publication | Proprietary GitLab integration; actual GitLab runner execution; customer portal or remote artifact publication |

The [verification report](../handoff/MERGED-VERIFICATION.md) binds the latest recorded 43-check Ubuntu reference run to `c3d440a3` and the earlier twenty-target qualification to `825a594`. These are different operations, not a scaling benchmark. See [fidelity limits](FIDELITY.md) for details. Wormhole is a reference implementation; production adapters and production evidence are separate work.

## Source and fixture map

Use the Test file column with `python -B -m unittest discover -s tests -p TEST_FILE -v`; for example, `python -B -m unittest discover -s tests -p test_chunks.py -v`. Discovery also makes sibling test imports available.

| Capability | Actual implementation and reusable contract | Test file |
| --- | --- | --- |
| Chunk integrity | [chunks.py](../wormhole/chunks.py): ordered sizes/hashes and verified reconstruction; current generated local/loopback fixtures are bounded to 8 MiB | `test_chunks.py` |
| Candidate identity | [candidate.py](../wormhole/candidate.py): bind content, manifest and image identity | `test_candidate.py` |
| Terraform lifecycle | [provisioning.py](../wormhole/provisioning.py), [runtime.py](../provisioning/runtime.py): saved plans and exact-owned Docker resources | `test_provisioning.py` |
| Target readiness | [readiness.py](../wormhole/readiness.py): explicit states, bounded deadlines and failure attribution | `test_readiness.py` |
| SSH and Ansible | [readiness/runtime.py](../readiness/runtime.py): pinned host keys, fixed SSH policy and structured Ansible results | `test_readiness.py` |
| Software Version Description | [software_inventory.py](../wormhole/software_inventory.py), [observed_svd.py](../wormhole/observed_svd.py): complete native versions/architectures, separate execution provenance and shared-kernel scope | `test_software_inventory.py` |
| Assessment evidence | [assessments.py](../wormhole/assessments.py): process explicitly synthetic findings and applicability | `test_assessments.py` |
| Real Ubuntu assessment | [ubuntu_runtime.py](../wormhole/ubuntu_runtime.py), [ubuntu_assessment.py](../wormhole/ubuntu_assessment.py): native result/identity/coverage validation; [proven hardening](../handoff/solutions/ubuntu-install-hardening.md) | `test_ubuntu_*.py` |
| RHEL 10 baseline | [rhel_inputs.py](../wormhole/rhel_inputs.py), [rhel_assessment.py](../wormhole/rhel_assessment.py): BIOS DVD replay, separate seed and pinned vendor-draft native accounting; fresh runtime verified | `test_vm_foundation.py` |
| Encrypted sandbox | [ubuntu_encryption.py](../wormhole/ubuntu_encryption.py), [ubuntu_sandbox.py](../wormhole/ubuntu_sandbox.py): controlled console unlock, offline disk proof, isolated services and durable archive readback; [actual failed transfer](../handoff/solutions/ubuntu-audit-transfer-reproduction.json) | `test_ubuntu_encryption.py`, `test_ubuntu_sandbox.py` |
| Result aggregation | [pipeline_records.py](../wormhole/pipeline_records.py), [pipeline_replay.py](../wormhole/pipeline_replay.py): complete check grids, JSON/text/JUnit and original-capture replay | `test_pipeline_records.py` |
| Reference qualification | [pipeline.py](../wormhole/pipeline.py), [reference_acceptance.py](../wormhole/reference_acceptance.py): candidate-bound checks and limited reference gate | `test_reference_acceptance.py` |
| Publication integrity | [publication.py](../wormhole/publication.py): copy tested bytes, verify the closed file set and commit completion last | `test_publication.py` |
| Cleanup and recovery | [recovery.py](../wormhole/recovery.py): exact resource identity, original-source proof and refusal of unknown outcomes | `test_recovery.py` |

These tests use disposable fixtures; Docker/SSH/Terraform interactions are mocked. Some tests use bounded local processes, filesystem operations or loopback sockets. Passing them does not prove a live external integration.

## Verify locally, then choose one integration

Use CPython **3.12.14**, Git and a full-history checkout. No pip installation, homelab credentials or Docker daemon is needed for these source checks:

```text
python -B scripts/verify_repository.py
python -B scripts/verify_acceptance_matrix.py
python -B -m unittest discover -s tests -v
```

Keep platform/privilege skips explicit. The acceptance-matrix check validates historical evidence and attribution; it does not rerun those homelab experiments. Resource-allocating commands in the [CLI guide](CLI.md) require a separately authorized environment.

Next, map one measured bottleneck to a module above. Define the receiving adapter, unchanged correctness checks, before/after timing and rollback. Preserve exact-owned cleanup and real failure propagation. Use the [ISO pipeline prompt](../handoff/JAKE-ISO-PIPELINE-PROMPT.md) for a complete handoff, [architecture](ARCHITECTURE.md) for execution boundaries, and [CI parity](CI-PARITY.md) for safe manual/CI evidence. Read [current handoff](../handoff/CURRENT.md) only when continuing Wormhole development; its milestone history is not a prerequisite for external reuse.
