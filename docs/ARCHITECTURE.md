# Architecture

The [active follow-up](FAILURE-REPRODUCTION.md) centralizes the readiness observation
contract in `execution_state.py`. Normal fleet dispatch requires complete readiness;
subset diagnostics are explicit and remain ineligible. Progress is a projection
of existing records, with a separate terminal outcome and unknown initialization
where no independent observation exists. It is not a second execution framework.

Jake Wormhole is a standard-library Python CLI/library with bounded Linux container adapters. There is no resident scheduler, dashboard, Kubernetes deployment, database, broker or model provider. [Current state](STATE.md) and [original acceptance](acceptance-matrix.md) distinguish implementation from execution.

| Boundary | Implemented responsibility |
| --- | --- |
| Run/source | UUID-owned storage outside Git/vaults, clean source identity, fixed plans, bounded atomic records and stable operation locks |
| Admission | Fresh measured capacity, canonical Linux flock, build/runtime budgets and durable exact-ID journal; recovery cannot invent allocations |
| Trusted provisioner | Pinned Terraform/provider in a separate constrained container; create stopped, inspect every PID cap before start, computed inventory and saved-plan destroy |
| Validation helper | Qualified non-root Docker-free helper, fixed read-only source-file binds, ephemeral credentials, pinned host keys, SSH/Ansible and complete aggregate events |
| Targets | Owned internal network, no host namespaces/socket/privileged mode, actual cgroups and finite lifetime; stock Ubuntu or explicitly bound UBI |
| Evidence | Original capture/hash/identity replay, mandatory grids including blocked/unverified rows, full native SVD and matching JSON/text/JUnit |
| Gate/publisher | Limited reference gate, then separate exact-tested-byte private filesystem publisher with closed file table and nonoverwriting completion protocol |

## Runtime and locking

Legacy fixture `run` executes only its labeled local preflight/SHA subset; v1 eligibility flags remain false. Separate `reference-smoke-v1` composes verified chunks, generated candidate image, admission, real Terraform/SSH/Ansible, candidate checks, native inventory, synthetic assessment, evidence, gate and cleanup. Optional PowerShell is a separate qualified variant, excluded from this combined pipeline.

Candidate-bound reference runs support one Ubuntu or UBI target. Stock scale qualification supports twenty actual Ubuntu targets in one graph, independently of Ansible forks four. This is not a twenty-target candidate publication pipeline. Five captures retain complete per-target inventories; the sampler binds all 22 owned live containers. See [bounds](TWENTY-TARGETS.md).

Outer locking order is selected Run, canonical admission, then held component operations. Held variants prevent nested reacquisition of the same Run lock. Suites use distinct child UUIDs. WORM-019 proves live coordinator overlap while allocation intervals remain serialized; it does not authorize concurrent unbudgeted graphs.

Terraform state/plans, authentication, known-hosts and raw bounded captures stay private. Recovery validates original source, current ownership, terminal records and uncertainty before exact cleanup. Unknown daemon outcomes block unsafe mutation until a specific reviewed proof resolves them; expiry never clears uncertainty. Primary errors and secondary cleanup failures remain separate. No global prune or ambiguous-prefix cleanup exists.

## Userland and provenance

Stock target/helper retain original WORM-005 build identities/pins. The provisioner uses the qualified stock target image with a separate fixed tools/runtime role; host Terraform/Ansible installation is unnecessary. Original image build SHA may differ from the controller only while exact recipe input hashes and actual immutable image identities remain verified.

UBI uses official public metadata, exact RPM hashes/signatures, retained EULA, offline dependency solve and a separate installation manifest over the same candidate bytes. Validated UBI SSH adds only documented AUDIT_WRITE to ordinary target capabilities. This permits owned authentication records in the shared kernel audit log; it provides no separate kernel, audit read/control or host policy change. See [RPM target](RPM-TARGET.md).

[Native SVD](SOFTWARE-INVENTORY.md) retains complete dpkg version/architecture and RPM NEVRA, separate virtual key headers, target/candidate/collector identity, helper/provisioner provenance and shared-kernel scope. [Assessment](ASSESSMENTS.md) is explicitly synthetic/reference-only. Scanner/STIG, VM/ISO and production claims are excluded.

## CI and handoff

Hosted source fixture CI runs the same local library/tests; historical source proof tests require full Git history. The implemented WORM-021 runner preserves seventeen synthetic component outcomes, compares source-bound semantic exports and retains safe diagnostics from deliberately failed jobs. [Merged verification](../handoff/MERGED-VERIFICATION.md) records actual manual/hosted checks at `c3d440a3`, separately from fresh container smoke and historical scale qualification. GitLab authorship/local checks are not runner execution. No persistent runner, homelab CI credentials/tunnel, external model or other-chat orchestration is needed.

See [CLI](CLI.md), [repository controls](REPOSITORY.md), [fidelity](FIDELITY.md), [original decision](decisions/0001-container-reference.md) and [handoff](../handoff/CURRENT.md). Original component contracts retain their versioned scope flags.
