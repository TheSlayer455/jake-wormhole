# External integration: start here

Luna and other engineering agents can use Wormhole's proven container reference and the separately tracked [home ISO extension](../handoff/ISO-FOUNDATION.md). Start with the [proven solution index](../handoff/solutions/README.md); only entries with actual evidence are listed. The [source repository](https://github.com/TheSlayer455/jake-wormhole) is intentionally public; credentials, Terraform state, runtime inputs and raw logs remain private. Public access supplies neither runtime credentials nor authority to change another environment.

Container runtime acceptance is established at the sources in the current checkpoint. The real-ISO extension is incomplete. Start with the modules below, adapt only what fits the receiving pipeline, and measure that pipeline's actual critical path. Container reference results do not establish production ISO eligibility, which remains false in Wormhole. For external mappings use only **rhel kvm host** and **ansible control node**; home Ubuntu-host results do not prove RHEL-host or work-runner compatibility.

## Capability boundary

| Area | Demonstrated in Wormhole | Not demonstrated by Wormhole |
| --- | --- | --- |
| Provisioning | Terraform-managed Docker targets; one candidate-bound Ubuntu/UBI target per reference run; 20 coexisting stock Ubuntu targets with task forks four | Terraform/libvirt VMs; RHEL/KVM installation and boot; customized ISO installation |
| Validation | Container SSH, Ansible checks, Ubuntu/UBI native software inventories, synthetic assessment processing | Real Evaluate-STIG or Nessus execution; operating-system compliance; production ISO qualification |
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
