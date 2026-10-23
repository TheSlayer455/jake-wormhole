# Discovery baseline

Reviewed October 23, 2026 from local Git history and privately retained discovery
artifacts. This note records observations, not a live-health guarantee or capacity
approval. It contains no credentials, host filesystem paths or raw command logs.
See [README](../README.md), [agent instructions](../AGENTS.md) and
[current handoff](../handoff/CURRENT.md) for continuation.

## Repository

The intended GitHub owner was verified as `TheSlayer455`. The private repository
is [TheSlayer455/jake-wormhole](https://github.com/TheSlayer455/jake-wormhole),
repository ID `1431014094`, with default branch `main`.

Local baseline history contains:

| Commit | Scope |
| --- | --- |
| `7e715be454d57a4b61129bd42f4b2758d8d7b060` | Initial repository baseline and explicit no-pipeline README |
| `ca6c203d47c98ce4232e0368b87ccdddc51c2cd0` | Scoped root engineering instructions |

These identifiers do not establish publication of later commits. Package/image
privacy, release controls, branch protection and CI execution are not verified by
the repository privacy flag. Existing unrelated worktrees must not be repurposed.

## Saved resource observation

The private resource snapshot reports:

| Observation | Value |
| --- | --- |
| Host-reported total memory | 29,161,349,120 bytes |
| Available memory at capture | 20,224,294,912 bytes |
| Swap total / free | 14,580,670,464 / 13,663,428,608 bytes |
| Observed application-storage total / free | 527,278,800,896 / 213,149,679,616 bytes |
| Docker server | 29.6.0 |
| Docker-reported CPUs | 16 |
| Docker containers / running | 54 / 51 |
| Cgroup version | 2 |
| Host executable discovery | Docker, Python 3 and SSH found; Terraform and Ansible not found |

The snapshot gives no Python/SSH version or Docker storage-driver value. It does
not establish image availability, package-source connectivity, K3s health,
provisioner behavior, enforceable project limits or spare capacity during a run.
Refresh relevant observations before resource admission. No target count or
initial budget is accepted as measured capacity from these numbers alone.

## Provenance and limits

The following artifacts remain in the private intake, outside this repository.
Hashes identify their complete contents; raw identities, paths and logs are not
copied here. Times below are artifact last-write metadata, not embedded capture
timestamps.

| Artifact | Last written UTC | SHA-256 |
| --- | --- | --- |
| `repository-verified.json` | 2026-10-23 12:24:03 | `62de6779510149fc42869120821f702f9159b7dd627ed900f9c1b262560094a1` |
| `implementation-resource-discovery.json` | 2026-10-23 12:22:59 | `d946bb4ec2c8b66da728635a72ee9201025ea0f2716b423705cdd32946ef0943` |

This baseline performs no installation, target provisioning, SSH/Ansible target
validation, scanner integration or workload fault injection. There is no working
Wormhole application yet. Tool/version selection, isolated runtime design and
execution proof belong to the relevant Minx contracts. Approval and claim status
must be retrieved from Minx rather than inferred from this snapshot or an older
intake authorization record.
