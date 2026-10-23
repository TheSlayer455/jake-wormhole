# Fidelity and evidence limits

This is a container reference project, not a Lightspeed rewrite or a VM/ISO
installation laboratory. Read [architecture](ARCHITECTURE.md),
[discovery](DISCOVERY.md) and the [current handoff](../handoff/CURRENT.md).

## Current baseline

| Area | Established now | Not established |
| --- | --- | --- |
| Repository | Private GitHub repository, pushed baseline, passing baseline CI and separately identified Codex engineering review | Release qualification or independent human review |
| Host discovery | Saved memory, disk, Docker and executable-availability observations | Current admission capacity, enforced limits or absence of impact under load |
| CLI/stages | Local CLI, bounded stage execution and explicitly synthetic fixture subset; six published artifact contracts | A complete Terraform/SSH/Ansible runtime pipeline |
| Terraform | Docker-provider lifecycle is the planned provisioner | Installed host Terraform, authored infrastructure or a provisioned target |
| SSH | Host executable availability recorded | Per-run keys, trusted host-key establishment or successful target authentication |
| Ansible | Required future validation transport | Installed host Ansible, connectivity, checks or observed inventories |
| Source/candidate | Synthetic chunks and an attributable payload are planned | Implemented reconstruction, candidate build or validated image mapping |
| SVD | Observed-target collection is planned | A generated inventory or version-preservation result |
| Assessment | Synthetic checklist processing and reference policy are planned | Real Evaluate-STIG integration or a production acceptance threshold |
| Publication | Separate tested-byte publication is planned | A complete reference release or private package/image publication |
| CI and scale | Shared CLI, negative tests and 1/5/20 profiles are planned | Actual CI execution, parity, twenty-target capacity or recovery acceptance |

## Evidence labels for future work

Use **real execution** only for an operation actually run, with tested source
commit, inputs, environment, command/exit status and retained evidence. A fixture
is controlled test data. A simulation exercises a substitute behavior and must
name that substitution. An unavailable dependency, skipped integration or missing
measurement remains **unverified**, even when unit tests pass.

A negative acceptance harness may pass because it observes the intended failure.
The underlying run must retain its failed outcome and refusal to publish.
Self-review and independent review are different facts; name an independent
reviewer only when that review occurred against an identified commit.

## Claims Wormhole cannot make

- A container run does not demonstrate ISO installation/boot, operating-system
  STIG compliance, VM sizing or RHEL/KVM compatibility.
- An RPM derivative must keep its actual identity. Shared host-kernel observations
  are not software installed in the target userland.
- Helper/build-tool versions are execution provenance, not target packages.
- PowerShell execution does not prove Evaluate-STIG controller, transport or
  target support. No authorized scanner package or invocation is presently known.
- Processing or repacking ISO bytes would prove only that stated file operation.
  This baseline does not implement it or authorize restricted-media publication.
- Authored/linted GitLab compatibility is not a GitLab runner result. GitHub
  success cannot establish GitLab execution or manual/CI parity by itself.
- A reference gate can never turn synthetic/container evidence into production
  approval. Production ISO eligibility remains false, with explicit reasons.

Lightspeed's reported completion percentage, infrastructure problems and prior
PowerShell attempt are unverified context. No proprietary source or work system
was accessed for this baseline, and no repair to that infrastructure is claimed.
Repository creation, tested code, pushed commits, runtime results and human
acceptance must be reported separately.
