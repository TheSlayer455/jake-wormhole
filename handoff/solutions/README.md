# Proven solution index

Only completed experiments appear here. The [ISO extension checkpoint](../ISO-FOUNDATION.md)
tracks pending installation, hardening, assessment and publication work.

| Solution | Actual evidence | Boundary |
| --- | --- | --- |
| [RHEL 10.0 installation and readiness](rhel10-install-baseline.md) | Real failed marker-traversal case, corrected fresh BIOS install, final SSH/Ansible, 413 RPM records, all 948 native vendor-draft outcomes and cleanup | 32 GiB lab disk; no hardening, encryption, FIPS, released-DISA alignment or ISO qualification |
| [Ubuntu PAM revocation and final acceptance pair](ubuntu-pam-crl.md) | Native crash/control-flow reproduction, two same-ISO encrypted installs with 40/40 checks each, matching inventories and 210 pass/one FIPS failure | Pro/USG/FIPS, physical-token assurance and accountable trust-root disposition remain pending; no qualified publication |
| [Storage lifecycle](../../docs/STORAGE.md) | Real cleanup/interruption recovery, active-VM refusal, retained hashes and fresh 34/34 Ubuntu acceptance | Shared home filesystem; protected retention can block admission; no qualification waiver |
| [Streaming ISO reconstruction](streaming-iso.md) | Real 2.14 GB official Ubuntu media; controlled interruption/resume; exact hash match | Local Linux artifact store, not GitLab or installed-OS acceptance |
| [Ubuntu ISO and VM baseline](ubuntu-vm-baseline.md) | Fresh 8 GiB KVM installation, final dotted account, trusted SSH, real Ansible, native inventory and exact-owned cleanup | Ubuntu-host BIOS baseline; no hardening, RHEL installation or assessment claim |
| [Ubuntu native audit and finalization](ubuntu-real-assessment.md) | Fresh scanner-equipped install, final reboot, trusted SSH/Ansible, real OpenSCAP XCCDF/ARF/HTML and all 639 rule outcomes; real pending-publication refusal | CaC V2R7 alternative; USG/FIPS/manual requirements pending; no qualified release |
| [Ubuntu installation hardening and sandbox](ubuntu-install-hardening.md) | Two fresh same-ISO encrypted installations, 34/34 checks each, real logging/time/CA/CRL/OCSP, cold-start/refusal/offline proof, 208 native passes/three failures and cleanup | BIOS home experiment; entitlement, physical/government assurance, content and qualified publication remain pending |

Existing [container runtime acceptance](../RUNTIME-ACCEPTANCE.md) remains a
separate proven regression layer. Do not relabel its simulated installer failures
as real VM experiments or its synthetic assessments as scanner evidence.
