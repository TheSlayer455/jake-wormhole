# Proven solution index

Only completed experiments appear here. The [ISO extension checkpoint](../ISO-FOUNDATION.md)
tracks pending installation, hardening, assessment and publication work.

| Solution | Actual evidence | Boundary |
| --- | --- | --- |
| [Streaming ISO reconstruction](streaming-iso.md) | Real 2.14 GB official Ubuntu media; controlled interruption/resume; exact hash match | Local Linux artifact store, not GitLab or installed-OS acceptance |
| [Ubuntu ISO and VM baseline](ubuntu-vm-baseline.md) | Fresh 8 GiB KVM installation, final dotted account, trusted SSH, real Ansible, native inventory and exact-owned cleanup | Ubuntu-host BIOS baseline; no hardening, RHEL installation or assessment claim |

Existing [container runtime acceptance](../RUNTIME-ACCEPTANCE.md) remains a
separate proven regression layer. Do not relabel its simulated installer failures
as real VM experiments or its synthetic assessments as scanner evidence.
