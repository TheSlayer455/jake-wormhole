# Home ISO extension checkpoint

This is an incomplete implementation increment, not an ISO qualification receipt.
Container baseline: main `d205040135c47611d821d3c1a202e2ea370284a5`, runtime
implementation `f8e5f0ef8f3764617516f5716840fcbb751589f6`. Preserve its evidence.

## Short implementation checklist

- Scope/access: authorized owner context recovered; real hardware KVM API and
  VM-creation ioctl verified. One 8 GiB / two-vCPU / 64 GiB-disk guest at a time;
  explicit BIOS assumption, no Secure Boot claim. Host preflight observed about
  20 GiB available memory and 170 GiB free project storage before media staging.
- Source media: official Ubuntu 22.04.5 amd64 ISO, signed checksum verified against
  the documented Ubuntu CD signing fingerprint. Authorized RHEL 9 DVD media and
  checksum are not yet available. Never substitute UBI or unofficial media.
- Streaming: `6e1920fffca0e0c5e6826cbc274d2d5f4851b372` split the real
  2,136,926,208-byte ISO into 32 chunks, interrupted reconstruction after its first
  committed chunk, resumed and matched the official whole-file SHA256. Split
  3.71 s / 26,144 KiB maximum RSS; resumed assembly 4.39 s / 26,656 KiB.
- VM baseline: separate journal, shared Docker lock, pinned Terraform 1.17.0 and
  libvirt provider 0.8.3; actual installed provider schema inspected. Ubuntu seed
  and ISO builder are implemented. Installation execution is being verified;
  consult the run result before starting another attempt.
- Still required: successful stock installations of both OS families; pinned
  installation-time hardening; actual supported assessment content/tooling;
  negative VM experiments; two-OS lab policy/gate; exact-byte publication and
  rejection proof; source-pinned proven solution handoffs.

## Execution and limits

The established Linux operator can execute as the canonical runtime owner.
Connection metadata stays in private engineering records. Minimal QEMU/libvirt,
xorriso and firmware packages were installed after transaction inspection, with
no package upgrades/removals. The packaged default network is inactive and not
autostarted. Guest hardening has not been applied to the host. AppArmor stays on.
No host reboot or bridge replacement was performed. A global firewall snapshot
changed during preflight, so byte-for-byte firewall invariance is not claimed;
no global policy edit was requested or applied.

Source checks: seven foundation regressions passed on the Linux runtime owner at
`98b5bb2ee17020cf7570992168a526cc3ce533c7`, plus 23 existing admission tests.
At `de6f66f`, eight foundation tests passed, including a regression for the first
failed baseline preflight: private umask removed new QEMU-directory traversal.
The correction sets traversal only on newly created project directories.
The original failed attempt is preserved; it created no VM/network/disk.
Subsequent partial Terraform applies established two concrete prerequisites:
libvirt requires the `dnsmasq-base` binary even with DNS/DHCP disabled, and the
provider's default SPICE display is incompatible with the minimal headless QEMU
package. The binary-only package was installed; the domain input now removes
graphics through the provider's XML adapter. Failed-attempt evidence and exact
partial-resource reconciliation remain private. These are runtime-discovered
integration defects, not successful installations.

Commands, from a clean checkout under the authorized Linux runtime owner:

```text
python -m unittest discover -s tests -p test_vm_foundation.py -v
python -m unittest discover -s tests -p test_media_store.py -v
python -m wormhole media-split /private/source.iso --store /private/chunks --sha256 APPROVED_SHA256
python -m wormhole media-assemble /private/chunks/manifests/SHA256.json --store /private/chunks --output /private/reconstructed.iso
python -m wormhole.vm_baseline --source /private/ubuntu-22.04.5-live-server-amd64.iso --terraform /private/pinned/terraform
```

The baseline command has a 30-minute absolute execution budget, a reserved
evidence/cleanup margin, persistent private console/results, real ISO boot and
separate controller-based final SSH/Ansible checks. It is intentionally always
lab-unqualified and production-ineligible. It does not implement hardened release
publication. Unknown Terraform outcomes retain ownership and require inspection;
there is no automatic takeover or complete VM recovery command yet.

All media, generated ISOs, run-scoped keys, Terraform state and raw evidence stay
outside Git. The local chunk adapter approximates an artifact store; GitLab
Generic Package Registry compatibility has not been executed. No scanner result,
RHEL install, production acceptance or independent review is claimed.
