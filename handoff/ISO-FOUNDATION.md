# Home ISO extension checkpoint

This is an incomplete implementation increment, not an ISO qualification receipt.
Container baseline: main `d205040135c47611d821d3c1a202e2ea370284a5`, runtime
implementation `f8e5f0ef8f3764617516f5716840fcbb751589f6`. Preserve its evidence.

## Verified Ubuntu installation baseline

Delivery: [PR 29](https://github.com/TheSlayer455/jake-wormhole/pull/29).
Final runtime confirmation at `55bb2fb1ba657149d836a916dfc6be318b43a430` repeated
the complete baseline with a new empty disk and seed, preserving the original
ISO hash. It passed in **201.471 seconds**: input reuse 7.394 s; installation
through final key emission 141.024 s; controller SSH/Ansible/inventory 40.875 s;
Terraform apply 1.467 s and teardown 1.517 s. All 610 package/version rows were
present, cleanup verified absent resources, both journals finished and the
unrelated sentinel remained unchanged. Ten VM foundation and 23 existing admission
tests passed at this source, including separate active-VM status reporting.
[Push CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40603833876)
and [PR CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40603942285)
passed. Later documentation/merge revisions do not relabel these observations.

At `31eca5832db3225ca7c10a5c4147c03ec8612e9f`, a fresh 8 GiB/two-vCPU/
64 GiB KVM guest installed Ubuntu 22.04.5 amd64 from the remastered ISO's BIOS
boot path. It booted its installed disk, authenticated through strict SSH host
verification as the generic dotted final account, passed real Ansible ping and
privilege escalation, and returned 610 native package/version records. The
nonroot pinned helper used an explicitly declared host-network controller
profile with no Docker/libvirt socket, host mounts, capabilities or listener;
credentials arrived on stdin into private tmpfs. Installer SSH did not satisfy
the installed-system readiness command.

The ISO bytes were reused from the previous reconciled installation attempt;
actual current GRUB inputs and the original hash matched. A new public-key seed,
credential pair and empty disk were used. The previous attempt had installed and
authenticated successfully but failed on Ansible CLI argument parsing. The
controller fix was exercised with the real pinned helper parser before retrying.
Neither attempt changed installer identities to hide a controller defect.

The first complete successful experiment took **205.201 seconds**: ISO reuse and new
seed preparation 8.103 s; Terraform init/validate/plan/apply 3.012 s;
installation through final host-key emission 144.022 s; controller SSH/Ansible/
inventory 40.812 s; controller cleanup 0.064 s and Terraform cleanup 1.417 s.
Other time includes preflight, explicit firmware start and media rehashing.
These are nonoverlapping coordinator stages, not peak resource measurements.
The preceding cold build took 6.254 s: warm copying and integrity checks did
**not** demonstrate a speedup, although the ISO was not rebuilt.

Cleanup verified zero owned domains, disks, pools, networks or helper containers;
both admission journals are finished with zero pending resources. The unrelated
sentinel matches its original identity, image, start/restart and running state.
Original source, failed attempts, diagnostic intervention, ISOs/seeds, console
capture and native outputs remain private. No hardening or real assessment was
performed, so lab ISO qualification and production eligibility remain false.

Source integration at `8cce6674eae525944a62d05cc2d453e475e856eb` passed 883 tests:
Linux runtime owner 881 passed/two skipped; Windows 591 passed/292 skipped.
Repository hygiene and historical evidence checks passed. [Hosted CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40603025830)
passed. The only subsequent input-code refactor extracts the same reuse predicate
for direct stale-input regressions; it does not relabel the earlier VM execution.
No independent review is claimed.

The unchanged container reference path was rerun at `8cce667`: Ubuntu passed all
43 required rows with an eligible reference receipt and production eligibility
false. Cleanup finished. K3s remains active, and the canonical runtime store is
still root-owned mode 0700. No twenty-container benchmark was repeated alongside
VM acceptance.

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
  and ISO builder were exercised in the successful baseline above. Reconcile
  current private run results before starting another attempt.
- Still required: RHEL installation and comparable stock assessment baselines; pinned
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
integration defects; they are not themselves successful installations. The
provider's transform also requires the minimal `xsltproc` binary package.

Further real failures established the correct QEMU primary group and private
volume ownership, the managed-volume reference incompatibility with confinement,
the provider's raw default for file-backed disks, and virsh's controlling-TTY
requirement. A controlled file-reference diagnostic started under dynamic
AppArmor with the exact disk path in its generated policy; it was stopped and
never counted as qualification. Fresh installation then verified the repository
file-reference/QCOW2 correction. Host confinement was not disabled or weakened.

Commands, from a clean checkout under the authorized Linux runtime owner:

```text
python -m unittest discover -s tests -p test_vm_foundation.py -v
python -m unittest discover -s tests -p test_media_store.py -v
python -m wormhole media-split /private/source.iso --store /private/chunks --sha256 APPROVED_SHA256
python -m wormhole media-assemble /private/chunks/manifests/SHA256.json --store /private/chunks --output /private/reconstructed.iso
python -m wormhole.vm_baseline --source /private/ubuntu-22.04.5-live-server-amd64.iso --terraform /private/pinned/terraform
python -m wormhole.vm_baseline --source /private/ubuntu-22.04.5-live-server-amd64.iso --terraform /private/pinned/terraform --reuse-run ORIGINAL_RECONCILED_RUN_UUID
```

The baseline command has a 30-minute absolute execution budget, a reserved
evidence/cleanup margin, persistent private console/results, real ISO boot and
separate controller-based final SSH/Ansible checks. It is intentionally always
lab-unqualified and production-ineligible. It does not implement hardened release
publication. Unknown Terraform outcomes retain ownership and require inspection;
there is no automatic takeover or complete VM recovery command yet.

ComplianceAsCode 0.1.82 was staged privately from its official release with the
published asset digest verified. Its actual Ubuntu 22.04 STIG profile identifies
V2R7; RHEL 9 content is present too. This is content inspection, not scanner
execution, remediation or compliance evidence. Evaluate-STIG/Nessus remain
unverified. Select and declare the lab policy before any qualification gate.

All media, generated ISOs, run-scoped keys, Terraform state and raw evidence stay
outside Git. The local chunk adapter approximates an artifact store; GitLab
Generic Package Registry compatibility has not been executed. No scanner result,
RHEL install, production acceptance or independent review is claimed.
