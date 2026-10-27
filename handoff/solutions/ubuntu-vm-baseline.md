# Ubuntu ISO installation and final identity baseline

**Signature/prerequisites:** a created VM or installer SSH port does not prove
installed-system readiness. Requires authorized Ubuntu 22.04.5 amd64 media,
hardware KVM, the declared isolated controller route, 8 GiB memory and 64 GiB
disk. The tested host is Ubuntu with AppArmor; RHEL-host behavior, UEFI and Secure
Boot are unverified.

**Established in Wormhole:** the candidate replays the ISO boot equipment, adds
unattended GRUB arguments and requires a separately bound NoCloud seed. Account
creation runs through `curtin in-target`, with no bootstrap account. The target
generates a unique SSH host key and emits its public key through controlled
serial capture. Final SSH checks the installed-root marker, intended identity,
OS and privilege escalation before actual Ansible ping, baseline checks and
native inventory. No synthetic result substitutes for these operations.

Real integration repairs cover missing helper binaries, headless display,
QEMU directory/group and volume ownership, file-backed disk confinement,
explicit QCOW2 interpretation, controlling-TTY capture and Ansible arguments.
A manually modified diagnostic VM was excluded from installation proof. A fresh
unmodified run then passed. These findings do not establish any work root cause.

**Pinned implementation and tests:**
[inputs/template](https://github.com/TheSlayer455/jake-wormhole/blob/31eca5832db3225ca7c10a5c4147c03ec8612e9f/wormhole/vm_inputs.py),
[coordinator](https://github.com/TheSlayer455/jake-wormhole/blob/31eca5832db3225ca7c10a5c4147c03ec8612e9f/wormhole/vm_baseline.py),
[shared admission](https://github.com/TheSlayer455/jake-wormhole/blob/31eca5832db3225ca7c10a5c4147c03ec8612e9f/wormhole/vm_admission.py),
[regressions](https://github.com/TheSlayer455/jake-wormhole/blob/8cce6674eae525944a62d05cc2d453e475e856eb/tests/test_vm_foundation.py).

```text
python -m unittest discover -s tests -p test_vm_foundation.py -v
python -m wormhole.vm_baseline --source /private/ubuntu-22.04.5-live-server-amd64.iso --terraform /private/pinned/terraform
python -m wormhole.vm_baseline --source /private/ubuntu-22.04.5-live-server-amd64.iso --terraform /private/pinned/terraform --reuse-run ORIGINAL_RECONCILED_RUN_UUID
```

Use a clean checkout and the established authorized Linux runtime-owner route.
Actual success took 205 seconds, including 144 seconds to final host-key emission
and 41 seconds for SSH/Ansible/inventory. It returned 610 complete package/version
records. ISO reuse verified current boot inputs and exact original bytes, then
used a new seed and empty disk. It did not reuse acceptance.

**Luna task:** inspect the existing installer/controller first; adapt only missing
behavior. Preserve **rhel kvm host** and **ansible control node** responsibilities.
Verify target-context finalization, final identity, permissions, labels, reboot
and access from the actual runner/helper. Do not copy the lab network, host,
firmware or sudo policy into work. This baseline proves no post-hardening repair.

**Failure/recovery:** failed readiness prevents dependent baseline checks;
incomplete terminal rows cannot pass. Preserve console, manifests, state and the
VM journal. Prove exact resource ownership before cleanup. Reconciliation-only
leases cannot allocate; unknown Terraform outcomes remain blocked for inspection.
A complete automated VM recovery command is not implemented. Hardening, real
assessment, lab policy, qualification and ISO publication remain pending.
