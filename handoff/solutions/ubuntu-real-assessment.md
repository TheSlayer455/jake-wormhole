# Ubuntu real audit and fail-closed finalization

Proven stock-audit execution:
[c22653d1dab343f36b2bab27e4adb6022a161050](https://github.com/TheSlayer455/jake-wormhole/tree/c22653d1dab343f36b2bab27e4adb6022a161050).
Ubuntu 22.04.5 amd64, Ubuntu-host KVM, BIOS, fresh 64 GiB disk, 8 GiB RAM,
two virtual CPUs, isolated networking and the designated pinned controller.

## Problem and observed cause

A created VM and installed account did not establish readiness. Finalization
failed because SSH syntax validation ran before the SSH service created its
runtime directory. The controller recorded a finalization failure rather than
waiting for SSH. The unit now declares that runtime directory itself. A fresh
installation completed finalization, a second boot, trusted final-account SSH,
password-required sudo and real Ansible. This establishes this home defect only;
it is not a diagnosis of a proprietary installer.

A separate real seed-layout failure showed that ISO directory arguments could
flatten identity files. Explicit graft points and extraction/hash verification
now prove the seed directory layout before allocating a VM. Identity secrets stay
in the private run seed, outside installer command arguments and public media.

## Assessment evidence and limits

The guest installs OpenSCAP 1.2.17 from a frozen, signature-verified Ubuntu
snapshot repository bundled as declared prerequisites. Assessment runs only after
finalization/reboot and never remediates the target. It produced native XCCDF,
ARF, HTML and an attributed receipt: 639 rules accounted, 230 selected, 55 pass,
64 fail, 107 not applicable, four not checked and 409 upstream not selected.
This includes assessment prerequisites; it is not untouched stock package state.

Content is ComplianceAsCode 0.1.82, Ubuntu STIG V2R7. Canonical's documented USG
V2R8 is a different content distribution. USG, approved FIPS modules, manual
controls and external services remain unresolved. Evaluate-STIG and Nessus were
not executed. A completed scan is not a passing rule set or lab qualification.

Implementation: [installation inputs](../../wormhole/ubuntu_inputs.py),
[installed finalization](../../ubuntu/guest/finalize.sh),
[assessment-only guest operation](../../ubuntu/guest/audit.sh),
[controller and collection](../../wormhole/ubuntu_runtime.py),
[full rule accounting](../../wormhole/ubuntu_assessment.py).
Source parser negatives are in
[test_ubuntu_assessment.py](../../tests/test_ubuntu_assessment.py);
they are synthetic regressions, separate from this real scan.

## Reproduce within an authorized home runtime

Use clean pinned source and the established runtime owner. Supply actual approved
private paths; the placeholders below are not configured locations or credentials.

~~~text
python -m unittest discover -s tests -p test_ubuntu_assessment.py -v
python -m wormhole.ubuntu_runtime prepare --store PRIVATE_STAGED_INPUTS
python -m wormhole.ubuntu_runtime run --mode stock-audit --store PRIVATE_STAGED_INPUTS --source VERIFIED_STOCK_ISO --terraform PINNED_TERRAFORM
python -m wormhole.ubuntu_runtime progress RETURNED_RUN_UUID
~~~

Expected positive: real installation, separate final reboot, trusted SSH,
Ansible and persisted native results. Expected negative: a finalization failure
blocks controller dispatch; missing, wrong-target, erroneous or incomplete rule
evidence cannot become a passing qualification. A pending candidate was actually
refused publication without creating a release directory. Positive qualified
publication remains unverified.

Retain the failed run, reconcile supervisor state, and use exact-owned teardown.
Never delete uncertain resources or reallocate through an old receipt. Current
recovery refuses a live supervisor; stopped-run recovery needs its own proof.
Do not run the installed guest scripts on a host or controller.

## Luna integration task

Inspect the existing implementation on **ansible control node** and its actual
runner context. Adapt only the relevant finalization ordering, complete native
result accounting or bounded collection. Preserve the existing pipeline and
verify final access through its real controller. The home **Ubuntu** hypervisor
does not establish behavior on **rhel kvm host**, RHEL installation, work GitLab
or customer qualification. Preserve original failures, bounded deadlines,
run-owned cleanup and a rollback to the previous attributable candidate.
