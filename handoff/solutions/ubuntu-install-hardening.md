# Ubuntu installation hardening and post-reboot assessment

Tested installation implementation:
[be1aac0cc0a027874337cd7587ee42e294a54d38](https://github.com/TheSlayer455/jake-wormhole/tree/be1aac0cc0a027874337cd7587ee42e294a54d38).
This is a home Ubuntu-host KVM experiment, not work-environment acceptance.
Delivered through [PR 31](https://github.com/TheSlayer455/jake-wormhole/pull/31).
The merged implementation
[63d3aa1fb90cdc478f7e50d76384d944130bfbff](https://github.com/TheSlayer455/jake-wormhole/tree/63d3aa1fb90cdc478f7e50d76384d944130bfbff)
also completed a third fresh same-ISO installation in 566 seconds: 14/14
functional passes, identical 191/18/16/5/409 native outcomes and full inventories,
verified cleanup and green main CI. This is repeatable partial acceptance;
eighteen findings and five manual checks still prevent qualification.

## Prerequisites and scope

Ubuntu 22.04.5 amd64 stock ISO, BIOS, an empty 64 GiB disk, 8 GiB RAM and two
virtual CPUs; one VM at a time. Offline dependencies come from the pinned Ubuntu
snapshot. Content is ComplianceAsCode 0.1.82 Ubuntu STIG V2R7, assessed by real
OpenSCAP 1.2.17 after installation-local hardening and a required reboot.
The ISO requires the declared private run seed. Account and boot credentials are
unique per installation; reusable secrets do not enter the candidate ISO.

## Established causes and corrections

- AIDE's configuration package is a recommendation, so disabling recommendations
  omitted necessary configuration. Install pinned aide-common and cron explicitly.
- Initial AIDE database construction actually took about four minutes. Allocate
  its measured share of the unchanged absolute budget and cancel the whole
  subprocess group on expiry. Do not remove hashes to obtain a faster result.
- A Python 3.11-only hashing API failed on Ubuntu 22.04's Python 3.10. Use bounded
  streaming SHA256 in the installed observer.
- The pinned generated log-permission remediation omitted removal of world-read
  bits. Its real OVAL check rejected a world-readable diagnostic log. Correct
  existing nonexempt log permissions during installation and set the existing
  logging wrapper's creation mask, preserving the diagnostic function.
- GRUB had graphical output with no VM display; finalization was also reported
  terminated during its intentional reboot. Serial GRUB, clean first-boot exit
  and explicit SSH finalization conditions passed fresh execution. The exact
  earlier invisible firmware wait was not established; do not transplant an
  asserted diagnosis of that wait.
- A separate run-scoped boot secret protects editing and the GRUB command line.
  Normal OS boot remains unattended and recovery entries are disabled. Passing
  the benchmark's UEFI-named password rule on BIOS does not prove UEFI boot.

## Actual result and fidelity

The fresh guest passed all 14 functional checks, final-account trusted SSH,
password-required sudo and real Ansible from the pinned helper. Native inventory
contains 630 Debian packages with versions/architectures and three Snap entries.
All 639 rules are accounted: 191 pass, 18 fail, 16 not applicable, five not checked
and 409 upstream not selected. The log, console-lock, boot-password and three
audit-space rules pass. All 166 selected upstream remediation operations completed;
their exit status alone is not treated as a passing assessment.

Required FIPS/USG entitlement, encryption/unlock, smart-card/directory/CA inputs,
authorized banner/time/logging requirements and manual dispositions remain open.
Canonical USG V2R8 equivalence, Evaluate-STIG and Nessus are unverified. Lab
qualification and positive qualified publication remain pending; production
eligibility is false. The earlier stock comparison has different applicability
because the hardened installation includes audit dependencies.

The second fresh installation at
[109efdcc42d2896c206dc5d0ea55e0db94f6aa06](https://github.com/TheSlayer455/jake-wormhole/tree/109efdcc42d2896c206dc5d0ea55e0db94f6aa06)
reused exactly the same ISO, with new disk, boot IDs and credentials. Functional
and native rule outcomes, all package/Snap versions and kernel matched. Runs took
558/544 seconds; build/reuse took 15.0/9.5 seconds (one sample each). Manual facts
were collected without approving dispositions. This establishes repeatability of
the observed partial contract, not qualification of the eighteen open findings.

## Source and reproduction

Read [installation inputs](../../wormhole/ubuntu_inputs.py),
[hardening extraction](../../wormhole/ubuntu_hardening.py),
[reviewed plan](../../ubuntu/remediation-plan-v1.json),
[guest finalization](../../ubuntu/guest/finalize.sh),
[installed hardening](../../ubuntu/guest/remediate.py),
[observations](../../ubuntu/guest/observe.py) and
[controller/collection](../../wormhole/ubuntu_runtime.py).
Focused source tests are the four test_ubuntu_*.py files; fixtures are labeled
separately from real execution.
The [sanitized reproduction manifest](ubuntu-observer-reproduction.json) was
generated from the actual earlier observer failure and reviewed before export.
It includes only public source identity, generic inputs and reproduction/recovery
instructions; credentials, private run identifiers and raw captures are excluded.

~~~text
python -m unittest discover -s tests -p "test_ubuntu_*.py" -v
python -m wormhole.ubuntu_runtime run --mode hardened --store PRIVATE_STAGED_INPUTS --source VERIFIED_STOCK_ISO --terraform PINNED_TERRAFORM
python -m wormhole.ubuntu_runtime run --mode hardened --store PRIVATE_STAGED_INPUTS --source VERIFIED_STOCK_ISO --terraform PINNED_TERRAFORM --reuse-run RECONCILED_ORIGIN_UUID
python -m wormhole.ubuntu_runtime compare ORIGIN_UUID NEW_RUN_UUID
~~~

Use the established authorized runtime owner and actual private paths. Never run
installed guest scripts on a host. A pending run exits nonzero and cannot publish.
A changed installed input was actually refused before Terraform allocation.
Recovery refused a live supervisor; a deliberately stopped supervisor's owned
resources were reconciled and removed while its original unknown result stayed
ineligible. Raw evidence and the diagnostic disk inspection remain private.

For Luna: inspect the current implementation on **ansible control node** and
**rhel kvm host** first. Adapt only the relevant behavior and test from the real
runner. Preserve working provisioning, hardening, result and cleanup components.
Ubuntu-host BIOS evidence does not prove RHEL-host, GitLab runner or production
compatibility. Roll back through a previous attributable candidate and a fresh
installation, never by rewriting an old receipt or repairing an accepted guest.
