# RHEL 10.0 ISO baseline and final readiness

The owner activated RHEL 10.0 after supplying official x86_64 DVD media. This is
a separate home baseline; Ubuntu's verified hardening and unresolved qualification
dependencies remain unchanged. The corrected fresh retry completed real
installation, final access, native inventory and baseline assessment. No RHEL
hardening, encryption, FIPS or qualified publication is claimed.

## Observed defect and correction

The first attempt at `28b23ad` booted the candidate's own BIOS entry, installed
onto an empty disk, and supported diagnostic final-account SSH with SELinux
enforcing. Normal readiness nevertheless failed: the completion marker was below
a root-owned `0700` directory, so the final user could not observe it. The required
Ansible/catalog path stayed blocked. That attempt remains failed and its owned
temporary resources were removed; private evidence is retained.

Implementation
[`d39f7a0bc6c10e200fff44fa26bf866bef9ab517`](https://github.com/TheSlayer455/jake-wormhole/tree/d39f7a0bc6c10e200fff44fa26bf866bef9ab517)
changes the nonsecret marker directory to `0755`. It preserves the protected
home/key modes and SELinux enforcement. The correction belongs to the declared
Kickstart seed; unchanged ISO boot bytes can be reused with fresh seed identity.
The corrected retry used a new empty disk and proved final-user traversal through
the normal controller path, followed by actual Ansible and assessment execution.

## Verified runtime and remaining work

At `d39f7a0`, one fresh installation passed trusted final SSH, Ansible ping and
the basic privileged `id -u` smoke; native inventory contains 413 RPM records
without package-key pseudoentries. This is not the full Ubuntu hardening catalog.
The audit completed with native exit 2 and all 948 outcomes: **172 pass, 261 fail,
56 not applicable, nine not checked and 450 not selected**. XCCDF/ARF outcomes,
HTML, pinned content and run/target/boot receipt passed collection checks. Both
qualification flags remain false.

Elapsed time was 272.246 seconds: preflight 16.257, candidate reuse/seed 42.908,
Terraform provisioning 2.529, installation to final host-key evidence 165.040,
controller validation/inventory/assessment 26.374, and Terraform cleanup 1.827.
Assessment took 23.165 seconds within the controller duration; do not add those
overlapping values. This is one measured successful baseline, not a speedup claim.
Exact-owned teardown completed with no cleanup/storage errors; no VM domains
remain and K3s stayed active. Private input bytes and evidence are retained.
Final journals are reconciled, the shared lock is available, and no owned
temporary containers, networks or filters remain. Retained project storage is
77.17 GiB within the 100 GiB budget; filesystem availability is 107.9 GiB.
Candidate readback confirms identical reused ISO bytes and a new installation-input
identity. Unrelated resources were excluded from cleanup; an old mutable-file
sentinel does not establish current bytewise immutability.

Linux verification ran 956 tests: 953 passed and three skipped in 93.513 seconds.
Two skips are Windows-specific; the missing-tool qemu-img integration passed
separately on the homelab. All 17 controlled parity cases passed, and
[CI at the tested implementation passed](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40970024592).
Independent engineering-agent code review found no blocking findings; this is
not a claim of independent human approval. Delivery/merge revisions remain
separate from the runtime source pinned here.

Next work is RHEL installation-time hardening, mapping an explicitly selected
current benchmark, required-control verification and eligible exact-byte
publication. Those are engineering requirements, not results of this baseline.

## Source, contract and verification

- [RHEL adapter](https://github.com/TheSlayer455/jake-wormhole/blob/d39f7a0bc6c10e200fff44fa26bf866bef9ab517/wormhole/rhel_inputs.py): original BIOS boot equipment, volume label and installer runtime source; local DVD packages; separate run seed; final dotted lab identity; installed-boot host-key evidence.
- [Existing VM lifecycle](https://github.com/TheSlayer455/jake-wormhole/blob/d39f7a0bc6c10e200fff44fa26bf866bef9ab517/wormhole/vm_baseline.py): shared admission, actual Terraform/libvirt, trusted controller SSH/Ansible, RPM inventory and exact-owned cleanup.
- [Native baseline audit](https://github.com/TheSlayer455/jake-wormhole/blob/d39f7a0bc6c10e200fff44fa26bf866bef9ab517/wormhole/rhel_assessment.py): pinned content, bounded scan, native XCCDF/ARF/HTML, receipt and complete rule accounting; no remediation.
- [Focused regressions](https://github.com/TheSlayer455/jake-wormhole/blob/d39f7a0bc6c10e200fff44fa26bf866bef9ab517/tests/test_vm_foundation.py): BIOS/source preservation, seed identity and traversal, stale reuse, wrong media, missing/misattributed assessment results and unsafe archives.

Run source checks without homelab access:

```text
python3 -m unittest discover -s tests -p test_vm_foundation.py -v
```

Under the established private operator, with approved media, pinned Terraform and
the existing KVM/helper dependencies available:

```bash
python3 -m wormhole.vm_baseline --distribution rhel10 \
  --source "$APPROVED_RHEL_ISO" --terraform "$PINNED_TERRAFORM"
```

Add `--reuse-run "$PRIOR_RUN_UUID"` only for an existing reconciled run accepted
by normal candidate validation. A retry creates its own declared seed; that seed
contains public authentication material and a protected password hash, not a
private key. The ISO is not represented as a self-contained credential bundle.

This lab uses an Ubuntu KVM host with x86-64-v3 support, BIOS, 8 GiB RAM, two vCPUs
and a 32 GiB disk. The smaller disk preserves measured shared-host headroom;
Ubuntu retains 64 GiB. One VM runs at a time. No UEFI, Secure Boot, RHEL-host
virtualization or work-runner compatibility is established by this baseline.

## Assessment and qualification boundary

The DVD supplies OpenSCAP 1.4.1 and SCAP Security Guide 0.1.76. Its server profile
`xccdf_org.ssgproject.content_profile_stig` is a vendor draft anticipating the
RHEL 10 STIG. The datastream contains 948 rules; native selected and unselected
outcomes remain visible in the completed native audit above.
[Red Hat's release notes](https://api.access.redhat.com/articles/7047972) distinguish
this 0.1.76 vendor profile from the later 0.1.82 alignment to DISA V1R2. The later
revision cannot be attributed to the DVD bytes.

Expected success means an installed final system reaches trusted SSH and real
Ansible, yields complete RPM inventory and attributable native assessment, and
cleans up its recorded resources. Findings remain findings; a completed baseline
does not make the ISO qualified. Missing readiness blocks the catalog. Missing or
inconsistent results fail collection. Preserve original diagnostics and use the
existing ownership-aware recovery command before another allocation; do not alter
a failed guest and present it as a fresh-installation result.

## Luna adaptation task

Inspect the existing **rhel kvm host** and **ansible control node** integration.
Compare the actual selected boot entry, installer source and final-user traversal
of completion evidence. Adapt only the relevant existing component, preserve
account/key protections, and test from the real runner path after fresh installation.
The marker defect is established in Wormhole; it is not a diagnosis of any work
failure. Reuse the source regressions for early feedback, then retain real boot,
SSH/Ansible and native assessment evidence. Stop claiming progress at the first
unproven boundary; lab success cannot establish production qualification.
