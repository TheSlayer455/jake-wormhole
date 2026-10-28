# Ubuntu installation hardening and post-reboot assessment

Verified merged implementation:
[564cfc5f02cdaf348b15fe788a62987b7d156b2a](https://github.com/TheSlayer455/jake-wormhole/tree/564cfc5f02cdaf348b15fe788a62987b7d156b2a),
delivered in [PR 34](https://github.com/TheSlayer455/jake-wormhole/pull/34).
Its fresh post-merge run passed 34/34 checks in 622 seconds, with unchanged
inventories/native findings, distinct host identity, verified cleanup and
[green main CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40716620271).
The same-ISO installation pair was initially tested at
[deda43f7100fb8aec42285fc941e2eecffcdb795](https://github.com/TheSlayer455/jake-wormhole/tree/deda43f7100fb8aec42285fc941e2eecffcdb795).
Two independent fresh encrypted installations passed all 34 functional checks, trusted final
SSH/Ansible, required reboot, powered-off inspection, cold start and exact-owned
cleanup. The second used identical ISO bytes with different guest credentials,
host keys and boot identities, at `8e510ce023aeb2196f3d637c69b7e50ee81a9520`.
All native outcomes, 636 package versions, three Snap entries, kernel and scanner
payload identity matched. Runs took 616/617 seconds; build/reuse took 17.6/12.7
seconds. Installation-to-final-host-key took 462/468 seconds, offline inspection
and cold start 63.6/63.8 seconds, and SSH/Ansible/inventory/assessment 56.2 seconds
each. AIDE initialized once at the stable end of hardening, about 122 seconds;
these samples do not establish a causal speedup over older runs.
This home Ubuntu-host BIOS experiment does not establish work compatibility.

A fresh stock-audit baseline at `d6ad3523867d8afbb365e01251190f656e10eec0`
used the same scanner/content and completed final SSH/Ansible, native assessment
and cleanup under the mandatory NIC filter. With its guest firewall inactive,
the management listener was refused while the host-side positive control worked.
Its native results were 56 pass/63 fail/107 not applicable/four not checked/409
unselected. The comparison found 60 failing rules became passes, no new failures
and 93 applicability changes. Scanner prerequisites mean this is not untouched
stock. Its hardened functional contract correctly retained two failures
(audit service/firewall inactive) and 20 blocked sandbox checks; it is not an
accepted hardened installation or a qualified artifact.

Actual OpenSCAP 1.4.6 accounts for all 639 rules: **208 pass, three fail,
14 not applicable, five not checked and 409 upstream not selected**. The unchanged
upstream profile is also assessed: 206 pass/five fail, with the other totals
unchanged. The two differences are explicit lab audit-address and truthful banner
values, not rule exclusions. Qualification remains pending; no qualified ISO has
been published. RHEL stays paused and production eligibility is false.

## Sandbox closure work

| Requirement | Earlier evidence | Cause | Correction | Dependency | Verification | Outcome |
|---|---|---|---|---|---|---|
| Encryption | Unencrypted baseline | Missing install contract | LUKS root, PBKDF2, no swap; clear BIOS/boot declared | Private console material | Fresh boot/reboot/cold start; correct/wrong/missing key and offline header tests | Passed |
| Log/audit retention | Partial received archive | Sender success lacked durable receipt | Fsync acknowledgment and unique transfer identity | TLS syslog/archive and native ASCII audit receiver | Guest events plus decompressed archive hashes | Passed; ASCII audit itself has no managed acknowledgment/Kerberos claim |
| Time | Missing lab source | Undeclared source/settings | Chrony and required step policy | Stratum-10 host-clock reference | Actual selected synchronized source | Passed lab integration; no external trusted-time claim |
| Isolation | IPv4 initially blocked | Ethernet and IP hooks differ | Separate L2/IP filter, fixed private routes | Per-VM libvirt filter | Management connection refused before guest outgoing deny; service routes succeed | Passed; no NAT/default route/public listener |
| PKI | No scoped trust/revocation input | Missing lab dependency | Private CA, CRL, delegated OCSP signer | Bounded OCSP receiver | Valid/revoked/untrusted certificate and signed online status checks | Passed lab behavior; no physical token or government CA |
| Guest listeners | Undeclared SMTP ingress | Default Postfix interfaces | Preserve local mail on loopback only | Installed mail package | Final listener inventory | Passed |
| Manual controls | Five native `notchecked` | Objective facts and external assurance differ | Observe expiry, sudo membership, listeners and audit capacity | Disposable workload assumptions | Four conditions met; government PKI unsupported | Native statuses preserved; one unresolved |
| USG/FIPS | No entitlement | External vendor input absent | Protected explicit provider and ephemeral guest configuration | Legitimate owner-supplied subscription | Real nonvendor lifecycle probe; failure regressions | Enrollment, USG, FIPS modules/runtime unexecuted |
| Benchmark coverage | 409 unselected rules | Upstream profile boundary | Keep all outcomes; map official V2R7/V2R8 manuals | Pinned public content | All 188 V2R8 controls referenced; seven changed check/fix records | Identifier mapping complete; USG/scanner equivalence unproven |
| Publication | Pending required controls | Eligibility not established | Strict original gate and consumer readback | Complete eligible run pair | Actual pending-run refusal; positive integrity fixtures only | No qualified release |

Real service-loss injection failed the installer promptly and blocked all 34
dependent checks without dispatch. Real supervisor interruption first proved live
recovery refusal, then exact-owned recovery retained unknown outcome and 34
blocked checks. Stale installed inputs were refused before provisioning.
Capture-derived missing-rule/wrong-target tests and actual pending/incomplete
publication refusals passed. These are distinct evidence categories, not extra
successful installations. A fresh container regression remained eligible; the
historical twenty-target fleet was not rerun during this VM work.

The remaining native failures are FIPS mode, smart-card PAM authentication and
`verify_use_mappers`. The last rule's regex omits the vendor configuration's
required semicolon. Preserve the valid configuration and native finding rather
than adding invalid syntax to obtain a pass. Physical-token authentication and
government-PKI evidence are absent. No exception has been approved.
See the upstream [configuration grammar and examples](https://opensc.github.io/pam_pkcs11/doc/mappers_api.html).

The scanner is an independently built, pinned upstream 1.4.6 artifact, not a
Canonical FIPS/USG build. A same-guest focused 1.2.17 audit still failed the
partition rule while 1.4.6 passed it alongside real encrypted-disk proof.
Do not compare different scanner builds as a measured security improvement.

Current supported operations use the existing protected operator and private
paths. Never run `ubuntu/guest/` programs on the host. The sandbox requires one
8 GiB guest plus a 128 MiB/0.5 CPU service container and the existing pinned
controller, all under the same admission lock. Receiver listeners bind only the
owned guest bridge; private CA keys stay in operator storage and container tmpfs.
Native support evidence remains private. Receivers are removed after dependent
assessment/collection; interruption recovery verifies the same run journal.
TLS syslog/archive uses port 6514, native ASCII audit 6000, signed OCSP 8080,
and the lab clock UDP 12345, only on the owned bridge. The mandatory guest NIC
filter permits those destinations and controller SSH, and denies other traffic.
The CA is scoped to these services and PKCS#11 inputs, not a global enterprise CA.

The disk threat model excludes compromise of the trusted operator host. The
unlock material stays in owner-only operator storage outside the ISO, seed,
Terraform state and QEMU-readable disk directory. A real installed-system scan
and a separate 2.36 GB ISO/seed/state/diagnostic inspection found no plaintext or
reversible copies outside declared credential originals. Those private originals,
seeds and failure diagnostics are intentionally retained for forensic/recovery
disposition, with no automatic deletion promised. Certificates expire after two
days; guest/controller copies and temporary disks are removed through ownership
checks. This is not hardware-rooted key protection or secure-erasure proof.

~~~text
python -m wormhole.ubuntu_runtime run --mode hardened --sandbox --store PRIVATE_STAGED_INPUTS --source VERIFIED_STOCK_ISO --terraform PINNED_TERRAFORM
python -m wormhole.ubuntu_runtime progress RUN_UUID
python -m wormhole.ubuntu_runtime recover RUN_UUID --terraform PINNED_TERRAFORM
python -m wormhole.ubuntu_runtime verify-release PRIVATE_RELEASE_DIRECTORY
python -m wormhole.ubuntu_runtime coverage RUN_UUID --baseline-manual PINNED_V2R7_XML --target-manual PINNED_V2R8_XML
~~~

The [sanitized audit-transfer reproduction](ubuntu-audit-transfer-reproduction.json)
records an actual failed VM attempt. Its race was observed, not a claim that the
whole installation always reproduces it. The focused real-TLS regression in
[test_ubuntu_sandbox.py at the tested source](https://github.com/TheSlayer455/jake-wormhole/blob/deda43f7100fb8aec42285fc941e2eecffcdb795/tests/test_ubuntu_sandbox.py)
exercises the corrected durable handshake. Adapt that pattern to the actual
transport on **ansible control node**; it does not make audispd ASCII reliable or
establish the cause of a work-environment failure. Keep **rhel kvm host** resource
ownership and the existing controller intact. Reconcile before retrying; rollback
uses a previous attributable candidate and a fresh installation.

For a legitimate existing Ubuntu Pro entitlement, the smallest owner action is
to create its one-line input file privately under the established operator with
mode 0600, then populate an owner-only 0700 provider directory. Do not send the
token in chat, Git, process arguments or portable evidence:

~~~text
python -m wormhole.ubuntu_secrets put --store PRIVATE_PROVIDER --kind ubuntu-pro --source-file OWNER_CREATED_PRIVATE_FILE
python -m wormhole.ubuntu_secrets status --store PRIVATE_PROVIDER
~~~

The guest delivery program supports a nonvendor probe and explicit private attach
configuration; real attach additionally requires supported client options and
deliberately authorized vendor connectivity/package staging. The current NIC
filter does not permit internet egress. Freeze resulting vendor packages/content
before qualification and exercise documented detach before disposable teardown.
Do not assume that populating a provider establishes USG, FIPS or a certified
operational environment. Those vendor-dependent paths remain unexecuted.

## Previously delivered evidence
Delivered through [PR 31](https://github.com/TheSlayer455/jake-wormhole/pull/31).
The merged implementation
[63d3aa1fb90cdc478f7e50d76384d944130bfbff](https://github.com/TheSlayer455/jake-wormhole/tree/63d3aa1fb90cdc478f7e50d76384d944130bfbff)
also completed a third fresh same-ISO installation in 566 seconds: 14/14
functional passes, identical 191/18/16/5/409 native outcomes and full inventories,
verified cleanup and green main CI. This is repeatable partial acceptance;
eighteen findings and five manual checks still prevent qualification.

## Historical prerequisites and scope

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
