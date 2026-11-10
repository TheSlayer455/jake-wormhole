# Wormhole: verified portable engineering reference

Use with [the Luna comparison prompt](LIGHTSPEED-CROSS-REFERENCE.md). This document
is an official, reviewed capability snapshot, not a claim of production approval
or compatibility with a proprietary image. Active real-ISO scope is **RHEL 10 and
Ubuntu 22.04**. The existing container regression layer remains separate.

Reconciled **2026-11-09** against the public main baseline
[`3a4b909bf95141a400bda3d19a779a152f3ecc7b`](https://github.com/TheSlayer455/jake-wormhole/commit/3a4b909bf95141a400bda3d19a779a152f3ecc7b).
Each installation below retains its own runtime revision.

## Safe facts and evidence discipline

The content allowlist is: public OS/tool versions and repository revisions;
generic mechanisms and roles; guest sizing/firmware needed for reproducibility;
aggregate test, inventory and native finding counts; rounded stage durations;
verification categories; general failure mechanisms; and explicit limitations.
Only approved public Wormhole source, PR and CI links are included. Public source
links are navigation for authorized inspection, not permission to copy their
configuration or every historical document into a portable report.

Facts are summarized from inspected records. This reconciliation checked
the Ubuntu intake and hardened RHEL results, native evidence and installed SVDs.
Private identifiers, paths, keys, fingerprints, media digests,
package lists and raw records are intentionally absent. The evidence labels below
are public reference labels, not internal run identities.

## Evidence index

Runtime receipts and sanitized public checkpoints have different roles. Public
checkpoints record observed results; native proof remains private. Source tests
can be rerun publicly but cannot reproduce licensed media or private execution.
Dates marked "checkpoint" are recorded public source/evidence dates, not an
assertion of the precise execution time.

| Label / evidence date | Actual tested source and public record | Observed scope |
| --- | --- | --- |
| U / 2026-11-01, runtime receipt date | [Ubuntu controller at a705e2b](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_runtime.py); [recorded final pair](https://github.com/TheSlayer455/jake-wormhole/blob/65b8e8ffde4a1a43c34cbc5ab8578e50cbabc980/handoff/solutions/ubuntu-install-hardening.md) | Two fresh encrypted installations of identical ISO bytes; 40/40 functional checks and five objective manual observations each; SVD, actual assessment, terminal records and cleanup. |
| R / 2026-10-31, runtime receipt date | [RHEL SVD/assessment at 77e6e16](https://github.com/TheSlayer455/jake-wormhole/blob/77e6e1611d478fcc1a713d40e66907a80c3207c5/wormhole/rhel_assessment.py); [recorded execution](https://github.com/TheSlayer455/jake-wormhole/blob/65b8e8ffde4a1a43c34cbc5ab8578e50cbabc980/docs/STATE.md) | Fresh installation, six controller checks, trusted SSH/Ansible, 413 RPM rows, actual assessment and cleanup. Unhardened baseline. |
| H / 2026-11-09, local runtime date | [Hardened RHEL inputs](https://github.com/TheSlayer455/jake-wormhole/blob/d6dfaf396e458bba7745e3541980c1879b5b434c/wormhole/rhel_hardening.py), [controller](https://github.com/TheSlayer455/jake-wormhole/blob/d6dfaf396e458bba7745e3541980c1879b5b434c/wormhole/vm_baseline.py) and [native collector](https://github.com/TheSlayer455/jake-wormhole/blob/d6dfaf396e458bba7745e3541980c1879b5b434c/wormhole/rhel_assessment.py) at d6dfaf3, repeated at [4980aa0](https://github.com/TheSlayer455/jake-wormhole/commit/4980aa0718e6860c45728aa00cbf9f825397419e) | Two independent fresh encrypted installations of identical ISO bytes, 10/10 each, matching 449 RPM rows and native outcomes. Both verified cold boot, trusted SSH/Ansible, audit receiver delivery and cleanup. |
| L / 2026-10-29 checkpoint | [Controller at 63a130a](https://github.com/TheSlayer455/jake-wormhole/blob/63a130a249111fc10c229a66922a51895b87e40e/wormhole/vm_baseline.py); [comparison and fault evidence](https://github.com/TheSlayer455/jake-wormhole/blob/56ca6fdb9f174c7649c27e2b778c67ca94849962/handoff/solutions/lifecycle-comparison.md) | Same-candidate lifecycle comparison; actual readiness failure and interrupted-supervisor recovery. Terraform retained. |
| I / 2026-10-29 checkpoint | [Intake at 0a6acb5](https://github.com/TheSlayer455/jake-wormhole/blob/0a6acb5754a943562a9e425288704cae928afa60/wormhole/intake.py); [delivery experiment](https://github.com/TheSlayer455/jake-wormhole/blob/56ca6fdb9f174c7649c27e2b778c67ca94849962/handoff/solutions/directory-intake.md) | Completed RHEL delivery installed without building/remastering; periodic incomplete-delivery, duplicate/restart and failed-readiness cases exercised. |
| D / 2026-11-07, runtime receipt date | [Ubuntu intake at 9a19b53](https://github.com/TheSlayer455/jake-wormhole/blob/9a19b537b0897fad5e649f7b9292f3e2102cacfa/wormhole/ubuntu_intake.py) and [focused tests](https://github.com/TheSlayer455/jake-wormhole/blob/9a19b537b0897fad5e649f7b9292f3e2102cacfa/tests/test_intake.py) | One fresh encrypted Ubuntu installation used unchanged delivered bytes and a fresh private seed. It passed 40/40, cold start, trusted SSH/Ansible, native assessment and cleanup. Terminal request replay returned the same result. |
| A / 2026-10-31 checkpoint | [Archive client at b881127](https://github.com/TheSlayer455/jake-wormhole/blob/b881127296ea9b2bc23dbde523b1c0a8b9021842/wormhole/archive_client.py); [failure-test revision](https://github.com/TheSlayer455/jake-wormhole/commit/61f91d9d29c4ceec5ec75e782bf0e6ecb4185668); [recorded storage proof](https://github.com/TheSlayer455/jake-wormhole/blob/56ca6fdb9f174c7649c27e2b778c67ca94849962/docs/STATE.md) | Real workstation archive, destination readback, eligible local deletion and exact-byte restore of a probe and historical ISO; actual unavailable/interrupted/corrupt transfer refusal. |
| S / 2026-10-31 checkpoint | [Retained SVD archival at f2a3d5c](https://github.com/TheSlayer455/jake-wormhole/blob/f2a3d5ca383a1fea9230a9d1225406ae1f9bde26/wormhole/storage_archive.py); [PR 45](https://github.com/TheSlayer455/jake-wormhole/pull/45) | 298 verified encrypted objects at that checkpoint; six additional SVD/build-manifest readbacks; local originals retained. This is not a live backlog count. |

## Verified mechanisms and boundaries

| Lifecycle | Implementation and actual proof | Transfer limitation |
| --- | --- | --- |
| Media and candidates | Streaming chunk reconstruction verifies source integrity. Installed-input fingerprints govern candidate reuse; unchanged bytes can serve new attempts without rebuilding. U verifies identical candidate/contract across two independent installations. | Hash identity alone does not prove freshness, qualification or team intent. Controller/report-only changes differ from installed-input changes. |
| RHEL installer | R preserves the DVD BIOS boot machinery and uses a separate Kickstart seed. H applies pinned hardening during installation and validates the resulting system after reboot. The powered-off check verified LUKS acceptance of the correct key and refusal of wrong and missing keys. | BIOS lab profiles. The receiving team owns its installation contract. H still has open assessment findings and cryptographic validation requirements. |
| Ubuntu installer | [Ubuntu inputs](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_inputs.py) bind versioned offline payloads and hardening with a declared private NoCloud seed. U installs Ubuntu 22.04.5 x86_64, completes first-boot finalization/hardening and required reboot. | Neither path is a universally self-contained ISO. Separate secrets/endpoints are declared dependencies; acceptance does not repair the guest into compliance. |
| VM provisioning | [Shared VM lifecycle](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/vm_baseline.py) uses Terraform/libvirt/KVM, empty disks, serial evidence and exact resource journals. One live acceptance guest; 8 GiB RAM/two vCPUs, RHEL 32 GiB disk or Ubuntu 64 GiB disk. | Ubuntu virtualization host, BIOS only. No UEFI/Secure Boot, enterprise scale, remote work-runner routing or arbitrary host compatibility claim. |
| Readiness and trust | Controlled serial evidence supplies the installed guest's unique host key. Strict SSH verifies host identity and the intended final account, completed installation marker, OS and mounted root. Real Ansible verifies interpreter/privilege access from the designated helper. U also proves encrypted reboot/cold-start and wrong/missing unlock refusal. | Port-open or installer SSH cannot satisfy readiness. RHEL baseline privilege policy differs from Ubuntu's required password-based escalation; preserve each contract. |
| Functional validation | U: 40/40 checks each, including real lab logging/audit/time, scoped trust/PAM, encryption and access probes. R: six controller checks, including Ansible and basic privileged smoke. L: authenticated but inaccessible completion marker immediately blocks four dependent checks. | R's six checks are not a full hardening catalog. Lab time/PKI/software-token tests do not establish external trusted time, government identity or physical-token assurance. |
| SVD | Structured native Ansible inventory feeds readable and JSON SVDs. R: 413 RPM rows with native version/release/epoch/architecture; key headers separate. U: 638 packages, three Snaps and two payload entries. Build inventory remains distinct from installed inventory. Original row/readable-output readback passed. | Counts do not establish equivalent proprietary packages or business behavior. No package list is exported here. |
| Assessment | Both OSes retain actual OpenSCAP machine-readable and readable reports, scanner/content identity and every native outcome. Ubuntu supplements manual observations without rewriting scanner statuses. | Findings must satisfy the declared policy. Evaluate-STIG, Nessus and Ubuntu USG/FIPS execution remain unproven. |
| Execution and recovery | L acknowledges actual admission/start, records observed phase/progress separately from liveness, and persists failure/unknown outcomes. Controlled interruption retained unknown state until stopped-process/ownership reconciliation. U's final pair finished automatically; compact terminal storage summaries reference full durable receipts. | Missing acknowledgment or observer loss requires reconciliation, not automatic duplicate launch. A recovered unknown attempt remains unknown, never successful. |
| Cleanup | Terraform destroys exactly recorded resources after evidence collection; storage uses the shared admission/ownership lock. U/R/L verified temporary resource absence. Original operation errors survive cleanup errors. | No global prune, ambiguous-prefix deletion or deletion of unresolved evidence. Historical absence is not evidence of current host availability. |
| Completed-ISO intake | I and D verify an explicit completion manifest, protected bytes, actual size/hash and a declared contract. They use the same dispatcher and fresh seed. D also binds the build manifest and verifies the embedded Ubuntu payload. | Evidence covers RHEL 10 BIOS baseline and Ubuntu 22.04 hardened sandbox. Periodic monitoring was exercised on RHEL and removed afterward. Other producer contracts need their own evidence. |
| Intake identity and retries | I proves no second active VM on duplicate notification/restart. Real-file source fixtures prove same filename/new bytes, changed assessment identity and explicit retry create distinct requests. | Those identity fixtures are not additional VM experiments. Deduplication must not permanently prevent legitimate requalification. |
| Storage/archive | A/S extend existing storage receipts: workstation-initiated strict SSH, age encryption, actual decrypted destination hash/size verification, durable commit before eligible local reclamation, explicit verified restore. Active disks/state/credentials/journals stay local. Offline/pending data is retained; admission can refuse new work. | Real archive/restore and failure tests, not a proposal or localhost-only copy. A limited periodic task was installed and exercised at the checkpoint; current availability is not asserted. Retention is not a proven independent backup or key-loss recovery policy. |
| Gates/publication | [Ubuntu gate/publisher](https://github.com/TheSlayer455/jake-wormhole/blob/a705e2be45979b0df8f4ac7178b43c95c4eb09d4/wormhole/ubuntu_release.py) requires complete bound results, matching independent installations and declared policy. U's normal publication attempt was refused for pending dependencies with no release created. | Positive ISO-publication integrity fixtures are source tests only. No lab-qualified ISO publication is proven. Historical container-reference publication is a separate capability. Production eligibility remains false. |

## Native outcomes and unresolved qualification

| Native result | RHEL baseline R | Hardened RHEL H | Ubuntu U and D, each |
| --- | ---: | ---: | ---: |
| Pass | 172 | 425 | 210 |
| Fail | 261 | 9 | 1 |
| Not applicable | 56 | 29 | 14 |
| Not checked | 9 | 10 | 5 |
| Not selected | 450 | 600 | 409 |
| Total | 948 | 1,073 | 639 |

R uses the DVD's pinned SCAP Security Guide 0.1.76 vendor-draft content; it does
not prove alignment with a current released DISA benchmark. U uses OpenSCAP 1.4.6
and ComplianceAsCode 0.1.82 identifying V2R7, with declared lab values and a
documented mapper correction. The unchanged upstream Ubuntu audit remains
207 pass/four fail; do not confuse it with the declared lab result above.

All 188 controls of the frozen V2R8 manual target were mapped, including seven
changed check/fix records supported by actual probes/native results. The 409
upstream-unselected rules carry no Ubuntu STIG identifiers; they are not passes
or hidden failures. Five native manual statuses remain unchanged despite five
objective supplemental observations. The newer V2R10 manual is a separate,
unqualified target. This mapping is not USG execution or scanner equivalence.

Ubuntu's remaining native failure is FIPS. Legitimate Pro entitlement and actual
USG/FIPS enrollment, package/module/runtime verification, reboot and assessment
remain required. The private provider interface does not supply entitlement.
Delegated lab trust review is complete; physical-token hardware is not required
by the prospective lab policy, while physical/government assurance remains
unverified. Historical policy/results have not been rewritten.

Evaluate-STIG has not run on either OS: an authorized official package, included
support documentation and permitted invocation remain unavailable. Nessus has no
verified runtime execution here. No alternative scan can satisfy those claims.
H uses ComplianceAsCode 0.1.82 and its pinned RHEL V1R2 profile. The native
findings, unresolved manual evidence and verification of cryptographic modules
and their operating environment keep qualification pending. The different
content in R and H prevents a direct finding-count comparison.

## Measurements and engineering lessons

- U: about 666/669 seconds for each complete CLI, including about 26/28 seconds
  of final storage/reporting; VM-through-teardown about 639/642 seconds. First
  installation-to-host-key stage: 465 seconds; offline encryption/cold-start: 63;
  SSH/Ansible/inventory/assessment: 56. Nested stages must not be added twice.
- R: 308 seconds for the fresh SVD run. I: completed delivered-ISO run 248 seconds;
  controlled failed-readiness intake 236 seconds. Different contracts/sample
  populations prevent treating these as a cross-OS performance ranking.
- H: about 536 and 496 seconds through guest teardown. Installation to host key
  took about 345 and 327 seconds, offline inspection and cold start about 35 each,
  and controller validation through assessment about 40 each. Archive transfer
  is a separate operation.
- L: one Terraform control took 272 seconds versus 278 for native libvirt; lifecycle
  commands about 5.6 versus 2.4 seconds. The alternative added another ownership/
  recovery path without an established overall advantage and was removed. The
  0.672-second readiness-failure detection starts after authentication, not VM launch.
- A: a roughly 2.14 GB historical ISO archived/reclaimed in 77 seconds and restored
  in 64 seconds. Subsequent scheduled reconciliation measured 5.978 GiB net local
  allocated-block reduction. This is a historical measurement, not live capacity.
  Budgets remain 100 GiB managed/40 GiB candidate cache, with 80% warning and 90%
  projected filesystem admission ceiling.

The final U pair follows two preserved failures: an oversized embedded terminal
storage receipt and an asynchronous guest mail-service stop/start race. Small
corrections reused durable receipt references and the packaged service-manager
restart. Source tests alone did not close either runtime claim.

H follows preserved failures in scanner exit handling, boot unlock observation,
audit startup and host-key framing. The installation treats a scanner findings
exit separately from an execution error. It preserves the vendor's early audit
ordering and labels the isolated receiver port inside the guest. The controller
accepts one unambiguous key in the bounded frame despite concurrent boot messages.
Actual boot and transport observations establish those corrections.

Historical source CI at `56ca6fd` passed 974 tests with 12 explicit skips and
controlled parity. Source CI at `4980aa0` passed 997 with 12 explicit skips
and controlled parity. Work-environment integration and proprietary-image acceptance
require separate work-side evidence. Production eligibility is false.
[Historical source CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/41257949098)
[Current source CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/42726826330)

## Maintenance and sharing contract

After a meaningful implementation/runtime milestone, the responsible engineer must
reconcile this capability matrix against original attributable evidence. Update
only changed safe facts, the reviewed revision, evidence date/category and limits;
preserve historical tested revisions. Read installed results and terminal/cleanup
receipts, not just a green CI badge or optimistic milestone prose. Do not ingest
raw logs automatically or require access to a private work repository.

Before sharing, run `python scripts/verify_repository.py` and the focused
`python -m unittest discover -s tests -p test_portable_handoff.py -v` check. The
validator covers these two files, approved public link forms and obvious unsafe
patterns; it is not comprehensive DLP, a factual verifier or disclosure approval.
Use the safe-fact allowlist above and independent engineering review of the exact
diff. Record actual reviewer/scope, tested and delivered revisions, evidence
changes and remaining limitations in the PR; never invent a review. The handoff
is part of milestone completion, including an explicit "no evidence change" when
appropriate. It does not require another VM installation for prose-only edits.
