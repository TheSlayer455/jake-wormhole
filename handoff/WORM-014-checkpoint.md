# WORM-014 checkpoint

<!-- WORM-014 actual qualification db5d8e74f54483a909faaed963c752962785653c -->
## WORM-014 actual RPM reference qualification

Exact source `db5d8e74f54483a909faaed963c752962785653c` completed four fresh actual UBI9.8-derived cases,
observed at 2026-10-23T19:09:20.242487+00:00. The healthy case retained twelve passing
checks. Missing optional openssh-clients retained twelve pass/one fail; the wrong
version expectation retained eleven pass/one fail; unsupported Ubuntu applicability
retained seven pass/one fail/four unverified RPM checks. These negative harnesses
passed by observing the intended failed underlying operation.

| Scenario | Run | Underlying operation | Primary failure | Cleanup |
| --- | --- | --- | --- | --- |
| healthy | `d473d988-f7d7-469f-95a1-2689295311fb` | passed | none | completed |
| missing-optional-package | `2948e601-9239-40f8-b681-8afd4b3c9903` | failed | rpm_missing_package | completed |
| version-expectation-mismatch | `86a24145-481c-4c96-aab0-7c8bccc37621` | failed | rpm_version_mismatch | completed |
| unsupported-os | `0274e785-d0f9-4382-8186-3d7326c61e22` | failed | rpm_applicability_mismatch | completed |

The fixed public BaseOS solve selected two RPMs. Actual isolated RPM verification
retained both original successful signature outputs and hashes; offline installation,
dependency checks, full package NEVRAs and the exact unmodified UBI EULA were
observed. The same four candidate file bytes retain one content identity across
separate UBI manifests/images. The stock helper and trusted provisioner remain
separate. The validated UBI binding selects exactly SETGID, SETUID, SYS_CHROOT and
AUDIT_WRITE; this permits owned authentication audit records in the shared kernel
audit log. No audit read/control, KILL, PAM or host-setting change is established.
Ordinary Ubuntu keeps its original three-capability policy. Ordinary Ubuntu regression Run `f623e6ca-858b-4f10-9311-0bfbe2a1028c` passed all ten
functional checks with readiness, normal cleanup and unchanged unrelated sentinel.

Source fixtures: Windows 454 cases, 276 pass/178 explicit skips
in 35.432 seconds; homelab Linux 454 cases, 452 pass/2 skips
in 33.834 seconds; native Linux 454 cases, 452 pass/2 skips
in 25.661 seconds. Source fixtures are separate from actual runtime acceptance.

Earlier failed image/probe, resolver and target-environment attempts remain failed
in history. Their cleanup/reconciliation does not rewrite their original outcomes.
The initial unknown pull receipt stayed unchanged; its separate positive-image
reconciliation did not mutate Docker or adopt resources. The 718 build had genuine
signature/EULA success but failed provision. The 66 retry passed provision/TCP
and then refused SSH authentication. The ce3 diagnostic retry also failed SSH;
its original bounded server log recorded audit-write EPERM. Successful diagnostic
capture does not turn that failed SSH result into a pass. All remain failed.

Exact owned containers/networks are absent, base/derived images and private evidence
are retained, and unrelated sentinel checks passed. Actual cgroups bound project
processes; daemon materialization and sampled storage are stated separately.
No full RHEL VM, ISO boot/install, scanner/STIG, complete pipeline, production
eligibility or owner acceptance is established. Publication and hosted CI remain
separate observations. Refresh Minx for current requirements and decisions.

See [evidence](evidence/WORM-014.json), [history](evidence/WORM-014-initial-attempts.json) and [engineering review](reviews/WORM-014.md).
