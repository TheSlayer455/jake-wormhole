# Current handoff

## Self-contained Terra handoff

[PR 54](https://github.com/TheSlayer455/jake-wormhole/pull/54) makes
`LIGHTSPEED-CROSS-REFERENCE.md` the complete initial Wormhole paste for Terra.
It incorporates the owner's direct-development directive, quick causal tests,
the current console-marker task, live internal logging, the 20-minute focused
budget, expected-result and cascading-failure behavior, current RHEL/Ubuntu
status, exact qualification blockers, storage disposition, source/API contracts,
focused tests and the work-side response format. Terra should request only a
genuinely missing private work observation, not another routine Wormhole file.

The source/test increment changes no controller, installation input, candidate,
runtime resource or qualification policy. Full clean-checkout verification at
`4c37488` passed 1,016 tests with 12 explicit skips, repository and historical
matrix verification, and all 17 controlled parity cases. Final precision source
`4ce81a2` passed all five focused portable tests and repository hygiene. An
independent read-only engineering/sanitization review checked the exact portable
diff, identified three corrections and cleared the corrected result. No fresh VM
or work-environment execution is claimed. Existing runtime remains attributed to
`21fb946`; this handoff carries that evidence forward without relabeling it.

## Fresh two-OS acceptance with automatic cleanup

Runtime source `21fb946831a451a93c970346855e2c2aec781fb0` completed one new
empty-disk installation for each OS on November 10, 2026. Both reused verified
unchanged candidate bytes with fresh disks, seeds, host identities and secrets.
Guests ran sequentially with 8 GiB RAM, two vCPUs and BIOS firmware. The existing
Terraform/controller/helper path performed installation, encryption/reboot,
trusted SSH, Ansible, native inventory and real assessment. No installed guest
was repaired during acceptance.

| Observed boundary | RHEL 10.0 | Ubuntu 22.04.5 |
| --- | --- | --- |
| Complete CLI elapsed | 582.820 s | 712.432 s |
| Installation through installed host key | 357.349 s | 495.561 s |
| Offline encryption and cold start | 35.503 s | 64.201 s |
| SSH/Ansible, validation, inventory and assessment | 42.363 s | 56.051 s |
| Functional results | 10/10 hardened and 6/6 controller | 40/40 |
| Installed SVD | 449 RPM records, readable and structured | 638 packages, three Snaps, two payload entries, readable and structured |
| Native pass / fail / not applicable / not checked / not selected | 425 / 9 / 29 / 10 / 600 | 210 / 1 / 14 / 5 / 409 |
| Native rules accounted | 1,073, pinned V1R2 | 639, pinned V2R7 plus frozen V2R8 manual reconciliation |
| Automatic file cleanup | 8,487,452,672 allocated bytes, seven actions | 2,287,243,264 allocated bytes, 196 actions |
| Further verified-archive reclamation | 319,488 allocated bytes | 667,648 allocated bytes, including the restored comparison console |
| New retained encrypted archive objects | Eight, 53,293,044 bytes | Eight, 28,924,636 bytes |
| CLI outcome | Lifecycle passed, exit 0 | Assessment complete, qualification pending, exit 1 |
| New lab-qualified release | None | Refused by the normal publisher |

The nested timings overlap and must not be added to the complete CLI time.
Terraform also removed the 32/64 GiB virtual disks. The largest sampled physical
allocations before teardown were 2.276/5.353 GiB, which are observed lower bounds
rather than exact final disk sizes. They are separate from file-cleanup receipts.
Both runs expired their private keys/passwords and detached seeds. Final
reconciliation found zero owned resources, stopped supervisors and the same
66 unrelated running containers. Repeating cleanup reclaimed zero.

RHEL archival took 65.776 seconds. Ubuntu archival was completed by the existing
scheduled task, whose lock correctly deferred the overlapping manual request.
Nine objects were verified in that pass because an existing comparison console
was reread without another upload. Workstation transfer staging is empty, with
407 committed objects, no pending bytes and no failed receipts.

Final managed storage is 83.473 GiB, including a 37.784 GiB candidate cache,
9.874 GiB source media, 22.402 GiB retained evidence and 13.354 GiB other protected
state. Another 55.676 MiB is classified as protected/retained staging and
3.820 MiB as historical reference-release bundles. The existing preview reports
46 protected entries. Required evidence and uncertain historical state were
preserved. Available host space is 131.340 GiB. The workstation retains
68.794 GiB of encrypted objects with 1,037.154 GiB available. Managed retention
grew about 200.7 MiB for the new evidence, while transient file cleanup reclaimed
10.035 GiB plus 964 KiB of archive-eligible source copies.

### Remaining qualification work

RHEL's nine observed automated failures have these public rule suffixes.

| Rule | Observed requirement still failing |
| --- | --- |
| accounts_authorized_local_users | Authorized local accounts |
| grub2_admin_username | Nondefault boot-loader administrator |
| network_configure_name_resolution | Multiple configured DNS servers |
| selinux_context_elevation_for_sudo | SELinux context elevation through sudo |
| service_kdump_disabled | Disabled kdump |
| chronyd_client_only | Chrony client-only operation |
| chronyd_no_chronyc_network | Disabled network management of chrony |
| sshd_enable_warning_banner | SSH warning banner |
| sssd_enable_certmap | SSSD certificate mapping |

The ten native not-checked rules still need accountable rule-level evidence
and disposition. Their suffixes are `crypto_policy_not_overridden`,
`encrypt_partitions`, `account_temp_expire_date`,
`accounts_user_home_paths_only`, `configure_firewalld_ports`,
`configured_firewalld_default_deny`, `libreswan_approved_tunnels`,
`ssh_keys_passphrase_protected`, `sssd_has_trust_anchor` and
`auditd_audispd_configure_sufficiently_large_partition`. Encryption and FIPS-mode
functional passes supply specific supplemental observations. Cryptographic
module identity, certification scope and operating-environment applicability
remain unverified. The current RHEL collector keeps qualification false and has
no completed RHEL release evaluator/publisher. Those are engineering tasks.

Ubuntu's remaining automated failure is `is_fips_mode_enabled`. The explicit
private Pro provider is empty. The owner must privately supply a legitimate
entitlement through the existing owner-file provider. Supported enrollment,
package/module freezing, USG/FIPS execution, reboot/unlock and reassessment then
remain engineering work. All five objective manual observations passed while
their native not-checked statuses remain intact. Delegated trust review and
the frozen V2R7/V2R8 mapping are resolved for this run. The existing comparator
proved unchanged ISO/contract, independent installation identities, matching
inventories and matching findings against the earlier intake run.

The Ubuntu publisher returned `lab_policy_dependencies_pending` and created
no release. Its static policy still lists dependencies that the report can
resolve from evidence, so the final prospective policy/gate reconciliation
remains engineering work. It does not create another owner trust-review chore.
After any installed-input correction, the final candidate needs the declared
fresh repeatability and eligible exact-byte publication proof.

Evaluate-STIG and Nessus did not run. Authorized supported packages/interfaces
remain external work-equivalence inputs, separate from the current required
OpenSCAP lab audits. Neither ISO is lab-qualified or production eligible.

## Automatic storage cleanup

Runtime source `461b113` verified temporary transfer cleanup on the workstation
even when transport failed, record-bound restore cleanup on the host, idempotent
repeat cleanup and normal exact-byte archive restore/reclamation. Each machine
freed a 32 MiB temporary file; the restored 6 MiB probe was also reclaimed.
No new encrypted archive object or VM was created, and all 66 unrelated running
containers remained. Partial files from killed or deadline-exhausted operations
are handled on the next bounded pass. Required archives and evidence remain.
The source suite at that revision passed 1,002 tests with 12 explicit skips;
all 17 controlled parity cases passed.

## Terra work-side handoff

Copy the [combined execution brief](LIGHTSPEED-CROSS-REFERENCE.md) into the
authorized work chat. It contains the first read-only step, live GitLab logging
requirements, focused 20-minute budget and verified Wormhole evidence. Use actual
remaining job time at remote launch and keep product-case mapping independent
from the current installer repair. The expected-result plan belongs in the
existing receipt. Private observations remain work-side unless the owner
requests a sanitized update. This change carries forward runtime evidence.

## Delivered increment: fixed two-OS engineering lifecycle

[PR 48](https://github.com/TheSlayer455/jake-wormhole/pull/48) delivers this
engineering increment. The completion checklist is in [STATE](../docs/STATE.md).
Ubuntu unchanged-media intake at `9a19b53` installed from the unchanged verified
ISO with a fresh private seed, password-required sudo and sandbox. It passed
40/40 functional checks, encrypted cold start, trusted SSH/Ansible and exact
cleanup. The observed inventory contains 638 packages, three Snaps and two
payloads. The native audit records 210 pass, one FIPS failure, 14 not applicable,
five not checked and 409 not selected. The completed request replay returned the
same terminal receipt. Frozen manual revision mapping was bound to the new run
through the existing coverage/report commands. The archive restored both console
records with verified hashes. The comparator confirmed matching software,
functional and assessment results with independent seeds, boots and host keys
for the historical build-path run and this intake run.
RHEL hardening selects pinned ComplianceAsCode 0.1.82/V1R2 separately from the
historical DVD draft baseline. The actual DVD's Kickstart parser accepts the
generated storage/configuration, installer Python exists, and requested packages
are present. This does not establish a hardened installation.

The first fresh RHEL trial at `e592643` stopped when the installer terminal
multiplexer echoed unlock input into the restricted console. No validation ran;
owned resources were removed. The next fresh trial at `39b2825` used documented
`inst.notmux`, received the secret without capturing it, created encrypted storage,
and installed 449 packages. It then failed in the installer-context payload copy:
that environment lacks the `install` executable. `6f75a46` uses its available
mkdir/cp/chmod tools. The fresh `737e2d1` trial reached hardening completion.
An error trap interpreted the scanner's normal findings exit as an installation
failure and stopped the run. `fa79984` distinguishes findings from scanner
errors. The fresh `027bc31` trial completed hardening and reached the installed
LUKS prompt. The controller stopped when a masked wrong-key submission returned
the same prompt without a visible error. It blocked dependents and verified
cleanup. `8b217ce` recognizes the completed retry, including terminal styling,
and leaves proof of cryptographic refusal to the required offline key test.
Replay of the restored console passed with synthetic input. A fresh
`8b217ce` guest used the exact archived and restored candidate. It passed
installed boot, powered-off key acceptance/refusal, cold start, trusted
SSH/Ansible and RPM inventory (449 packages). Native V1R2 coverage accounted
for all 1,073 outcomes: 424 pass, ten fail, 29 not applicable, ten not checked
and 600 not selected. Nine hardened checks passed. Both consoles showed an
ordering cycle that skipped the required audit service. The original failure
and complete audit evidence remain retained after verified cleanup.

The vendor DVD unit orders auditd before sysinit. The added dependency on
network-online formed the cycle. `c49edf9` preserves the vendor unit and
distinguishes an observed inactive service from a failed observation. Its fresh
guest started auditd on both boots. Cold boot then panicked after the audit
backlog filled, with the audit forwarder in SELinux socket-connect auditing.
The original terminal receipt recorded a cold-start timeout and verified cleanup.
The DVD policy permits the audit port type for the forwarder; the sandbox port
had an X server type. `b8b93f7` sets the one guest port label and recognizes the
kernel panic directly. The original console replay confirms that classification.
The fresh `b8b93f7` guest sent more than a thousand real audit records to its
receiver and emitted a complete host-key frame. Concurrent boot diagnostics
interleaved the frame and blocked the original parser. An exact supervisor
interrupt preserved the unknown outcome and verified all temporary resource
absence. `d6dfaf3` accepts a single complete key within the bounded frame and
rejects ambiguity. Replay of the original RHEL console and comparison against
both retained Ubuntu consoles passed. A fresh run reuses the exact same ISO.

The fresh `d6dfaf3` run passed all ten hardened functionals and six controller
checks. It verified encrypted cold boot, trusted final SSH/Ansible, the 449 RPM
inventory, actual guest audit delivery and exact cleanup. The native assessment
recorded 425 pass, nine fail, 29 not applicable, ten not checked and 600 not
selected. Lab qualification remains pending. The first completed run took
536.490 seconds through teardown. The prior protected copy and the completed
copy left candidate storage above its retention budget. Verified encrypted
archival reclaimed 8,487,047,168 allocated bytes from the obsolete failed
candidate before the repeat.

The fresh repeat at `4980aa0` took 495.733 seconds through teardown. Both runs
used identical ISO bytes, the same pinned policy and scanner content, and
different seeds, boot IDs and host keys. The comparison matched every package,
kernel, functional result and native rule outcome. The receiver retained 4,030
and 4,032 guest audit records. The protected record retains both runtime
revisions. `4980aa0` changes only the existing recovery path and its fixture
relative to `d6dfaf3`; live interruption used the original controller cleanup.
The repeat's cleanup unlinked 8,487,452,672 allocated bytes, including its
redundant candidate copy. Both admission journals are finished. No owned VM
or helper remains, and the existing host services are active.

The hardened path uses the existing VM command. On the authorized Linux runtime,
set the variables to the verified stock DVD, pinned Terraform executable and
profile datastream. The profile records the required content hash. A fresh
build needs the verified ISO checksum tool on the path.

```sh
python -m wormhole.vm_baseline --distribution rhel10 --source "$stock_iso" \
  --terraform "$terraform" --rhel-content "$datastream"
```

For a fresh installation of verified retained bytes, add `--reuse-run RUN_UUID`.
The controller checks the retained manifest and creates a fresh disk and seed.
No private capture may be exported. The private operational checkpoint
holds actual attempts, paths and continuation commands.

Shared controller review also corrected an intermediate success record masking a
later failure and required the complete hardened functional/native-evidence grid.
Source CI at `4980aa0` passed 997 tests with 12 explicit skips and controlled
parity. Pro is absent from the configured provider. Evaluate-STIG and Nessus
remain unverified. The real Ubuntu intake publication attempt refused pending
qualification and created no release. Both lab releases remain pending under
the declared policies.

## Previous increment: portable Lightspeed cross-reference

PR 47 originally delivered a separate prompt and evidence reference, since
consolidated into the [Terra execution brief](LIGHTSPEED-CROSS-REFERENCE.md).
The handoff compares the first confirmed failure, preserves the original ISO
contract and keeps private source inside work. The PR reconciled the reference
against pinned implementation, checkpoints and read-only original OS records. No new
installation or scanner capability is claimed. The existing repository verifier
checks both portable files. Maintain them after meaningful evidence changes and
use [PR 47](https://github.com/TheSlayer455/jake-wormhole/pull/47) for tested,
delivered/merged revisions and final CI. Independent engineering-agent review of
`089670b`'s content found no blocking issues or obvious confidential information;
the three focused tests passed. This is not human approval or a runtime rerun.

## Previous increment: non-Pro Ubuntu closure

Use [PR 46](https://github.com/TheSlayer455/jake-wormhole/pull/46) and the
[Ubuntu solution](solutions/ubuntu-install-hardening.md). `2a0fc82` produced a
fresh encrypted 40/40 installation with all five objective manual observations.
The terminal storage receipt overflow is fixed at `134e1e1`; full receipts remain
durable and run records now reference them. A subsequent real guest failure saved
the correct blocked/cleanup result and identified a Postfix stop/start race.
`a705e2b` uses the packaged instance restart. Its two fresh same-ISO installations
passed 40/40 checks and all five objective manual observations each, with complete
native assessment, matching inventories/findings and independent seed/host/boot
identities. CLI times: 665.923/669.224 seconds. Automatic reporting/storage cleanup
passed; normal pending publication was refused and no VM remains. Source CI:
974 passed/12 explicit skips plus parity. The PR records delivered/merged revisions
and final CI; original runtime evidence stays pinned to `a705e2b`. Original
failure evidence and runtime attribution remain intact; no ISO bytes changed for
the storage-only correction; the later service fix does require a rebuilt ISO.
See [current counts and limitations](../docs/STATE.md).

Official Evaluate-STIG distribution requires authorized access/package/docs that
this session has not obtained. Do not use a mirror or claim PowerShell/OpenSCAP
proves that tool. Legitimate Pro entitlement is the remaining owner input for
Ubuntu qualification; actual USG/FIPS execution follows. Physical hardware and
another owner certificate review are not required by the declared lab profile.

## Current priority: two-OS runtime and assessment proof

Fresh execution is verified at `77e6e16`: RHEL 10 passed six controller checks
with a 413-package SVD in 308.123 seconds; encrypted Ubuntu 22.04 passed 40/40
checks with 638 packages, three Snaps and two payloads in 649.973 seconds.
Both used existing ISO bytes, real SSH/Ansible/native OpenSCAP and verified cleanup.
See [counts and qualification boundaries](../docs/STATE.md) and [PR 44](https://github.com/TheSlayer455/jake-wormhole/pull/44).
Delivery merged at `1a8d412`; post-merge CI and original SVD replay/readback passed.
Fresh installation evidence stays attributed to `77e6e16`.
Evaluate-STIG needs an authorized release package and its documentation before
supported invocation can be implemented and executed. Ubuntu Pro is a separate
owner input; the newer increment above records benchmark and trust closure.

At `b881127`, selective archival reuses strict SSH, age and existing storage cleanup.
A real 6 MiB probe and historical Ubuntu ISO archive/delete/restore passed; real
interrupted transfer and corrupt-ciphertext rejection passed at `61f91d9`. The
limited Windows schedule completed 194 objects after the reviewed `33f2ea0`
cleanup optimization; its later no-op pass succeeded. Net allocated storage fell
5.978 GiB, with no active domains and Docker/K3s active. [PR 43](https://github.com/TheSlayer455/jake-wormhole/pull/43)
tracks delivery without relabeling old installation evidence. Use [storage commands and
retention rules](../docs/STORAGE.md); restore missing candidate bytes before admission.
Only fresh verified commits permit reclamation. Required assessment copies remain
local, and this increment changes neither budgets nor qualification eligibility.

Storage is delivered on main at `6a78d39`, with passing post-merge CI/readback.
Historical identity comparisons may require restoring the archived console first;
that exact recovery was exercised successfully for the new Ubuntu comparison.
The SVD/manifest selection follow-up at `f2a3d5c` completed 298 real encrypted
objects with zero pending/failed and additional readback of all six fresh SVD/
manifest files. Local originals remain intact. [PR 45](https://github.com/TheSlayer455/jake-wormhole/pull/45)
adds only eight production lines/removes three; full CI and independent review
passed. See storage for measured timing and current resource state.

## Previous delivery: directory-delivered ISO acceptance

Use the [directory intake handoff](solutions/directory-intake.md), delivered by
[PR 42](https://github.com/TheSlayer455/jake-wormhole/pull/42). Runtime-tested
`0a6acb5754a943562a9e425288704cae928afa60` passed manual RHEL 10 intake in 247.755
seconds and the monitored readiness-failure case in 236.396 seconds. Same ISO
bytes, fresh seeds, existing Terraform/SSH/Ansible/native audit, complete results
and cleanup; no builder/remaster or new execution framework. Timer duplicate/
restart reconciliation did not allocate another run. Qualification remains false.

Luna should establish the receiving team's delivery-completion and installation
contract, then adapt this one intake function to its existing controller. Discover
the private source/Forge build contract separately when source builds are needed.
Do not substitute this lab's seed for team customizations. Ubuntu intake, private
runner routing and actual scanner automation rights are not proven by this run.
The test timer is stopped; canonical inputs and private evidence are retained.

## Latest compatibility repair

[PR 41](https://github.com/TheSlayer455/jake-wormhole/pull/41) fixes the Ubuntu
helper's stale substitutions after the shared readiness split. Runtime-tested
`e8fdaa62b831eef071daa6eedff3bd808a196e96` passed one fresh encrypted policy-v2
installation: 40/40 functional checks, trusted SSH, password-required Ansible
privilege escalation, native assessment and cleanup in 644.915 seconds. No builder, hardening,
scanner or RHEL execution change. Source verification: 958 pass/three explicit
skips; independent engineering-agent review found no blocking code findings.
See [current evidence and storage headroom](../docs/STATE.md).

At that checkpoint, qualification remained pending: selected native results were 210 pass/one fail/
14 not applicable/five manual, plus 409 upstream not selected. Pro entitlement
is the owner input; actual USG/FIPS execution, benchmark reconciliation, delegated
trust review and a second matching v2 installation remained engineering work.
The fresh run above now supplies that second matching installation; it does not
resolve the entitlement, assessment-content or trust-review requirements.
The earlier v1 pair retains its attribution. No qualified release is claimed.
Use [the integration entry point](../docs/EXTERNAL-INTEGRATION.md) to adapt the
proven lifecycle. Runner is an optional, unexecuted trial; do not add it around
existing structured callbacks without demonstrating removed complexity.

## Current decision: retain Terraform, integrate observable execution

Delivery: [PR 40](https://github.com/TheSlayer455/jake-wormhole/pull/40); use its
final head/merge and CI records without relabeling the tested sources below.

Start with the [Luna lifecycle handoff](solutions/lifecycle-comparison.md).
The same-candidate native experiment at `7b59975` passed but did not justify a
second implementation: 278.225 seconds total versus Terraform's 272.246; lifecycle
commands saved 3.254 seconds. Same guest contract, 413 package versions and all
948 rule outcomes match. These are single observations, not a benchmark claim.
The native adapter remains in pinned history; normal execution stays Terraform.

Tested retained code: `63a130a249111fc10c229a66922a51895b87e40e`. Launch acknowledgment
follows durable admission; status distinguishes observed progress from liveness.
The actual controlled readiness failure kept SSH passing, blocked all four
dependents and never started Ansible/catalog. An actual supervisor interruption
reported unknown, refused overlapping admission, then recovered exact-owned
Terraform resources and its orphan console without changing unknown to success.
Both runs cleaned up; journals reconcile, no domains remain, Docker/K3s are active.
Full source suite: 957 pass/three explicit skips; parity 17/17 and implementation
CI passed. Independent engineering-agent review found no blocking findings.

Next integration: adapt the existing foreground execution/receipt, meaningful
progress and separate final-system readiness checks on the **ansible control
node**, then prove one guest and interruption recovery on the **rhel kvm host**.
Keep actual hardening/scanners/release policy. Do not replace Terraform or infer
the cause of missing work-run launch/status evidence from this home experiment.
RHEL hardening, encryption and qualified publication are deliberately deferred.

Current Ubuntu decisions are in [policy v2](../docs/UBUNTU-LAB-POLICY.md): no home
physical-token hardware requirement, physical assurance unverified, trust-anchor
review delegated to Codex and pending engineering. Legitimate Pro entitlement
remains the owner input; actual USG/FIPS execution and required content evidence
remain outstanding. No new Ubuntu qualification or historical reclassification.

## Historical checkpoints

The following source-bound results and dependency lists describe their original
checkpoints. Current scope and owner responsibilities are stated above.

RHEL delivery: [PR 39](https://github.com/TheSlayer455/jake-wormhole/pull/39);
use its head/merge records for delivery attribution, not a new runtime claim.

RHEL 10.0 is the newly activated target on `codex/WORM-001-rhel10-baseline`.
Current implementation: `d39f7a0bc6c10e200fff44fa26bf866bef9ab517`.
The first real attempt at `28b23ad` installed and supported diagnostic SSH with
SELinux enforcing, but `0700` on the completion-marker directory blocked final-user
readiness. It remains failed; owned resources were removed. The narrow `0755`
correction is in the declared Kickstart seed. A fresh empty-disk retry using the
same candidate ISO passed final SSH, actual Ansible, privileged smoke and complete
413-package inventory. The real DVD SSG 0.1.76 vendor-draft audit retained all 948
outcomes: 172 pass, 261 fail, 56 not applicable, nine not checked and 450 not selected.
Exit 2 is retained; neither lab nor production qualification is granted.
Runtime was 272.246 seconds, with verified exact-owned cleanup and no errors.
No VM domains remain; K3s stayed active. Source CI and 17/17 parity passed;
Linux source tests passed 953 with three explicit skips. See [commands, tested
source and limits](solutions/rhel10-install-baseline.md). Next RHEL engineering is
installation-time hardening, current benchmark mapping and qualification/publication.
Final journals are reconciled and the shared lock is available; no owned temporary
containers, networks or filters remain. Retained project storage is 77.17 GiB
within the 100 GiB budget. Unrelated resources were excluded from cleanup;
this audit does not prove their bytewise immutability against historical metadata.
One BIOS guest uses 8 GiB RAM, two vCPUs and a 32 GiB disk under shared admission.
Ubuntu evidence and its exact owner dependencies below remain unchanged.

Latest comparison repair: [PR 38](https://github.com/TheSlayer455/jake-wormhole/pull/38),
implementation `7fdf05be546b8c13af519d4310355079b5a0a8fe`. Seven focused tests,
independent engineering-agent review and replay of the retained real pair passed;
copied seed/boot/host identities and missing receipts cannot prove freshness.
This changes retained-evidence comparison only, so no new VM or candidate build
was needed. The private Pro provider remains empty. Resume vendor-dependent work
when legitimate input is supplied; physical-token assurance and accountable
trust-root disposition also remain pending. Required qualification policy is
unchanged. Follow the owner's simplicity rules in [AGENTS](../AGENTS.md).

## Ubuntu PAM closure

Delivery is tracked by [PR 37](https://github.com/TheSlayer455/jake-wormhole/pull/37);
its head and merge records identify delivered/main revisions separately from the
tested source below. Final audit: zero owned temporary resources, no pending
journal entries, available shared lock, unchanged sentinel and active K3s.

Tested implementation: `3e1e00bc64d6d7c3fb4d3f2d846188626db8eace`.
Two fresh same-ISO encrypted KVM installations passed 40/40 checks in 651/638
seconds with matching native results/inventories and distinct credentials,
host keys and boot IDs. The repaired native PAM passes all six real software-token
cases; required earlier PAM failures remain failed. Trust inventory and extended
PAM controls close the two final technical findings. See
[implementation, commands and adaptation limits](solutions/ubuntu-pam-crl.md).
Native lab counts: 210 pass/one FIPS fail/14 not applicable/five manual/409
unselected. The original upstream audit remains 207 pass/four fail. Qualification
is pending legitimate vendor input/content verification, physical-token assurance
and accountable approval/disposition of 141 trust roots. Actual publication was
refused; no qualified ISO exists. Both guests/support services were removed.

Storage admission initially refused new allocation after unrelated shared-disk
growth. Under the shared and individual run locks, 100 byte-verified, duplicate
tool binary extractions from 50 terminal failed/reconciled container runs were
unlinked, reclaiming 9.5 GiB. Every original ZIP, receipt and failure/evidence file
was retained; ZIP member hashes prove exact reconstruction. This was scoped
maintenance, not a new automatic cleanup capability. Unknown/running runs,
qualified artifacts and unrelated data were excluded. Private receipts record it.

Do not repeat authentication discovery, weaken policy, or relabel old evidence.
RHEL was paused at that Ubuntu checkpoint; review there was self-review, not an invented independent approval.
Full Linux source verification at the tested revision: 947 tests, 945 pass/two
platform skips in 158 seconds. Hosted CI passed 947 with 12 explicit skips and
the controlled parity job. Documentation delivery does not change tested guest
inputs or relabel historical executions as testing a later source revision.

## Automatic storage lifecycle

[PR 36](https://github.com/TheSlayer455/jake-wormhole/pull/36) tracks delivery;
its merge record identifies the delivered main revision. Guest execution tested
`254161b9ed822be350ec691689c8846c95dbfc7a`; final guards/21 focused Linux tests and
[CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40787533279) tested
`d5a9e7c757a1fb805a8e530c22606710f4d6f3ae`. Installed input hashes are unchanged.
The fresh encrypted Ubuntu run passed 34/34 checks in 650 seconds, then reclaimed
2.1 GiB automatically. Native results remain 208 pass/three fail/14 not applicable/
five not checked/409 not selected; the CLI correctly remains nonzero because
qualification is pending. RHEL stays paused.

Use the existing private operator procedure and [storage commands](../docs/STORAGE.md).
Private receipts preserve failures, interrupted intents and measured blocks.
The footprint is 70.5 GiB; warm cleanup found zero further actions. No owned
temporary resources or pending admission remain. All checked original evidence
and retained release hashes match. Small legacy fragments remain protected.
The excluded live media image's inode, size and blocks match; its timestamp
changed during observation. Review was self-review, not independent. Protected
retention exceeding 100 GiB/32 GiB budgets must block allocation, not erase evidence.

## Ubuntu sandbox: verified engineering, qualification pending

Implementation delivery: [PR 34](https://github.com/TheSlayer455/jake-wormhole/pull/34)
merged as `564cfc5f02cdaf348b15fe788a62987b7d156b2a`.
[Merged-main CI passed](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40716620271).
A third fresh installation from that exact merge reused the same ISO and again
passed 34/34 checks, with matching package/Snap/kernel/payload inventories and
208/3/14/5/409 native outcomes. It took 622.454 seconds: reuse 14.106, installation
471.387, offline/cold start 63.239, SSH/Ansible/inventory/assessment 56.539 and
Terraform cleanup 2.224 seconds. All three guest host keys are distinct and stable
across their cold starts. This is repeated technical acceptance, not qualification.

Final private audit: zero owned containers, Docker networks, libvirt domains,
networks, pools or filters; both journals finished with zero pending resources
and the canonical lock available. All 34 recorded retained images are present;
32 private candidate copies, seeds, credential originals and failure evidence
remain intentionally retained. The unrelated sentinel is unchanged and K3s is
active. The publisher refused the matching final pair for pending requirements
and created no release. This later documentation delivery does not relabel a
runtime as testing a different implementation revision.

Tested implementation: `deda43f7100fb8aec42285fc941e2eecffcdb795`. A second independent
fresh installation at `8e510ce023aeb2196f3d637c69b7e50ee81a9520` reused the same ISO;
only the sanitized reproduction adapter changed between these sources. Both
passed 34/34 checks, real trusted final-user SSH/Ansible, normal reboot/cold-start
unlock, powered-off encryption/refusal inspection, logging/time/CA/CRL/OCSP
integration and cleanup. Packages (636), Snaps (three), kernel, scanner payload
and native findings matched; identities and credentials differed. Total times:
616/617 seconds. Private records retain failures and original source identities.

Actual negatives at `8e510ce`: stopping required support services caused installer
failure with 34 blocked checks and no catalog; live recovery was refused, then a
stopped supervisor recovered as unknown with 34 blocked checks and exact cleanup;
stale installed inputs were refused before Terraform allocation. Real captured
missing-rule/wrong-target negatives and pending/incomplete publication refusal
also passed. A fresh single-target container regression remained reference-eligible
with no pending resources. The twenty-target historical result was not rerun.

The disk gate correctly refused an attempt when retained duplicate media used
its reserved headroom. Under the shared lock, six verified byte-identical copies
were reclaimed (12.1 GiB), with matching retained copies and new disposition
records. Original results, logs, state, seeds and unique media were preserved.

The source suite at `deda43f` ran 918 tests: Linux 916 pass/two skips; Windows
618 pass/300 skips. Hosted CI passed. Later reproduction/report-only changes use
focused tests and CI; they do not relabel the tested runtime source. Delivery and
merge identity are recorded by [PR 34](https://github.com/TheSlayer455/jake-wormhole/pull/34).
Do not infer independent review; execution and self-review are the actual review.

Integration source `d6ad3523867d8afbb365e01251190f656e10eec0` also passed all
918 source tests on Linux (916/two skips, 148 seconds) and Windows (618/300 skips,
170 seconds), plus CI. It extends the same mandatory filter to assessment-only
Ubuntu guests. Its fresh stock audit completed SSH/Ansible and native collection:
56 pass/63 fail/107 not applicable/four not checked/409 unselected. The guest
management probe failed with guest UFW inactive and a successful host positive
control. Same-scanner comparison: 60 failing controls became passes, zero new
failures, 93 applicability changes. Stock retains two functional failures and 20
blocked sandbox checks; do not call it hardened acceptance. Cleanup was verified.

The remaining native results are 208 pass/three fail/14 not applicable/five not
checked/409 upstream not selected. The unmodified upstream audit is retained
separately (206 pass/five fail); no rules are excluded. Four objective manual
checks are satisfied, government-PKI evidence is not. All 188 official V2R8 manual
control identifiers map to the current content, with seven changed check/fix
records; that is not proof of USG execution or scanner equivalence.

Read [the current solution](solutions/ubuntu-install-hardening.md) for the closure
table, exact supported commands, private entitlement input procedure and Luna
adaptation. No valid Pro input has been supplied. FIPS/USG, physical-token and
government trust assurance, the preserved mapper-check syntax mismatch and
qualified publication remain pending. Do not weaken policy or call the sandbox
production-qualified. RHEL stays paused; the accepted container history is preserved.

## Previous Ubuntu hardening checkpoint (historical)

### Previous Ubuntu-only hardening milestone

The owner paused RHEL implementation/media work until Ubuntu is fully complete
and explicitly authorizes RHEL afterward. Continue from current main;
`codex/WORM-001-ubuntu-hardening` is the merged PR 31 history. The existing VM
baseline below remains historical installation evidence, not hardened acceptance.
The versioned policy is `profiles/ubuntu-lab-policy-v1.json`: zero unresolved
applicable automated failures/errors, accountable manual evidence, two fresh
installs and exact-byte publication. No engineer-created waiver is permitted.
USG/Pro/FIPS enrollment is unavailable (owner confirmed); keep those requirements
pending while performing legitimate alternative OpenSCAP work. Source `c22653d`
completed a fresh stock-audit installation, final reboot, trusted final SSH,
password-required sudo, real Ansible and OpenSCAP 1.2.17 in about 264 seconds.
CaC 0.1.82 Ubuntu V2R7: 639 accounted rules, 230 selected; 55 pass, 64 fail,
107 not applicable, four not checked, 409 upstream not selected. Native XML,
ARF, HTML and receipt stay private. This is not Canonical USG V2R8 equivalence.
The stock audit includes pinned offline scanner prerequisites, not untouched
stock package state. Cleanup was verified before the next allocation.

Confirmed installation defects: NoCloud directory flattening (fixed with graft
points plus real seed readback); SSH syntax validation before `/run/sshd` existed
(fixed by the finalization unit's runtime directory); AIDE configuration missing
when recommendations were disabled (explicit `aide-common`/cron dependency).
Failures blocked readiness/catalog dispatch; their console evidence remains
private. Hardened execution at `be1aac0cc0a027874337cd7587ee42e294a54d38`
and a fresh reuse installation at `109efdcc42d2896c206dc5d0ea55e0db94f6aa06`
passed 14/14 functional checks each. Actual OpenSCAP: 191 pass, 18 fail,
16 not applicable, five not checked, 409 upstream not selected. Native reports,
630 Debian packages/three Snap entries and cleanup are verified. ISO bytes,
installed contract, kernel, inventories and required outcomes matched; boot IDs
and credentials differed. Elapsed: 558/544 seconds, build/reuse 15.0/9.5 seconds
(one sample each). AIDE initialization is the measured critical path at about
222 seconds. A remediation operation's zero exit is never substituted for audit.

[PR 31](https://github.com/TheSlayer455/jake-wormhole/pull/31) merged as
`63d3aa1fb90cdc478f7e50d76384d944130bfbff`.
[Main CI passed](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40626679451).
A third fresh installation from that exact merged implementation reused the
same candidate and again passed 14/14 functional checks, with identical native
assessment counts, installed contract, kernel and package/Snap inventories.
It completed in 566.099 seconds; installation-to-host-key took 522.233 seconds,
SSH/Ansible/inventory 12.956 seconds and Terraform cleanup 1.826 seconds.
Its verified reuse stage took 16.949 seconds; these single samples do not prove
a speed improvement. Native-capture-derived negatives refused a wrong target,
missing result and unapproved exclusion without changing the original capture.
These transformations are not additional guest fault experiments. No owned
domains, pools, networks or controllers remain; both admission journals are
reconciled. Private evidence/media remain retained. The unrelated Docker sentinel
was unchanged and K3s remained active. See the
[source-pinned hardening handoff](solutions/ubuntu-install-hardening.md).
The final 901-test suite at `63d3aa1` passed on Linux (899 pass/two skips,
170 seconds) and Windows (607 pass/294 skips, 191 seconds). Earlier test counts
retain their original attribution in Git history. Self-review only; no
independent review is claimed. Documentation-only delivery does not relabel
runtime observations as tests of a later implementation.

Remaining: approved guest USG/FIPS procedure and modules, encryption/unlock
integration, smart-card/directory/CA inputs, authorized banner/NTP/remote-audit
requirements, five accountable manual dispositions and V2R8 distribution mapping.
The second and merged-source runs collected manual facts without approving
them. Qualification and positive qualified publication remain unverified;
manual-disposition integration and complete release evidence still need work.
Next independent implementation task: design and exercise installation-time
encryption with a declared private unlock contract, retaining observational
acceptance and fresh-install proof. Do not invent entitlement, smart-card,
directory, CA, time-server or remote-audit inputs. RHEL stays paused.

Use the established operator route, clean pinned source and private stores:
`python -m wormhole.ubuntu_runtime --help`. `prepare`, `run --mode stock-audit`
or `run --mode hardened`, `run --reuse-run UUID`, `progress UUID`, `report UUID`,
`compare PREVIOUS CURRENT`, `catalog`, `recover UUID --terraform TOOL`, and
`reproduce-package UUID --output PRIVATE_DIRECTORY` plus `publish` share the
existing lifecycle/ownership boundary. Never execute files
under `ubuntu/guest/` on the host. Reuse needs unchanged installed-input identity;
each run creates a fresh disk, credentials and native assessment. Report-only
changes are excluded from that input fingerprint. Recovery requires the original
supervisor/operation to be stopped and exact journal/configuration/resource proof.
Publication is required to refuse the currently pending policy. Its eligible
positive path remains unverified; no qualified ISO or completed Ubuntu milestone
is claimed.

## Accepted ISO foundation (historical two-OS scope)

Continue [ISO foundation](ISO-FOUNDATION.md) from current `main`; the
`codex/WORM-001-iso-foundation` branch is its merged delivery history.
The owner explicitly authorized the separate KVM/libvirt profile and routine
verified incremental merges. Use the recovered private operator route below.
The first increment streams genuine Ubuntu media and passed a real empty-disk
Ubuntu installation, final SSH and Ansible at `31eca5832db3225ca7c10a5c4147c03ec8612e9f`.
Final runtime source `55bb2fb1ba657149d836a916dfc6be318b43a430` repeated it in 201
seconds with complete inventory, verified cleanup and passing CI. [PR 29](https://github.com/TheSlayer455/jake-wormhole/pull/29)
delivers this baseline, not the complete ISO extension.
Implementation merge: `44f33f8dccfec0f7806524cb229674e5f4b08336`. A fresh real
VM run on that merge passed in 201.816 seconds with all 610 inventory records,
strict final SSH/Ansible and verified teardown. [Post-merge CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40604686004)
passed. No owned domains, disks, pools, networks or controllers remain; failed
attempts/media stay private. The live VM also excluded a real parallel Docker
admission attempt before allocation. Continue with pinned Ubuntu guest-side
assessment dependencies and installation-time hardening; obtain authorized RHEL
9 DVD media/checksum for the other OS path. No additional authentication setup is needed.
RHEL media, installation-time hardening, actual assessments and
two-OS lab qualification remain outstanding. Preserve active VM ownership and
reconcile both backend journals before any further allocation. No independent
review or completed ISO capability is claimed.

## Final runtime recovery

Tested code: `f8e5f0ef8f3764617516f5716840fcbb751589f6`.
Delivery: [PR 28](https://github.com/TheSlayer455/jake-wormhole/pull/28), branch `codex/WORM-001-runtime-recovery`. Follow the PR for the merge revision and main CI; later documentation/merge commits do not relabel earlier runtime observations. The [acceptance checkpoint](RUNTIME-ACCEPTANCE.md) records commands, source scope, repairs, timings and limitations. Container reference acceptance is complete.

The previously successful WSL service-operator identity and its authorized owner escalation were recovered from prior session records. Admission and private ownership checks now succeed. Connection metadata and raw evidence remain in private engineering storage; no key, account, permission or host-service change was needed. Use that existing route, not the default client identity from the earlier failed attempts. Reconcile canonical admission before any new operation.

Real results: Ubuntu 43/43; fresh/reused UBI 46/46; all nineteen controlled scenarios; twenty simultaneous stock targets with 160/200/200 readiness, functional and inventory checks; mixed twenty with 200 blocked functional rows and no catalog dispatch. Interrupted initialization/normal recovery, isolation, incomplete publication and successful exact-byte local publication were verified. Windows: 585 passed/282 skipped; Linux owner: 865 passed/two skipped, 867 total each. Implementation CI passed. Source-fixture durations are not runtime timings.

Final audit: zero project containers/networks and pending resources, 33 retained images verified present, canonical lock available and unrelated sentinel unchanged. Preserve failed Runs, source checkouts, images and deliberately incomplete publication evidence. No independent reviewer was contacted. Stock twenty is separate from candidate-single qualification; assessments remain synthetic and production ISO eligibility remains false.

## Historical follow-up

Continue the [failure-reproduction rebuild](../docs/FAILURE-REPRODUCTION.md) from
tested implementation `492aa1051d3c298bd8ac71d602803f035d3f6501` on
`codex/WORM-001-failure-reproduction`, [draft PR 27](https://github.com/TheSlayer455/jake-wormhole/pull/27).
The 862-test suite passed on Windows (581 pass/281 skip), Linux nonroot (852
pass/10 skip) and local WSL Linux root (860 pass/two skip), with successful hosted
CI. Manual controlled parity returned 0/1/1 and validated its diagnostics.

Normal fleet validation requires every planned target's initialization and
SSH/Ansible conditions. The version-2 stock-twenty record retains all 200 blocked
functional rows when initialization prevents execution. Fixed fault experiments
use the existing admission, Terraform, helper and cleanup adapters. The absent
identity is explicitly simulated and requires a separate rejected SSH diagnostic.

Ubuntu and UBI can reuse an immutable original image only after input, build and
artifact replay; UBI includes original package/resolution/signature/license proof
and the requested base package set. New manifests separate installed-format
identity from the current Run's test/collector contracts. Publication retains
the original tested bytes. `recover` can reconcile an interrupted contained
initialization using its known pre-exec provider receipt and exact target/start.
It cannot clear an unknown create, Terraform operation or image commit.

Actual runtime acceptance is still unexecuted because the available operator
cannot read the canonical private Run/admission store. No new project containers
were allocated, no prior runtime state adopted, and no independent reviewer was
contacted. Obtain an existing authorized operator connection, reconcile current
ownership, then run the focused/fault, mixed/fleet/twenty-target, fresh/reused
Ubuntu/UBI reference and publication acceptance with measured timings. Preserve
the source-vs-runtime distinction and all original historical qualification below.

External engineering agents, including Luna, should start with [EXTERNAL-INTEGRATION](../docs/EXTERNAL-INTEGRATION.md). It is the short public-source entry point; this handoff retains development history. Public source and private runtime data are distinguished in [decision 0006](../docs/decisions/0006-public-source.md).

Read [AGENTS](../AGENTS.md), [merged verification](MERGED-VERIFICATION.md), [state](../docs/STATE.md), [architecture](../docs/ARCHITECTURE.md), [fidelity](../docs/FIDELITY.md) and the [historical matrix](../docs/acceptance-matrix.md). All 21 original delivery PRs are merged. Actual merged-source qualification is bound to `c3d440a3c7eee9691f30315b49146eb72998d2df`; later documentation commits have separate CI and do not change that attribution.

All 20 children WORM-002 through WORM-021 have recorded Done/approved-revision-2 completion, 66 passing criteria and solution comments. Original parent/child ledgers and checkpoints remain unchanged as dated snapshots. Minx is authoritative for current workflow state; refresh before mutations. Owner actions were explicitly delegated automation, distinct from independent human examination. Do not elevate roles, extract Owner credentials or bypass guards.

Fresh merged-source checks passed on Windows and Linux root/nonroot with explicit interpreter versions/skips. Linux manual/GitHub parity observed 0/1/1, all three semantic files matched for each mode, and both intended red jobs retained validated uploaded diagnostics. GitLab is authored/local-checked only.

Latest actual runtime is Ubuntu reference Run `8f14b817-486f-4340-87fd-85fe53a9aa6b` at `c3d440a3`: all 43 required checks passed, separate report/gate replay agreed, cleanup completed and canonical admission finished with no pending resources. Its candidate image is retained; four containers and one network are absent. The unrelated sentinel was unchanged. Production ISO eligibility is false.

Latest actual twenty-target qualification remains source `825a594862b816401d4b963329e6242bd8ed8aeb`, Run `290ad14a-e6ec-4822-ae36-258d336ecc38`, with 160/200/200 checks, twenty full inventories, 22 measured containers and all 23 transient resources absent. The [WORM-020 checkpoint](WORM-020-checkpoint.md) preserves four failed predecessors. Retained private state/images and intentionally incomplete publications remain; do not repair old markers or reinterpret old Runs under new code.

## Historical container continuation

No original Wormhole delivery PR remains to merge. The documentation-only follow-up has its own normal PR/main checks. Safe local verification remains:

```text
python -B scripts/verify_repository.py
python -B scripts/verify_acceptance_matrix.py
python -B -m unittest discover -s tests -v
```

Use full Git history for original-source proof fixtures and a fresh clean checkout per parity mode. Refresh repository/Minx state before future work; this handoff is not a claim lease. No new resource allocation is needed merely to continue documentation. Original-source recovery, exact ownership and unknown-outcome refusal remain required.

No VM/ISO, scanner/STIG, proprietary system repair, external model, other-chat messaging, remote release or production eligibility is established. Container reference publication is separate from image export and repository merging.
