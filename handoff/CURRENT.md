# Current handoff

## Active Ubuntu-only hardening milestone

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

## Next bounded activity

No original Wormhole delivery PR remains to merge. The documentation-only follow-up has its own normal PR/main checks. Safe local verification remains:

```text
python -B scripts/verify_repository.py
python -B scripts/verify_acceptance_matrix.py
python -B -m unittest discover -s tests -v
```

Use full Git history for original-source proof fixtures and a fresh clean checkout per parity mode. Refresh repository/Minx state before future work; this handoff is not a claim lease. No new resource allocation is needed merely to continue documentation. Original-source recovery, exact ownership and unknown-outcome refusal remain required.

No VM/ISO, scanner/STIG, proprietary system repair, external model, other-chat messaging, remote release or production eligibility is established. Container reference publication is separate from image export and repository merging.
