# Engineering checkpoint

## WORM-006 qualification passed, October23 at15:25UTC

Exact clean controller06c19f16d45fe66cd0ebde0432372b2d060f7226 passed the full
actual three-case [acceptance](../handoff/evidence/WORM-006.json). Healthy run
f88f2e95-e195-4154-b9f5-fdd9646f6437, ownership-negative run
891c412a-e1d5-45ba-9c2d-eca49d0c226d and provider-unavailable run
590105e7-8ac5-42a3-b604-2ee281dba09a all passed their acceptance checks and exact
cleanup. The negative partial operations retain failed outcomes. Actual provider
inventory, stopped-before-PID/start checks, cgroups, offline h1 verification,
credential scans, separate state/IDs and unchanged unrelated sentinel are recorded.

Linux146 tests:144passed,two Windows-only skips,6.524s. Windows146:79passed,
67 platform skips,3.975s. Sampled logical run bytes reached266,262,337; this is
neither a hard quota nor a continuously measured peak. All prior failed attempts
were separately reconciled without changing their failure outcomes. Public base,
two qualified images and private tools/state/evidence remain intentionally retained.

Source review found no material remaining blocker. Publishing the evidence,
exact-source hosted CI and the normal delegated Owner completion are the next
delivery operations; retrieve Minx and GitHub for their current authoritative
states. After006 is Done,007 readiness and008 cleanup/recovery become eligible.
No complete pipeline, functional Ansible, production ISO eligibility, automatic
merge or independent human examination is claimed. Historical checkpoints follow.

## WORM-006 runtime qualification, October23 at15:16UTC

WORM-002 through005 remain Done. WORM-006 r2 remains In Progress under the
root session claim. Integration branch codex/WORM-006-integration contains the
reviewed core, fixed scenarios and three-run acceptance operator. No006 passing
criterion or completion has been submitted yet. Current Git revision and Minx
claim must be retrieved before continuing; PR5 is still published only through
9bf2178f762ea9a9c1a146da4b7797e395220d40.

Actual clean source6e4c3028564cf8b1fd7618542c96d817c80fef25 passed133 Linux
cases,131 pass/two Windows-only skips,6.349s. Its real run
7938710b-431e-4101-b07f-7494d8d1c2a6 initialized the offline pinned tools,
confirmed the provider h1, applied an owned network and target, inspected the
never-started target, enforced its PID cap, started it and observed cgroups.
The refresh-only plan exposed an incorrect JSON-shape assumption in the adapter;
the target's actual endpoint appeared in provider output, but the partial run
correctly remained failed. Normal retained-controller recovery then used a saved
Terraform destroy and proved exact target/network/controller absence. All three
attempts below have reconciled resources and retain their original failures:

- 4620b7d2-33b4-463b-bd05-ec60f7ffafc7 at2431de3 failed initialization on HCL
  syntax before provider/state/resource mutation. A separately reviewed fixed
  initialization-only operator removed its sole exact controller, with bound
  terminal diagnostics and no Terraform execution or state edits.
- ac84bfd7-435e-4567-a9c7-44c24a53a58b at94c35cc initialized and planned, then
  refused an unknown startup command before apply. Normal saved empty destroy
  and controller cleanup passed. The command is now explicit and remains guarded.
- 7938710b-431e-4101-b07f-7494d8d1c2a6 at6e4c302 applied real resources and
  failed at refresh validation as described above; normal scoped destroy passed.

Final acceptance must still demonstrate two disjoint complete lifecycles, scans
for credential contents/exposure, ownership refusal with an unchanged unrelated
sentinel, and actual fixed provider failure with bounded diagnostics/accounting.
Fresh source review/test evidence and hosted CI must cover the final code. Raw
state, keys and logs stay private outside Git. No complete pipeline, Ansible
execution, production eligibility or independent human examination is claimed.

## Current: WORM-006, October23 at14:52UTC

WORM-002/003/004/005 are Done. WORM-005 has a solution comment, three passing
criteria, two actual strict SSH qualifications, private PR4 final CI and delegated
Owner decisions. WORM-006 revision2 is approved/claimed and In Progress. Current
branch is codex/WORM-006-integration; private draft PR5 is stacked on005.

Reviewed source fc9ccf81e26ec83c11560f2f5579ab8ec316871e adds new real-run kernel
locks, fail-closed policy handling, evidence-only retained-controller budget checks
and verified bounded private tool preparation. Actual homelab106 tests:104 pass,
two Windows-only skips,5.208s. Windows106:66 pass,40 platform skips,4.667s.

Actual tool preparation run b810b648-15db-41bd-a79e-d24bfb42fdf6 passed in3.007s
with265,992,159 file bytes/266,047,488 allocated bytes,9 files, no Docker allocation
or downloaded-binary execution. See [tool evidence](../handoff/evidence/WORM-006-tool-preparation.json).
Its canonical lease finished with no resources; private cache remains retained.
Terraform/provider version execution, actual h1 confirmation, plan/apply/output/
destroy and failure acceptance remain unfinished. Separate provisioner source is
being implemented in codex/WORM-006-provisioner. No006 completion is claimed.

## Prior WORM-005 checkpoint

October 23, 2026, 14:32 UTC. WORM-002/003/004 revision 2 are Done in Minx.
WORM-005 revision 2 is In Progress; its actual image/SSH acceptance checks pass
and final publication/CI/review are next. Retrieve Minx for current status and
claims. Jake delegated repeated Owner browser decisions; these are automated
rather than independent human examination. See [decision 0002](decisions/0002-owner-delegated-workflow.md).

Implemented: local CLI, isolated fixture runs, six artifact contracts, bounded
stage execution, measured Linux admission/shared flock/durable journal, pinned
Ubuntu target/helper images, per-run keys and strict SSH image qualification.
Terraform, functional Ansible, candidate processing, SVD, assessment and
publication remain unfinished. The complete pipeline and production eligibility
remain false.

Tested image controller: `731eabee3d691404e22c9422e37ff1c6ccddfcf4`. This follow-up
changes documentation and sanitized evidence only. [Actual evidence](../handoff/evidence/WORM-005.json)
and [review](../handoff/reviews/WORM-005.md) preserve separate original build,
controller and reviewer revisions.

- Windows CPython 3.12.14: 93 cases, 63 passed, 30 platform skips, 3.939 seconds.
- Actual homelab Linux CPython 3.12.3: 93 cases, 91 passed, two Windows-only
  skips, 4.417 seconds. Fixture tests and host integration are separate evidence.
- Target build 759b5541-a077-46ca-97a1-1cdfb782ba15 at source 5c4656c683f02b4dca51ee6e24bd9b476a6c781a:
  sha256:6d15eb2c495d48c1eb6485a74d1adaef3e0e3a6e7c83063ba8459f90c27c683e.
- Helper build 9e864d00-ea9f-4a85-bdb5-f5873166e4d7 at source 244ea4b8961fa3be5ca82c122f95a1bd776c210d:
  sha256:4f7f306ecd431b4b48169777966d88c1f09f2139506176a6b85203f5bae69a71.
- Both image tool doctors pass: Ubuntu 24.04, Python 3.12.3, OpenSSH 9.6p1 and
  helper Ansible Core 2.21.5 were observed. Builder cgroups enforce 2 GiB,
  no extra swap, 2 CPUs and 256 PIDs. Exact stopped builders/networks reconciled.
- Fresh SSH runs 1272ece0-83ea-4205-993e-3ca44f5b0590 and
  6b5e5606-fa45-496d-9591-d064495d1167 pass as UID 10001 with distinct client
  and host keys. Wrong host key, root and unknown-user authentication are rejected
  specifically. Actual target/helper cgroups match 256 MiB/.25 CPU/64 PIDs and
  512 MiB/1 CPU/128 PIDs, with no extra swap.
- Each qualification removes its exact containers/network and passes run-label
  sweeps. Images/public base remain intentionally retained. Failed attempts stay
  failed with separate reconciliation receipts. One helper API failure's cause
  remains unknown; a fresh retry passed. No key contents or raw logs are exported.

Layer/free-space sampling is not a hard disk quota. Shared-daemon pull/commit work
is outside builder cgroups. A client timeout remains an unknown outcome and cannot
justify resetting the journal. Private runtime state is outside Git/vault under
/srv/homelab/jake-wormhole/runtime on the existing unlocked encrypted ext4 mount.
No host tool, daemon configuration, routing, authentication, storage or unrelated
application changed.

The repository is verified private TheSlayer455/jake-wormhole. PRs 1-4 remain
unmerged draft increments. Latest push/CI observations belong to Minx and the PR;
earlier CI cannot qualify new source. Paid-plan required-status protection remains
unavailable. No remote image/release or homelab CI runner is configured.

Next: publish final WORM-005, observe exact-source hosted CI, attach all three
criterion results and a solution comment, submit In Review/release, then use the
delegated normal Owner workflow on passing evidence. After Done, approve/claim
WORM-006 for real Terraform lifecycle. Its verified supply-chain preparation is
not execution. WORM-007 is readiness, WORM-008 recovery, WORM-009 functional Ansible.
