# Engineering checkpoint

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
