# WORM-021 implementation checkpoint

Tested source `3f7e3cf3db5715f88cd0d60fd8caf1426ae5df14`, October 24, 2026.
Evidence: [portable receipt](evidence/WORM-021.json); [review](reviews/WORM-021.md).

The shared runner executes seventeen existing synthetic component APIs and strict
original report replays. Manual Windows CPython 3.12.14 observed exits 0/1/1.
GitHub at the identical source retained matching plan/results/decision bytes for
all three modes. Normal push40124181051 and PR40124184502 passed; required-failure
40124189750 and unexpected-success40124192027 failed only their intended steps.
Both red jobs successfully validated and uploaded exactly five safe diagnostics.
Original underlying outcomes remain visible; a diagnostic validation pass is not
a successful implementation decision.

Actual GitHub environment: Actions runner2.338.0, Ubuntu24.04.5LTS, image
ubuntu-24.04/20261012.334.1, Python3.12.14. Image provisioner versions are separate.
The independent offline audit checked 102 distinct manual/hosted component Run IDs,
complete grids, original hashes, cleanup, actual child exits and provider steps.

Final source fixtures: Windows788,515pass273skips,118.447s. Local nonroot Linux
788,778pass10skips,69.004s. Local root-owned disposable Linux788,786pass2Windows-only
skips,69.179s, including eight UID/RPM fixtures; Docker operations in those builder
fixtures are mocked. Linux interpreter was3.12.3, distinct from pinned manual/hosted
parity3.12.14. All repository and historical-index checks passed.

The [independent root-fixture supplement](evidence/WORM-021-root-audit.json)
enumerates the eight additional cases, commands, original receipt hashes and
remaining platform skips. Its source/helper basis is explicit; it does not invent
a direct UID measurement absent from the original receipt.

The initial root qualification correctly refused cross-owner Git transport before
cloning/testing. Its failed receipt remains private. A checksum-verified complete
history bundle supplied the successful isolated root clone; no global trust,
hooks, host permissions or network settings changed.

The historical matrix preserves83 scenarios/11categories/16original evidence
files, with exact source/selector/hash checks. Earlier container observations are
not reruns at this source. Latest actual stock20 runtime remains825a594, all23
transient resources absent and sentinel unchanged. No new Docker/host operation
was needed for this ticket. Private diagnostic state and deliberately incomplete
publication history remain retained.

Source is privately pushed in unmerged draft PR20, based on WORM-020. This evidence
delivery commit is separate from tested runtime source. GitLab is authored and
locally structurally checked; runner availability, official lint and execution
remain unverified. No VM/ISO/scanner/remote release or production eligibility.

At this source snapshot WORM-021 is awaiting the Minx review decision and parent
WORM-001 remains. Refresh live Minx before any mutation; this file is not a lease.
Root's next action is criterion evidence, solution comment, Agent review/release,
authorized normal Owner decision, then parent closeout. Those Owner decisions are
explicitly delegated automation, not independent human examination.

Safe read-only check: `python scripts/verify_acceptance_matrix.py`. For code
rollback, use a separate checkout of the verified parent source65db; do not reset
another session's files, repair incomplete publication markers or remove retained
evidence. There is no new deployed service to roll back.
