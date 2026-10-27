# Current engineering state

The owner-authorized [failure-reproduction follow-up](FAILURE-REPRODUCTION.md) is
in progress. It adds strict fleet readiness admission, shared observation
projections, explicit diagnostic scope, inherited deadline support and candidate
input fingerprints. Fresh runtime acceptance is blocked by operator access to
retained project state. The original qualification below is not evidence for the
new source. Current test/review status is recorded in the follow-up checkpoint.

Implementation `ba9d1a23ac591a122c0d0b3017d5c5a80afc31db` passed 805 tests on
Windows (273 skips) and Linux nonroot (10 skips), plus hosted CI. Manual controlled
parity observed 0/1/1; all three mode-all semantic files matched hosted output byte
for byte. [Draft PR 27](https://github.com/TheSlayer455/jake-wormhole/pull/27)
contains the increment. Runtime acceptance, additional fault adapters and actual
image reuse were outstanding at that checkpoint; no independent review or full rebuild completion
is claimed. See the checkpoint for commands, timings and the retained failed
test-fixture predecessor.

The current implementation adds observed initialization/configuration, an explicit
lifecycle with separate terminal outcomes, nineteen fixed fault scenarios,
bounded contained-exec reconciliation, per-target reports and verified immutable
Ubuntu and UBI image reuse. New complete-reference and stock-twenty paths require
initialization before SSH/Ansible. Reference publication preserves original
tested bytes on reuse. Current source verification and runtime limitations are
tracked in the same checkpoint. The existing recovery command now reconciles
contained initialization after coordinator interruption while preserving unknown
Terraform/create/commit refusals. Actual Docker execution, benchmarks and
independent review remain outstanding.

Earlier tested implementation `6a8f7bf46b45f07332d0ca4bb1570aab74149839` passed
840 tests: Windows 564 passed/276 skips; Linux nonroot 830 passed/10 skips.
Its hosted PR workflow passed. Manual/hosted semantic parity matched at the
separately recorded predecessor `a6d5109`. No new Docker acceptance or runtime
performance result is established by those source checks.

Latest tested implementation `492aa1051d3c298bd8ac71d602803f035d3f6501` passed
862 tests: Windows 581 passed/281 skips; Linux nonroot 852 passed/10 skips; local
WSL Linux root 860 passed/two skips. Hosted CI passed. Manual controlled parity
at that source returned 0/1/1 with validated diagnostics. The final source checks
include collector-only reuse, original UBI package/license replay, interrupted
initialization proof and no-catalog admission regressions. No new homelab
containers were allocated and no independent review has occurred.

Post-merge verification, October 24, 2026. All 21 original delivery PRs are merged. The qualified main source is `c3d440a3c7eee9691f30315b49146eb72998d2df`, tree `f5a69b447b224840c66229c00f0fd2e102812449`. See [merged verification](../handoff/MERGED-VERIFICATION.md). Original ticket evidence and tested revisions remain unchanged.

| Fact | Recorded scope |
| --- | --- |
| Implemented | Fixture CLI, admission, pinned images, real Terraform/SSH/Ansible, recovery, functional checks, chunks/candidates, optional PowerShell, UBI, observed SVD, reference reports/gate, local publisher, isolation and stock twenty-target operation |
| Repository | PR21 merged at 19:50:33 UTC; all 21 original delivery PRs recorded merged by 19:50:35 UTC. The qualified tree equals the accepted parent closeout tree |
| Source checks at merged main | Windows: 788 total, 515 passed/273 skips, CPython 3.12.14, 121.747 s. Linux nonroot: 778 passed/10 skips, 76.733 s. Linux root: 786 passed/two Windows-only skips, 78.403 s. Both Linux runs used CPython 3.12.3; this difference is explicit |
| Hygiene/discovery | Repository baseline, original acceptance matrix and local doctor passed on all three environments |
| Controlled parity | Same-source Linux nonroot manual/GitHub modes observed 0/1/1; first three semantic files matched byte for byte, 102 distinct component Runs. Both red jobs failed intentionally and retained validated uploaded diagnostics |
| Latest actual runtime | Merged-source Ubuntu Run `8f14b817-486f-4340-87fd-85fe53a9aa6b`: all 43 required rows passed; separate report/gate agreed; cleanup completed, canonical admission finished with no pending resources, unrelated sentinel unchanged |
| Latest actual twenty-target qualification | Source `825a594862b816401d4b963329e6242bd8ed8aeb`, Run `290ad14a-e6ec-4822-ae36-258d336ecc38`: 160/200/200 rows, twenty 123-package inventories, 22-container interval, all 23 transient resources absent |
| Historical acceptance | [Matrix](acceptance-matrix.md): 83 original scenarios across 11 categories and 16 evidence files; these remain original-source observations |
| Minx | Original child completion/criterion/solution records remain in the [parent ledger](../handoff/evidence/WORM-001.json). Refresh live Minx before mutations; source snapshots are not leases |

The fresh Ubuntu reference run retained its candidate image; its four containers and network are absent. Earlier retained images/private Run state and intentionally incomplete publications remain preserved. No cleanup, source reinterpretation or marker repair is implied by merging.

[WORM-020 evidence](../handoff/evidence/WORM-020.json) retains all four failed actual predecessors. Historical WORM-021 source `3f7e3cf3` parity, source checks and red jobs remain in its [checkpoint](../handoff/WORM-021-checkpoint.md). New merged-source results supplement those facts; they do not replace their hashes or attribution.

The documentation-only follow-up has its own PR/main CI. A later documentation commit does not become the source of the `c3d440a3` runtime or parity observations. Built, merged, source-tested, hosted-CI-tested, homelab-executed, locally reference-published and accepted remain separate facts. GitLab runner execution, VM/ISO/scanner compatibility and production ISO eligibility remain unverified or excluded.
