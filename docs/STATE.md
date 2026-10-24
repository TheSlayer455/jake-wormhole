# Current engineering state

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
