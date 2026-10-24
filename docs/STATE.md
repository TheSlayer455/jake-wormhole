# Current engineering state

WORM-021 implementation snapshot, October 24, 2026. Baseline delivery is `65db67b90fb104e1e58efffb5fb0e3d80f0c0871`; this curation does not rerun historical runtime observations.

| Fact | Recorded scope |
| --- | --- |
| Implemented | Fixture CLI, admission, pinned images, real Terraform/SSH/Ansible, recovery, functional checks, chunks/candidates, optional PowerShell, UBI, observed SVD, reference reports/gate, local publisher, isolation, stock twenty-target operation |
| Actual homelab qualification | Original commits in the [acceptance matrix](acceptance-matrix.md); latest stock runtime `825a594862b816401d4b963329e6242bd8ed8aeb` |
| Latest runtime | Run `290ad14a-e6ec-4822-ae36-258d336ecc38`, all 160/200/200 rows, twenty 123-package inventories, 22-container interval, all 23 transient resources absent, sentinel unchanged |
| Source fixtures at that runtime | Windows 741: 472 pass/269 platform skips, 94.928 seconds; Linux 741: 739 pass/two Windows-only skips, 85.702 seconds |
| Private GitHub | Delivery `65db67b90fb104e1e58efffb5fb0e3d80f0c0871`, draft PR19, both hosted checks passed; PRs remain unmerged |
| Local reference publication | Actual private Ubuntu/UBI filesystem bundles at original WORM-018 source; no image or remote release |
| Minx snapshot | WORM-002 through WORM-020 Done by explicitly delegated normal Owner actions; WORM-021 approved/claimed In Progress; parent WORM-001 remains |
| WORM-021 parity | Source3f7e3cf3: actual manual/hosted0/1/1 and byte-identical semantic projections; both red jobs retained valid diagnostics; [checkpoint](../handoff/WORM-021-checkpoint.md) |

[WORM-020 evidence](../handoff/evidence/WORM-020.json) retains all four failed actual predecessors: nonmutating Terraform diagnostic truncation, readiness deadline exhaustion, sampler counter grammar refusal and inventory console overflow. Cleanup and later success do not rewrite failures.

The latest runtime has no pending transient graph. Images/private Run state are retained. Earlier intentionally incomplete publication outputs remain incomplete; do not repair markers or delete them to improve a report. No active host operation was reported at that snapshot; recheck ownership before new work.

All original per-ticket checkpoints/evidence/reviews remain unchanged under `handoff/`. The [matrix JSON](acceptance-matrix.json) gives exact source/file hashes and selectors. Earlier nested STATE/CURRENT versions remain in Git at the baseline commit.

WORM-021 implementation and actual source/CI parity passed at3f7e3cf3. Windows788/515pass273skips; local Linux788/786pass2Windows-onlyskips in isolated root fixtures. See the checkpoint for interpreter versions, additional nonroot coverage, exact failures and independent reviews. Delivery/Minx review decisions are separate; refresh their current state. Parent WORM-001 is last.

Refresh Minx and use its supported scoped Agent token/API path. Verify actual deployed capabilities, roles, revision and claim guards; where normal Owner action remains required, record the authorized delegation honestly. Do not elevate roles or treat an obsolete browser-login path as the intended universal access method.

Built, source-tested, privately pushed, hosted-CI-tested, homelab-executed, locally reference-published and accepted are separate facts. Production ISO eligibility stays false.
