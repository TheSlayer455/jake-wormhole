# Current handoff

## Final runtime recovery

PR [27](https://github.com/TheSlayer455/jake-wormhole/pull/27) is merged at
`01b1e806dc18fc581ea78f89747460fc0c6dfc0f`, with passing post-merge CI. The
older draft references below retain their historical attribution. Current
recovery branch: `codex/WORM-001-runtime-recovery`; application code is unchanged.

On the approved Linux host, that exact clean merged source passed local doctor
(exit 0), but canonical admission status returned exit 2,
`observation_unavailable`. Filesystem discovery confirms the available SSH
identity cannot access the root-owned private store, sudo needs authentication,
the existing service-account login rejects the available key, and no Wormhole
operator helper is installed. Another application's operator service is not a
Wormhole access route. No credentials, permissions or host services were changed.

The operator must make an existing authenticated connection as the canonical
store owner available to this task. Preserve private ownership; storage checks
require the executing UID to match, so merely granting read permission is not a
solution. Reconcile original-source retained Runs and admission before allocating.
Then begin with `reference-run --platform ubuntu --fresh-candidate` through the
existing CLI, followed by its report/gate and verified cleanup. Continue the
existing fault, Ubuntu/UBI reuse, mixed/twenty-target, interruption and publication
entry points only after their prerequisites are proven.

Read-only project-label queries found zero containers, zero networks and 29
retained images. This is not proof of reconciled journals or valid cache entries.
No new resources were allocated and no runtime acceptance or performance result
was produced. Evidence remains private outside Git. Full source tests were not
repeated for this documentation-only checkpoint. Runtime-dependent changes must
remain unmerged until actually verified; production ISO eligibility stays false.

## Active follow-up

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
