# Failure reproduction follow-up

The owner's architecture and failure-reproduction brief authorizes this follow-up.
The original WORM-001 through WORM-021 completion records remain historical and
unchanged. This work is an increment toward the rebuild, not a completed rebuild
or a new production qualification claim.

## Baseline and gaps

Baseline `b71ee89d9ba9898c785bc99d563927b658fd4be0` passed repository hygiene,
the original 83-row acceptance index, and 788 Windows tests (515 pass, 273 explicit
platform skips) in 109.069 seconds on CPython 3.12.14. No open PR covered this work
at discovery. Existing real execution evidence retains its original source.

| Requirement | Existing implementation and follow-up |
| --- | --- |
| Terraform, strict SSH, Ansible, Ubuntu/UBI, inventories, publication | Existing implemented paths and historical runtime evidence preserved; fresh runtime verification outstanding |
| Creation versus readiness | Explicit lifecycle conditions and target initialization receipts are independent of the existing eight SSH/Ansible observations; new complete reference and stock-twenty paths require both |
| Incomplete fleet readiness | Confirmed gap: batch validation previously dispatched a ready subset. Normal validation now dispatches no catalog unless every required target passes revalidation |
| Safe subset diagnostics | Existing negative acceptance now explicitly selects diagnostic subset mode; it retains the full result grid and cannot pass fleet acceptance |
| Initialization failure | A fixed target-side command failure retains its actual exit before dependent probes; account/home/key checks have distinct categories. The original early target-exit diagnosis remains |
| Restart during partial readiness | A changed actual start invalidates cached observations. An explicit pre-authentication restart retains its old epoch and absolute deadline; it cannot discard an established trust pin |
| Deadlines and terminal reporting | Existing readiness windows and owned process bounds preserved. Batch validation accepts only a shortening inherited deadline and persists invocation scope, timing and outcome |
| Observer lifecycle | Fixed contained initialization writes a durable target-side result before exit. Bounded reconciliation verifies the exact resource/start; a separately confirmed stop resolves only that contained exec. Unknown creates/Terraform/image operations retain their existing recovery boundary |
| Candidate freshness | Ubuntu reference runs select a small content-addressed index, replay original build/bundle proof and inspect the exact immutable image under admission. Current test/controller provenance stays separate from the original embedded manifest; every acceptance check reruns |
| Reporting | JSON and readable per-target progress derive from the same records. Missing checks stay missing, blocked rows remain counted, and unobserved initialization stays unknown |
| Failure scenarios | Nineteen focused/fleet scenarios compose existing adapters. New target operations cover command failure, account expectation, home/key loss, hardening regression and observer loss; simulations are explicitly labeled |
| Twenty targets | Original actual stock twenty-target capability retained. New mixed-readiness source regression accounts for 200 blocked rows and launches no catalog. This is not a new actual scale execution |
| Runtime performance | No runtime speed claim. Record invocation timing; measure actual initialization/readiness/validation and compare equivalent runtime inputs once operator access is available |
| Public source | Current private endpoint links and production host aliases removed from documentation. Runtime endpoint URLs are now rejected by the repository hygiene check; history is preserved |

## Current interfaces

`BatchValidationSession.validate()` is full-fleet acceptance. It can receive
`absolute_deadline` as a monotonic expiry inherited from its caller; it never
extends its existing 60-second operation bound. It revalidates every planned
target before dispatch. One unready target blocks all dependent functional rows.

The existing controlled negative harness explicitly calls
`validate(diagnostic_subset=True)`. Diagnostic invocation is recorded in
`evidence/batch-validation-invocation.json`, remains failed/ineligible, and cannot
be confused with a successful full catalog. A later timing-write failure cannot
replace an earlier operation failure; the provisioner records the secondary issue.

`python -m wormhole progress RUN_UUID --format text` reads atomic progress
snapshots without acquiring the active coordinator lock. Use `--format json` for
the same records. The existing fixed runtime store is the default; `--workspace`
selects a retained Run store for read-only reporting. Missing readiness returns
`progress_unavailable`, not zero counts. This command neither allocates nor
cleans resources and never decides qualification. Candidate-specific reference
acceptance continues to use the existing `reference-report` and `reference-gate`.

`candidate.input_identity` fingerprints the source content, pinned builder/base
image, customization bytes, installed configuration and version. Controller/test
revision and generation attempt remain separate provenance. Newly prepared
candidates retain that identity in `evidence/candidate-inputs.json`; bundle replay
recomputes it. `compare_inputs` reports content reuse potential only. Existing
image identity, Run attribution and artifact checks still apply. Ubuntu
`reference-run` now selects and verifies a retained original image when its
construction inputs match. `--fresh-candidate` explicitly builds a new image.
An invalid index, missing original proof or mismatched image refuses execution;
it cannot silently substitute different bytes after the plan freezes. UBI keeps
its existing full build/resolution path; cross-Run UBI image reuse is not claimed.

The reused image keeps its original embedded manifest and labels. A new binding
records the current Run/source and original build identity. Qualification results
are never reused. Publication copies the original tested manifest and payload
bytes, rather than the new attempt's unused preparation manifest.

`python -m wormhole reproduce --profile smoke --scenario healthy --sentinel-id
EXACT_APPROVED_CONTAINER_ID` runs the focused stock experiment. Profiles
`five-targets` and `twenty-targets` use the same operators and real simultaneous
target graph. Select a fixed scenario listed by `reproduce --help`; there is no
arbitrary command or host-policy interface. This command uses the canonical
runtime store and shared admission lock. It does not qualify a candidate fleet.
An expected negative still exits 1; unknown state exits 2. The separate
`scenario_expectation_met` field credits the experiment only after exact cleanup
and an unchanged unrelated sentinel.

The fixed home faults require a dedicated 4MiB target tmpfs. They change only its
owner's directory permissions; the host root filesystem, SELinux and policy are
untouched. The missing-account scenario queries an intentionally absent expected
identity; it does not delete the image's real account. Stale-input and pre-cleanup
error injections are labeled controlled simulations. Installation-source failure
is a separately labeled target-runtime simulation, never ISO installation proof.

Each experiment retains `failure-reproduction.json`, `lifecycle.json`, original
initialization captures, readiness/functional records when reached, a full
`failure-report.json`, `failure-report.txt` and one readable report per expected
target under `evidence/targets`. Blocked and missing checks remain counted. Stage
timings distinguish unexecuted work from measured time. New reference pipelines
also retain `pipeline-timings.json`; no before/after runtime speedup is claimed.

The new complete-reference request contract requires initialization evidence and
a consistent terminal lifecycle result in addition to the original strict
component replays. The stock twenty-target operation is now version 2 and requires
twenty initialization/configuration receipts before helper readiness, inventory
and full validation. Original version-1 runtime evidence remains historical at
its tested source, with its requirements unchanged.

## Earlier tested increment

Implementation revision: `ba9d1a23ac591a122c0d0b3017d5c5a80afc31db`.
Review branch: `codex/WORM-001-failure-reproduction`.
[Draft PR 27](https://github.com/TheSlayer455/jake-wormhole/pull/27) is the review
boundary; the full rebuild is not complete and has not received independent review.

| Execution | Observed result |
| --- | --- |
| Windows, CPython 3.12.14 | 805 tests: 532 passed, 273 platform skips; 121.339 seconds |
| Linux nonroot, CPython 3.12.3 | 805 tests: 795 passed, 10 explicit skips; 100.214 seconds |
| Repository hygiene and original acceptance index | Passed on both environments; original 83 rows/16 evidence files preserved |
| [Hosted PR workflow](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40419128433) | Successful source suite, controlled parity, diagnostic validation and artifact upload at the implementation revision |
| Manual controlled parity | Fresh checkout per mode; observed process exits 0/1/1 for all/required-failure/unexpected-success; all diagnostics staged |
| Manual versus hosted semantic records | plan.json, results.json and decision.json matched byte for byte for mode all at the same revision; downloaded archive matched the provider digest |
| New mixed-twenty regression | Nineteen ready target fixtures plus one authentication failure: zero catalog dispatches and all 200 required rows retained as blocked |
| New Docker/SSH/Ansible/scale/publication acceptance | Not executed: retained project runtime store inaccessible to the available operator |

Commands were `python -B scripts/verify_repository.py`,
`python -B scripts/verify_acceptance_matrix.py`,
`python -B -m unittest discover -s tests -v`, and
`python -B scripts/run_ci_parity.py --mode MODE` (python3 on Linux).
The intentionally failing parity modes remained nonzero; they were not new
intentionally red hosted jobs. Raw test logs and the parity comparison are in
private engineering evidence, outside Git. Hosted artifacts contain only the
existing five validated synthetic projections.

The first full-suite predecessor at `3791ca4` failed on both platforms because the
new twenty-target test selected a five-target helper fixture. The correction
reuses the existing twenty-target policy fixture; runtime limits were unchanged.
Those failure logs remain retained. Source suite timings include seventeen new
tests and are not runtime performance benchmarks or evidence of a speedup.

Self-review covered the dispatch gate, diagnostic ineligibility, earliest failure
retention, restart invalidation, readonly progress and public-tree changes.
Initialization/configuration completion remains explicitly unobserved where the
old receipts do not establish it. No external reviewer or model was contacted.
No containers were allocated by this follow-up; a final read-only Docker query
found no containers carrying Wormhole run labels. Existing private Run/image
state was not adopted, modified or reinterpreted. Source test checkouts/logs remain
retained. A later documentation commit has separate CI and does not relabel these
observations as executions of that commit.

## Remaining execution boundary

The configured homelab operator reaches Docker but cannot read the retained
private project runtime store; passwordless elevation and the available root SSH
route were denied. No bypass or new runtime allocation was attempted. An existing
authorized operator route or accessible project runtime is needed before fresh
Terraform/SSH/Ansible, full-scale and publication acceptance can be established.

The initialization journal, fixed fault adapters, expected pre-authentication
restart recovery and Ubuntu verified reuse are now implemented in the follow-up
commits. The current source verification checkpoint follows below. Fresh focused,
mixed-fleet, twenty-target, reused-candidate and publication runtime acceptance
and equivalent-input performance comparisons remain blocked by runtime access.
The automatic bounded reconciliation path covers contained initialization execs;
it does not override unknown allocation/commit state or claim general recovery
after a whole coordinator crash. UBI cross-Run reuse remains a separate extension.
Preserve stock fleet versus candidate-bound single-target scope. Production ISO
eligibility remains false. No independent review has been claimed.

## Current source verification

Implementation commits add the lifecycle/initialization, immutable Ubuntu reuse,
and fixed fault harness as separate review checkpoints on PR 27. Source fixtures
and mocked Docker observations verify these contracts; they are not new Docker
acceptance results. Tested implementation:
`6a8f7bf46b45f07332d0ca4bb1570aab74149839`. No project containers have been allocated.

| Execution | Observed result |
| --- | --- |
| Windows, CPython 3.12.14 | 840 tests: 564 passed, 276 explicit platform skips; 123.552 seconds |
| Linux nonroot, CPython 3.12.3 | 840 tests: 830 passed, 10 explicit skips; 104.689 seconds |
| [Hosted PR workflow](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40434362622) | Successful full source suite, controlled parity, validated diagnostics and artifact upload at the tested implementation |
| Hygiene and original acceptance index | Passed; original 83 rows/16 evidence files unchanged |
| Actual new Docker/fleet/reuse/publication acceptance and runtime benchmarks | Unexecuted: existing canonical runtime store remains inaccessible to the available operator |

The full-suite commands were `python -B -m unittest discover -s tests` on Windows
and `python3 -B -m unittest discover -s tests -v` on Linux. Repository checks use
the commands above. Source-fixture timings include added tests and are not runtime
performance comparisons. Self-review covered original-byte attribution on reuse,
full readiness admission, initialization priority, bounded reconciliation,
exact-owned stopping, retained trust pins, complete grids and public-tree hygiene.
No independent reviewer was contacted.

At predecessor `a6d5109f7108e332d706be5be7537d97c662f9ef`, manual parity in fresh
checkouts returned 0/1/1 and validated all staged diagnostics. The passing manual
plan/results/decision files matched the hosted artifact byte for byte. The
downloaded ZIP matched the provider digest. That parity comparison is attributed
to its actual revision; the final implementation has its own successful hosted
parity execution, not a relabeled manual comparison.

Private evidence retains the Windows logs, Linux nonroot logs, controlled parity
captures, downloaded synthetic artifact and comparison record. Only source test
checkouts and these logs remain from this work; no new project containers were
observed in the final read-only query. Existing private runtime state/images were
not adopted or modified. Documentation-only commits have separate CI and do not
change the implementation test attribution.

Next authorized runtime step: use an existing operator route that can read the
canonical Run/admission/image receipts, reconcile existing ownership first, then
run focused healthy/initialization/home/key/restart/observer cases, mixed and
twenty-target execution, fresh and reused Ubuntu reference acceptance, and exact
publication. Retain the actual CLI exits, complete grids, cleanup/sentinel proof
and stage timings. Validate Ubuntu and UBI initialization on the real images.
Continue the remaining UBI reuse/recovery extensions only with their original
package/build evidence available; do not weaken the established binding checks.

Predecessor `1c8bd04b1a24c79a2cefe72c860ae2b1273e229f` passed 834 Windows tests
(273 skips; 121.989 seconds). Its Linux nonroot suite and hosted CI caught a
twenty-target replay compatibility defect: the new explicit `mutable_home=false`
input was missing from that replayer's expected variables. The correction accepts
the literal normal default and still refuses the fault-enabled home policy.
Those failed logs are retained privately rather than relabeled as a passing run.
