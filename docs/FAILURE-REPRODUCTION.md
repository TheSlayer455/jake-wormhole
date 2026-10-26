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
| Creation versus readiness | Shared eight-observation contract now serves readiness, admission reporting and pipeline records; access does not establish separate initialization/configuration completion |
| Incomplete fleet readiness | Confirmed gap: batch validation previously dispatched a ready subset. Normal validation now dispatches no catalog unless every required target passes revalidation |
| Safe subset diagnostics | Existing negative acceptance now explicitly selects diagnostic subset mode; it retains the full result grid and cannot pass fleet acceptance |
| Initialization failure | An observed nonzero target exit before authentication is classified at runtime initialization; exact cause still requires original diagnostics |
| Restart during partial readiness | A changed actual container start invalidates cached observations before more probes; trusted host-key pins are retained. Automatic expected-restart recovery is still pending |
| Deadlines and terminal reporting | Existing readiness windows and owned process bounds preserved. Batch validation accepts only a shortening inherited deadline and persists invocation scope, timing and outcome |
| Observer lifecycle | Shared classifier distinguishes progress, stalled execution, verified terminal results, confirmed stopped cancellation and unknown state; it does not operate a remote supervisor |
| Candidate freshness | Construction input fingerprint added. Manifest/bundle checks reject changed inputs. Verified image reuse across Runs still requires a separate implementation; comparison alone cannot skip a build |
| Reporting | JSON and readable per-target progress derive from the same records. Missing checks stay missing, blocked rows remain counted, and unobserved initialization stays unknown |
| Failure scenarios | Existing wrong key/user, host-key change, interpreter, delayed/never-start, mixed Ansible and cleanup scenarios remain. New source regressions cover strict fleet admission, early exit, partial-readiness restart and expired inherited deadline |
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
image identity, Run attribution and artifact checks still apply, and actual build
reuse remains unimplemented.

## Tested increment

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

Remaining engineering includes an observed target initialization/configuration
journal, deterministic container fault adapters for account/home/key/hardening
failures, expected restart recovery, verified candidate reuse, measured focused
and mixed-fleet runs, and runtime performance comparisons. Preserve the original
stock fleet versus candidate-bound single-target distinction. Production ISO
eligibility remains false. No independent review has been claimed.
