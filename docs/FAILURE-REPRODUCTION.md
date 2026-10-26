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
