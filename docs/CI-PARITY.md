# Controlled manual and CI parity

The versioned `wormhole.parity` runner exercises existing chunk and synthetic
assessment APIs, then reads their original reports. It provisions no containers,
performs no admission and needs no homelab credentials. Its seventeen cases are
twelve local/loopback chunk scenarios and five assessment scenarios. Historical
real container qualification remains in the [acceptance matrix](acceptance-matrix.md).

Run from a fresh clean checkout with CPython 3.12.14 and Git:

```text
python3 -B scripts/run_ci_parity.py --mode all
python3 -B -m wormhole.parity validate --output ci-artifacts
```

The wrapper is the same fixed command in manual, GitHub and authored GitLab jobs.
It observes the core's real child-process return code, preserves nonzero status,
validates five projections and stages only validated bytes. Existing `ci-safe` or
`ci-artifacts` paths refuse before execution; use a separate fresh checkout per
mode. Do not overwrite interrupted outputs to make them appear complete. The core
uses fresh current-user-owned fixture storage outside Git and verifies exact
ownership, marker and tree scope before cleanup.

| Mode | Required decision / process exit | Controlled observation |
| --- | --- | --- |
| `all` | passed / 0 | All seventeen expectations, original report replays and cleanup succeed |
| `required-failure` | failed / 1 | The actual rejecting assessment is deliberately required to pass; its rejection remains visible |
| `unexpected-success` | failed / 1 | The actual healthy assessment is deliberately expected to reject; its success cannot satisfy that negative expectation |

Each case retains four checks, underlying status, content hashes, chunk order and
sizes, findings/applicability and cleanup. Per-case exits are explicitly **domain
CLI contract mappings**, not seventeen observed subprocesses. `execution.json`
records a **computed runner return code** before termination. The outer wrapper,
manual observer and provider job supply actual process/job observations. Validation
proves complete safe records and returns zero even for a recorded failed decision;
it cannot change the original runner/job failure into success.

Exactly five canonical JSON files may be staged/uploaded: `plan.json`,
`results.json`, `decision.json`, `execution.json` and `checksums.json`. Closed typed
contracts, complete grids, original-record hashes, byte bounds, checksums and
ordinary-file checks reject incomplete, edited, linked or unsafe data. No raw logs,
private inputs, state, environment dump or credentials are artifacts. The schema
is [parity-export-v1](../schemas/parity-export-v1.schema.json).

At the same exact source revision, compare the first three files byte for byte
between separately executed modes of the same name. Only four named case fields
normalize: run ID, update time, duration and loopback port. Source, expectations,
actual results, domain values and cleanup remain. Runner/Python, original-record
hashes and actual IDs stay in separate execution metadata. Different environments
must not be relabeled as one execution.

GitHub uses pinned actions, read-only repository permission, disabled credential
persistence, full history for original-source proof fixtures and explicit PR-head
checkout. One job owns verification through diagnostics, with a ten-minute limit
and 300-second controlled-child ceiling. Fixed push branches
`codex/WORM-021-required-failure` and `codex/WORM-021-unexpected-success` select
genuine red controls; other branches run `all`. Diagnostics validate after a failed
step. The uploader receives five literal paths only after validation. There is no
`continue-on-error` or failure suppression.

The JSON-subset `.gitlab-ci.yml` targets an existing `wormhole-python31214` runner
with CPython 3.12.14/Git already installed. One job uses the same checks/wrapper and
staged diagnostics, with `allow_failure: false`; it installs no runner/interpreter.
Local structural checks are implemented. Official GitLab lint and runner execution
remain unperformed; authorship does not establish compatibility in an unobserved
environment.

Frozen-source manual/hosted results and reviews belong in WORM-021 evidence after
execution. This document alone claims no hosted success, deployment, publication
or owner acceptance. Reference and production ISO eligibility stay false for
every controlled parity outcome.
