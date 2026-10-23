# Limited reference pipeline contracts

The `reference-smoke-v1` record family describes one candidate-bound container
target, `target-001`, on either Ubuntu or UBI. It is distinct from the legacy
fixture artifacts and their verification. It excludes optional PowerShell,
multi-target candidate execution and publication. Production ISO eligibility is
always false. A synthetic assessment is not scanner or operating-system STIG
acceptance; the target shares the host kernel.

The pure [`pipeline_records`](../wormhole/pipeline_records.py) module implements
structure, deterministic reports and portable projections. It opens no files,
executes no commands and observes no infrastructure. A structurally valid record
does not prove that its captures, candidate image or admission archive exist.
The pipeline domain must replay original retained plans, component captures,
candidate files, image identity and cleanup/archive evidence before rendering or
making a reference decision. The domain remains authoritative for eligibility.

## Versioned plan and result

The generated [plan schema](../schemas/pipeline-plan-v1.schema.json) and
[result schema](../schemas/pipeline-v1.schema.json) use exact closed fields and
typed JSON. Booleans cannot stand in for integers, and counts cannot replace
result rows. Canonical plan hashing excludes only its own `plan_sha256` field.
The original clean Run identity, policy, plan hash and candidate hashes must
remain consistent across the plan and result.

Because the plan precedes allocation, its SVD target-identity expectation is the
fixed semantic `exact-owned-target-001`. During full SVD export, a passing
semantic row must be backed by the original collector's passing expected and
observed 64-character ID, both equal to the pipeline's independently bound actual
resource. The safe full SVD keeps that actual ID. No other row's expected or
observed value receives this translation.

The fixed plan carries `platform`, `profile:smoke`, `targets:[target-001]`, empty
`capabilities`, candidate hashes and `expected_rows`. Its candidate may be null
only to represent preparation failure honestly. This cannot establish a passing
pipeline. Planned resource IDs are not invented; the result's `candidate` and
`targets` contain the independently observed image and resource identities.

`grid(platform)` defines every required tuple before observations. Each row is
identified by `component`, `scope`, `target_id` and `check_id`. Run-wide checks
have scope `run` and a null target; target checks use scope `target` and
`target-001`. The result must retain the exact ordered plan rows and expected
values, adding observed value, status, reason code, safe explanation and artifact
IDs. Missing, duplicate, reordered, optional or foreign rows are rejected.

| Component | Required rows |
| --- | --- |
| Preflight | Clean source |
| Chunks | Original ordered source-integrity replay |
| Candidate | Exact candidate/image binding |
| Admission | Measured capacity |
| Provisioning | Terraform lifecycle, owned network, target confinement |
| Readiness | All eight declared creation, endpoint, TCP, SSH, Python and Ansible states |
| Functional | Seven candidate checks on Ubuntu; twelve on UBI |
| SVD | Fourteen healthy inventory checks on Ubuntu; twelve on UBI |
| Assessment | All four fixed synthetic findings, bound to this target by the domain |
| Evidence | Original evidence replay |
| Cleanup | Exact owned teardown and finalized admission archive |

These total 43 Ubuntu rows or 46 UBI rows. Stock-image functional checks cannot
replace candidate checks. Complete native SVD package inventories retain full
versions and architectures; helper/build tools and shared-kernel information
remain separate. The ordinary UBI runtime policy's limited AUDIT_WRITE effect
does not imply audit read/control or a change to Ubuntu's capabilities.

Every row is required. Status is one of `pass`, `fail`, `error`, `unreachable`,
`skipped`, `blocked` or `unverified`. A pass requires equal expected/observed
values and a nonempty reference to declared artifact metadata. An earlier
failure leaves later rows explicitly blocked or unverified instead of removing
them. Failure must remain visible in the grid. The first failure and secondary
diagnostic/cleanup failures remain separate fields.

`cleanup` records its own status, pending-resource count, admission-finalized
boolean and archive hash. Reference scope completion and reference eligibility
can be true only with every required row passing, an actual candidate/target
binding, no primary failure or unknown outcome, completed cleanup with no pending
resources, and a finished admission archive. Structural hash presence alone is
not archive proof: domain replay must verify the retained archive bytes. A
successful cleanup cannot turn a failed pipeline into a passing one.

## One record, three formats

The pure API is `schema()`, `plan_schema()`, `grid(platform)`,
`validate_plan(plan)`, `validate_record(record, plan)`,
`render_json(record, plan)`, `render_text(record, plan)`,
`render_junit(record, plan)`, `decision(record, plan)` and
`safe_export(record, plan, svd_record=...)`. Validation returns independent copies.

JSON is canonical ASCII-escaped JSON plus one newline. Text preserves every row,
expected/observed value, reason and artifact reference. JUnit emits exactly one
testcase per planned row, named `component/target-or-run/check-id`. A failed
check becomes a failure; every other required nonpass becomes an error with its
original status retained in properties. Required skipped or blocked work never
produces a zero-error passing suite. Counts are derived from those same rows.
ASCII control characters are rejected and XML metacharacters are escaped.

## Closed portable projections

`safe_export` returns a fixed relative-path-to-bytes map without filesystem I/O:

- `manifest.json`, `plan.json`, `summary.json`, `report.json`, `report.txt`,
  `report.junit.xml`, `checksums.json` and `decision.json`.
- `targets/target-001/readiness.json`, `tests.json`, `svd.json`,
  `assessment.json`, `logs.json`, `observed-svd.json` and `observed-svd.txt`.
- `cleanup.json`.

Per-target component files are explicitly labeled normalized-result-row
projections. The two `observed-svd` files additionally preserve every native
package/key-header, OS, payload, collector, candidate, helper/provisioner and
shared-kernel field from the domain's original replayed SVD record. The pure
layer validates that original with the WORM-015 contract and requires exact Run,
candidate/image/resource and check-grid agreement. It replaces the private
capture path and source evidence paths with explicit logical artifact IDs, keeps
capture hashes/byte counts, and binds the original validated record hash. The
safe JSON file's hash is also shown in its complete readable text projection;
the checksum manifest binds both actual safe files. No raw capture is copied.
If all SVD checks are nonpassing and no collection exists, the fixed files state
unverified with a null record. Any passing SVD row requires a supplied full
record; an empty inventory cannot replace one. The logs projection contains
capture hash/size metadata and explicitly states that raw captures were not
exported. Artifact IDs never become paths or instructions.

Checksums cover all preceding fixed projections, excluding the checksum file
itself and the final decision. The final decision binds the exact record bytes
and checksum-manifest hash. This avoids circular self-hashes. The domain exporter
must verify actual owned single-link source/output files and byte hashes; this
pure map cannot establish safe filesystem ownership or visibility.

Do not recursively copy `evidence` or `private`. Terraform state/plans, keys,
authentication inputs, raw helper/SSHD logs, environment dumps, private host
paths and credential-bearing URLs are outside the projection contract. Fixed
domain-selected safe fields are the primary boundary. A small additional
private-path/credential-pattern check is defense in depth and does not establish
that arbitrary prose is safe to export. Reference publication remains a separate
operation and cannot rebuild or replace the tested candidate.

## Verification and current limits

Run the pure synthetic fixtures with:

```text
python -m unittest tests.test_pipeline_records -v
```

The tests cover both exact grids, each required nonpass, identity/hash/type
tampering, missing and duplicate evidence, early failures, archive/cleanup
consistency, XML escaping/control refusal, identical report rows, the closed
export map and checksum layering. They allocate no infrastructure and supply no
actual runtime or publication acceptance. Complete integration and real
candidate-bound qualification belong to the separately tested pipeline domain.

<!-- WORM-017 actual qualification 753b67d7e550218f28e2f765d3e3abf254c31656 -->
## WORM-017 actual limited reference pipeline

Exact clean source `753b67d7e550218f28e2f765d3e3abf254c31656` completed three fresh actual candidate-bound
pipeline cases, observed at 2026-10-23T20:30:51.544447+00:00. Each healthy Run includes
verified reconstructed source, candidate/image binding, measured admission,
Terraform lifecycle, strict SSH/Ansible readiness, candidate functional checks,
full observed native SVD, the declared synthetic assessment, safe evidence
projections and exact-owned cleanup with a finished admission archive.

| Platform / scenario | Underlying pipeline | Planned rows | Reference eligible | New-process CLI exit | Cleanup |
| --- | --- | --- | --- | --- | --- |
| ubuntu / healthy | passed | 43 | true | 0 | completed |
| ubi / healthy | passed | 46 | true | 0 | completed |
| ubuntu / version-expectation-mismatch | failed | 43 | false | 1 | completed |

JSON, text and JUnit use the same complete row grid and their actual hashes
agree with the reviewed pure renderers. Required blocked/skipped/unverified work
cannot disappear behind zero failures. Healthy native JSON/text samples preserve
all package/version/architecture records, target/collector identity, payload,
helper/provisioner provenance and shared-kernel scope; private capture paths are
replaced by logical IDs. Final checksums bind the actual safe export bytes.
The wrong expected-version case retains `candidate_required_check_mismatch`, failed eligibility and
blocked SVD. Its successful cleanup does not change that primary failure.

homelab_linux: 536 cases, 534 pass/2 explicit skips in 42.934 seconds; windows: 536 cases, 347 pass/189 explicit skips in 58.211 seconds; native_linux: 536 cases, 534 pass/2 explicit skips in 32.393 seconds. Source fixtures remain separate from actual runtime qualification.
Original failed attempts are preserved in history. Independent source review,
publishing/CI and normal Owner acceptance are separate facts. This is the
versioned one-container generated/synthetic reference scope. Production ISO
eligibility remains false; no VM, twenty-target candidate, scanner/STIG or
publication claim is made. See [evidence](../handoff/evidence/WORM-017.json), [history](../handoff/evidence/WORM-017-initial-attempts.json) and
[review](../handoff/reviews/WORM-017.md).
