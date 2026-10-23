# Bound synthetic reference candidates

WORM-013 adds an explicit candidate path. The stock Ubuntu target, its original
image recipe and the separate trusted stock provisioner remain the defaults.
This source has synthetic policy/collector tests; actual Docker/SSH/Ansible
qualification must identify its clean tested commit and fresh Runs separately.

The input is WORM-012's generated `.synthetic.bin`, not installation media.
`chunks.execute_fixture(run)` owns its Run lock and must complete before the
caller acquires that lock for candidate operations. `prepare_candidate(run)`
requires the passing chunk report and `verified_source(run)`, rehashes the source,
and creates one fixed private bundle. The bundle contains that binary, original
`candidate/payload.py`, software version and configuration plus a canonical
manifest. The [published schema](../schemas/candidate-manifest-v1.schema.json)
comes from `wormhole.candidate.schema()`. Unknown paths, extra files, links,
changed bytes and incomplete/failed chunk results are refused.

`build_candidate(run, lease, bundle=None)` requires the caller's held Run lock,
Docker scope and real canonical smoke admission. Its offline ordinary builder
uses the existing immutable qualified stock target as its base, no network,
no socket/authentication mounts, dropped capabilities, no-new-privileges and the
reviewed build memory/swap/CPU/PID/log/deadline limits. It installs only the four
fixed files under `/opt/wormhole/reference`; the stock runtime and SSH configuration
are unchanged. Source, installer and bundle hashes are checked before creation,
before commit and after materialization. Actual cgroups, installed-file hashes,
sampled writable-layer size and disk headroom must be observed.

The daemon commit is a bounded admitted operation, not a hard-capped shared
daemon. One unique Run tag is inspected after its completed request; mixed
Docker diagnostics are never parsed as an image ID. Exact image/parent/config/
labels prove the result. The image is journaled as retained, the exact builder
is removed and reconciled, and the lease remains in materializing for the
normal forward transition to provisioning. Unknown create/commit/stop/removal
outcomes preserve the journal and prevent further allocation or normal cleanup;
no generic reviewed boolean clears them. A known installation failure can stop
and remove only its exact identified builder, preserving its primary failure.

`ProvisioningSession(..., target_binding=None)` keeps the stock default.
An explicit candidate binding must match the same Run's saved complete bundle,
build receipt, retained-image journal and actual immutable image. Only the target
uses that image; the socket-mounted Terraform provisioner uses the original
stock image. `target_image_id` and `target_image_labels` keep these identities
separate. The private controller stores `target_binding_version:1` plus the exact
binding. Original-source destroy-only recovery revalidates that record without
requiring reconstructed data to authorize cleanup. Original stock contexts are
not migrated or silently reinterpreted. Candidate execution starts with one
Ubuntu24.04/linux-amd64 target; this increment grants no twenty-target credit.

`CandidateValidationSession(readiness, binding, scenario='healthy')` uses the
existing capped Docker-free helper and strict SSH/Ansible readiness. It freezes
the exact source/chunk/bundle/image/Run/resource/test-contract/collector identities
before probing. The additive fixed `candidate-functional-v1` request uses the
already hash-bound validation source mount. It never accepts commands, paths or
URLs. Seven required rows cover userland applicability, source/manifest/payload
hashes, software version, configuration and a fixed functional result. The
authored payload is executed only after its exact expected hash matches.

The response requires the original one-host structured callback, terminal
completeness and bounded private raw capture. `report_candidate_validation(run)`
rechecks the original capture and reconstructs all rows before producing JSON
and readable output. Wrong candidate/image identities refuse; the fixed
`version-expectation-mismatch` scenario retains actual observations and fails
the version criterion and overall primary outcome. Unknown helper exec outcomes
block normal scoped cleanup. Functional failure never rewrites established
readiness or claims that transport failed.

No ISO bytes are processed/repacked/uploaded, and no boot, installation, RHEL,
scanner or operating-system STIG result is established. This is an original
synthetic source bundle copied into a derived Ubuntu reference image. The full
pipeline and production ISO eligibility remain false; reference publication is
a separate later gate. Private generated inputs, authentication, state, logs and
images are retained according to their explicit ownership and evidence records.

## Explicit qualification operator

After exact source review, the approved-host operator may invoke
`python -m wormhole.candidate_acceptance --sentinel EXACT_UNRELATED_CONTAINER_ID --all`.
`--case` selects only one of the four fixed cases: healthy, wrong-candidate,
wrong-image or version-expectation-mismatch. It accepts no URL, image override,
command, public registry destination or arbitrary input bundle.

Each case creates fresh generated chunks/bundle/image/Run under the same measured
canonical lease. Identity negatives demonstrate refusal before Terraform/helper
allocation, then prove exact builder absence/retained image plus empty Run
container/network sweeps. Full healthy/version cases use genuine Terraform,
strict SSH readiness and Ansible, then normal WORM-008 cleanup. Negative
underlying outcomes remain failed. Private captures/state, retained candidate
images, credential scans, disk samples and unchanged unrelated sentinel checks
are recorded. Unexpected failure stops the suite and preserves unresolved
resources; existing exact-source recovery may safely reconcile known established
provisioning, while unknown image/daemon work remains blocked. The operator's
presence and mocked tests are not an actual acceptance result.
