# Runtime acceptance and delivery

Tested implementation: `f8e5f0ef8f3764617516f5716840fcbb751589f6`.
Delivery: [PR 28](https://github.com/TheSlayer455/jake-wormhole/pull/28).
Later documentation and merge revisions retain this test attribution. Original
ticket evidence is unchanged. Review consists of self-review and execution;
independent approval is not claimed.

## Access and reconciliation

Prior session records identified the established WSL service-operator identity
and its authorized escalation to the private store owner. The default client
identity used in earlier attempts was different. Authentication, effective owner,
canonical admission status and exclusive flock were verified without changing
keys, accounts, permissions, services or the runtime root.

Before allocation, all 105 historical admission archives were finished, the
current journal had no pending resources, and all 31 recorded retained images
were present. Raw receipts, commands, identities and logs remain private.

## Confirmed repairs

- Failed functional/deadline outcomes incorrectly erased previously observed
  Ansible-ready counts. Reports now retain the observed conditions; a restart
  still invalidates them. Fresh deadline/playbook failures verified the correction.
- Image reuse failed with `intent_required`. The adapter now reserves the existing
  assembly/materialization phases before registering verified retained images.
  A real admission-lease regression covers the previously permissive test double.
- Live UBI metadata no longer matched the approved pins. The bounded source
  worker now reuses only hash/size-matching public input bytes from retained Runs.
  Pins, offline resolution, RPM signature checks and installed-package checks
  remain required. Twelve pinned source files were reused in the fresh UBI build.
- Known UBI source-preparation failures left admission active despite completed
  resolver cleanup. The outer controller now recognizes the source-bound resolver
  receipt before assembly begins; unknown outcomes or pending resources still
  block completion. A fresh missing-base negative verified automatic cleanup.

The first failed UBI attempt was separately reconciled at its original source
through the existing resolver cleanup and resumed admission APIs. Its receipt
proved no allocation intent had been reached; absence of containers alone was
not the proof. The original failure/unknown report remains preserved alongside
the later scoped reconciliation evidence. No failed attempt was relabeled green.

## Actual execution

| Contract | Observed result |
| --- | --- |
| Fresh Ubuntu at merged predecessor `01b1e80` | Real Terraform, Docker, initialization, strict SSH/Ansible, functional checks, native SVD and gate; 43/43 passed |
| Ubuntu reuse across reporting/controller revisions | 43/43 passed, original image identity retained, no builder |
| Fresh UBI at tested implementation | 46/46 passed, offline resolution/signatures/install and native SVD observed |
| UBI reuse | Same image and tested artifact identity, 46/46 passed, no builder |
| Installed-input change | Isolated committed configuration/payload change produced a new cache key; old candidate was not selected; zero allocation |
| Version mismatch | Actual candidate check failed; failed gate and publication rejection retained |
| Twenty simultaneous stock targets | 160 readiness, 200 functional and 200 inventory checks passed; twenty complete 123-package inventories |
| Mixed twenty | Nineteen initialized/authenticated/Ansible-ready, one initialization failure; all 200 functional rows blocked, none missing, no catalog dispatch |
| Interrupted initialization coordinator | Only the exact owned process was killed; normal recovery read durable evidence, retained `coordinator_interrupted`, cleaned resources and did not resume acceptance |
| Existing isolation suite | Overlap, interrupted run, interrupted publication and synthetic oversized-capacity refusal all passed |
| Local Ubuntu/UBI publication | Exact tested files and original manifests preserved; completion inspection passed; duplicate and failed-run publication rejected |

All nineteen fixed `reproduce` scenarios executed at `01b1e80`: healthy,
initialization-command-fails, account-missing, home-inaccessible,
authorized-key-missing, hardening-breaks-home, wrong-key, port-briefly-opens,
restart-during-readiness, never-ready, ready-late, interpreter-unavailable,
playbook-fails, controller-deadline, remote-unknown, candidate-stale,
source-chunk-corrupted, required-evidence-missing and cleanup-error. Every
experiment met its expectation with cleanup complete and the sentinel unchanged.
Expected negatives retained nonzero exits. These runtime adapters and target
programs are byte-identical at the tested implementation; the changed reporter
was independently re-exercised by fresh negatives and the current mixed fleet.
Where used, simulated identity, stale-input, installation and cleanup outcomes retain their
existing labels; they are not proof of OS installation or host hardening.

Actual commands used existing `reference-run`, report/gate, `reproduce`,
`twenty-check`/report/gate, `recover`, `isolation-check`, publication initialization,
`publish-reference` and `publication-status` interfaces, plus a private controlled
coordinator-interruption operator composed from the existing ownership APIs.
No replacement orchestration or permission subsystem was introduced.

A later CLI recovery request for an older completed Run correctly returned
`resume_mismatch` after admission had moved to another Run. The current journal
and original completed cleanup were preserved; stale state was not adopted.

## Source verification

| Environment | Total | Passed | Skipped | Seconds |
| --- | ---: | ---: | ---: | ---: |
| Windows CPython 3.12.14 | 867 | 585 | 282 | 152.202 |
| Linux runtime owner, CPython 3.12.3 | 867 | 865 | 2 | 112.922 |

Both used `python -B -m unittest discover -s tests` (verbose on Linux).
Repository hygiene, original acceptance index and diff checks passed.
[Hosted implementation CI](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40455121591)
passed the source suite, controlled parity and diagnostic checks. Focused cache,
source, controller-cleanup and reporting regressions preceded runtime retries.
The first cleanup regression fixture had a missing mock import; that fixture
error was corrected before committing. Source fixtures are not runtime proof.

## Measured runtime

| Operation | Elapsed seconds |
| --- | ---: |
| Ubuntu fresh / reuse | 52.9 / 49.6 |
| UBI fresh / reuse | 61.3 / 57.7 |
| UBI construction / reuse integrity stage | 16.1 / 4.2 |
| Twenty stock acceptance, CLI total | 199.2 |
| Twenty provisioning: created / started | 24.4 / 13.1 |
| Twenty initialization / readiness | 4.4 / 102.1 |
| Twenty functional / inventory / cleanup | 12.4 / 16.4 / 14.8 |
| Mixed twenty, CLI total | 163.4 |
| Isolation suite | 153.0 |
| Ubuntu / UBI publication | 1.5 / 7.6 |

Readiness was the measured scale critical path. Reuse avoided builders and
resolution while preserving immutable identity; these are individual observations,
not guaranteed speedups or cross-machine benchmarks. Resource samples covered
all 22 live owned containers; point measurements are not guaranteed peaks.
Existing lifetimes, concurrency, resource limits and evidence margins were kept.

## Resource and scope disposition

Final audit: 140 finished admission archives, zero project containers or networks,
zero pending resources, 33 receipt-recorded retained images independently present,
canonical lock available, unrelated sentinel unchanged from the initial baseline.
Private failed attempts and intentionally incomplete publication directories
remain retained. No unrelated workload or host security configuration was changed.

Stock twenty-target acceptance remains separate from candidate-bound single-target
acceptance. Assessments remain explicitly synthetic; publication is a private
local reference bundle, not a container image, customer release or qualified ISO.
Production ISO eligibility remains false. No runtime-access blocker remains.
