# Completed directory delivery to existing acceptance

This increment validates an already delivered ISO. Discovering a private source
build/Forge contract is a separate task and is not a prerequisite for this path.
The first supported contract is the existing RHEL 10.0 BIOS baseline: 8 GiB RAM,
two vCPUs, 32 GiB empty disk, separate run-scoped Kickstart seed, final key-based
SSH and declared passwordless baseline sudo. It is not hardened or qualified.
Ubuntu intake and arbitrary team installation contracts are not implemented here.

## Verified experiment

Runtime-tested source: [`0a6acb5754a943562a9e425288704cae928afa60`](https://github.com/TheSlayer455/jake-wormhole/tree/0a6acb5754a943562a9e425288704cae928afa60).
[Intake implementation](https://github.com/TheSlayer455/jake-wormhole/blob/0a6acb5754a943562a9e425288704cae928afa60/wormhole/intake.py),
[existing VM hook](https://github.com/TheSlayer455/jake-wormhole/blob/0a6acb5754a943562a9e425288704cae928afa60/wormhole/vm_baseline.py),
[seed preparation](https://github.com/TheSlayer455/jake-wormhole/blob/0a6acb5754a943562a9e425288704cae928afa60/wormhole/rhel_inputs.py)
and [focused tests](https://github.com/TheSlayer455/jake-wormhole/blob/0a6acb5754a943562a9e425288704cae928afa60/tests/test_intake.py)
are pinned separately from [PR 42](https://github.com/TheSlayer455/jake-wormhole/pull/42)'s delivered/merged documentation.

| Case | Observed evidence |
| --- | --- |
| Completed manual delivery | Fresh Terraform/KVM installation, all six checks passed, trusted SSH/Ansible, 413 unique RPM records and native assessment; 247.755 seconds |
| ISO present without completion marker | Real local-ext4 timer scan returned no requests and created no VM |
| Completion arrives | The same timer/scan function registered and launched exactly one controlled-failure request |
| Notification during execution / timer restart | Same supervisor; duplicate scan refused while its request lock was held; no second run |
| Failed acceptance | 236.396 seconds; SSH passed, completion-marker access failed, four dependents blocked; exact-owned cleanup completed |
| Subsequent timer reconciliation | Five service starts (empty, execution, repeats), one launch acknowledgment, four outputs of the same terminal failed request |
| Same filename/new bytes; changed assessment; explicit retry | Real-file focused fixtures registered separate identities while preserving earlier records; no additional VM claim |

Both real runs attached identical delivered ISO bytes, used distinct fresh seeds,
had `candidate-intake` and no `candidate-build` stage, and cleaned up. Native audit
retains all 948 outcomes: 172 pass, 261 fail, 56 not applicable, nine not checked,
450 not selected; scanner exit 2 remains visible. Baseline success does not grant
qualification. The negative case deliberately changed marker access in the owned
guest; it diagnoses the readiness boundary, not a new defect in delivered media.
An independent engineering agent read the private controller/native records and
rehashed retained media. It did not rerun these installations.

The test timer/service was stopped after reconciliation. The experiment's extra
producer copy was removed only after exact identity/ownership proof; canonical
media, completion manifests, requests and runtime evidence remain private.
Normal intake never deletes producer files. No work infrastructure was accessed.
Final existing storage cleanup deduplicated the retained run copy. Project data
occupies 69.441 GiB/100 GiB, candidate cache 27.945 GiB/40 GiB, with 115.630 GiB
filesystem space available. Both journals are finished, no domains remain and
Docker/K3s are active. Capacity must still be remeasured before future allocation.

Source verification: 965 passed, three explicit skips (968 total), 85.514 seconds.
Run the seven focused cases with
`python -B -m unittest discover -s tests -p test_intake.py -v` on Linux. They cover
distinct copy, cache, completion, contention, interruption, identity and seed
boundaries using existing fixtures/locks; mocked dispatch is not VM evidence.

## Producer and operator contract

Run `python -m wormhole intake contract` to obtain the supported declaration and
its digest. The producer writes the ISO completely, closes/syncs it, then writes
this JSON to a temporary filename and atomically renames it to `release.ready.json`
**last**. Use the actual filename, byte count, ISO SHA256 and contract digest:

```json
{
  "schema_version": "1.0",
  "iso": "team-delivered.iso",
  "bytes": 8464236544,
  "sha256": "<actual-delivered-ISO-SHA256>",
  "contract_sha256": "<digest-from-intake-contract>"
}
```

These placeholders are not valid input values. A quiet size/mtime interval is
not completion. Missing markers are ignored; wrong size/hash/contract is refused.
The manifest selects only a supported contract, never executable controller code.
The delivered boot entries must already discover the declared seed. Intake does
not remaster the ISO, change the team recipe or repair the installed guest.

Use the established authorized runtime owner and private paths outside Git:

```sh
python -m wormhole intake register /private/inbox/release.ready.json
python -m wormhole intake submit REQUEST_SHA256 --terraform /private/tools/terraform
python -m wormhole intake scan /private/inbox --submit --terraform /private/tools/terraform
python -m wormhole.vm_baseline --status RUN_UUID
```

The first command registers a durable request/run identity; the next submits that
exact request. Scan calls those same functions. Intake verifies an independent
private copy, or reuses an already protected candidate after existing ownership,
reconciliation and hash proofs. It never hard-links writable producer data.
Producer files are not cleanup-owned. Missing cache origins or changed staged
bytes are refused. All copies and guest allocation use existing storage/admission
budgets; no additional host capacity or relaxed limit is assumed.

Request identity includes ISO bytes, the installation contract, acceptance-code
fingerprint, native scanner content/profile, policy and generation. Repeated
notifications/restarts observe the same run. Same filename/different bytes is a
new candidate. New acceptance content or explicit `--generation retry-2` permits
a new attempt without overwriting the old one. This does not waive host admission:
an unresolved earlier run still requires existing recovery.

## Monitoring and recovery

Check the actual inbox filesystem with `findmnt -T /private/inbox`. The example
[service](../../examples/intake/wormhole-intake.service) and
[timer](../../examples/intake/wormhole-intake.timer) invoke a periodic scan, with
paths to adapt privately. They are examples, not installed services. A timer does
not start a second copy of its already-active service; the shared runtime lease
also coordinates manual invocations and other backends.
The example has no timeout for the whole sequential batch; every VM retains its
existing absolute execution deadline. A short service-wide timeout must not kill
a later valid request simply because an earlier request consumed its allowance.
[systemd.path](https://www.freedesktop.org/software/systemd/man/latest/systemd.path.html)
uses inotify and cannot reliably detect changes made by another machine on remote
NFS. A local path event may shorten latency, but it must invoke the same scan.
Periodic reconciliation remains appropriate for missed events and remote storage.

Dispatch intent precedes execution. Known tool/admission refusal stays retryable;
a disappeared dispatcher with uncertain launch remains unknown and is not
automatically resubmitted. Inspect the recorded run and use the existing exact-run
recovery command before any retry. Stop the project timer/service to roll back
monitoring; retain candidate/request/run evidence. Do not destroy unknown guests.

Private request records are in the canonical runtime's `intake/requests`; their
run IDs refer to existing `vm-runs` results, console evidence, native assessments
and cleanup records. Baseline success is separate from qualification, which stays
false. Failed readiness retains the cause, blocks dependents and returns nonzero.
No new publisher or parallel qualification decision is introduced.

## Luna adaptation

Inspect the real delivery-completion convention and installation contract first.
Map only the supported team profile, firmware, access, seed and external inputs;
do not substitute this home Kickstart for the team's customization. Keep the
existing Terraform/Ansible controller and release policy. Prove one unchanged
delivered ISO from the **ansible control node** against the **rhel kvm host**,
then incomplete delivery, repeat notifications, known failure and recovery.
Home Ubuntu-host/local-ext4 evidence does not prove RKE2-to-remote-host routing,
NFS notification behavior, scanner rights or the team's release qualification.
