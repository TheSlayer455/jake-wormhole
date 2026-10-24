# Observed Software Version Description

WORM-015 adds a separate observed-record contract. Legacy fixture `svd-v1`
artifacts and their existing verifier are unchanged. Structural validity and
readable rendering do not establish that a collector ran or authorize a release.
The complete pipeline and production ISO eligibility flags remain false.

The pure API in `wormhole.observed_svd` is:

```text
schema() -> dict
validate_record(record) -> independent validated copy
validate_observation(observation) -> independent validated copy
render_json(record) -> canonical sorted ASCII JSON bytes plus newline
render_text(record) -> deterministic complete text
```

`ObservedSVDError` is a `RunError` with a bounded failure code. These functions
read no files, execute no commands and make no network calls. The domain API
`report_software_inventory(run)` must first re-read the original complete bounded
capture and frozen plan, reconstruct every expected/observed check, and verify
the actual controller/candidate/image/resource/source bindings. It then renders
the same validated record as `svd.json` and `svd.txt`. Editing an observation and
its local checksum is not proof of execution; the original domain replay remains
necessary. Host administrators can rewrite local source and records.

The observed record binds the clean real Run, versioned plan, collector program,
helper/readiness sources, independent target resource/image/candidate identities,
capture metadata, native observation and terminal required checks. The
[published schema](../schemas/observed-svd-v1.schema.json) is generated from the
same definitions. Fixed validation additionally enforces full native ordering,
unique identities, all eight core checks followed by sorted package checks,
candidate file/content hashes and passing-status consistency. A typed boolean
cannot replace a count, epoch or numeric capture field.

The native observation is complete or unavailable; it is never silently
truncated. It is limited to 32 KiB canonical bytes, 2,048 installed package rows
and 16 virtual key headers. The enclosing record is limited to 256 KiB and the
original helper capture to 64 KiB. Exceeding any bound fails. A failed collector
leaves dependent checks unverified and does not become an empty successful
inventory. The domain's fixed target collector must use an absolute deadline
and bounded native query; this pure module does not run that query.

Debian rows preserve bare package name, full native version including epoch and
Debian revision, and architecture. Multiple architectures remain separate. The
collector must select genuinely installed entries, including held-installed
packages, rather than treating every dpkg status-file entry as installed. RPM
rows retain full name/epoch/version/release/architecture and are sorted/unique by
the complete tuple, preserving parallel installed versions. A missing native RPM
epoch may be normalized to zero according to the collector contract. Virtual
`gpg-pubkey` headers are reported separately, with an honest null architecture
where RPM reports none; they are not application package rows.

The fixed payload has four ordered files: `source.synthetic.bin`, `payload.py`,
`version.txt`, `config.json`. Their actual byte counts/hashes, manifest/content
identity and observed version remain in both output formats. The full package
list, every required check and each failed/unverified outcome is rendered. Text
never replaces native version fields with a simplified upstream version.

Helper Python/Ansible and provisioner Terraform/provider versions appear only in
the separate execution-provenance section. Actual target packages remain target
packages even if a similarly named tool is genuinely installed there; tool names
are not guessed or removed. The observed kernel is explicitly host-shared, not
an assertion that a target kernel package was installed. Ubuntu/RPM-derived
container evidence does not establish a complete VM installation, ISO boot,
operating-system STIG or scanner support.

Pure source fixtures cover full Debian and RPM fields, multiarch/parallel RPM
versions, virtual keys, truthful failed-collector output, exact check completeness,
type aliases, ordering, capture/candidate tampering, output bounds, JSON/text
agreement and legacy-contract separation. Actual SSH/Ansible collection,
interruption/replay and resource cleanup remain separate domain/runtime checks;
do not infer those outcomes from these pure fixtures.

<!-- WORM-015 actual qualification 14d510044757f588c256e27c62a0cbad037d7ca1 -->
## WORM-015 actual observed software inventory

Exact clean source `14d510044757f588c256e27c62a0cbad037d7ca1` completed six fresh actual SSH/Ansible inventory
cases, observed at 2026-10-23T19:44:15.537475+00:00. Actual healthy observations contain
ubuntu 123 packages / 10213 canonical bytes, ubi 188 packages / 17538 canonical bytes. Full Debian epoch/revision/architecture and RPM
name/epoch/version/release/architecture are retained. Virtual RPM key headers are
separate. Every full package row and required expected/observed result is present
in the same frozen record used for JSON/TXT. Their exact hashes match the actual
exporter. Helper/provisioner versions and host-shared kernel are separate fields.

| Platform / scenario | Run | Underlying operation | Pass/fail/unverified | Cleanup |
| --- | --- | --- | --- | --- |
| ubuntu / healthy | `61d48412-350e-481f-9ee1-242ec47c37c4` | passed | 14/0/0 | completed |
| ubi / healthy | `63ae38dc-161e-44f1-b5e4-28acc4f0916b` | passed | 12/0/0 | completed |
| ubi / missing-package | `b3d1f1ce-1e3c-4b41-aabe-5db9a197b891` | failed | 12/1/0 | completed |
| ubi / wrong-version | `4ca5fe86-ca16-496d-ac9b-39c772d4b348` | failed | 11/1/0 | completed |
| ubuntu / collector-unavailable | `dd316694-d3d8-48aa-8c0b-1cbb87145fc4` | failed | 1/0/13 | completed |
| ubuntu / wrong-identity | `24695bc7-4e33-4b7a-af31-cc7bb53da71f` | failed | 0/1/13 | completed |

The optional-package negative observes actual absence without installing it.
Wrong-version and wrong-identity are controlled expectations, not target damage
or changed cleanup ownership. Failed collection produces unverified dependent
rows, never an empty successful inventory. Every case preserved its primary,
completed exact-owned cleanup, retained state/images/evidence and passed the
unrelated sentinel check. Private raw helper captures remain private; source-bound
capture metadata and independently checked canonical packet/export hashes are
in the [evidence](../handoff/evidence/WORM-015.json).

homelab_linux: 488 cases, 486 pass/2 explicit skips in 37.066 seconds; windows: 488 cases, 306 pass/182 explicit skips in 47.875 seconds; native_linux: 488 cases, 486 pass/2 explicit skips in 28.913 seconds. These source fixtures are separate from actual runtime acceptance.
Independent engineering source review is clear at the named revision; publication,
hosted CI and Owner acceptance are separate. No complete pipeline, full VM/RHEL
installation, ISO boot, operating-system STIG, scanner or production eligibility
is established. See [history](../handoff/evidence/WORM-015-initial-attempts.json) and [review](../handoff/reviews/WORM-015.md).
