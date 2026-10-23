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
