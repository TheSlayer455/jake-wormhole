# Private reference artifact publication

WORM-018 adds a separate Linux local publication operation after the reference
pipeline. This document describes the implementation contract. Actual acceptance
results belong in the source-bound WORM-018 evidence record when qualified.

The output is a **WORMHOLE REFERENCE ARTIFACT**: the four exact tested generated
candidate files, their original candidate manifest, the sixteen validated safe
reference evidence files, a fixed reference notice, and the unchanged pinned UBI
EULA for UBI. It does not publish an image, registry package, remote release or
validated ISO. Simulation remains explicit and production eligibility is false.

From the reviewed clean source on approved Linux storage:

```text
python -B -m wormhole publication-init
python -B -m wormhole publish-reference RUN_UUID
python -B -m wormhole publication-status RUN_UUID
```

The release store is fixed at `/srv/homelab/jake-wormhole/releases`. Initialization
is explicit and refuses an unrelated existing directory. A release is uniquely
named `reference-RUN_UUID`. There is no CLI destination, URL, fault hook or
arbitrary command option. The compatibility `--workspace` publication argument
accepts only the fixed real-run storage; local fixture workspaces cannot publish.

The publisher owns the Run lock and then the stable publication-root lock. It
replays the same clean source, original candidate and evidence, finished admission
archive and strict reference gate. Failed, stale, malformed, missing, foreign or
incomplete evidence refuses publication. It repeats validation before completion.
Publication does not build the candidate again, run Docker or change the original
safe reference exports.

Copying uses a bounded closed file table and ordinary owned single-link files.
Files are created exclusively with private permissions; copied bytes, sizes and
hashes must match the original tested sources. Existing complete or incomplete
destinations refuse a retry rather than being overwritten. Checksums cover copied
files and the reference notice; the completion manifest binds the checksum bytes.
There is no circular self-checksum.

`COMPLETE.json` is the last logical commit marker. A pending marker, extra entry,
wrong hash, unsafe file or transient two-link marker is incomplete. Readers verify
the closed tree and original evidence without repairing it. File and directory
fsync results are separate producer observations: an inspection does not invent
historical power-loss durability. A process can die after a logically complete
commit but before acknowledging its receipt. That is distinct from a process
interrupted before a valid completion marker.

Private per-attempt receipts remain in the selected Run's private storage. A
failed publication does not replace its pipeline's primary failure or erase
earlier evidence. Keep incomplete releases for exact inspection and reviewed
recovery; elapsed time does not authorize their deletion or reuse.

Private visibility is limited to the observed Linux filesystem and identities.
The acceptance harness checks owner access and an actual bounded child process
that drops to the existing unprivileged identity and receives EACCES. This does
not establish remote image/release visibility or protection from a host
administrator. Windows publication is unsupported by this implementation.

The actual acceptance entrypoint creates fresh same-source runs for Ubuntu and
UBI completion, duplicate refusal, a controlled publisher-child interruption in
the marker-link window, and a failed reference pipeline that cannot publish:

```text
python -B -m wormhole.publication_acceptance --sentinel-id EXACT_CONTAINER_ID --base-run QUALIFIED_UBI_BASE_RUN_UUID
```

Only an authorized operator supplies those verified identifiers. This command
performs bounded project-owned container work; it is separate from the fixture
suite. Its expected negative cases pass only when the underlying publication
remains refused or incomplete. Original pipeline outcomes, exact-owned cleanup,
private evidence and the unrelated sentinel observations remain attributable.
