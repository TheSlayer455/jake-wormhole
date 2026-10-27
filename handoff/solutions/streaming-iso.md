# Streaming ISO reconstruction with interrupted-output recovery

**Signature:** source media exceeds fixture-sized limits, reconstruction is
interrupted, or chunks are missing, corrupted or ordered incorrectly.

**Prerequisites:** authorized ISO and independently verified whole-file SHA256;
Linux owner-private external storage with space for source, chunks and output.
The actual experiment used official Ubuntu 22.04.5 amd64 media. RHEL media was not
available; no RHEL/GitLab-specific behavior is established.

**Established mechanism:** fixed-size reads and content-addressed chunk objects
bound memory independently of ISO size. Ordered offsets bind reconstruction to
the manifest. Durable prefix checkpoints are rehashed before reuse; incomplete
uncheckpointed tails are discarded. Only the complete verified file is promoted.
This is an independently developed solution, not a diagnosed work-environment bug.

**Pinned source and tests:**
[implementation at 6e1920f](https://github.com/TheSlayer455/jake-wormhole/blob/6e1920fffca0e0c5e6826cbc274d2d5f4851b372/wormhole/media_store.py),
[regressions at the same revision](https://github.com/TheSlayer455/jake-wormhole/blob/6e1920fffca0e0c5e6826cbc274d2d5f4851b372/tests/test_media_store.py).
The later chunk-count bound reduction is a source correction, not a claim to
have rerun the original experiment at a later revision.

```text
python -m unittest discover -s tests -p test_media_store.py -v
python -m wormhole media-split /private/source.iso --store /private/chunks --sha256 APPROVED_SHA256
python -m wormhole media-assemble /private/chunks/manifests/SHA256.json --store /private/chunks --output /private/reconstructed.iso
```

**Observed:** 2,136,926,208 bytes / 32 chunks; split 3.71 seconds, 26,144 KiB peak
RSS. The owned reconstruction child was terminated after one committed chunk;
no final ISO existed. A subsequent identical invocation resumed that chunk and
produced the approved whole-file hash in 4.39 seconds at 26,656 KiB peak RSS.
Five Linux streaming fixtures and one manifest fixture passed. Corruption,
missing/reordered chunks and changed checkpoints fail without final promotion.

**Luna task:** inspect the existing artifact adapter on **ansible control node**,
adapt only streaming/prefix-verification behavior that is missing, retain the
approved registry/authentication and manifest design, then exercise it from the
real helper/runner. Do not assume a local Ubuntu filesystem test establishes
GitLab registry semantics or **rhel kvm host** behavior.

**Success/failure/recovery:** success is exact byte count and whole-file identity,
never ISO qualification. Failure leaves no promoted output. Preserve partials,
checkpoint and original manifest, reconcile the interrupted operation, and retry
the same invocation. Changed inputs require a new output/manifest. Do not delete
unowned files or silently adopt a mismatched partial. An interruption before a
complete checkpoint pair exists requires explicit inspection; automatic recovery
of every possible crash point is not claimed.
