# Storage lifecycle

Use the established private runtime owner on Linux:

```sh
python3 -m wormhole storage status
python3 -m wormhole storage preview
python3 -m wormhole storage clean
```

These commands use the shared infrastructure lock. Preview is read-only; clean
rechecks journals, hashes, ownership, live resources, mounts and open files.
There is no arbitrary deletion-root argument. Unrelated homelab storage, including
the media backing image, is outside scope.

The post-run managed footprint budget is 100 GiB, including protected evidence;
the reusable candidate cache budget is 40 GiB for the combined Ubuntu/RHEL lab.
The measured retained Ubuntu candidates occupy 28.2 GiB; one RHEL DVD candidate
adds 7.9 GiB. The 100 GiB total and 90% projected filesystem ceiling remain.
The initial RHEL baseline reserves its full 32 GiB disk, one streamed candidate
output and evidence; it extracts only small boot files. Ubuntu retains its full
64 GiB disk and existing three-media build allowance. Identical ISOs share one verified
copy through durable run aliases. Candidates whose recorded installed source
inputs demonstrably differ from the current clean checkout may be evicted.
Original reports, manifests, SVDs and native assessment output remain. Unresolved
and qualified runs are pinned. No evidence or candidate is evicted by age.
Baseline candidates without sufficient freshness metadata remain protected.
If protected retention exceeds the budgets, builds are refused, not evidence.

After evidence reporting and verified teardown, the VM pipeline automatically
cleans package staging, extracted boot files and detached seeds. Run keys/passwords
and identity staging expire once no guest disk remains. Unlinking is not physical
erasure on SSD/CoW storage; necessary sensitive evidence remains private. Recovery
uses the same cleanup after confirming stopped operations and exact-owned resource
absence. New builds record intent before construction so partial outputs can be
reconciled; legacy unmanifested partials remain protected.

Scanner builds retain their tool archive, package/version inventory and logs;
source/build/stage regular intermediates can be cleaned after their finished
admission and output are verified. Unsafe links/ownership protect affected paths.
Terraform continues to handle exact-owned domains, networks, pools and disks.
Storage cleanup does not destroy libvirt resources, prune Docker, alter host
permissions or delete releases. Promotion takes the same lock and revalidates
exact bytes. Reusing an evicted stale candidate fails explicitly.

VM preflight cleans before reservation. Its peak estimate includes three source
sizes for extraction/remastering/output, the full 64 GiB guest disk and 1 GiB for
evidence/support data. Existing source bytes are already in measured usage.
Container/scanner admission applies filesystem projection to its existing resource
plan. At 80% usage the admission record warns; projected usage above 90% or
insufficient availability refuses allocation. Existing memory/CPU/disk margins
remain enforced. Active or unreconciled admission is never bypassed.

Status uses allocated blocks, deduplicated by device/inode, with separate
filesystem availability. Docker shared image layers remain under existing image
policy and are excluded from path accounting. Sparse logical disk capacity is
not reclaimed space. Private cleanup receipts record intent/completion, original
inode signatures, reasons, unlinked blocks and observed availability delta. Other
writers and metadata allocation can make that delta differ from removed blocks.
An interrupted prepared receipt never asserts deletion completed: retry checks
actual files and durable aliases again.

Keep receipts and operational paths private. `tests/test_storage.py` exercises
corruption, active refusal, links, sparse accounting, stale/pinned candidates and
interrupted cleanup. These source fixtures do not establish ISO qualification.
