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

## Encrypted workstation archive

Use `python3 -m wormhole storage archive-preview` as the established runtime owner
to inspect eligible objects without transferring them. On the workstation, run
the same checkout in Linux/WSL with age installed and the existing strict SSH route:

```sh
python3 -m wormhole storage archive-sync --config /home/operator/.config/wormhole/archive.json
python3 -m wormhole storage archive-sync SHA256 --config /home/operator/.config/wormhole/archive.json
python3 -m wormhole storage archive-verify --config /home/operator/.config/wormhole/archive.json
python3 -m wormhole storage restore SHA256 --config /home/operator/.config/wormhole/archive.json
```

Replace `SHA256` with the complete object digest. Default sync processes pending
objects and eligible local copies restored since archival. Existing ciphertext is
reread rather than uploaded again; an explicit digest also requests revalidation.
Verification also accepts a digest. Restore requires one digest and refuses an
existing destination; it does not overwrite retained runtime files. Restore before
admission when a candidate is needed: admission/alias resolution never downloads
data while holding the shared lock. Candidate aliases can use any verified
restored copy of their recorded bytes.

The private workstation JSON has this shape (replace all example values):

```json
{
  "archive_id": "00000000-0000-4000-8000-000000000001",
  "root": "/mnt/c/PrivateArchive/Wormhole",
  "identity": "/home/operator/.config/wormhole/archive.agekey",
  "recipient": "age1REPLACE_WITH_PUBLIC_RECIPIENT",
  "ssh": ["ssh", "-i", "/home/operator/.ssh/lab", "operator@lab-hypervisor.invalid"],
  "command": "sudo -n env PYTHONPATH=/srv/wormhole python3 -m wormhole storage",
  "reserve_bytes": 10737418240,
  "timeout_seconds": 900
}
```

Provision config and identity as owner-only Linux files (0600), outside the
archive. Pre-enroll the SSH host identity; the client requires batch authentication
and strict host-key checking. Provision the Windows archive ACL for the owning
user and SYSTEM only. Its `owner.json` must contain `schema_version: "1.0"` and
the matching `archive_id`; changed/missing ownership or symlink paths are refused.
The runtime owner's private infrastructure `archive-config.json` contains
`schema_version`, the same `archive_id`, and `keep_local_digests` for current inputs.
Neither configuration contains private key material or other embedded secrets.

Eligible terminal-run candidates and console/Terraform apply/cleanup logs may be
reclaimed after verified archival. Native assessment XML/HTML copies are archived
but retained locally. Source ISOs, current-input pins, keys, Terraform state,
journals, unresolved runs and qualified artifacts stay outside reclamation.
Existing key/seed expiry remains unchanged. The 100/40 GiB budgets are unchanged.

The workstation pulls plaintext through SSH directly into age; only encrypted
objects and nonsecret receipts are stored in its archive. It decrypts the stored
ciphertext and checks the original size/hash before committing. That fresh commit
alone authorizes existing ownership-safe cleanup under a new shared lock. Old
receipts, queued work or an offline workstation never authorize deletion. Partial
files are ineligible; corrupt verification refuses restore and reports failure.
No Windows inbound listener is required. A separate 30-minute/sign-in Task Scheduler
task is installed using a limited interactive account, IgnoreNew and no wake request.
It runs the same `archive-sync` command, with a bounded pass; the runtime queues
work while the PC is off and preserves local copies until a later verified pass.
This encryption does not establish
BitLocker protection or a private-key recovery/backup policy.

Actual strict-SSH/NTFS proof at `b881127`: a 6 MiB probe and a 2,136,473,600-byte
historical Ubuntu ISO were encrypted, read back, reclaimed locally, restored and
verified byte-for-byte. The ISO archive/reclaim took 76.997 seconds; restore took
64.319 seconds and restored mode 0640. Revalidating existing ciphertext and
reclaiming the restored copy took 53.377 seconds, without another upload.
At `61f91d9`, a real unavailable SSH endpoint, interrupted 256 MiB transfer,
retained partial/retry and damaged disposable ciphertext exercised failure paths.
None authorized unverified deletion. The scheduled pass exposed unnecessary
whole-catalog preview/queue work per object; `33f2ea0` restricts fresh-commit
cleanup to those verified objects using the same deletion engine. Its real
6 MiB restore/reclaim passed. Bounded scheduled passes completed all 194 objects
(18,033,375,417 original bytes; 18,037,815,785 encrypted bytes). A later scheduled
pass completed with zero transfers. Managed allocated storage fell from 69.447
to 63.469 GiB, a 5.978 GiB net reduction; the current inputs, protected journals,
native assessments and unresolved evidence remain local. Candidate storage is
21.976 GiB. This is archive retention and verified recovery, not an independently
established backup/key-recovery policy. No new VM installation was needed to prove
this storage-only increment.
