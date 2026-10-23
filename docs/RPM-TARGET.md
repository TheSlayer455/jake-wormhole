# UBI target work

WORM-014 first adds a fixed base observation operator. RPM assembly, candidate
binding, SSH/Ansible package checks and four-case runtime qualification are still
unimplemented by this increment. The existing Ubuntu recipes and defaults are
unchanged. A fixture pass is not an actual UBI result.

On the explicitly approved Linux host, root reviews the source before invoking:

```text
python -B -m wormhole.rpm_target probe --sentinel-id EXACT_UNRELATED_CONTAINER_ID
```

This creates a fresh canonical smoke Run with a stable kernel lock and the shared
admission lease. The pinned official UBI9 linux/amd64 manifest and its complete
inherited labels are checked. A needed pull has a durable materialization intent,
finite client timeout and retained image identity. Docker's shared-daemon pull is
not claimed to have an operation-specific hard cgroup cap.

One ordinary probe container uses the admitted build CPU/memory/swap/PID/rotated
log limits, no network, read-only root, UID0, all capabilities dropped, no new
privileges, private namespaces and two bounded tmpfs mounts. Its sole bind is a
hash-bound copy of this repository's fixed public probe, readable under a private
host umask. It receives no Docker socket, repository, key, credential or host state
mount. No package is installed, resolved or downloaded; no repository is loaded.

The controller verifies the never-started container and actual live cgroups before
a fixed release marker permits collection. The Python PID1 has an explicit45s
alarm handler and stays alive for bounded stdout collection, avoiding stopped
tmpfs archive behavior. The report is at most48KiB and records the actual base RPM
database's full NEVRA tuples, Python/RPM/DNF API facts, fixed executable presence,
os-release fields and fixed key/license file metadata. Computed OpenPGP primary
fingerprints identify bytes; signature verification remains **not performed**.
The separately labeled shared kernel is not an installed UBI/RHEL kernel package.

The controller retains the original bounded capture and its hash in private Run
storage, removes only its exact inspected container, verifies empty Run-label
container/network/image/volume sweeps, compares the unrelated sentinel and
finishes admission. The pulled base image and evidence remain intentionally
retained. A known probe failure keeps its primary error even after cleanup.
Unknown pull/create/start/exec/stop/remove outcomes preserve the active journal;
no timeout, empty sweep or boolean assertion clears them. This increment does not
provide generic interrupted-operation recovery.

`probe_base(run, lease)` is the caller-held library form: the caller already owns
the Run lock, Docker scope and real canonical admission lease. It cleans its
container but leaves the lease held for later reviewed phases. A new attempt must
use a fresh Run; the public operator cannot reopen a finished admission.
`read_base_observation(run)` replays a successful saved receipt against its exact
private capture and unchanged probe/lock recipe. A newer clean controller may read
those facts with original Run/source provenance; this does not authorize old-run
allocation or treat historical measurements as current capacity.

The lock records official public manifest/config and BaseOS metadata observed on
October23,2026. Package closure, actual installed base facts, signing-key trust,
license retention, resource observations and SSH/Ansible behavior require later
review and actual execution. No subscription channel, host package change, VM,
ISO boot, full RHEL, scanner, STIG or production acceptance is claimed. Production
ISO eligibility and runtime-pipeline completion remain false.
