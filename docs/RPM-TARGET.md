# UBI target work

WORM-014 adds a fixed base observation operator and an explicit offline RPM
candidate builder and validation path. The fresh base probe passed at source
be55565 on October23,2026:188 RPM headers, unchanged os-release ID=rhel and
VERSION_ID=9.8, Python3.9.25, DNF4.14.0 and RPM4.16.1.3. OpenSSH components were
absent. This identifies a pinned UBI9-derived container userland, not a full RHEL
installation. RPM assembly/signature and SSH/Ansible qualification of the new
candidate remain unverified until the separate actual acceptance runs finish.
The existing Ubuntu recipes and defaults are unchanged; fixtures are not runtime
acceptance.

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

The first actual probe at01fe92b failed before creating a container: Docker29's
containerd image store reports the pinned manifest digest as image `Id`, while
the original lock mistakenly used the upstream config digest. The corrected
contract distinguishes those identities and checks the exact Docker descriptor,
repository digest, complete inherited labels and platform. Failed historical
receipts remain unchanged. Future pulls persist their terminal client result and
bounded capture before image validation. This does not itself clear an unknown
operation or authorize adoption in a resumed admission.

The read-only key observer computes v4 (SHA1) and v6 (SHA256) primary fingerprints
as specified by [RFC9580](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4).
It does not verify a signature, choose an installation trust anchor, or declare
that a bundled key was observed until the actual probe returns its facts.

## Explicit RPM candidate

`wormhole.rpm_candidate.build_rpm_candidate(run, lease, base_run=...)` requires the
canonical real smoke Run lock, Docker scope and held admission. The caller first
uses the existing verified chunk reconstruction and `candidate.prepare_candidate`.
The original Ubuntu source manifest remains provenance. A separate UBI manifest
declares the actual supported platform, fixed package NEVRAs and its own checks.
The ordered four-file table has a shared content identity; all four original file
bytes are copied unchanged. Ubuntu and UBI installation manifests have different
hashes. Neither manifest silently changes applicability to match an observation.

The source worker resolves the exact fixed BaseOS transaction in a network-none,
read-only, capped container using the actual base RPMDB and pinned metadata.
It allows no removals, weak dependencies, plugins or ambient repositories. A
separate bounded HTTPS worker fetches only that validated package set. The
offline builder checks each file's exact bytes/hash, verifies real RPM signatures
using a dedicated container-local RPM database and only the two primary keys
observed in the actual base's exact ordinary key file. Digests alone, missing keys,
bad signatures or unsupported verification fail. It does not preemptively import
other signing keys or suppress signature errors.
The installed record retains each original signature-check output (at most4096
UTF8 bytes), its SHA256 and the strict integer return code. The controller checks
that capture again before accepting the installed record; a digest alone is not
the reviewable signature evidence.

The builder applies the exact same closed transaction from local files with
local-package GPG checks, runs a real dependency check, observes installed full
epoch/version/release/architecture tuples, creates the fixed public-key-only
account and installs the unchanged generic target runtime/SSH configuration.
The optional original runtime doctor remains Ubuntu-specific and is not used as
an RPM qualification. No systemd PID1, host service, subscription media, arbitrary
repository, package removal, `--nodeps` or `--nogpgcheck` is supported.

The unmodified official [UBI EULA](https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf)
is independently pinned at248785 bytes and SHA256
`a07025b9f5b71a816febe6ac76f21c9f759c806fa0a66874af90a50c3293f1b6`.
The worker retains it privately and the builder copies the exact bytes to
`/licenses/ubi9-container/UBI-EULA-20190422.pdf` with mode0444. Existing component
licenses and inherited image terms remain. This explicit input avoids claiming
the initial fixed-path probe found an embedded EULA when it did not.

An ordinary network-none builder uses the existing build resource profile and
reviewed package-install capabilities, with one active build at a time. The
controller verifies stopped configuration, actual cgroups and a fixed release
handshake before installation. The unchanged generic PID1 supervisor owns a600s
lifetime. Writable-layer size and shared storage headroom are sampled before
start, during execution and before commit; these are not a quota or reservation.
Commit uses a fresh owned tag plus inspected immutable image/configuration proof,
not a hash guessed from mixed CLI output. Unknown mutations retain admission.
Commit overrides only fixed project labels with bounded identifier values.
Inherited UBI labels, including descriptions with spaces, stay in container
configuration and the resulting image must preserve their exact values.
The base and derived image remain retained; the exact builder is reconciled.
Builder identity is passed only to the fixed PID1 process with `/usr/bin/env`
and a validated canonical Run UUID, so it is absent from Docker `Config.Env`.
Both stopped-builder and final-image checks require the fixed clean environment.
The final runtime uses the same two-element Python entrypoint and `target` command
as the unchanged strict Terraform target policy.

The first actual candidate case at71878d1 built the image and passed the two
signature checks, dependency check and exact EULA retention. It then failed
`unsafe_target` before SSH/Ansible qualification and completed known scoped
cleanup. The inspected image retained builder-only `WORMHOLE_ROLE` and Run
environment variables; those conflict with the target's strict environment gate.
Its three-element entrypoint/empty command also disagreed with that policy, though
Terraform already overrides those values. The correction removes the inherited
builder environment and aligns image layout; a fresh actual run is still required.
The original failed Run and signature captures remain historical evidence.

The fixed binding operation `ubi9-candidate-image-binding` uses private controller
layout version2. The existing Ubuntu binding remains version1 and stock defaults
are unchanged. Terraform manages the target and its lifecycle. The trusted
provisioner keeps its separate stock image, fixed socket/mounts and limits. Exact
original-source recovery validates the recorded platform binding without
executing reconstructed candidate data; no generic image override is introduced.

The later actual ce3ec10 attempt reached SSH but the retained server log reported
`linux_audit_write_entry failed: Operation not permitted`. Known scoped cleanup
completed and the original failed capture remains unchanged. A separate
`cleanup_exit: kill(...)` error was secondary; it does not authorize another
capability. The UsePAM warning did not establish an authentication-policy defect.

Only an already validated UBI binding now selects the fixed typed
`ubi9-ssh-audit-write-v1` target policy. It adds `AUDIT_WRITE` to `SETGID`, `SETUID`
and `SYS_CHROOT`; the stock and Ubuntu candidate policy keep their existing three
capabilities. Exact generated Terraform inputs, the saved-plan gate, stopped/live
container checks, private controller metadata and recovery evidence must agree.
No CLI or mutable capability list grants this policy. Original failed Runs use
their original source and are not converted to the new policy.

`AUDIT_WRITE` permits records in the shared kernel audit log, a real effect beyond
the container filesystem. It does not grant audit read/control or alter host audit
settings. The bounded target lifetime, exact owned calls, resource limits and
remaining confinement stay in force. No `AUDIT_CONTROL`, `AUDIT_READ`, `KILL`,
privileged mode, host setting, PAM or algorithm change is included. See the
[Linux capability reference](https://man7.org/linux/man-pages/man7/capabilities.7.html)
and [Docker capability documentation](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities).
This source correction still requires a fresh actual SSH/Ansible qualification.

## Read-only RPM validation

`RPMValidationSession(readiness, binding, scenario=...)` uses the existing fixed
Docker-free helper, strict SSH trust and actual Ansible command/callback path.
The authored target collector reads full RPM NEVRAs and all four candidate file
bytes and executes only the hash-matching authored payload. It retains original
captures and recomputes JSON/text rows from them. Missing/duplicate fields, changed
capture bytes, source/image/plan mismatches, incomplete events, unexecuted
functions and unknown helper execs cannot become passing evidence.

The healthy plan has12 required checks:actual userland, four package tuples and
seven source/manifest/content/payload/version/configuration/function checks.
Three fixed fresh negative scenarios preserve their failed underlying outcome:

- `missing-optional-package` adds a13th required openssh-clients check only after
  the final installed record proves the optional package absent; no package is
  removed or installed to manufacture the result.
- `version-expectation-mismatch` freezes an explicitly wrong openssh-server
  version expectation and preserves the real observed package version.
- `unsupported-os` declares Ubuntu24.04 applicability against actual UBI9.8.
  The userland check fails, four RPM checks remain unverified and the independent
  seven candidate/content observations are retained. No runtime repair or
  applicability override is attempted.

Structured unreachable, skip and collector errors keep their actual category;
they are not relabeled as observed OS/version mismatches. The normal scoped
cleanup preserves the first failure and exact historical IDs. A four-case root
operator still must qualify these paths against an unchanged unrelated sentinel;
this document does not establish that it has run. No twenty-target, VM, boot,
scanner, STIG, complete-pipeline or production acceptance follows from this work.

<!-- WORM-014 actual qualification db5d8e74f54483a909faaed963c752962785653c -->
## WORM-014 actual RPM reference qualification

Exact source `db5d8e74f54483a909faaed963c752962785653c` completed four fresh actual UBI9.8-derived cases,
observed at 2026-10-23T19:09:20.242487+00:00. The healthy case retained twelve passing
checks. Missing optional openssh-clients retained twelve pass/one fail; the wrong
version expectation retained eleven pass/one fail; unsupported Ubuntu applicability
retained seven pass/one fail/four unverified RPM checks. These negative harnesses
passed by observing the intended failed underlying operation.

| Scenario | Run | Underlying operation | Primary failure | Cleanup |
| --- | --- | --- | --- | --- |
| healthy | `d473d988-f7d7-469f-95a1-2689295311fb` | passed | none | completed |
| missing-optional-package | `2948e601-9239-40f8-b681-8afd4b3c9903` | failed | rpm_missing_package | completed |
| version-expectation-mismatch | `86a24145-481c-4c96-aab0-7c8bccc37621` | failed | rpm_version_mismatch | completed |
| unsupported-os | `0274e785-d0f9-4382-8186-3d7326c61e22` | failed | rpm_applicability_mismatch | completed |

The fixed public BaseOS solve selected two RPMs. Actual isolated RPM verification
retained both original successful signature outputs and hashes; offline installation,
dependency checks, full package NEVRAs and the exact unmodified UBI EULA were
observed. The same four candidate file bytes retain one content identity across
separate UBI manifests/images. The stock helper and trusted provisioner remain
separate. The validated UBI binding selects exactly SETGID, SETUID, SYS_CHROOT and
AUDIT_WRITE; this permits owned authentication audit records in the shared kernel
audit log. No audit read/control, KILL, PAM or host-setting change is established.
Ordinary Ubuntu keeps its original three-capability policy. Ordinary Ubuntu regression Run `f623e6ca-858b-4f10-9311-0bfbe2a1028c` passed all ten
functional checks with readiness, normal cleanup and unchanged unrelated sentinel.

Source fixtures: Windows 454 cases, 276 pass/178 explicit skips
in 35.432 seconds; homelab Linux 454 cases, 452 pass/2 skips
in 33.834 seconds; native Linux 454 cases, 452 pass/2 skips
in 25.661 seconds. Source fixtures are separate from actual runtime acceptance.

Earlier failed image/probe, resolver and target-environment attempts remain failed
in history. Their cleanup/reconciliation does not rewrite their original outcomes.
The initial unknown pull receipt stayed unchanged; its separate positive-image
reconciliation did not mutate Docker or adopt resources. The 718 build had genuine
signature/EULA success but failed provision. The 66 retry passed provision/TCP
and then refused SSH authentication. The ce3 diagnostic retry also failed SSH;
its original bounded server log recorded audit-write EPERM. Successful diagnostic
capture does not turn that failed SSH result into a pass. All remain failed.

Exact owned containers/networks are absent, base/derived images and private evidence
are retained, and unrelated sentinel checks passed. Actual cgroups bound project
processes; daemon materialization and sampled storage are stated separately.
No full RHEL VM, ISO boot/install, scanner/STIG, complete pipeline, production
eligibility or owner acceptance is established. Publication and hosted CI remain
separate observations. Refresh Minx for current requirements and decisions.

See [evidence](../handoff/evidence/WORM-014.json), [history](../handoff/evidence/WORM-014-initial-attempts.json) and [engineering review](../handoff/reviews/WORM-014.md).
