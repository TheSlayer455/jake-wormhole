# Optional PowerShell helper (WORM-011)

This capability is explicitly selected and separate from the ordinary helper.
It adds no PowerShell package, source, provider or hook to the host or target.
The original seven image recipe files and ordinary helper pins remain unchanged.
There is no automatic fallback and no scanner invocation.

## Verified source investigation

Observed October 23, 2026: the official [PowerShell 7.6.8 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.8)
was published October 22. Source revision is
`6e29e4530c5631b6d3d2afacb49c6f1267fb0b42`. The selected universal amd64
Debian package is 55,409,518 bytes; its downloaded SHA-256 matches the release
and [committed lock](../capabilities/powershell/lock.json). Read-only `dpkg-deb`
inspection confirmed package `powershell`, version `7.6.8-1.deb`, architecture
amd64 and installed size 182,641 KiB. No downloaded program was executed on the
host during investigation.

[Microsoft's installation guidance](https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu?view=powershell-7.6)
documents the universal Debian package and Ubuntu 24.04 support. Its example
version was older than the observed release; it is not copied as an unpinned
installation script. No Microsoft package repository is registered. The
upstream container Dockerfile's stale preview default is not used.

The package declares libc6, libgcc1, libgssapi-krb5-2, libstdc++6, zlib1g, an ICU
alternative and an SSL alternative. The existing hash-pinned Ubuntu snapshot
indexes were independently downloaded and matched all three original main-index
hashes. They show `libgcc-s1` provides libgcc1 and `libssl3t64` provides libssl3.
The separate recipe adds exactly `libicu74=74.2-1ubuntu3.1`, whose 10,860,078-byte
snapshot package and SHA-256 are pinned. All other dependencies must already be
satisfied by the exact qualified helper image. `dpkg` validates that actual
closure; failure remains unavailable rather than fetching alternative packages.

PowerShell's [MIT licence](https://github.com/PowerShell/PowerShell/blob/v7.6.8/LICENSE.txt)
and third-party notices remain installed from the original package. Read-only
archive inspection recorded hashes of the packaged licence, notices and `pwsh`
binary. There was no detached release signature, and the source tag was reported
unsigned; this is TLS/SHA-256 verification, not a claimed signature verification.

## Build and execution boundaries

The optional variant starts from exact qualified ordinary helper image
`sha256:4f7f306ecd431b4b48169777966d88c1f09f2139506176a6b85203f5bae69a71`,
original build Run `9e864d00-ea9f-4a85-bdb5-f5873166e4d7` at source
`244ea4b8961fa3be5ca82c122f95a1bd776c210d`. Both that original provenance and
the new variant recipe/source/image identity are retained. Building does not
relabel or replace the original image.

One fixed preparation worker downloads only the two reviewed URLs, with a
64 MiB per-file limit, 80 MiB total cache limit and 180-second whole-operation
deadline. One GitHub-to-release-assets HTTPS hop is allowed only for the exact
PowerShell release URL; original headers are discarded and signed redirect URLs
are never persisted. ICU uses the fixed Ubuntu snapshot URL. Parent code checks
the exact cache names, sizes and hashes again. The ordinary image downloader's
16 MiB limit is unchanged.

Builds hold the existing Run lock and canonical admission lease. They use an
ordinary capped builder: 2 GiB, 2 CPU, 256 PIDs, bounded rotated logs, no network,
no Docker socket, no privileged mode and only exact read-only recipe/artifact
mounts. The recipe installs two local hash-verified packages without APT feeds.
Its PID1 becomes a fixed 580-second timeout with a five-second kill grace.
Actual cgroups, sampled storage headroom and stopped writable-layer size are
checked before commit. Shared-daemon commit work remains admitted overhead,
not a claimed hard-capped daemon. The immutable variant is retained separately.
Commit completion is bound to a previously absent unique Run tag and actual
immutable image inspection. Bounded Docker diagnostics are retained privately;
they are not parsed as the image ID. Truncation or an incomplete request keeps
the outcome unknown. Later smoke selection derives original build labels from
the clean build Run and current recipe hashes, then checks linux/amd64, the exact
ordinary-helper parent, unique tag, non-root entrypoint/configuration and telemetry
opt-out. Receipt-supplied labels cannot establish that provenance.

Smoke and missing-package probes use the helper budget of 512 MiB, 1 CPU and
128 PIDs, no network, UID10001, a read-only root, dropped capabilities, no socket
or port publication, bounded tmpfs and a fixed 60-second PID1 supervisor. Only
the missing-package probe mounts two public source files: mode0444 files under
a private0700 Run directory, bound by exact path, inode, owner, mode and hash.
There are no host credentials or key mounts.

The PowerShell smoke uses a fixed `-NoLogo -NoProfile -NonInteractive` command
that returns actual PowerShell/.NET versions and a deterministic arithmetic
result. Telemetry opt-out is set before launch. It also verifies the ordinary
helper doctor and actual dependency versions. This demonstrates only that this
selected container can run that PowerShell command.

## Missing-package fixture and independent diagnostics

The missing case uses the ordinary helper image, an empty local APT sources
file/source-parts directory, empty package status and lists, and network-none
confinement. A fixed noninstalling `apt-get -s install powershell=7.6.8-1.deb`
must fail with exit100 and the package-unavailable diagnostic. Its receipt names
the package, expected version and execution location. It cannot silently use an
installed package database, public feed, proxy or replacement source.

That failed capability operation remains failed after exact cleanup. The ordinary
helper doctor is recorded independently, but it is not Terraform/SSH evidence.
Acceptance must additionally run fresh ordinary Terraform/SSH/Ansible functional
diagnostics and retain their distinct Run IDs/evidence after the isolated failure.
Unit fixtures simulate those subprocess responses and do not claim a real image
build, PowerShell smoke, APT/container execution or SSH acceptance.
Known-ID cleanup can resume after durable absence reconciliation or an interrupted
archive-first lease finish. It re-proves actual absence before skipping an already
absent journal entry, preserving the original failure. An absent entry with a live
container, dirty/fixture original Run, or unknown outcome is refused.

## Operator interface

These commands require a new clean-source real Run at the canonical runtime
Runs root, the existing measured admission policy and authorized Docker access.
They allocate owned containers only when explicitly invoked by that operator:

```text
python -m wormhole.powershell missing-package-fixture --run-id RUN_UUID
python -m wormhole.powershell powershell-helper --run-id BUILD_RUN_UUID
python -m wormhole.powershell powershell-helper --run-id SMOKE_RUN_UUID --build-run BUILD_RUN_UUID
python -m wormhole.powershell recover --run-id FAILED_RUN_UUID
python -m wormhole.powershell_acceptance --sentinel-id EXACT_EXISTING_64_HEX_CONTAINER_ID
```

The acceptance operator records four fresh, serial operations: missing package,
ordinary real Terraform/SSH/Ansible functional diagnostics, optional offline
build, then a fresh optional PowerShell smoke. It checks the unchanged unrelated
sentinel and exact clean source between every stage, requires distinct Run IDs,
and stops before the next allocation after an unexpected or uncertain outcome.
Its compound checkpoint is `evidence/powershell-acceptance.json` in a separate
coordinator Run. A negative case can pass acceptance while its component remains
failed. This operator must be reviewed before actual host execution.

Each command uses its own Run. Exit0 means a completed optional build/smoke;
exit1 means the expected dependency-unavailable operation is still failed;
exit2 means refusal/error. The component receipt is
`evidence/powershell-capability.json`; logs and download artifacts remain private.
Original failure and cleanup failures stay separate. Known owned IDs can be
reconciled by the original clean source. Unknown create/start/commit/remove
outcomes remain blocked; recovery cannot adopt IDs, allocate replacements,
clear uncertainty or change an admitted plan. No global cleanup is performed.

PowerShell execution does not prove Evaluate-STIG controller, transport or target
compatibility. There is no authorized scanner package or documented compatible
method, and no production-system policy or scanner invocation is invented. Production
ISO eligibility and complete-pipeline claims remain false for every outcome.

<!-- WORM-011 actual capability 88c8df01c38986fb909b3cfe231a97081f790bc1 -->

## Actual capability qualification

On October 23, 2026, the four-stage operator passed at clean `88c8df01c38986fb909b3cfe231a97081f790bc1`. The isolated missing-package operation remained failed while a fresh ordinary Terraform/strict SSH/Ansible Run passed all ten functional rows. Offline build and a separate no-network, read-only UID 10001 helper smoke observed PowerShell 7.6.8 Core/Unix, .NET 10.0.13 and fixed result 2. Dependency versions and the original helper doctor passed, with all seven original image recipe inputs unchanged.

Retained image: `sha256:7cbb64abd73f3a91b4d8d17a5f825902302e0fa772b88a1c3d66ec8aaa56b737`. Actual builder cgroups were 2 GiB/2 CPU/256 PIDs; probe cgroups 512 MiB/1 CPU/128 PIDs with no extra swap. Known owned containers were reconciled and the suite sentinel unchanged. Linux homelab source fixtures: 258 cases, 256 passed, two Windows-only skips, 11.361 seconds. Windows writer fixtures: 258 cases, 149 passed, 109 platform skips, 8.346 seconds. Source fixtures are separate from actual runtime evidence.

This proves only the explicitly selected fixed PowerShell container command. Scanner compatibility remains unavailable. The [portable evidence](../handoff/evidence/WORM-011.json) records sanitized child receipts and package/file hashes. Raw captures, credentials, state paths and downloaded packages remain private. Publishing, final CI and Owner acceptance are separate facts.
