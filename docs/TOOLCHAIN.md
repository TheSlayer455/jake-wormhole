# Private Terraform tool preparation

WORM-006 prepares Terraform 1.17.0 and kreuzwerker/docker 4.6.0 for a separate
capped trusted provisioner. It does not execute downloaded binaries, install host
tools, allocate Docker resources or establish a Terraform apply result.

`provisioning/tools.lock.json` pins the original Linux amd64 ZIP bytes and every
member's hash, size and Unix archive mode. The Terraform archive contains its
binary and LICENSE.txt. The provider archive contains its binary, LICENSE,
README.md and CHANGELOG.md; all four remain in the unpacked provider mirror.
These six member pins were derived by streaming the actual previously verified
archives. Terraform's license is BUSL-1.1; the provider's is MPL-2.0. License and
signature metadata retain their public source URLs and hashes.

The lock records **prior** isolated GPG2.4.4 verification on October23,2026,
including signing and primary fingerprints, checksums/signature hashes and the
recorded trust basis. Tool preparation verifies those authenticated archive pins;
it does not rerun GPG. The provider key came from Terraform Registry HTTPS
metadata, without independent identity certification. Its extracted key-material
hash is identified separately from the containing Registry response hash.
Python-derived provider h1 is source-traced metadata only. Actual Terraform init,
h1 enforcement, provider schema and binary execution must be observed in the
provisioner, not inferred from this cache.

## Caller contract

Call `wormhole.toolchain.prepare_toolchain(run)` while holding that real Run's
exclusive operation lock and the measured infrastructure lease. The function does
not acquire the Run lock itself, avoiding a nested lock inside provisioning.
The caller must admit its disk budget before preparation and retain the lease
through allocation. The source checkout must be clean and equal to the Run's
clean container-reference source revision; it is checked again after the worker.

The return value is a dictionary with:

| Key | Value |
| --- | --- |
| root | Path to run/private/toolchain |
| terraform | root/bin/terraform Path |
| mirror | root/mirror Path |
| archives | Tuple of the two retained original archive Paths |
| receipt | Verified dictionary of archive/member hashes, byte accounting, source and prior signature provenance |

Mount root read-only at `/opt/toolchain` in the separate admitted provisioner.
The unpacked provider is at
`mirror/registry.terraform.io/kreuzwerker/docker/4.6.0/linux_amd64`.
No file is installed into host PATH or executed by preparation. Executables are
private mode0500; documentation and original archives are mode0400, below private
0700 directories. The receipt and preparation diagnostic remain private.

## Bounds and failure behavior

One fixed Python worker, in the current source directory, receives only the Run's
canonical workspace and UUID. The existing bounded process executor enforces an
absolute 180-second deadline over all downloads and extraction; expiry terminates
and reaps the worker group. Socket timeouts are supplementary. The worker streams
64KiB chunks, accepts at most 64MiB per archive and 96MiB combined, and requires
exact pinned byte counts and SHA256 before extraction. Its proxy handler is empty;
no ambient authorization, cookies or proxy credentials are used.

Terraform's fixed releases.hashicorp.com URL permits no redirect. The approved
exception for the fixed provider GitHub release URL permits exactly one HTTPS hop
to release-assets.githubusercontent.com. Credentials, non443 ports, fragments,
extra hops and other destinations are rejected. No original headers follow that
hop. Its signed Location/query is temporary request data and is never recorded;
download failures log a generic code rather than a urllib URL/exception dump.

ZIP preflight bounds the central directory to 64KiB and 16 entries before ZipFile
constructs member objects. ZIP64, multidisk, comments and trailing data are refused.
Only the complete pinned ordinary-file set, modes and sizes may be extracted.
Traversal, links, duplicate members, encryption and unexpected compression are
rejected. Decompression streams into exclusive nofollow files, checking expansion
counts and member hashes. The complete cache has a 512MiB ceiling, reserving
256KiB for its bounded receipt. The receipt's cache_bytes counts archive plus
expanded payload, with the separate receipt exclusion stated explicitly.

The parent independently rechecks the exact files/directories, private modes,
streamed hashes, sizes, receipt source and original pins before returning paths.
Partial private cache and bounded diagnostic codes survive failure. Preparation
refuses any existing cache rather than silently retrying it; use a new Run after
the failed attempt is accounted for. JSON provenance and a passing fixture do not
substitute for actual provisioner execution, h1 validation or lifecycle evidence.

Verification: `python -m unittest discover -s tests -p test_toolchain.py -v`.
Tests use generated labeled ZIP fixtures, not the downloaded executables. Linux
tests exercise actual private files, streaming extraction, links, archive attacks,
parent tamper rejection and the actual worker deadline. Windows skips the POSIX
filesystem fixtures. No test installs host tools or calls Docker.
