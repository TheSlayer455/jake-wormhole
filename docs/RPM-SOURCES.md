# Fixed UBI sources and offline resolution

WORM-014 source preparation downloads only the pinned public UBI 9 BaseOS
metadata and selected RPMs. It does not install host tools, import host keys,
load subscription repositories, execute packages or allocate containers.
The explicit driver owns canonical admission, exact container configuration,
runtime bounds, original capture provenance and cleanup.

`rpm/lock.json` is the source of the exact repository pins. The fixed HTTPS
origin is `cdn-ubi.redhat.com`, without a proxy, redirect, alternate mirror,
credentials or provider fallback. All eight metadata objects referenced by the
pinned repomd are retained under a private Run cache. Compressed bytes and their
declared expanded bytes are stream-hashed within separate limits. XML documents
with entities/DOCTYPE declarations, changed repomd contracts, extra cache files,
unlisted architectures and unsafe relative paths are refused.

One fixed Python worker has an absolute 180-second whole-operation deadline,
including slow-progress downloads and decompression. Socket timeouts supplement
that owned-process deadline. Metadata is limited to 16 MiB per file/32 MiB total,
expanded metadata 32 MiB per file/128 MiB total, RPMs 64 MiB per file/512 MiB total,
128 selected RPMs and 256 KiB resolution JSON. Downloaded RPMs remain inert bytes.
Package signature verification and installation must happen separately inside
the reviewed offline builder; SHA256 metadata checks do not claim GPG validation.

## APIs and mounts

Call public cache APIs while holding the current Run operation lock and the
driver's appropriate admission budget:

```python
metadata = prepare_metadata(run, lock)
request = resolve_request(run, lock, observed, base_run=original_probe_run)
resolved = validate_resolution(run, original_resolver_capture, request, lock)
packages = prepare_packages(run, lock, resolved)
```

`resolve_request` calls the existing strict `read_base_observation` API. The
supplied body must match its original complete capture. An earlier probe Run
retains its original source revision/capture/recipe hashes; its finished lease
is never reopened. The new driver must create a fresh Run/admission for actual
resolver or build operations. Current lock/probe recipe bytes must still match.

The fixed `rpm/resolve.py` uses only `/recipe/lock.json`,
`/request/resolve.json` and `/metadata/repodata/*`. The driver mounts the current
source read-only, the exact request read-only at that fixed path, and the
validated metadata directory read-only at `/metadata`. It sets the exact
`WORMHOLE_RUN_ID`, runs as root in the bounded owned UBI resolver with no network,
no Docker socket, no capabilities and bounded writable tmpfs. No path or code
is accepted through an argument. Runtime DNF/RPM availability remains a probe
fact; the module does not install missing tooling.

The resolver creates `dnf.Base` without reading ambient config/repository files
or initializing plugins. It explicitly disables weak dependencies, registers
only the fixed local file repository, and compares the actual RPM database with
the captured base snapshot, including key pseudo-packages. It requests exact
NEVRAs and calls `resolve(allow_erasing=False)` only. Removal/replacement sets
are refused. It never calls package download, key import or `do_transaction`.
Selected package records must match the pinned primary metadata, exact
architecture/size/hash/repository and complete requested set. An unresolved or
changed transaction is a failure; no alternate package source is invented.

`validate_metadata`, `validate_resolution` and `validate_packages` recheck
original pins before use. The parent must also bind the resolver capture to its
exact owned container/source/request and refuse incomplete or unknown daemon
outcomes. A structurally valid JSON object alone does not authorize allocation,
prove a successful DNF execution or establish a complete package transaction.

## Verification limits

Source fixtures use generated public bytes, actual bounded gzip reads, fake DNF
protocol objects and disposable worker processes. They perform no container,
DNF/RPM transaction, installation, SSH or proprietary operation. Actual closure
resolution, signature verification, offline assembly and RPM target acceptance
must be recorded by the approved driver after independent source review.

The [pinned DNF 4.14 Base API](https://raw.githubusercontent.com/rpm-software-management/dnf/4.14.0/doc/api_base.rst)
documents RPMDB loading, explicit resolution and distinct download/transaction
operations. The [transaction API](https://raw.githubusercontent.com/rpm-software-management/dnf/4.14.0/doc/api_transaction.rst)
documents its install/remove sets. These sources inform the protocol; they do
not replace observations of the actual UBI implementation.
