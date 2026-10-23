# Ubuntu image operations

WORM-005 provides two original Ubuntu 24.04 image recipes and a Linux-local assembly driver. Actual image construction and SSH qualification are separate operations. At authoring, neither image has been built or qualified. A successful assembly receipt still says `runtime_ssh_qualification: pending`, `runtime_pipeline_complete: false` and `production_iso_eligible: false`.

`images/assemble.sh` is the authoritative recipe. There is no parallel Dockerfile with different behavior. `images/images.lock.json` records the official Ubuntu linux/amd64 manifest, observed multi-platform index, frozen apt snapshot, selected apt versions, metadata sources, and all nine helper wheel filenames, versions and SHA256 values. The two flat lockfiles are projections of that JSON and tests check their parity. Snapshot apt installation retains archive-signature verification and HTTPS verification; historical `Check-Valid-Until` is disabled for the frozen snapshot. A hash-verified CA package supplies public trust anchors before the minimal base has its normal CA package installed. No TLS-verification bypass is used. Remaining apt dependencies resolve from that frozen signed snapshot; this is not a claim that every transitive apt package has its own version in the selected-package lock.

The helper uses Python 3.12 and Ansible Core 2.21.5 with a complete hash-pinned wheel closure, installed offline inside its image venv. Ansible's [support matrix](https://docs.ansible.com/projects/ansible-core/devel/reference_appendices/release_and_maintenance.html) documents the selected Python compatibility. Official [Ubuntu snapshots](https://snapshot.ubuntu.com/) preserve package selection. The helper contains SSH, Python and Ansible tooling; it contains no Docker CLI or socket. The provisioner's Docker/Terraform responsibility remains separate.

## Operator preconditions

Use an explicitly reviewed clean Git checkout of the exact committed source, on the approved Linux host with its existing local Docker socket. The operator is trusted to control Docker; these scripts are not a sandbox against that operator. No host pip, Ansible, Terraform, daemon reconfiguration, privileged builder, host namespace or public image push is part of assembly. Existing `ssh-keygen` is needed only for the separate per-run authentication operation.

State must live in the canonical approved locations, outside the checkout and vault:

```text
/srv/homelab/jake-wormhole/runtime/runs
/srv/homelab/jake-wormhole/runtime/infrastructure
```

The driver refuses alternate real allocation roots, synthetic plans, dirty source and mismatched run revisions. It requires WORM-004 `AdmissionLease`, takes the same exclusive infrastructure flock, and refreshes actual capacity before allocating the next phase. Its reviewed `smoke` profile permits one assembly builder at a time. An attempt that has begun allocation retains its journal after failure until explicit reconciliation. All image Docker calls require `docker_scope(run)`, which selects an empty private run-owned `--config` and the fixed local Unix socket. The bounded subprocess environment excludes ambient Docker context, host, TLS and credential variables; no operator Docker configuration is consulted. Qualification adapters can obtain the scoped non-secret config directory with `docker_configuration()` for their bounded stdin-only key provisioning call.

Create **a fresh non-fixture run for each image role**. The existing main `run` command records the currently unsupported runtime pipeline and returns nonzero; this is expected and must remain recorded. An image operation adds its own evidence without rewriting that pipeline outcome. Replace each UUID with the actual output from its separate run command:

```text
python -m wormhole run --workspace /srv/homelab/jake-wormhole/runtime/runs
python -m wormhole.images build target --run-id TARGET_BUILD_UUID

python -m wormhole run --workspace /srv/homelab/jake-wormhole/runtime/runs
python -m wormhole.images build helper --run-id HELPER_BUILD_UUID
```

A completed admission run ID cannot be reused. Do not build target and helper with the same UUID, retry into an old artifact cache, or overwrite an image receipt. Recover a failed attempt, then use a fresh UUID and clean source for a new attempt.

## What is bounded

The ordinary assembly container is created stopped. Before start, exact-ID Docker inspection must match admitted memory, equal memory/swap limit (no extra swap), CPU, PID and rotated-log limits, six explicitly listed assembly capabilities, `no-new-privileges`, its private bridge, and exactly two read-only recipe/artifact binds. The builder needs a writable root filesystem to install packages. It has no socket, host-network, host-PID or privileged setting. After start, actual owned-PID cgroup v2 files must match the plan; desired Docker fields alone do not pass qualification.

Assembly has a finite workload deadline; Docker requests also have finite client deadlines. Downloads are individually SHA256-verified and bounded to 16 MiB each and 64 MiB total. Captured client output is bounded during capture. Docker logs rotate at the admitted per-container bound and private captured logs remain at most 64 KiB. The driver samples shared free disk and builder writable-layer size at approximately two-second intervals plus bounded Docker observation time. It stops on loss of the configured 4 GiB free-space headroom plus 2 GiB remaining materialization reserve, or a sampled layer above 1 GiB. This is a sampled stop guard, **not a hard filesystem quota or reserved disk space**. Independent shared workloads can change capacity between samples.

Only a successful stopped exact owned builder may be committed. Fresh admission, the layer ceiling and disk reserve precede commit. [Docker commit](https://docs.docker.com/reference/cli/docker/container/commit/) and pulls execute in the existing shared daemon outside the assembly container's cgroup. Their daemon work is not hard CPU/memory/PID capped by this driver. The reviewed plan budgets 512 MiB shared-daemon overhead and 2 GiB extra disk reserve; commit has a 120-second client deadline. A timed-out request has an unknown daemon result. Killing the client does not establish cancellation, and admission remains blocked until a supported reconciliation proves what happened.

Success retains the exact image and its actual size, removes only the exact verified stopped builder and empty owned network, confirms absence plus a run-label container sweep, and then finishes admission. No global prune or ambiguous prefix deletion is used. The private build receipt records source revision, recipe-file hashes, base reference and actual image identity, platform, installed package/wheel observations, Docker/cgroup observations, layer size, and pending runtime qualification. Private logs are not portable evidence and must not be committed unsanitized.

## Runtime authentication and qualification

The target has a dedicated `wormhole` user UID/GID 10001, Python and OpenSSH. Its root SSH master needs only SETUID, SETGID and SYS_CHROOT; remote sessions run as the dedicated user. SSH accepts plain per-run Ed25519 public authentication only. Root/password/keyboard-interactive login, forwarding, tunnels, PTY, user RC and user environment are disabled. Image assembly suppresses package-created host keys and refuses any resulting `ssh_host_*` files. Each target start generates a fresh Ed25519 host key in private tmpfs. No reusable private host key is stored in an image.

Use a separate fresh non-fixture qualification run and generate its client authentication once:

```text
python -m wormhole.images auth --run-id QUALIFICATION_UUID
```

This writes a private 0600 client key below that run's 0700 credentials directory. Output contains its public fingerprint only. A separate public-only target-input directory is mode0755 with authorized_keys0644 so a target root without DAC override can read a key owned by a different host UID. The containing run/private directory remains private on the host. Never bind the client credentials directory into a target.

`runtime_arguments` constructs reviewed stopped-container arguments for the trusted qualification adapter. Target/helper runtime root filesystems are read-only, log/CPU/memory/PID bounds are reapplied, `/run` and `/tmp` are bounded tmpfs, no host ports are published, and only the target receives its public-key input bind. Helper runs as UID10001 with all capabilities dropped. Its private key and known_hosts must be explicitly provisioned as UID10001 mode0600 into its `/run/input` tmpfs by the trusted operator; the image never discovers host secrets. Its doctor runs in the locked venv and reports actual versions and execution location. Resource observations inside doctor are supplementary; qualification must independently check actual HostConfig and cgroups.

Known-host trust must come from exact-owned target control-plane public host-key observation, with matching SSH fingerprint and explicit known_hosts. No AutoAddPolicy, disabled StrictHostKeyChecking, or untrusted ssh-keyscan result establishes trust. Qualify two separate runs to demonstrate unique host keys and per-run client authentication. Record actual SSH user, Python and Ubuntu userland/package observations, negative authentication, resource/privilege inspections and exact image IDs. The helper sets `ANSIBLE_REMOTE_TEMP=/tmp/wormhole-ansible` for the read-only target home and separately sets its local temporary path. This follows the documented [remote_tmp override](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/sh_shell.html#parameter-remote_tmp). Ansible checks and Terraform lifecycle are later tickets, not established by an SSH connection or a passing dependency doctor.

## Failure and recovery boundaries

The repository qualification adapter is available after both builds complete at
the same clean source revision:

```text
python scripts/qualify_images.py --target-build-run TARGET_BUILD_UUID --helper-build-run HELPER_BUILD_UUID
```

Each invocation creates a fresh qualification run, client key and private internal
network. It rechecks completed build receipts against actual image identity, holds
the canonical admission lease, inspects stopped runtime limits before start and
reads actual cgroups. It provisions the helper's private tmpfs through a bounded
stdin-only archive, obtains the exact-owned target's public host key through the
trusted Docker control plane, then uses strict authenticated SSH as UID10001.
Root and nonexistent-user login must fail specifically at authentication.
No private key is printed or placed in evidence. The receipt includes client and
host public fingerprints so two invocations can prove isolation. Every created
container/network is inspected and removed by exact ID before admission finishes;
unknown allocations preserve the journal. Failure output identifies the run UUID.
These are image tests, not Terraform/Ansible pipeline acceptance.

Admission-entry refusal records a failed-before-allocation receipt and makes no Docker request. After any mutating Docker request, failure stops a known owned running builder where possible, retains bounded private logs, and leaves the journal unresolved. Missing/changed ownership, a failed stop, or an unknown pull/commit result stays explicitly unverified. Do not edit/delete admission.json, remove its stable lock file, create a second infrastructure root or retry allocation to bypass this state.

Reconciliation must take the same flock for the same run and source, inspect each exact journaled resource and run-label leftovers, and act only on ownership-verified resources. An assembly failure can be reconciled by stopping/removing its exact builder and empty network and accounting for retained images. A timed-out pull/commit requires separately established daemon completion and exact image/tag outcomes before resolution; elapsed client time or an empty container list is insufficient. The WORM-005 assembly driver intentionally does not auto-clear these unknown outcomes. A supported reconciliation adapter is required before unattended retries; no generic infrastructure cleanup or later lifecycle implementation is implied.

## Verification at this source slice

```text
python -m unittest discover -s tests -p test_images.py -v
python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

Image policy tests use synthetic metadata and mock all Docker operations. POSIX authentication tests use existing local ssh-keygen in disposable private directories. These tests verify policy and failure behavior, not image build success, network reachability or actual SSH qualification. Host-execution receipts must supply those missing observations before WORM-005 acceptance.
