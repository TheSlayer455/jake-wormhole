# 0004: Provisioning run locks and retained-controller recovery checks

October 23, 2026. WORM-006 revision 2 is approved and claimed after WORM-004/005
completed. Terraform execution is still being implemented. These prerequisites
do not establish successful provisioning, cleanup or crash recovery.

New real Linux provisioning runs opt into `create_run(..., kernel_lock=True)`.
A fixed run-specific lock-policy.json selects a persistent operation.lock inode.
Run.locked uses nonblocking exclusive Linux flock, checks ordinary private
ownership, refuses symlink/hard-link paths and never unlinks that inode. Kernel
release on process exit permits an explicit same-run recovery process to acquire
the run lock; it does not clear the independent infrastructure journal or imply
successful teardown.

Existing runs and fixtures retain their original O_EXCL policy. A legacy .lock
residue is preserved even when a PID appears dead. A missing/invalid kernel policy
with operation.lock present is an error, never a downgrade to a second legacy
lock. No automatic migration, stale-file deletion or force takeover is provided.
This coordinates cooperating clients; it is not protection against a host owner
who can replace files and code.

The reconcile-only infrastructure lease still cannot refresh/replace its plan,
register resources, adopt unknown IDs or enter allocation/execution phases.
check_destroy_recovery_capacity(container_id) only produces fresh budget evidence
for an exact existing pending container in a resumed reconciling lease. It requires
the original executable profile/limits to match and sufficient current capacity.
It changes neither plan nor journal and returns allocation_permitted=false.

The Terraform adapter must independently prove that container is the retained
provisioner: exact immutable image, run/role/source, complete mounts/security/limits
and fixed bounded destroy-only command. A budget result is not ownership proof or
restart permission. A narrowly reviewed adapter may restart that already-known
controller for destruction; it cannot allocate a replacement or infer completion
of an unknown daemon operation. General recovery remains WORM-008 scope.

The provisioner's disk planning slot increases from 256 to 512 MiB, retaining
512 MiB memory, .5 CPU, 128 PIDs and 600-second lifetime. Verified original ZIPs
plus their two extracted ELF binaries alone total 265,853,975 bytes (about
253.54 MiB), leaving inadequate room in the old slot for notices, Terraform data,
plans, state and logs. Actual complete cache/state/peak measurements are required
before WORM-006 acceptance. This finite planning slot is not a hard disk quota.

Tests use disposable identities/state. Windows baseline plus prerequisites ran
98 cases (64 passed,34 platform skips). A native Linux Git fixture under WSL ran
the same current source bytes: 98 cases,96 passed,two Windows-only skips,3.980s.
Actual child competition/SIGKILL, stable inode, missing policy, legacy residue,
linked locks, insufficient capacity, profile changes and continued allocation
refusal are covered. The Windows worktree's Git pointer cannot be read by Linux;
running CLI tests directly there failed source discovery. The native fixture
resolves that environment mismatch; it is not homelab runtime qualification.
