# 0005: Fixed Terraform operations in a retained capped provisioner

October23,2026. WORM-006 implementation decision; actual host acceptance is a
separate evidence record. See [lifecycle details](../TERRAFORM.md) and
[lock/recovery prerequisite](0004-provisioning-locks-and-recovery-capacity.md).

Reuse the already qualified Ubuntu target image as the base of a distinct trusted
provisioner container, overriding its entrypoint with fixed authored Python PID1
source. Bind verified Terraform1.17.0/provider4.6.0 tools read-only rather than
installing host tools or creating another image. This preserves original image
provenance and a single modular controller. The provisioner alone receives the
existing root-equivalent Docker socket. The validation helper stays Docker-free.

Use the existing state owner's explicit UID/GID, caps-drop-all/NNP/read-only root,
network none, finite600-second lifetime and admitted memory/CPU/PID/log limits.
Expose only fixed operation names, a mirror-only CLI configuration, a read-only
dependency lock and private state. Validate saved create/destroy plans against
the exact generated smoke graph. Targets are Terraform-created stopped, then
PID-capped and inspected natively before start. Refresh-only provider output,
cross-checked against the exact network, supplies inventory.

Retain the exact provisioner and state until ownership-verified Terraform destroy.
Do not reconstruct its targets natively or allocate a replacement under a
reconciliation-only lease. A known failure can restart only the exact retained
controller after fresh capacity and command/mount/ownership proof. Unknown daemon
outcomes stay blocked for separately reviewed recovery. Failed partial receipts
retain their primary status; they never become full-pipeline or release approval.
