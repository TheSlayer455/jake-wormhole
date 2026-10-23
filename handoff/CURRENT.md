# Current continuation point

Read [AGENTS](../AGENTS.md), [STATE](../docs/STATE.md),
[architecture](../docs/ARCHITECTURE.md), [fidelity](../docs/FIDELITY.md),
[admission](../docs/ADMISSION.md), [images](../docs/IMAGES.md) and
[delegation decision](../docs/decisions/0002-owner-delegated-workflow.md).

WORM-002/003/004 are Done. WORM-005 revision 2 has passing actual image/SSH
results; final publication/CI and Minx decisions are next at this 14:32 UTC
checkpoint. Retrieve current Minx state. Never reuse expired claims or a different
session identifier.

1. Verify Git/source. Actual qualified controller is
   731eabee3d691404e22c9422e37ff1c6ccddfcf4; this follow-up changes only context
   and sanitized evidence. [Evidence](evidence/WORM-005.json) records exact image
   IDs/original build revisions, two passing fresh SSH runs, cgroups, negative
   checks, cleanup and preserved failures. Controller-only fixes cannot relabel
   images or accept changed recipe files.
2. Finish WORM-005 private publication/exact-source hosted CI, criterion evidence
   and solution comment. Submit In Review through Agent API, releasing its claim.
   Use delegated normal Owner browser Verified/Done on passing evidence; record
   automated provenance. Never change Minx's roles/revision/evidence guards.
3. After 005 Done, approve/claim WORM-006. Terraform 1.17.0 and Docker provider
   4.6.0 archives were verified separately but neither binary has executed.
   Use a separate capped trusted provisioner, verified readonly tool mirror,
   fixed local Docker socket and private run state. No host installation.
   Create targets stopped, apply PID limits and inspect every control before
   start. Generate endpoints from actual provider refresh/output, never guessed IPs.
4. Hold one canonical lease across provisioning/readiness/cleanup. Review a narrow
   exact-provisioner destroy/recovery path before Terraform execution. Existing
   reconcile-only resume cannot allocate replacements. Do not delete a legacy
   O_EXCL run lock just because a PID looks dead. Retain unknown outcomes, state
   and ownership until resources reconcile.
5. WORM-007 covers endpoint/SSH/Ansible readiness; WORM-008 scoped cleanup/recovery;
   WORM-009 the first functional Ansible integration. Keep partial real receipts
   distinct from the still-unsupported complete runtime pipeline. Skips are not
   success; production ISO eligibility remains false.

The two images and public Ubuntu base remain intentionally retained on the allowed
host. Qualification containers/networks were removed. Private keys/logs and all
failed-attempt/recovery history remain outside Git on encrypted storage. No
unrelated service, external model or other chat changed or was contacted. No
image/release has been remotely published.
