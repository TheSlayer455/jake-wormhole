# Jake Wormhole engineering instructions

Build this container-only reference project. Jake explicitly confirmed the public repository on October 24, 2026; see [decision 0006](docs/decisions/0006-public-source.md). Runtime state, credentials and raw evidence remain private. Minx WORM-001 and its current child contracts define the work; original source milestone labels are not live ticket keys.

- Read README.md, docs/STATE.md, docs/ARCHITECTURE.md, docs/FIDELITY.md and handoff/CURRENT.md before changing code. Verify Git status, current source and evidence.
- WORM-002 establishes the repository baseline. The application CLI and pipeline are not implemented by that ticket. Do not present proposed commands as working commands.
- Verify this baseline with `python scripts/verify_repository.py`. It uses the Python standard library and Git and performs no provisioning or network access.
- Use ticket-key branches and reviewable commits/PRs. One writer per worktree and one owner per task. Preserve unrelated changes; no force-push, broad clean/reset, or automatic merge.
- Use scoped Minx API/CLI credentials outside Git. Claim approved work atomically; renew/checkpoint explicitly. Attach criterion-level pass/fail/unverified evidence and solution comments. The Agent API cannot approve requirements or move work to Verified/Done. Jake explicitly delegated the existing Owner browser approval/completion clicks for WORM-001 through WORM-021 in this chat on October 23; see [decision 0002](docs/decisions/0002-owner-delegated-workflow.md). Record these as owner-directed automated decisions, never independent human review. Do not grant roles, extract Owner credentials or bypass server guards.
- Keep runtime state, Terraform state/plans, private keys, credentials and unsanitized logs outside Git and portable evidence. Commit only labeled sanitized samples.
- Preserve shared Docker/K3s workloads and host security, routing, storage, VPN and recovery. Use run-owned resources, measured admission, enforced limits and an actual shared run lock. No global Docker prune or cleanup by ambiguous prefix.
- No VMs/KVM/libvirt/nested virtualization, work GitLab/XR2/Foreman/proprietary registry access, host PowerShell installation, privileged targets or unrelated service changes.
- Real Terraform lifecycle, SSH trust, Ansible checks and observed inventories are required where the contract says so. Fixtures, simulations, skipped checks and unverified capabilities must remain labeled.
- Production ISO eligibility remains false. A container result cannot prove ISO boot/install, operating-system STIG compliance, scanner compatibility or a repair to another system.
- Do not invoke external models, contact other chats or message Luna automatically. Label self-review and record actual independent reviewers and tested commits.
- At handoff, record the tested commit, exact commands/results, evidence, owned resources remaining, defects and next eligible ticket. GitHub hosts code; Minx owns requirements and review state.
