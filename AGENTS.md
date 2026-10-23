# Jake Wormhole engineering instructions

Build this private, container-only reference project. Minx WORM-001 and its current child contracts define the work; original source milestone labels are not live ticket keys.

- Read README.md, docs/STATE.md, docs/ARCHITECTURE.md, docs/FIDELITY.md and handoff/CURRENT.md before changing code. Verify Git status, current source and evidence.
- WORM-002 establishes the repository baseline. The application CLI and pipeline are not implemented by that ticket. Do not present proposed commands as working commands.
- Verify this baseline with `python scripts/verify_repository.py`. It uses the Python standard library and Git and performs no provisioning or network access.
- Use ticket-key branches and reviewable commits/PRs. One writer per worktree and one owner per task. Preserve unrelated changes; no force-push, broad clean/reset, or automatic merge.
- Use scoped Minx API/CLI credentials outside Git. Claim approved work atomically; renew/checkpoint explicitly. Attach criterion-level pass/fail/unverified evidence and solution comments. Agents do not approve their own requirements or move work to Verified/Done. Report enforced workflow boundaries honestly.
- Keep runtime state, Terraform state/plans, private keys, credentials and unsanitized logs outside Git and portable evidence. Commit only labeled sanitized samples.
- Preserve shared Docker/K3s workloads and host security, routing, storage, VPN and recovery. Use run-owned resources, measured admission, enforced limits and an actual shared run lock. No global Docker prune or cleanup by ambiguous prefix.
- No VMs/KVM/libvirt/nested virtualization, work GitLab/XR2/Foreman/proprietary registry access, host PowerShell installation, privileged targets or unrelated service changes.
- Real Terraform lifecycle, SSH trust, Ansible checks and observed inventories are required where the contract says so. Fixtures, simulations, skipped checks and unverified capabilities must remain labeled.
- Production ISO eligibility remains false. A container result cannot prove ISO boot/install, operating-system STIG compliance, scanner compatibility or a repair to another system.
- Do not invoke external models, contact other chats or message Luna automatically. Label self-review and record actual independent reviewers and tested commits.
- At handoff, record the tested commit, exact commands/results, evidence, owned resources remaining, defects and next eligible ticket. GitHub hosts code; Minx owns requirements and review state.
