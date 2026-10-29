# Jake Wormhole engineering instructions

## Engineering simplicity

Deliver working functionality with the smallest maintainable implementation.
Identify the first confirmed defect, fix the existing owning component and reuse
its libraries/contracts. Prefer fewer files, dependencies and simpler control
flow. Do not refactor unrelated working code or add speculative frameworks,
wrappers, services, approval, attestation, validation or recovery layers. Add a
layer only when a demonstrated requirement cannot use existing mechanisms.
Delete superseded code once its replacement is proven.

Inspect existing coverage first. Extend the closest test for a distinct
requirement, realistic failure or observed regression. Prefer cheap real tests
over mocks; avoid duplicate tests, trivial permutation matrices, giant fixtures
and new test frameworks. Ordinary fixes usually need 1-5 focused tests; this is
guidance, not a security coverage cap. More than 200 added test lines or a new
test framework requires a concise justification of new coverage before delivery.
Preserve valuable existing tests regardless of counts.

Use focused unit tests, small boundary integrations and actual KVM acceptance.
Run focused checks first, relevant integrations next and full verification at
delivery boundaries. Repeat VM installation only after relevant implementation,
installation inputs or acceptance-contract changes, or for explicit repeatability
proof. Unit tests never establish ISO installation, SSH/Ansible or assessment.

For each delivery report the confirmed defect/requirement, changed files,
production and test lines added/removed, each new test's distinct behavior,
actual runtime evidence and remaining blocker. Explain disproportionate test
changes before delivery. Stop adding code when the requirement and relevant
regressions pass and the actual runtime outcome is proven.

## Authorized scope

The owner authorizes automatic manifest-bound transient cleanup and storage
budget enforcement under the existing shared admission lock. Preserve reusable
current ISO bytes, qualification evidence, releases and unresolved recovery state;
never touch unrelated storage. See [storage lifecycle](docs/STORAGE.md).

Build this public Linux image reference project. Preserve the verified container backend as the fast regression layer. The owner explicitly authorized a separate home KVM/libvirt and real-ISO profile for RHEL 9 and Ubuntu 22.04 on October 27, 2026; this supersedes the former container-only prohibition, not its historical evidence. Runtime state, licensed media, credentials and raw evidence remain private. Original ticket records are historical, not new claim leases.

Current owner milestone: complete Ubuntu 22.04 hardening, real assessment,
repeatability and exact-byte local release independently. RHEL implementation and
media work are paused until Ubuntu is complete and the owner explicitly starts
RHEL. Preserve its existing code/tests. Canonical USG/FIPS require authorized
entitlement; never discover tokens in unrelated private state or invent access.
Only an explicit owner-populated protected provider slot may supply enrollment.
An alternative pinned OpenSCAP audit must retain its content identity and all
upstream rule outcomes. Missing required FIPS, manual evidence or owner exception
decisions keep lab qualification pending; engineers cannot approve their own
waivers. Acceptance observes the guest and never remediates it. Keep the baseline
command unqualified and add a separate explicit policy/evidence gate.

The current sandbox assignment authorizes project-owned logging/time services,
private test CA/identities and protected local secret delivery. Implement valid
lab settings rather than treating absent production endpoints as approval gates.
Use the existing shared admission and exact resource journals, bounded services
and tested guest isolation. Never manufacture a Pro entitlement, government CA,
physical-token assurance or certification. RHEL remains paused. Preserve actual
host controls; support services cannot expose public listeners or mutate the host.

The owner has directly authorized the architecture and failure-reproduction follow-up in [the active engineering checkpoint](docs/FAILURE-REPRODUCTION.md). Preserve the original Done ticket history; do not imply an old claim authorizes a new session or that this follow-up is already accepted. Continue in bounded, reviewable increments and record unverified runtime work explicitly.

- Read README.md, docs/STATE.md, docs/ARCHITECTURE.md, docs/FIDELITY.md and handoff/CURRENT.md before changing code. Verify Git status, current source and evidence.
- WORM-002 establishes the repository baseline. The application CLI and pipeline are not implemented by that ticket. Do not present proposed commands as working commands.
- Verify this baseline with `python scripts/verify_repository.py`. It uses the Python standard library and Git and performs no provisioning or network access.
- Use ticket-key branches and reviewable commits/PRs. One writer per worktree and one owner per task. Preserve unrelated changes; no force-push, broad clean/reset, or automatic merge.
- Use scoped Minx API/CLI credentials outside Git. Claim approved work atomically; renew/checkpoint explicitly. Attach criterion-level pass/fail/unverified evidence and solution comments. The Agent API cannot approve requirements or move work to Verified/Done. Jake explicitly delegated the existing Owner browser approval/completion clicks for WORM-001 through WORM-021 in this chat on October 23; see [decision 0002](docs/decisions/0002-owner-delegated-workflow.md). Record these as owner-directed automated decisions, never independent human review. Do not grant roles, extract Owner credentials or bypass server guards.
- Keep runtime state, Terraform state/plans, private keys, credentials and unsanitized logs outside Git and portable evidence. Commit only labeled sanitized samples.
- Preserve shared Docker/K3s workloads and host security, routing, storage, VPN and recovery. Use run-owned resources, measured admission, enforced limits and an actual shared run lock. No global Docker prune or cleanup by ambiguous prefix.
- Home KVM/libvirt VMs are authorized only through the separate lab profile: initially one 8 GiB guest at a time, shared host admission with Docker, empty disks, verified installer ISO boot, isolated owned networking and exact-owned teardown. Never apply guest hardening to the host/control environment. No emulation fallback, cloud-image substitution, host reboot/repartition/bridge replacement/global firewall changes, work infrastructure or proprietary registry access, Windows/MDT/KubeVirt, host PowerShell installation, privileged containers or unrelated service changes.
- Routine verified increments may be merged when current owner authorization and repository requirements permit. Keep container reference, lab ISO qualification and production qualification distinct. Production eligibility is always false; real ISO/assessment evidence is required for the new lab gate. Never let a container receipt satisfy it. Do not commit licensed ISO files or private operational data.
- Real Terraform lifecycle, SSH trust, Ansible checks and observed inventories are required where the contract says so. Fixtures, simulations, skipped checks and unverified capabilities must remain labeled.
- Production ISO eligibility remains false. A container result cannot prove ISO boot/install, operating-system STIG compliance, scanner compatibility or a repair to another system.
- Do not invoke external models or contact other engineering sessions automatically. Instructions and checkpoints must be model-neutral. Label self-review and record actual independent reviewers and tested commits.
- At handoff, record the tested commit, exact commands/results, evidence, owned resources remaining, defects and next eligible ticket. GitHub hosts code; Minx owns requirements and review state.
