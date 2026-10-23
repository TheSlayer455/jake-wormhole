# Current continuation point

Read [AGENTS](../AGENTS.md), [STATE](../docs/STATE.md),
[architecture](../docs/ARCHITECTURE.md), [fidelity](../docs/FIDELITY.md),
[admission](../docs/ADMISSION.md), [images](../docs/IMAGES.md),
[tool preparation](../docs/TOOLCHAIN.md) and [delegation](../docs/decisions/0002-owner-delegated-workflow.md).

October23,2026,14:52UTC: WORM-002/003/004/005 are Done in Minx. WORM-006 r2 is
approved/claimed and In Progress. Root branch codex/WORM-006-integration is stacked
on005; private draft PR5 is open. Separate active writer codex/WORM-006-provisioner
has unfinished source. Coordinate before changing that worktree; never reset it.
Retrieve current Minx version/claim before mutations; do not borrow another
session's identifier or reuse an expired claim.

1. Exact prerequisite/tool source fc9ccf81e26ec83c11560f2f5579ab8ec316871e passed
   actual homelab106 tests (104pass/two Windows-only skips,5.208s) and Windows106
   (66pass/40platformskips,4.667s). Separate source review found no material blocker.
   New real provisioning runs explicitly use kernel_lock=True. Existing legacy
   locks are preserved; missing policy cannot downgrade a persistent kernel lock.
2. Actual [tool preparation](evidence/WORM-006-tool-preparation.json) passed at
   that source in3.007s, cache265,992,159 file bytes. Its no-allocation canonical
   lease finished. Terraform1.17.0/provider4.6.0 are verified/extracted but have
   not executed. Recorded GPG verification is prior provenance; SHA/TLS checks
   are repeated by preparation. Runtime h1 verification remains pending.
3. Integrate/review the separately authored ProvisioningSession and fixed bounded
   provisioner runtime/tests. Use the existing authorized state owner (actual host
   UID0), explicit group only if needed for its fixed Docker socket, dropALL/NNP/
   readonlyroot/networknone/finiteTTL and exact four-mount allowlist. Docker socket
   access remains host-authority trust regardless UID; no host user/chown/auth change.
4. Actual acceptance requires two disjoint one-target Terraform plan/savedapply/
   refresh/output/destroy runs, inspected stopped targets/PID limits before start,
   provider-derived endpoints, actual controller/target cgroups and private state.
   Prove provider/create failure accounting, no key contents/unintended SSH ports,
   ownership refusal and exact destruction. Do not substitute native target creation
   or guessed IPs. Preserve primary diagnostics, state and all uncertain outcomes.
5. Retain the exact provisioner until Terraform destroy. Resume cannot allocate a
   replacement. Its capacity check is evidence only; the adapter must prove exact
   retained identity/configuration and bounded destroy-only operation. A bare flag
   cannot establish an unknown daemon request's completion. No journal edits/prune.
6. Publish final006 source and observe exact hosted CI; attach criterion results and
   solution comment, submit In Review/release. Use delegated normal Owner decisions
   for solved work. Then007 readiness and008 scoped cleanup/recovery become eligible;
   009 is first functional Ansible integration. Keep partial receipts separate from
   the unsupported complete pipeline; production ISO eligibility remains false.

WORM-005 [evidence](evidence/WORM-005.json) records two actual strict SSH runs,
negative trust/authentication, distinct keys and exact cleanup. Its original image
IDs/build revisions remain intact. Images/public base and private tool/run evidence
are intentionally retained. No unrelated workload, host install, routing, security,
storage, external model or other chat changed. No PR merged or remote image/release
published. Minx owns current review state; engineering review is not independent
human examination.
