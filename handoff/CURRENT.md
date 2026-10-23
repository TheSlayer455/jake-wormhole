# Current continuation point

The private repository baseline (WORM-002) is Done under the owner's explicitly
delegated automated browser workflow. WORM-003 provides the real local CLI and
fixture contracts, not a Terraform/SSH/Ansible runtime pipeline. Read
[AGENTS](../AGENTS.md), [STATE](../docs/STATE.md), [CLI](../docs/CLI.md),
[ARCHITECTURE](../docs/ARCHITECTURE.md), [FIDELITY](../docs/FIDELITY.md) and
[delegation decision](../docs/decisions/0002-owner-delegated-workflow.md).

The implementation checked locally is
`a0f8381f08d2884532ebe53fd9aa8591ba94d67d`. Inspect actual Git status/log and Minx
before continuing; the containing documentation and later commits need their own
checks. Source publication, CI and ticket status are separate facts.

1. With real CPython 3.12.14 and Git, run `python -m unittest discover -s tests -v`
   and `python scripts/verify_repository.py`. See README for the actual CLI flow.
   Windows supports only the reviewed leaf fixture adapters; Linux exercises
   general bounded stage execution. Skipped platform checks remain explicit.
2. Retrieve WORM-003 and its current claim. The implementer's recorded session is
   `codex-WORM-003-20261023-primary`; never borrow it to impersonate its holder.
   Renew/checkpoint only an owned active claim. If already Done, read its solution
   comment and evidence instead of repeating implementation or submission.
3. If submission is pending, finish exact-source tests/CI/review, attach every AC's
   pass/fail/unverified evidence and solution comment, then submit In Review and
   release the claim through the Agent API. Use the existing authenticated Owner
   browser only under the explicit delegation and honest automated decision
   reasons. Do not broaden credentials, weaken guards or claim human examination.
4. After actual WORM-003 Done, approve and claim eligible WORM-004/WORM-005 using
   their current scoped contracts and distinct session IDs/worktrees. They cover
   measured shared resource admission and pinned minimal SSH target/helper images.
   Terraform lifecycle and first real SSH/Ansible acceptance follow in later tickets.

There are no Wormhole runtime resources from this slice. Private local fixture
state is outside Git and portable reports; cleanup retains evidence and primary
outcome. No target or homelab cleanup is needed. No external model was invoked or
other chat messaged. Production ISO eligibility remains false.
