# WORM-007 engineering review

October23,2026. Source review by an independent engineering subagent is separate
from independent human examination. Owner decisions follow Jake's explicit
[delegation](../../docs/decisions/0002-owner-delegated-workflow.md).

The reviewer examined helper isolation, strict SSH trust, exact provider endpoint
checks, real Ansible transport, bounded subprocesses and helper-only cleanup.
Findings fixed before final qualification included progression operations that
could exceed the readiness deadline, late EOF accepting a result, and recovery of
a known pre-allocation helper failure. The acceptance operator also gained bounded
host-key observation after its single exact-owned target restart, with the
original pin retained throughout.

Actual runtime exposed three additional integration defects: private staged source
was unreadable by UID10001; Ansible forced a terminal refused by the target; and
empty JSON ping arguments were parsed as raw parameters. Reviewed corrections
use only a hash/inode-bound readonly public code copy under a private parent,
explicit documented no-TTY/piped SSH options, and omission of empty ping args.
The target image, sshd configuration and SSH trust policy were not weakened.
Each earlier failed attempt was independently reconciled through the original
source's normal helper and retained-controller Terraform cleanup, preserving its
failure and the unchanged unrelated sentinel. No state/journal edits, uncertainty
override or replacement allocation was used.

The final frozen fixes are original9850192,475dafa and91e8164, integrated with
the reviewed deadline/harness fixes at clean9db5f24fc8e27228a7dbe7ba7b5c8d8263a17fa5.
No material source finding remained. Actual Linux fixtures passed171/173, two
Windows-only skips,7.792s; Windows passed99/173,74 platform skips,5.483s.

Root ran the actual nine-case qualification at that exact source. Healthy and
delayed-start cases reached real Ansible wait and remote ping. Never-starts,
wrong key/user, unavailable configured interpreter, wrong expected endpoint/network
and actual host-key rotation all produced the required distinct failed readiness
outcome and blocked dependent work. Every case reconciled exact helper and
Terraform resources with unchanged sentinel observations. See
[criterion evidence](../evidence/WORM-007.json).

The interpreter test proves that the configured remote path is unavailable,
not that the baked Python package was removed. Network mismatch tests change
expected metadata, not unrelated attachments. Public-key observation establishes
the pin; it does not replace actual helper SSH/Ansible checks. Functional
package/configuration/payload validation remains WORM-009. No complete pipeline,
production ISO eligibility or independent human acceptance is claimed here.
