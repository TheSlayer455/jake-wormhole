# Minx work index

[WORM-001: Build Jake Wormhole](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-001) is the parent Epic. Minx is authoritative for each ticket's requirements revision, acceptance criteria, dependencies, assignment, approval and review state. This index is a navigation aid, not another editable ticket database. Open the ticket or its API handoff for the current dependency graph before choosing work.

| Ticket | Bounded work |
|---|---|
| [WORM-002](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-002) | Private repository and durable engineering baseline |
| [WORM-003](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-003) | Versioned CLI and isolated run contracts |
| [WORM-004](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-004) | Resource admission and shared run ownership |
| [WORM-005](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-005) | Minimal SSH targets and pinned validation helper |
| [WORM-006](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-006) | Terraform Docker target lifecycle |
| [WORM-007](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-007) | Endpoint, SSH trust and Ansible readiness |
| [WORM-008](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-008) | Scoped cleanup, cancellation and leftover recovery |
| [WORM-009](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-009) | First real one-target Terraform to SSH to Ansible path |
| [WORM-010](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-010) | Five-target execution and readiness failures |
| [WORM-011](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-011) | Optional PowerShell and missing-package diagnostics |
| [WORM-012](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-012) | Chunk integrity and reconstruction |
| [WORM-013](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-013) | Candidate identity tied to the tested image |
| [WORM-014](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-014) | Legally usable RPM-userland target coverage |
| [WORM-015](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-015) | Observed Software Version Description |
| [WORM-016](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-016) | Synthetic assessments and reference-only policy |
| [WORM-017](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-017) | Complete evidence, reports and strict gates |
| [WORM-018](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-018) | Atomic private reference publication |
| [WORM-019](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-019) | Overlapping-run isolation and interrupted recovery |
| [WORM-020](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-020) | Measured twenty-target demonstration |
| [WORM-021](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-021) | Manual/CI parity, failure matrix and final handoff |

The attachment's milestone labels WORM-001 through WORM-007 are illustrative. Use the real Minx keys above; for example, the first target acceptance path is WORM-009, not WORM-002.

The current source checkpoint and reported WORM-002 ownership are in [STATE.md](STATE.md). Refresh Minx rather than treating that snapshot as a lease. An Agent claims only a current approved contract with satisfied dependencies; blockers require truthful records. Claims expire and do not authorize overwriting another writer's files. Use one owner per task and one writer per worktree.

For every submitted increment, map pass/fail/unverified evidence to all criterion IDs and add a solution comment with source references, actual commands/results, limitations and cleanup/rollback. Agent completion submits In Review and releases the claim. Only an authorized human records Verified/Done. A prerequisite awaiting review is not Done; project-wide implementation authorization does not grant agents those transitions. Continue independent eligible work when possible and record an explicit checkpoint at any enforced boundary.
