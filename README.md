# Jake Wormhole

Private, container-only reference automation for source integrity, Terraform-managed targets, SSH/Ansible checks and attributable engineering evidence.

Minx tracks the approved work under [WORM-001](https://jakeubuntu.taila85348.ts.net:4317/tickets/WORM-001). WORM-002 establishes the engineering baseline; application functionality follows in dependent tickets. No working pipeline is claimed at this checkpoint.

Start with [AGENTS.md](AGENTS.md), [current state](docs/STATE.md) and [handoff](handoff/CURRENT.md). The [fidelity record](docs/FIDELITY.md) separates actual behavior from planned or simulated capabilities. [Repository controls](docs/REPOSITORY.md) records publication and CI observations.

With Python 3.12 or newer and Git installed, verify this checkout without provisioning anything:

```text
python scripts/verify_repository.py
```

This checks tracked context files, portable local links and selected accidental state/secret patterns. It is not a complete secret scanner or a Terraform/SSH/Ansible test. Runtime CLI commands will be documented only when implemented.

Container tests cannot establish that an ISO boots or installs, passes an operating-system STIG, or repairs another system. Production ISO eligibility remains false.
