# CLI and versioned run records

WORM-003 provides the shared Python CLI/library foundation. CPython 3.12.14 and
Git are selected; no pip dependencies are required. `.python-version` and
`dependencies.lock.json` record this selection. Run `python -m wormhole --help`
from the checkout with a real installed Python executable.

| Command | Behavior at this slice |
| --- | --- |
| `doctor` | Read-only local tool/source discovery; no network or provisioning |
| `run --workspace PATH --fixture` | Fresh UUID directory and actual fixed synthetic stage execution |
| `run --workspace PATH` | Persist a failed unsupported attempt; no pretend real pipeline |
| `report RUN_UUID --workspace PATH` | Read the selected run's validated portable records |
| `verify RUN_UUID --workspace PATH` | Check record contracts, run identity and evidence integrity |
| `cleanup RUN_UUID --workspace PATH` | Remove only owned fixture private state while retaining evidence |
| `publish-reference RUN_UUID --workspace PATH` | Explicit nonzero refusal pending WORM-018 |

Use a dedicated absolute workspace outside Git and vault synchronization. Each
run has a distinct directory, owner marker, inventory, Terraform state location,
private credential location and portable evidence. Never export an entire work
directory. Credentials, state and private logs are not portable evidence.

The manifest records the source revision and whether it was dirty, the run UUID,
fixture status and outcomes. Fixed local subprocess adapters run without a shell;
ticket text and JSON do not become commands. Stages declare inputs, outputs,
execution location and a finite timeout. Failure, timeout and unsupported results
remain explicit; logs are bounded. A negative test's expected rejection does not
make its failed run successful. Later tickets replace unsupported runtime stages
with real bounded implementations and retain these failure semantics.

The Windows executor permits only the two reviewed leaf Python fixture adapters;
other adapters are rejected before launch. It does not claim general Windows
process-tree containment. POSIX execution uses its own process group and an
absolute deadline covering process completion and output-drain completion, so a
descendant holding stdout cannot turn an expired stage into success. Real runtime
provisioning/validation will use the authorized Linux execution environment.

Published artifact contracts are under `schemas/`: run manifest, inventory, test
results, observed SVD, synthetic assessment and release decision. Schema version
`1.0` is required. The library accepts only the implemented contracts; an arbitrary
JSON Schema document is not executable configuration. Unknown fields, malformed
values and unsupported versions fail rather than silently producing empty success.
These schemas define records, not proof that an inventory or assessment ran.

Fixture evidence cannot qualify a reference publication. Production ISO
eligibility is always false. Required real stages and whole-run completeness
remain unimplemented until their tickets pass actual runtime acceptance.

## Verification

`python -m unittest discover -s tests -v` exercises the library and real CLI,
including malformed records, concurrent fixture isolation, bounded stage output,
failure/timeout handling, unsafe workspace paths and the publication refusal.
Tests use disposable synthetic data outside the checkout. No Docker daemon or
homelab credentials are needed. The private GitHub workflow invokes this same
command using pinned CPython 3.12.14. It is fixture CI, not homelab execution.
Platform-specific tests report skips honestly: NTFS junction checks are Windows
only; general subprocess-tree, output-flood and POSIX permission checks run on
Linux. Windows also proves unsupported adapters are refused before launch.

Selected setup action source was read before use:
[setup-python v7.1.0](https://github.com/actions/setup-python/blob/6d4fd22b20465ccc0f7354476588e8df7c9ca0e0/action.yml).
The official Python distribution manifest listed 3.12.14 for Ubuntu 24.04 x64 at
selection time. Runtime target images, Terraform and Ansible pins are separate
work; this lockfile does not pretend they have been installed.
