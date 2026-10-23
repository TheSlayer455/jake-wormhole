# WORM-008 qualification checkpoint

Actual four-case acceptance passed at clean
68bd82dd3202c27a63d03fcaad9a8c32a12521b2 on October23 at16:05UTC.
[Evidence](evidence/WORM-008.json), [engineering review](reviews/WORM-008.md)
and [operations](../docs/RECOVERY.md) describe the exact scope and limits.

Run the documented bounded command only in the authorized Linux environment:

```text
python3 -B -m wormhole.recovery_acceptance --sentinel-id EXISTING_EXACT_UNRELATED_CONTAINER_ID
```

It allocates fresh owned fixtures. The sentinel is observed, never mutated.
Normal, failed, cancelled and interrupted cases all reconciled their exact
resources; private state and qualified images remain intentionally retained.
Cancellation requests are cooperative and do not kill an in-flight Docker CLI.
Unknown mutation outcomes remain visible and block recovery.

Next delivery steps are publication and exact-source hosted CI, criterion-level
Minx evidence and a solution comment, In Review submission/release, then normal
delegated Owner verification/completion. Retrieve Minx before assuming those
steps happened. WORM-007 readiness is separately active. After both are Done,
WORM-009 becomes eligible. No PR is merged or complete pipeline advertised here.
