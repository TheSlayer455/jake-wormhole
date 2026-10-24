# WORM-019 overlap and scoped recovery checkpoint

Tested runtime source: `973c24a4b9e196d8d3117a3b91d372bd0397394a`. Actual suite `c870d716-41b3-4f0f-baf1-9e0f710e9a27` passed
at the retained receipt timestamp `2026-10-24T17:07:00.586Z`. This records engineering
qualification; it does not claim Owner acceptance.

Two independent live coordinator lifetimes overlap while their one-target
resource graphs use serialized canonical admission intervals. A competing fresh
Run refuses before capacity collection or Docker. Recovery of the earlier Run
first refuses its held Run lock, then refuses the other active infrastructure
lease. Original state/evidence and per-Run authentication remain distinct.

The owned interrupted coordinator is killed only after terminal successful
Terraform destroy, hash-bound empty final state and exact resource absence are
proved. Normal exact-source recovery preserves `controlled_teardown_interruption`
and retained Terraform state, then accounts for the complete graph.

The separate filesystem-only publisher exits 86 before either completion marker.
Its 23-file partial output remains incomplete; independent CLI inspection exits 1,
duplicate publication refuses, and original evidence and sentinel remain unchanged.
The isolated synthetic oversized-capacity case refuses allocation and preserves
its previous fixture admission/sentinel. It earns no actual twenty-target credit.

All four admitted real graphs have original finished archives with exact resource
sets and terminal dispositions. Private captures/authentication/state are retained
outside Git. See [criterion evidence](evidence/WORM-019.json) and
[engineering review](reviews/WORM-019.md). WORM-020 actual twenty-target execution,
WORM-021 parity and parent acceptance remain separate work.
