# Run isolation and interruption qualification

The fixed Linux qualification entrypoint is:

```text
python -m wormhole isolation-check --sentinel-id APPROVED_READ_ONLY_CONTAINER_ID
```

The operator supplies the already approved unrelated sentinel's exact container
ID. The qualification uses only the fixed project Run store, canonical
infrastructure admission and private release store. It accepts no arbitrary
workspace, target profile, executable command or fault hook. Run it only from
the exact clean, reviewed source revision under the approved owned-container
plan. Fixture tests do not establish actual qualification.

The four cases are ordered. Each completed case binds its original bounded
proof by logical path, SHA-256 and byte count. The compact versioned receipt
keeps every fresh child Run ID, including failed or refused attempts. A
missing, partial or failed case prevents suite success. The CLI returns
nonzero for a failed or incomplete suite.

| Case | Required observation |
| --- | --- |
| Overlap | Distinct live coordinators, authentication, state, inventories, resource names and evidence. The canonical admission lease serializes resource graphs. A separate competing attempt refuses before allocation. Recovery refuses while the first Run lock is held, then refuses while the other Run holds infrastructure admission. |
| Interrupted Run | Only the owned coordinator is interrupted, after terminal Terraform teardown has been positively observed. A new admission refuses unreconciled work. Exact-source scoped recovery accounts for retained state and known resources while preserving the primary failure. |
| Interrupted publication | A fresh same-source healthy Ubuntu reference Run supplies the tested bytes. An owned filesystem-only publisher stops before either completion-marker filename exists. Inspection remains incomplete, retry refuses overwrite and original reference evidence is preserved. |
| Oversized capacity | A separately owned synthetic capacity fixture refuses the fixed twenty-target plan before allocation. Prior fixture state is preserved. This establishes no actual twenty-target execution. |

Overlapping coordinator lifetimes are distinct from simultaneous resource
graphs. The canonical lock deliberately admits one graph at a time. A busy
attempt and a later admitted attempt have separate immutable Run IDs; the
refusal is never rewritten as a successful retry.

No private authentication bytes or private-key hashes belong in portable
evidence. Authentication separation is recorded as an explicit equality-test
result derived in memory. Public identity and source-bound original proof
metadata remain attributable. Terraform state, raw logs and private runtime
records stay outside Git.

An interrupted publication is retained for diagnosis. There is no repair,
overwrite or cleanup shortcut that adds a completion marker. Resource recovery
uses the existing exact-source public operation, and uncertain daemon mutations
continue to block allocation. No unrelated container, network, service, image
or host security control is changed by these cases.

Actual source revision, commands, outcomes, cleanup and independent engineering
review belong in the ticket's criterion evidence and qualification checkpoint.
Minx remains authoritative for current requirements and review state.
Production ISO eligibility remains false.
