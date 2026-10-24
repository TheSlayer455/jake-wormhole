# Bounded target infrastructure

WORM-010 adds indexed infrastructure for fresh smoke and five-target runs.
These source fixtures are not actual runtime qualification. Twenty-target
layouts can be tested purely, but the allocation adapter refuses that profile;
its real demonstration remains WORM-020. Production ISO eligibility stays false.

`TargetPlan.from_lease(lease)` freezes deterministic target IDs, the profile and
the exact resource layout. Every new real controller records
`resource_layout: indexed-targets-v1` and its complete target-plan record.
The plan cannot be inferred from mutable provider state. Terraform owns one
internal network and `docker_container.target["target-001"]` through the exact
admitted count. New output contains an exact target-ID map. Original runs and
receipts remain unchanged under their original immutable source revision.

The caller holds the existing Run lock, Docker scope and canonical admission
lease across the whole lifecycle. Terraform plan/apply operations use fixed
parallelism 1; this is separate from helper Ansible concurrency. The exact image,
private local state, verified tools/mirror, limits, no-public-port policy,
saved-plan validation and unknown-outcome rules remain in force.

`ProvisioningSession.target_resources` returns a copy of observed target IDs to
exact container IDs; `network_id` is the observed network ID. `target_inventory`
returns a copied actual endpoint row or None for a known target whose endpoint
has not been observed. Invalid target identities are refused.
`verify_target(..., target_id=None)` resolves an omitted ID only for a one-target
plan. Fleet callers must name their exact planned target.

`create_stopped()` applies all resources and observes every target created and
never started, updates each exact PID limit, then reinspects the complete
confinement. No target can start until that whole stage succeeds.
`start_targets(ids)` starts an exact nonempty subset once. `refresh_inventory()`
uses actual refresh-only state and provider output. Pending targets have no
invented IP or placeholder inventory row; inventory remains unverified until
every planned target has an observed running endpoint. `start_and_inventory()`
composes both methods and defaults to the whole target set.

PID updates and starts persist conservative unknown intent before Docker calls;
only successful complete inspection clears it. Failure preserves all historical
IDs and evidence. Terraform destruction checks every remaining managed ID and
the exact network endpoint set; native target/network deletion is never a
fallback. Repeated cleanup and interrupted-finalization proof remain intact.
Cleanup projections classify every recorded Terraform container as a target.

Pure policy and mocked lifecycle coverage:

```text
python -m unittest discover -s tests -p test_targets.py
python -m unittest discover -s tests -p test_provisioning_fleet.py
```

Actual one-target regression and five-target qualification require reviewed
integrated helper code, a fresh clean source, measured admission and the owner's
approved runtime environment. They must record resource observations and exact
scoped cleanup separately from fixture results.
