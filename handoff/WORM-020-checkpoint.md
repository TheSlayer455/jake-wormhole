# WORM-020 actual twenty-target checkpoint

Actual Run `290ad14a-e6ec-4822-ae36-258d336ecc38` passed at `2026-10-24T18:39:28.663Z` using clean
runtime `825a594862b816401d4b963329e6242bd8ed8aeb`. All twenty stock Ubuntu targets coexisted in one graph.
Configured Ansible forks were four, independently of target count twenty.
The complete result contains 160 readiness pairs, 200 functional rows and twenty
full native software inventories with 200 required inventory rows. JSON and text
derive from each same validated native record.

The source-declared shared readiness window is 120 seconds for this twenty-target
profile. Smoke/five readiness remains 90 seconds. Per-probe bounds and the fixed
300-second target lifetime/helper wait and 600-second provisioner lifetime are unchanged.
Inventory precedes functional checks because its remaining-lifetime requirement
is larger; each stage still refuses insufficient actual remaining lifetime.

The two exact-owned container samples retain memory/PID observations, optional
peak availability, CPU counter deltas over measured intervals, bounded log-tail
bytes, writable-layer samples and finite stage timings. Samples are not guaranteed
peaks, disk quotas or full historical log sizes. Cleanup accounts for all 23
transient resources as absent in the original finished admission archive, with
zero pending resources and the unrelated sentinel unchanged.

This qualifies the bounded stock scale operation. Candidate reference publication,
production ISO eligibility, WORM-021 parity/handoff and parent acceptance remain
separate. See [evidence](evidence/WORM-020.json) and [review](reviews/WORM-020.md).
Earlier diagnostic truncation, incomplete readiness, resource-sample and inventory
console-truncation failures
remain failed in the history; their separate recovery is not twenty-target
qualification credit.
