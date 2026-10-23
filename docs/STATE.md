# Engineering checkpoint

October 23, 2026, 13:27 UTC. WORM-002 and WORM-003 revision 2 are Done in
Minx with solution comments and criterion evidence. Jake delegated repeated
Owner browser actions; these are automated decisions, not independent human
examination. See [decision 0002](decisions/0002-owner-delegated-workflow.md).
WORM-004 and WORM-005 revision 2 are approved and claimed by separate sessions.
Minx owns current claims, decisions, evidence and development references.

Implemented: local CLI, isolated synthetic runs, six versioned artifact contracts,
bounded stage execution, report/verify/fixture cleanup, and Linux measured
resource admission with a canonical shared flock and durable resource journal.
See [admission](ADMISSION.md) for profile, freshness, crash/cancellation,
reconciliation, Terraform PID-cap and Docker materialization boundaries.

Admission source tested: 576379e0d7a03ccf64d53849bc13939e9981d0a3.
This documentation follow-up changes no runtime code. Actual verification:

- Windows CPython 3.12.14: 47 unittest cases, 34 passed and 13 explicit platform
  skips, 3.121 seconds.
- Existing homelab Linux CPython 3.12.3: same 47 cases, 45 passed and two
  Windows-only skips, 2.731 seconds. Actual Linux lock/crash/cancellation and
  interrupted-finalization tests use disposable synthetic test roots.
- Read-only host collection at 13:26:45 UTC: 29,161,349,120 total memory bytes,
  20,285,952,000 available, 213,143,437,312 free disk bytes, 16 allowed CPUs,
  load 0.8931, 51 existing running containers. Docker 29.6.0 positively reports
  cgroup v2 memory, swap, CPU quota and PID support. All 1/5/20 plans admitted
  at that instant; this does not demonstrate scale execution or enforced limits.
- Repository verifier: 43 tracked files, 43 local links, clean exact-source tree.
  Independent engineering review of identical admission files at c8bb89d8 found
  no material remaining defects; see [review](../handoff/reviews/WORM-004.md).

Only private offline Git source and its bundle were staged under the existing
unlocked /srv/homelab mount; no GitHub credential was transferred. No Wormhole
runtime root, container, image, network, Terraform state or SSH material exists
from this slice. Existing workloads were observed without mutation. Plans label
allocation_performed=false and limits_enforced=false. Actual target execution
and applied-limit verification remain later integrations.

WORM-003 source 9fb7ee772aae2e3b96b8541c5b7b9e41b05decc4 is pushed in private
draft PR 2. Exact-source hosted CPython 3.12.14 CI passed 31 cases with two
Windows-only skips. Final admission push/CI observations belong in Minx/its PR;
earlier success does not qualify new source. Required branch protection remains
unavailable on the private account plan. No PR was automatically merged.

Next: finish WORM-004 publication/evidence, submit In Review and release the
claim, then apply delegated normal Owner workflow only on passing criteria.
Finish/review WORM-005 before its first admitted capped image build. Terraform
WORM-006 becomes eligible only after both are Done. Production ISO eligibility
remains false.
