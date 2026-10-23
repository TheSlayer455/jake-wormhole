# WORM-010 real acceptance operator

This explicit Linux operator uses the normal measured admission, exact qualified
images, Terraform lifecycle, shared helper, strict SSH/Ansible and WORM-008
cleanup APIs. It does not install host software, change unrelated workloads,
qualify twenty targets or establish complete-pipeline/candidate/ISO eligibility.
Source must be clean and the existing sentinel must be an exact unrelated
container ID. The sentinel is inspected only, never allocated, executed or
modified.

Run the shared Batch APIs with one actual target first. Substitute only the
verified existing container ID for `EXISTING_SENTINEL_ID`:

```text
python -m wormhole.fleet_acceptance --profile smoke --scenario healthy --sentinel-id EXISTING_SENTINEL_ID
python -m wormhole.fleet_acceptance --profile five-targets --scenario healthy --sentinel-id EXISTING_SENTINEL_ID
python -m wormhole.fleet_acceptance --profile five-targets --scenario all --sentinel-id EXISTING_SENTINEL_ID
```

The first two commands are useful staged checks before the complete suite. `all`
uses ten fresh serial five-target Runs: healthy, delayed-start, never-starts,
wrong-key, wrong-user, configured-interpreter-unavailable, wrong-endpoint,
wrong-network, changed-host-key and validation-interpreter-unavailable. `all`
with the smoke profile is refused before allocation. The suite refuses a changed
source revision, reused Run/resource identity or any failed acceptance case
before allocating the next case. Serial Runs may legitimately reuse IP addresses;
the observed container/network IDs and private Run/state directories are distinct.

Each five-target plan declares fifty required functional rows before probes.
The normal profile independently configures two Ansible forks. Delayed and absent
cases create and confine all five targets first, start four, and retain an honest
missing provider endpoint for target005. A trusted coordinator starts only that
exact target after at least two seconds in the delayed case. The absent case
retains the normal 90-second readiness window. Four healthy targets still receive
actual functional Ansible observations; the blocked target receives ten explicit
nonpassing readiness-precondition rows, not fabricated Ansible attempts.

Wrong endpoint/network cases change only expected in-memory metadata for target005
and must fail exact identity checks before foreign contact. That metadata is
restored after the attempt without editing Terraform state or discarding failure
evidence. The host-key case makes one exact owned stop/start, records inspected
PID-zero/new StartedAt and actual cgroups, refreshes provider inventory, observes
the new public identity and retains the original known-host pin for rejection.
Only transient absence of the newly generated public key is retried.

Both interpreter cases select a deliberately missing configured interpreter path;
they do not remove Python or demonstrate package absence. The readiness case must
block that target before functional transport. The validation-only case first
establishes all five actual ready snapshots, then invokes genuine Ansible for all
five using the bad configured path for target005. Its actual mixed result must
retain forty passing rows, ten failing rows and the specific interpreter category.
An aggregate failed result remains failed even when its negative-test harness
and cleanup pass.

Budgets are unchanged: readiness at most90 seconds, functional validation60,
outer helper exec45 with an inner two-second margin, target lifetime300 and
helper wait180. The validator checks actual StartedAt values and requires its
remaining60 seconds plus20 seconds before those lifetimes expire. In particular,
an absent-target run leaves about90 seconds of the helper's nominal wait after
the readiness window; it proceeds only if actual overhead still leaves the
required80 seconds. Slow preflight causes explicit failure rather than extending
a lifetime. Cleanup has its own bounded operations and the retained provisioner
must remain alive. A client timeout or unexplained operation retains its unknown
state and blocks further allocation; this operator does not reconcile ambiguity.

Every Run retains `evidence/fleet-acceptance.json`, the frozen batch plan, all
fifty batch rows, capture-bound observations, readiness records, private bounded
attempt logs, Terraform state and the cleanup receipt. The acceptance summary
points to row evidence and reports per-target counts, probe categories and log
paths without exporting raw logs or keys. JSON/text row agreement is verified
through the normal strict report API. Credential scans run before and after
cleanup; logical disk samples are observations, not quotas.

Known failures use normal helper-first `cleanup_session`, preserving the original
primary cause independently from cleanup. The existing sentinel's stable
allowlisted projection must match after exact cleanup before a case can pass.
Unexpected known failures still attempt that policy. Unknown outcomes are left
blocked with the original private Run and active admission journal; there is no
fallback delete, replacement controller, journal reset or broad prune.

`tests/test_fleet_acceptance.py` runs synthetic coordinator and existing protocol
fixtures only. Its success is not an actual host/container/SSH/Ansible result.
Real acceptance must be executed separately from the reviewed clean source and
recorded with its actual observations, failures and cleanup outcomes.

<!-- WORM-010 actual qualification 1920c9621017190a8756affab36e5d25e6102978 -->

## Actual qualification at `1920c96`

The staged smoke/five-target commands and the full ten-case fleet command passed on October 23, 2026, using clean `1920c9621017190a8756affab36e5d25e6102978`. The full suite used ten distinct five-target Runs with fifty declared rows each and two independent Ansible forks. All expected faults retained their failed underlying operation and nonpassing target rows; exact cleanup and the unrelated sentinel stayed separate and successful. The [portable evidence](../handoff/evidence/WORM-010.json) records sanitized identities/counts while full row/capture/state artifacts remain private.

Linux: 277 cases, 275 passed, 2 Windows-only skips, 19.359 seconds. Windows: 277 cases, 161 passed, 116 platform skips, 17.542 seconds. Fixture counts and real runtime observations are recorded separately. No twenty-target, candidate/full-pipeline, VM/ISO/STIG or scanner qualification is inferred.
