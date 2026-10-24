# WORM-005 engineering review

October 23, 2026. This is Codex engineering review and actual host evidence,
not independent human examination. Owner workflow decisions use Jake's explicit
delegation in [decision 0002](../../docs/decisions/0002-owner-delegated-workflow.md).

Independent engineering subagent brief_and_research reviewed the image policy,
Docker isolation, bounded artifact worker and reconciliation changes. Subsequent
review of exact integrated source `0bc5ad0636ca5c27460f831d0262d4a6dc43525e`
found no material blocker in separating original image build provenance from the
qualification controller's revision. Every original build remains bound to its
own clean Run, exact immutable image and original labels. All seven recipe files
and their combined digest must still match the controller. The reviewer did not
execute tests for that review.

Actual host execution identified and corrected Docker 29 capability spelling,
equivalent no-new-privileges spelling, exact network-not-found responses and
commit-response handling. A successful commit is resolved through its unique
owned tag and actual immutable identity. A timed-out request still has unknown
daemon outcome and cannot be cleared by guessing. An earlier successful but
unparsed commit was inspected and its unused exact image removed through an
explicit reconciliation operation; the original failure remains recorded.

The first helper assembly failed with `docker_api_failed`. Its known builder
was stopped (exit 137, OOMKilled false), then its exact builder/network were
reconciled. The underlying API failure was not retained at that source and its
cause is unknown. A fresh attempt with private first-failure diagnostics built
successfully; this does not retroactively turn the failed attempt into a pass.

The first SSH qualification failed when Docker's archive API could not read the
public host key in live tmpfs. Both runtime cgroup inspections passed; all owned
containers and the network were removed. Docker documents this archive
[limitation](https://docs.docker.com/reference/cli/docker/container/cp/#corner-cases).
The host-side transfer correction and bounded pre-cleanup failure diagnostics
require their own source review and actual qualification results below.

The reviewer then inspected clean fix `20c4310ba795350a68d01b7d9e2ec5537d081a78`
(integrated as b6bd81e), finding no material remaining blocker. Fixed live-exec
adapters read only the public host key and accept only three bounded ordinary
helper input files, validating the whole archive before exclusive no-follow
writes into UID10001 tmpfs. Private role/stage diagnostics now precede cleanup;
diagnostic errors cannot replace the primary failure or strand other resources.
The stdin receiver has bounded input, fixed output and a 15-second client timeout;
its capture_output call is not a generic streaming output limiter.

Exact controller `731eabee3d691404e22c9422e37ff1c6ccddfcf4` passed 93 tests on
Windows (63 passed,30 platform skips,3.939s) and the actual homelab Linux
(91 passed,two Windows-only skips,4.417s). Actual live SSH qualification runs
1272ece0-83ea-4205-993e-3ca44f5b0590 and
6b5e5606-fa45-496d-9591-d064495d1167 both passed. Client and host public
fingerprints differ between runs. Each required the exact UID10001/Python3.12.3/
Ubuntu24.04 observation, strict trust, rejection of wrong known-host key and
root/unknown-user authentication, actual resource limits and exact cleanup.
See [sanitized evidence](../evidence/WORM-005.json).

Final publication/hosted CI and Minx decisions are recorded separately. These
results do not establish Terraform, functional Ansible, a candidate pipeline,
production eligibility or independent human examination.
