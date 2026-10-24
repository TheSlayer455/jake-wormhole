# Repository controls and publication

`TheSlayer455/jake-wormhole` is the verified repository, ID `1431014094`. Jake explicitly confirmed public visibility on October 24, 2026; see [decision 0006](decisions/0006-public-source.md). Earlier verification took place while it was private. All 21 original delivery PRs are merged; PR21 established merged main `c3d440a3c7eee9691f30315b49146eb72998d2df` at 19:50:33 UTC on October 24, 2026, and GitHub recorded all remaining contained heads as merged by 19:50:35 UTC. [Merged verification](../handoff/MERGED-VERIFICATION.md) records fresh source, manual/hosted parity and one Ubuntu reference smoke. A merge/CI result is separate from deployment, runtime execution and acceptance. The documentation-only follow-up receives its own PR/main CI; original evidence stays source-bound.

## Verification

`python scripts/verify_repository.py` checks tracked context, links and selected state/key/token patterns. `python scripts/verify_acceptance_matrix.py` checks original evidence hashes, exact JSON selectors, typed selected observations and Markdown parity. Neither provisions resources, reads credentials or proves complete secret absence.

The current hosted Ubuntu 24.04 job uses `contents: read`, a ten-minute timeout, exact repository-ID/name guard, pinned CPython 3.12.14, full history and no persisted checkout credential. Checkout is pinned to `3d3c42e5aac5ba805825da76410c181273ba90b1`; setup-python to `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0`; the validated five-file uploader is pinned. The same fixed wrapper runs manually and in authored CI. Deliberate red controls remain failures after successful diagnostic validation/upload. Actual merged-source observations are linked above.

## WORM-020 CI history

Delivery `193a9fd78b31595861904df2a93c26323bec2834` failed both [push 40122081169](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40122081169) and [PR 40122084718](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40122084718). The original-source preapply fixture could not read historical `6f3f28e` from the depth-one checkout. This source-fixture CI error is separate from four actual twenty-target runtime failures.

The sole `fetch-depth: 0` correction preserved pinned actions, triggers, read-only permission, `persist-credentials: false` and all tests. Final [push 40122478923](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40122478923) and [PR 40122482009](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40122482009) passed at `65db67b90fb104e1e58efffb5fb0e3d80f0c0871`. Independent local shallow-clone reproduction first lacked the original blob, then passed all 12 targeted proof fixtures after normal unshallowing. It is a local test, not another hosted run. The [matrix JSON](acceptance-matrix.json) retains safe run metadata/private receipt hashes, not raw job logs or local paths.

Earlier source CI remains historical. [WORM-021](../handoff/WORM-021-checkpoint.md) established controlled manual/GitHub normalized comparison, genuine failing-job status and safe artifact metadata at3f7e3cf3. Its single-job ten-minute workflow uses the additional pinned uploader, explicit reviewed-head checkout, preserved child failure and five literal validated artifact paths. GitLab authored/local checks are distinct from official lint and runner availability/execution.

## Review and rollback

Required-status branch protection for private main was rejected with HTTP 403 because the account plan did not support it. No billing/visibility change was made during that earlier observation; do not report an enforced protection gate. The later owner-confirmed public-source decision is separate. No automatic merge, persistent self-hosted runner or homelab CI access is configured.

Minx owns current contracts/claims/review state. Engineering source review differs from delegated normal Owner decisions and independent human examination. [Review records](../handoff/reviews/README.md) preserve exact source/scope/finding dispositions.

Use normal corrective/revert commits and reviewable PRs. No force push, broad deletion, global prune or historical-evidence rewrite is part of rollback. [Local reference publication](PUBLICATION.md) is a separate tested-byte filesystem operation; it does not publish a GitHub release or image.
