# Repository controls and publication

Verified through GitHub API on October 23, 2026: the authenticated personal owner is `TheSlayer455`; repository `TheSlayer455/jake-wormhole` was absent, then created explicitly private and re-read with `private=true` (repository ID `1431014094`). Visibility was verified before the first push. No application packages, images or releases have been published.

The separate checkout began empty and clean. The minimal initial `main` commit is `7e715be` (`WORM-002 Initialize private Wormhole baseline`), pushed successfully. Engineering work continues on `codex/WORM-002-baseline` and isolated ticket-key worktrees. No pre-existing implementation, dirty files or unrelated repository was reset or repurposed.

## Checks

`python scripts/verify_repository.py` uses only Git and the Python standard library, with Python 3.12 or newer. It reads the tracked checkout, checks required continuation files and local Markdown link targets, and rejects selected runtime-state paths, private-key headers and known GitHub token formats. It never prints matching content, fetches documentation, provisions resources or changes Git. It labels its limits and whether the working tree is clean. Passing this check does not establish that every possible secret is absent or that the runtime pipeline works.

`.github/workflows/verify.yml` defines the `repository-verification` job on hosted Ubuntu 24.04, with read-only contents permission, a five-minute limit and no persisted checkout credential. Checkout is pinned to the official `actions/checkout` v7.0.1 commit `3d3c42e5aac5ba805825da76410c181273ba90b1`; its source action declares Node 24. The action source was read before selection: [pinned action definition](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml).

The workflow is authored at this checkpoint. An actual GitHub run, final source commit and branch-protection availability must be observed after pushing the development branch. Record those results in the next state/handoff checkpoint; authored configuration is not proof of an enforced or passing remote check.

## Review and rollback

No automatic merge, billing change, self-hosted runner or homelab CI access is configured. Minx retains requirements and acceptance decisions. Source review by an engineering subagent is labeled as such and is separate from Owner acceptance. Record exact reviewed commits under [handoff/reviews](../handoff/reviews/README.md).

An authorized maintainer can revert a reviewed baseline commit in a normal new commit/PR. This baseline creates no target resources and requires no service or production-data rollback. Do not force-push, delete ticket keys, or overwrite another writer's files to undo a documentation or verifier change.
