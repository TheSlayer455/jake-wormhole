# Public source repository

On October 24, 2026, while the ISO handoff prompt was being prepared, GitHub reported the existing `TheSlayer455/jake-wormhole` repository as public. Its immutable repository ID remains `1431014094`. The publishing guard stopped the merge because earlier instructions required private source. Jake then explicitly replied: **"Public is intentional; merge."** The agent did not change repository visibility.

That owner decision supersedes the previous private-source requirement. Original observations, checkpoints and evidence still describe their actual source and repository state at the time; they are not rewritten. Runtime inputs, credentials, Terraform state/plans, raw captures and private local publication remain outside Git and portable exports.

GitHub CI now checks the exact repository ID and owner/name before checkout instead of requiring private visibility. It retains `contents: read`, pinned actions and Python, full history, explicit PR-head checkout, disabled credential persistence, fixture-only execution, complete failure propagation and five validated artifact paths. No self-hosted runner, homelab credential, public tunnel, deployment or runtime-policy change is introduced.

The current visibility decision does not change container-reference acceptance into production ISO acceptance. Normal reviewable commits/PRs, scoped access, source attribution and exact-owned recovery remain required.
