# Review records

Store concise sanitized reviews tied to an exact source commit here. Current records: [baseline](2026-10-23-baseline.md), [CLI](2026-10-23-cli.md), [admission](WORM-004.md) and [images/SSH](WORM-005.md), [Terraform](WORM-006.md), [readiness](WORM-007.md), [recovery](WORM-008.md) and [functional validation](WORM-009.md) and [chunk integrity](WORM-012.md). Engineering subagent review is separate from independent human examination and Owner-directed workflow decisions.

See also [synthetic assessments](WORM-016.md).

Each report should identify reviewer role and whether it is self-review or independent, reviewed SHA/base, Minx ticket and approved revision, environment, commands and actual outcomes, findings with source locations, skipped/unverified checks and limitations. Track each finding's disposition and the correction SHA without erasing the original finding. A later fix needs its own verification evidence.

Do not include credentials, private keys, Terraform state/plans, environment dumps or unsanitized runtime logs. Link approved safe evidence rather than copying private stores. Minx remains authoritative for criterion evidence and human review decisions; repository reviews provide source context and do not automatically change ticket state. See [review prompt](../../prompts/REVIEW.md).

See also [candidate source/image/test binding and exact-source recovery](WORM-013.md).
