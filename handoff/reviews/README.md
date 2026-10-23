# Review records

Store concise sanitized reviews tied to an exact source commit here. No completed independent review is recorded at the WORM-002 baseline checkpoint.

Each report should identify reviewer role and whether it is self-review or independent, reviewed SHA/base, Minx ticket and approved revision, environment, commands and actual outcomes, findings with source locations, skipped/unverified checks and limitations. Track each finding's disposition and the correction SHA without erasing the original finding. A later fix needs its own verification evidence.

Do not include credentials, private keys, Terraform state/plans, environment dumps or unsanitized runtime logs. Link approved safe evidence rather than copying private stores. Minx remains authoritative for criterion evidence and human review decisions; repository reviews provide source context and do not automatically change ticket state. See [review prompt](../../prompts/REVIEW.md).
