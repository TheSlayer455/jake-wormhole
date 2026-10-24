# WORM-004 engineering review

October 23, 2026. Independent Codex engineering subagent brief_and_research
reviewed c8bb89d8fe05ddc9ef169b00201d9e023acd01e8. Its four admission files are
byte-identical to integrated 576379e0d7a03ccf64d53849bc13939e9981d0a3.
No material remaining defects were found. This is engineering review, not
independent human acceptance.

Earlier findings closed: real leases require the canonical host root; synthetic
mode requires opt-in plus synthetic observations. Each allocation phase refreshes
measurements under the held lock and unchanged profile. Refusal preserves active
state/resources; reconciliation remains possible without fresh capacity.
Review covered stable lock inodes, crash/cancel refusal, exact archive matching,
archive-first fsync finalization and run-ID reuse rejection.

Reviewer Windows CPython 3.12.14 tests: 16 cases, eight passed and eight explicit
Linux-only skips; verifier passed 43 files/43 links with clean source. The primary
agent separately ran actual homelab Linux checks and read-only collection; see
[STATE](../../docs/STATE.md). No Docker allocation or effective host limit
enforcement is claimed by the planning implementation.
