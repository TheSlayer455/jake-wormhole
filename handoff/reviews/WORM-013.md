# WORM-013 engineering review

Reviewed source: `dfff72bec8bbea050bae73e6bba846e388f449e9`. Reviewer: independent Codex subagent `/root/ui`.
This is engineering source review, separate from an Owner-directed workflow
decision or independent human acceptance. No material source findings remain open.

Review covered exact reconstructed bytes to candidate manifest and derived image,
fixed full provenance/label checks, stock default separation, frozen seven-check
plan and capture-backed SSH/Ansible report validation. Corrections retained an
explicit bounded PID1 installer, readable public target files under private host
umask, known already-absent resource accounting and accurate failed-child identity.
The observed pinned Ubuntu OCI version label is now an exact trusted label;
arbitrary extra or changed labels still refuse before allocation.

The new preallocation recovery path checks original clean source, failed bound
receipts, reserved empty journal and complete run-label sweeps before public
`AdmissionLease.resume/finish`. Fixture coverage includes lock/busy/source/unknown/
resource refusal and interrupted finalization. Actual historical recovery used
the separately reviewed private original-source operator, not this new adapter.

Actual runtime proof, separately executed by the primary operator, contains four
fresh cases at this source with completed exact cleanup and unchanged sentinel.
Negative harness success does not turn an underlying refusal/failure into pass.
See [evidence](../evidence/WORM-013.json) and
[historical failed attempt](../evidence/WORM-013-initial-attempts.json).

The exact-source test counts and skipped checks are preserved in evidence.
Local summary raw test output was not separately saved; actual host test output
was retained privately. This review establishes neither ISO behavior, full
pipeline/publication eligibility nor a comprehensive secret scan. Minx remains
the authority for requirements and acceptance; no owner approval is inferred.
