# Engineering checkpoint

October 23, 2026. WORM-002 revision 2 is Done in Minx after owner-directed
browser actions, with passing criterion evidence and a solution comment. Jake
explicitly delegated the repeated approval/completion clicks; see
[decision 0002](decisions/0002-owner-delegated-workflow.md). This is automated
verification under owner instruction, not independent human examination.

WORM-003 revision 2 is approved and being implemented on `codex/WORM-003-cli`.
The implementation commit checked locally is
`a0f8381f08d2884532ebe53fd9aa8591ba94d67d`; this documentation follow-up also needs
verification before publication. Minx is authoritative for the current status,
lease, evidence and development references.

Implemented: local standard-library Python CLI; canonical isolated UUID run
storage outside Git/vaults; six generated v1 artifact schemas and matching fixed
validators; bounded fixed-adapter stage execution; report/verify; exact fixture
private-state cleanup; explicit unsupported real-run and publication results.
The CLI quick-start commands ran, including the expected nonzero refusals.

Local verification: CPython 3.12.14, Git 2.55.0.windows.3, unittest exit 0;
31 cases, 26 passed and five explicitly skipped for platform/policy reasons,
3.237 seconds. Real CLI checks, two simultaneous fixture runs and two spawned
workspace creators passed. Wrong-source/hash/check/status evidence, malformed
records, unsafe paths and NTFS junctions reject. POSIX-only output-flood,
process-group and timeout cases require Linux; the implementation agent exercised
those in a disposable WSL Git snapshot with Python 3.12.3 (31 cases, two
Windows-only skips). The final hosted CI must run the selected Python 3.12.14.

Review found and corrected scoped IPv6 host parsing and a descendant-held stdout
pipe that exceeded the stage deadline. Stage execution now uses an absolute
deadline and POSIX process groups. Windows permits only two immutable reviewed
leaf adapters and refuses other execution before launch; Windows ACL protection
is not claimed verified. See [CLI details](CLI.md).

CI now selects CPython 3.12.14 with full-SHA official checkout/setup-python pins
and runs the same unittest command. Exact-source hosted observations belong in
the ticket/PR after pushing; earlier baseline CI is not evidence for this change.
Required private branch protection remains unavailable on the account plan.

No Wormhole target images, containers, networks, Terraform state or SSH material
were created. The fixture run is synthetic and cannot qualify reference
publication. The runtime pipeline and production ISO eligibility remain false.

Next: finish exact-source review/CI, attach WORM-003 criterion evidence and solution
comment, submit In Review and release the claim, then apply the delegated normal
Owner workflow after all criteria pass. WORM-004 and WORM-005 become eligible
only after WORM-003 is actually Done. Continue with measured resource admission
and minimal pinned target/helper images; no host tools or daemon settings changes.
