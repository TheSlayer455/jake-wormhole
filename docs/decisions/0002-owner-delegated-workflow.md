# Owner-directed WORM workflow actions

October 23, 2026. This decision supersedes the earlier requirement that Jake
personally click every WORM approval and completion button. It changes the
operator workflow; Minx code, roles, API authorization and guards are unchanged.

After requesting implementation of all WORM work and solution comments, Jake
explicitly said in the controlling chat: "I am not clicking that button every
time, you can do it."

Use the existing authenticated Owner browser session to perform those ordinary
workflow actions on his behalf for WORM-001 through WORM-021. The decision reason
must identify this explicit delegation, the exact requirements revision, and
automated operation. Requirements approval still needs a complete scoped contract
and satisfied prerequisites. Verification/completion needs actual criterion-level
passing evidence and a solution comment. Do not close unfinished work or turn
unverified integration results into passes.

Implementation uses the separate scoped Agent API and normal claims, concurrency,
revision and evidence checks. No Owner credential is read, copied or supplied to
agents. Browser access does not authorize credential extraction or an API bypass.
If the authenticated session is unavailable, preserve work and report that actual
access boundary.

Owner-directed automated verification is not independent human examination. Keep
that distinction in every decision and final report. The delegation does not
authorize new repository scope, host/security changes, external model use, GitHub
merges or production/scanner approval. Existing safety and source-fidelity limits
remain in force.

First observed use: WORM-002 revision 2 moved In Review to Verified to Done using
the normal UI, after its three passing evidence records and solution comment.
WORM-003 revision 2 then moved Draft to Ready through the same UI and was claimed
through the scoped Agent API. Minx's audit records the authenticated actor and
decision reasons; it does not claim to attest to which physical person clicked.
