# Ubuntu prospective home-lab policy

[Policy v2](../profiles/ubuntu-lab-policy-v2.json) applies the owner's explicit
home-lab scope correction. Physical-token hardware is not required for lab
acceptance. The real software-token/PAM tests remain required, while physical
assurance and government identity remain unverified limitations. This does not
turn a software token into a physical credential or change a native scanner result.

The owner delegated trust-anchor review to Codex under home-lab authority.
Reconciling the installed roots with their sources and lab purposes is engineering
work. The manual observation remains unresolved until that review is performed
and bound to the actual installation; the presence of public DoD roots alone is
insufficient. No further owner review of the 141-entry inventory is requested.
This delegated lab review does not claim government authorization.

The inherited 137 public roots exactly match the pinned stock ISO. Four were
expired at review, and the declared offline workload needs none of them. The
guest-only correction deselects those roots with Ubuntu's native
[update-ca-certificates](https://manpages.ubuntu.com/manpages/jammy/man8/update-ca-certificates.8.html)
and keeps only the four date-valid roots from the pinned official public DoD
bundle. Lab service/PAM trust stays explicitly scoped. Acceptance checks both
the bundle and hashed trust directory; native manual statuses remain unchanged.
This is an accountable home-lab disposition, not government authorization.

The frozen coverage target remains the manual revision documented by Canonical
for [Ubuntu 22.04 USG](https://documentation.ubuntu.com/security/compliance/usg/):
V2R8. Official DISA [V2R7](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R7_STIG.zip)
and [V2R8](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R8_STIG.zip)
contain 188 controls. Seven check/fix records differ; only the effective UFW and
SSH-banner check procedures changed. Closure requires exact pinned manual hashes,
complete mapping and the actual supplemental probes/native results for that run.
This does not establish USG scanner equivalence. The newer official
[manual V2R10](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R10_STIG.zip)
has 191 controls, including three additions, and separate text/logic changes;
it remains visible as a newer, unqualified target rather than silently replacing
the frozen policy. Manual and SCAP release numbers are not interchangeable.

Run reports list evidence-resolved requirements separately from the original
policy declaration. They cannot resolve Pro/USG/FIPS from trust or identifier
mapping, and pending policy still refuses publication.

Legitimate Pro entitlement, actual USG/FIPS execution, supported cryptographic
modules, benchmark reconciliation and other required evidence remain mandatory.
The external owner input is a legitimate entitlement supplied through the existing
protected provider. Credentials must never be sent in chat. Supplying it does not
itself establish FIPS operation or qualification; that execution remains engineering.

The unchanged [v1 policy](../profiles/ubuntu-lab-policy-v1.json), prior receipts and
native reports retain their original meaning. V2 has a new policy ID and hash and
is included in the installed-input fingerprint. Old candidates are refused by the
existing reuse check; historical results are not regenerated or retroactively
qualified. V2 needs new policy-bound installation and validation evidence before
qualification. Production eligibility remains false, and pending publication is
still refused. This policy correction adds no new framework or approval step.
