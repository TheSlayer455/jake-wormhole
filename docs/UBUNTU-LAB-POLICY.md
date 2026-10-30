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
