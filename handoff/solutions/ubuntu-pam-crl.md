# Ubuntu PAM CRL crash and automation output

[Prospective lab policy v2](../../docs/UBUNTU-LAB-POLICY.md) removes physical-token
hardware from home acceptance and assigns trust-anchor review to Codex. The
historical results below retain v1 attribution and unverified physical-assurance
limits. Legitimate Pro input, actual USG/FIPS execution and required evidence
remain outstanding; no prior result is retroactively qualified.

Delivery and merge identity: [PR 37](https://github.com/TheSlayer455/jake-wormhole/pull/37).
The runtime source is pinned below; later documentation does not relabel it.

This is an independently developed home-lab reproduction. It does not establish
the cause of a failure in another environment. Physical-token assurance, FIPS
validation and production eligibility are separate requirements.

## Established cause and correction

Real Ubuntu 22.04 `libpam-pkcs11` 0.6.11-4ubuntu0.1 crashed during authentication
with offline CRL checking. A bounded native debugger traced the fault into
`X509_CRL_get_issuer`. The matching Ubuntu source passes `X509_OBJECT **` to
OpenSSL accessors expecting `X509_OBJECT *`, then releases a borrowed CRL before
using it. The online issuer fallback also contains the pointer mismatch.

The [narrow source repair](https://github.com/TheSlayer455/jake-wormhole/blob/3e1e00bc64d6d7c3fb4d3f2d846188626db8eace/ubuntu/support/patch-pam-crl.py)
uses the correct version-specific pointers and owns the CRL reference through
verification and cleanup. CA, signature, OCSP and CRL validation remain enabled.
The [offline build recipe](https://github.com/TheSlayer455/jake-wormhole/blob/3e1e00bc64d6d7c3fb4d3f2d846188626db8eace/ubuntu/support/build-pam.sh)
runs only in a capped Ubuntu 22.04 container with authenticated, pinned Ubuntu
source and staged dependencies. It produces a declared lab rebuild, not a
Canonical-signed binary or a certified cryptographic module.

A fresh VM also exposed a separate integration fault: optional no-reader PAM
conversation messages entered sudo command output, corrupting JSON and potentially
binary transfers. The module emitted its startup notice before reading the documented `quiet`
option. The patch moves that notice after configuration and honors both `quiet`
and `PAM_SILENT`, without changing authentication return codes. Native probes
verify zero startup notices; the optional-token password fallback emits no
conversation notices. Dedicated PAM probes retain failure evidence. Reporting still emits a complete blocked grid when output is malformed.

## Proven focused evidence and limits

Real installed libpam/SoftHSM diagnostics accept the correct credential and reject
wrong PIN, missing token, revoked certificate, untrusted certificate and wrong
identity. The network-isolated container diagnostic disables OCSP only for that
diagnostic; it independently exercises real offline CRL rejection. VM acceptance
uses the installed configuration with both OCSP and CRL checks enabled.

The vendor parser accepts the installed mapper configuration and rejects a
malformed assignment. It tolerates a missing semicolon with an internal warning;
we do not claim that omission produces a syntax error. The installed configuration
uses the documented semicolon. A separately hashed, one-pattern SCAP erratum
recognizes it; the original unmodified upstream audit is always retained too.

The [source regressions](https://github.com/TheSlayer455/jake-wormhole/blob/3e1e00bc64d6d7c3fb4d3f2d846188626db8eace/tests/test_ubuntu_closure.py)
protect exact source matching, reference ownership, check derivation and key
decoding. The [controller regression](https://github.com/TheSlayer455/jake-wormhole/blob/3e1e00bc64d6d7c3fb4d3f2d846188626db8eace/tests/test_ubuntu_helper.py)
preserves failure accounting for non-JSON output. Fixtures do not prove VM behavior.

```text
python -m unittest discover -s tests -p test_ubuntu_closure.py
python -m unittest discover -s tests -p test_ubuntu_helper.py
python -m wormhole.ubuntu_runtime run --source VERIFIED_STOCK_ISO --terraform PINNED_TERRAFORM --store PRIVATE_STAGED_INPUTS --mode hardened --sandbox
python -m wormhole.ubuntu_runtime run --source VERIFIED_STOCK_ISO --terraform PINNED_TERRAFORM --store PRIVATE_STAGED_INPUTS --mode hardened --sandbox --reuse-run FIRST_RUN_UUID
python -m wormhole.ubuntu_runtime compare FIRST_RUN_UUID SECOND_RUN_UUID
```

These runtime commands require the established private operator, shared admission,
staged native package and existing KVM sandbox. A nonzero pending-qualification
exit must be inspected; it does not by itself mean installation failed or passed.

## Fresh installation evidence

The converged implementation at
[3e1e00bc64d6d7c3fb4d3f2d846188626db8eace](https://github.com/TheSlayer455/jake-wormhole/tree/3e1e00bc64d6d7c3fb4d3f2d846188626db8eace)
completed two independent encrypted Ubuntu 22.04.5 BIOS installations with **40/40**
functional passes each in 651/638 seconds. The installed repaired PAM binary passed all
six cases with OCSP and offline CRL validation enabled, zero startup notices,
trusted final SSH/Ansible, cold-start unlock and exact-owned cleanup.
The second reused identical ISO bytes with different host keys, seeds and boot
identities. The normal comparison verified equivalent findings, 638 package
versions, three Snap entries, running kernel, payloads and installation inputs.
The candidate hash is `b767f0c325e10248e09ceb08ea30f8365867c220e1ebae970f6655a74f192936`.
Build/reuse took 18.6/15.0 seconds, installation 480/474, offline inspection and
cold start 64/64, and SSH/Ansible/inventory/assessment 57/55. These are two samples,
not a causal performance improvement claim. The 8 GiB/two-vCPU/64 GiB profile and
designated controller were used; no container can substitute for this VM proof.

Corrected lab content reports 210 pass, one FIPS failure, 14 not applicable,
five native manual outcomes and 409 upstream unselected. The unmodified upstream
scan remains separate: 207 pass/four fail. No native status is rewritten. All
required outcomes remain visible; no qualified ISO is published.
The real publisher refused this pair for pending policy dependencies. A captured
assessment with a required result removed was rejected as incomplete; reuse of
the earlier stale candidate was refused. These negatives do not qualify a release.

The exact owner inputs still needed are a legitimate Pro entitlement delivered
through the protected provider (for real USG/FIPS execution and content checks),
the required real physical token/credential, and accountable review/disposition
of the 141 installed trust anchors. The existing provider procedure is in
[the Ubuntu entry document](ubuntu-install-hardening.md). Successful enrollment
would still require pinned vendor inputs, actual audits and new installation
verification; it does not certify the entire VM or authorize customer publication.

## Related configuration and inventory checks

The common PAM stack uses the standard extended equivalent of `sufficient`:
`[success=done new_authtok_reqd=done default=ignore]`. This preserves the existing
password fallback while matching the benchmark control form. Real native tests
accept a valid software token and prove that a preceding required failure remains
failed. It is not evidence that physical-token authentication is mandatory.

Trust inventory explicitly reads the installed system CA bundle. Python's
`get_ca_certs` reports loaded roots and can omit a lazy `capath`; a real OpenSSL
regression distinguishes an empty loaded list from an installed root. Default
verification paths/counts are retained separately. Official public DoD roots do
not constitute an accountable approval of every installed trust anchor.

## Luna adaptation and recovery

Inspect the actual package source, OpenSSL ABI, authentication policy and first
failure in the receiving implementation before adapting this repair. Do not copy
private binaries, credentials or logs. Preserve existing working components on
**rhel kvm host** and validate through the real helper on **ansible control node**.
The home host is Ubuntu; a RHEL host or different PAM build requires its own proof.

Expected success is authenticated final-system access, six correct PAM outcomes,
complete native reports and matching installed binary identity. Wrong credentials
and revoked certificates must remain rejected; failed readiness must block the
dependent catalog. Reconcile interrupted ownership before retrying. Rollback uses
an attributable previous candidate and a new empty disk, never an edited receipt
or a manually repaired guest counted as qualification evidence.
