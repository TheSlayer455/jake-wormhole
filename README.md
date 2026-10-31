# Jake Wormhole

Use `python -m wormhole storage status`, `storage preview` and `storage clean`
through the established private runtime owner. VM completion/recovery cleans
verified intermediates under the shared lock. `storage archive-preview` inspects
selective encrypted workstation retention; WSL `archive-sync`, `archive-verify`
and explicit `restore` use verified age readback before reclamation. Current-input
pins and required local evidence stay protected. See [commands and budgets](docs/STORAGE.md).

Verified container reference runtime: [acceptance checkpoint](handoff/RUNTIME-ACCEPTANCE.md) and [delivery PR 28](https://github.com/TheSlayer455/jake-wormhole/pull/28).
Use `python -m wormhole progress RUN_UUID` for readable atomic readiness snapshots;
qualification still requires the existing original-evidence replay gates.
The follow-up also adds `python -m wormhole reproduce --help` for fixed focused
and fleet fault experiments, explicit initialization/configuration receipts and
verified Ubuntu/UBI candidate reuse and contained initialization recovery after
coordinator interruption. Actual Ubuntu/UBI, fault, reuse, mixed/twenty-target, recovery and private local publication execution is verified at the recorded sources. Production ISO eligibility remains false.

Container reference automation remains the fast regression layer. The authorized [home real-ISO extension](handoff/ISO-FOUNDATION.md) now includes a verified [RHEL 10.0 installation baseline](handoff/solutions/rhel10-install-baseline.md): fresh KVM installation, trusted SSH/Ansible, 413 RPM records and all 948 native vendor-draft assessment outcomes. This is not hardened or qualified. Ubuntu retains two fresh installations of the same encrypted/hardened ISO with 40/40 checks each, including real SSH/Ansible, cold-start unlock, isolated logging/time/PKI services and cleanup. Actual Ubuntu OpenSCAP reports 210 pass, one FIPS failure, 14 not applicable, five not checked and 409 upstream not selected. Required USG/FIPS/vendor-content verification and delegated lab trust review keep Ubuntu qualification and successful qualified publication pending. Physical-token hardware is not required by prospective lab policy v2; physical assurance remains unverified. See [current continuation](handoff/CURRENT.md) and [source-pinned PAM repair](handoff/solutions/ubuntu-pam-crl.md). The source repository is public by [Jake's October 24 decision](docs/decisions/0006-public-source.md); runtime inputs, credentials and raw evidence remain private.

**Luna and external engineering agents: [start here](docs/EXTERNAL-INTEGRATION.md).** The short guide maps capabilities to source and tests, with explicit integration limits.

Completed ISO delivery can enter the existing RHEL 10 BIOS acceptance path with
`python -m wormhole intake register /private/inbox/release.ready.json`, then
`python -m wormhole intake submit REQUEST_SHA256 --terraform /private/tools/terraform`. Periodic
`python -m wormhole intake scan /private/inbox --submit --terraform /private/tools/terraform` uses
the same dispatch. See the [installation contract, completion marker and runtime
evidence](handoff/solutions/directory-intake.md). This path does not call the ISO
builder or remaster delivered bytes; it remains an unqualified lab baseline.

The measured [lifecycle comparison](handoff/solutions/lifecycle-comparison.md)
keeps Terraform. Native libvirt passed the same RHEL candidate and checks, but
saved only about three seconds of lifecycle commands while adding another
resource/recovery implementation. Use the existing foreground VM command, its
durable launch acknowledgment and `python -m wormhole.vm_baseline --status RUN_UUID`.
RHEL hardening, encryption and qualified publication are deferred.

[Ubuntu lab policy v2](docs/UBUNTU-LAB-POLICY.md) prospectively removes physical-token
hardware as a lab requirement and delegates trust-anchor review to Codex. Physical
assurance remains unverified; legitimate Pro input and actual USG/FIPS execution
remain required. Earlier results retain their original policy attribution.

For the Build Jake ISO Pipeline chat, use the [single copy-and-paste handoff prompt](handoff/JAKE-ISO-PIPELINE-PROMPT.md).

All 20 children WORM-002 through WORM-021 are Done at approved revision 2 with 66 passing criteria and solution comments under Jake's explicitly delegated normal Owner workflow. All 21 original delivery PRs are merged. [Merged verification](handoff/MERGED-VERIFICATION.md) records the tested main commit `c3d440a3c7eee9691f30315b49146eb72998d2df`, fresh source/CI checks and Ubuntu reference smoke. Minx remains authoritative for workflow state; this document is not a claim lease. Engineering review and Owner-directed automation are distinct from independent human examination.

Original merged-source runtime is the Ubuntu reference Run `8f14b817-486f-4340-87fd-85fe53a9aa6b`: all 43 required checks passed, the reference gate was eligible, cleanup finished with no pending resources and the unrelated sentinel was unchanged. Production ISO eligibility remains false.

Original twenty-target qualification: twenty simultaneous stock Ubuntu targets at `825a594862b816401d4b963329e6242bd8ed8aeb`, Run `290ad14a-e6ec-4822-ae36-258d336ecc38`, 160 readiness pairs, 200 functional rows, 200 inventory rows and twenty full 123-package inventories. All 23 transient resources were removed, admission finished with no pending resources and the unrelated sentinel unchanged. Two point samples/CPU deltas are not guaranteed peaks. See [WORM-020](handoff/WORM-020-checkpoint.md).

Start with [AGENTS](AGENTS.md), [state](docs/STATE.md), [handoff](handoff/CURRENT.md), [architecture](docs/ARCHITECTURE.md) and [fidelity](docs/FIDELITY.md). The [historical matrix](docs/acceptance-matrix.md) indexes original tested commits/evidence hashes; it does not relabel earlier homelab results as final-source CI parity.

## Local verification

Use CPython 3.12.14 and Git. Application dependencies are standard-library-only; no pip installation is needed. Run from this checkout with an installed Python executable:

```text
python -m wormhole doctor
python scripts/verify_repository.py
python scripts/verify_acceptance_matrix.py
python -m unittest discover -s tests -v
```

These commands do not provision homelab resources. Platform skips stay explicit. Repository hygiene checks selected patterns/links, not every possible secret.

The [controlled parity runner](docs/CI-PARITY.md) adds a fixed seventeen-case
synthetic operation with safe diagnostics and explicit process failure. Use a
fresh clean checkout per mode; this is separate from actual container runs.

The legacy synthetic fixture is a separate limited operation. Use dedicated absolute storage outside Git/vault sync, substituting an actual workspace and returned UUID:

```text
python -m wormhole run --workspace WORKSPACE --fixture
python -m wormhole report RUN_UUID --workspace WORKSPACE
python -m wormhole verify RUN_UUID --workspace WORKSPACE
python -m wormhole cleanup RUN_UUID --workspace WORKSPACE
```

`run` without `--fixture` records an unsupported attempt and returns nonzero. Actual Linux operations use the [runtime CLI](docs/CLI.md), [pipeline](docs/PIPELINE.md), [private publisher](docs/PUBLICATION.md), [isolation](docs/ISOLATION.md) and [twenty-target operation](docs/TWENTY-TARGETS.md). Resource-allocating commands require the approved environment and current authority; documentation does not authorize arbitrary-machine execution.

Actual component records cover Ubuntu/UBI, separate optional PowerShell, one/five/twenty-target paths, candidate identity, native inventories, recovery and private local tested-byte publication. Generated inputs and synthetic assessment remain labeled. [WORM-021 evidence](handoff/WORM-021-checkpoint.md) records actual matching manual/GitHub parity and safe diagnostics from genuinely failed jobs. GitLab authorship is not execution. [Repository controls](docs/REPOSITORY.md) separates merges, source CI and runtime execution. The documentation-only follow-up has its own PR/main checks; it does not relabel the qualified `c3d440a3` source.

Production ISO eligibility is always false. Container evidence cannot qualify an installable ISO. Follow the extension checkpoint for actual VM observations; scanner/STIG acceptance, proprietary infrastructure repair, remote release and external-model orchestration are not implied.
