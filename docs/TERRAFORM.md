# Terraform smoke lifecycle (WORM-006)

This source implements the one-target provisioning adapter. Fixture tests mock
every Docker operation; actual Terraform/container acceptance must be recorded
separately by the authorized Linux operator. A successful partial operation does
not establish SSH/Ansible readiness, a complete pipeline or reference eligibility.

Use the exact reviewed clean source and existing authorized Linux Docker access:

```text
python -m wormhole.provisioning qualify
python -m wormhole.provisioning qualify --scenario provider-unavailable
python -m unittest discover -s tests -p test_provisioning.py -v
```

`qualify` creates a fresh real run in the fixed external runtime root, using the
new stable kernel run-lock policy. It records the existing unsupported complete
pipeline attempt, generates per-run authentication before taking its outer run
lock, then holds one canonical admission lease through its partial lifecycle.
Output identifies the run and relative receipt; failure identifies the failed run
without printing raw diagnostics or keys. No host Terraform/Ansible installation,
arbitrary Docker endpoint, source URL, image override or shell command is accepted.

The separately scoped trusted provisioner reuses the immutable qualified target
image `sha256:6d15eb2c495d48c1eb6485a74d1adaef3e0e3a6e7c83063ba8459f90c27c683e`.
Its role, source bind and fixed Python PID1 entrypoint differ from a target; this
does not relabel or rebuild that image. Image provenance remains in
[WORM-005 evidence](../handoff/evidence/WORM-005.json). The container runs as the
actual authorized state-owner UID/GID, including UID0 on the existing host, with
only a necessary existing socket group added. Socket access is root-equivalent
Docker control regardless of UID, not a narrow security boundary.

Before start, exact-ID inspection must match 512 MiB memory/no extra swap,
0.5 CPU, 128 PIDs, rotated logs, all capabilities dropped, no-new-privileges,
read-only root, private bounded tmpfs, network none and no host PID/IPC namespaces.
Only four binds exist: verified tools and authored source read-only, the run's
private Terraform directory read-write, and the fixed Docker socket. No private
key directory or target input directory is mounted in the provisioner. Actual
cgroups are read after start. Its PID1 lifetime is fixed at 600 seconds; expiry
exits124 and TERM exits143, ending the container's process namespace. State stays
on its private bind. There is no auto-remove/restart policy.

[Tool preparation](TOOLCHAIN.md) verifies pinned Terraform1.17.0/provider4.6.0
archives without executing them on the host. The original ZIPs and complete
unpacked mirror remain private. Inside the capped provisioner, actual Terraform
version, offline init with a read-only h1 lock, and provider schema are checked.
The fixed CLI configuration allows only that mirror and disables checkpoint
requests. Private HOME/data/configuration and an explicit environment prevent
ambient Terraform flags, credentials, Docker contexts or reattached providers
from selecting another execution path. No modules or direct provider fallback
are configured.

The fixed source [main.tf](../provisioning/main.tf) creates one internal local
bridge and a stopped target (`start=false`, `must_run=false`). Its typed saved-plan
allowlist checks identity, labels, resources/actions, inputs, capability/namespace
limits, tmpfs, public-only key bind and absence of host ports. Unknown sensitive
values, replacements, imports, modules and Terraform executable provisioners
refuse. Only the saved plan is applied. The configuration/lock hashes are checked
before each operation and the saved apply plan is hashed. All plans/state/logs
remain private; public key contents are not Terraform variables.

The target declares both entrypoint (`/usr/bin/python3`, the authored runtime)
and command (`target`) explicitly. Their combined process arguments match the
qualified image. An omitted command is OptionalComputed in provider 4.6.0 and
remained unknown in an actual plan; the validator continues to reject unknown
commands and inspection requires the exact declared split.

Docker provider4.6.0 has no PID-cap field. After actual apply/state observation,
the controller records exact owned IDs and observes the target still created and
never started before updating only its PID cap. It then inspects all confinement
again while stopped before starting it. Actual cgroup checks
follow. A saved refresh-only plan/apply and provider output supply the endpoint;
the controller cross-checks the exact Docker network/container. No guessed IP,
public port, native-created target or local connection substitutes for this.

Terraform 1.17's actual refresh-only JSON can have an empty planned root module
while refreshed owned resources appear in `prior_state.values`. The refresh guard
requires both exact owned IDs there, no infrastructure `resource_changes`, and
only bounded unique `resource_drift` updates for the same addresses, provider and
before/after IDs. Each drift result must equal its refreshed prior-state value;
the run output must retain the exact image/network/target identities. Missing
resources, creates/deletes/replacements, foreign IDs, unknown drift and modules
refuse. This observation layout never falls back to creating infrastructure.

Provider 4.6.0 disconnects the default bridge and connects the requested advanced
network while the target is stopped. `HostConfig.NetworkMode` remains `bridge`;
the actual endpoint map must contain only this run's network name. A stopped
endpoint may have an empty, pending network ID, backed by independent exact-ID,
name, ownership-label and internal local-bridge inspection. Once running, the
endpoint ID must equal the owned network ID. A default bridge, extra endpoint,
foreign network or noninternal network refuses; there is no repair fallback.

Raw Terraform JSON is bounded at4MiB, diagnostics at64KiB, each fixed operation
at120 seconds, and operation attempts at four. Host Docker-exec requests have a
supplementary135-second deadline. Outputs are exclusive files with size/hash and
completion receipts. Truncation, timeout or missing receipts never pass. The
controller durably records an unknown in-flight outcome before each mutating
Terraform operation; it clears that intent only after a successful terminal receipt
and matching captured output. A captured nonzero mutating exit remains unknown:
the provider may have timed out while the daemon continued. Controller interruption cannot silently authorize
another command against potentially running Terraform work. The
600-second provisioner lifetime additionally bounds an abandoned controller.
Disk budgets remain sampled planning/admission limits, not filesystem quotas.

`ProvisioningSession(run, held_lease)` is the later WORM-007/008 integration
boundary: the caller holds `run.locked()` and `images.docker_scope(run)` and passes
its existing real lease. `provision()` returns the actual versioned inventory;
the session retains exact controller/state/resources until `destroy()`. Do not
nested-acquire admission or mark the full pipeline passed from this receipt.

Destroy first reads actual state and verifies every ID/name/image/label, refuses
unexpected endpoints, validates an exact saved destroy plan, and applies it via
Terraform. Native target/network deletion is never a fallback. Empty final state,
exact resource absence and run-label sweeps are required. The provisioner is
stopped and removed last. Only then may the caller finish admission. Failed
provisioning retains state, primary diagnostics and pending resources; secondary
diagnostic/cleanup errors do not replace the primary failure.

For a known retained-controller failure at the same reviewed source:

```text
python -m wormhole.provisioning recover --run-id EXACT_RUN_UUID
```

Recovery takes the existing run lock and reconciliation-only canonical lease;
it creates no replacement controller and registers no resource. It checks exact
retained mounts, image, command, owner and existing pending IDs, then obtains a
fresh capacity check for only that existing provisioner. It may restart that exact
stopped container for fixed state/destroy operations. The admission plan is not
replaced. Unknown daemon results, missing context, legacy locks, source/ownership
changes and unmatched resources refuse. There is no generic confirmation flag
to clear an unknown result. General recovery belongs to WORM-008. Never delete
the journal, lock or Terraform state to bypass a refusal.

The fixed `provider-unavailable` scenario is an acceptance negative, not an
operator-supplied endpoint. Before input hashes are captured, it selects only
`unix:///run/wormhole/provider-unavailable.sock` in the authored provider block.
A bounded inside-container probe requires that exact tmpfs path to be absent and
an actual Unix connect to fail with ENOENT. The probe runs before an actual saved
apply; schema and plan alone need not contact Docker. A successful apply is an
unexpected failure of the negative scenario, never a passing negative result.

`provision()` preserves and raises the actual nonzero apply failure. The explicit
`prove_provider_unavailable()` method can clear only this scenario's uncertainty:
it binds successful preparation, the validated saved-plan hash, complete failed
apply diagnostics identifying the exact pinned provider client/Ping failure,
the SDK's fixed-endpoint wrapped sentence and authored network-resource context,
a second inside-container
ENOENT probe, empty actual state, no Terraform-owned IDs, and complete run-label
and journal observations showing only the existing provisioner. Every operation
file must match its bound terminal receipt and output hash; missing, extra,
timed-out or truncated attempts refuse. It accepts no confirmation flag or
arbitrary proof payload. Normal saved empty destroy and controller-last cleanup
then run. The primary Terraform failure and failed partial status remain intact;
the separately recorded negative proof does not turn failed provisioning into a
successful workload. Actual host acceptance must still verify this sequence.

Generic uncertain operations cannot be followed by another mutating Terraform
command or destroy, including within the original session. A captured nonzero
provider failure at the real socket remains unresolved; the fixed absent-endpoint
proof cannot authorize its cleanup.

Acceptance still requires two actual serial runs with disjoint state/names and
inventory, actual saved-plan Terraform lifecycle and cgroups, a provider failure,
an ownership-negative destroy attempt with an unchanged unrelated sentinel,
state/configuration/evidence checks for key contents/exposure, and final exact
cleanup. Record exact source, commands, observed outputs, timing and skips.

Primary references: [provider container schema](https://github.com/kreuzwerker/terraform-provider-docker/blob/v4.6.0/docs/resources/container.md),
[network schema](https://github.com/kreuzwerker/terraform-provider-docker/blob/v4.6.0/docs/resources/network.md),
[provider refresh behavior](https://github.com/kreuzwerker/terraform-provider-docker/blob/v4.6.0/internal/provider/resource_docker_container_funcs.go#L827-L950),
[Terraform mirror configuration](https://developer.hashicorp.com/terraform/cli/config/config-file#provider-installation),
and [plan JSON format](https://developer.hashicorp.com/terraform/internals/json-format).
