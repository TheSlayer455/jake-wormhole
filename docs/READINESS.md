# SSH and Ansible readiness (WORM-007)

This adapter is a partial operation. Source fixtures do not establish actual
SSH or Ansible execution. The authorized operator must record exact-source real
acceptance separately. Complete-pipeline and production ISO eligibility stay false.

The caller holds the existing Run lock, Docker scope and canonical admission
lease across provisioning, readiness and teardown. No nested lease or replacement
provisioner is created. `ProvisioningSession.create_stopped()` establishes the
real owned target/network and stopped target confinement;
`start_and_inventory()` starts it explicitly and returns actual provider inventory.
The existing `provision()` composes those operations.

```python
readiness = ReadinessSession(provisioning)  # same .run and .lease
readiness.start_helper()
provisioning.start_and_inventory()
readiness.wait_ready()
readiness.require_ready()                  # before dependent checks
readiness.cleanup()                        # exact helper only
provisioning.destroy()                     # Terraform target/network; controller last
# Caller finishes admission only after all resources and run-label sweeps reconcile.
```

The helper is original qualified build `9e864d00-ea9f-4a85-bdb5-f5873166e4d7`,
immutable image `sha256:4f7f306ecd431b4b48169777966d88c1f09f2139506176a6b85203f5bae69a71`.
Its original build provenance stays intact. Only current reviewed `readiness/runtime.py`
is copied into the Run's `private/helper-source/runtime.py`. Its host parent is
0700 and its public-code file is0444, owned by the state operator. The staged
checkout keeps its original private permissions. The single-file read-only bind
exposes the code inode at `/opt/readiness/runtime.py` without exposing private host
ancestors. Source/copy hashes, exact path, owner/group, ordinary unique inode,
size and modes are checked before execution and recovery; no keys, environment
or configuration are copied. Original source provenance and retained copy identity
are separate fields in the private controller context. The helper has UID/GID10001, all capabilities
dropped, no-new-privileges, read-only root, bounded private tmpfs and the existing
512MiB/1CPU/128PID/log limits. It joins only the actual owned internal network,
has no host ports or Docker socket, and is inspected stopped before start and at
each probe. Actual cgroups are measured. Its existing PID1 lifetime600s and wait180s
remain finite. No image recipe or host package changes are needed.

Target transitions are recorded independently: created, started, endpoint
discovered, TCP reachable, SSH identity accepted, Python usable, Ansible usable
and required readiness checks complete. Pending probes retain actual attempt
timing and target identity. `wait_ready(on_poll=callback)` may invoke a trusted
in-process coordinator callback to start the target after a measured delay.
There is no command/text callback interface. `poll()` exposes one bounded
progression attempt. Readiness itself never starts or repairs a target.

Provider inventory must match the exact owned target/network/endpoint, SSH user
and port before any connection. TCP and SSH run inside the validation helper.
An ownership-checked control-plane reader obtains only the target's public host
key, then the existing bounded receiver provisions the run key and known-hosts
pin into helper-private tmpfs. This is trust establishment, not SSH acceptance.
`pin_trust()` can establish that pin before a controlled host-key-change test;
it returns false while startup is pending and never replaces an established pin.
`observe_hostkey()` records the current public fingerprint and whether it matches
the original, without accepting the new identity.

SSH explicitly retains strict host-key checking, the run-scoped known-hosts file,
public-key-only authentication and no multiplexing/forwarding. A real SSH command
must observe UID10001. A separate SSH executable check identifies an unusable
configured Python interpreter. Genuine pinned Ansible Core2.21.5 then runs
`ansible.builtin.wait_for_connection` and `ansible.builtin.ping`, requiring the
expected target's structured result and actual `pong`. Connection is explicitly
`ssh`; no local connection or target Docker exec substitutes for these checks.
The inventory sets `ansible_ssh_use_tty=false` and
`ansible_ssh_transfer_method=piped`. Pinned2.21.5 otherwise defaults to forced
TTY allocation, which the target deliberately forbids. Piped transfer uses
SSH/dd without the smart SFTP/SCP fallback; it does not change sshd, image,
authentication or trust settings. Observed transfer warnings alone do not prove
that the target's configured SFTP subsystem is absent.
Ansible local and remote temporary directories are private helper tmpfs and
`/tmp/wormhole-ansible`, respectively. No facts, application acceptance or repair
tasks are run by readiness.

Fixed ad-hoc `ansible --tree` produces per-target JSON; the adapter does not parse
human console success messages. The tree callback exists in pinned2.21.5 and is
deprecated for removal in2.23; a future dependency update must replace or requalify
it. Both probes require a successful CLI exit, complete capture and the expected
positive field shape. A wait result's `elapsed` field alone is insufficient;
`msg`, exception, failure, unreachable or skipped results cannot establish
readiness even if a callback omits the failure flag. Missing, duplicate/wrong-identity,
truncated, malformed and fabricated `pong` results also fail.

The coordinator has one absolute90s readiness deadline, bounded attempts and
short connection timeouts. Control-plane inspections, public-key reads and private
input delivery use the remaining budget; late replies cannot establish readiness.
Trusted in-process callbacks and admission refresh retain their own bounded
operation timeouts, and the deadline is checked again when they return. This is
not preemption of arbitrary Python callbacks. Child capture limits memory/output and terminates its
owned process group. Ansible's own waits have explicit smaller limits plus the
outer deadline; their defaults are not a wall-clock guarantee. The actual Docker
StartedAt timestamp must leave target lifetime300s sufficient for remaining
readiness and20s cleanup reserve. Target restart invalidates an already accepted
ready record. There is no automatic TTL extension or retry that replaces targets.
Later `require_ready()` revalidates the already accepted live identities under a
separate20s check budget without reopening the establishment window. Cleanup also
keeps independent bounded operations so expiry never prevents owned teardown.

Fixed scenarios `wrong-key`, `wrong-user` and
`configured-interpreter-unavailable` select only reviewed inputs. Wrong-key
material is generated inside helper-private tmpfs by its existing ssh-keygen;
the target retains the original authorized key. The interpreter negative selects
the fixed absent `/run/wormhole/no-such-python`, confirms SSH accessibility and
actual Ansible failure, and never claims that Python packages are absent from the
qualified image. Controlled endpoint/network mismatches are rejected before
foreign contact. A changed host key retains the old pin and must produce the
actual strict SSH refusal. Authentication outcomes are distinguished by the
controlled scenario and observed refusal, not by pretending SSH exposes a more
specific server-side explanation.

Portable `evidence/readiness.json` stores bounded stage/target/result metadata,
public host-key fingerprints and relative private-log references. Keys, raw
diagnostics and generated Ansible inventory/results remain private. No key
contents or hashes of private keys are exported. A failure remains failed even
when teardown succeeds; `require_ready()` blocks dependent work. The complete
pipeline's existing unsupported artifacts are not overwritten with a readiness
pass.

`cleanup()` removes only the exact owned helper and reconciles its absence.
It neither deletes Terraform resources nor finishes admission. It can stop a
known owned helper with damaged networking without touching other resources.
`ReadinessSession.resume_cleanup(run, lease)` requires the same clean original
source, an already-held reconciliation-only lease, exact private context and
journal identity. It allocates/restarts/executes nothing. Missing context, changed
identity/source, unknown create/mutation or a lost outer exec result stays blocked.
A complete inner probe timeout is a known failed probe and does not imply unknown
Docker allocation. Legacy state or elapsed time never authorizes adoption.
A known pre-create failure can recover a bound null-helper context only when no
helper intent is unknown, the journal contains only the known Terraform resources,
and an exact run/role observation finds no helper. It does not invent an ID or
remove an unregistered object.
The read-only `readiness_status(run)` returns validated retained primary failure,
unknown outcome and cleanup metadata before recovery, including when cleanup must
refuse. Recovery must preserve this outcome before trying another component.

Run scoped fixtures without infrastructure:

```text
python -m unittest discover -s tests -p test_readiness.py -v
```

Primary evidence: [pinned wait action](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/plugins/action/wait_for_connection.py),
[ping](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/modules/ping.py),
[ad-hoc CLI](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/cli/adhoc.py),
[tree callback](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/plugins/callback/tree.py)
and [SSH connection options](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/plugins/connection/ssh.py).
