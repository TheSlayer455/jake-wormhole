# One-target functional validation (WORM-009)

The adapter executes one fixed read-only collector through genuine SSH Ansible
from the existing Docker-free helper. The caller holds the same Run lock,
canonical admission lease and Docker scope used for Terraform and readiness.
No host Ansible installation, target Docker exec, local transport, target repair,
new helper or replacement target is part of collection.

```python
readiness = ReadinessSession(provisioning, validation=True)
readiness.start_helper()
provisioning.start_and_inventory()
readiness.wait_ready()
validation = ValidationSession(readiness)
validation.validate()
validation.require_passed()
report = report_validation(provisioning.run)  # {'result': JSON record, 'text': same rows}
# Existing cleanup_session tears down helper first, then saved Terraform destroy.
```

This is an API example. The authorized coordinator must record actual commands,
source, runtime evidence and cleanup; source fixtures alone do not establish an
actual SSH/Ansible result. On validation failure, the exact held provisioning
session durably records the overall primary error before the component terminal
record. Existing primary errors are preserved. The coordinator subsequently uses
`cleanup_session(reason='failure')`, without duplicating an already recorded primary.
The established readiness receipt remains a separate historical fact. A lost
outer helper exec sets both validation and helper uncertainty and blocks cleanup
until that operation is reconciled. A complete failed inner check is known data.

The fixed `validation=True` option mounts only a hash-verified public code copy
of `validation/runtime.py` alongside the unchanged readiness source. Both files
are ordinary, unique, operator-owned 0444 in a private 0700 per-run directory,
each mounted read-only. No private key, environment, host directory or Docker
socket is exposed by these binds. Readiness verifies the same copied identities
on use and recovery. The validation adapter accepts no script path, command,
module, plugin, URL or arbitrary expected values from callers.

## Declared checks and actual observations

`evidence/validation-plan.json` is written before the validation probe. Its hash
binds one exact target/resource/network/image, the current controller commit,
the original immutable target build, current seven-file image recipe, collector
and helper-source hashes, fixed Ubuntu24.04/linux-amd64 applicability, scenario
and ten required target/check pairs:

- Ubuntu ID and VERSION_ID from the ordinary `/usr/lib/os-release`.
- Full dpkg versions for ca-certificates, python3, python3.12, openssh-client,
  openssh-server and openssh-sftp-server, compared to common/target image-lock pins.
- `/etc/ssh/sshd_config` SHA256 compared to the original unchanged recipe.
- `/opt/wormhole/runtime.py` SHA256 as this smoke payload's content revision.
- That verified baked payload's `public_key()` behavior with fixed synthetic
  valid and invalid public inputs. Its main entrypoint is never invoked.

The collector reads current files and runs actual dpkg-query; it does not trust
the baked installed.json doctor record as target observations. Payload code is
loaded from those exact verified source bytes into a module without invoking main
only after its source hash matches; a mismatch leaves the unexecuted
function check unverified, rather than claiming an observed functional defect.
The pure function cases prove only those declared behaviors of that baked file.
They do not establish a complete application suite or candidate-derived image.

The original target is build759b5541-a077-46ca-97a1-1cdfb782ba15 at source
5c4656c683f02b4dca51ee6e24bd9b476a6c781a, immutable image
sha256:6d15eb2c495d48c1eb6485a74d1adaef3e0e3a6e7c83063ba8459f90c27c683e.
Its completed original build must match the current full image recipe. The
controller SHA remains separate; no image is relabeled or claimed newly built.
Candidate-derived bundle/image binding belongs to WORM-013 and is unimplemented.

## Bounds, results and failure semantics

The fixed `ansible.builtin.command` uses an argv list with argument expansion
disabled, Python `-I -B`, no shell, no TTY and piped SSH transfer. Authentication
remains run-scoped public-key-only with the original strict known-host pin.
The helper's sanitized environment excludes ambient provider/SSH/Ansible overrides.
The target collector has fixed public paths, bounded reads and a three-second,
8KiB dpkg-query capture. No repair, package installation or persistent write is
performed by the collector; normal Ansible module files use the existing tmpfs.
Ansible's command `changed` flag does not assert a target mutation: this fixed
command performs the read-only operations described above.

One validation attempt has an absolute60s coordinator deadline and at most35s
outer helper exec, with a shorter inner deadline. Actual helper StartedAt/wait180
and target StartedAt/TTL300 must leave validation plus20s cleanup reserve. These
checks do not extend either lifetime. The trusted unreachable-test callback has
its own root-owned bounded operations; the validation deadline is checked on
return and cannot establish late success.

The fixed per-target tree result must identify the exact command and contain a
successful terminal exit and complete typed observation. Missing results, wrong
Run/source/plan/target, duplicates, malformed JSON, timeout, truncation, required
skip, unreachable or error cannot become success because zero failures were
recorded. Every terminal attempt has all ten required rows with expected,
observed, status and evidence references. No irrelevant check is silently dropped.

The private bounded original helper response is retained with size, SHA256 and
relative path. Execution, `require_passed()` and `report_validation()` share the
same strict parser. Reports re-read that capture and require the public
observations and rows to match it. Missing or changed capture blocks reporting
success. This is application consistency checking, not protection against a host
administrator who can rewrite all records and code. Private diagnostics and keys
are not copied into readable or JSON reports. Both report formats use the same
validated rows, with no independent pass calculation.

## Fixed negative cases

Each acceptance case must use a fresh Run and target. The source supports:

- `version-expectation-mismatch`: one deliberately wrong expected python3 version.
- `functional-expectation-mismatch`: one deliberately wrong expected function
  result. The actual healthy function output remains visible.
- `configured-interpreter-unavailable`: the deliberately absent configured
  `/run/wormhole/no-such-python`; this does not mean Python packages were removed.
- `unexpected-skip`: fixed Ansible command check mode without creates/removes,
  which the pinned module reports skipped. Required checks stay nonpassing.
- `unreachable`: only a trusted in-process `before_probe` coordinator callback,
  after successful readiness and endpoint freezing. The authorized harness stops
  the exact owned target, then actual Ansible contacts that unchanged endpoint.
  If readiness itself refuses first, rows record that blocker, not a fictitious
  Ansible unreachable attempt. There is no callback/command field in a CLI,
  import or serialized request.

Expectation/input negatives are labeled as such, rather than falsely claiming
actual package removal or a defective target function. All underlying failures
remain failed when a negative harness confirms the expected outcome or cleanup
succeeds. Complete-pipeline, publication and production ISO eligibility remain
false. No VM/ISO boot/STIG or Lightspeed repair conclusion follows.

Scoped fixtures: `python -m unittest discover -s tests -p test_validation.py -v`.
Primary implementation evidence: pinned Ansible
[command module](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/modules/command.py)
for argv/no-shell, disabled argument expansion and check-mode skips, and the
[SSH plugin](https://github.com/ansible/ansible/blob/v2.21.5/lib/ansible/plugins/connection/ssh.py)
for no-TTY/piped transport. Actual host acceptance is recorded separately.
