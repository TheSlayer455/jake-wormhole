# Keep Terraform; make launch, progress and failure observable

Decision: retain Terraform. A successful native-libvirt comparison established no
reliability or overall speed advantage. The alternative was removed from supported
execution at [63a130a](https://github.com/TheSlayer455/jake-wormhole/tree/63a130a249111fc10c229a66922a51895b87e40e); its source/private evidence remain attributable to the experiment.

## What was compared

| Real RHEL 10 baseline | Total elapsed | Recorded lifecycle stages |
| --- | ---: | ---: |
| [Terraform, d39f7a0](https://github.com/TheSlayer455/jake-wormhole/tree/d39f7a0bc6c10e200fff44fa26bf866bef9ab517) | 272.246 s | 5.631 s |
| [Native libvirt, 7b59975](https://github.com/TheSlayer455/jake-wormhole/tree/7b59975c81debc1832929f02aa87d64769a310b3) | 278.225 s | 2.377 s |

Lifecycle totals cover Terraform init/validate/plan/apply/destroy and all native
provisioning/inspection/cleanup/verification stages; common operations are separate.
These are one healthy execution per implementation, not a statistical speed
comparison. Retained evidence verifies identical candidate ISO bytes, unchanged
builder code and the same BIOS/8 GiB/two-vCPU/32 GiB guest contract. Both completed
fresh empty-disk installation, trusted final SSH, actual Ansible, 413 RPM records,
all 948 native assessment outcomes and exact-owned cleanup. Native results match:
172 pass, 261 fail, 56 not applicable, nine not checked and 450 not selected.
The DVD's 0.1.76 vendor-draft assessment is not current DISA qualification.

No Terraform defect was demonstrated. Its lifecycle is approximately 2% of the
original run; installation is the larger cost. Native added 162 production lines
plus recovery/ownership logic, while the container layer still needs Terraform.
Maintaining both would add operational choices without an established benefit.

## Small changes retained in the existing controller

The [controller](https://github.com/TheSlayer455/jake-wormhole/blob/63a130a249111fc10c229a66922a51895b87e40e/wormhole/vm_baseline.py)
emits a flushed launch acknowledgment after acquiring the shared admission lease.
The durable record supplies run/source identity, phase, observed progress and
terminal outcome. Status compares the recorded supervisor PID and start identity;
liveness is separate from meaningful installation/controller progress. Neither a
missing acknowledgment nor a stopped local observer proves a guest failure.

Final authentication and installed-system readiness are distinct. Once trusted
SSH reports an inaccessible completion marker, exit 42 identifies that first
failure immediately and blocks dependent Ansible, functional, inventory and audit
checks. It does not wait out the readiness budget or report a passing empty catalog.
The [existing recovery path](https://github.com/TheSlayer455/jake-wormhole/blob/63a130a249111fc10c229a66922a51895b87e40e/wormhole/ubuntu_recovery.py)
retains original source/outcome attribution and reconciles only verified owned
resources after the recorded supervisor and operation stop. Cleanup cannot turn
unknown execution into success. [Focused checks](https://github.com/TheSlayer455/jake-wormhole/blob/63a130a249111fc10c229a66922a51895b87e40e/tests/test_vm_foundation.py)
cover status and result accounting; source tests do not replace live execution.

At `63a130a`, the real marker fault preserved final authentication, exit 42 and
`completion-marker-inaccessible` as the first failure. Detection took 0.672 seconds;
the complete attempt took 238.174 seconds. All four downstream checks were blocked,
Ansible/catalog dispatch stayed false, the result stayed failed and cleanup completed.
The interruption trial stopped the exact recorded supervisor during installation.
Status reported `unknown-supervisor-stopped` while the saved outcome was running.
Storage refused `storage_active_run`. Existing recovery validated original
Terraform/configuration ownership and removed the owned resources and orphan console.
The final outcome stayed unknown with `supervisor_interrupted_without_terminal_result`,
six blocked checks and CLI exit 1. Admission reconciled; no VM domains remained.
Docker/K3s stayed active. Source verification passed 957/960 tests with three skips
in 84.318 seconds, all 17 parity cases passed, and CI at `63a130a` passed.

## Execute and inspect the public example

Use the authorized Linux operator/controller, verified media, pinned Terraform
and one-guest admission. These foreground commands use the same implementation.

```bash
python3 -m wormhole.vm_baseline --distribution rhel10 \
  --source "$APPROVED_RHEL_ISO" --terraform "$PINNED_TERRAFORM"
python3 -m wormhole.vm_baseline --status "$RUN_UUID"
python3 -m wormhole.vm_baseline --distribution rhel10 \
  --source "$APPROVED_RHEL_ISO" --terraform "$PINNED_TERRAFORM" \
  --reuse-run "$RECONCILED_RUN_UUID" --scenario marker-inaccessible
python3 -m wormhole.vm_baseline --recover-run "$STOPPED_RUN_UUID" \
  --terraform "$PINNED_TERRAFORM"
```

The fault command intentionally changes only its disposable guest and must fail
the acceptance run. It cannot qualify the original candidate. Status is read-only;
recovery requires confirmed stopped execution and recorded ownership. Preserve
private diagnostics and inputs before cleanup. Do not infer completion from a
detached shell, local command timeout, process existence or an old status file.

## Luna integration task

1. Inspect the existing Terraform and execution path between **ansible control
   node** and **rhel kvm host**. Retain working provisioning and authentication.
2. Reduce an opaque launch chain to the existing foreground execution command
   plus its durable run record; acknowledge actual admission/start, not dispatch.
3. Record meaningful installer/check transitions separately from process liveness.
   Read status from the real runner context without creating another controller.
4. Reproduce one final-system readiness failure. Expect authenticated access,
   a specific first failure, blocked dependent checks and a nonzero terminal result.
5. Interrupt one owned attempt; prove stopped-process identity, preserve unknown
   work and original evidence, then use existing exact-owned recovery. Revert the
   narrow controller change if it breaks the established execution contract.

Home measurements use an Ubuntu KVM host and one RHEL 10 BIOS guest. They do not
prove work-host behavior, customer eligibility or the cause of a work failure.
No work infrastructure was accessed. Lab and production qualification stay false;
the [RHEL baseline](rhel10-install-baseline.md) records remaining assessment/hardening work.
