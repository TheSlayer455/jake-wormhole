# WORM-015 checkpoint

<!-- WORM-015 actual qualification 14d510044757f588c256e27c62a0cbad037d7ca1 -->
## WORM-015 actual observed software inventory

Exact clean source `14d510044757f588c256e27c62a0cbad037d7ca1` completed six fresh actual SSH/Ansible inventory
cases, observed at 2026-10-23T19:44:15.537475+00:00. Actual healthy observations contain
ubuntu 123 packages / 10213 canonical bytes, ubi 188 packages / 17538 canonical bytes. Full Debian epoch/revision/architecture and RPM
name/epoch/version/release/architecture are retained. Virtual RPM key headers are
separate. Every full package row and required expected/observed result is present
in the same frozen record used for JSON/TXT. Their exact hashes match the actual
exporter. Helper/provisioner versions and host-shared kernel are separate fields.

| Platform / scenario | Run | Underlying operation | Pass/fail/unverified | Cleanup |
| --- | --- | --- | --- | --- |
| ubuntu / healthy | `61d48412-350e-481f-9ee1-242ec47c37c4` | passed | 14/0/0 | completed |
| ubi / healthy | `63ae38dc-161e-44f1-b5e4-28acc4f0916b` | passed | 12/0/0 | completed |
| ubi / missing-package | `b3d1f1ce-1e3c-4b41-aabe-5db9a197b891` | failed | 12/1/0 | completed |
| ubi / wrong-version | `4ca5fe86-ca16-496d-ac9b-39c772d4b348` | failed | 11/1/0 | completed |
| ubuntu / collector-unavailable | `dd316694-d3d8-48aa-8c0b-1cbb87145fc4` | failed | 1/0/13 | completed |
| ubuntu / wrong-identity | `24695bc7-4e33-4b7a-af31-cc7bb53da71f` | failed | 0/1/13 | completed |

The optional-package negative observes actual absence without installing it.
Wrong-version and wrong-identity are controlled expectations, not target damage
or changed cleanup ownership. Failed collection produces unverified dependent
rows, never an empty successful inventory. Every case preserved its primary,
completed exact-owned cleanup, retained state/images/evidence and passed the
unrelated sentinel check. Private raw helper captures remain private; source-bound
capture metadata and independently checked canonical packet/export hashes are
in the [evidence](evidence/WORM-015.json).

homelab_linux: 488 cases, 486 pass/2 explicit skips in 37.066 seconds; windows: 488 cases, 306 pass/182 explicit skips in 47.875 seconds; native_linux: 488 cases, 486 pass/2 explicit skips in 28.913 seconds. These source fixtures are separate from actual runtime acceptance.
Independent engineering source review is clear at the named revision; publication,
hosted CI and Owner acceptance are separate. No complete pipeline, full VM/RHEL
installation, ISO boot, operating-system STIG, scanner or production eligibility
is established. See [history](evidence/WORM-015-initial-attempts.json) and [review](reviews/WORM-015.md).
