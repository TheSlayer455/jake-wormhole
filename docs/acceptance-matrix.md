# Historical acceptance matrix

This is an index of original, source-bound observations, not a rerun at the
current WORM-021 source. Expected-negative harness success retains the failed
underlying operation. Full hashes, exact JSON selectors, selected original
fields, cleanup references and limitations are in [the JSON record](acceptance-matrix.json).

WORM-021 is In Progress at this snapshot. Controlled manual/hosted parity and
safe failing-job diagnostics still need their own final evidence. GitLab runner
execution, scanner/STIG, VM/ISO and production eligibility are unverified or excluded.

| ID | Category / scenario | Original tested source | Observation | Evidence |
| --- | --- | --- | --- | --- |
| H001 | healthy-reference / image-ssh-qualification-1 | `731eabee3d69` | status=passed | [WORM-005](../handoff/evidence/WORM-005.json) |
| H002 | healthy-reference / image-ssh-qualification-2 | `731eabee3d69` | status=passed | [WORM-005](../handoff/evidence/WORM-005.json) |
| H003 | healthy-reference / healthy | `06c19f16d45f` | status=pass | [WORM-006](../handoff/evidence/WORM-006.json) |
| H004 | healthy-reference / healthy | `06c19f16d45f` | status=pass | [WORM-006](../handoff/evidence/WORM-006.json) |
| H005 | interruption-recovery / provider-unavailable | `06c19f16d45f` | status=pass | [WORM-006](../handoff/evidence/WORM-006.json) |
| H006 | readiness-auth-trust-network-python / healthy | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H007 | readiness-auth-trust-network-python / delayed-start | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H008 | readiness-auth-trust-network-python / never-starts | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H009 | readiness-auth-trust-network-python / wrong-key | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H010 | readiness-auth-trust-network-python / wrong-user | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H011 | readiness-auth-trust-network-python / configured-interpreter-unavailable | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H012 | readiness-auth-trust-network-python / wrong-endpoint | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H013 | readiness-auth-trust-network-python / wrong-network | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H014 | readiness-auth-trust-network-python / changed-host-key | `9db5f24fc8e2` | status=pass | [WORM-007](../handoff/evidence/WORM-007.json) |
| H015 | interruption-recovery / normal | `68bd82dd3202` | status=pass | [WORM-008](../handoff/evidence/WORM-008.json) |
| H016 | interruption-recovery / functional-failure | `68bd82dd3202` | status=pass | [WORM-008](../handoff/evidence/WORM-008.json) |
| H017 | interruption-recovery / cancelled | `68bd82dd3202` | status=pass | [WORM-008](../handoff/evidence/WORM-008.json) |
| H018 | interruption-recovery / interrupted-cleanup | `68bd82dd3202` | status=pass | [WORM-008](../handoff/evidence/WORM-008.json) |
| H019 | functional-version / healthy | `de745a6ee7f8` | status=pass | [WORM-009](../handoff/evidence/WORM-009.json) |
| H020 | functional-version / version-expectation-mismatch | `de745a6ee7f8` | status=pass | [WORM-009](../handoff/evidence/WORM-009.json) |
| H021 | functional-version / functional-expectation-mismatch | `de745a6ee7f8` | status=pass | [WORM-009](../handoff/evidence/WORM-009.json) |
| H022 | functional-version / configured-interpreter-unavailable | `de745a6ee7f8` | status=pass | [WORM-009](../handoff/evidence/WORM-009.json) |
| H023 | functional-version / unexpected-skip | `de745a6ee7f8` | status=pass | [WORM-009](../handoff/evidence/WORM-009.json) |
| H024 | functional-version / unreachable | `de745a6ee7f8` | status=pass | [WORM-009](../handoff/evidence/WORM-009.json) |
| H025 | readiness-auth-trust-network-python / smoke/healthy | `1920c9621017` | status=pass; underlying_status=passed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H026 | readiness-auth-trust-network-python / five-targets/healthy | `1920c9621017` | status=pass; underlying_status=passed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H027 | readiness-auth-trust-network-python / five-targets/healthy | `1920c9621017` | status=pass; underlying_status=passed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H028 | readiness-auth-trust-network-python / five-targets/delayed-start | `1920c9621017` | status=pass; underlying_status=passed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H029 | readiness-auth-trust-network-python / five-targets/never-starts | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H030 | readiness-auth-trust-network-python / five-targets/wrong-key | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H031 | readiness-auth-trust-network-python / five-targets/wrong-user | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H032 | readiness-auth-trust-network-python / five-targets/configured-interpreter-unavailable | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H033 | readiness-auth-trust-network-python / five-targets/wrong-endpoint | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H034 | readiness-auth-trust-network-python / five-targets/wrong-network | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H035 | readiness-auth-trust-network-python / five-targets/changed-host-key | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H036 | functional-version / five-targets/validation-interpreter-unavailable | `1920c9621017` | status=pass; underlying_status=failed | [WORM-010](../handoff/evidence/WORM-010.json) |
| H037 | powershell-source / missing | `88c8df01c389` | status=failed | [WORM-011](../handoff/evidence/WORM-011.json) |
| H038 | powershell-source / ordinary | `88c8df01c389` | source fields retained in JSON | [WORM-011](../handoff/evidence/WORM-011.json) |
| H039 | powershell-source / build | `88c8df01c389` | status=completed | [WORM-011](../handoff/evidence/WORM-011.json) |
| H040 | powershell-source / smoke | `88c8df01c389` | status=completed | [WORM-011](../handoff/evidence/WORM-011.json) |
| H041 | integrity-evidence / local/healthy | `72d3e6ded014` | acceptance_status=passed; operation_status=passed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H042 | integrity-evidence / local/missing | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H043 | integrity-evidence / local/duplicate | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H044 | integrity-evidence / local/reordered | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H045 | integrity-evidence / local/truncated | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H046 | integrity-evidence / local/corrupted | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H047 | integrity-evidence / http-loopback/healthy | `72d3e6ded014` | acceptance_status=passed; operation_status=passed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H048 | integrity-evidence / http-loopback/missing | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H049 | integrity-evidence / http-loopback/duplicate | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H050 | integrity-evidence / http-loopback/reordered | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H051 | integrity-evidence / http-loopback/truncated | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H052 | integrity-evidence / http-loopback/corrupted | `72d3e6ded014` | acceptance_status=passed; operation_status=failed | [WORM-012](../handoff/evidence/WORM-012.json) |
| H053 | integrity-evidence / ubuntu/healthy | `dfff72bec8bb` | status=passed; operation_status=passed | [WORM-013](../handoff/evidence/WORM-013.json) |
| H054 | integrity-evidence / ubuntu/wrong-candidate | `dfff72bec8bb` | status=passed; operation_status=failed | [WORM-013](../handoff/evidence/WORM-013.json) |
| H055 | integrity-evidence / ubuntu/wrong-image | `dfff72bec8bb` | status=passed; operation_status=failed | [WORM-013](../handoff/evidence/WORM-013.json) |
| H056 | integrity-evidence / ubuntu/version-expectation-mismatch | `dfff72bec8bb` | status=passed; operation_status=failed | [WORM-013](../handoff/evidence/WORM-013.json) |
| H057 | functional-version / ubi/healthy | `db5d8e74f544` | status=passed; operation_status=passed | [WORM-014](../handoff/evidence/WORM-014.json) |
| H058 | functional-version / ubi/missing-optional-package | `db5d8e74f544` | status=passed; operation_status=failed | [WORM-014](../handoff/evidence/WORM-014.json) |
| H059 | functional-version / ubi/version-expectation-mismatch | `db5d8e74f544` | status=passed; operation_status=failed | [WORM-014](../handoff/evidence/WORM-014.json) |
| H060 | functional-version / ubi/unsupported-os | `db5d8e74f544` | status=passed; operation_status=failed | [WORM-014](../handoff/evidence/WORM-014.json) |
| H061 | native-inventory / ubuntu/healthy | `14d510044757` | operation_status=passed | [WORM-015](../handoff/evidence/WORM-015.json) |
| H062 | native-inventory / ubi/healthy | `14d510044757` | operation_status=passed | [WORM-015](../handoff/evidence/WORM-015.json) |
| H063 | native-inventory / ubi/missing-package | `14d510044757` | operation_status=failed | [WORM-015](../handoff/evidence/WORM-015.json) |
| H064 | native-inventory / ubi/wrong-version | `14d510044757` | operation_status=failed | [WORM-015](../handoff/evidence/WORM-015.json) |
| H065 | native-inventory / ubuntu/collector-unavailable | `14d510044757` | operation_status=failed | [WORM-015](../handoff/evidence/WORM-015.json) |
| H066 | native-inventory / ubuntu/wrong-identity | `14d510044757` | operation_status=failed | [WORM-015](../handoff/evidence/WORM-015.json) |
| H067 | synthetic-assessment / pass | `3e11548a253f` | component_status=passed | [WORM-016](../handoff/evidence/WORM-016.json) |
| H068 | synthetic-assessment / reject | `3e11548a253f` | component_status=rejected | [WORM-016](../handoff/evidence/WORM-016.json) |
| H069 | synthetic-assessment / malformed | `3e11548a253f` | component_status=failed | [WORM-016](../handoff/evidence/WORM-016.json) |
| H070 | synthetic-assessment / unsupported | `3e11548a253f` | component_status=failed | [WORM-016](../handoff/evidence/WORM-016.json) |
| H071 | synthetic-assessment / incomplete | `3e11548a253f` | component_status=failed | [WORM-016](../handoff/evidence/WORM-016.json) |
| H072 | healthy-reference / ubuntu/healthy | `753b67d7e550` | status=passed; operation_status=passed | [WORM-017](../handoff/evidence/WORM-017.json) |
| H073 | healthy-reference / ubi/healthy | `753b67d7e550` | status=passed; operation_status=passed | [WORM-017](../handoff/evidence/WORM-017.json) |
| H074 | functional-version / ubuntu/version-expectation-mismatch | `753b67d7e550` | status=passed; operation_status=failed | [WORM-017](../handoff/evidence/WORM-017.json) |
| H075 | publication / ubuntu/complete | `85f4c56116f3` | qualification_status=passed | [WORM-018](../handoff/evidence/WORM-018.json) |
| H076 | publication / ubi/complete | `85f4c56116f3` | qualification_status=passed | [WORM-018](../handoff/evidence/WORM-018.json) |
| H077 | publication / ubuntu/marker-linked-interruption | `85f4c56116f3` | qualification_status=passed | [WORM-018](../handoff/evidence/WORM-018.json) |
| H078 | publication / ubuntu/ineligible | `85f4c56116f3` | qualification_status=passed | [WORM-018](../handoff/evidence/WORM-018.json) |
| H079 | overlap-resource-refusal / overlap | `973c24a4b9e1` | status=passed | [WORM-019](../handoff/evidence/WORM-019.json) |
| H080 | interruption-recovery / interrupted-run | `973c24a4b9e1` | status=passed | [WORM-019](../handoff/evidence/WORM-019.json) |
| H081 | interruption-recovery / interrupted-publication | `973c24a4b9e1` | status=passed | [WORM-019](../handoff/evidence/WORM-019.json) |
| H082 | overlap-resource-refusal / oversized-capacity | `973c24a4b9e1` | status=passed; synthetic; no allocation | [WORM-019](../handoff/evidence/WORM-019.json) |
| H083 | twenty-targets / stock-twenty-targets | `825a594862b8` | status=passed | [WORM-020](../handoff/evidence/WORM-020.json) |

## Interpretation

- PowerShell missing-package evidence uses an isolated empty local APT source/state; ordinary helper checks passed separately. It is not a package removed from the normal helper.
- Wrong-version, wrong-identity and applicability cases use declared controlled expectations; they do not claim a naturally broken production payload.
- WORM-019 overlaps live coordinators while serializing allocation. Its oversized-capacity refusal is synthetic; WORM-020 separately ran twenty simultaneous stock targets.
- Native inventories retain full target package versions and architectures. Helper/provisioner versions and the shared kernel are separate provenance.
- Publication is verified private local filesystem publication of tested reference bytes, not a remote release or image export.
- Original checkpoints, evidence, reviews and failed attempts remain unchanged. Private state, raw logs and credentials are not copied here.

## CI history

WORM-020 delivery source `193a9fd78b31595861904df2a93c26323bec2834` failed hosted verification because a depth-one checkout lacked the original `6f3f28e` fixture source.
The reviewed `fetch-depth: 0` correction preserves pinned actions, read-only permissions, disabled credential persistence and all tests.
Both hosted checks passed at `65db67b90fb104e1e58efffb5fb0e3d80f0c0871`. This is fixture CI success, not WORM-021 normalized parity.

Verify this index with `python scripts/verify_acceptance_matrix.py`.
