# Merged-main verification

All 21 original delivery PRs were merged. PR21 merged on October 24, 2026 at 19:50:33 UTC, establishing tested main source `c3d440a3c7eee9691f30315b49146eb72998d2df` with tree `f5a69b447b224840c66229c00f0fd2e102812449`. All PRs were retargeted to main; PR21's merge commit brought every original head into main, and GitHub recorded the other 20 as indirectly merged by 19:50:35 UTC. Its parents are the prior main and accepted parent-closeout delivery. The merged tree matches the tree of closeout commit `2de9f1489af876ba28b355079870b3e912be8820`.

These are new post-merge observations, separate from the unchanged [original evidence](../docs/acceptance-matrix.md). A documentation-only follow-up receives its own PR/main CI; it does not relabel this tested source or rerun historical work.

## Local source checks

| Environment | Interpreter | Full suite | Duration |
| --- | --- | --- | --- |
| Windows | CPython 3.12.14 | 788 total: 515 passed, 273 explicit platform skips | 121.747 s |
| Linux nonroot | CPython 3.12.3 | 788 total: 778 passed, ten explicit skips | 76.733 s |
| Linux root | CPython 3.12.3 | 788 total: 786 passed, two Windows-only skips | 78.403 s |

All three also passed repository verification, original acceptance-matrix verification and local doctor. The Linux interpreter differs from the pinned hosted/Windows 3.12.14 interpreter; that difference is retained rather than hidden. Root Linux executes the extra UID/EACCES and Docker-mocked RPM fixtures. Source fixtures allocate no homelab resources.

Commands were the installed Python executable with `-B` and these fixed arguments:

```text
-m unittest discover -s tests -v
scripts/verify_repository.py
scripts/verify_acceptance_matrix.py
-m wormhole doctor
```

Fresh Linux-owned full-history checkouts came from a hash-verified local bundle. Hooks and non-file Git protocols were disabled for child processes; global Git trust/configuration and host permissions were unchanged. Historical `6f3f28e830911aea21f216d6e1c006a96202a771` source blobs remain available for exact preapply proof fixtures.

## Manual and hosted parity

Three fresh Linux nonroot manual executions and three GitHub executions used the same merged source and wrapper:

```text
python3 -B scripts/run_ci_parity.py --mode all
python3 -B scripts/run_ci_parity.py --mode required-failure
python3 -B scripts/run_ci_parity.py --mode unexpected-success
```

Each mode retains the complete seventeen-case grid, native component outcomes, original-record fingerprints and completed private fixture cleanup. Across manual/hosted runs, 102 component Run UUIDs are distinct. For each matching mode, `plan.json`, `results.json` and `decision.json` are byte-identical. All five canonical files and their checksums validated; execution metadata keeps actual interpreter/runner identity separately. Manual Linux used CPython 3.12.3; hosted GitHub used pinned CPython 3.12.14.

| Mode | Observed wrapper exit | Hosted result |
| --- | --- | --- |
| `all` | 0 | [Main run 40127124129](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40127124129): success |
| `required-failure` | 1 | [Run 40127210886](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40127210886): intended failure step failed |
| `unexpected-success` | 1 | [Run 40127214045](https://github.com/TheSlayer455/jake-wormhole/actions/runs/40127214045): intended failure step failed |

Both red jobs then successfully validated and uploaded the five safe diagnostic files. The rejecting assessment remains rejected in required-failure mode; the healthy assessment remains passed in unexpected-success mode. Their deliberate expectation mismatch produces sixteen harness passes and one harness failure. Diagnostic validation does not turn either job green.

Per-case component exits are domain CLI contract mappings. Pre-exit `execution.json` contains a computed runner return code. The outer wrapper and provider job separately observe actual process/job outcomes. Raw logs, credentials, private paths and Terraform state are not portable artifacts. GitLab remains authored/local-checked, without official lint or runner execution claims.

## Fresh Ubuntu reference smoke

A single healthy Ubuntu reference run completed at the merged source on October 24, 2026 at 19:57:53.863187 UTC:

- Run: `8f14b817-486f-4340-87fd-85fe53a9aa6b`.
- All 43 required rows passed. The limited reference gate was eligible; production ISO eligibility stayed false.
- Separate original report/gate replays matched the completed run. Observed reference-run duration was 50.075 s; doctor/report/gate took approximately 0.068/0.452/0.443 s.
- Cleanup completed, canonical admission finished with no pending resources, and the unrelated sentinel was unchanged.
- The finished six-resource archive records four containers and the network absent, with the candidate image retained. Its original-byte SHA256 is `888912040ca6e7bc4301f0f5b3a8bd8499d0292f6951447b0c8ada084bae9562`.

This is a new one-target Ubuntu observation. Latest actual twenty-target qualification remains `825a594862b816401d4b963329e6242bd8ed8aeb`, Run `290ad14a-e6ec-4822-ae36-258d336ecc38`: 160 readiness pairs, 200 functional rows, 200 inventory rows and twenty 123-package inventories, with all 23 transient resources absent. Its original evidence, failed predecessors and source attribution are unchanged. The merge did not rerun five/twenty-target or UBI qualification and does not claim otherwise.

## Scope and continuing attribution

Original ticket checkpoints/evidence, the historical matrix and their hashes remain unchanged. Old Runs still require their original clean source for replay/recovery. Retained images/private state and deliberately incomplete publication trees remain intact.

This documentation-only update changes no application, test, schema, recipe, pin, workflow or recovery policy. Its later commit/main CI is separate from the exact `c3d440a3` source qualification above. No production ISO, VM/boot/install, scanner/STIG, proprietary repair, remote release or new deployed service is established.
