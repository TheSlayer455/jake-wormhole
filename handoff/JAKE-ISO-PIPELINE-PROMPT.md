Continue this **Build Jake ISO Pipeline** conversation. Use the finished Jake Wormhole work to reduce the real pipeline's elapsed time while preserving required outputs, validation, provenance, security and recovery. My priority is the fastest reliable pipeline. Start with the pipeline and decisions already established in this chat, then use the evidence below to make the next concrete improvement.

Wormhole is finished. Its 21 original delivery PRs and the verification follow-up were merged. Use it as an inspected reference and reuse compatible implementation where appropriate. Keep ISO work in its verified repository and environment; preserve completed Wormhole evidence.

The repository `TheSlayer455/jake-wormhole` is now public by my explicit October 24, 2026 decision. Use evidence snapshot `898d8764f46f661b852eb3332c12d2d6925d79d7`. Application qualification belongs to `c3d440a3c7eee9691f30315b49146eb72998d2df`; that later evidence snapshot changes only documentation. The snapshots describe repository privacy at their observation time. Read these first:

- [Merged verification](https://github.com/TheSlayer455/jake-wormhole/blob/898d8764f46f661b852eb3332c12d2d6925d79d7/handoff/MERGED-VERIFICATION.md)
- [Architecture](https://github.com/TheSlayer455/jake-wormhole/blob/898d8764f46f661b852eb3332c12d2d6925d79d7/docs/ARCHITECTURE.md)
- [Evidence limits](https://github.com/TheSlayer455/jake-wormhole/blob/898d8764f46f661b852eb3332c12d2d6925d79d7/docs/FIDELITY.md)

If GitHub or these files are unavailable in your environment, say which files you need and request the smallest relevant sanitized excerpts. Use the facts supplied here meanwhile; distinguish them from source you inspected yourself. Refresh current source before implementation and keep the tested revisions above attached to their original observations. Public source does not make runtime inputs, credentials or raw evidence public.

Verified results from October 24, 2026:

- The 788-test suite passed with explicit skips: Windows/Python 3.12.14 had 515 passes and 273 skips; Linux/Python 3.12.3 had 778 passes/10 skips as a normal user and 786 passes/two skips as root. Final snapshot GitHub CI also passed on Python 3.12.14, with 778 passes/10 skips.
- At qualified source `c3d440a3`, actual manual/GitHub controlled modes returned **0 / 1 / 1**. Their three semantic files matched byte for byte; both deliberate failures retained validated uploaded diagnostics. These were seventeen-case synthetic modes, not real ISO builds.
- A fresh actual Ubuntu reference Run `8f14b817-486f-4340-87fd-85fe53a9aa6b` passed all 43 required checks in **50.1 seconds**. Report/gate replay agreed. Four containers and the network were removed; the candidate image was retained, admission finished with zero pending resources, and the unrelated service sentinel was unchanged.
- Earlier actual stock twenty-target qualification, source `825a594862b816401d4b963329e6242bd8ed8aeb`, Run `290ad14a-e6ec-4822-ae36-258d336ecc38`, took **195.1 seconds**. It passed 160 readiness pairs, 200 functional rows, 200 inventory rows and twenty complete package inventories. All 23 transient resources were removed. Readiness took **102.4 seconds, 52.5%** of the total. Twenty targets coexisted with task forks four; this was not twenty simultaneous candidate/ISO builds.

Those timings come from different harnesses and sources; they are not a controlled scaling comparison or a prediction for Jake ISO. Resource samples were point observations, not peak-capacity guarantees. Wormhole's container results leave its production ISO eligibility false. Wormhole does not establish real ISO boot/install, VM/RHEL installation, real scanner/STIG/Evaluate-STIG compatibility or remote runtime-artifact release. Its GitLab configuration was authored and locally checked, without official GitLab lint or an actual GitLab runner execution.

Work through this sequence:

1. Reconstruct the actual ISO pipeline from this chat and accessible current source. Identify stages, dependencies, inputs/outputs, runners/helpers, caches and queue boundaries. Treat Jakeboom1's reported RKE2/runners/helper placement, Jakeboom1/7's reported matching specifications, and Jakeboom7's reported 192 GB RAM/planned 1 TB upgrade as reports until checked. Do not assume the upgrade is installed or that RAM is the bottleneck. Use sanitized Luna updates already provided here; obtain additional updates through me unless I explicitly authorize contact.

2. Establish a representative baseline. Separate queue time from execution, transfer, build, readiness, validation, publication and cleanup. Capture cache hits/misses, bytes transferred, concurrency and CPU/memory/disk/network observations. Identify the real critical path and the highest-cost repeated work. Ask for missing measurements in one focused request while continuing analysis that the available evidence supports. Wormhole's readiness result is a lead to investigate, not a diagnosis of this pipeline.

3. Map actual pipeline stages to these inspected Wormhole patterns. For each proposed reuse, name the exact module/revision, required production adapter, expected benefit and verification:

   | Pipeline concern | Wormhole source to inspect |
   | --- | --- |
   | Verified transfer/reassembly | `docs/CHUNKS.md`, `wormhole/chunks.py` |
   | Stable base/helper/tool caches, separated from controller revisions | `docs/IMAGES.md`, `images/images.lock.json`, `dependencies.lock.json` |
   | Readiness states, deadlines and attributable failures | `docs/READINESS.md`, `wormhole/readiness.py`, `wormhole/fleet_readiness.py` |
   | Measured capacity, bounded concurrency and shared allocation locks | `docs/ADMISSION.md`, `wormhole/admission.py` |
   | Complete planned checks, source-bound reports and evidence replay | `docs/PIPELINE.md`, `wormhole/pipeline_records.py`, `wormhole/pipeline_replay.py` |
   | One manual/CI command, real failure propagation and safe diagnostics | `docs/CI-PARITY.md`, `.github/workflows/verify.yml`, `.gitlab-ci.yml` |
   | Publish exact tested bytes without rebuilding | `docs/PUBLICATION.md`, `wormhole/publication.py` |
   | Exact-owned cleanup and interrupted-run recovery | `docs/RECOVERY.md`, `wormhole/recovery.py` |

   Inspect implementation and tests before copying it. Chunk fixtures are generated/local-or-loopback, bounded to 8 MiB; the remote registry adapter refuses unsupported use. The candidate reference pipeline has one candidate-bound target plus supporting containers and synthetic assessments. Its publisher writes private filesystem bundles. Real ISO-size inputs, registries, runners and release destinations need their own measured, authorized adapters and tests.

4. Choose the smallest experiment on the measured critical path. Specify the baseline, change, success threshold, correctness checks and rollback before making it. Consider content-bound cache reuse, eliminating repeated downloads/rebuilds, stage overlap and readiness orchestration where measurements justify them. Rebuild only when relevant content/recipe/tool dependencies change. Set concurrency from measured CPU, RAM, storage and network headroom. Keep structured results separate from bounded console output. Preserve required checks and failure visibility while reducing elapsed time.

5. If this chat has authorized repository access and execution tools, implement and test that bounded improvement through the normal review workflow. Otherwise, produce one executable Codex handoff with the verified allowed repository, exact scope, prerequisites, stable acceptance criteria, commands, before/after measurement method, rollback and evidence requirements. Prepare a Minx import batch only when requested; verify existing work before proposing duplicates. This prompt supplies context and a performance objective, not credentials or access to additional systems.

6. Compare equivalent before/after runs on recorded revisions and inputs. Show observed wall time, cache state, resource observations and unchanged output/validation results. Keep cold and warm runs separate. Include failed experiments and unverified checks. Distinguish implementation, tests, merge, deployment and acceptance; use fixture-only improvements as fixture results until a representative real pipeline run verifies the benefit.

Keep normal homelab workloads, authentication, routing, VPN, storage and recovery controls intact. Use isolated branches/worktrees and exact run-owned resources. Preserve uncertain/interrupted state for scoped recovery; do not use broad cleanup, global prune, weakened checks or public tunnels to obtain a faster result.

Start your reply with the current evidence-based critical path, the specific Wormhole components worth reusing, and the first measurable experiment. State explicitly when the critical path is still unmeasured. Include only the missing information that actually blocks that next step. If execution access is unavailable, finish with the concrete Codex handoff so the work can continue.
