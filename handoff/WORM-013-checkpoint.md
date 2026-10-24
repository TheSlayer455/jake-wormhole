# WORM-013 continuation checkpoint

<!-- WORM-013 actual qualification dfff72bec8bbea050bae73e6bba846e388f449e9 -->
## WORM-013 actual candidate qualification

Exact source `dfff72bec8bbea050bae73e6bba846e388f449e9` completed four fresh, serial actual candidate acceptance
cases observed at 2026-10-23T17:56:51.036437+00:00. The healthy case retained seven passing read-only
SSH/Ansible checks. The controlled version-expectation negative retained six pass
and one fail; it changed the expected version, not the actual target. Wrong
candidate and image identities refused before Terraform/helper allocation.

| Scenario | Run | Underlying operation | Primary failure | Cleanup |
| --- | --- | --- | --- | --- |
| healthy | `c912efb0-a63b-439a-b4cb-b028ac74cbec` | passed | none | completed |
| wrong-candidate | `1ff477b0-d748-4e9b-9da3-82b8ac5391e9` | failed | candidate_binding_invalid | completed |
| wrong-image | `9e67de2c-11f0-4411-9aa7-7aa65491e449` | failed | candidate_image_mismatch | completed |
| version-expectation-mismatch | `297cece7-858c-4d45-977f-3bb19ea4429e` | failed | candidate_required_check_mismatch | completed |

Each case bound reconstructed source, candidate manifest, a distinct derived
image and the fixed test contract. Cleanup removed exact owned containers and
networks, retained each derived image and private evidence, and preserved the
existing unrelated sentinel. The stock qualified helper/provisioner stayed
unchanged. No candidate ISO or proprietary input was used.

Exact-source fixtures: Windows CPython3.12.14, 330 tests, 195 pass and 135 explicit
skips in 24.651s; nonroot WSL CPython3.12.3, 330 tests, 327 pass and three skips
in 18.731s; actual homelab CPython3.12.3, 330 tests, 328 pass and two skips in
24.693s. The repository baseline passed with 148 tracked files and 129 local link
targets. Source fixtures are separate from the real runtime cases.

The earlier `baaf2f6` attempt remains failed with `candidate_base_invalid`.
Its reviewed private original-source operator proved zero allocation and finalized
the admission journal through `AdmissionLease.resume/finish`, preserving original
receipt hashes and failure. It made no Docker mutation, adoption or unknown-result
clear. The new public recovery adapter has fixture coverage; it was not the
operator exercised for that historical failure.

Portable [evidence](evidence/WORM-013.json) and [review](reviews/WORM-013.md) contain sanitized Run,
binding, check and cleanup details. Private captures, keys, Terraform state and
generated source remain outside Git. Production ISO eligibility and complete
runtime-pipeline flags remain false. Publication, hosted CI and Minx review or
acceptance are not established by this checkpoint. Refresh Minx before continuing.
