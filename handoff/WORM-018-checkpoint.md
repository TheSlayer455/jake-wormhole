# WORM-018 tested-byte private publication outcome

Tested runtime source: `85f4c56116f30679c083795bed17bb56f7b25d6d`. The actual four-case suite `7cfbc355-3649-4b88-99b1-15ff2a7ec589` passed.
This delivery record describes engineering qualification, not Owner acceptance.

| Platform | Scenario | Publication case | Fresh Run | Result |
| --- | --- | --- | --- | --- |
| ubuntu | healthy | complete | 403b58ad-9596-4a8b-a3b3-f22e297c0bc3 | completed |
| ubi | healthy | complete | 1a94b32f-5aca-4489-b032-05976e531fdd | completed |
| ubuntu | healthy | marker-linked-interruption | 9d224f7e-7598-44f1-9e62-391ae5f07231 | incomplete |
| ubuntu | version-expectation-mismatch | ineligible | f42c3797-a4cb-4856-af21-f674d37cfa22 | absent |

Ubuntu and UBI complete outputs contain respectively 24 and 25 exact files.
Every original candidate/evidence byte was compared, hashes and closed file sets
matched, duplicate destinations refused without overwrite, and the unmodified
pinned UBI EULA was retained. The actual separate UID observed EACCES for the
private release. Producer completion separately acknowledged directory fsync.

The owned marker-linked child exited 86 with two names for the same marker
inode/bytes and link count two. Read-only inspection reported incomplete;
duplicate publication refused. This is not a completed release. The wrong
expected-version reference preserved `candidate_required_check_mismatch`, remained ineligible and
created no publication. All original pipeline cases finished exact scoped
cleanup, finalized admission and preserved the unrelated sentinel.

Only tested candidate files and safe reference evidence were published locally.
The image digest is metadata; no image, remote release or production ISO was
published. Synthetic assessment and one-container scope remain explicit.
Earlier failed attempts remain historical in the portable proof record and are
not credited as successful qualification. See [the portable proof record](evidence/WORM-018.json).
