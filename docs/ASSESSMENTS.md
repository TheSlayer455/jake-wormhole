# Synthetic assessment component (WORM-016)

This original JSON format exercises parsing and reference policy. It is not CKL,
Evaluate-STIG output or a real scanner adapter. No scanner package, proprietary
system, production finding threshold or transport compatibility is assumed.

The caller declares a nonempty unique finding set and applicability before input
is parsed. The component freezes that plan with the source and Run identity,
preserves original bytes privately and records SHA256/size. It accepts at most
64KiB and128 findings, rejects duplicate JSON members/IDs, unsupported formats,
missing/unplanned findings, invalid statuses and unsafe control text. Unknown
input never turns into zero findings. Failed originals remain available; changing
the input requires a new Run rather than overwriting a failed attempt.

The format supports Open, Not a Finding, Not Reviewed and Not Applicable.
Versioned `wormhole.synthetic-reference-v1` policy rejects Open or Not Reviewed;
Not Applicable requires the exact applicability and reason declared in advance.
Counts, readable text and the normalized assessment share the same parsed records.
Reporting re-reads the original and frozen plan, recomputes policy, and rejects
changed counts, findings, outcomes, originals or eligibility flags.

Reference-policy pass/reject is separate from reference-release eligibility.
Both release flags remain false for either outcome: synthetic assessment,
absent installation evidence, undefined production policy and an incomplete
release gate remain explicit limitations. WORM-017 owns the complete evidence
gate. Existing v1 release guards and synthetic foundation artifacts are unchanged.

Use dedicated storage outside Git and vault synchronization. These commands run
local generated fixtures only and allocate no Docker resources:

```text
python -B -m wormhole.assessments fixture --workspace WORKSPACE --case pass
python -B -m wormhole.assessments fixture --workspace WORKSPACE --case reject
python -B -m wormhole.assessments fixture --workspace WORKSPACE --case malformed
python -B -m wormhole.assessments report RUN_UUID --workspace WORKSPACE
```

Supported cases also include unsupported and incomplete. Exit0 means the
synthetic policy passed; exit1 means a parsed policy rejection; exit2 means an
invalid/incomplete operation. None authorizes publication or production use.
The returned run ID identifies retained originals, frozen plan and component
receipt. Reports use the same bytes across processes. Whole-pipeline state stays
separate; this component cannot convert the existing fixture into runtime proof.
Run from a clean committed checkout. Source changes or an existing component
attempt refuse mutation, and every write uses the exact Run lock and owned paths.

The API is `assess_run(run, raw_bytes, expected_findings)` and
`report_assessment(run)`. The first acquires its own Run lock, so callers must not
hold a nested lock. It accepts bytes and declarations, never a command, URL,
plugin, scanner configuration or path to fetch. The published authoring contract
is [synthetic-checklist-v1.schema.json](../schemas/synthetic-checklist-v1.schema.json).
Private-original consistency is not tamper-proof protection against a host
administrator able to rewrite all source and records.
