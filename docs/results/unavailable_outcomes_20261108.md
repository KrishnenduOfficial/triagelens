> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Unavailable outcome persistence - 2026-11-08

Status: **FIXED+VERIFIED** for attempted-triage persistence and availability
accounting (WIRE-6 follow-up, ADR-045), with explicit implementation approval.
No live API calls were made. WIRE-11 remains paused and unresolved; the latest
operator primary-only output was HTTP 429, without enough detail to identify its
exact quota window. A successful smoke probe did not verify primary-model triage.

## Reproduced behavior

The repeated-run audit used real CLI/evaluation runners, SQLite, and in-process
API requests with stubbed triage and no active enrichment providers. After two
successful CLI outcomes followed by a None result and an exception, there were
four timelines but only two evaluations. Availability incorrectly remained 1.0.
The evaluation runner counted None as Unavailable in memory but omitted the record
from SQLite, leaving API availability optimistic. Direct persistence failed a
foreign-key constraint because None became the string "None"; the schema also
required non-null prediction/verdict columns, and prediction conversion made None
false. Successful/failed metric differences across runs also reflect scope: CLI
uses the current run, while the API uses stored evaluation history.

New regressions before implementation:

```text
9 failed, 3 passed, 1 warning in 3.17s
```

## Outcome contract

Every attempted logical triage returning no verdict or raising an Exception now
produces one Unavailable evaluation. Both runners persist it. SQL NULL is retained
for verdict_id, llm_prediction, is_correct, and confidence_score. Ground truth is
independent and can remain true, false, or unknown. No missing prediction becomes
a benign decision or a false positive/negative. Per-timeline reads and full-history
reads preserve nulls. Unknown-label successful verdicts remain available outcomes.

Availability retains the existing definition:

```text
(labelled results + unknown-label results)
----------------------------------------------------------
(labelled results + unknown-label results + unavailable)
```

Unavailable results are excluded from confusion and calibration samples. Internal
HTTP retries/fallbacks are not separate logical outcomes. Deliberately skipped or
inactive CLI triage adds no evaluation; missing/failed engine initialization is
also outside this attempted-prediction denominator. Empty streams retain the
existing 1.0 convention, which is not a measured service-uptime claim. Cached
available results retain existing evaluation-row counting; replay weighting remains
a separate open finding.

CLI/evaluation console summaries now show unavailable counts and availability.
Generated evaluation rows label missing predictions Unavailable, and missing
ground truth Unknown, rather than presenting either as Benign. The evaluation
runner catches model-call exceptions but lets timeline/evaluation storage failures
propagate so an incomplete persisted run cannot claim successful completion.

## Legacy migration

Fresh schemas allow nullable verdict_id and llm_prediction. On next init_db,
supported legacy schemas are rebuilt inside a savepoint with foreign-key
enforcement kept ON. The original table definition is retained except for those
two NOT NULL declarations. Existing columns/values/IDs, custom indexes/triggers,
and AUTOINCREMENT high-water marks are preserved. Foreign keys are checked before
replacing the old table. Any rebuild failure rolls back to the original table.
Initialization can be repeated safely; non-null verdict and timeline references
remain enforced. Old schemas missing confidence/severity-prediction columns still
receive the existing compatibility additions before rebuilding.

Custom tables with inbound foreign keys to evaluations are refused before
rebuilding: dropping the old table could otherwise cascade and delete their rows.
Those custom schemas need a separate explicit migration. Unsupported outcome-column
declarations also fail rather than silently rewriting an unrecognized schema.
No foreign-key-disable step is used.

Tests isolate the default ASGI database in memory via DATABASE_PATH=:memory: and
use temporary files for migration cases. No migration of operator database files
was executed as part of verification. Normal application startup/CLI init_db will
apply the supported migration to the selected file.

## Verification

First focused persistence/database/API run:

```text
31 passed, 1 warning in 4.49s
```

Migration rollback, unknown-label semantics, and unavailable-only API history
expanded the full suite to 447 passing cases. Review then added checks for custom
inbound references and storage-failure reporting; the unguarded reference case
reproduced before the safeguard:

```text
1 failed, 2 passed, 14 deselected, 1 warning in 1.60s
```

Generated report tests reproduced missing predictions being labelled Benign:

```text
2 failed, 17 deselected, 1 warning in 2.38s
```

Final full offline command (project virtual environment, DATABASE_PATH=:memory:
for ASGI import isolation; all ordinary tests still have the default network guard):

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
451 passed, 1 warning in 17.34s
```

Nineteen new cases in tests/test_unavailable_persistence.py:

- test_unavailable_roundtrip_preserves_sql_nulls_and_ground_truth
- test_unavailable_keeps_timeline_foreign_key_enforced
- test_legacy_migration_preserves_rows_ids_sequence_indexes_and_foreign_keys
- test_failed_legacy_migration_rolls_back_table_rebuild
- test_migration_refuses_custom_inbound_foreign_keys_without_losing_rows
- test_evaluation_storage_failure_cannot_report_success
- test_unavailable_report_does_not_label_missing_prediction_benign
- test_unknown_success_and_unavailable_have_distinct_availability_semantics
- test_api_reads_only_unavailable_history_instead_of_fallback_tracker
- test_repeated_runner_failures_are_persisted_and_in_api_denominator
- test_deliberately_inactive_cli_does_not_create_unavailable_outcome

Both runners are exercised through success/failure/success with None and raised
exceptions. The API sees exactly one evaluation per outcome and availability of
1.0, 0.5, then 2/3; current-run failure metrics show unavailable=1, availability=0.
Ground-truth true/false/unknown cases and an unknown available result plus an
unavailable result verify null/denominator semantics. Migration tests verify
deleted-ID sequence preservation (next ID 100), original data, indexes/triggers,
FK enforcement, rollback after denied DROP, and safe repeated initialization.

No existing tests were deleted, skipped, or weakened. No dependency was added.
The sole warning is the existing Starlette HTTPX TestClient deprecation.

## Remaining limitations

Historical missing failures are not backfilled: timelines without verdicts cannot
reliably distinguish skipped from failed attempts. Historical availability may
therefore remain optimistic. Severity evaluation fields are still lost in the
existing persistence path and need a separate fix. Cached re-evaluation still
adds evaluation rows and needs an explicit reporting policy. CLI remains scoped
to one run while API metrics aggregate stored history. Live WIRE-6 completion
still depends on a successful primary-model run after WIRE-11 is resolved.
