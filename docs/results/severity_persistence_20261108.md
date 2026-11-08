> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Severity-result persistence - 2026-11-08

Status: **FIXED+VERIFIED** for persisted severity snapshots and reconstruction
(WIRE-6 follow-up, ADR-046), following explicit implementation approval.
No live API calls or operator database migrations were executed. WIRE-11 remains
paused and unresolved; operator/live WIRE-6 completion is still pending.

## Reproduced defect

The offline audit found that EvaluationResult contained severity_ground_truth,
severity_prediction, and severity_correct, but SQLite stored only prediction.
Both readers omitted the other two fields. Five synthetic outcomes produced
severity_evaluated=3, severity_matches=2, and accuracy=2/3 in memory, but all three
API severity metrics were zero after persistence. Binary counts and availability
remained consistent. Adding/populating columns in a temporary audit database did
not help because the reader also needed correction.

New regressions before implementation:

```text
19 failed, 1 warning in 4.34s
```

## Implemented behavior

Fresh schemas include nullable severity_ground_truth TEXT and severity_correct
INTEGER. init_db adds either missing field to legacy schemas independently, with
no default or historical backfill. Existing data/IDs/indexes/triggers/sequences
are preserved. Repeated initialization is safe; partially extended schemas retain
their known values. The existing unavailable-outcome migration preserves these
columns when it rebuilds older NOT NULL outcome tables. Foreign keys stay enabled.

Writes snapshot the evaluation's severity label, prediction, and correctness.
True is stored as 1, False as 0, and unknown as SQL NULL. Both read paths restore
the label and tri-state correctness. Full-history readers select NULL for absent
legacy fields rather than failing or inventing results. Per-timeline readers
normalize absent new fields to None and convert known correctness to bool.

Stored labels/correctness are never reconstructed from binary correctness or
mutable source/verdict records. The existing prediction fallback to verdicts is
retained for older rows lacking a stored prediction. New complete snapshots stay
stable after a verdict or in-memory source record changes.

The evaluator and API route need no algorithm changes: AccuracyTracker already
reconstructs severity counts when severity_correct is present. Known mismatches
count in the denominator even when binary classification was correct. A successful
prediction with unknown binary ground truth can still have known severity
correctness. Missing severity labels and unavailable predictions remain excluded
from the severity denominator; an unavailable result can retain a known severity
label without fabricating a prediction. Existing confusion, calibration, and
availability behavior is retained.

## Verification

The first focused selection reported:

```text
1 failed, 56 passed, 1 warning in 7.21s
```

All new severity regressions passed. The remaining failure was an existing
unavailable-migration rollback fixture that recreated a table lacking the new
writer columns and then invoked the modern writer before initialization. Its
fixture now includes current snapshot columns while retaining the old NOT NULL
constraints. Every original rollback, row-preservation, FK, and retry assertion
remains unchanged. Dedicated new cases separately cover actual older schemas
without those columns and with/without earlier optional columns.

Final complete offline suite (virtual environment, DATABASE_PATH=:memory: for
default ASGI import isolation, default external-network guard enabled):

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
470 passed, 1 warning in 20.29s
```

Nineteen new parametrized cases in tests/test_severity_persistence.py:

- test_severity_snapshot_roundtrip_preserves_false_and_null (5)
- test_api_severity_denominator_matches_mixed_in_memory_results (1)
- test_legacy_migration_is_additive_preserves_history_and_does_not_guess (4)
- test_readers_handle_legacy_and_partially_extended_schema_without_migration (4)
- test_stored_severity_result_does_not_change_when_verdict_is_updated (1)
- test_runner_and_api_agree_on_persisted_severity (4)

The mixed API test confirms evaluated=3, matches=2, accuracy=2/3, unchanged binary
counts, and availability=0.8. Round trips compare the complete EvaluationResult
and reconstructed metrics. Runner tests use real intake/timeline/persistence/API
paths with stubbed external triage and no active enrichment providers. They
verify both HIGH/HIGH matches and HIGH/MEDIUM severity mismatches that are still
binary true positives. Legacy tests preserve row ID 7, an AUTOINCREMENT high-water
mark of 99 (next ID 100), original values, custom index/trigger, and FK checks.

No existing test was deleted, skipped, or weakened. No dependency was added.
The warning is the existing Starlette HTTPX TestClient deprecation.

## Remaining boundaries

Historical missing results remain NULL and excluded from severity counts. A
stored binary true positive cannot establish a severity match. The existing
zero-denominator severity_accuracy value is still 0.0; interpret it together with
severity_evaluated rather than as observed zero accuracy. Source-label policy and
cached replay weighting are unchanged. The current run and stored API history can
have different scopes. Selected operator databases receive migration on their
next init_db; none were migrated during these offline tests.
