# Replay provenance stage 1 - 2026-11-08

Status: **FIXED+VERIFIED** for ADR-047 stage 1 (implementation ADR-048), with
explicit operator approval. History remains evaluation-row based. Stage 2 cache
validation, stage 3 metric scopes, and stage 4 presentation are not implemented.
WIRE-11 remains unresolved. No live requests or operator database migrations were
executed during this task.

## Storage and lifecycle

evaluation_runs stores run UUID, entry point, lifecycle timestamps/status, and an
immutable run-local ad hoc namespace. triage_observations stores observation UUID,
run/ordinal uniqueness, timeline identity, acquisition origin, optional unique
fresh-attempt UUID, timestamps/status, verdict reference, sanitized failure
category, and terminal outcome digest. Evaluations gain nullable observation,
evaluation-context, cohort, and provenance-version fields. Verdict cache identity
and expiry columns are reserved nullable fields for stage 2.

CLI/evaluation processing creates a run and starts each observation before triage.
Skips have observation metadata and no evaluation. Terminal model failure remains
an Unavailable evaluation. Storage/protocol failures fail the run and interrupt
pending work; they do not fabricate unavailable results. KeyboardInterrupt also
propagates with failed/interrupted lifecycle metadata. Hard process death can
leave running/pending records; these remain incomplete rather than guessed failures.
Database connections close on success, failure, and run-start failure. Missing CLI
input now raises FileNotFoundError with a failed run, instead of returning a
successful zero-metric summary. Empty valid inputs can complete with no observations.

Finalization uses BEGIN IMMEDIATE or a nested savepoint under the connection lock.
It validates observation/timeline/cohort/verdict identity, compares verdict/outcome
snapshots, and atomically persists verdict, evaluation, and observation completion.
The evaluation observation reference has a unique non-null index. Identical retries
return the same evaluation ID, including across independent connections. Conflicts
raise without overwriting prior snapshots. Injected terminal-update failure rolls
back the new verdict and evaluation, leaving the observation pending for retry.
Existing unlinked insert_evaluation callers remain supported; linked outcomes must
use the finalizer. Nested verdict/evaluation writers defer their commits.

## Acquisition and truth boundary

Gemini exposes acquire_timeline while analyze_timeline and the base protocol remain
compatible. Context-local hooks report actual memory-cache returns or attempted
HTTP sends. An origin notification is persisted before sending; if it fails, no
HTTP call occurs. Fallback HTTP calls share one fresh logical attempt UUID. This
metadata is not a remote request/billing count or exactly-once delivery guarantee.

SQLite cache replay is recorded as cache origin, still unverified. Opaque providers
without acquisition metadata are unknown, not guessed fresh from verdict IDs.
Explicit acquisition providers must notify before work and return matching origin.
Every stage-1 cache_validation value remains unverified. Evidence/inference hashes
and verdict expiry stay NULL until a later stage can establish them accurately.

The recorder computes a versioned evaluation-context SHA-256 digest from resolved
binary/severity labels and effective dataset policy. It is evaluation-only metadata;
none of these provenance values enter the model prompt or cache key. Current cohort
hashes are run-local ad hoc namespaces, not verified reusable dataset manifests.
get_provenance_coverage reports legacy versus linked evaluation rows; linkage alone
does not establish known fresh origin or future quality eligibility.

Legacy initialization adds tables/nullable fields/indexes without assigning old
rows fake run IDs, origin, or versions. Existing snapshots and history counts stay
intact. The earlier unavailable migration still runs before the new lineage FK
columns are added. Its rollback fixture includes current writer columns while
retaining all old NOT NULL, rollback, data-preservation, and FK assertions.

## Offline verification

Initial new regression selection before implementation:

```text
11 failed in 1.19s
```

Compatibility verification after fixing the evaluation helper's path scope and
the legacy writer fixture:

```text
53 passed, 1 warning in 8.46s
```

Expanded stage-1 selection:

```text
26 passed, 1 warning in 4.51s
```

Final complete suite (project virtual environment, DATABASE_PATH=:memory: isolates
the default ASGI app; the default pytest network guard remains enabled):

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
496 passed, 1 warning in 33.26s
```

Twenty-six new cases in tests/test_run_provenance.py:

- test_terminal_outcome_is_idempotent_and_run_finishes
- test_conflicting_terminal_retry_is_rejected (3)
- test_replay_occurrences_preserve_history_counting
- test_atomic_failure_preserves_pending_observation_and_rolls_back_verdict
- test_run_error_marks_pending_work_interrupted_without_inventing_outcome (2)
- test_skips_and_opaque_acquisition_do_not_claim_fresh_attempts
- test_run_cannot_complete_with_pending_work_or_accept_work_after_completion
- test_legacy_rows_remain_unknown_after_repeat_initialization
- test_independent_connections_finalize_one_observation_once
- test_verdict_snapshot_conflicts_on_terminal_retry
- test_observation_identity_and_foreign_keys_are_enforced
- test_lifecycle_uses_injected_clock
- test_real_engine_reports_fresh_then_memory_cache_and_keeps_evaluation_metadata_out
- test_acquisition_storage_failure_stops_http_and_marks_run_failed
- test_provider_cannot_claim_fresh_after_work_without_notification
- test_real_runners_persist_lifecycle_but_keep_history_metrics (2)
- test_context_closes_database_even_when_run_creation_fails
- test_tracked_outcome_cannot_bypass_atomic_finalization
- test_wrong_cohort_cannot_be_attached_to_an_observation
- test_fallback_http_calls_are_one_logical_fresh_attempt
- test_cli_skip_or_missing_input_has_honest_run_lifecycle (2)

Real runner tests use injected HTTP responses through the actual Gemini engine,
real intake/persistence, and in-process API requests. Two evaluation runs reuse one
verdict with one HTTP send, two observations, and API total=2. Two CLI runs likewise
retain history total=2. Memory replay records fresh/cache origins with one send;
fallback uses two sends but one logical attempt. The prompt contains none of the
observation/context/cohort or independent-ground-truth metadata.

No existing test was removed, skipped, or weakened. No dependency was added. The
warning is the existing Starlette HTTPX TestClient deprecation.

## Remaining work

Cache identity/model-policy/expiry checks remain stage 2. Current hits may still be
stale, and are deliberately marked unverified. Quality deduplication, reusable
cohort validation, fresh-attempt availability scopes, and dashboard scope selection
remain later stages. Legacy provenance cannot be reconstructed reliably. Current
API metrics retain their old history semantics; stage 1 does not remove replay
weighting or turn cached success into primary-model verification.
