> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Provider attempt quotas - 2026-11-08

Status: **FIXED+VERIFIED** for built-in providers through EnrichmentEngine
(WIRE-3 follow-up, ADR-043). Explicit implementation approval was provided.
WIRE-11 remains paused and unresolved. No live API calls were made.

## Reproduction and implementation

Before implementation, the new regressions reported:

```text
20 failed, 1 passed in 5.54s
```

The audit found three sends (503, 503, 200) counted as one lookup despite a daily
limit of one, local throttling/validation charged without sending, timeouts missing
RPM accounting, a check/increment race across connections, response-day charging,
and daily budgets unenforced without SQLite. Cache hits were already free.

VirusTotal, AbuseIPDB, and URLhaus now call a shared attempt gate before every
HTTP send. RPM availability is established first, including any allowed wait;
then daily quota is atomically reserved and the RPM timestamp recorded. Denied
quota consumes neither a reservation nor an RPM slot. All executed attempts keep
their reservations, including HTTP failures, malformed responses, and timeouts
whose remote receipt cannot be established. No response-time increment remains.

SQLite uses a conditional UPSERT and commit to enforce the cap across independent
connections. Dispatch UTC day is selected after any RPM wait. Memory-only engines
share a locked process-local ledger; separate processes require SQLite for shared
budgets, and restart resets memory-only accounting. None/non-positive limits keep
the existing unlimited semantics. Logical lookup caps remain per dispatch, rather
than per retry. Cache hits, validation/missing-key rejection, and local throttling
do not consume built-in daily budgets. Quota denials are deliberately not cached.

Scoped context callbacks select the current engine quota gate, allowing one
provider instance to be shared without binding it to the last-created engine.
The context is restored after exceptions. Reservation storage errors propagate
before sending. Providers accept injected sender, clock, and sleep callbacks;
engine quota clocks and memory ledgers are also injectable.

Opaque legacy/custom providers retain one conservative reservation per dispatch.
Their hidden internal retries cannot be observed until they adopt the attempt
hook. Direct calls outside an engine enforce RPM but have no daily ledger. The
ledger measures local attempts, not the provider's authoritative billing/quota
usage. Existing persisted counts may undercount historical attempts and cannot
be reconstructed; no migration or retrospective rewrite was performed.

## Verification

The first focused run after implementation reported `40 passed, 1 failed`. The
older bounded-retry fixture skipped sleep without advancing its clock, leaving
Retry-After active under the corrected gate. It now injects an advancing clock
and sleep function; all original assertions remain. No tests were deleted,
skipped, or weakened. Additional 429 and context/boundary coverage was then added.

New test names in `tests/test_provider_attempt_quotas.py` (29 parametrized cases):

- `test_each_retry_reserves_daily_quota_and_rpm_slot`
- `test_retry_stops_before_send_when_daily_budget_exhausted`
- `test_local_throttling_does_not_consume_daily_quota`
- `test_validation_rejection_does_not_consume_daily_quota`
- `test_timeouts_conservatively_keep_each_attempt_reservation`
- `test_429_retry_and_cache_hit_have_correct_attempt_counts`
- `test_process_local_quota_shared_between_memory_only_engines`
- `test_reservation_charged_to_dispatch_day_not_response_day`
- `test_quota_denial_does_not_poison_cache_after_day_reset`
- `test_atomic_reservation_across_independent_sqlite_connections`
- `test_injected_sender_clock_and_sleep_cover_every_retry`
- `test_shared_provider_uses_current_engine_quota_context`
- `test_reservation_failure_prevents_send_and_restores_context`
- `test_wait_reserves_on_day_after_rpm_delay`

Complete offline suite with the default network guard:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
405 passed, 1 warning in 17.40s
```

The warning is the existing Starlette HTTPX TestClient deprecation. No dependency
or schema changes were added. Documentation records the changed accounting
contract in README, ARCHITECTURE, DECISIONS (ADR-043), TASKS, and GEMINI.
