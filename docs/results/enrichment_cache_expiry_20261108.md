> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Enrichment cache-expiry enforcement — 2026-11-08

Status: **FIXED+VERIFIED** for the audited expiry defect (WIRE-3, ADR-041).
WIRE-11 remains paused and unresolved. No live API calls were made for this task.

## Reproduced defect

The same enrichment engine returned stale memory copies after SQLite correctly
rejected them at their deadline: successful results at 86400 seconds, negative
`not_found` and `rate_limited` results at 900 seconds, and entries loaded shortly
before the original SQLite deadline. Memory-only caches also had no time metadata.
Expired copies could bypass the cap/quota checks that a fresh lookup should reach.

New regression tests before implementation:

```text
13 failed, 1 passed in 0.45s
```

## Implementation

`EnrichmentEngine` continues querying SQLite first when configured. A miss now
evicts the matching local result and deadline instead of returning stale memory.
SQLite handles expiry using the existing persisted timestamp comparison, so warming
a new engine cannot grant a fresh lifetime to an old entry. Deleted rows also
invalidate memory copies. No schema or database API changes were required.

Memory-only engines record a deadline after the provider returns, using optional
`cache_clock` injection with `time.monotonic` as the default. Entries are valid only
before their deadline. A hit does not slide the deadline. The existing public result
mapping and result identity for fresh memory hits are preserved. Expired entries
are removed when accessed; this is not a background cleanup or capacity feature.

The existing TTL policy remains 86400 seconds for `ok`, 900 seconds for other
provider-result statuses. Cache misses proceed through normal lookup caps, quotas,
and provider routing. A blocked refresh returns its appropriate unavailable status
instead of stale intelligence. Fresh hits consume no additional lookup budget.

## Verification

Fourteen new cases in `tests/test_enrichment_cache_expiry.py` cover:

* Positive, not-found, rate-limited, and error result boundaries in both modes.
* Fresh reuse immediately before expiry and refresh exactly at expiry.
* SQLite-warmed entries preserving their original deadline and deleted-row handling.
* Caps and daily quotas after expiry, plus fresh-hit accounting when limits are reached.
* Changed provider findings becoming visible after refresh without mutating old results.

Provider stubs, simulated clocks, and in-memory SQLite kept these tests offline
and immediate; tests did not sleep. SQLite's clock was replaced only within the
test fixture, with normal pytest restoration. Production code contains no test
framework dependency. No existing tests were deleted, skipped, or loosened.

```text
Focused cache/enrichment/quota/database selection:
51 passed in 1.34s

python -B -m pytest -q -p no:cacheprovider --tb=short
340 passed, 1 warning in 8.05s
```

The full suite used its built-in network guard. The warning is the existing
Starlette HTTPX TestClient deprecation. No dependencies or migrations were added.
