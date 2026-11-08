> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Verdict cache validity - 2026-11-08

Status: **FIXED+VERIFIED** for ADR-047 stage 2 (implementation ADR-049), with
explicit approval. No live API requests or operator database migrations were run.
History remains evaluation-row based. Stages 3-4 and WIRE-11 remain unresolved.

## Reproduced gaps

The SQLite evaluation cache checked only timeline ID. Model comparison additionally
checked model name, but ignored changed evidence and expiry. Memory keys omitted
prompt/fallback policy, returned shared mutable verdicts, and served at the exact
TTL deadline. Stage-1 observations correctly labelled those hits unverified.

Initial offline regressions before implementation:

```text
19 failed, 1 passed in 4.08s
```

## Shared contract and validation

Gemini prepares its sanitized, masked, byte-bounded request once. A versioned
contract hashes model-visible events, time window, and compact intelligence,
excluding synthetic timeline/grouping identity from the evidence digest. Reuse
still requires the same timeline ID; cross-timeline reuse is not introduced.
Policy hashing covers the provider API, preparation version, ordered requested
model/fallback list, effective per-model generation settings, actual system
instruction/user template, and response schema. Independent labels/evaluation
metadata, API credentials, and transport timeout do not enter this contract.

Both cache layers use the same candidate validator. It requires supported
provenance version, matching hashes and timeline, allowed actual answering model,
finite timezone-aware generation/expiry, an unexpired fixed deadline, fresh model
schema validation, and a matching immutable verdict-body digest. Malformed JSON,
missing metadata, unsupported versions, changed bodies, future generation, naive
dates, changed evidence/policy, and disallowed fallback results are misses. An
invalid candidate cannot mask a failed fresh primary request as cached success.

Default engine cache lifetime is 3600 seconds, configurable via cache_ttl_seconds.
A shorter supplied LLMResponseCache TTL also bounds persistent reuse. A non-positive
memory-cache TTL disables verified reuse/writes. Engine TTL must be positive and
finite. UTC and memory-age clocks are injectable; default memory age is monotonic.
Expire at now >= deadline. Reads do not renew timestamps, and a longer later policy
does not extend an old fixed expiry. Invalid UTC clocks withhold the request before
HTTP. Sub-microsecond date precision is normalized to persisted UTC representation.

Memory stores serialized snapshots and returns newly validated detached models.
Caller mutation cannot corrupt later hits. Unversioned standalone get/set remain
available, but engine reuse additionally requires compatible provenance. With a
persistent store, SQLite is authoritative for acquisition: memory cannot bypass
rejected or deleted stored candidates. Search candidates for a valid contract,
including an older matching record behind a newer incompatible one.

Historical get_verdict_for_timeline and the API timeline display remain separate
from raw cache-candidate lookup. Unverified legacy verdicts remain viewable.

## Persistence and acquisition

Fresh verdict provenance uses the existing evidence/policy/version/expiry slots.
cache_generated_at and cache_verdict_hash are added as nullable fields. Old rows
stay NULL; no request attaches current provenance to an unverifiable old verdict.
New metadata is finalized atomically with verdict, evaluation, and observation.
An injected cache-metadata write failure rolls back verdict/outcome and leaves the
observation pending for lifecycle error handling. Existing provenance is immutable.

Acquisition returns cache provenance and validation state. A validated hit is
verified; an invalid candidate followed by fresh acquisition is rejected; a fresh
acquisition without a candidate remains unverified (not a cache hit). Observations
persist contract identity before cache return or HTTP send. Lookup/storage failures
propagate instead of being treated as safe misses. Opaque providers stay unknown
and have no verified persistent-cache bypass.

Both evaluation scripts use shared acquisition. The comparison writer persists
cache provenance but adds no evaluation rows, preserving its existing behavior.
Its database connection now closes on success/error. Cache-only reads do not
rewrite expiry. Ordinary evaluation replay still adds its own history observation;
same-observation persistence retries remain idempotent. Cache-disabled diagnostics
bypass both layers and keep their primary-only isolation.

## Verification

Compatibility selection initially reported `1 failed, 121 passed`: its sole
failure was a stage-1 assertion requiring all hits to remain unverified. The
assertion now requires exactly unverified/verified for fresh/validated replay,
while preserving origin, HTTP-count, history-count, and lifecycle assertions.
The injected storage-failure fixture accepts metadata keyword arguments so it
continues to raise its intended SQLite failure; no assertions were removed.

Additional clock/custom-TTL cases reproduced boundary issues before correction:

```text
3 failed, 22 deselected in 0.83s
```

Expanded cache/provenance selection:

```text
59 passed, 1 warning in 8.79s
```

Final complete offline suite after the older-matching-candidate regression:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
529 passed, 1 warning in 33.08s
```

Tests run with DATABASE_PATH=:memory: for default ASGI import isolation and the
ordinary pytest network guard enabled. No dependency was added. No existing test
was deleted, skipped, or weakened. The sole warning is the existing Starlette
HTTPX TestClient deprecation.

Thirty-three new cases in tests/test_verdict_cache_validity.py:

- test_memory_cache_invalidates_changed_inference_policy (4)
- test_primary_only_cannot_reuse_shared_cache_fallback
- test_returned_verdict_mutation_does_not_corrupt_cache
- test_memory_cache_exact_deadline_and_no_replay_refresh
- test_label_and_source_changes_do_not_invalidate_memory_cache
- test_memory_cache_refreshes_changed_model_visible_inputs (3)
- test_credentials_and_transport_timeout_do_not_change_cache_policy
- test_memory_cache_rejects_unsupported_provenance_version
- test_sqlite_validation_preserves_history_and_refreshes_invalid_candidates (13)
- test_invalid_cache_clock_withholds_request (2)
- test_persistent_expiry_honors_custom_ttl_and_does_not_refresh
- test_comparison_script_uses_shared_validation_without_adding_evaluation_rows
- test_disallowed_fallback_cache_cannot_mask_a_fresh_primary_failure
- test_historical_api_still_displays_unverified_legacy_verdict
- test_cache_stamp_failure_rolls_back_verdict_and_outcome

## Remaining boundaries

Legacy cache entries require fresh triage before verified reuse and may therefore
cause new requests on the first subsequent live run. Their historical records are
preserved. Cache validation does not implement unique-quality counting, new metric
scopes, reusable manifest/cohort validation, or dashboard selection. Result history
still includes replays. A cached valid verdict still does not prove present primary
service availability; WIRE-11 needs a successful cache-disabled primary diagnostic.
