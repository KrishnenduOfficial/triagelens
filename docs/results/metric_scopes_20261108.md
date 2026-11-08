# Metric scopes and validated cohorts - 2026-11-08

Status: **FIXED+VERIFIED** for ADR-047 stage 3 (ADR-050), with explicit approval.
History counting and all previous outcome snapshots remain intact. No live calls,
operator database migrations, commits, or pushes were performed for this task.

## Reproduction and implementation

The audit showed that run, quality, attempts, malformed, and unknown selectors
returned HTTP 200 with identical global history. Run manifests contained only a
run ID. Conflicting case contexts and canonical confidence values could coexist.
The 82 existing relevant tests passed without testing stage-3 selectors.

Failing-first command (DATABASE_PATH=:memory:):

```text
python -B -m pytest tests/test_metric_scopes.py -q -p no:cacheprovider --tb=short
E   ModuleNotFoundError: No module named 'src.engine.metric_scopes'
1 warning, 1 error in 0.92s
```

The new shared selector and immutable cohort tables implement explicit scopes.
The API validates unknown/repeated query parameters as well as combinations and
identifiers. Missing selectors are 422; unknown run/cohort is 404; conflicting
members/canonical outcomes are 409. No latest-run selection or explicit-scope
fallback exists. One SQLite savepoint read snapshot supplies rows, history
reconstruction, observations, runs, manifests, and bindings across WAL writers.

| Scope | Unit | Availability |
| --- | --- | --- |
| history | All evaluation rows including legacy/replay | Prior result-availability formula and empty convention |
| run + run_id | One run's evaluation occurrences | Same formula, scoped to that run |
| quality + cohort_id | One identical verdict/context snapshot in the manifest | null; no service-availability claim |
| attempts + run_id XOR cohort_id | Completed fresh logical attempts with persisted identity | Valid fresh results / completed fresh attempts; null when none |

Fresh unavailable results are separate attempts, never deduplicated on NULL
verdict IDs. Unknown binary results can contribute severity and availability
without binary/calibration samples. Fresh outcomes after a rejected cache candidate
remain eligible; fresh without a prior candidate is legitimately unverified for
cache-hit purposes. Only cache-origin quality samples require verified replay.
Past quality is unchanged by TTL expiry or mutable source-label changes.

All quality calculations (including severity, calibration, and confidence
intervals) consume the same canonical selection. Conflicting snapshots fail;
no arbitrary first/latest snapshot wins. Coverage reports legacy, unverifiable,
replay/fresh/unknown origin, skipped/pending/interrupted work, failed run status,
deduplication, missing outcomes/cases, and unique/repeated evidence. Repeated
evidence does not become independent sampling evidence through deduplication.

## Manifest schema and workflow

`metric_cohorts` stores canonical JSON addressed by SHA-256. Registration is
idempotent under member ordering; unknown/unsupported fields/versions, malformed
hashes, and duplicate case assignments are rejected. `metric_run_cohorts` immutably
binds a run to a declaration; both tables have FK and UPDATE/DELETE guards.
Original `evaluation_runs.quality_cohort_hash` remains the original namespace;
evaluation snapshots, context hashes, IDs, and observation outcome hashes are not
retagged. Only the new binding selects a registered cohort.

Required manifest fields:

```text
version: 1
kind: declared | ad_hoc
revision: nonblank immutable dataset/manifest revision
evaluator_version: AccuracyTracker-v1
label_policy_version: evaluation-context-v1
inference_policy_hash: 64 lowercase hex characters
members: nonempty list of {
    case_id: persisted timeline UUID,
    evidence_hash: 64 lowercase hex characters,
    evaluation_context_hash: 64 lowercase hex characters
}
source_run_id: terminal source UUID (required only for ad_hoc)
```

Members can have distinct evaluation contexts for benign/malicious/severity
labels. A case cannot carry competing assignments within one manifest. The
manifest records the policy and case-specific contexts; filtering a whole dataset
by one row's context hash is never used. The evaluator policy configuration and
resolved labels are already included in each persisted context digest.

Python workflow using an initialized DatabaseManager:

```python
from src.engine.metric_scopes import scoped_metrics
from src.engine.provenance import evaluation_run

# Explicitly freeze a terminal run with complete verifiable outcome provenance.
cohort_id = db.declare_run_cohort(run_id)
quality = scoped_metrics(db, scope="quality", cohort_id=cohort_id)
attempts = scoped_metrics(db, scope="attempts", run_id=run_id)

# Or register a complete declared manifest before evaluation.
cohort_id = db.register_metric_cohort(manifest)
with evaluation_run(db, "evaluation", cohort_id=cohort_id) as run:
    # Existing observe -> acquire -> evaluate -> complete lifecycle.
    ...
```

The ad hoc helper freezes known completed cases only; it does not invent missing
dataset membership. It refuses empty, running, mixed-policy, conflicting-context,
or unverifiable outcome sets. Failed terminal runs can freeze known completed
outcomes while retaining interrupted-work coverage. Ad hoc registration verifies
its claimed members against its terminal source run. A declared manifest can
include unevaluated cases, reported as missing. Subset replay binds the original
cohort before observations; the initial complete declaration remains unchanged.
These operations require no network and are not exposed as public write routes.
Incompatible bound outcomes remain in history; the cohort selection fails closed.

## Verification

The first full regression run found one compatibility failure:

```text
1 failed, 548 passed, 1 warning in 21.06s
test_context_closes_database_even_when_run_creation_fails
TypeError: ... fail() got an unexpected keyword argument 'cohort_id'
```

The recorder now preserves its original one-argument run-creation call unless a
cohort is explicitly supplied. The existing test was unchanged. A new HTTP
comparison initially compared JSON interval arrays with Python tuples; its expected
payload now uses the same standard JSON encoder. No assertions were removed.

Final full offline suite, with DATABASE_PATH=:memory: to isolate the global ASGI
import and the ordinary HTTP/TCP network guard active:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
578 passed, 1 warning in 27.33s
```

49 new cases in `tests/test_metric_scopes.py`, including:

- `test_history_run_quality_and_attempts_have_distinct_units`
- `test_replay_only_attempts_are_null_not_available`
- `test_manifest_includes_mixed_contexts_and_subset_replay`
- `test_api_rejects_invalid_selectors` (8 combinations)
- `test_quality_rejects_conflicting_canonical_snapshots` (confidence/severity)
- `test_declared_cohort_rejects_incompatible_subset_outcomes` (4 changes)
- `test_one_canonical_selection_drives_all_quality_statistics`
- `test_snapshot_survives_a_concurrent_file_database_writer`
- `test_real_engine_replay_quality_survives_cache_expiry_and_label_mutation`
- migration/binding immutability, ad hoc membership, no-verdict attempts, unknown
  labels, failed/pending/interrupted work, registration ordering, strict API
  errors, and explicit-scope no-fallback checks.

No dependencies were added. Existing tests were not deleted, skipped, or weakened.
The warning is the existing Starlette/HTTPX TestClient deprecation.

## Limits and next step

Stage 4 still needs an offline audit of dashboard scope presentation and client
compatibility before changing displays. Existing runner output and dashboard
default remain as before; Python/API scoped access is explicit. Case IDs remain
persisted timeline UUIDs; cross-timeline identity is not inferred. No live provider
success, benchmark improvement, independent-sample claim, or operator database
migration is established here. WIRE-11 remains paused and unresolved; operator/live
WIRE-6 completion still depends on successful live verification.
