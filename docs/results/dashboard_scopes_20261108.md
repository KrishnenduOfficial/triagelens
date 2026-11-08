> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Dashboard scope presentation - 2026-11-08

Status: **FIXED+VERIFIED offline** for the approved dashboard portion of ADR-047
stage 4 (ADR-051). Interactive browser/viewport verification remains open because
the browser access host was unavailable. No live provider requests or operator
database access/migrations were performed; no commit/push was made.

## Behavior and compatibility

History remains the initial selection, using the original bare `/api/metrics`
request. Its backend values, replay counting, legacy records, and API memory
fallback are unchanged. Run requires a UUID; Quality a registered cohort digest;
Fresh attempts accepts exactly one of those selectors. Draft edits apply only on
submission. The applied selection and identifiers remain visible. Refresh retries
that selection without choosing a latest run or substituting History.

The service validates core numeric results, selection source/unit/IDs, coverage,
denominators, and fresh-attempt availability. Explicit scopes require matching
server metadata. Older metadata-free History responses remain supported with
unknown source/provenance and N/A for absent extras. No new backend route or
frontend dependency was needed; no inference/provider call is triggered by a
dashboard refresh.

Cards present classification, severity, calibration, sample bases, Wilson intervals,
source, and lifecycle/evidence/manifest coverage. Unknown labels, unavailable
outcomes, skipped, pending, interrupted, legacy, and unverifiable records are distinct.
Undefined sample denominators show N/A while genuine zero rates remain 0.0%.
Quality availability is Not applicable; replay-only fresh attempts explain N/A.
Result availability never claims provider/primary-model uptime. Static online/active
provider badges are removed. Unique/repeated evidence and sampling assumptions
remain visible; no independent-sample claim is inferred from deduplication.

The generation-guarded request coordinator aborts its predecessor and ignores
outdated success/failure even if a transport ignores cancellation. Cleanup prevents
post-unmount updates. Applied query identity also hides old values before the next
effect executes; loading/error views never render previous results under new labels.
Errors 404/409/422 stay attached to the selected request without fallback retries.

## Failing-first evidence

New Node regressions were written before implementation and run offline:

```text
node --import ./tests/register.mjs --test ./tests/metrics.test.mjs
Error [ERR_MODULE_NOT_FOUND]: ... dashboard/src/metrics/presentation.ts
tests 1
pass 0
fail 1
```

The first implemented pass reported 22 passed, 1 failed. The failing new legacy
assertion searched the entire page for `100.0%`, inadvertently rejecting valid
precision and Wilson bounds. It now specifically asserts availability N/A and
rejects availability 100%; no production value or existing test was changed to
force a pass. Expanded coverage includes API contract errors, actual rendered
loading/error states, stale failures, and cleanup ordering.

## Final verification

Using installed local dependencies (Node 26.13.0; test loader requires Node 22.15+):

```text
cd dashboard
npm test
tests 48
pass 48
fail 0
cancelled 0
skipped 0
```

48 cases cover initial History selection, all five selector combinations,
ambiguous/malformed selectors and payloads, immutable applied scope identity,
old History and memory fallback labels, null/zero/undefined values, unknown versus
skipped/unavailable counts, severity/calibration/interval bases, manifest/evidence
coverage, API error propagation, canceled/stale success/failure, effect cleanup,
failed-run coverage, and removal of unsupported live-provider claims. Named cases
include `latest request wins even when an older request ignores cancellation`,
`all five wire selector combinations pass the API response contract`, and
`loading/error screen never renders prior results under a new scope`.

Tests import the actual modules with the installed Rolldown compiler and render
the actual components through React DOM server rendering. Axios adapters and
deferred promises are injected only in tests; HTTP/HTTPS/TCP/fetch are blocked.
No test framework/package installation, generated fixture file, or source rewrite
is part of this test harness.

```text
npm run build
tsc -b && vite build
89 modules transformed.
dist/assets/index-DBTbXwv8.css   22.45 kB
dist/assets/index-CA-Rdy0L.js   353.62 kB
built in 245ms

npm run lint
exit 0
src/components/TimelineFeed.tsx:30:5: warning react(set-state-in-effect)
```

The remaining lint warning predates this task; the previous MetricsOverview effect
warning is no longer reported. No existing warning suppression was added.

Full Python suite with DATABASE_PATH=:memory:, `-B`, no pytest cache, and the
ordinary HTTP/TCP guard active:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
578 passed, 1 warning in 24.94s
```

The warning is the existing Starlette/HTTPX TestClient deprecation. Backend sources
and prior tests remain unchanged.

An additional transient in-memory SQLite/ASGI cross-check passed actual API payloads
through the dashboard validator and real component renderer:

```text
history: real API payload validated and rendered; availability=0.6666666666666666
run / run: real API payload validated and rendered; availability=1
quality / cohort: real API payload validated and rendered; availability=null
attempts / run: real API payload validated and rendered; availability=null
attempts / cohort: real API payload validated and rendered; availability=0.5
```

This used a fresh success, a fresh unavailable outcome, and a verified replay.
It made no HTTP provider calls and created no persisted diagnostic artifacts.

## Remaining work

The computer-use inventory returned `The browser access host is unavailable` and
an unavailable native pipe. No browser interaction, screenshot, or viewport result
is claimed. The temporary loopback-only fixture server was stopped (task-owned PID
20888). Interactive visual verification remains on TASKS.md; CSS includes narrow
viewport wrapping and visible keyboard focus, but those layouts were not observed
in a browser here.

The separate stage-4 CLI/generated-report scope wording still needs an offline
audit before any default report changes. WIRE-11 remains paused and unresolved;
operator/live WIRE-6 completion still needs successful authorized live verification.
No cohort discovery/write API, automatic cohort registration, live provider probe,
operator database migration, or changed benchmark claim was introduced.
