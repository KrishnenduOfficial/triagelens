# Groq replacement and live integration verification ? 2026-11-08

## Current outcome (ADR-054 and ADR-055)

Follow-up: an authorized agent-executed [six-case evaluation](groq_evaluation_report.md)
returned six valid verdicts and six correct binary labels, but only one exact
severity match. Persistence, API scopes and static dashboard rendering were checked.
That report records recommendation risks and small-sample limits. The original
single-request migration evidence below remains historical.

Groq is the sole supported runtime AI provider. The user explicitly requested
removing the retired provider code and obsolete diagnostics, updating all relevant
Markdown, and leaving the work ready for a later Git commit/push.

The operator supplied this live result from:

```powershell
python scripts/diagnose_groq.py --timeout 30 --trace
```

```json
{"mode":"primary_only_triage","provider":"groq","requested_model":"openai/gpt-oss-120b","answering_model":"openai/gpt-oss-120b","success":true,"schema_valid":true,"failure_category":null,"http_status":200,"elapsed_ms":1248.8,"timeout_seconds":30.0,"cache_enabled":false,"fallback_count":0,"request_count":1}
```

Connection, TLS, upload, response headers and body phases completed. Response-header
wait was 918.9ms; response-body duration was 0.8ms. This is one operator-observed
full synthetic triage success, not an agent-run live test, an accuracy evaluation
or a guarantee of future availability. No key or response content is included.

## What the active model does

`openai/gpt-oss-120b` receives sanitized chronological security evidence through
Groq chat completions. Its assessment contains severity, confidence, summary,
reasoning, recommended actions, uncertainty and missing information. The application
supplies IDs/provenance, validates exact JSON and field types/ranges, verifies the
answering model, and rejects refusal, truncation, tool calls and invalid responses.

Privacy filtering, compact intelligence budgets, prompt boundaries, cache expiry,
run lifecycle, idempotent persistence and metric counting remain in the application.
These controls do not prove analytical correctness or immunity to prompt injection.
No containment action or tool execution is performed by the model.

## Configuration and operation

- `GROQ_API_KEY`: required for active inference.
- `GROQ_MODEL`: defaults to `openai/gpt-oss-120b`.
- `GROQ_FALLBACK_MODELS`: optional comma-separated strict-schema-compatible models;
  default empty. Explicit fallback can consume additional quota.
- Existing threat-intelligence, database and dashboard settings remain supported.
- No new dependency, arbitrary provider URL, automatic retry loop or implicit
  cross-provider fallback was introduced. HTTPS verification remains enabled.

```powershell
python scripts/diagnose_groq.py --dry-run
python scripts/check_connections.py --dry-run
```

Both actual local dry runs passed during the migration with zero requests and no
secret output. A dry run checks configuration, not service authentication.

## Removal and preservation

Removed: the old engine class/export/config getters, legacy smoke function,
`scripts/diagnose_gemini.py`, `scripts/gemini_comparison.py`, four exclusive
`test_gemini_*.py` files and three detailed `wire11_*.md` troubleshooting reports.
Shared transport tracing tests were ported to `test_diagnostic_transport.py`.
Shared pipeline tests retain their assertions using `PipelineTestEngine`, an
explicitly synthetic neutral test transport defined only under tests/.

`GEMINI.md` was replaced by `AGENTS.md`, preserving project objectives, integrity
rules and agent workflow. README, ARCHITECTURE, TASKS, DECISIONS, dashboard README
and the environment template now identify the current provider and measured limits.
Older result reports are labelled historical snapshots, with no altered scores.

Stored old verdicts and benchmarks are retained with original attribution. Memory
and SQLite regression tests verify that retired provider-policy results remain
stored but cannot satisfy a current Groq cache contract. No DB migration, deletion,
backfill or metric-counting change was performed by this retirement task.

## WIRE-11 disposition

WIRE-11 is retired as **superseded by provider replacement**, not fixed upstream.
Prior observations: generation timeouts on HTTPX/curl; full-request failure on
Wi-Fi and hotspot; simple generation failures on configured/latest-alias endpoints;
HTTP 200 for model listing and token counting; one earlier valid triage success.
Those observations did not establish the provider/intermediary root cause. They
are retained here and in decision history; no further Gemini probe is a project task.

## Verification and limits

Final cleanup verification:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
619 passed, 1 warning in 21.50s

dashboard: npm test
48 passed, 0 failed

Local Markdown link check: no broken links
git diff --check: clean
Runtime src/scripts/.env.example scan: no retired provider references
```

Tests ported into `test_diagnostic_transport.py` preserve phase attribution,
raw-trace noninspection, bounded events, real HTTPcore behavior, header/body timeout
distinction, filter restoration/thread isolation and client closure. Smoke timeout
override and invalid diagnostic timeout coverage are retained under current names.

The pre-retirement migration suite passed 688 tests. Removing tests exclusive to
removed features changes the total; the current final count is recorded in TASKS.md.
The applicable privacy, cache, provenance, strict Groq validation, HTTPcore phase,
log-filter restoration, thread isolation, client closure and timeout tests remain.
All tests run offline under the unchanged network guard. The existing Starlette/
HTTPX deprecation warning remains. No agent live requests or production DB writes.

Pre-publication directory cleanup removed five unused dashboard assets/styles and
an empty rule file. Fourteen unused dependency pins, including the old Google SDK,
were removed after checking imports and installed dependency metadata. The existing
environment was not uninstalled or rebuilt. Ignore rules now cover environment
variants, SQLite sidecars and TypeScript build metadata; `.env.example` stays tracked.
The dashboard's 48 tests and production build pass after asset removal.

The worktree already included dashboard changes, which remain intact. Repository
publication is authorized separately and recorded in Git history. Next: independently
evaluate Groq's accuracy/calibration on sanitized cases and verify the real workflow.

API/schema reference: [Groq API](https://console.groq.com/docs/api-reference),
[strict output](https://console.groq.com/docs/structured-outputs). Provider limits
and supported model IDs can change; this report makes no free-tier SLA claim.
