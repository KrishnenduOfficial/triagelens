# TriageLens Tasks

## Current status ? 2026-11-08

Groq is the sole runtime AI provider (ADR-055), default `openai/gpt-oss-120b`.
The operator verified one full synthetic triage: HTTP 200, schema-valid output,
1248.8ms, one request, no cache and no fallback. This does not establish benchmark
accuracy or sustained availability. See [verification](docs/results/groq_migration_20261108.md).

A subsequent authorized agent-run six-case sample produced six schema-valid
verdicts, TP=3/TN=3/FP=0/FN=0, and exact severity agreement 1/6. Saved API metrics and
static dashboard rendering matched. This selected synthetic sample is not a
general performance claim. See [evaluation](docs/results/groq_evaluation_report.md).

Gemini WIRE-11 is **retired / superseded by provider replacement**. Its upstream
cause was not established or repaired. It is not an active blocker or a task to
resume. Prior benchmark reports and stored outcomes retain historical attribution.

## Implemented

- [x] JSON/CSV alert intake, normalization, indicator extraction and source preservation.
- [x] VirusTotal, AbuseIPDB and URLhaus enrichment with explicit unavailable states.
- [x] Enrichment cache expiry, per-attempt provider quota accounting and rate limits.
- [x] Correlated security timelines with bounded events and compact intelligence summaries.
- [x] Recursive ground-truth/provenance filtering and PII/credential masking before egress.
- [x] Groq chat completions, strict assessment schema, local validation and actual model attribution.
- [x] Single-attempt Groq synthetic diagnostics, metadata-only trace and safe dry run.
- [x] Groq smoke checks; fallback remains explicitly opt-in and provider-local.
- [x] Live primary-model integration accepted for the operator's successful request.
- [x] Remove retired provider engine, credential settings, diagnostics and exclusive tests.
- [x] Keep shared privacy/cache/provenance regressions using a test-only neutral transport.
- [x] Shared CLI/API database path resolution and SQLite legacy-compatible migrations.
- [x] Severity/availability persistence, run-observation lifecycle and idempotent outcomes.
- [x] Provenance-aware memory/SQLite verdict cache policy and expiry checks.
- [x] History, run, quality and attempts metric scopes with validated cohorts.
- [x] Dashboard scope selection, unavailable values, coverage and stale-request protection.
- [x] Replace provider-specific project rules with AGENTS.md and correct current Markdown claims.
- [x] Remove unused dashboard starter assets and the empty rule file; remove 14
  obsolete dependency pins and protect environment variants, SQLite sidecars and
  TypeScript build metadata from accidental commits.
- [x] Correct remaining README drift: prerequisites, dependency/test versions,
  dashboard routes, metric-scope checks, input folder examples, enrichment network
  behavior and actual directory paths. Verified 13 documentation/config/API parity
  tests and all listed repository paths; application behavior unchanged.

## Next work

- [x] Run a small sanitized Groq evaluation using independent labels. Inspect severity,
  false negatives, unsupported reasoning, missing-information handling and calibration.
- [x] Audit severity criteria, evidence-qualified assertions and preservation-first
  recommendations offline before changing prompts or running a larger benchmark.
- [x] Agree and implement independent disposition, response-priority severity,
  binary-confidence meaning and legacy compatibility (ADR-056). `triage-v1` adds
  a versioned rubric, preservation-first/evidence-qualified analyst recommendations,
  nonblank content checks, abstention accounting, additive persistence, exact
  prompt/cache identity and evaluator-aware cohorts. See the
  [audit and implementation verification](docs/results/severity_safety_audit_20261108.md).
- [ ] Verify new-policy Groq output on a bounded development sample, then evaluate
  untouched cases under a new explicit inference-policy/cohort identity. Existing
  six-case scores predate this policy; do not relabel them or alter reference labels.
- [ ] Measure Groq prompt-injection resistance and availability; report sample size and scope.
- [ ] Verify the normal CLI -> shared SQLite -> API -> dashboard workflow manually.
  Preserve default History behavior and select explicit run/cohort IDs for provider comparisons.
- [ ] Complete interactive dashboard visual QA; previous browser access was unavailable.
- [ ] Audit operator-report metric-scope wording; do not infer real-time provider status from history.

Repository publication requires an explicit operator request; actual commits and
remote publication are recorded in Git history.

## Deferred

Authentication/roles, deployment/containerization, advanced hunting/YARA/MITRE
features and larger real-world datasets remain separate work. Do not implement
these without a scoped request. Human analysts retain final response authority.

## Verification rules

Latest offline verification: **652 backend tests passed**, with one existing
Starlette/HTTPX deprecation warning; **49 dashboard tests passed** and production
build succeeded. Local Markdown
link checks and `git diff --check` passed. Removed-provider tests explain the change
from the pre-retirement 688-case suite; ADR-056 adds 33 backend cases. Those offline checks made no provider
requests; the separate live evaluation above made six authorized requests.

Ordinary pytest stays offline, including with local credentials configured. Use
injected transports and temporary databases. Never weaken security tests or claim
model quality from schema validation alone. Keep .env and generated databases out
of Git. Historical audit documents in docs/results are snapshots, not current tasks.
