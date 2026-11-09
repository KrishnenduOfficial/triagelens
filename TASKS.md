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

The later `triage-v1` development check completed six live requests: TP=3/TN=1/FN=1
on five labelled cases, one unlabelled abstention, and severity agreement 3/5. All
four API scopes and static dashboard rendering matched saved metrics. Semantic
policy compliance remains incomplete; see
[new-policy evidence](docs/results/triage_v1_live_check_20261108.md).

Gemini WIRE-11 is **retired / superseded by provider replacement**. Its upstream
cause was not established or repaired. It is not an active blocker or a task to
resume. Prior benchmark reports and stored outcomes retain historical attribution.

## Current provider and verified status — 2026-11-08

Groq is the sole supported runtime AI provider (ADR-055). Use `GROQ_API_KEY`,
`GROQ_MODEL` (default `openai/gpt-oss-120b`) and optional `GROQ_FALLBACK_MODELS`
(blank by default). `.env` is private and must never be printed or committed.

The operator ran `python scripts/diagnose_groq.py --timeout 30 --trace` and
reported HTTP 200, the expected answering model, a schema-valid full triage,
1248.8ms, one request, no cache and no fallback. This verifies that request,
not benchmark accuracy or guaranteed future availability.

Subsequent agent-executed live verification: six preselected synthetic cases,
six valid verdicts, TP=3/TN=3/FP=0/FN=0, but severity agreement only 1/6. API persisted
metrics and real-component static rendering matched. See
`docs/results/groq_evaluation_report.md`. The offline rubric/preservation audit is
complete: `docs/results/severity_safety_audit_20261108.md`. It reproduced M23's
malicious/LOW scoring conflict and structural validation accepting unsafe or
unsupported advice. The operator subsequently approved and implemented ADR-056:
`triage-v1` separates disposition from severity, adds an evidence-qualified,
preservation-first policy and structural content checks, and preserves legacy
history with explicit prediction-basis metadata. The subsequent authorized
`triage-v1` live development check made six requests: six valid outcomes, TP=3,
TN=1/FN=1 on five labelled cases, one unlabelled abstention, and severity 3/5.
Saved metrics matched all four API scopes and static dashboard rendering. Review
still found unsupported TLS/success/legitimacy claims and incomplete containment
qualification. See `docs/results/triage_v1_live_check_20261108.md`. The earlier six
outcomes remain pre-policy evidence. No live calls were made by the offline audit
or implementation themselves.

Follow-up evidence/abstention audit is complete:
`docs/results/evidence_abstention_audit_20261108.md`. Six saved completions replay
with matching request-body hashes; 14 injected local probes made zero network
attempts, and 228 targeted regressions passed. Structural checks do not enforce
evidence sufficiency or prose support, and the audit found missing uncertainty/gap
presentation. ADR-057 is now implemented offline: active `triage-v2` /
`evidence-basis-v1`, structured basis/observation/hypothesis/gap checks, validated
references to immutable sanitized snapshots, and legacy-safe uncertainty display.
Labelled coverage is reported separately from abstentions and unknown truth.
Live v2 acceptance/semantic quality remains unmeasured. Normalization is a separate
follow-up. Preserve all previous
labels, metrics and policy identities; do not claim the semantic gaps are fixed.
This does not close interactive UI, full CLI or prompt-injection verification.

Gemini runtime code, settings and diagnostics are removed. WIRE-11 is retired
as superseded by the provider replacement, not repaired upstream. Historical
benchmark reports and stored records retain their true model attribution.
Do not ask the operator to resume Gemini diagnostics as a current project task.
See README.md, TASKS.md, DECISIONS.md and docs/results/groq_migration_20261108.md.

Current offline verification: 728 backend tests passed (one existing warning),
79 dashboard tests passed and production build succeeded; local Markdown links and
diff whitespace checks passed. Removed-provider tests were retired; the new policy
added 33 backend cases; ADR-057 adds 76 backend and 30 dashboard cases. References
establish traceability, not semantic proof. The earlier bounded live check used v1;
v2 live acceptance and untouched-case evaluation remain pending.

## Roadmap progress

- [x] T0.1 token hygiene: ADR index, concise agent rules, Markdown encoding check, and scratch ignore rule. The operator reported 728 backend tests passed (one warning); 79 dashboard tests passed.
- [x] T0.2 config leftovers: removed the generic URLhaus key alias, set the VirusTotal threshold to 3, retained wait mode off, and documented that the per-run lookup environment variable is currently unused.
- [ ] T0.3 terminology: describe the hunting feature as a KQL-style hunting filter across docs, API, engine documentation, and dashboard; confirm unchanged behavior with the targeted tests (pending: Python cannot launch in this environment).
- [x] T0.5 Groq pacing: per-engine rolling-minute request and estimated-token limits, bounded waits and 429 Retry-After handling; 748 offline backend tests passed (one existing warning). Daily quotas and cross-process coordination are not enforced; see ADR-058.
- [ ] T0.6 workflow check: README documents the CLI, database, API and dashboard sequence and same-run comparison; awaiting operator execution, screenshots and confirmation on a populated database.
  An authorized synthetic CLI run was interrupted after repeated Groq 429s; it
  produced no final CLI summary, so it cannot establish dashboard parity.

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
- [x] Verify new-policy Groq output on a bounded development sample under a new
  explicit inference-policy/cohort identity. Six valid responses include one
  unlabelled abstention, but review found a high-confidence false negative and
  unsupported assertions; this is not a semantic-safety sign-off.
- [x] Audit evidence-qualified conclusions and abstention consistency offline.
  Six saved completions replay with matching request fingerprints; structural
  probes reproduce missing sufficiency/claim checks. Abstention accounting and
  label isolation remain correct. The analyst view omits stored uncertainty/gaps;
  telemetry context projection also needs a separately scoped review. See the
  [audit and proposed contract](docs/results/evidence_abstention_audit_20261108.md)
  (228 targeted regressions passed; 14 local probes, zero network attempts).
- [x] Agree the versioned evidence-basis contract and uncertainty/gap presentation
  before runtime changes (ADR-057). Target `triage-v2` / `evidence-basis-v1` adds
  referenced observations, hypotheses and blocking gaps, with legacy-safe display.
- [x] Implement and verify ADR-057 offline: active `triage-v2` / `evidence-basis-v1`,
  deterministic references/basis checks, immutable sanitized snapshots, nullable
  legacy migration/cache validation, visible uncertainty/gaps/citations, and labelled
  coverage disclosure. Existing scoring identities and history counts are preserved.
- [ ] Perform a separately bounded `triage-v2` live acceptance and quality check;
  offline structural validation does not certify factual support or action safety.
- [ ] Evaluate untouched cases after addressing the development findings. Preserve
  labels, earlier scores and policy attribution; do not tune to hidden intent.
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

Latest offline verification: **728 backend tests passed**, with one existing
Starlette/HTTPX deprecation warning; **79 dashboard tests passed** and production
build succeeded. Local Markdown
link checks and `git diff --check` passed. Removed-provider tests explain the change
from the pre-retirement 688-case suite; ADR-056 added 33 backend cases and ADR-057
adds 76 backend / 30 dashboard cases. Those offline checks made no provider
requests; two separate live development evaluations made six authorized requests
each, using different policy identities and sample compositions.

Ordinary pytest stays offline, including with local credentials configured. Use
injected transports and temporary databases. Never weaken security tests or claim
model quality from schema validation alone. Keep .env and generated databases out
of Git. Historical audit documents in docs/results are snapshots, not current tasks.
