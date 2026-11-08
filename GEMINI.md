# GEMINI.md â€” TriageLens
## Current verification update — 2026-11-08

Stage-3 metric scopes and validated cohort selection are implemented (ADR-050).
Default history keys/counting and memory fallback remain; run, quality, and attempts
require explicit validated selectors. Quality deduplicates identical verdict/context
snapshots within immutable case/evidence/context/policy manifests; conflicts fail.
Attempts count completed fresh logical acquisitions, with null availability when
none exist. New immutable cohort/run bindings preserve all prior snapshots; terminal
runs can be explicitly frozen as ad hoc cohorts. Missing provenance is never invented.
One SQLite read snapshot supplies metrics and coverage. Latest offline verification:
**578 passed, 1 warning**, including 49 new cases. See
`docs/results/metric_scopes_20261108.md`. Stage 4 and WIRE-11 remain unresolved.

Stage-2 verdict cache validity is enforced (ADR-049). Memory/SQLite use shared
evidence/policy/schema/provenance/model/expiry checks and detached snapshots.
Invalid/legacy entries refresh without overwriting history; labels alone do not
invalidate inference reuse. Valid hits are verified; history counting is unchanged.
The stage-2 verification reported **529 passed, 1 warning**, with 33 new cases.
See `docs/results/verdict_cache_validity_20261108.md`. Stage 3 adds explicit cohort
validation above; stage 4 and WIRE-11 remain unresolved. No live requests were made.

Replay provenance stage 1 is implemented (ADR-048): run/observation lifecycle,
atomic idempotent outcomes, actual cache/send origin hooks, opaque-provider unknown
origin, and legacy coverage. Replays still add history rows; same-observation write
retries do not. Those initial hooks did not verify cache validity; ADR-049 now does.
Ad hoc cohort namespaces do not implement verified quality scopes.
That task's offline suite reported **496 passed, 1 warning**, with 26 new cases.
See `docs/results/run_provenance_stage1_20261108.md`. WIRE-11 remains unresolved.

Replay provenance and metric-scope design is accepted in ADR-047.
History/run observations, unique verdict/context quality units, and completed
fresh attempts have separate counting rules. Legacy provenance remains unknown;
cache reuse needs evidence/model-policy/expiry validation. Staged implementation
continues in stage 4; history counting remains unchanged, with stage-3 API selectors
and additive selection metadata described above.
The earlier design-only task made no runtime changes.

Severity evaluation snapshots now persist and reconstruct through SQLite/API
(ADR-046). The label and True/False/unknown correctness survive round trips;
legacy schemas gain nullable columns without historical backfill. Known binary
correctness is not substituted for severity correctness. That task's offline suite
reports **470 passed, 1 warning**, with 19 new cases. See
`docs/results/severity_persistence_20261108.md`. Cached replay weighting remains
open; WIRE-11 and operator/live WIRE-6 completion remain unresolved.

Unavailable triage outcomes now persist with null verdict/prediction values in
CLI and evaluation runs (ADR-045). API availability reconstructs those outcomes;
skipped/inactive CLI triage is excluded. Supported legacy schemas migrate under a
savepoint with FK checks enabled; custom inbound references are refused. Historical
missing failures are not backfilled. That task's offline suite reported **451 passed,
1 warning**, with 19 new cases. See `docs/results/unavailable_outcomes_20261108.md`.
Cached replay weighting remains a separate open finding.
Latest operator evidence is smoke HTTP 200 followed by primary-only HTTP 429,
with no valid verdict; its exact quota window is not shown. WIRE-11 remains paused.

CLI/API/evaluation database paths now share project-root-based resolution (ADR-044).
Blank environment values fall through; explicit blanks and ambiguous Windows
partial paths fail. Parent creation is consistent and errors propagate. Existing
databases remain separate and untouched; overrides affect only their invocation.
That task's offline suite reported **432 passed, 1 warning**, with 27 new path cases,
including real CLI persistence and API reads across working directories. See
`docs/results/database_paths_20261108.md`. WIRE-6 still needs operator/live completion
after WIRE-11 is resolved; this does not populate the currently empty default DB.

Daily provider budgets now reserve every built-in HTTP attempt atomically (ADR-043),
including retries and timeouts, on the UTC dispatch day. SQLite shares limits across
connections; memory-only engines share a process-local ledger. Cache hits and local
rejections are free. Quota denials are not cached. Legacy providers reserve once
per dispatch until adopting the attempt hook; historical undercounts remain unknown.
That task's offline suite reported **405 passed, 1 warning**, with 29 new quota cases.
See `docs/results/provider_attempt_quotas_20261108.md`. WIRE-11 remains paused.

Compact intelligence summaries now enforce a shared <800-byte final prompt-fragment
budget (ADR-042), accounting for ASCII escaping, nested formatting, and masking
expansion. Omissions are marked; raw evidence is preserved. That task's offline
suite reports **376 passed, 1 warning**, including 36 new summary/validation cases.
Complete values are redacted before truncation to prevent unmasked secret prefixes.
See `docs/results/compact_summary_budget_20261108.md`. WIRE-11 remains paused.

Enrichment cache-expiry enforcement is fixed (ADR-041). SQLite is authoritative
when configured; memory-only entries use `cache_clock` (monotonic by default) with
24-hour successful / 15-minute negative TTLs. Expired results cannot bypass lookup
caps or quotas. Its verification reported **340 passed, 1 warning**, including
14 new cache regressions. See `docs/results/enrichment_cache_expiry_20261108.md`.

Recursive structured prompt isolation is fixed (ADR-040). The actual outbound
prompt is tested against nested metadata and list bypasses while preserving
source records, forensic strings, and independent provider detection counts.
The prompt-isolation verification reported **326 passed, 1 warning**. See
`docs/results/prompt_isolation_20261108.md` for the filtering boundary and evidence.
WIRE-11 remains paused; no live provider calls were made for this fix.

Pytest isolation is fixed (ADR-039): the end-to-end enrichment test injects provider
stubs into the real engine and verifies persistence with credentials present and
absent. `tests/conftest.py` blocks real HTTP/TCP attempts during tests. The normal
isolation verification reported **299 passed, 1 warning**; Gemini's live quota/service issue remains
unresolved. No live provider checks were run during the isolation fix.

Latest Gemini response confirms HTTP 429 `RESOURCE_EXHAUSTED`, a daily free-tier
limit of 20 requests, and a server-provided retry delay of 28163 seconds. The
blocker for that response was daily quota exhaustion; do not keep probing or change transport
settings to address it. WIRE-11 requires a successful primary-only verdict after
quota becomes available. Earlier timeout/503 observations do not establish their
own root cause and must not be rewritten as proven quota failures.

Follow-up request corrections are recorded in ADR-038. Gemini 3 triage now uses
provider-default sampling; the smoke probe has a meaningful token/latency budget.
Live follow-up returned HTTP 503 and 429. WIRE-11 remains unresolved; do not mask
the failure by renaming fallback output as primary success.

WIRE-11 is **REPRODUCED**, not fixed. Primary-only synthetic triage returned no
valid verdict at 15s or 30s; curl also timed out. Do not assume a Python-only,
IPv6, proxy, or certificate root cause. `scripts/diagnose_gemini.py` now verifies
actual primary triage separately from lightweight connectivity, without fallback
or cache. See `docs/results/wire11_diagnostics_20261108.md` and the current update
in `TASKS.md`; older completion/test-count claims below are historical.

## 1. Project Identity

**Project Name:** TriageLens

**Project Type:** AI-powered SOC alert triage and threat analysis platform.

**Project Tagline:** An alert triage pipeline that measures how often its AI is wrong.

TriageLens is a cybersecurity engineering project designed to automate parts of the security alert investigation and triage process while maintaining human oversight.

The objective is to build a practical, modular, industry-oriented platform demonstrating SOC automation, threat intelligence enrichment, event correlation, AI-assisted analysis, and measurable AI reliability.

This is not intended to be a simple AI chatbot or an alert summarization application.

Its distinguishing feature is the ability to evaluate AI-generated triage decisions against independently labelled ground truth and record where the AI makes mistakes.

---

## 2. Primary Objectives

The system should:

1. Ingest security alerts from structured files and public security datasets.
2. Enrich suspicious indicators using external threat intelligence services.
3. Correlate related security events into meaningful timelines.
4. Use a cloud-based LLM to assist with alert analysis.
5. Generate structured triage summaries, severity assessments, and recommended investigation steps.
6. Compare AI-generated assessments against known ground-truth labels.
7. Record AI errors and calculate meaningful performance metrics.
8. Present investigation information through an analyst dashboard.
9. Maintain human oversight over security decisions.

The AI must never be treated as the final authority on whether an incident is malicious.

---

## 3. System Architecture

TriageLens consists of six major stages.

### Stage 1: Alert Intake

* Ingest alerts from JSON and CSV files.
* Support publicly available security datasets.
* Normalize incoming records into a consistent internal schema.
* Validate incoming data.
* Preserve original source information and ground-truth labels separately.

### Stage 2: Threat Intelligence Enrichment

Enrich relevant indicators using external services:

* VirusTotal
* AbuseIPDB
* URLhaus

Requirements:

* Support IP addresses, file hashes, and domains.
* Handle API failures and rate limits.
* Implement caching to avoid unnecessary requests.
* Preserve enrichment source and retrieval timestamps.
* Handle missing or unavailable intelligence gracefully.

### Stage 3: Timeline Builder

Correlate related events into an understandable sequence.

Example:

* 10:02 â€” Unusual login detected.
* 10:05 â€” Suspicious process execution.
* 10:09 â€” Possible lateral movement.

Requirements:

* Correlate events using available identifiers and timestamps.
* Preserve event provenance.
* Avoid claiming relationships that cannot be supported by the available evidence.

### Stage 4: LLM-Assisted Triage

Use the Gemini API as the initial cloud-based AI provider.

Expected outputs:

* Alert summary.
* Suggested severity.
* Classification or assessment.
* Supporting evidence.
* Recommended investigation steps.
* Uncertainty and missing information.

Requirements:

* Use structured outputs.
* Validate AI responses.
* Mask sensitive information before external transmission.
* Handle API errors and rate limits.
* Cache suitable responses.
* Keep the AI provider replaceable through a defined interface.

The Gemini AI Pro subscription and Gemini API access are separate. Never assume that an application subscription provides API access.

### Stage 5: Accuracy and Validation Engine

This is the project's distinguishing component.

Compare AI-generated assessments against independently established ground-truth labels.

Track appropriate metrics, including:

* Accuracy.
* Precision.
* Recall.
* F1-score.
* False-positive rate.
* False-negative rate.
* Severity classification performance.

Requirements:

* Never use the AI's own answer as ground truth.
* Preserve original labels.
* Record incorrect predictions.
* Make evaluation results reproducible.
* Distinguish missing ground truth from an incorrect AI prediction.

### Stage 6: Analyst Dashboard

Provide an interface for analysts to review:

* Incoming alerts.
* Enriched indicators.
* Correlated timelines.
* AI-generated triage results.
* Ground-truth comparisons.
* AI performance metrics.
* Investigation recommendations.

The dashboard must communicate that AI recommendations require human review.

---

## 4. Technology Stack

Use the following technologies as the initial architectural direction.

| Technology | Purpose                           |
| ---------- | --------------------------------- |
| Python     | Core processing and orchestration |
| FastAPI    | Backend API                       |
| SQLite     | Lightweight database              |
| Gemini API | AI-assisted triage                |
| HTTPX      | External API communication        |
| Pydantic   | Data validation                   |
| pytest     | Automated testing                 |
| TypeScript | Frontend development              |
| SQL / KQL  | Security data querying            |
| YARA       | Later-stage file matching         |
| Git        | Version control                   |

Do not introduce additional technologies without a clear technical justification.

The frontend and optional advanced capabilities should be introduced when the backend foundation is stable.

---

## 5. Hardware Constraints

Development environment:

* Processor: Intel Core i5 10th Generation.
* RAM: 8 GB.
* Internal storage: 512 GB SSD.
* External storage: 256 GB SSD.
* Operating system: Windows.
* IDE: Visual Studio Code.
* AI coding environment: Antigravity.

Development must account for limited memory and processing resources.

Rules:

* Do not run locally hosted LLMs.
* Prefer cloud-based AI inference.
* Use SQLite instead of unnecessarily complex database infrastructure.
* Avoid resource-heavy services and unnecessary containers.
* Keep datasets and large log collections on the external SSD where practical.
* Keep source code and Git repositories on the internal SSD.
* Process datasets in manageable batches.

Docker is optional, not a mandatory dependency.

---

## 6. Development Principles

Follow these principles throughout development.

### Modular Architecture

Each major stage must have a clearly defined responsibility.

Avoid tightly coupled modules.

Use explicit input and output contracts between stages.

### Security First

* Never hardcode API keys or credentials.
* Store secrets in environment variables.
* Keep `.env` out of Git.
* Mask sensitive information before sending data to external AI services.
* Validate external API responses.
* Apply reasonable timeouts and error handling.
* Never expose secrets in application logs.

### Reliability

* Handle missing fields and malformed records.
* Implement appropriate exception handling.
* Avoid silently ignoring processing failures.
* Use structured logging.
* Preserve data provenance.

### Testing

* Write tests for important functions.
* Test normal, edge, and failure conditions.
* Mock external API calls during unit testing.
* Do not make real API requests in ordinary unit tests.
* Do not claim a feature is complete without verifying it.

### Code Quality

* Follow Python conventions and PEP 8.
* Use meaningful variable and function names.
* Add type hints where appropriate.
* Write useful docstrings.
* Avoid unnecessary abstraction.
* Prefer readable, maintainable code over clever shortcuts.

---

## 7. AI Agent Working Instructions

You are acting as a senior software engineering assistant and cybersecurity engineering mentor.

Follow these rules:

1. Read this file before beginning project work.
2. Read ARCHITECTURE.md to understand the system.
3. Read TASKS.md to identify the current development status.
4. Read DECISIONS.md before proposing changes that could conflict with earlier decisions.
5. Inspect the existing source code before modifying it.
6. Never assume that a feature or file exists without checking.
7. Never recreate an existing module unnecessarily.
8. Work on one clearly defined task at a time.
9. Explain the implementation plan before making significant changes.
10. Do not modify unrelated files.
11. Do not install unnecessary dependencies.
12. Do not silently change the architecture.
13. Ask for clarification when an important requirement is ambiguous.
14. Report all modified and newly created files.
15. Explain how to run and test the implementation.

Do not claim that commands, tests, installations, or API integrations succeeded unless they have actually been executed and verified.

---

## 8. Development Workflow

For every assigned task:

**Step 1 â€” Understand**

Read the relevant documentation and inspect the existing implementation.

**Step 2 â€” Plan**

Explain:

* What needs to be built.
* Why it is needed.
* Which files will be affected.
* What dependencies are required.
* How it will be tested.

**Step 3 â€” Implement**

Implement only the approved task.

**Step 4 â€” Verify**

Run appropriate tests and inspect the resulting changes.

**Step 5 â€” Document**

Update TASKS.md and DECISIONS.md whenever the task changes project progress or establishes a technical decision.

**Step 6 â€” Report**

Summarize:

* What was implemented.
* Files created or modified.
* Tests executed and their results.
* Known limitations.
* Recommended next task.

Never mark an incomplete or untested feature as completed.

---

## 9. Project Integrity

The following principles are non-negotiable:

* Human analysts retain decision-making authority.
* AI-generated conclusions must be distinguishable from verified evidence.
* Ground truth must remain independent of AI predictions.
* Security data must be handled responsibly.
* Every important processing stage must be testable.
* The system should be explainable and auditable.
* No feature should be added merely for visual appeal.

---

## 10. Current Project Status

The core TriageLens architecture is fully implemented, verified, and empirically benchmarked:

1. **Stage 1 (Alert Intake):** JSON and CSV ingestion with normalization and validation (`AlertIntakeEngine`).
2. **Stage 2 (Threat Intel):** Multi-provider enrichment (VirusTotal, AbuseIPDB, URLhaus) with TTL caching (`EnrichmentEngine`).
3. **Stage 3 (Timeline Builder):** Multi-key identity-driven event correlation (host + user, IP, domain), sliding time windows (30m), confirmed/potential classification, and event capping (`TimelineBuilder`).
4. **Stage 4 (LLM Triage):** Cloud-based Google Gemini DFIR triage with `<FORENSIC_EVIDENCE>` XML isolation against prompt injection, model catalog verification, automated failover (`gemini-3.8-flash` -> `gemini-3.5-flash-lite` -> `gemini-3.1-flash-lite`), in-memory response caching (`LLMResponseCache`), provider protocol (`TriageProvider`), uncertainty telemetry (`uncertainty_level`, `missing_information`), and regex PII/secret scrubbing with Luhn defense (`GeminiTriageEngine`).
5. **Stage 5 (Accuracy Engine):** Independent ground-truth evaluation (ADR-008), confusion matrix (TP, TN, FP, FN), precision, recall, specificity, F1-score, FPR, FNR, class balance validation, confidence calibration (Brier score, ECE, 5-bin calibration curve), and SHA-256 reproducibility digest (`AccuracyTracker`).
6. **Stage 6 (Storage & Backend):** Foreign-key enforced SQLite database with WAL mode, automated schema migrations, and REST API endpoints (`FastAPI`, `DatabaseManager`).
7. **Stage 7 (Analyst Dashboard):** Dark-mode TypeScript / React 19 / Vite / Tailwind CSS frontend with Operations Console and Threat Hunting UI.
8. **Stage 8 (Threat Hunting Engine):** Parameterized KQL-to-SQLite translation engine with deep JSON extraction (`ThreatHuntingEngine`).
9. **Real Evaluation Run:** 70-timeline balanced benchmark dataset (`data/eval_benchmark_70.json`) evaluated with 92.8% accuracy, 96.8% precision, 97.1% specificity, 2.9% FPR, and 11.8% FNR (`docs/results/evaluation_report_20261106.md`).
10. **2-Model Comparison & Calibration:** Empirical comparison of `gemini-3.5-flash-lite` (95.0% accuracy, Brier: 0.0390, ECE: 0.0020) vs `gemini-3.1-flash-lite` (100.0% accuracy, Brier: 0.0071, ECE: 0.0585) across 20 representative timelines (`docs/results/model_comparison_report.md`).
11. **Test Suite:** 263 unit, adversarial, security, and edge-case tests passing across all components with zero failures.

Current Priorities:
- Audit and align all task tracking in `TASKS.md` with verifiable deliverables.
- Maintain human-in-the-loop oversight and non-negotiable architectural principles (ADR-008).
- Prepare comprehensive documentation (`README.md`, setup instructions) for portfolio presentation.

---

**Final instruction:** Treat the repository documentation and existing code as the source of truth. Never rely on conversational memory alone.
