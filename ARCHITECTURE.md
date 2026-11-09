# ARCHITECTURE.md — TriageLens

**Project:** TriageLens
**Version:** 0.1.0
**Status:** Architecture Definition
**Architecture Style:** Modular, lightweight, pipeline-based
**Primary Language:** Python

---

# 1. System Overview

TriageLens is an AI-assisted SOC alert triage and threat analysis platform.

The system follows a pipeline architecture in which security alerts pass through multiple independent processing stages.

Each stage enriches, transforms, evaluates, or presents information before passing it to the next stage.

The six primary stages are:

1. Alert Intake
2. Threat Intelligence Enrichment
3. Timeline Builder
4. LLM-Assisted Triage
5. Accuracy Tracker
6. Analyst Dashboard

The architecture is designed to run on modest hardware without requiring a locally hosted AI model or a full SIEM deployment.

## Sole LLM Provider: Groq (ADR-054, ADR-055)

Groq replaces Gemini in CLI triage, evaluation, two-model comparison, startup
configuration reporting, and connection checks. `src/engine/groq.py` implements
the Groq chat-completions wire contract using the existing HTTPX dependency.
Default model: `openai/gpt-oss-120b`. Only `GROQ_API_KEY` authenticates active triage;
Groq is the sole supported runtime provider. Model fallback is explicitly opt-in.

`TriageEngineBase` in `llm.py` owns evidence isolation, recursive scrubbing, compact
summary budgeting, prompt construction, cache/provenance lifecycle and verdict
construction. Concrete transports own generation settings, credentials, endpoint,
response extraction and additional validation. The retired provider transport,
credentials, exports and diagnostic tools have been removed (ADR-055).

Groq sends nine model-authored assessment fields under strict JSON schema (ADR-057).
Application-generated IDs and answering-model provenance cannot be authored by the
model. A non-stop finish reason, refusal, tool call, mismatched model or invalid
assessment is unavailable. Configured fallback is attempted only at the existing
transport/HTTP 429/503/404 boundaries; there is no implicit retry loop.
Cache policy hashes include provider identity, model chain, schema, prompt and
generation settings, preventing Gemini/Groq cache reuse. Historical records and
history metric counting are preserved. Provider replacement itself required no
backfill; the later ADR-056 migration adds nullable disposition/policy snapshots.

## Versioned Assessment Contract (ADR-056, ADR-057)

`src/engine/triage_policy.py` defines application-owned `triage-v2`. Disposition
is MALICIOUS/BENIGN/UNDETERMINED, independently of severity as response priority.
Groq locally requires a nonblank summary, at least one nonblank reason/action,
nonblank gap entries, and HIGH uncertainty with a blocking gap for UNDETERMINED. Empty gaps
remain permitted for other dispositions. Policy identity is attached by the engine,
never authored by the model. Confidence means correctness of the selected binary
disposition; abstention confidence is excluded from calibration.

The policy instructs evidence-qualified claims and preservation before destructive
cleanup, authorized analyst review, scoped actions, and justified emergency
containment when ongoing harm makes full acquisition impractical. This is model
guidance plus structural checks, not semantic certification or automatic response.
The dashboard repeats the review/preservation warning beside recommendations.

`src/models/evidence.py` defines strict `evidence-basis-v1` support, observation,
hypothesis, gap and reference objects. Request-local E/I IDs are assigned after
isolation, scrubbing and summary budgeting. References resolve only to existing
non-null scalar fields in those records; declared basis/disposition, blocking gaps,
decision/observation references and the duplicated missing-information descriptions
must agree. Invalid relationships become unavailable, without automatic repair.
The normalized assessment is stored while its raw response remains unchanged.
Existing scalar references do not establish semantic correctness.

Verdicts store nullable `evidence_basis`, application-owned `evidence_context`
and `evidence_contract_version`. The captured sanitized map is immutable evidence
for citation display, independent of later source-timeline changes. Cache returns
revalidate relationships and require matching current context, policy and contract.
Old rows keep nulls and old terminal hashes; no backfill or rescoring occurs.
API-only `missing_information_recorded` is derived before SQL NULL is normalized;
it never enters verdict hashes or inference. The actual timeline view shows gaps,
uncertainty, basis and saved-value citations, with legacy and malformed states.

One captured system prompt is used for both the actual request and cache contract;
policy version is also hashed. Changed policies invalidate reuse while retaining
history. New verdicts/evaluations persist nullable disposition and policy version;
evaluations additionally snapshot prediction basis. Legacy null fields remain
unrecorded without backfill; original evaluation categories/calibration persist.
Legacy verdicts evaluated again retain their original severity-derived prediction.

UNDETERMINED is an available response in `unknown`, with a separate `abstained`
count; it is excluded from binary/calibration denominators but can have a scored
severity. Metrics disclose explicit, legacy-proxy and unrecorded basis counts.
New evaluation contexts/cohorts identify `AccuracyTracker-disposition-v1`; existing
`AccuracyTracker-v1` manifests and terminal hashes remain valid. A cohort cannot
mix the two binary evaluator rules. Run/History counting units are unchanged.
V2 keeps `AccuracyTracker-disposition-v1`, since binary scoring is unchanged.
Additive metrics disclose labelled available outcomes, binary predictions, labelled
abstentions, unknown-truth available responses and labelled binary coverage. Unknown
truth and unavailable results do not enter that coverage denominator. No available
labelled outcomes yields null coverage. These diagnostics do not change accuracy,
availability or calibration formulas. Live v2 acceptance/quality remains unmeasured.

`scripts/diagnose_groq.py` checks one synthetic full triage, bypassing cache and
fallback. Its dry run makes no request; optional traces use shared allow-listed
metadata-only helpers in `scripts/diagnostic_transport.py`. Logging and TLS guards
are retained. Live availability and Groq analytical quality require operator
verification; offline integration success does not establish either.

## Shared Database Target (ADR-044)

CLI, API, and `scripts/run_evaluation.py` use `config.get_database_path(override)`.
Selection is an explicit override, then the first nonblank canonical/alias setting,
then `data/triagelens.db`. Relative paths resolve against the root containing `src/`,
derived from `src/config.py`, independently of cwd. The resolver returns an absolute
disk path and creates its parent; failures propagate before SQLite is opened.
Explicit blanks and partially qualified Windows paths are rejected. `:memory:`
remains an intentional connection-local exception. Injected DatabaseManager
instances and low-level DatabaseManager paths retain their caller-owned behavior.

An override changes only its invocation; the API must independently select the
same file. Existing databases are never discovered, merged, moved, or preferred
based on row counts. The legacy root database remains separate from the default.
API state selects its database at startup, so configuration changes require a
restart. Path consistency is verified offline with real CLI persistence and API
reads; Groq primary-only live verification succeeded once; normal operator workflow verification remains pending.

## Metric Scopes and Cohort Selection (ADR-050)

Metric scope selection (ADR-050) lives in `src/engine/metric_scopes.py`, shared by
Python callers and `GET /api/metrics`. History remains evaluation-row based; run
selects occurrences; quality selects canonical verdict/context pairs within an
explicit immutable case/evidence/context/policy manifest; attempts select completed
fresh logical acquisitions. All statistics and coverage derive from one SQLite
read snapshot. Invalid selector combinations fail, and explicit scopes never use
unrelated global or in-memory metrics.

`metric_cohorts` stores canonical versioned manifests addressed by SHA-256.
`metric_run_cohorts` immutably binds runs to declarations, with foreign keys and
UPDATE/DELETE guards. Binding a declared/subset run happens before observations.
An explicit terminal-run freeze can create an ad hoc declaration from persisted,
verifiable completed outcomes. These side tables do not rewrite evaluation
snapshots, original run namespaces, or unknown historical provenance. A declared
manifest may include unevaluated cases, disclosed as missing coverage. Ad hoc
manifests cover known completed cases only, with interrupted/skipped work disclosed.

One canonical quality selection feeds confusion, severity, calibration, and Wilson
intervals; conflicting snapshots or manifest member assignments fail selection.
Past quality does not expire with a verdict cache TTL. Quality availability is
null; attempts availability is null without completed fresh attempts. Default
history/run empty conventions remain compatible. Coverage distinguishes replay,
fresh, unknown, skipped, pending, interrupted, legacy, and repeated evidence.
Truth/cohort metadata never enters model prompts or inference/cache fingerprints.
Stage-4 dashboard presentation (ADR-051) consumes this contract without changing
the server's selectors, formulas, stored records, or History default. Browser
preview verification and operator-report presentation remain separate follow-ups.

`dashboard/src/metrics/presentation.ts` owns typed selector validation, response
selection checks, and undefined-value formatting. `request.ts` coordinates request
generation and AbortController cleanup, withholding superseded success/failure
callbacks even when a transport ignores cancellation. `MetricsOverview` separates
draft controls from applied selection, and renders only results belonging to that
applied request identity. `MetricResults` presents the server-selected units,
denominators, source, severity/calibration/intervals, and lifecycle/evidence coverage;
it does not deduplicate or reselect data in the browser. Metadata-free legacy
History remains supported with unknown provenance; explicit scopes fail closed
when response selection mismatches. No live-provider status is inferred from
stored evaluation history. Tests use Node's built-in runner, in-memory TSX
compilation, real React server rendering, injected Axios adapters/deferred requests,
and network guards; no dependency or public cohort-write endpoint is added.

## Groq Operator Diagnostics (ADR-055)

`scripts/diagnose_groq.py` submits one synthetic full triage using the real engine,
with cache/fallback disabled. `--dry-run` validates local configuration only;
`--trace` records bounded allow-listed HTTPcore phases without raw trace data.
Shared trace/log filters live in `scripts/diagnostic_transport.py`.

The operator reported one HTTP 200/schema-valid result in 1248.8ms, requested and
answering model `openai/gpt-oss-120b`, no cache or fallback. This is integration
acceptance for that request, not an accuracy benchmark. See the migration report.
Gemini WIRE-11 tooling is retired after provider replacement, not fixed upstream.


## Core Design Philosophy

* Lightweight infrastructure.
* Modular components.
* Independent and testable processing stages.
* Human-controlled security decisions.
* Explainable AI recommendations.
* Measurable AI reliability.
* Reproducible evaluation using labelled datasets.

---

# 2. High-Level Architecture

The processing pipeline:

```text
        PUBLIC SECURITY DATASETS
           JSON / CSV FILES
                  |
                  v
        +---------------------+
        | 1. ALERT INTAKE     |
        | Python              |
        +---------------------+
                  |
                  v
        +---------------------+
        | 2. THREAT INTEL     |
        | ENRICHMENT          |
        | VT / AbuseIPDB /    |
        | URLhaus             |
        +---------------------+
                  |
                  v
        +---------------------+
        | 3. TIMELINE BUILDER |
        | Event Correlation   |
        +---------------------+
                  |
                  v
        +---------------------+
        | 4. LLM TRIAGE       |
        | Groq API            |
        +---------------------+
                  |
                  v
        +---------------------+
        | 5. ACCURACY TRACKER |
        | Ground Truth        |
        | Performance Metrics |
        +---------------------+
                  |
                  v
        +---------------------+
        | SQLITE DATABASE     |
        +---------------------+
                  |
                  v
        +---------------------+
        | FASTAPI BACKEND     |
        +---------------------+
                  |
                  v
        +---------------------+
        | TYPESCRIPT DASHBOARD|
        +---------------------+
                  |
                  v
           HUMAN ANALYST
```

Note: SQLite is the persistent storage layer used by the processing components and dashboard. It is not intended to be an additional processing stage.

---

# 3. Component Architecture

## 3.1 Alert Intake Engine

**Responsibility:** Collect, validate, and normalize security alerts.

### Input

* JSON files.
* CSV files.
* Public security datasets.

Initial dataset sources:

* EVTX-ATTACK-SAMPLES.
* OTRF Security Datasets.
* Splunk attack_data.

### Processing

1. Read incoming files.
2. Identify the available fields.
3. Validate the incoming records.
4. Normalize the records into a consistent internal representation.
5. Preserve the original source information.
6. Preserve available ground-truth information separately.
7. Assign an internal identifier to each ingested alert.

### Output

Normalized alert records.

### Important Requirements

* Handle malformed records.
* Handle missing fields.
* Preserve original event timestamps.
* Avoid overwriting source information.
* Support batch processing.
* Maintain data provenance.

No live SIEM integration is required in the initial version.

---

## 3.2 Threat Intelligence Enrichment Engine

**Responsibility:** Add external threat intelligence context to suspicious indicators.

### Supported Services

1. VirusTotal.
2. AbuseIPDB.
3. URLhaus.

### Supported Indicator Types

* IP addresses.
* Domains.
* File hashes.
* URLs where supported by the respective provider.

### Processing

1. Extract available indicators from normalized alerts.
2. Identify the indicator type.
3. Query the appropriate intelligence provider.
4. Validate the returned response.
5. Store enrichment information.
6. Associate the enrichment results with the original alert.

### Output

Enriched alert records containing:

* Original indicator.
* Indicator type.
* Threat intelligence source.
* Reputation or detection information when available.
* Lookup timestamp.
* Lookup status.

### Important Requirements

* Implement API timeouts.
* Handle rate limits.
* Implement caching.
* Avoid unnecessary repeated API calls.
* Handle unavailable services gracefully.
* Never interpret missing intelligence as proof that an indicator is benign.

---

### Compact Threat-Intelligence Summaries (ADR-030, ADR-042)

Compact provider summaries have a separate byte contract (ADR-030, ADR-042): each
`intel_summary` object is strictly below 800 UTF-8 bytes as formatted inside the
final evidence JSON, including ASCII escaping and nested indentation. A shared
limiter runs after projection/full-value redaction and after full-payload masking. It prioritizes
numeric/status signals, marks omissions with `summary_truncated: true`, and preserves
full raw records. Invalid masked JSON/enrichment structure withholds the request.
This cap excludes enrichment wrappers and the rest of the prompt.

### Enrichment Cache Lifetimes (ADR-029, ADR-041)

Successful (`ok`) lookups have a 24-hour TTL; non-`ok` provider results use the
existing 15-minute negative TTL. When SQLite is configured, its persisted expiry
is authoritative on every lookup. A miss invalidates any local copy before the
normal lookup-cap and quota checks. Loading a cached record into a new engine
does not extend its deadline. Memory-only engines use an injected `cache_clock`
(default `time.monotonic`) and reject entries at or after their deadline. Fresh
hits consume no lookup budget; expired local state is removed when accessed.

### Daily Provider Attempt Budgets (ADR-043)

Each built-in provider reserves daily quota immediately before every HTTP send,
including retries and failures. RPM availability is checked first; reservations
use the dispatch UTC day after any wait. SQLite atomically checks/increments in a
conditional UPSERT shared across connections. Memory-only engines share a locked
process-local ledger, which resets on restart; separate processes require SQLite.
`quota_clock` and `quota_ledger` are injectable. Quota storage failures stop sends.
Timeout reservations are retained conservatively. This measures local attempts,
not remote billing. Old persisted undercounts cannot be reconstructed.

Cache hits, built-in validation/missing-key rejections, and local throttling
consume no daily quota. Quota denials are not cached. Logical per-run lookup caps
remain separate from retry counts. Scoped callbacks select the current engine
budget even for shared providers. Opaque legacy providers reserve once per
dispatch until they adopt the per-attempt hook; direct provider calls outside an
engine have no daily ledger. Optional provider sender/clock/sleep callbacks enable
offline verification. See `docs/results/provider_attempt_quotas_20261108.md`.

## 3.3 Timeline Builder

**Responsibility:** Correlate related security events into a chronological investigation timeline.

### Example

Input events:

```text
10:02 - Unusual login detected.
10:05 - Suspicious process execution.
10:09 - Connection to suspicious external IP.
10:12 - Possible lateral movement.
```

Expected output:

```text
Incident Timeline:

10:02 - Initial suspicious login.
10:05 - Suspicious process execution.
10:09 - External communication detected.
10:12 - Possible lateral movement.

Assessment:
Potentially related suspicious activity.
```

### Processing

1. Identify potentially related events.
2. Examine timestamps.
3. Compare available identifiers and contextual information.
4. Group related events.
5. Sort events chronologically.
6. Generate an investigation timeline.

### Output

Correlated event groups and chronological timelines.

### Important Requirements

* Preserve individual event records.
* Maintain event provenance.
* Do not invent relationships between unrelated events.
* Distinguish confirmed relationships from possible correlations.
* Handle missing timestamps.

The initial implementation should use transparent, deterministic correlation logic rather than depending entirely on AI.

---

## 3.4 LLM-Assisted Triage Engine

**Responsibility:** Use an external LLM to assist with alert investigation and triage while enforcing security boundaries and provider abstraction.

### Active Provider and Model

Groq chat completions (`https://api.groq.com/openai/v1/chat/completions`):
- Primary: `openai/gpt-oss-120b`.
- Configure `GROQ_API_KEY`, `GROQ_MODEL` and optional `GROQ_FALLBACK_MODELS`.
- No model fallback or retry is enabled by default. Explicit fallback consumes
  additional requests and does not guarantee continuity under provider limits.
- Strict-schema-compatible model identifiers are validated before dispatch.


### Processing Pipeline

1. **Deterministic Redaction:** Retain allow-listed telemetry roots and recursively copy their structured values, excluding evaluation/ground-truth keys and dataset provenance regardless of case/separator variants. Remove standalone classification values and complete technique IDs while preserving forensic strings and false/zero/null values. Original records and independent provider intelligence remain intact (ADR-008, ADR-017, ADR-040). Dataset adapters must keep evaluation metadata out of free-form observable text.
2. **PII & Secret Scrubbing:** Mask API keys (including Groq tokens), private keys, passwords, bearer tokens, emails, and credit cards using `PIIScrubber` with Luhn credit-card defense (ADR-019).
3. **Prompt Injection Defense & Boundary Isolation:** Encapsulate untrusted log telemetry inside `<FORENSIC_EVIDENCE>...</FORENSIC_EVIDENCE>` XML tags. Instruct the model that log content is untrusted and cannot override system instructions (ADR-023).
4. **Response Caching:** Check `LLMResponseCache` using SHA-256 fingerprint of sanitized timeline alerts and candidate model before making external requests (ADR-025).
5. **API Invocation:** Transmit system/user messages and strict JSON schema to Groq. Only explicitly configured fallbacks are tried upon HTTP 429, 503, 404 or transport failures.
6. **Safe Failure Reporting:** Withhold upstream error bodies and exception details from Groq logs; report status/category without exposing telemetry or credentials.
7. **Strict Schema Parsing:** Require exact JSON with nine model-authored fields, local strict types/ranges/content and evidence-relationship checks, expected model identity and a completed answer. Reject prose, fences, truncation, refusals and tool calls.
8. **Verdict Attribution:** Store answering `model_name`, `uncertainty_level`, and `missing_information` in `TriageVerdict` and persist to SQLite.

### Expected Output Schema

Each triage assessment produces a structured `TriageVerdict`:

```json
{
  "disposition": "MALICIOUS" | "BENIGN" | "UNDETERMINED",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
  "confidence_score": 0.0 - 1.0,
  "uncertainty_level": "LOW" | "MEDIUM" | "HIGH",
  "summary": "Executive threat summary",
  "reasoning": [
    "Analytical finding with forensic evidence"
  ],
  "missing_information": [
    "Telemetry gap or investigative lead"
  ],
  "recommended_actions": [
    "Authorized, scoped investigation/preservation step; cleanup only after preservation"
  ],
  "evidence_basis": {
    "kind": "insufficient_evidence",
    "decision_refs": [], "observations": [], "hypotheses": [],
    "gaps": [{
      "category": "process_context", "description": "Telemetry gap or investigative lead",
      "required_evidence": "Process/context records needed to determine intent",
      "blocks_disposition": true
    }]
  }
}
```

The schema sketch's insufficient-evidence example requires UNDETERMINED/HIGH;
ADR-057 specifies the binary-support variants and all cross-field relationships.

### Provider Abstraction (`TriageProvider`)

The engine implements a runtime-checkable protocol (`TriageProvider`) defined in `src/engine/llm.py`:

```python
@runtime_checkable
class TriageProvider(Protocol):
    """Provider-independent interface protocol for LLM triage engines."""
    model: str

    def analyze_timeline(self, timeline: ThreatTimeline) -> Optional[TriageVerdict]:
        ...
```

This guarantees that alternative backends (such as Azure OpenAI, Anthropic Claude, or local testing doubles) can be introduced without modifying pipeline or evaluation logic.

---

## 3.5 Accuracy and Validation Engine

**Responsibility:** Measure how accurately and reliably the AI evaluates security alerts against independent ground truth.

This is the distinguishing component of TriageLens.

### Core Principle (ADR-008)

The AI-generated assessment must be compared against independently established ground-truth information. The AI must never evaluate its own correctness.

### Evaluation Metrics & Calibration

* **Confusion Matrix:** True Positives (TP), True Negatives (TN), False Positives (FP), False Negatives (FN).
* **Statistical Performance:** Accuracy, Precision, Recall (Sensitivity), Specificity (True Negative Rate), F1-Score.
* **Error Rates:** False Positive Rate (FPR), False Negative Rate (FNR).
* **Confidence Calibration (ADR-025):**
  - **Brier Score:** Mean squared error between predicted confidence and empirical correctness ($0.0 = \text{perfect probabilistic calibration}$).
  - **Expected Calibration Error (ECE):** Weighted absolute gap between confidence and empirical accuracy across 5 probability bins (`0.0-0.2`, `0.2-0.4`, `0.4-0.6`, `0.6-0.8`, `0.8-1.0`).
  - **5-Bin Reliability Diagram:** Per-bin sample counts, mean confidence, and empirical accuracy.
* **Class Imbalance Guard (ADR-022):** Detects single-class or heavily skewed datasets ($>10:1$ ratio), invalidates misleading zero-FPR calculations, and flags `is_imbalanced`.
* **Reproducibility Digest:** SHA-256 hash across all ground truth and prediction pairs ensuring auditable benchmarks.

### Persisted Availability (ADR-045)

CLI and evaluation runners persist an Unavailable evaluation for each attempted
logical triage that returns no verdict or raises an Exception. SQL NULL preserves
the missing verdict/prediction/correctness/confidence; ground truth remains separate.
Foreign keys still require an existing timeline and validate any non-null verdict.
Skipped/inactive CLI triage adds no evaluation. Availability is (labelled + unknown)
/ (labelled + unknown + unavailable); unavailable results do not enter confusion
or calibration counts. Empty streams retain the existing 1.0 convention.

CLI reports its current run; the API reconstructs stored history, including
unavailable-only history. Reports label unavailable predictions explicitly.
Supported legacy schemas migrate transactionally on init_db, preserving records,
sequence counters, indexes/triggers, and FK enforcement. Custom inbound references
require an explicit separate migration. Historical missing failures are not inferred
or backfilled. Repeated cached-evaluation weighting remains an open finding.
See `docs/results/unavailable_outcomes_20261108.md`.

### Persisted Severity Results (ADR-046)

Each evaluation snapshots severity_ground_truth, severity_prediction, and
severity_correct. Nullable correctness preserves True/False/unknown distinctly;
readers restore these fields without re-evaluating current alerts or verdicts.
Legacy initialization adds missing nullable columns without backfilling history.
The unavailable-outcome migration retains these columns when rebuilding older
NOT NULL schemas. Both readers tolerate absent fields as unknown.

API severity counts therefore reconstruct the same stored results used by a run.
Only known severity_correct values contribute to the denominator. A prediction
can have unknown binary ground truth but known severity correctness. Unavailable
predictions and missing severity labels do not enter severity accuracy. Historical
unknown rows remain excluded; zero evaluated results retain the existing 0.0
accuracy convention. See `docs/results/severity_persistence_20261108.md`.

### Replay Provenance and Metric Scopes (ADR-047; stages 1-3 ADR-048/049/050)

Accepted design separates stored history/run rows, unique verdict/context quality
units, and completed fresh logical attempts. It adds run/observation provenance,
idempotent outcome links, versioned evidence/inference/evaluation fingerprints,
cache validation/expiry, and explicit API scope/coverage metadata. Independent
labels remain evaluation-only. Legacy rows retain unknown provenance and are not
silently deduplicated. History stays the compatibility default; dashboard display
changes are a separate stage. The detailed schema, denominators, staged plan, and
acceptance examples are in ADR-047. History counting is unchanged.

Stage 1 adds evaluation_runs and triage_observations plus nullable evaluation
lineage. Observations start before acquisition; atomic finalization writes verdict,
evaluation, and terminal observation with cross-connection idempotency. New
observations retain separate history rows; retries of one observation reuse its
outcome. Model failures are unavailable outcomes; storage/protocol errors fail the
run and interrupt pending work. Skips have observation metadata and no evaluation.
Contexts store independent-label/policy digests outside prompts. Each run currently
has an ad hoc cohort namespace; legacy rows remain unknown. Groq reports actual
cache/send origin via context-local hooks, while opaque providers remain unknown.
Stage 3 now supplies explicit validated cohort bindings and scoped selection. See
`docs/results/run_provenance_stage1_20261108.md`.

Stage 2 prepares one sanitized request and hashes model-visible evidence plus the
complete inference policy/template/schema. Memory and SQLite acquisition use a
shared validator for provenance version, identity, answering-model eligibility,
fixed expiry, fresh schema validation, and body digest. Memory returns detached
snapshots; persistent acquisition does not bypass SQLite through memory. Legacy
or rejected entries cause fresh triage without rewriting old records. Expiry is
generation-based, bounded by configured TTL, and rejects exact deadlines/future
generation. UTC and memory-age clocks are injectable. No label/evaluation hash
or credential enters the inference cache contract or model prompt.

Observations record verified cache hits or rejected candidates followed by fresh
acquisition. Fresh verdict provenance is persisted atomically; existing provenance
cannot be rewritten. Historical API lookup stays separate and both evaluation
scripts use shared cache acquisition. Stage 2 preserves history counts and metric
shapes; stage 3 adds explicit scopes and additive selection metadata as described above.
See `docs/results/verdict_cache_validity_20261108.md`.

### Model Verification and Historical Benchmarks

Groq `openai/gpt-oss-120b` completed one operator-observed schema-valid synthetic
triage in 1248.8ms. No Groq benchmark accuracy or calibration result is available.
The 70-timeline evaluation and earlier two-model comparison in `docs/results/`
are archived Gemini evidence. Do not apply their scores to the active provider.


## 3.6 Analyst Dashboard

**Responsibility:** Provide an interface through which analysts can review alerts, timelines, AI assessments, and evaluation results.

### Frontend

TypeScript-based web interface.

### Backend

FastAPI.

### Initial Dashboard Sections

1. Overview.
2. Alert Management.
3. Threat Intelligence.
4. Incident Timelines.
5. AI Triage Results.
6. Accuracy and Performance Analytics.

### Overview

Display:

* Total ingested alerts.
* Alert severity distribution.
* AI triage statistics.
* Evaluation metrics.
* Recent investigation activity.

### Alert Management

Allow analysts to:

* Browse alerts.
* Inspect alert details.
* Review enrichment information.
* Examine associated timelines.

### AI Triage Results

Display:

* AI-generated summaries.
* Suggested severity.
* Supporting evidence.
* Recommended investigation steps.
* Uncertainty information.

### Accuracy Analytics

Display:

* Correct predictions.
* Incorrect predictions.
* Accuracy.
* Precision.
* Recall.
* F1-score.
* False-positive and false-negative statistics.

### Important Requirements

* Clearly distinguish AI recommendations from verified evidence.
* Display evaluation limitations.
* Maintain human analyst authority.
* Avoid presenting AI confidence as proof of correctness.

---

# 4. Data Flow

The following describes the expected flow of a security alert.

### Step 1: Ingestion

A security alert is imported from a JSON or CSV dataset.

### Step 2: Normalization

The ingestion engine converts the record into the internal alert representation.

### Step 3: Enrichment

Available IP addresses, domains, URLs, and file hashes are submitted to their appropriate threat intelligence providers.

### Step 4: Correlation

Related events are grouped into a chronological timeline.

### Step 5: AI Analysis

The enriched alert and relevant contextual information are submitted to Groq.

### Step 6: Evaluation

The AI assessment is compared against available ground-truth information.

### Step 7: Persistence

Alerts, enrichment information, timelines, AI assessments, and evaluation results are stored in SQLite.

### Step 8: Presentation

FastAPI exposes the relevant information to the TypeScript dashboard.

### Step 9: Human Review

The analyst examines the evidence and decides what action should be taken.

---

# 5. Database Architecture

**Database:** SQLite 3 with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and foreign-key enforcement (`PRAGMA foreign_keys=ON`).

The database is designed to remain lightweight, robust against concurrent access, and responsive on an 8 GB RAM system.

### Active Relational Schema

| Table | Primary Key | Foreign Keys | Key Columns | Responsibility |
|---|---|---|---|---|
| `timelines` | `id` (TEXT/UUID) | None | `grouping_key`, `start_time`, `end_time`, `total_events`, `correlation_type`, `correlation_reason` | Stores correlated incident timelines |
| `alerts` | `id` (TEXT/UUID) | `timeline_id -> timelines(id)` | `source_dataset`, `source_file`, `event_type`, `timestamp`, `original_record` (JSON), `ground_truth_label` | Normalized alerts with independent ground truth |
| `enrichments` | `id` (INTEGER) | None | `indicator`, `indicator_type`, `provider`, `lookup_status`, `is_malicious`, `raw_response`, `lookup_timestamp` | Extracted IPs, domains, hashes with recorded threat intel |
| `enrichment_cache` | `cache_key` (TEXT) | None | `indicator`, `indicator_type`, `provider`, `lookup_status`, `is_malicious`, `raw_response`, `cached_at`, `expires_at` | Persistent SQLite cache with positive/negative TTL (ADR-029) |
| `verdicts` | `id` (TEXT/UUID) | `timeline_id -> timelines(id)` | `severity`, `confidence_score`, `uncertainty_level`, `summary`, `reasoning` (JSON), `missing_information` (JSON), `recommended_actions` (JSON), `model_name` | AI triage decisions with model attribution and telemetry |
| `evaluations` | `id` (INTEGER) | `verdict_id -> verdicts(id)` (nullable), `timeline_id -> timelines(id)` | `ground_truth`, `llm_prediction`, `is_correct`, `category`, `confidence_score`, `severity_prediction`, `severity_ground_truth`, `severity_correct` | Statistical evaluation snapshots (ADR-008, ADR-032, ADR-045, ADR-046) |

### Planned Schema Additions (Future YARA Engine — Planned / Not Built)

| Table | Primary Key | Foreign Keys | Key Columns | Responsibility |
|---|---|---|---|---|
| `yara_rules` | `rule_name` (TEXT) | None | `description`, `author`, `rule_content`, `created_at` | Compiled YARA threat hunting rules (planned extension) |
| `yara_matches` | `id` (TEXT/UUID) | `rule_name -> yara_rules(rule_name)`, `timeline_id -> timelines(id)` | `matched_strings` (JSON), `detected_at` | Forensic file & memory pattern matches (planned extension) |

### Automated Migrations

`DatabaseManager.init_db()` executes idempotent `ALTER TABLE` statements ensuring legacy database files automatically acquire new columns (`model_name`, `uncertainty_level`, `missing_information`) without requiring manual migration scripts.

---

# 6. Backend Architecture

**Framework:** FastAPI.

FastAPI acts as the application interface between the processing layer, database, and frontend.

### Responsibilities

* Expose alert information.
* Provide enrichment results.
* Serve incident timelines.
* Provide AI assessment details.
* Expose evaluation statistics.
* Validate API requests.
* Handle application-level errors.

The backend should remain separate from the frontend.

The processing modules should also be usable independently of the dashboard wherever practical.

---

# 7. Technology Responsibilities

| Technology | Assigned Responsibility   |
| ---------- | ------------------------- |
| Python     | Processing stages 1–5     |
| FastAPI    | Backend API               |
| SQLite     | Persistent data storage   |
| Groq API | AI-assisted analysis      |
| HTTPX      | External API requests     |
| Pydantic   | Data validation           |
| TypeScript | Dashboard                 |
| SQL / KQL-style filter | Security hunting queries  |
| YARA       | Later-stage file matching |
| pytest     | Automated testing         |

KQL-style hunting filters and YARA file matching are additional capabilities to be introduced after the core pipeline is established.

They are not prerequisites for the first working version.

---

# 8. Resource and Infrastructure Architecture

The project must run efficiently on the available hardware.

### Hardware

* Intel Core i5 10th Generation.
* 8 GB RAM.
* 512 GB internal SSD.
* 256 GB external SSD.
* Windows operating system.

### Resource Allocation

**Internal SSD:**

* Source code.
* Virtual environment.
* Git repository.
* Configuration files.

**External SSD:**

* Large datasets.
* Security logs.
* Experimental data.
* Generated evaluation datasets.

### Infrastructure Decisions

* SQLite is preferred for the initial version.
* Cloud LLM inference is preferred over local model hosting.
* Docker is optional.
* Avoid unnecessary background services.
* Use small batches for data processing.
* Cache external API responses.
* Avoid loading entire large datasets into memory.

---

# 9. Security Architecture

Security must be considered throughout the application.

### API Credentials

* Store API keys in environment variables.
* Use a local `.env` file.
* Add `.env` to `.gitignore`.
* Never commit credentials.

### Sensitive Information

* Identify sensitive fields before external LLM requests.
* Mask unnecessary personal or organizational information.
* Do not transmit raw logs when a reduced structured representation is sufficient.

### External API Communication

* Use HTTPS.
* Implement timeouts.
* Validate external responses.
* Handle service failures.
* Avoid exposing sensitive request information in logs.

### AI Safety

* Treat model-generated content as untrusted output.
* Validate all structured responses.
* Do not execute commands suggested by the model.
* Never allow AI output to trigger destructive security actions automatically.

---

# 10. Development Roadmap

The initial target is approximately eight weeks. Actual duration will depend on implementation and testing.

| Timeline  | Development Objective                           |
| --------- | ----------------------------------------------- |
| Weeks 1–2 | Alert intake and threat intelligence enrichment |
| Weeks 3–4 | Timeline builder and SQL-backed KQL-style hunting filters |
| Weeks 5–6 | LLM triage and accuracy scoring                 |
| Week 7    | Dashboard implementation & YARA matching (planned) |
| Week 8    | README, architecture diagram and demo video     |

The development sequence should prioritize a working, testable pipeline before advanced features.

---

# 11. Future Extensions

The architecture should allow future additions without requiring a complete redesign.

Potential extensions:

* Additional LLM providers.
* Model-to-model accuracy comparison.
* ATT&CK technique mapping.
* ATT&CK coverage heatmap.
* Telemetry drift detection.
* YARA-based file matching.
* Additional threat intelligence providers.
* More advanced incident correlation.
* Additional dataset integrations.

These are future possibilities, not requirements for the initial implementation.

---

# 12. Architectural Principles and Non-Negotiable Decisions

1. No locally hosted LLM in the initial version.
2. No full SIEM deployment required.
3. SQLite remains the initial database.
4. Python handles the first five processing stages.
5. FastAPI serves the backend.
6. TypeScript powers the dashboard.
7. AI predictions must be independently evaluated.
8. Ground-truth labels must remain independent.
9. Sensitive information must be masked before external LLM transmission.
10. Human analysts retain final decision-making authority.
11. Each processing stage must be independently testable.
12. Architecture changes must be documented in DECISIONS.md.

---

# 13. Repository Directory Structure

```text
triagelens/
├── data/                      # Benchmark and test datasets
│   ├── eval_benchmark_70.json # 70-timeline balanced evaluation dataset
│   ├── eval_cache.db          # Evaluation run verdict cache
│   └── eval_compare_cache.db  # 2-model comparison cache
├── dashboard/                 # React 19 + TypeScript + Vite Analyst Dashboard
│   ├── src/
│   │   ├── components/        # Operations Console, Hunting UI, Timeline views
│   │   ├── services/          # REST API clients
│   │   └── types/             # Frontend TypeScript interfaces
│   └── package.json
├── docs/                      # Technical reports and documentation
│   └── results/
│       ├── evaluation_report_20261106.md # 70-timeline empirical benchmark report
│       └── model_comparison_report.md    # 2-model comparison & calibration report
├── scripts/                   # SOC automation and benchmarking utilities
│   ├── generate_eval_dataset.py # Generates balanced 70-timeline benchmark
│   ├── generate_soc_data.py   # Synthetic SOC log generator
│   ├── run_evaluation.py      # 70-timeline evaluation benchmark runner
│   └── compare_models.py      # 2-model evaluation & calibration comparison
├── src/                       # Core Python backend and engine
│   ├── api/                   # FastAPI REST endpoints
│   │   └── main.py
│   ├── engine/                # Core pipeline stages
│   │   ├── database.py        # SQLite persistence, foreign keys & WAL manager
│   │   ├── enrichment.py      # Multi-provider threat intel (VT, AbuseIPDB, URLhaus)
│   │   ├── evaluation.py      # AccuracyTracker, calibration, metrics (ADR-008)
│   │   ├── hunting.py         # Parameterized KQL-style hunting filter to SQLite translator
│   │   ├── intake.py          # Alert normalization and intake engine
│   │   ├── llm.py             # Shared triage, privacy, cache and provider protocol
│   │   └── timeline.py        # Identity-based event correlation & time windows
│   ├── models/                # Pydantic data schemas
│   │   ├── alert.py
│   │   ├── enrichment.py
│   │   ├── evaluation.py
│   │   ├── timeline.py
│   │   └── triage.py
│   └── utils/                 # Security & extraction utilities
│       ├── extraction.py      # Indicator extraction and validation
│       └── masking.py         # PIIScrubber regex & Luhn credit-card defense
└── tests/                     # Test suite (263 passing adversarial, security, and unit tests)
    ├── test_api_adversarial.py
    ├── test_database_adversarial.py
    ├── test_enrichment.py
    ├── test_evaluation_adversarial.py
    ├── test_hunting_adversarial.py
    ├── test_intake_adversarial.py
    ├── test_llm_adversarial.py
    ├── test_timeline_adversarial.py
    └── test_wire7_docs_and_health.py
```

---

**Final architectural principle:**

TriageLens should not simply tell an analyst what an AI thinks about an alert. It should provide the evidence, explain the reasoning available, preserve the investigation trail, and demonstrate how reliably its AI performs against known outcomes.
