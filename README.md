# TriageLens

**Active provider: Groq, `openai/gpt-oss-120b` (ADR-055).**
A pre-policy six-case live synthetic check on 2026-11-08 returned six valid verdicts:
6/6 binary classifications matched the labels, but exact severity matched 1/6.
This small selected sample does not establish general accuracy or service uptime.
Gemini runtime support is removed. Historical results remain attributed correctly.
The later `triage-v1` check returned six valid assessments, including one abstention,
but still exposed a false negative and unsupported assertions; see
[new-policy evidence](docs/results/triage_v1_live_check_20261108.md).

> **An alert triage pipeline that measures how often its AI is wrong.**

[![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.0-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.3.1-20232A?logo=react&logoColor=61DAFB)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-7.0.2-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Pytest](https://img.shields.io/badge/Pytest-728_Passing-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

TriageLens is a cybersecurity engineering platform designed to automate Tier-1 and Tier-2 Security Operations Center (SOC) alert investigation while maintaining strict human-in-the-loop oversight. It ingests raw telemetry, enriches indicators with threat intelligence, reconstructs chronological incident timelines, applies cloud-based LLM digital forensics triage, and evaluates its own AI reliability against independently labelled ground truth.

Unlike conventional AI summarizers or chatbots, **TriageLens's distinguishing capability is measuring how often its AI makes mistakes** — calculating precision, recall, false-positive rate, false-negative rate, Brier score calibration, and Expected Calibration Error (ECE) on independently labelled evaluation cases.

---

## 1. System Architecture

Six functional stages turn alert telemetry into analyst-reviewed results:

```text
JSON / CSV alerts
    -> Intake: normalize records and preserve source evidence/labels
    -> Enrichment: VirusTotal, AbuseIPDB and URLhaus lookups
    -> Timeline builder: correlate identities and split event sessions
    -> Groq triage: sanitize evidence, request strict JSON, validate verdict
    -> Evaluation: compare predictions with independent ground truth
    -> Dashboard: inspect timelines, verdicts and scoped reliability metrics

SQLite stores alerts, intelligence, verdicts, outcomes and run provenance.
FastAPI serves stored results and parameterized hunting queries to React.
The human analyst retains final investigation and response authority.
```

`src/engine/llm.py` owns shared privacy, prompt and cache processing;
`src/engine/groq.py` owns the active provider's request/response contract.
The pipeline's implementation is verified offline. An operator-checked three-case
CLI/database/API/dashboard run matched stored counts (three unavailable outcomes,
zero scored; 2026-11-09). Successful-verdict display and broader interactive UI
verification remain pending; this workflow check does not establish AI quality.

---

## 2. Core Engineering Principles

1. **Human Analyst Authority:** AI output provides structured evidence and suggested response actions, never autonomous remediation.
2. **Independent Ground Truth (ADR-008):** AI predictions and reference labels are stored and evaluated separately. The prompt serializer recursively filters structured evaluation/provenance metadata beneath allow-listed telemetry fields, including nested lists and key variants (ADR-040). Original evidence and independent provider detection counts are preserved. Dataset adapters must keep labels and provenance out of free-form observable text; see the [prompt-isolation verification](docs/results/prompt_isolation_20261108.md).
3. **Prompt Injection Boundary Isolation (ADR-023):** Adversarial log telemetry is encapsulated inside `<FORENSIC_EVIDENCE>...</FORENSIC_EVIDENCE>` XML delimiters, instructing the model to treat all evidence strictly as untrusted forensic data.
4. **Wire-Level PII & Secret Scrubbing (ADR-018, ADR-019):** Cloud API keys, AWS/GCP tokens, private keys, passwords, bearer tokens, emails, and Luhn-validated credit cards are redacted before network egress.
5. **Measurable Confidence Calibration (ADR-025):** Model confidence scores are evaluated using Brier scores and Expected Calibration Error (ECE) across 5 probability bins.
6. **SQL Injection Defense (ADR-015, ADR-019):** KQL-style hunting filter expressions are compiled to parameterized SQLite queries using SQLite's `json_extract()` function.

---

## 3. Groq Capabilities and Verification

### 3.1 What the model does in TriageLens

Groq receives sanitized chronological security evidence and returns a structured
assessment: independent disposition, severity, confidence, summary, supporting reasoning, recommended
investigation actions, uncertainty and missing information. It assists analysts;
it does not execute containment, run tools or independently verify its own claims.

The application enforces evidence/label separation, secret masking, strict JSON
schema, local type/range checks, answering-model attribution and cache provenance.
Refused, truncated, mismatched or invalid responses become unavailable outcomes.
These are tested software boundaries, not a guarantee against every model error
or adversarial prompt. `GROQ_FALLBACK_MODELS` is empty by default.

### 3.2 Operator-observed live result ? 2026-11-08

| Check | Observed result |
|---|---|
| Provider / model | Groq / `openai/gpt-oss-120b` |
| HTTP / verdict validation | 200 / valid |
| Elapsed time | 1248.8ms (one observation) |
| Requests / fallback / cache | 1 / 0 / disabled |
| Transport | Connection, TLS, upload and response phases completed |

Evidence: [Groq migration and live verification](docs/results/groq_migration_20261108.md).
That initial result was operator-supplied. A later agent-run sample is described below.
A successful schema check does not establish correct severity or safe recommendations.

### 3.3 Six-case evaluation and remaining quality work

Six preselected synthetic cases (three malicious, three benign) produced six
HTTP 200/schema-valid verdicts with no retries, fallback, cache or enrichment.
Binary counts were TP=3, TN=3, FP=0, FN=0. Exact severity agreement was 1/6 (16.7%).
Mean request time was 1.24 seconds. Saved results matched the API's History, Run
and Fresh attempts metrics and rendered through the dashboard's real component.

The review found unsupported assertions and a recommendation to delete a dump
without specifying evidence preservation first. The subsequent
[offline audit](docs/results/severity_safety_audit_20261108.md) confirmed missing
policy criteria and a malicious/LOW reference conflicting with severity-derived
binary scoring. The approved `triage-v1` contract and recommendation policy are
now implemented and verified offline (ADR-056). These six measured results predate
that policy and are unchanged. The subsequent selected `triage-v1` live check made
six successful requests: TP=3/TN=1/FN=1 across five labelled cases, one unlabelled
UNDETERMINED response, and exact severity agreement 3/5. Saved metrics matched all
four API scopes and static dashboard rendering. Review still found unsupported
TLS/success/legitimacy assertions and incomplete containment qualification. This
does not establish safe recommendations or an improvement over a different sample.
See [new-policy results and remaining gaps](docs/results/triage_v1_live_check_20261108.md).
Injection resistance, real-world generalization and sustained availability remain
unmeasured. The
repository's 70-case dataset is synthetic, not a real-world SOC benchmark.
See the [six-case evidence and limitations](docs/results/groq_evaluation_report.md).

New assessments separate `disposition` (MALICIOUS, BENIGN or UNDETERMINED) from
severity (response priority/impact). A malicious event can have LOW priority.
The active policy is now **`triage-v2` / `evidence-basis-v1`** (ADR-057), implemented
and verified offline after the v1 review. It adds a ninth response field with
declared support, observations, hypotheses, gaps and references to captured
sanitized evidence. Binary answers require observed references and no declared
blocking gap. UNDETERMINED requires HIGH uncertainty and a blocking gap;
it counts as available but contributes to neither binary accuracy nor calibration.
Severity agreement remains independently scored when a reference severity exists.
Confidence concerns disposition correctness, not severity or action safety.

The [versioned policy](src/engine/triage_policy.py) requires evidence-qualified
claims, authorized analyst review, and preservation before destructive cleanup.
Emergency containment may precede full collection when observed ongoing harm
justifies it; the analyst must assess scope, urgency and evidence-loss tradeoffs.
Nonblank summary, reasoning and recommendations are validated locally. Free-text
correctness and safety still require human review; structural validation cannot
certify them. The exact system prompt and policy identity enter cache fingerprints.
New references and basis relationships are checked on fresh output and cache
return; the UI resolves citations against the saved sanitized snapshot. It shows
uncertainty and gaps before actions, distinguishing assessed empty lists from
unrecorded legacy values. References prove traceability, not entailment. Labelled
binary coverage and abstentions are shown alongside accuracy. Live v2 schema
acceptance and semantic quality remain unmeasured; earlier results are not v2 scores.
Old records retain their original scores and null/unrecorded new metadata;
History may mix scoring generations, so use explicit cohorts for comparisons.

### 3.4 Historical benchmark evidence

The [2026-11-06 evaluation](docs/results/evaluation_report_20261106.md) and
[earlier model comparison](docs/results/model_comparison_report.md) used Gemini.
They are archived evidence, not Groq performance claims. Stored history can contain
old models; use explicit run/cohort selections for a current-provider comparison.

## 4. Technology Stack

| Layer | Technologies | Purpose |
| :--- | :--- | :--- |
| **Core Processing** | Python 3.14, Pydantic 2.x | Normalization, pipeline orchestration, data validation |
| **Backend API** | FastAPI 0.162, Uvicorn, Starlette | High-performance async REST API and OpenAPI schema |
| **Database** | SQLite 3 (`WAL` mode, foreign keys) | Lightweight, ACID-compliant relational persistence |
| **AI Inference** | Groq chat-completions API | Cloud DFIR triage (`openai/gpt-oss-120b`, strict JSON schema) |
| **Protocol Abstraction**| `TriageProvider` Protocol | Provider-independent interface for interchangeable LLM backends |
| **Response Caching** | `LLMResponseCache` | In-memory thread-safe LRU/TTL cache with SHA-256 keys |
| **HTTP Client** | HTTPX | Sync and async external intelligence and Groq communication |
| **Threat Intelligence**| VirusTotal, AbuseIPDB, URLhaus | Indicator enrichment for IP addresses, domains, and file hashes |
| **Query Engine** | KQL-style hunting filter to SQLite translator | Parameterized security hunting queries with JSON path extraction |
| **Testing** | Pytest 9.2 (728 passing backend tests) | Unit, adversarial, security injection, and regression testing |
| **Frontend** | React 19, TypeScript 7, Vite 8, custom CSS | Dark-mode SOC analyst investigation console |

---

## 5. Quickstart Guide

### 5.1 Prerequisites

- Python 3.14, the version used for the verified pinned environment.
- Node.js satisfying the installed Vite requirement: `^20.19.0 || >=22.12.0`, plus npm.
- The documented development environment is Windows/PowerShell. Other operating
  systems have not been verified by this project evidence.
- Cloud inference avoids running a local model. Hardware performance has not been
  benchmarked; the project targets a modest workstation.

---

### 5.2 Backend Setup

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/KrishnenduOfficial/triagelens.git
   cd triagelens
   ```

2. **Create and activate a virtual environment (PowerShell):**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   On a POSIX shell, activation is `source .venv/bin/activate`.

3. **Install dependencies:**
   ```powershell
   python -m pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```powershell
   if (-not (Test-Path -LiteralPath .env)) {
       Copy-Item .env.example .env
   }
   ```
   Edit `.env` to configure your API keys and model parameters:
   ```env
   GROQ_API_KEY=your_groq_api_key_here
   GROQ_MODEL=openai/gpt-oss-120b
   GROQ_FALLBACK_MODELS=
   DATABASE_PATH=data/triagelens.db
   VIRUSTOTAL_API_KEY=
   ABUSEIPDB_API_KEY=
   URLHAUS_API_KEY=
   ```
   Groq needs a real key for live triage. Intelligence credentials are optional:
   enter real values for services you use and leave unused credentials blank,
   including `URLHAUS_API_KEY` in the template. Example placeholder strings are
   treated as configured credentials; they are not working API keys.
   *(Note: `TRIAGELENS_DB_PATH` is also recognized as an alias for `DATABASE_PATH`, and `VT_API_KEY` as an alias for `VIRUSTOTAL_API_KEY`).*

   `VIRUSTOTAL_MIN_DETECTIONS` defaults to 3 malicious engine detections;
   set it to a positive integer to adjust the enrichment flag. A result below
   the threshold, including one or two detections, does not prove an indicator
   is safe. `ENRICHMENT_WAIT_MODE` defaults to `false`; set it to `true` to
   allow rate-limit waits bounded by `ENRICHMENT_MAX_WAIT_SECONDS`.
   `ENRICHMENT_MAX_LOOKUPS_PER_RUN=0` is parsed as no cap, but the environment
   variable is currently unused by the runtime, even when set to a positive
   value. Use the CLI `--max-lookups` option to enforce a per-run lookup cap.

   CLI, API, and the evaluation runner share database resolution: explicit CLI
   override, nonblank `DATABASE_PATH`, nonblank `TRIAGELENS_DB_PATH`, then
   `data/triagelens.db`. Relative paths use the project root containing `src/`,
   regardless of the process working directory; absolute paths retain their target.
   Parent directories are created consistently. Blank explicit overrides and
   filesystem errors fail before SQLite opens. Windows drive-only/root-only paths
   must be replaced with fully qualified or ordinary project-relative paths.
   `:memory:` explicitly selects an ephemeral database local to each connection.

   `--db-path` affects only that CLI/evaluation invocation. Configure the API with
   the same target and restart it after changing configuration. Existing databases
   are not moved or merged. The historical root `triagelens.db` is separate from
   the default `data/triagelens.db`; to select it, use `DATABASE_PATH=triagelens.db`
   consistently for both processes. A genuinely empty selected database still
   produces zero metrics. See the [path verification](docs/results/database_paths_20261108.md).

---

### 5.3 Run Automated Test Suite

```powershell
python -m pytest -q
cd dashboard
npm ci
npm test
npm run build
cd ..
```

Ordinary pytest blocks real network calls, including when credentials are present.
Groq wire/schema tests use injected senders or MockTransport. Shared privacy/cache/
provenance tests use a neutral test-only transport; it is not a production provider.
Live provider commands are manual and separate from tests. The latest verified
suite and counts are recorded in the migration report and TASKS.md.

### 5.4 End-to-End Execution Sequence

Run these from the project root with the virtual environment active. Live CLI
runs can contact both Groq and configured intelligence services and consume quota.

1. **Prepare a dedicated synthetic alert input folder:**
   ```powershell
   python scripts/generate_soc_data.py
   New-Item -ItemType Directory -Force data/raw/demo | Out-Null
   Copy-Item data/synthetic_soc_telemetry.json data/raw/demo/telemetry.json
   ```
   `data/raw/` is Git-ignored. Keep alert inputs separate from the benchmark JSON
   and databases; do not feed the entire mixed `data/` directory into alert intake.

2. **Run the pipeline:**
   ```powershell
   python -m src.cli --data-dir data/raw/demo --db-path data/triagelens.db
   ```
   Save the `Evaluation run:` UUID and the final `PIPELINE EXECUTION SUMMARY`
   for the comparison below. A configured Groq key and completed triage outcomes
   are needed for a meaningful AI metric comparison; missing credentials skip
   triage. This command makes live requests and may consume quota; one run of
   this synthetic input produced 50 timelines, potentially requiring 50 triage
   requests before retries. Check your available quota before starting.
   To skip Groq while retaining enrichment:
   ```powershell
   python -m src.cli --data-dir data/raw/demo --db-path data/triagelens.db --skip-llm
   ```
   **`--skip-llm` is not an offline switch:** intelligence lookups can still occur.
   Use the guarded test suite for offline verification.

3. **Check the database populated by that run:**
   ```powershell
   python -c "import sqlite3; c=sqlite3.connect('file:data/triagelens.db?mode=ro', uri=True); print('timelines:', c.execute('SELECT COUNT(*) FROM timelines').fetchone()[0], 'evaluations:', c.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]); c.close()"
   ```
   The read-only open fails if the file is missing. Existing rows can be from
   earlier runs; the Run selection below isolates this run. A zero evaluation
   count does not demonstrate populated AI metrics.

4. **Start the backend in a separate terminal, from the project root:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   $env:DATABASE_PATH = 'data/triagelens.db'
   python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   Configure the API's `DATABASE_PATH` to the same file as the CLI. Open
   `http://127.0.0.1:8000/docs` for the API or `/api/metrics` for stored metrics.

5. **Start the dashboard in another terminal, initially at the project root:**
   ```powershell
   cd dashboard
   npm ci
   npm run dev
   ```
   Open the local URL printed by Vite (normally `http://localhost:5173`).
   The default backend URL is `http://localhost:8000`. For a different backend,
   put the public URL in `dashboard/.env.local` before starting Vite:
   ```env
   VITE_API_BASE_URL=http://127.0.0.1:8000
   ```
   Vite uses the dashboard directory for its environment files; setting this only
   in the root `.env` does not configure the frontend. Restart Vite after changes.
   Groq and intelligence secrets stay in the root `.env`, never in `VITE_*` values.

---

### 5.5 Manual Click-Through Verification Checklist

- [ ] Open `/health` on the API and verify database connectivity.
- [ ] Open `http://127.0.0.1:8000/api/metrics?scope=run&run_id=<UUID>`,
  replacing `<UUID>` with the CLI's `Evaluation run:` value. Compare `tp`, `tn`,
  `fp`, `fn`, `total`, `unknown`, `abstained` and `unavailable` with the CLI
  summary; compare applicable rates after converting API fractions to percentages.
- [ ] On dashboard `/`, select **Run** under **Scope**, enter the same UUID in
  **Run UUID**, and click **Apply selection**. Verify the displayed Run ID, then
  compare confusion counts, binary-labeled results, unscored outcomes, undetermined
  dispositions, unavailable outcomes and applicable rates with the API and CLI.
  Default History includes earlier evaluations and need not match the latest run.
  N/A can be valid when a rate's denominator is zero; the CLI may print 0% instead.
  Check loading/error states; the UI does not certify live provider availability.
- [ ] Use the timeline list on `/` and follow a row to `/timeline/:id`. Verify its
  alert details, intelligence and stored verdict. There is no `/timelines` page or
  incident-detail drawer in the current router.
- [ ] On `/hunt`, try `event_type == "ProcessCreate"` or
  `CommandLine contains "powershell"`. A valid query may return zero matching rows.
- [ ] Check that failed triage is unavailable rather than a benign prediction and
  that historical model results remain distinguishable from new Groq results.
- [ ] Record whether the same-run numbers match and share screenshots of the CLI
  summary and dashboard selection/results, with sensitive information removed.
  Do not claim this check passed until the operator confirms it on populated data.

---

### 5.6 Groq Verification

From the project root, use these operator commands (each live command is separate):

```powershell
python scripts/diagnose_groq.py --dry-run
# One synthetic full-triage request, no cache/fallback/retry:
python scripts/diagnose_groq.py --timeout 30 --trace
# Optional separate smoke probes; one request per configured provider:
python scripts/check_connections.py --groq-timeout 30
```

Success requires `success: true`, `schema_valid: true`, and the expected answering
model. A dry run checks configuration only. Groq strict JSON schema covers only
model-authored assessment fields; application code supplies identity and provenance.
Truncation, refusal, model mismatch, invalid fields, and HTTP failures remain
unavailable outcomes. TLS remains verified. Trace output contains phase metadata
only. Existing secrets in the parent shell override `.env`; clear stale
`Env:GROQ_API_KEY` if needed and restart running processes after changing settings.

`GROQ_MODEL` defaults to `openai/gpt-oss-120b`; supported strict-schema models also
include `openai/gpt-oss-20b` and `qwen/qwen3.8-27b`. No fallback is enabled by default.
An optional comma-separated `GROQ_FALLBACK_MODELS` explicitly enables same-provider
fallback on transport failures or HTTP 429/503/404. This can spend additional quota.
Each engine instance paces attempted requests using a rolling minute (defaults: 30
requests, 8,000 tokens, 4,000 initially reserved tokens per request); configure
`GROQ_REQUESTS_PER_MINUTE`, `GROQ_TOKENS_PER_MINUTE`,
`GROQ_ESTIMATED_TOKENS_PER_REQUEST`, and `GROQ_MAX_WAIT_SECONDS` (default 60).
Reported token usage increases reservations and the estimate for later requests,
including when a response fails verdict validation. Valid remaining-token/reset
headers also constrain sends; a 429 token-reset header supplies a cooldown even
without `Retry-After`. It honors a 429 `Retry-After` before a later request or fallback; it does not retry
the same model. If the cumulative wait would exceed the budget, it withholds the
request. Reservations include failed attempts. Future usage can exceed the estimate,
and separate engines or processes do not share limits. The reported account
limits of 1,000 requests/day and 200,000 tokens/day are not enforced; monitor
account usage and configure limits for your model and account. Provider rate limits
can still be exceeded. Valid JSON does not prove
correct security analysis. Evaluate sanitized cases before using real alerts.
No Groq SDK or other dependency is needed; the engine uses existing HTTPX.

## 6. API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System health check and database connectivity status |
| `GET` | `/api/metrics` | Retrieve stored-result metrics for History or explicit run/cohort scopes |
| `GET` | `/api/timelines` | Retrieve paginated correlated threat timelines |
| `GET` | `/api/timelines/{timeline_id}` | Retrieve detailed threat timeline with alerts and LLM verdict |
| `GET` | `/api/alerts/{alert_id}` | Retrieve normalized security alert by ID |
| `GET` | `/api/enrichments/{indicator}` | Retrieve cached threat intelligence lookups for an indicator |
| `POST` | `/api/hunt` | Execute a parameterized KQL-style hunting filter across telemetry |

---

## 7. Known Limitations & Operational Boundaries

To ensure transparency and maintain defensible security engineering standards, the following known limitations are documented:

1. **Telemetry Identity Preservation (Unmasked Internal Identifiers):**
   - **Design Decision:** Internal RFC 1918 private IP addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), workstation hostnames, and user account names (e.g., `admin_jdoe`, `WORKSTATION-01`) are **intentionally NOT masked** in outbound LLM prompts.
   - **Rationale:** In Digital Forensics and Incident Response (DFIR), hostnames, user identities, and network topology are essential forensic anchors. Redacting them would blind the AI to user-process relationships, service executions, and lateral movement paths.
   - **Boundary Enforcement:** `PIIScrubber` strictly and aggressively redacts passwords, cloud secrets (AWS, GCP, GitHub tokens), private keys, authorization tokens, emails, and Luhn-validated credit cards prior to prompt encapsulation.
2. **Single-Analyst SQLite Architecture:**
   - The embedded SQLite database utilizes Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and foreign keys (`PRAGMA foreign_keys=ON`) for lightweight, zero-configuration local workstation deployment (optimizing for 8 GB RAM machines).
   - Enterprise multi-tenant deployments requiring distributed ingest pipelines or concurrent analyst write operations should transition to PostgreSQL.
3. **External LLM Cloud Dependency & API Rate Limits:**
   - Cloud triage requires outbound HTTPS access to `api.groq.com`.
   - Free-tier quotas can produce HTTP 429. Caching reduces repeated requests; fallback is opt-in and cannot guarantee availability. Missing credentials skip CLI triage; evaluation fails before processing.
4. **Supervised Ground Truth Prerequisite for Accuracy Metrics:**
   - Accuracy, Precision, Recall, Specificity, Brier score, and ECE can only be calculated when independent ground-truth labels are available (ADR-008). In raw, unlabelled enterprise production telemetry, triage verdicts are recorded as unverified leads pending human analyst disposition.

---

## 8. Repository Structure

Selected version-controlled paths are shown below; this is a structural summary.

```text
triagelens/
  .env.example                  # Placeholder configuration; real .env is private
  .gitignore                    # Excludes secrets, dependencies and runtime artifacts
  AGENTS.md                     # Project rules and working instructions
  ARCHITECTURE.md                # Components and data contracts
  DECISIONS.md                   # Versioned technical decisions
  TASKS.md                      # Current progress and next work
  LICENSE                       # MIT license
  pytest.ini                    # Backend test discovery configuration
  requirements.txt              # Pinned Python dependencies
  data/
    dummy_alerts.json            # Intake test fixture
    dummy_alerts.csv             # Intake test fixture
    synthetic_soc_telemetry.json # Generator output used for demonstrations
    eval_benchmark_70.json       # Synthetic timeline evaluation dataset
  dashboard/
    src/
      api/apiService.ts         # Typed API client and contracts
      components/               # MetricsOverview and TimelineFeed
      metrics/                  # Scope validation, formatting and request lifecycle
      pages/                    # DashboardHome, TimelineView and ThreatHunt
    tests/                      # 79 verified frontend tests
    package.json
    package-lock.json
  docs/results/                 # Verification reports and labelled historical evidence
  scripts/
    check_connections.py        # Manual provider smoke probes
    diagnose_groq.py            # One synthetic full-triage diagnostic
    diagnostic_transport.py     # Metadata-only tracing helpers
    generate_eval_dataset.py
    generate_soc_data.py
    run_evaluation.py
    compare_models.py
  src/
    api/main.py                 # FastAPI routes
    cli.py                      # Pipeline orchestration
    config.py                   # Configuration and shared database-path resolution
    engine/                     # Pipeline, Groq, cache, provenance and metric scopes
    models/                     # Validated data contracts
    utils/                      # Indicator extraction and credential/PII masking
  tests/                        # 728 verified backend cases; network blocked by default
```

Local `.env`, virtual environments, dependencies, build output, databases and
SQLite sidecars are Git-ignored. An ignored file can still contain valuable local
results; exclusion from Git is not a reason to delete it.

---

## 9. License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
