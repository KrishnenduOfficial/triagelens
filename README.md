# TriageLens

> **An alert triage pipeline that measures how often its AI is wrong.**

[![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.0-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.3.1-20232A?logo=react&logoColor=61DAFB)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Pytest](https://img.shields.io/badge/Pytest-529_Passing-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

TriageLens is a cybersecurity engineering platform designed to automate Tier-1 and Tier-2 Security Operations Center (SOC) alert investigation while maintaining strict human-in-the-loop oversight. It ingests raw telemetry, enriches indicators with threat intelligence, reconstructs chronological incident timelines, applies cloud-based LLM digital forensics triage, and evaluates its own AI reliability against independently labelled ground truth.

Unlike conventional AI summarizers or chatbots, **TriageLens's distinguishing capability is measuring how often its AI makes mistakes** — calculating precision, recall, false-positive rate, false-negative rate, Brier score calibration, and Expected Calibration Error (ECE) across standardized benchmarks.

---

## 1. System Architecture

TriageLens operates as a modular, pipeline-driven architecture where security telemetry flows through decoupled, testable processing stages:

```text
               PUBLIC & ENTERPRISE SECURITY TELEMETRY (JSON / CSV)
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 1. ALERT INTAKE ENGINE (intake.py)                               │
    │    • Normalizes schema, maps timestamps to UTC, extracts IoCs    │
    │    • Preserves provenance & isolates ground-truth labels         │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 2. THREAT INTEL ENRICHMENT ENGINE (enrichment.py)                │
    │    • Multi-provider queries: VirusTotal, AbuseIPDB, URLhaus      │
    │    • In-memory TTL caching, rate-limit & backoff resilience      │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 3. TIMELINE BUILDER & CORRELATION (timeline.py)                  │
    │    • Identity-driven correlation: host + user, IP, and domain    │
    │    • 30-minute sliding time windows; caps events per timeline    │
    │    • Classifies correlations as 'confirmed' vs 'potential'       │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 4. LLM-ASSISTED TRIAGE ENGINE (llm.py)                           │
    │    • <FORENSIC_EVIDENCE> XML boundary isolation against injection│
    │    • Cloud Gemini DFIR triage with automated model failover      │
    │      (gemini-3.8-flash -> gemini-3.5-flash-lite -> 3.1-flash-lite)│
    │    • In-memory SHA-256 LLM response caching (LLMResponseCache)   │
    │    • Provider-independent protocol abstraction (TriageProvider)  │
    │    • Wire-level PII/secret scrubbing with Luhn credit-card check │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 5. ACCURACY & VALIDATION ENGINE (evaluation.py)                  │
    │    • Independent ground-truth comparison (ADR-008)               │
    │    • Confusion matrix: TP, TN, FP, FN, Accuracy, Precision,      │
    │      Recall, Specificity, F1-Score, FPR, and FNR                 │
    │    • Probabilistic confidence calibration: Brier score & ECE     │
    │    • Class imbalance detection & SHA-256 reproducibility digest  │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 6. RELATIONAL PERSISTENCE (database.py)                          │
    │    • Foreign-key enforced SQLite database with WAL journal mode  │
    │    • Automated idempotent schema migrations for verdicts & alerts│
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 7. FASTAPI BACKEND API (main.py, hunting.py)                     │
    │    • REST endpoints for alerts, timelines, verdicts, and metrics │
    │    • Parameterized KQL-to-SQLite threat hunting query engine     │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 8. ANALYST DASHBOARD (dashboard/)                                │
    │    • React 19 + TypeScript + Vite + Tailwind CSS dark-mode UI    │
    │    • SOC Operations Console, Timeline Explorer, Threat Hunting   │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
                            HUMAN SOC ANALYST
             (Retains final decision-making authority; ADR-008)
```

---

## 2. Core Engineering Principles

1. **Human Analyst Authority:** AI output provides structured evidence and suggested response actions, never autonomous remediation.
2. **Independent Ground Truth (ADR-008):** AI predictions and reference labels are stored and evaluated separately. The prompt serializer recursively filters structured evaluation/provenance metadata beneath allow-listed telemetry fields, including nested lists and key variants (ADR-040). Original evidence and independent provider detection counts are preserved. Dataset adapters must keep labels and provenance out of free-form observable text; see the [prompt-isolation verification](docs/results/prompt_isolation_20261108.md).
3. **Prompt Injection Boundary Isolation (ADR-023):** Adversarial log telemetry is encapsulated inside `<FORENSIC_EVIDENCE>...</FORENSIC_EVIDENCE>` XML delimiters, instructing the model to treat all evidence strictly as untrusted forensic data.
4. **Wire-Level PII & Secret Scrubbing (ADR-018, ADR-019):** Cloud API keys, AWS/GCP tokens, private keys, passwords, bearer tokens, emails, and Luhn-validated credit cards are redacted before network egress.
5. **Measurable Confidence Calibration (ADR-025):** Model confidence scores are evaluated using Brier scores and Expected Calibration Error (ECE) across 5 probability bins.
6. **SQL Injection Defense (ADR-015, ADR-019):** Threat hunting KQL queries are dynamically compiled to parameterized SQLite queries utilizing SQLite's `json_extract()` function.

---

## 3. Empirical Evaluation & Benchmark Results

### 3.1 Real 70-Timeline Balanced Benchmark Run

TriageLens was evaluated across a balanced 70-timeline benchmark dataset (`data/eval_benchmark_70.json`: 35 Malicious, 35 Benign) spanning 9 core MITRE ATT&CK DFIR techniques (credential dumping, C2 beaconing, ransomware, lateral movement, persistence, reconnaissance, privilege escalation, defense evasion, exfiltration) and routine enterprise operations (Windows updates, Docker builds, npm installs, IT administration).

> [!NOTE]
> **Dataset & Pipeline Disclosure:** Telemetry in `eval_benchmark_70.json` consists of **synthetically generated textbook scenarios** created inside the repository. **Threat intelligence enrichment was disabled** during this baseline run to evaluate raw prompt comprehension.

- **Execution Date:** 2026-11-06
- **Answering Model:** `gemini-3.5-flash-lite` (generated 100% of evaluated verdicts; configured primary `gemini-3.8-flash` failed over)
- **Evaluation Digest (SHA-256):** `3f623a7091599f710137b0b3c248c0cf5e3eb946c8e14a89e3b7c65d2b27bac7`
- **Full Report:** [`docs/results/evaluation_report_20261106.md`](docs/results/evaluation_report_20261106.md)

| Metric | Measured Value | Wilson 95% Confidence Interval | Sample Basis | SOC Engineering Target |
|---|---|---|---|---|
| **Accuracy** | **92.8%** | **[84.1%, 96.9%]** | 64 / 69 | ≥ 85.0% |
| **Precision** | **96.8%** | **[83.8%, 99.4%]** | 30 / 31 | ≥ 80.0% |
| **Recall (Sensitivity)** | **88.2%** | **[73.4%, 95.3%]** | 30 / 34 | ≥ 85.0% |
| **Specificity (TNR)** | **97.1%** | **[85.5%, 99.5%]** | 34 / 35 | ≥ 85.0% |
| **F1-Score** | **92.3%** | N/A (harmonic mean) | Harmonic mean | ≥ 85.0% |
| **False Positive Rate (FPR)** | **2.9%** | **[0.5%, 14.5%]** | 1 / 35 | ≤ 15.0% |
| **False Negative Rate (FNR)** | **11.8%** | **[4.7%, 26.6%]** | 4 / 34 | ≤ 15.0% |
| **Availability Rate** | **98.6%** | - | 69 / 70 | 100.0% |

#### Confusion Matrix & Failure Mode Breakdown
- **True Positives (TP):** `30` (Real attacks correctly triaged as Malicious)
- **True Negatives (TN):** `34` (Benign operations correctly triaged as Benign)
- **False Positives (FP):** `1` (Benign administration query flagged as suspicious)
- **False Negatives (FN):** `4` (Attacks triaged as Benign / Low severity)
- **Unavailable / Failed:** `1` (`attack_scenario_M31-Exfiltration-ArchiveAndCurl`, handled without crash)

*Failure Mode Finding:* All 5 prediction errors occurred exclusively on **low-evidence, single-event or 2-event timelines** (such as an isolated `PassTheHash` LogonType 9 event, a standalone `.vbs` creation, a single `spoolss` NamedPipeConnect, an un-enriched `dnsleak.net` query, and an `nltest.exe` domain check) where lack of surrounding telemetry or threat intelligence reputation produced inherent ambiguity.

---

### 3.2 2-Model Comparison & Confidence Calibration Benchmark

TriageLens was tested in a head-to-head empirical evaluation comparing `gemini-3.5-flash-lite` against `gemini-3.1-flash-lite` across 20 representative balanced timelines (10 Malicious, 10 Benign) from the synthetic benchmark.

> [!WARNING]
> **Small-Sample Caveat ($n=20$):** With only 20 timelines evaluated, 100% observed accuracy corresponds to a wide Wilson 95% confidence interval of [83.9%, 100.0%]. Similarly, Brier score and ECE values at this sample size are subject to high variance and should be viewed as preliminary observations. Latency was not measured during this cached evaluation run.

- **Full Report:** [`docs/results/model_comparison_report.md`](docs/results/model_comparison_report.md)

| Metric | Model A: `gemini-3.5-flash-lite` | Model B: `gemini-3.1-flash-lite` | Wilson 95% CI (A) | Wilson 95% CI (B) | Target |
|---|---|---|---|---|---|
| **Accuracy** | **95.0%** (19/20) | **100.0%** (20/20) | [76.4%, 99.1%] | [83.9%, 100.0%] | ≥ 85.0% |
| **Precision** | **90.9%** (10/11) | **100.0%** (10/10) | [62.3%, 98.4%] | [72.2%, 100.0%] | ≥ 80.0% |
| **Recall** | **100.0%** (10/10) | **100.0%** (10/10) | [72.2%, 100.0%] | [72.2%, 100.0%] | ≥ 85.0% |
| **Specificity** | **90.0%** (9/10) | **100.0%** (10/10) | [59.6%, 98.2%] | [72.2%, 100.0%] | ≥ 85.0% |
| **F1-Score** | **95.2%** | **100.0%** | N/A | N/A | ≥ 85.0% |
| **False Positive Rate (FPR)** | **10.0%** (1/10) | **0.0%** (0/10) | [1.8%, 40.4%] | [0.0%, 27.8%] | ≤ 15.0% |
| **False Negative Rate (FNR)** | **0.0%** (0/10) | **0.0%** (0/10) | [0.0%, 27.8%] | [0.0%, 27.8%] | ≤ 15.0% |
| **Brier Score** *(Lower = Better)* | **0.0390** | **0.0071** | High variance ($n=20$) | High variance ($n=20$) | < 0.100 |
| **Expected Calibration Error (ECE)** | **0.0020** | **0.0585** | High variance ($n=20$) | High variance ($n=20$) | < 0.100 |

#### 5-Bin Reliability Diagram (Probability vs Empirical Accuracy)

| Bin Range | Samples (A) | Mean Conf (A) | Empirical Acc (A) | Samples (B) | Mean Conf (B) | Empirical Acc (B) |
|---|---|---|---|---|---|---|
| `0.0 - 0.2` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.2 - 0.4` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.4 - 0.6` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.6 - 0.8` | 0 | 0.0% | 0.0% | 1 | 75.0% | 100.0% |
| `0.8 - 1.0` | 20 | 95.2% | **95.0%** | 19 | 95.2% | **100.0%** |

*Observation:* Both models classified textbook attack scenarios effectively, but the small sample size ($n=20$) and synthetic nature of the data mean real-world production performance with live threat intel will show greater variance.

## 4. Technology Stack

| Layer | Technologies | Purpose |
| :--- | :--- | :--- |
| **Core Processing** | Python 3.14, Pydantic 2.x | Normalization, pipeline orchestration, data validation |
| **Backend API** | FastAPI 0.162, Uvicorn, Starlette | High-performance async REST API and OpenAPI schema |
| **Database** | SQLite 3 (`WAL` mode, foreign keys) | Lightweight, ACID-compliant relational persistence |
| **AI Inference** | Google Gemini API (`v1beta`) | Cloud DFIR triage (`gemini-3.8-flash`, `3.5-flash-lite`, `3.1-flash-lite`) |
| **Protocol Abstraction**| `TriageProvider` Protocol | Provider-independent interface for interchangeable LLM backends |
| **Response Caching** | `LLMResponseCache` | In-memory thread-safe LRU/TTL cache with SHA-256 keys |
| **HTTP Client** | HTTPX | Sync and async external intelligence and Gemini communication |
| **Threat Intelligence**| VirusTotal, AbuseIPDB, URLhaus | Indicator enrichment for IP addresses, domains, and file hashes |
| **Query Engine** | Custom KQL-to-SQLite Transpiler | Parameterized security hunting queries with JSON path extraction |
| **Testing** | Pytest 9.2 (529 passing tests) | Unit, adversarial, security injection, and regression testing |
| **Frontend** | React 19, TypeScript, Vite, Tailwind | Dark-mode SOC analyst investigation console |

---

## 5. Quickstart Guide

### 5.1 Prerequisites
- **Operating System:** Windows, Linux, or macOS
- **Python:** 3.12+ (tested and verified on Python 3.14)
- **Node.js:** 18+ and npm
- **Hardware:** Runs efficiently on standard workstation hardware (8 GB RAM / Intel Core i5)

---

### 5.2 Backend Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/KrishnenduOfficial/triagelens.git
   cd triagelens
   ```

2. **Create and activate virtual environment:**
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` to configure your API keys and model parameters:
   ```env
   GEMINI_API_KEY=your_google_gemini_api_key_here
   GEMINI_MODEL=gemini-3.8-flash
   GEMINI_FALLBACK_MODELS=gemini-3.5-flash-lite,gemini-3.1-flash-lite
   DATABASE_PATH=data/triagelens.db
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   ```
   *(Note: `TRIAGELENS_DB_PATH` is also recognized as an alias for `DATABASE_PATH`, and `VT_API_KEY` as an alias for `VIRUSTOTAL_API_KEY`).*

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

TriageLens contains 529 unit, adversarial, security, and regression test cases.
External providers use injected stubs or test-scoped mocks. An autouse guard in
`tests/conftest.py` rejects real HTTP/TCP attempts; local credentials do not enable
live calls. The end-to-end enrichment case verifies both credential states while
retaining real enrichment routing and SQLite persistence. Live smoke checks must
be run separately, outside pytest.

Enrichment caches enforce 24-hour successful and 15-minute negative TTLs. SQLite
is authoritative when configured; expired/deleted rows invalidate memory copies.
Memory-only engines use monotonic deadlines with an injectable clock for tests.
Refreshes still respect lookup caps and daily quotas. See the
[cache-expiry verification](docs/results/enrichment_cache_expiry_20261108.md).

Daily budgets count every built-in provider HTTP attempt, including retries and
timeouts. SQLite atomically reserves on the dispatch UTC day across connections;
without SQLite, engines share a process-local budget that resets on restart.
Cache hits and local rejections are free; quota denials are not cached. Logical
lookup caps remain separate. Legacy custom providers reserve once per dispatch
until adopting the attempt hook. Existing historical undercounts cannot be
reconstructed. See the [quota verification](docs/results/provider_attempt_quotas_20261108.md).

Attempted triage that returns no verdict or raises an exception is persisted as
`Unavailable`, preserving null prediction/verdict fields. Availability counts
labelled and unknown-label results over those results plus unavailable attempts;
failures are excluded from confusion-matrix and calibration samples. Deliberately
skipped/inactive CLI triage is outside this denominator. CLI metrics cover the
current run; API metrics cover stored history. An empty denominator retains the
existing 1.0 convention and does not prove service availability.

Supported legacy evaluation tables migrate on the next database initialization,
preserving records and foreign keys. Custom tables referencing evaluations need
an explicit separate migration. Historical missing failures cannot be backfilled
reliably, so old availability may remain optimistic. Generated reports distinguish
unavailable predictions from benign verdicts. See the
[unavailable-outcome verification](docs/results/unavailable_outcomes_20261108.md).

Severity evaluations snapshot their ground-truth label, prediction, and tri-state
correctness in SQLite. API metrics reconstruct those snapshots, preserving false
separately from unknown. Legacy initialization adds nullable fields without
backfilling missing history. Only known severity correctness contributes to the
denominator; binary correctness does not imply a severity match. Historical rows
without severity results remain excluded. See the
[severity verification](docs/results/severity_persistence_20261108.md).

CLI and evaluation runs now record run IDs, observation lifecycles, acquisition
origin, and atomic outcome links. Retrying the same observation cannot duplicate
its evaluation; a separate replay observation still adds a history row. Skips
have no evaluation, and interrupted work is distinguished from unavailable model
results. Opaque providers retain unknown origin. Legacy evaluations keep unknown
provenance. Default API history counting is unchanged. See the
[stage-1 verification](docs/results/run_provenance_stage1_20261108.md).

Verdict caches now validate sanitized evidence, complete inference policy, actual
answering-model eligibility, schema/provenance version, body integrity, and fixed
expiry. A label-only change can reuse inference; a changed prompt/model policy
cannot. Memory snapshots are detached from returned objects. Legacy entries lacking
provenance remain historical records but require fresh triage before verified reuse.
The default one-hour TTL is configurable in the engine and bounded by any shorter
supplied memory-cache TTL. Replays do not renew expiry. Both evaluation scripts
share validation; historical API display and history counting are preserved. See
the [stage-2 verification](docs/results/verdict_cache_validity_20261108.md).

Metric scopes are explicit (ADR-050):

| Request | Counting unit |
| --- | --- |
| `/api/metrics` or `?scope=history` | All persisted evaluation rows, including replays and legacy rows |
| `?scope=run&run_id=<UUID>` | Evaluation occurrences in that run |
| `?scope=quality&cohort_id=<SHA256>` | One identical verdict/context snapshot per validated cohort |
| `?scope=attempts&run_id=<UUID>` | Completed fresh logical inference attempts in that run |
| `?scope=attempts&cohort_id=<SHA256>` | Completed fresh attempts in runs bound to that immutable policy/case cohort |

Existing history metric keys and memory fallback remain compatible; explicit scopes
never fall back to unrelated history or memory. `selection` describes source, unit,
coverage, applicable denominators, and inference/context selection. Invalid,
conflicting, unknown, or repeated query parameters return 422; unknown run/cohort
identifiers return 404; conflicting canonical snapshots or member bindings return
409. The selector is `cohort_id`, not the old run-local `quality_cohort_hash` namespace.

Quality has `availability_rate: null`. Attempts return null with
`no_completed_fresh_attempts` when their denominator is zero; unavailable fresh
outcomes count, while replay, pending, skipped, and interrupted work do not.
History/run retain their earlier empty-denominator convention. Cache expiry controls
future reuse, not past evaluation eligibility. Coverage discloses repeated evidence;
deduplication does not establish independent samples or provider uptime.

Cohort registration is an evaluation-only Python storage operation, not a public
write endpoint. For a terminal run with verifiable stage-2 provenance:

```python
from src.engine.metric_scopes import scoped_metrics

cohort_id = db.declare_run_cohort(run_id)
quality = scoped_metrics(db, scope="quality", cohort_id=cohort_id)
```

This explicitly freezes known completed cases as an ad hoc cohort. It does not
reconstruct missing or unfinished dataset members. A reusable declared dataset
manifest can be registered before running with `db.register_metric_cohort(manifest)`;
pass its ID to `evaluation_run(db, "evaluation", cohort_id=cohort_id)` or
`RunRecorder(db, "evaluation", cohort_id=cohort_id)` before any observations. Subset
replays retain that original declaration. Membership is validated during scoped
selection; a mismatched run remains in history and makes cohort selection fail.
See the [manifest schema and stage-3 verification](docs/results/metric_scopes_20261108.md).
Dashboard scope controls remain stage 4; its default display is unchanged.

Provider `intel_summary` objects stay strictly below 800 UTF-8 bytes as formatted
inside the final prompt's evidence JSON. The shared limiter accounts for escaping,
indentation, and masking expansion; it prioritizes numeric/status evidence and
marks shortened or omitted content with `summary_truncated: true`. Full raw records
remain available. Complete values are redacted before truncation. This is a
per-summary limit, separate from total prompt size.
See the [byte-budget verification](docs/results/compact_summary_budget_20261108.md).

```bash
pytest -v
```

Expected output:
```text
======================== 529 passed, 1 warning ========================
```

---

### 5.4 End-to-End Execution Sequence (Ingest, Triage, Evaluate, Store, API, Dashboard)

To run the complete system from raw ingestion to the analyst dashboard:

1. **Generate synthetic SOC telemetry (58 alerts across 14 enterprise timelines):**
   ```bash
   python scripts/generate_soc_data.py
   ```

2. **Execute the end-to-end pipeline via CLI:**
   Ingests alerts from `data/`, enriches indicators, correlates chronological timelines, executes LLM DFIR triage, evaluates accuracy against ground truth, and persists records to SQLite:
   ```bash
   python -m src.cli --data-dir data/ --db-path data/triagelens.db
   ```
   *(For offline execution without an active LLM API key, pass `--skip-llm`:)*
   ```bash
   python -m src.cli --data-dir data/ --db-path data/triagelens.db --skip-llm
   ```

3. **(Optional) Run benchmark evaluation with end-to-end enrichment:**
   ```bash
   python scripts/run_evaluation.py --end-to-end
   ```

4. **Launch the FastAPI Backend:**
   Starts the REST API server connected to the populated SQLite database:
   ```bash
   uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   - Interactive Swagger UI: `http://127.0.0.1:8000/docs`
   - Real-time database metrics endpoint: `http://127.0.0.1:8000/api/metrics`

5. **Launch the Analyst Dashboard (in a second terminal):**
   ```bash
   cd dashboard
   npm install
   npm run dev
   ```
   Open `http://localhost:5173` to interact with the SOC Operations Console and Threat Hunting Console.

---

### 5.5 Manual Click-Through Verification Checklist

Follow this checklist to verify that the dashboard and backend reflect the CLI pipeline results:

- [ ] **1. API Server & Metrics Verification:**
  - Navigate to `http://127.0.0.1:8000/api/metrics`.
  - Confirm the JSON response contains non-zero `total`, `tp`, `tn`, and calculated `accuracy`, matching the CLI summary.
- [ ] **2. Operations Overview Console (`/`):**
  - Open `http://localhost:5173` in your browser.
  - Confirm the header indicates backend connectivity (`Connected to API: 127.0.0.1:8000`).
  - Verify the 4 primary KPI cards (**Accuracy**, **Precision**, **Recall**, **F1-Score**) display non-zero percentages matching the CLI summary.
  - Verify the **Confusion Matrix** widget displays the True Positive, True Negative, False Positive, and False Negative counts.
- [ ] **3. Timeline Explorer (`/timelines`):**
  - Verify the table lists correlated threat timelines with non-zero event counts.
  - Click on any timeline row to open the incident detail drawer.
  - Confirm the detail drawer renders chronological event cards, threat intelligence badges, and the AI Triage Verdict (severity, confidence score, reasoning bullets, and recommended actions).
- [ ] **4. Threat Hunting Console (`/hunt`):**
  - Navigate to the Threat Hunting tab.
  - Select a sample pre-built query or type: `Event.Type == 'process_creation'` or `Alert.Severity == 'CRITICAL'`.
  - Click **Run Query** and verify matching alerts are returned and highlighted.

---

### 5.6 Primary Gemini Triage Diagnostics (WIRE-11)

The smoke probe now gives Gemini a 30-second timeout by default, requests a short
reply without a two-token output cap, and uses low thinking for Gemini 3 models.
Threat-intelligence probes retain their five-second defaults. `--timeout N`
explicitly overrides all probes; `--gemini-timeout N` overrides Gemini alone.
Success requires nonempty answer text, not merely a `candidates` field. HTTP 503
is reported as `service_unavailable`; HTTP 429 as `quota_or_rate_limit`, without
printing upstream response bodies. These service failures still exit nonzero.

The triage engine now leaves sampling temperature at the provider default for
Gemini 3 candidates, following Google's migration guidance. It retains the existing
temperature setting for older candidates and does not silently lower triage thinking
effort. This request change requires fresh evaluation before comparing new results
with historical benchmarks.

The lightweight `scripts/check_connections.py` probe checks connectivity; it does
not establish that the primary can generate a valid triage verdict. For that check:

```bash
python scripts/diagnose_gemini.py --dry-run
python scripts/diagnose_gemini.py
# Optional explicit diagnostic budget; this does not change the engine default:
python scripts/diagnose_gemini.py --timeout 30
```

Run live checks manually, outside pytest. The diagnostic sends one synthetic
timeline to the configured primary, disables fallback and cache, and writes no
database records. Exit 0 requires a schema-valid verdict from that primary; exit 1
reports a missing key or failed check. Dry-run exits 0 without a request and reports
credential presence only. Invalid timeout arguments exit 2 before any request.

JSON output reports HTTP status, total elapsed milliseconds, model attribution,
schema validity, and a safe failure category. It withholds response/verdict content,
exception messages, and keys. TLS verification remains enabled. HTTPX's timeout is
a per-operation budget, not a strict total wall-clock deadline; `elapsed_ms` measures
the entire engine attempt. `read_timeout` means the response read stalled, whereas
`invalid_verdict` means HTTP succeeded but no acceptable verdict was produced.

**Current status:** WIRE-11 remains **REPRODUCED**, not fixed. Diagnostics do not
establish a Python-only network failure. See the
[diagnostic evidence](docs/results/wire11_diagnostics_20261108.md).

## 6. API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System health check and database connectivity status |
| `GET` | `/api/metrics` | Retrieve live confusion matrix, precision, recall, F1, and calibration metrics |
| `GET` | `/api/timelines` | Retrieve paginated correlated threat timelines |
| `GET` | `/api/timelines/{timeline_id}` | Retrieve detailed threat timeline with alerts and LLM verdict |
| `GET` | `/api/alerts/{alert_id}` | Retrieve normalized security alert by ID |
| `GET` | `/api/enrichments/{indicator}` | Retrieve cached threat intelligence lookups for an indicator |
| `POST` | `/api/hunt` | Execute parameterized KQL threat hunting query across telemetry |

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
   - Cloud triage requires outbound internet access to Google Generative Language APIs.
   - On free-tier API keys, flagship models (such as `gemini-3.8-flash`) can encounter HTTP 429 quota exhaustion. TriageLens mitigates this via automatic runtime failover to high-throughput endpoints (`gemini-3.5-flash-lite`, `gemini-3.1-flash-lite`) and response caching (`LLMResponseCache`).
4. **Supervised Ground Truth Prerequisite for Accuracy Metrics:**
   - Accuracy, Precision, Recall, Specificity, Brier score, and ECE can only be calculated when independent ground-truth labels are available (ADR-008). In raw, unlabelled enterprise production telemetry, triage verdicts are recorded as unverified leads pending human analyst disposition.

---

## 8. Repository Structure

```text
triagelens/
├── data/                      # Benchmark datasets & SQLite storage
│   ├── eval_benchmark_70.json # 70-timeline balanced evaluation benchmark
│   ├── test_sample_attack.csv # Sample attack logs (CSV format)
│   └── test_sample_attack.json# Sample attack logs (JSON format)
├── dashboard/                 # React 19 + TypeScript Analyst Dashboard
│   ├── src/
│   │   ├── components/        # MetricsOverview, TimelineFeed, ThreatHuntView
│   │   ├── services/          # Typed Axios REST API client
│   │   └── types/             # TypeScript data contracts matching Pydantic
│   └── package.json
├── docs/                      # Technical reports & architecture specifications
│   ├── results/
│   │   ├── evaluation_report_20261106.md # 70-timeline empirical benchmark report
│   │   └── model_comparison_report.md    # 2-model comparison & calibration report
│   └── architecture/          # Diagrams and ADR reference material
├── scripts/                   # SOC automation & benchmark runners
│   ├── generate_eval_dataset.py # Generates balanced 70-timeline dataset
│   ├── generate_soc_data.py   # Synthetic SOC log generator
│   ├── run_evaluation.py      # Real evaluation benchmark runner
│   └── compare_models.py      # 2-model evaluation & calibration comparison
├── src/                       # Core Python backend and pipeline engine
│   ├── api/                   # FastAPI application & REST route handlers
│   │   └── main.py
│   ├── engine/                # Core pipeline stages
│   │   ├── database.py        # SQLite persistence, foreign keys & WAL manager
│   │   ├── enrichment.py      # Threat intel (VirusTotal, AbuseIPDB, URLhaus)
│   │   ├── evaluation.py      # AccuracyTracker, calibration, metrics (ADR-008)
│   │   ├── hunting.py         # Parameterized KQL-to-SQLite translation engine
│   │   ├── intake.py          # Alert normalization and intake engine
│   │   ├── llm.py             # Gemini DFIR triage, prompt defense, cache & protocol
│   │   └── timeline.py        # Identity-based event correlation & time windows
│   ├── models/                # Pydantic schemas
│   │   ├── alert.py
│   │   ├── enrichment.py
│   │   ├── evaluation.py
│   │   ├── timeline.py
│   │   └── triage.py
│   └── utils/                 # Security & extraction utilities
│       ├── extraction.py      # Indicator extraction and validation
│       └── masking.py         # PIIScrubber regex & Luhn credit-card defense
├── tests/                     # 529 passing adversarial, security, and unit test cases
│   ├── test_api_adversarial.py
│   ├── test_database_adversarial.py
│   ├── test_enrichment.py
│   ├── test_evaluation_adversarial.py
│   ├── test_hunting_adversarial.py
│   ├── test_intake_adversarial.py
│   ├── test_llm_adversarial.py
│   ├── test_timeline_adversarial.py
│   └── test_wire7_docs_and_health.py
├── ARCHITECTURE.md            # Complete architecture specification
├── DECISIONS.md               # 32 Architectural Decision Records (ADRs)
├── GEMINI.md                  # Project identity and operational guidelines
├── LICENSE                    # MIT License
├── TASKS.md                   # Task tracking and phase completion records
└── requirements.txt           # Python dependency specification
```

---

## 9. License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
