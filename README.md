# TriageLens

**Active provider: Groq, `openai/gpt-oss-120b` (ADR-055).**
A full synthetic triage succeeded on 2026-11-08: HTTP 200, schema-valid verdict,
1248.8ms, one request, no cache or fallback. This proves one live integration
success; benchmark accuracy and sustained availability remain unmeasured.
Gemini runtime support is removed. Historical results remain attributed correctly.

> **An alert triage pipeline that measures how often its AI is wrong.**

[![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.0-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.3.1-20232A?logo=react&logoColor=61DAFB)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Pytest](https://img.shields.io/badge/Pytest-619_Passing-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/)
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
    │    • Cloud Groq DFIR triage with strict assessment JSON          │
    │      (openai/gpt-oss-120b; model fallback explicitly opt-in)      │
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

## 3. Groq Capabilities and Verification

### 3.1 What the model does in TriageLens

Groq receives sanitized chronological security evidence and returns a structured
assessment: severity, confidence, summary, supporting reasoning, recommended
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
The result is operator-supplied; no agent live provider request was made.
A successful schema check does not establish correct severity or safe recommendations.

### 3.3 Quality evaluation still required

Use independent ground-truth labels and explicit metric scopes to measure accuracy,
false negatives, severity agreement, calibration, availability and injection
resistance. Run a small sanitized evaluation before a larger quota-consuming run.
The repository's 70-timeline dataset is synthetic, not a real-world SOC benchmark.

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
   GROQ_API_KEY=your_groq_api_key_here
   GROQ_MODEL=openai/gpt-oss-120b
   GROQ_FALLBACK_MODELS=
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

```powershell
python -m pytest -q
cd dashboard
npm test
npm run build
```

Ordinary pytest blocks real network calls, including when credentials are present.
Groq wire/schema tests use injected senders or MockTransport. Shared privacy/cache/
provenance tests use a neutral test-only transport; it is not a production provider.
Live provider commands are manual and separate from tests. The latest verified
suite and counts are recorded in the migration report and TASKS.md.


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

### 5.6 Groq Verification

From the project root, use these operator commands (each live command is separate):

```bash
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
Fallback remains within the configured Groq models. Rate limits still apply; valid JSON does not prove
correct security analysis. Evaluate sanitized cases before using real alerts.
No Groq SDK or other dependency is needed; the engine uses existing HTTPX.



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
   - Cloud triage requires outbound HTTPS access to `api.groq.com`.
   - Free-tier quotas can produce HTTP 429. Caching reduces repeated requests; fallback is opt-in and cannot guarantee availability. Missing credentials skip CLI triage; evaluation fails before processing.
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
│   │   ├── llm.py             # Shared triage, privacy, cache and provider protocol
│   │   ├── groq.py            # Active Groq transport and strict assessment validation
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
├── AGENTS.md                  # Project identity and operational guidelines
├── LICENSE                    # MIT License
├── TASKS.md                   # Task tracking and phase completion records
└── requirements.txt           # Python dependency specification
```

---

## 9. License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
