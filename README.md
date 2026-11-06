# TriageLens

> **An alert triage pipeline that measures how often its AI is wrong.**

[![Python](https://img.shields.io/badge/Python-3.14-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.3.1-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL--Mode-003B57.svg?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Pytest](https://img.shields.io/badge/Pytest-213%20Passing-0A9EDC.svg?logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

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
2. **Independent Ground Truth (ADR-008):** AI predictions and verified ground truth labels are strictly separated. The LLM is never permitted to evaluate its own correctness or access ground-truth metadata in prompts.
3. **Prompt Injection Boundary Isolation (ADR-023):** Adversarial log telemetry is encapsulated inside `<FORENSIC_EVIDENCE>...</FORENSIC_EVIDENCE>` XML delimiters, instructing the model to treat all evidence strictly as untrusted forensic data.
4. **Wire-Level PII & Secret Scrubbing (ADR-018, ADR-019):** Cloud API keys, AWS/GCP tokens, private keys, passwords, bearer tokens, emails, and Luhn-validated credit cards are redacted before network egress.
5. **Measurable Confidence Calibration (ADR-025):** Model confidence scores are evaluated using Brier scores and Expected Calibration Error (ECE) across 5 probability bins.
6. **SQL Injection Defense (ADR-015, ADR-019):** Threat hunting KQL queries are dynamically compiled to parameterized SQLite queries utilizing SQLite's `json_extract()` function.

---

## 3. Empirical Evaluation & Benchmark Results

### 3.1 Real 70-Timeline Balanced Benchmark Run

TriageLens was evaluated across a balanced 70-timeline benchmark dataset (`data/eval_benchmark_70.json`: 35 Malicious, 35 Benign) spanning 9 core MITRE ATT&CK DFIR techniques (credential dumping, C2 beaconing, ransomware, lateral movement, persistence, reconnaissance, privilege escalation, defense evasion, exfiltration) and routine enterprise operations (Windows updates, Docker builds, npm installs, IT administration).

- **Execution Date:** 2026-11-06
- **Primary Model:** `gemini-3.8-flash` (with automated failover to `gemini-3.5-flash-lite`)
- **Evaluation Digest (SHA-256):** `3f623a7091599f710137b0b3c248c0cf5e3eb946c8e14a89e3b7c65d2b27bac7`
- **Full Report:** [`docs/results/evaluation_report_20261106.md`](docs/results/evaluation_report_20261106.md)

| Metric | Measured Value | SOC Engineering Target | Status |
|---|---|---|---|
| **Accuracy** | **92.8%** | ≥ 85.0% | **Exceeded** |
| **Precision** | **96.8%** | ≥ 80.0% | **Exceeded** |
| **Recall (Sensitivity)** | **88.2%** | ≥ 85.0% | **Exceeded** |
| **Specificity (TNR)** | **97.1%** | ≥ 85.0% | **Exceeded** |
| **F1-Score** | **92.3%** | ≥ 85.0% | **Exceeded** |
| **False Positive Rate (FPR)** | **2.9%** | ≤ 15.0% | **Exceeded** |
| **False Negative Rate (FNR)** | **11.8%** | ≤ 15.0% | **Exceeded** |
| **Availability Rate** | **98.6%** | 100.0% | Stable |

#### Confusion Matrix Breakdown
- **True Positives (TP):** `30` (Real attacks correctly triaged as Malicious)
- **True Negatives (TN):** `34` (Benign operations correctly triaged as Benign)
- **False Positives (FP):** `1` (Benign activity escalated as Malicious)
- **False Negatives (FN):** `4` (Complex multi-stage attacks triaged as Low/Benign)
- **Unavailable / Failed:** `1` (Handled safely without pipeline crash)

---

### 3.2 2-Model Comparison & Confidence Calibration Benchmark

TriageLens was tested in a head-to-head empirical evaluation comparing `gemini-3.5-flash-lite` against `gemini-3.1-flash-lite` across 20 representative balanced timelines (10 Malicious, 10 Benign).

- **Full Report:** [`docs/results/model_comparison_report.md`](docs/results/model_comparison_report.md)

| Metric | Model A: `gemini-3.5-flash-lite` | Model B: `gemini-3.1-flash-lite` | Target |
|---|---|---|---|
| **Accuracy** | **95.0%** | **100.0%** | ≥ 85.0% |
| **Precision** | **90.9%** | **100.0%** | ≥ 80.0% |
| **Recall** | **100.0%** | **100.0%** | ≥ 85.0% |
| **Specificity** | **90.0%** | **100.0%** | ≥ 85.0% |
| **F1-Score** | **95.2%** | **100.0%** | ≥ 85.0% |
| **False Positive Rate (FPR)** | **10.0%** | **0.0%** | ≤ 15.0% |
| **False Negative Rate (FNR)** | **0.0%** | **0.0%** | ≤ 15.0% |
| **Brier Score** *(Lower = Better)* | **0.0390** | **0.0071** | < 0.100 |
| **Expected Calibration Error (ECE)** | **0.0020** | **0.0585** | < 0.100 |

#### 5-Bin Reliability Diagram (Probability vs Empirical Accuracy)

| Bin Range | Samples (A) | Mean Conf (A) | Empirical Acc (A) | Samples (B) | Mean Conf (B) | Empirical Acc (B) |
|---|---|---|---|---|---|---|
| `0.0 - 0.2` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.2 - 0.4` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.4 - 0.6` | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.0% |
| `0.6 - 0.8` | 0 | 0.0% | 0.0% | 1 | 75.0% | 100.0% |
| `0.8 - 1.0` | 20 | 95.2% | **95.0%** | 19 | 95.2% | **100.0%** |

*Finding:* `gemini-3.5-flash-lite` exhibits near-perfect probabilistic calibration in the high-confidence bin (`ECE = 0.0020`, 95.2% confidence vs 95.0% empirical accuracy), while `gemini-3.1-flash-lite` achieved a perfect 100% classification score with an exceptionally low Brier score (`0.0071`).

---

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
| **Testing** | Pytest 9.2 (213 passing tests) | Unit, adversarial, security injection, and regression testing |
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
   TRIAGELENS_DB_PATH=data/triagelens.db
   ```

---

### 5.3 Run Automated Test Suite

TriageLens contains a comprehensive test suite of 213 unit, adversarial, security, and regression tests (mocking all external APIs so no live network calls or credentials are required):

```bash
pytest -v
```

Expected output:
```text
======================== 213 passed, 1 warning in 12.16s ========================
```

---

### 5.4 Ingest Telemetry & Run Benchmarks

1. **Generate synthetic SOC telemetry (58 alerts across 14 timelines):**
   ```bash
   python scripts/generate_soc_data.py
   ```

2. **Run the 70-timeline evaluation benchmark:**
   ```bash
   python scripts/run_evaluation.py
   ```

3. **Execute the 2-model comparison & calibration benchmark:**
   ```bash
   python scripts/compare_models.py
   ```

---

### 5.5 Launch FastAPI Backend

```bash
uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger UI documentation is available at: `http://127.0.0.1:8000/docs`
- Redoc documentation is available at: `http://127.0.0.1:8000/redoc`

---

### 5.6 Launch Analyst Dashboard

```bash
cd dashboard
npm install
npm run dev
```
Open `http://localhost:5173` in your browser to access the SOC Operations Console and Threat Hunting Console.

---

## 6. API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/alerts` | List all ingested security alerts with filtering by dataset or event type |
| `POST` | `/api/alerts` | Ingest a new normalized security alert |
| `GET` | `/api/timelines` | List correlated incident timelines with pagination |
| `GET` | `/api/timelines/{id}` | Retrieve a specific timeline with its chronological events and IoCs |
| `POST` | `/api/triage/{timeline_id}` | Trigger LLM triage analysis for a timeline |
| `GET` | `/api/triage/{timeline_id}` | Retrieve existing triage verdict, reasoning, and actions |
| `GET` | `/api/accuracy/metrics` | Retrieve live confusion matrix, precision, recall, F1, and calibration metrics |
| `POST` | `/api/hunt` | Execute a parameterized KQL hunting query across telemetry |
| `GET` | `/health` | System health check and database connectivity status |

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
│   │   ├── timeline.py        # Identity-based event correlation & time windows
│   │   └── yara_engine.py     # YARA rule compilation and forensic matching
│   ├── models/                # Pydantic schemas
│   │   ├── alert.py
│   │   ├── enrichment.py
│   │   ├── evaluation.py
│   │   ├── timeline.py
│   │   └── triage.py
│   └── utils/                 # Security utilities
│       └── masking.py         # PIIScrubber regex & Luhn credit-card defense
├── tests/                     # 213 passing adversarial, security, and unit tests
│   ├── test_api.py
│   ├── test_database_adversarial.py
│   ├── test_enrichment.py
│   ├── test_evaluation_adversarial.py
│   ├── test_hunting_adversarial.py
│   ├── test_intake_adversarial.py
│   ├── test_llm_adversarial.py
│   ├── test_timeline_adversarial.py
│   └── test_yara_adversarial.py
├── ARCHITECTURE.md            # Complete architecture specification
├── DECISIONS.md               # 26 Architectural Decision Records (ADRs)
├── GEMINI.md                  # Project identity and operational guidelines
├── TASKS.md                   # Task tracking and phase completion records
└── requirements.txt           # Python dependency specification
```

---

## 9. License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
