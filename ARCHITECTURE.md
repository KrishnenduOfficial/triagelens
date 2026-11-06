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
        | Gemini API          |
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

### Initial Provider & Active Tiering

Google Gemini API (Generative Language API v1beta):
- **Primary Model:** `gemini-3.8-flash` (Flagship analytical tier)
- **Candidate Fallbacks:** `gemini-3.5-flash-lite`, `gemini-3.1-flash-lite` (High-throughput, reliable failovers)
- Fully configurable via `GEMINI_MODEL` and `GEMINI_FALLBACK_MODELS` environment variables.

### Processing Pipeline

1. **Deterministic Redaction:** Strip evaluation/ground-truth keys and dataset provenance to prevent prompt data leakage (ADR-008).
2. **PII & Secret Scrubbing:** Mask API keys, private keys, passwords, bearer tokens, IP addresses, emails, and SSNs using `PIIScrubber` with Luhn credit-card defense (ADR-019).
3. **Prompt Injection Defense & Boundary Isolation:** Encapsulate untrusted log telemetry inside `<FORENSIC_EVIDENCE>...</FORENSIC_EVIDENCE>` XML tags. Instruct the model that log content is untrusted and cannot override system instructions (ADR-023).
4. **Response Caching:** Check `LLMResponseCache` using SHA-256 fingerprint of sanitized timeline alerts and candidate model before making external requests (ADR-025).
5. **API Invocation & Model Failover:** Transmit structured prompt to primary model; automatically fail over through candidate fallbacks upon HTTP 429, 503, 404, or network timeout.
6. **Log Truncation & Sanitization:** Sanitize and truncate any raw API errors or candidate outputs to 250 characters via `_safe_log_text()` (ADR-024).
7. **Strict Schema Parsing:** Enforce JSON object extraction, removing markdown code fences or trailing commas.
8. **Verdict Attribution:** Store answering `model_name`, `uncertainty_level`, and `missing_information` in `TriageVerdict` and persist to SQLite.

### Expected Output Schema

Each triage assessment produces a structured `TriageVerdict`:

```json
{
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
    "Immediate containment or remediation step"
  ]
}
```

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

### Empirical Benchmarks

1. **70-Timeline Balanced Benchmark (`docs/results/evaluation_report_20261106.md`):**
   - 92.8% Accuracy, 96.8% Precision, 88.2% Recall, 97.1% Specificity, 92.3% F1-score, 2.9% FPR, 11.8% FNR.
2. **2-Model Calibration Benchmark (`docs/results/model_comparison_report.md`):**
   - `gemini-3.5-flash-lite`: 95.0% Accuracy, Brier: 0.0390, ECE: 0.0020.
   - `gemini-3.1-flash-lite`: 100.0% Accuracy, Brier: 0.0071, ECE: 0.0585.

---

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

The enriched alert and relevant contextual information are submitted to Gemini.

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

### Finalized Relational Schema

| Table | Primary Key | Foreign Keys | Key Columns | Responsibility |
|---|---|---|---|---|
| `timelines` | `id` (TEXT/UUID) | None | `grouping_key`, `start_time`, `end_time`, `total_events`, `correlation_type`, `correlation_reason` | Stores correlated incident timelines |
| `alerts` | `id` (TEXT/UUID) | `timeline_id -> timelines(id)` | `source_dataset`, `source_file`, `event_type`, `timestamp`, `original_record` (JSON), `ground_truth_label` | Normalized alerts with independent ground truth |
| `indicators` | `id` (INTEGER) | None | `indicator_type`, `value` (UNIQUE), `source`, `enrichment_data` (JSON), `first_seen`, `last_seen` | Extracted IPs, domains, hashes with cached threat intel |
| `verdicts` | `id` (TEXT/UUID) | `timeline_id -> timelines(id)` | `severity`, `confidence_score`, `uncertainty_level`, `summary`, `reasoning` (JSON), `missing_information` (JSON), `recommended_actions` (JSON), `model_name` | AI triage decisions with model attribution and telemetry |
| `evaluations` | `id` (TEXT/UUID) | `verdict_id -> verdicts(id)`, `timeline_id -> timelines(id)` | `ground_truth`, `llm_prediction`, `is_correct`, `category`, `confidence_score` | Statistical evaluation records (ADR-008) |
| `yara_rules` | `rule_name` (TEXT) | None | `description`, `author`, `rule_content`, `created_at` | Compiled YARA threat hunting rules |
| `yara_matches` | `id` (TEXT/UUID) | `rule_name -> yara_rules(rule_name)`, `timeline_id -> timelines(id)` | `matched_strings` (JSON), `detected_at` | Forensic file & memory pattern matches |

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
| Gemini API | AI-assisted analysis      |
| HTTPX      | External API requests     |
| Pydantic   | Data validation           |
| TypeScript | Dashboard                 |
| SQL / KQL  | Security hunting queries  |
| YARA       | Later-stage file matching |
| pytest     | Automated testing         |

KQL/SQL hunting capabilities and YARA file matching are additional capabilities to be introduced after the core pipeline is established.

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
| Weeks 3–4 | Timeline builder and SQL/KQL hunting queries    |
| Weeks 5–6 | LLM triage and accuracy scoring                 |
| Week 7    | YARA matching and dashboard                     |
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
│   │   └── server.py
│   ├── engine/                # Core pipeline stages
│   │   ├── database.py        # SQLite persistence, foreign keys & WAL manager
│   │   ├── enrichment.py      # Multi-provider threat intel (VT, AbuseIPDB, URLhaus)
│   │   ├── evaluation.py      # AccuracyTracker, calibration, metrics (ADR-008)
│   │   ├── hunting.py         # Parameterized KQL-to-SQLite translation engine
│   │   ├── intake.py          # Alert normalization and intake engine
│   │   ├── llm.py             # Gemini DFIR triage, prompt defense, cache & protocol
│   │   ├── timeline.py        # Identity-based event correlation & time windows
│   │   └── yara_engine.py     # YARA rule compilation and forensic matching
│   ├── models/                # Pydantic data schemas
│   │   ├── alert.py
│   │   ├── enrichment.py
│   │   ├── evaluation.py
│   │   ├── timeline.py
│   │   └── triage.py
│   └── utils/                 # Security utilities
│       └── masking.py         # PIIScrubber regex & Luhn credit-card defense
└── tests/                     # Test suite (213 passing adversarial/security tests)
    ├── test_api.py
    ├── test_database_adversarial.py
    ├── test_enrichment.py
    ├── test_evaluation_adversarial.py
    ├── test_hunting_adversarial.py
    ├── test_intake_adversarial.py
    ├── test_llm_adversarial.py
    ├── test_timeline_adversarial.py
    └── test_yara_adversarial.py
```

---

**Final architectural principle:**

TriageLens should not simply tell an analyst what an AI thinks about an alert. It should provide the evidence, explain the reasoning available, preserve the investigation trail, and demonstrate how reliably its AI performs against known outcomes.
