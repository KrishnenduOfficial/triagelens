# TASKS.md — TriageLens

**Project:** TriageLens
**Version:** 0.1.0
**Development Status:** Enhanced, Calibrated & Empirically Benchmarked
**Project Stage:** Phases 1–8 Core Implemented & Benchmarked / 213 Passing Tests / Portfolio Preparation

---

# 1. Task Status Legend

Use the following status indicators:

* [ ] Not Started
* [x] Completed and Verified
* [~] In Progress
* [!] Blocked

**Important:** A task can only be marked completed after its implementation has been tested or otherwise verified.

Do not mark a task complete merely because files or code have been generated.

---

# 2. Initial Project Setup

## 2.1 Local Environment

* [x] Create the TriageLens project directory.
* [x] Initialize Git repository.
* [x] Create Python virtual environment.
* [x] Create initial source directory structure.
* [x] Create initial configuration files.
* [x] Install initial Python dependencies.
* [x] Create initial Git commit.

## 2.2 Dependencies

Initial dependencies:

* [x] FastAPI
* [x] Uvicorn
* [x] HTTPX
* [x] Pydantic
* [x] pytest
* [x] python-dotenv
* [x] google-genai

Note: Initial installation is recorded as complete. Individual package versions and compatibility must be verified when implementation begins.

---

# 3. Documentation and Project Knowledge

## 3.1 Core Documentation

* [x] Finalize GEMINI.md.
* [x] Finalize ARCHITECTURE.md.
* [x] Finalize TASKS.md.
* [x] Create DECISIONS.md.
* [x] Review consistency across all documentation.
* [x] Verify documentation is stored in the project root.

## 3.2 AI Coding Agent Configuration

* [x] Verify Antigravity workspace instruction-loading mechanism.
* [x] Configure project-specific agent instructions.
* [x] Verify the agent can access GEMINI.md.
* [x] Verify the agent understands ARCHITECTURE.md.
* [x] Verify the agent uses TASKS.md to track progress.
* [x] Verify the agent updates project documentation after completed tasks.

## 3.3 GitHub

* [x] Create GitHub repository (remote: https://github.com/KrishnenduOfficial/triagelens.git).
* [x] Connect local repository to GitHub remote.
* [x] Verify remote configuration.
* [x] Push initial project commit.
* [x] Verify repository contents online.
* [x] Review repository for exposed credentials or sensitive information.

---

# 4. Phase 1 — Alert Intake Engine

**Priority:** High

**Objective:** Build a reliable ingestion and normalization system for structured security alerts.

### Tasks

* [ ] Research suitable public security datasets (synthetic dataset created; public repository integration pending).
* [ ] Select initial dataset (synthetic telemetry created; public repository selection pending).
* [x] Define normalized alert data model.
* [x] Implement JSON ingestion.
* [x] Implement CSV ingestion.
* [x] Implement input validation.
* [x] Implement field normalization.
* [x] Implement timestamp normalization.
* [x] Preserve original source information.
* [x] Preserve ground-truth labels independently.
* [x] Implement batch processing.
* [x] Add structured logging.
* [x] Write unit tests.
* [x] Test malformed records.
* [x] Test missing fields.
* [x] Verify ingestion results.

### Completion Criteria

* JSON and CSV records can be ingested.
* Records are converted into the normalized internal representation.
* Invalid records are handled gracefully.
* Original source information is preserved.
* Ground-truth labels are not overwritten.
* Automated tests pass.

---

# 5. Phase 2 — Threat Intelligence Enrichment

**Priority:** High

**Objective:** Enrich suspicious indicators using external threat intelligence services.

### Tasks

* [x] Design indicator extraction logic.
* [x] Implement IP address extraction.
* [x] Implement domain extraction.
* [x] Implement file hash extraction.
* [x] Implement URL extraction where applicable.
* [x] Design provider-independent enrichment interface.
* [x] Integrate VirusTotal.
* [x] Integrate AbuseIPDB.
* [x] Integrate URLhaus.
* [x] Implement API timeouts.
* [x] Implement rate-limit handling.
* [x] Implement caching.
* [x] Implement enrichment error handling.
* [x] Preserve lookup timestamps.
* [x] Write unit tests using mocked API responses.
* [x] Verify enrichment results.

### Completion Criteria

* Supported indicators are extracted correctly.
* Appropriate intelligence providers are queried.
* API failures do not crash the ingestion pipeline.
* Repeated lookups can use cached results.
* Enrichment results retain their source information.

---

# 6. Phase 3 — Timeline Builder

**Priority:** High

**Objective:** Correlate related security events into chronological investigation timelines.

### Tasks

* [x] Define event correlation data model.
* [x] Implement timestamp-based ordering.
* [x] Identify relevant event identifiers.
* [x] Implement deterministic correlation rules.
* [x] Group potentially related events.
* [x] Generate chronological timelines.
* [x] Preserve individual event references.
* [x] Distinguish confirmed and potential correlations (ADR-021).
* [x] Handle missing timestamps.
* [x] Write unit tests.
* [x] Verify timeline generation.

### Completion Criteria

* Events are ordered correctly.
* Related events can be grouped using documented rules.
* Original event information is preserved.
* Unsupported relationships are not presented as confirmed facts.
* Timeline generation is independently testable.

---

# 7. Phase 4 — LLM-Assisted Triage

**Priority:** High

**Objective:** Integrate Gemini API for structured security alert analysis.

### Tasks

* [x] Configure Gemini API credentials.
* [x] Implement secure environment configuration (centralized `src/config.py` with canonical names, `VT_API_KEY` alias, and parity testing; ADR-027).
* [x] Design provider-independent LLM interface (`TriageProvider` Protocol; ADR-025).
* [x] Implement Gemini provider.
* [x] Design structured triage prompt.
* [x] Implement prompt injection defense and untrusted evidence delimiters (<FORENSIC_EVIDENCE>) (ADR-023).
* [x] Implement verified model configuration and graceful candidate fallback (`gemini-3.8-flash`, `gemini-3.5-flash-lite`, `gemini-3.1-flash-lite`) (ADR-023, ADR-026).
* [x] Record responding model name on triage verdicts in memory and SQLite (ADR-023).
* [x] Define expected AI response schema.
* [x] Implement response validation.
* [x] Implement alert summarization.
* [x] Implement suggested severity assessment.
* [x] Implement evidence extraction.
* [x] Implement investigation recommendations.
* [x] Implement uncertainty reporting (`uncertainty_level` and `missing_information` in schema, prompt, DB migrations; ADR-025).
* [x] Implement sensitive-data masking (enhanced with JSON-aware KV regex, recursive scrub_dict, and Luhn credit-card validation; ADR-018).
* [x] Implement log sanitization and truncation boundaries for raw API errors and raw LLM text (ADR-024).
* [x] Implement ground-truth and provenance isolation via allow-list serialization (ADR-017).
* [x] Implement API timeout and error handling.
* [x] Implement response caching where appropriate (`LLMResponseCache` with SHA-256 fingerprinting, TTL, capacity bounding; ADR-025).
* [x] Write mocked integration tests.
* [x] Verify structured triage results.

### Completion Criteria

* Enriched alerts can be submitted for AI analysis.
* AI responses follow the defined schema.
* Invalid responses are handled safely.
* Sensitive information is masked.
* AI output is distinguishable from verified evidence.
* Human review remains mandatory.

---

# 8. Phase 5 — Accuracy and Validation Engine

**Priority:** Critical

**Objective:** Evaluate AI triage performance against independent ground-truth labels.

### Tasks

* [x] Define evaluation data model.
* [x] Establish ground-truth mapping.
* [x] Implement prediction comparison.
* [x] Implement accuracy calculation.
* [x] Implement precision calculation.
* [x] Implement recall calculation.
* [x] Implement F1-score calculation.
* [x] Implement confusion matrix.
* [x] Implement false-positive rate.
* [x] Implement false-negative rate.
* [x] Implement severity evaluation where labels permit (ADR-022).
* [x] Handle missing ground truth.
* [x] Handle unavailable AI predictions (ADR-022).
* [x] Store evaluation results.
* [x] Ground-truth independence verification: Automated regression tests verify zero label or provenance leakage into LLM prompts (ADR-008, ADR-017).
* [x] Implement reproducible evaluation (ADR-022).
* [x] Execute real evaluation benchmark run across 70 balanced enterprise timelines (`docs/results/evaluation_report_20261106.md`; ADR-024).
* [x] Implement confidence calibration metrics (Brier score, ECE, 5-bin calibration curve; ADR-025).
* [x] Execute 2-model evaluation and calibration comparison (`docs/results/model_comparison_report.md`; ADR-026).
* [x] Write unit tests using known expected outcomes.
* [x] Verify metric calculations.

### Completion Criteria

* AI predictions are compared against independent labels.
* Evaluation results are reproducible.
* Incorrect predictions are recorded.
* Missing ground truth is handled separately.
* Metrics are mathematically verified using test cases.
* Classification and severity performance are not incorrectly combined.

---

# 9. Phase 6 — Database and Backend

**Priority:** High

**Objective:** Establish persistent storage and API access.

### Tasks

* [x] Finalize database schema.
* [x] Configure SQLite (centralized DATABASE_PATH with TRIAGELENS_DB_PATH alias, automatic directory creation, WAL mode; ADR-027).
* [x] Implement database connection management.
* [x] Implement alert persistence.
* [x] Implement indicator persistence.
* [x] Implement enrichment persistence.
* [ ] Implement incident persistence (schema persists timelines, alerts, verdicts; incident aggregation entity deferred).
* [x] Implement timeline persistence.
* [x] Implement AI assessment persistence.
* [x] Implement evaluation persistence.
* [x] Configure FastAPI application.
* [x] Implement alert API endpoints.
* [x] Implement enrichment API endpoints.
* [x] Implement timeline API endpoints.
* [x] Implement AI assessment API endpoints.
* [x] Implement evaluation API endpoints.
* [x] Implement API error handling.
* [x] Implement API security and concurrency hardening (restricted CORS, SQLite WAL mode, KQL row limits, Pydantic bounds, and global 500 error sanitization; ADR-019, ADR-020).
* [x] Test API endpoints.

### Completion Criteria

* Application data persists in SQLite.
* Database relationships are consistent.
* Backend endpoints return validated responses.
* Errors are handled appropriately.
* API tests pass.

---

# 10. Phase 7 — Analyst Dashboard

**Priority:** Medium

**Objective:** Build a user-friendly security investigation interface.

### Tasks

* [x] Establish TypeScript frontend.
* [x] Configure frontend-backend communication.
* [x] Create dashboard layout.
* [x] Create overview section.
* [ ] Create alert management interface.
* [x] Create alert detail view.
* [ ] Create threat intelligence view.
* [x] Create incident timeline interface.
* [x] Create AI triage result view.
* [x] Create accuracy analytics dashboard.
* [x] Implement severity indicators.
* [x] Implement loading and error states.
* [x] Verify responsive layout.
* [ ] Test frontend-backend integration (static Vite/tsc build verified; automated E2E testing deferred).

### Completion Criteria

* Dashboard displays actual backend data.
* Analysts can inspect alert information.
* AI assessments are clearly identified.
* Evaluation metrics are displayed correctly.
* Interface handles loading and errors gracefully.

---

# 11. Phase 8 — Additional Security Capabilities

**Priority:** Medium / Future

### SQL and KQL Hunting

* [x] Research relevant security hunting queries.
* [x] Create a collection of investigation queries.
* [x] Document query use cases.
* [ ] Validate queries against compatible datasets (verified on unit fixtures and synthetic dataset; real public dataset test pending).
* [x] Implement ThreatHuntingEngine with KQL-to-SQL parameterized translation.
* [x] Support deep JSON attribute extraction (e.g., `Network.DestinationIp`).
* [x] Add `POST /api/hunt` endpoint with input validation and error handling.
* [x] Enforce parameterized row limits on KQL SQL queries to prevent resource exhaustion (ADR-019).
* [x] Validate against adversarial SQL injection and syntax corruption attack vectors.

### YARA Integration

* [ ] Research YARA rule structure.
* [ ] Define file-analysis workflow.
* [ ] Implement optional YARA integration.
* [ ] Test with safe sample files.
* [ ] Present results in investigation records.

### MITRE ATT&CK Mapping

* [ ] Research ATT&CK technique mapping.
* [ ] Define technique mapping structure.
* [ ] Associate supported detections with techniques.
* [ ] Display mapped techniques in the dashboard.

These features should not delay the completion of the core pipeline.

---

# 12. Phase 9 — Testing and Quality Assurance

* [x] Run complete unit test suite (213 passing unit, security, and adversarial tests).
* [x] Run integration tests (FastAPI test client with mocked external endpoints).
* [x] Test ingestion-to-enrichment pipeline (`test_intake_adversarial.py`, `test_enrichment.py`).
* [x] Test enrichment-to-timeline pipeline (`test_timeline_adversarial.py`).
* [x] Test timeline-to-AI pipeline (`test_llm_adversarial.py`).
* [x] Test AI-to-evaluation pipeline (`test_evaluation_adversarial.py`).
* [x] Verify database consistency (`test_database_adversarial.py`: foreign keys, WAL mode, migrations).
* [x] Test API failure scenarios (`test_api.py`: 404, 422, sanitized 500 responses).
* [x] Test external API failure scenarios (503 high demand, 429 rate limit, 404 deprecated models, timeouts).
* [x] Review sensitive-data handling (`PIIScrubber` with Luhn check, `_safe_log_text` secret redaction, ADR-008 prompt isolation).
* [x] Test on available hardware (verified on Intel Core i5, 8 GB RAM development workstation).
* [x] Identify performance bottlenecks (resolved via SQLite WAL mode, in-memory `LLMResponseCache`, and query row bounds).
* [x] Fix high-priority issues (audits F1 through F11 fully resolved with regression tests).

### Completion Criteria

The complete core pipeline operates reliably on the development machine, with automated tests covering important processing stages.

---

# 13. Phase 10 — Portfolio Preparation

* [x] Create comprehensive README.md (production-ready with architecture, setup, evaluation, and limitations).
* [x] Document installation instructions (backend Python venv and frontend npm setup).
* [x] Document environment variables (`.env.example` and README reference table).
* [x] Document architecture (full ASCII flow across Stages 1–8 in README.md and ARCHITECTURE.md).
* [x] Document API usage (table of REST endpoints and interactive Swagger UI docs).
* [x] Document supported datasets (JSON, CSV, synthetic SOC dataset, 70-timeline benchmark).
* [x] Document evaluation methodology (ADR-008 independent ground truth, confusion matrix, Brier score, ECE).
* [x] Add architecture diagram (ASCII pipeline flow and repository directory trees).
* [ ] Add dashboard screenshots (deferred for manual UI screenshot capture).
* [ ] Record project demonstration video (deferred for offline presentation recording).
* [x] Document known limitations (internal IP/hostname/username retention, single-node SQLite, API quotas, ground-truth requirements).
* [x] Review GitHub repository (clean git tree, no secrets, `.env` and `*.db` in `.gitignore`, remote verified).
* [ ] Prepare project presentation for SOC analyst interviews (offline portfolio slide deck preparation).

---

# 14. Current Development Milestone

## Milestone 0 — Project Foundation

**Objective:** Establish a documented and reproducible development environment.

### Current Progress

* [x] Local project directory created.
* [x] Git initialized.
* [x] Python virtual environment created.
* [x] Initial dependencies installed.
* [x] Initial project structure created.
* [x] GEMINI.md prepared; verify it is saved.
* [x] ARCHITECTURE.md saved and reviewed.
* [x] TASKS.md saved and reviewed.
* [x] DECISIONS.md created.
* [x] Antigravity instruction loading verified.
* [x] GitHub repository created.
* [x] Initial project pushed to GitHub.

### Milestone Completion Criteria

All four documentation files must be present and internally consistent.

Antigravity must be able to understand the project using repository documentation.

The local repository must be ready for controlled implementation.

---

# 15. Development Rules

1. Work on one task at a time.
2. Follow the development order unless a documented reason requires a change.
3. Do not implement future-stage features prematurely.
4. Do not install dependencies without justification.
5. Do not overwrite existing working code unnecessarily.
6. Test every important implementation.
7. Update this file after verified progress.
8. Update DECISIONS.md when important technical decisions are made.
9. Record blockers explicitly.
10. Never claim completion without verification.

---

# 16. Next Immediate Action

Complete Milestone 0.

After documentation is finalized:

1. Verify Antigravity reads the project instructions.
2. Verify the existing local project structure.
3. Review the repository before the first implementation.
4. Begin Phase 1: Alert Intake Engine.

**Development principle:** Build a working, testable security platform incrementally. Quality and technical understanding take priority over development speed.
