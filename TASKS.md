# TASKS.md — TriageLens

**Project:** TriageLens
**Version:** 0.1.0
**Development Status:** Initial Setup Complete
**Project Stage:** Documentation and Architecture Definition

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

* [ ] Create public GitHub repository.
* [ ] Connect local repository to GitHub remote.
* [ ] Verify remote configuration.
* [ ] Push initial project commit.
* [ ] Verify repository contents online.
* [ ] Review repository for exposed credentials or sensitive information.

---

# 4. Phase 1 — Alert Intake Engine

**Priority:** High

**Objective:** Build a reliable ingestion and normalization system for structured security alerts.

### Tasks

* [x] Research suitable public security datasets.
* [x] Select initial dataset.
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
* [ ] Distinguish confirmed and potential correlations.
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
* [x] Implement secure environment configuration.
* [ ] Design provider-independent LLM interface.
* [x] Implement Gemini provider.
* [x] Design structured triage prompt.
* [x] Define expected AI response schema.
* [x] Implement response validation.
* [x] Implement alert summarization.
* [x] Implement suggested severity assessment.
* [x] Implement evidence extraction.
* [x] Implement investigation recommendations.
* [ ] Implement uncertainty reporting.
* [x] Implement sensitive-data masking.
* [x] Implement API timeout and error handling.
* [ ] Implement response caching where appropriate.
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
* [ ] Implement severity evaluation where labels permit.
* [x] Handle missing ground truth.
* [ ] Handle unavailable AI predictions.
* [x] Store evaluation results.
* [ ] Implement reproducible evaluation.
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
* [x] Configure SQLite.
* [x] Implement database connection management.
* [x] Implement alert persistence.
* [x] Implement indicator persistence.
* [x] Implement enrichment persistence.
* [x] Implement incident persistence.
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
* [ ] Create overview section.
* [ ] Create alert management interface.
* [ ] Create alert detail view.
* [ ] Create threat intelligence view.
* [ ] Create incident timeline interface.
* [ ] Create AI triage result view.
* [ ] Create accuracy analytics dashboard.
* [ ] Implement severity indicators.
* [ ] Implement loading and error states.
* [ ] Verify responsive layout.
* [ ] Test frontend-backend integration.

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

* [ ] Research relevant security hunting queries.
* [ ] Create a collection of investigation queries.
* [ ] Document query use cases.
* [ ] Validate queries against compatible datasets.

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

* [ ] Run complete unit test suite.
* [ ] Run integration tests.
* [ ] Test ingestion-to-enrichment pipeline.
* [ ] Test enrichment-to-timeline pipeline.
* [ ] Test timeline-to-AI pipeline.
* [ ] Test AI-to-evaluation pipeline.
* [ ] Verify database consistency.
* [ ] Test API failure scenarios.
* [ ] Test external API failure scenarios.
* [ ] Review sensitive-data handling.
* [ ] Test on available hardware.
* [ ] Identify performance bottlenecks.
* [ ] Fix high-priority issues.

### Completion Criteria

The complete core pipeline operates reliably on the development machine, with automated tests covering important processing stages.

---

# 13. Phase 10 — Portfolio Preparation

* [ ] Create comprehensive README.md.
* [ ] Document installation instructions.
* [ ] Document environment variables.
* [ ] Document architecture.
* [ ] Document API usage.
* [ ] Document supported datasets.
* [ ] Document evaluation methodology.
* [ ] Add architecture diagram.
* [ ] Add dashboard screenshots.
* [ ] Record project demonstration video.
* [ ] Document known limitations.
* [ ] Review GitHub repository.
* [ ] Prepare project presentation for SOC analyst interviews.

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
* [ ] GitHub repository created.
* [ ] Initial project pushed to GitHub.

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
