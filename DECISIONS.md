# DECISIONS.md

# TriageLens — Technical Decision Records

**Project:** TriageLens
**Version:** 0.1.0
**Status:** Initial decisions documented
**Last Updated:** 2026-11-05

---

## 1. Purpose

This document records the important technical and architectural decisions made during the development of TriageLens.

Its purpose is to:

* Preserve the reasoning behind technical choices.
* Prevent unnecessary architectural changes.
* Give AI coding agents clear boundaries.
* Distinguish confirmed decisions from ideas that are still under consideration.
* Make future changes deliberate and traceable.

**Important:** A proposed or deferred decision must not be treated as a finalized implementation requirement.

---

## 2. Decision Status

| Status     | Meaning                                                           |
| ---------- | ----------------------------------------------------------------- |
| Accepted   | Decision has been agreed upon for the initial version.            |
| Proposed   | Intended direction, but implementation details need confirmation. |
| Deferred   | Decision will be made at a later development stage.               |
| Superseded | An earlier decision has been replaced.                            |

---

## 3. Accepted Technical Decisions

### ADR-001: Python for the Core Processing Pipeline

**Status:** Accepted

**Decision:**

Python will be used for the core TriageLens backend and processing pipeline.

**Rationale:**

* Strong ecosystem for cybersecurity and data processing.
* Suitable libraries for API integration and automation.
* Convenient integration with AI services.
* Supports rapid development and testing.

**Consequences:**

Core ingestion, enrichment, event processing, and AI-assisted analysis should be implemented in Python.

---

### ADR-002: Modular Pipeline Architecture

**Status:** Accepted

**Decision:**

TriageLens will use a modular pipeline rather than one large application component.

**Rationale:**

Each processing stage should have a clearly defined responsibility.

**Consequences:**

* Keep ingestion separate from enrichment.
* Keep deterministic event processing separate from AI analysis.
* Keep validation and accuracy measurement independent.
* Avoid unnecessary coupling between modules.
* Make individual components testable.

---

### ADR-003: Gemini API as the Initial AI Provider

**Status:** Accepted

**Decision:**

Google Gemini API will be the initial LLM provider.

The application should avoid unnecessarily coupling its entire architecture to one provider.

**Rationale:**

* Enables cloud-based AI inference.
* Avoids the hardware requirements of hosting a local LLM.
* Fits the initial development scope.

**Consequences:**

* Keep API credentials outside source code.
* Use configuration or environment variables for model settings.
* Handle API failures, rate limits, and invalid responses.
* Validate AI-generated output before using it.
* Keep the provider integration sufficiently modular to allow future alternatives.

**Still to decide:** Exact Gemini model identifier and production configuration.

---

### ADR-004: SQLite for Initial Database

**Status:** Accepted

**Decision:**

SQLite will be used for the initial development version.

**Rationale:**

* Lightweight and easy to configure.
* No separate database server required.
* Suitable for an early-stage single-developer project.
* Reduces infrastructure complexity.

**Consequences:**

Database design should avoid unnecessary assumptions that would make future migration difficult.

A move to another database should happen only when actual application requirements justify it.

---

### ADR-005: FastAPI for the Backend API

**Status:** Accepted

**Decision:**

FastAPI will be used to expose backend functionality through HTTP APIs.

**Rationale:**

* Python-native framework.
* Supports request validation through Pydantic.
* Provides automatic API documentation.
* Suitable for connecting the processing pipeline to a frontend.

**Consequences:**

Keep API routes, business logic, and data-access responsibilities separated.

---

### ADR-006: TypeScript for the Frontend

**Status:** Accepted as the initial direction

**Decision:**

The frontend will use TypeScript.

**Rationale:**

* Adds static type checking.
* Helps maintain consistency when handling API responses.
* Suitable for building an interactive analyst dashboard.

**Still to decide:** Frontend framework, build tooling, and component library.

---

### ADR-007: Cloud-Based AI Inference

**Status:** Accepted

**Decision:**

The initial version will use cloud AI inference rather than hosting a local LLM.

**Rationale:**

The development machine has 8 GB RAM. Running a local LLM alongside the development environment and other services would introduce unnecessary resource constraints.

**Consequences:**

* Use the Gemini API for initial inference.
* Keep network failures and API limits in mind.
* Do not introduce local model hosting without a clear technical reason.

---

### ADR-008: Independent Ground Truth

**Status:** Accepted — Core Project Principle

**Decision:**

AI predictions and independently labelled ground-truth results must be stored and evaluated separately.

**Rationale:**

TriageLens is intended to measure how often its AI is wrong, not merely produce AI-generated alert summaries.

**Consequences:**

* Never treat an AI prediction as ground truth.
* Preserve the original reference labels.
* Record AI predictions independently.
* Calculate evaluation metrics using appropriate labelled data.
* Make the distinction between AI output and verified findings visible to analysts.

This principle must not be weakened for convenience.

---

### ADR-009: Deterministic Processing Before AI Analysis

**Status:** Accepted

**Decision:**

Where appropriate, deterministic processing and event correlation should occur before AI-assisted analysis.

**Rationale:**

Reliable, reproducible processing should not depend on an LLM.

**Consequences:**

* Use defined rules for parsing and normalization.
* Preserve event timestamps and source information.
* Do not invent relationships between events.
* Provide the AI with structured context.
* Keep AI-generated conclusions distinguishable from deterministic findings.

---

### ADR-010: Initial Threat Intelligence Integrations

**Status:** Proposed initial scope

**Decision:**

The initial threat intelligence integration plan includes:

* VirusTotal
* AbuseIPDB
* URLhaus

**Rationale:**

These services can provide external context for indicators such as IP addresses, domains, URLs, and file hashes.

**Consequences:**

Before implementation, verify:

* API access requirements.
* Free-tier limitations.
* Rate limits.
* Data fields returned.
* Terms of use.
* Error and timeout handling.

Do not assume that every service provides unrestricted access.

---

### ADR-011: Environment-Based Secret Management

**Status:** Accepted

**Decision:**

API keys and sensitive configuration must be stored outside application source code.

**Rationale:**

Hardcoding credentials creates unnecessary security risks.

**Consequences:**

* Use environment variables and a local `.env` file.
* Include `.env` in `.gitignore`.
* Provide a safe example configuration file without real credentials.
* Never commit API keys, tokens, or passwords.
* Validate required configuration at application startup.

---

### ADR-012: Automated Testing with Pytest

**Status:** Accepted

**Decision:**

Pytest will be used for backend testing.

**Rationale:**

Automated tests help identify regressions and verify individual pipeline components.

**Consequences:**

* Test modules independently.
* Test invalid and unexpected input.
* Mock external API calls where appropriate.
* Test failure scenarios.
* Verify AI output validation.
* Do not rely exclusively on successful end-to-end demonstrations.

---

### ADR-013: Hardware-Conscious Development

**Status:** Accepted

**Decision:**

Development must remain practical on the available machine:

* Intel Core i5 10th generation
* 8 GB RAM
* 512 GB internal SSD
* 256 GB external SSD

**Consequences:**

* Prefer lightweight dependencies.
* Avoid unnecessary background services.
* Do not introduce heavy infrastructure without justification.
* Avoid local LLM hosting in the initial version.
* Prefer SQLite initially.
* Keep development and testing resource-efficient.

---

### ADR-014: Documentation as the Project Source of Truth

**Status:** Accepted

**Decision:**

The project's documentation must remain consistent with its actual implementation.

**Consequences:**

* `GEMINI.md` defines AI-agent working instructions.
* `ARCHITECTURE.md` describes the intended system architecture.
* `TASKS.md` tracks implementation progress.
* `DECISIONS.md` records technical decisions.

When implementation changes an accepted decision, update the relevant documentation.

Never mark a task complete merely because an AI agent claims it is complete. Verify the implementation.

---

### ADR-015: Parameterized KQL-to-SQLite Threat Hunting Engine

**Status:** Accepted

**Decision:**

A dedicated `ThreatHuntingEngine` translates a simplified KQL syntax into SQLite queries leveraging `json_extract(original_record, '$.path')`.

**Rationale:**

Security analysts expect KQL-style syntax (e.g., `event_type == "ProcessCreate" AND CommandLine contains "mimikatz"`). Because security alerts are ingested from heterogeneous schemas into the JSON-backed `original_record` column, dynamic extraction is necessary. To prevent SQL Injection, field identifiers are strictly validated against `^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$` and all user-supplied values are strictly parameterized using SQLite `?` placeholders.

**Consequences:**

* Allows hunting across direct table columns and arbitrary nested JSON attributes.
* Protects against SQL injection in values, operators, and field paths.
* Raises `KQLParseError` on invalid syntax, translating to HTTP 400 at the API boundary.

---

### ADR-016: Repository Hygiene and Credential Sanitization Standards

**Status:** Accepted

**Decision:**

Repository artifacts must adhere to strict cleanliness:
1. Environment variables and secrets must only be documented via placeholder `.env.example` templates.
2. Temporary memory dumps, diagnostic scripts (`debug_*.py`), and monolithic codebase packing text files (`*codebase*.txt`) are barred from version control via `.gitignore`.
3. All repository markdown and configuration files must be encoded in UTF-8 without BOM to prevent mojibake and platform-dependent decoding failures.
4. Tasks in `TASKS.md` must not remain marked `[x]` unless backed by verified, automated tests or committed artifacts.

**Rationale:**

Prevents accidental credential leakage, keeps the repository reproducible across Windows/Linux environments, and enforces honesty in project tracking.

---

## 4. Deferred Decisions

The following decisions are intentionally not finalized yet.

| Area           | Decision to make                                      |
| -------------- | ----------------------------------------------------- |
| Database       | Exact tables, relationships, and schema               |
| Backend        | Final API endpoint naming and response contracts      |
| Frontend       | React or another TypeScript framework                 |
| AI             | Exact Gemini model identifier and generation settings |
| Dataset        | Final labelled datasets for evaluation                |
| Correlation    | Detailed event correlation rules and time windows     |
| Authentication | Login, user roles, and authorization design           |
| Deployment     | Hosting platform and deployment architecture          |
| Infrastructure | Whether Docker or containers are necessary            |
| Detection      | Detailed YARA and MITRE ATT&CK implementation         |
| Hunting        | Simplified KQL-to-SQLite engine implemented (ADR-015) |

These should be decided when the relevant implementation stage is reached.

Do not introduce them prematurely.

---

## 5. Rules for AI Coding Agents

Any AI coding agent working on TriageLens must follow these rules:

1. Read the project documentation before proposing major changes.
2. Do not replace an accepted technology without explaining why.
3. Do not introduce new dependencies without justification.
4. Do not fabricate test results, threat intelligence, or security findings.
5. Never mix AI predictions with independent ground truth.
6. Keep secrets out of source code and Git.
7. Prefer small, testable implementation steps.
8. Run relevant tests after modifying code.
9. Update documentation when an accepted decision changes.
10. Ask for clarification when an important architectural decision is unresolved.

Before implementing a feature, inspect the actual project structure and existing code. Do not assume that a proposed folder, module, or feature already exists.

---

## 6. Updating This Document

When a new important technical decision is made:

1. Assign a new ADR number.
2. Give it a descriptive title.
3. Set its status.
4. Document the context and decision.
5. Explain the rationale.
6. Record consequences and limitations.
7. Update the status if the decision changes.

Do not silently overwrite an earlier decision. Mark it as superseded and record the replacement.

---

## 7. Current Decision Summary

The initial technical direction is:

* **Core language:** Python
* **Backend framework:** FastAPI
* **Database:** SQLite
* **AI provider:** Gemini API
* **Frontend language:** TypeScript
* **Testing:** Pytest
* **HTTP client:** HTTPX
* **Configuration:** Environment variables and `.env`
* **Architecture:** Modular processing pipeline
* **Inference:** Cloud-based
* **Core principle:** Independently evaluate AI predictions against ground truth

The exact database schema, frontend framework, model identifier, dataset, and deployment approach remain open decisions.

**TriageLens must prioritize explainability, reproducibility, security, and measurable AI reliability over unnecessary complexity.**
