# AGENTS.md ? TriageLens

## Current provider and verified status ? 2026-11-08

Groq is the sole supported runtime AI provider (ADR-055). Use `GROQ_API_KEY`,
`GROQ_MODEL` (default `openai/gpt-oss-120b`) and optional `GROQ_FALLBACK_MODELS`
(blank by default). `.env` is private and must never be printed or committed.

The operator ran `python scripts/diagnose_groq.py --timeout 30 --trace` and
reported HTTP 200, the expected answering model, a schema-valid full triage,
1248.8ms, one request, no cache and no fallback. This verifies that request,
not benchmark accuracy or guaranteed future availability.

Subsequent agent-executed live verification: six preselected synthetic cases,
six valid verdicts, TP=3/TN=3/FP=0/FN=0, but severity agreement only 1/6. API persisted
metrics and real-component static rendering matched. See
`docs/results/groq_evaluation_report.md`. Unsupported assertions and a destructive
cleanup recommendation require an offline rubric/preservation audit before scaling.
This does not close interactive UI, full CLI or prompt-injection verification.

Gemini runtime code, settings and diagnostics are removed. WIRE-11 is retired
as superseded by the provider replacement, not repaired upstream. Historical
benchmark reports and stored records retain their true model attribution.
Do not ask the operator to resume Gemini diagnostics as a current project task.
See README.md, TASKS.md, DECISIONS.md and docs/results/groq_migration_20261108.md.

Current offline verification: 619 backend tests passed (one existing warning),
48 dashboard tests passed; local Markdown links and diff whitespace checks passed.
The lower backend total reflects retirement of tests exclusive to removed features.

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

Use Groq chat completions with `openai/gpt-oss-120b` as the active AI provider.

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

Groq API credentials and quotas are independent of consumer chat subscriptions. Never assume unlimited free API access.

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
| Groq API | AI-assisted triage                |
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

1. Read AGENTS.md before beginning project work.
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

The six-stage pipeline, persistence, provenance-aware caches, metric scopes and
scope-aware dashboard are implemented. Groq uses strict assessment JSON and local
validation. Shared tests remain offline; human analysts retain decision authority.

Pending work: independently evaluate Groq's quality and prompt-injection resistance,
verify the real CLI/API/dashboard workflow, review operator report metric labels,
and complete interactive visual QA. Do not relabel old model scores as Groq results.
