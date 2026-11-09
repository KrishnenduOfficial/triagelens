# AGENTS.md — TriageLens
Read the rules here, `docs/ROADMAP.md` sections 1 and 2 and the active step, and `TASKS.md`. Use `docs/ADR_INDEX.md` and targeted searches for relevant decisions.

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

## 3. Architecture and technology

The pipeline comprises alert intake, threat intelligence enrichment, timeline
correlation, LLM-assisted triage, accuracy evaluation, and an analyst dashboard.
Keep stage responsibilities and input/output contracts explicit; preserve source
provenance, independent labels, uncertainty, and human analyst authority.
Use Python, FastAPI, SQLite, Groq, HTTPX, Pydantic, pytest, and TypeScript as
appropriate. Add technology only with a clear justification. Use environment
variables for secrets; never print or commit .env or expose secrets in logs.
Mask sensitive information before external transmission, validate responses,
and handle missing data, failures, quotas, and timeouts explicitly.

## 4. Hardware and development principles

Target Windows and modest hardware (10th-generation Core i5, 8 GB RAM). Do not
run local LLMs; prefer cloud inference, SQLite, manageable batches, and avoid
unnecessary resource-heavy services or containers. Keep large datasets outside
the repository where practical. Use modular, readable, typed, testable code.
Ordinary tests must mock external API calls and cover important failure cases.

## 5. Agent workflow

1. Read the instructions and current task context before making changes.
2. Inspect existing implementation before modifying it; do not recreate modules.
3. Work on one task at a time, explain significant changes, and follow the
   roadmap approval protocol. Do not change unrelated files or architecture.
4. Avoid unnecessary dependencies and ask when important requirements are unclear.
5. Verify work; never claim a command, test, or integration succeeded without evidence.
6. Update TASKS.md when progress changes and DECISIONS.md for technical decisions.
7. Report changed files, verification, limitations, and how to run and test changes.

---

## 6. Project Integrity

The following principles are non-negotiable:

* Human analysts retain decision-making authority.
* AI-generated conclusions must be distinguishable from verified evidence.
* Ground truth must remain independent of AI predictions.
* Security data must be handled responsibly.
* Every important processing stage must be testable.
* The system should be explainable and auditable.
* No feature should be added merely for visual appeal.

---
