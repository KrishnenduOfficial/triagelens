# TriageLens

> **An alert triage pipeline that measures how often its AI is wrong.**

[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.0-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6.svg)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

TriageLens is an AI-assisted Security Operations Center (SOC) alert triage and threat analysis platform. It automates log normalization, threat intelligence enrichment, chronological timeline reconstruction, and LLM-assisted investigation while enforcing strict human-in-the-loop validation.

Unlike conventional AI summarizers, TriageLens evaluates AI triage verdicts against deterministically labelled ground truth, recording mistakes into a confusion matrix and tracking accuracy, precision, recall, and false-positive/negative rates in real time.

---

## Architecture Overview

```text
       SECURITY TELEMETRY (JSON / CSV)
                     │
                     ▼
        ┌─────────────────────────┐
        │   1. Alert Intake       │  Schema normalization, validation & metadata extraction
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │   2. Threat Intel       │  VirusTotal, AbuseIPDB, URLhaus with caching
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │   3. Timeline Builder   │  Chronological event correlation & grouping
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │   4. LLM Triage Engine  │  Cloud Gemini DFIR triage with PII/secret scrubbing
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │   5. Accuracy Tracker   │  Independent ground-truth comparison & confusion matrix
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │   6. SQLite Storage     │  Foreign-key enforced relational telemetry persistence
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │   7. FastAPI Backend    │  REST API with parameterized KQL hunting engine
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │  8. Analyst Dashboard   │  Dark-mode TypeScript/React SOC investigation console
        └────────────┬────────────┘
                     │
                     ▼
             HUMAN ANALYST
```

---

## Core Engineering Principles

1. **Human Analyst Authority:** AI output provides evidence-backed recommendations, never autonomous eradication or unreviewed actions.
2. **Independent Ground Truth (ADR-008):** AI predictions and verified ground truth labels are strictly separated. The LLM is never permitted to grade its own performance.
3. **Defense Against Prompt Injection & Hallucinations:** Structured Pydantic schema validation defends against malformed markdown fences and conversational drift.
4. **Wire-Level PII Scrubbing:** All emails, credit cards, and cloud API keys are regex-masked before leaving the boundary.
5. **SQL Injection Immunity:** Threat hunting KQL queries are strictly parameterized with dynamic SQLite JSON extraction (`json_extract`).

---

## Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Core Processing** | Python 3.14, Pydantic 2.x |
| **Backend API** | FastAPI, Uvicorn, Starlette |
| **Database** | SQLite3 (Foreign Keys enabled, parameterized) |
| **AI Inference** | Google Gemini API (Interactions / REST `generateContent`) |
| **HTTP Client** | HTTPX (Async & Sync with backoff resilience) |
| **Testing** | Pytest (174 adversarial & resilience test cases) |
| **Frontend** | React 19, TypeScript, Vite, React Router 7, Axios |

---

## Quickstart Guide

### 1. Prerequisites
- Python 3.12+ (tested on Python 3.14)
- Node.js 18+ and npm
- Hardware: Standard workstation (runs efficiently on 8 GB RAM / Intel i5)

### 2. Backend Setup

```bash
# Clone the repository
git clone https://github.com/your-username/triagelens.git
cd triagelens

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and supply your GEMINI_API_KEY
```

### 3. Run Automated Tests

TriageLens includes a comprehensive adversarial test suite covering SQL injection, prompt leakage, rate limiting, and clock-skew defenses:

```bash
pytest -v
```

### 4. Ingest Telemetry

Generate synthetic alerts and execute the end-to-end ingestion pipeline:

```bash
# Generate synthetic SOC telemetry (58 alerts across 14 timelines)
python scripts/generate_soc_data.py

# Run ingestion pipeline
python src/cli.py --data-dir data/
```

### 5. Launch FastAPI Backend

```bash
uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation is interactively available at `http://127.0.0.1:8000/docs`.

### 6. Launch Analyst Dashboard

```bash
cd dashboard
npm install
npm run dev
```
Open `http://localhost:5173` in your browser to access the SOC Operations Console and Threat Hunting Console.

---

## Repository Structure

```text
triagelens/
├── data/                   # Security alert datasets (JSON, CSV)
├── dashboard/              # React/TypeScript Analyst Dashboard
│   ├── src/
│   │   ├── api/            # Typed Axios API client
│   │   ├── components/     # MetricsOverview, TimelineFeed
│   │   └── pages/          # DashboardHome, TimelineView, ThreatHunt
├── scripts/                # Synthetic data generation utilities
├── src/
│   ├── api/                # FastAPI backend endpoints
│   ├── engine/             # Intake, Enrichment, Timeline, LLM, Evaluation, Hunting, Database
│   ├── models/             # Pydantic schemas (Alert, Enrichment, Timeline, Triage, Evaluation)
│   └── utils/              # Indicator extraction & PII scrubber
├── tests/                  # Adversarial pytest suites (174 tests)
├── ARCHITECTURE.md         # Full system architecture specification
├── DECISIONS.md            # Architecture Decision Records (ADRs)
├── GEMINI.md               # AI coding agent instructions and project identity
└── TASKS.md                # Task tracking and development roadmap
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
