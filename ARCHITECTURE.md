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

**Responsibility:** Use an external LLM to assist with alert investigation and triage.

### Initial Provider

Google Gemini API.

### Processing

1. Receive enriched alert information.
2. Prepare a structured prompt.
3. Mask sensitive information.
4. Send the relevant information to Gemini.
5. Receive the model response.
6. Validate the response.
7. Convert it into a structured internal result.
8. Cache the result where appropriate.

### Expected Output

Each triage assessment should contain:

* Alert summary.
* Suggested severity.
* Suggested classification.
* Supporting evidence.
* Recommended investigation steps.
* Confidence or uncertainty information.
* Missing information or limitations.

### Important Requirements

* Use structured responses.
* Validate model output.
* Handle API failures.
* Respect API rate limits.
* Cache suitable responses.
* Never send unnecessary raw logs.
* Mask sensitive information before external transmission.
* Keep model integration replaceable.

### Provider Abstraction

The LLM integration should use a simple provider-independent interface.

Conceptual example:

```python
def triage(alert):
    """
    Accept an enriched alert
    and return a structured assessment.
    """
```

Gemini should be an implementation of this interface rather than being deeply coupled to the rest of the application.

This will allow additional providers to be integrated later.

---

## 3.5 Accuracy and Validation Engine

**Responsibility:** Measure how accurately the AI evaluates security alerts.

This is the distinguishing component of TriageLens.

### Core Principle

The AI-generated assessment must be compared against independently established ground-truth information.

The AI must never evaluate its own correctness.

### Processing

1. Retrieve the AI-generated assessment.
2. Retrieve the corresponding ground-truth label.
3. Compare the predicted classification with the actual classification.
4. Record correct and incorrect predictions.
5. Calculate appropriate performance metrics.
6. Store evaluation results.

### Initial Metrics

* Accuracy.
* Precision.
* Recall.
* F1-score.
* False-positive rate.
* False-negative rate.
* Classification confusion matrix.

### Additional Evaluation

Where the dataset provides suitable labels, evaluate severity classification separately.

### Important Requirements

* Never modify original ground-truth labels.
* Exclude records without usable ground truth from supervised accuracy calculations.
* Record incorrect AI predictions.
* Preserve the reason for evaluation failure where available.
* Distinguish unavailable predictions from incorrect predictions.
* Ensure metrics can be reproduced.

The evaluation engine must clearly distinguish classification accuracy from severity-assessment accuracy.

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

**Database:** SQLite.

The database should remain lightweight and manageable on an 8 GB RAM system.

The following are proposed logical entities, not finalized SQL schemas.

| Entity          | Responsibility                            |
| --------------- | ----------------------------------------- |
| Alerts          | Store normalized security alerts          |
| Indicators      | Store extracted IPs, domains and hashes   |
| Enrichments     | Store threat intelligence lookup results  |
| Incidents       | Represent correlated investigation groups |
| Timeline Events | Store chronological incident events       |
| AI Assessments  | Store AI-generated triage results         |
| Ground Truth    | Preserve independent reference labels     |
| Evaluations     | Store comparison results and metrics      |

### Database Requirements

* Use stable internal identifiers.
* Maintain relationships between records.
* Preserve original dataset references.
* Store timestamps consistently.
* Avoid duplicating enrichment results unnecessarily.
* Support reproducible evaluation.

The final schema should be defined during database implementation.

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

**Final architectural principle:**

TriageLens should not simply tell an analyst what an AI thinks about an alert. It should provide the evidence, explain the reasoning available, preserve the investigation trail, and demonstrate how reliably its AI performs against known outcomes.
