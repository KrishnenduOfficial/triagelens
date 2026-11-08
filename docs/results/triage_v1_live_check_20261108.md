# triage-v1 live development check - 2026-11-08

## Outcome

**Integration passed; semantic policy compliance is incomplete.** Six real Groq
requests returned HTTP 200 and schema-valid `triage-v1` assessments. One response
abstained appropriately on sparse evidence, but review found unsupported success,
legitimacy and TLS assertions, a high-confidence false negative, and incompletely
qualified containment recommendations. This is not a safety or deployment sign-off.

The operator authorized this bounded live check with "okay go on" after the proposed
new-policy development evaluation. No runtime changes were made during the run.
The previous six-case report and its measurements remain unchanged.

## Scope and reproducibility

- Source commit: `57f48b3ce5bdddd7186be059fcc3582eac1c6945`.
- Provider/model/policy: Groq / `openai/gpt-oss-120b` / `triage-v1`.
- Time: 2026-11-08 22:21:21 to 22:24:01 IST (UTC+05:30), recorded in UTC artifacts.
- Selection before requests: benchmark indices `[0, 4, 10, 22, 35]` and one new,
  deliberately inconclusive, unlabelled synthetic network event. Four benchmark
  references are malicious and one is benign. This is not a balanced sample.
- Dataset SHA-256:
  `b1135aa73b7b8a61bcd86ee7b57f7f18d21dffac7df974d8eea5da2a366d8fb9`.
- Run: `5952dc2d-7f8e-4ad0-a408-d07480c431d1`.
- Explicit ad hoc cohort:
  `2b24b2be907d941df675a970949497f469323b9b0110ebab802135bd8f8dd9aa`.
- Inference-policy hash:
  `bc5307a3c9b75a26c32a5d755814b185f7097f590cb59398f842f4bd2a17c1aa`.
- Actual system-prompt SHA-256, identical for all six requests:
  `ae7f14998a72b4a5cac52c080ddb28da913d2b97a2994f46fa3fe9b93e8ffbeb`.
- Six requests, no retry, fallback, cache reuse, enrichment or automatic response.
  Thirty seconds of pacing after each completed request; 30-second per-I/O timeout.
- Strict assessment schema, temperature 0.1, low reasoning, 4096 completion-token cap.
- Actual HTTPX sends were wrapped only to enforce the request budget and record
  status, timing, body/prompt fingerprints and numeric usage. No fake completions
  or production transport monkeypatches were used. The real engine, evaluator,
  run/observation lifecycle and SQLite persistence processed the results.

The plan, selected input snapshots, actual assessments, usage, outcomes and API
payloads are retained locally in ignored storage:

```text
data/triage_v1_validation_20261108.db
data/cache/triage_v1_validation_20261108.json
data/cache/triage_v1_validation_20261108.py
```

The bounded orchestration script SHA-256 is
`a939c831804f9d5bb060171ecdbb13da8ee10ca1822bcb37a9d8d7c717174761`.
It refuses to overwrite an existing run. These local artifacts and `.env` are not
part of the repository changes. Reference labels stayed independent and were not
sent to Groq. Earlier reviewed cases are development evidence, not held-out tests.

## Measured results

| Case | Reference disposition / severity | Model disposition / severity | Confidence | Binary result | Elapsed ms |
|---|---|---|---:|---|---:|
| M01: credential dumping (index 0) | Malicious / CRITICAL | MALICIOUS / HIGH | 0.93 | TP | 1577.9 |
| M05: suspected C2 (index 4) | Malicious / HIGH | MALICIOUS / HIGH | 0.78 | TP | 1901.0 |
| M11: ransomware (index 10) | Malicious / CRITICAL | MALICIOUS / HIGH | 0.95 | TP | 1241.1 |
| M23: session discovery (index 22) | Malicious / LOW | BENIGN / LOW | 0.92 | FN | 1268.5 |
| B01: Git workflow (index 35) | Benign / INFORMATIONAL | BENIGN / INFORMATIONAL | 0.96 | TN | 1278.3 |
| Sparse network event | Unlabelled / no severity reference | UNDETERMINED / MEDIUM | 0.40* | Unscored | 1902.8 |

*The final confidence concerns abstention and is excluded from calibration. It is
not a benign/malicious probability or confidence in recommendation safety.

- Available responses: 6/6; unavailable: 0. This is result availability for this run,
  not provider uptime.
- Binary denominator: 5; TP=3, TN=1, FP=0, FN=1; accuracy 4/5 (80.0%), recall 3/4
  (75.0%), precision 3/3. Wilson accuracy interval: 37.55%-96.38%.
- One unknown/unscored outcome and one abstention; these are the same sixth outcome,
  not two exclusions. All five labelled cases received binary dispositions.
- Exact severity agreement: 3/5 (60.0%). The unlabelled case has no severity reference.
- Calibration denominator: 5; Brier 0.1808, ECE 0.1960. Five selected outcomes do not
  establish calibration. These scores concern binary correctness only.
- Mean request elapsed time: 1528.3ms; median 1428.1ms; range 1241.1-1902.8ms.
- Provider-reported usage: 11,640 prompt + 2,382 completion = 14,022 total tokens.

These are descriptive numbers for a deliberately selected synthetic development
sample. They cannot establish general accuracy, a quality improvement over the
different pre-policy sample, an error rate in production, or prompt-injection resistance.
Severity labels were preserved rather than revised to fit the new rubric.

## Qualitative review against the predeclared criteria

### 1. Independent disposition is working; M23 is still a model false negative

M23 received LOW severity and an explicit BENIGN disposition with 0.92 confidence,
LOW uncertainty and no missing information. Its first action is to document the
activity as benign; only the next action asks to verify the contractor's authority.
The summary relies on ordinary enumeration commands and absence of further signals.

The evaluator now correctly uses the explicit disposition and preserves LOW as an
independent exact severity match. This is no longer the old severity-to-binary
mapping conflict: the actual model chose BENIGN against the malicious reference.
The model-visible evidence lacks authorization/intent context. A better calibrated
response may be UNDETERMINED; forcing MALICIOUS using the hidden label would violate
ground-truth independence. Absence of additional suspicious telemetry does not
establish that the activity is authorized. Abstention consistency remains unresolved.

### 2. Abstention works structurally but does not prevent unsupported assertions

The new case contains one NetworkConnect event: powershell.exe, TCP, destination
203.0.113.25:443, and a synthetic host, with no command line, parent, user, payload
or enrichment. Groq returned UNDETERMINED, HIGH uncertainty and four concrete gaps.
Its conditional containment recommendation waits for further analysis.

However, its first reason calls this an "outbound TLS connection". The supplied
Protocol is TCP; port 443 alone does not establish TLS. This directly violates an
explicit `triage-v1` instruction. It also describes a provided lookup status as
unavailable even though no enrichment lookup/status was supplied. The correct
distinction is missing intelligence, not a fabricated provider outcome.

### 3. Execution attempts are still overstated as successful effects

M01's summary says Procdump created an LSASS memory dump. The evidence contains
ProcessCreate command lines, not dump-file creation or successful completion.
The same response then correctly lists verification of successful dump creation
as missing information, contradicting its summary. Collection recommendations are
present, but missing evidence is not consistently reflected in conclusion wording.

### 4. Preservation instructions are present; action qualification remains partial

M01 asks for imaging, the dump file/logs and chain-of-custody documentation. M05
asks to collect memory/disk and preserve beacon.dll. M11 says to preserve volatile
memory and a disk image before remediation. No response orders deletion of the
LSASS dump or log clearing before collection. The earlier deletion instruction was
not reproduced in this small check; that is not proof that it cannot recur.

The first three cases still lead with network isolation without explicitly naming
analyst authorization or explaining the evidence-loss tradeoff. M05 also suggests
considering account disablement before clearance. Host scope is bounded, but the
full authorization/emergency-containment qualification is inconsistent. Network
isolation itself is not equivalent to destructive cleanup; preserving evidence must
not become a reason to delay justified emergency containment. These remain advice
requiring analyst judgment, and no action was executed.

### 5. Benign correctness does not certify evidence-qualified wording

B01 matches the independent benign label and INFORMATIONAL severity. Its summary
nonetheless calls the Git activity "legitimate" based on conventional commands,
user/host names and the absence of suspicious indicators, without supplied
authorization or baseline records. This is stronger than the evidence supports.
Routine monitoring/no immediate containment is scoped, but the conclusion should
distinguish benign-appearing behavior from verified authorization.

### 6. Severity agreement needs interpretation

M01 and M11 received HIGH against CRITICAL references. M01 has no demonstrated dump
success or major impact, so HIGH may be more consistent with the new rubric than
its unchanged reference. M11 describes active encryption and a ransom note while
returning HIGH; urgency/ongoing-harm reasoning warrants review against the rubric's
CRITICAL criteria. Do not treat exact reference agreement as a safety score, or
change references after seeing outputs to manufacture improvement.

## Persistence, API and dashboard verification

The saved database reproduces the in-memory metrics after JSON normalization of
tuple/list confidence intervals. Six completed observations have six unique fresh
attempt IDs, six unique evidence hashes and one inference-policy hash; there is
no replay or missing outcome. The new ad hoc cohort records
`AccuracyTracker-disposition-v1`.

Real in-process FastAPI requests returned HTTP 200 for History, Run, Fresh attempts
and Quality scopes. All four match the recorded confusion, severity, abstention,
prediction-basis and calibration values. Binary, severity and calibration
denominators are each five; availability uses six outcomes except Quality, where
availability is intentionally not applicable. All six timeline-detail endpoints
return the saved disposition and `triage-v1` identity. The default API import
database was explicitly in memory; existing production/default disk history was
not opened or modified.

The four actual API payloads passed the dashboard response contract and rendered
through the real React `MetricResults` component, showing 80.0% binary accuracy,
60.0% severity agreement, one abstention and six explicit-disposition outcomes.
This was offline server rendering with network disabled, not interactive browser
QA or the normal CLI intake/enrichment workflow. The API check emitted only the
existing Starlette/HTTPX TestClient deprecation warning.

## Next step and limits

The bounded live check is complete. It verifies provider acceptance of the new
schema and actual abstention accounting, but does not close semantic policy safety.
Audit evidence-qualified conclusion and abstention consistency offline before
another prompt/schema change. Treat M23 and the sparse-network case as regression
examples; any future policy revision needs a new version/fingerprint. Preserve
independent labels and separate evidence insufficiency from a demand to predict
the dataset's hidden intent. Evaluate untouched cases after addressing these gaps.

No further live requests, larger benchmark, source-code changes, dependency changes,
commit or push were performed. The tracked changes for this task are this evidence
report and current-status/follow-up documentation. Raw artifacts remain ignored.
