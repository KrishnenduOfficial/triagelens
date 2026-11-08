# Offline severity criteria and recommendation safety audit - 2026-11-08

**Follow-up:** The original audit below is a historical snapshot. The operator
subsequently approved the contract and implementation in ADR-056; see
[implementation and verification](#approved-implementation-and-verification).
The original findings and six-case measurements have not been rewritten.

## Outcome and scope

**Result: policy/contract gaps reproduced; implementation not changed.** No API
calls, model reruns, database writes or reference-label changes were made. The
six saved Groq results were recomputed in memory and their scores reproduced.

The strongest finding is a conflict between an existing reference label and the
severity-derived binary scoring rule. The other main findings are an undefined
severity rubric and absent preservation/evidence-qualification instructions.
Valid JSON is not a semantic safety guarantee.

Sources inspected: `src/engine/llm.py`, `src/engine/groq.py`,
`src/engine/evaluation.py`, `src/models/triage.py`, `src/models/evaluation.py`,
`scripts/generate_eval_dataset.py`, the existing benchmark, saved six-case results,
`dashboard/src/pages/TimelineView.tsx`, and related regression tests/decisions.
This is a project-local audit, not a claim of compliance with an external standard.

## Findings

### 1. High: binary disposition and severity have a contradictory reference case

`AccuracyTracker.evaluate` maps CRITICAL/HIGH/MEDIUM to malicious and
LOW/INFORMATIONAL to benign (ADR-022). The benchmark has this reference case:

```text
index: 22
scenario: attack_scenario_M23-Discovery-SessionRecon
reference binary: malicious
reference severity: LOW
```

An offline verdict matching LOW exactly produced:

```json
{"category":"False Negative","severity_correct":true,"binary_correct":false}
```

Thus this case cannot achieve both correct binary classification and exact severity
under the current contract. This is not an arithmetic error: the evaluator faithfully
applies the existing rule. The cross-component policy/reference contract conflicts.
Severity represents priority/impact, while maliciousness can exist at low priority.

Full benchmark distribution, measured without changing it:

| Binary reference | Severity references |
|---|---|
| Malicious, 35 | 9 CRITICAL, 20 HIGH, 5 MEDIUM, 1 LOW |
| Benign, 35 | 35 INFORMATIONAL |

No benign LOW reference exists. This helps explain why all three benign LOW answers
in the six-case run were binary-correct yet severity-mismatched. It does not prove
those answers are preferable to INFORMATIONAL.

**Proposed direction, not implemented:** decide whether to introduce an explicit
model disposition separate from severity. That requires a schema/evaluator/provenance
design and legacy compatibility, not a threshold tweak. Preserve old scores and
labels. Any adjudicated dataset revision needs a new manifest/hash; never alter a
reference solely to make the model or metric look better.

### 2. High: preservation and authorization are absent from the model policy

`DFIR_SYSTEM_PROMPT` specifies the JSON shape, evidence isolation and unavailable
intelligence handling. It gives no preservation-before-cleanup rule, response-action
authorization rule, or containment-versus-acquisition tradeoff instruction.

The saved credential-dumping response recommended deleting the LSASS dump without
specifying preservation first. An injected offline completion recommending deletion
of the dump and logs before collection also passed `GroqAssessment` validation and
the full engine, returning a verdict.

Recommendations are stored as strings and rendered by React. No recommendation
executor, shell invocation or action button consuming them was found. Human-review
messaging already exists. This finding concerns advice quality, not demonstrated
automatic destructive execution or code execution.

**Proposed direction:** require evidence preservation and explicit analyst approval
before destructive cleanup. Emergency containment of observed ongoing harm may
precede full collection when justified; state the tradeoff rather than universally
delaying containment. Do not promise that a prompt or keyword blacklist makes all
recommendations safe.

### 3. Medium: no shared operational severity rubric

The system prompt enumerates five labels but supplies no definitions, impact criteria,
evidence thresholds or LOW/INFORMATIONAL distinction. The generator assigns labels
in scenario tuples; the evaluator takes the highest recognized reference severity
in each timeline and measures exact equality. Neither defines a shared rubric.

All six live scores recomputed correctly: TP=3, TN=3, FP=0, FN=0; severity matches
1/6. The five mismatches are two HIGH versus CRITICAL and three LOW versus
INFORMATIONAL. They cannot all be called model mistakes without adjudicated criteria.

**Draft for design discussion only:**

| Label | Proposed priority meaning |
|---|---|
| CRITICAL | Evidence supports immediate major impact or ongoing destructive harm requiring urgent response |
| HIGH | Credible serious malicious behavior or exposure requiring prompt analyst response |
| MEDIUM | Security-relevant behavior needing investigation, with limited demonstrated impact/urgency |
| LOW | Low-priority security concern or limited-impact deviation requiring routine follow-up |
| INFORMATIONAL | Observed activity without an evidenced additional response priority |

These are proposed starting points, not implemented or authoritative definitions.
They deliberately do not define binary maliciousness. Business impact, scope and
evidence requirements must be agreed before adopting them. Unknown authorization
is not proof of either benignness or maliciousness. Uncertainty remains a separate
dimension; it should not automatically raise or lower severity.

### 4. Medium: evidence qualification is underspecified and unenforced

Strict output validation checks fields, types, enum values and confidence range.
It does not compare assertions with supplied evidence or require missing context.

The saved C2 response inferred TLS from TCP/443 and called a user low-privilege
without privilege telemetry. Benign summaries described activity/accounts/hosts as
legitimate or known without an independently supplied authorization baseline.
An offline response asserting confirmed TLS exfiltration and an unprivileged user
from only TCP/443 and a username passed the full engine.

**Proposed direction:** separate observations, hypotheses and unknowns in the prompt;
require evidence-qualified wording, prohibit unsupported success/privilege/protocol
claims, and disclose missing authorization/context. Preserve current unavailable-
intelligence handling. Stronger machine-checkable evidence/action fields would be
a separate schema design; free-text plausibility cannot be guaranteed by types.

### 5. Medium: support/action completeness is not defined

`reasoning`, `missing_information` and `recommended_actions` are unrestricted string
lists. Offline probes with empty reasoning/actions, and with blank entries, passed
the schema and full engine. The current contract requires the fields, not useful
content. Empty missing-information lists are also permitted for sparse benign cases.

Decide which empty lists are legitimate before tightening validation. Meaningful
reasoning should be required; if no action is warranted, the policy should express
that explicitly without manufacturing work. Nonblank/minimum-item checks enforce
structure only, not correct or safe recommendations.

### 6. Interpretation limit: calibration concerns binary correctness

`AccuracyTracker` stores `(confidence_score, is_correct)` for known binary outcomes.
Brier and ECE therefore concern confidence in binary correctness, not exact severity
or recommendation safety. The prompt describes a numeric confidence without making
that target explicit. A confidence of 0.92 can accompany a severity mismatch while
still contributing as a correct binary prediction.

The saved scores reproduce as Brier 0.0610 and ECE 0.2133. They do not counter the
1/6 severity agreement, and six selected cases do not establish calibration.
Clarify the confidence target before treating these values as operational assurance.

### 7. Separate evidence-normalization follow-up

The ransomware case's `Path` roots are excluded by the allowlist, although `.locked`
and ransom-note indicators survive. This is not evidence that the model invented
those indicators. An alias/field-normalization audit is warranted separately;
expanding a telemetry allowlist must retain recursive label/provenance isolation.

## Offline verification

Four distinct synthetic completion probes, each using an explicitly injected sender
and a fake credential, were accepted by both schema and engine:

1. Destructive cleanup ordered before collection.
2. Unsupported TLS/exfiltration/privilege claims.
3. Empty supporting reasoning and actions.
4. Blank reasoning and action entries.

These were four local synthetic responses, not live Groq generations. Their
acceptance demonstrates the current checks' limits, not a model-generation rate.
The M23 conflict was reproduced by constructing an exact-reference LOW verdict and
calling the real evaluator. All six saved live outcomes were independently rescored.

Existing relevant regression command:

```text
python -B -m pytest tests/test_groq.py tests/test_evaluation_adversarial.py tests/test_severity_persistence.py tests/test_prompt_isolation.py tests/test_verdict_cache_validity.py -q -p no:cacheprovider --tb=short
159 passed, 1 warning in 10.87s
```

The warning is the existing Starlette/HTTPX deprecation. Network guards stayed
unchanged and the default test database was in memory. No permanent new tests,
production source changes, dependency changes or real API requests were added.

## Recommended implementation order - requires a separate implementation task

1. Agree the severity/disposition contract and confidence meaning. Preserve legacy
   severity-derived metrics with explicit interpretation rather than reinterpreting
   stored outcomes. Do not silently revise M23 or other reference labels.
2. Adopt a versioned severity rubric and preservation-first, analyst-authorized,
   evidence-qualified recommendation policy. Define emergency containment exceptions.
3. Agree useful-content requirements, then add offline regression cases for weak
   evidence, action ordering, empty text, uncertainty and prompt injection. Avoid
   brittle checks claiming that dangerous-word absence proves semantic safety.
4. Verify the exact sent system prompt and generation policy enter cache fingerprints.
   The current Groq module imports the prompt by value while the shared cache builder
   references the base module's prompt; a future policy refactor should use one
   canonical source and test actual request/cache consistency. No existing live
   result is attributed to that implementation risk by this audit.
5. Keep the six reviewed cases as development evidence. Evaluate later changes on
   untouched cases under a new inference-policy/cohort identity; preserve prior
   results, reference labels and history counting.

No fix, benchmark rerun, commit or push was performed by this audit.

## Approved implementation and verification

The operator approved independent disposition, the confidence target and legacy
compatibility, then authorized the versioned rubric and preservation-first,
evidence-qualified recommendation policy. Implementation is `triage-v1` in
[`triage_policy.py`](../../src/engine/triage_policy.py), recorded in ADR-056.

| Field | New contract |
|---|---|
| Disposition | MALICIOUS or BENIGN only when supported; otherwise UNDETERMINED |
| Severity | Five-level response priority based on observed impact, scope and urgency; independent of disposition |
| Confidence | Correctness of the binary disposition; abstention confidence excluded from calibration |
| UNDETERMINED | HIGH uncertainty and at least one nonblank gap; available, unscored for binary/calibration |
| Policy identity | Application-owned `triage-v1`, stored outside the eight-field model response |
| Legacy | Original categories, counts, labels and confidence snapshots retained; absent metadata stays null |

New binary scoring no longer derives maliciousness from severity. M23 can be a
true positive and an exact LOW severity match at once. This is verified with an
injected offline assessment, not a new Groq generation or a changed reference label.
Re-evaluating a legacy verdict retains its original severity proxy, explicitly
recorded as such; existing snapshots without that metadata remain unrecorded.
Severity scoring remains independent and can include abstained binary outcomes.
History/replay units and default scope are unchanged.

The policy distinguishes observations, hypotheses and gaps; command execution
does not establish success, TCP/443 does not establish TLS/exfiltration, and a
username does not establish privilege. Missing authorization/intelligence does
not prove either disposition. It requires authorized analyst review and evidence
preservation before deletion, log clearing or other destructive cleanup.
Emergency containment can precede full acquisition when observed ongoing harm
justifies it, with supported scope, urgency and volatile-evidence tradeoffs.
No automatic execution or indiscriminate remediation is introduced.

Local validation rejects blank summaries/list entries, empty reasons/actions,
missing/invalid disposition and model-authored policy identity. Abstention requires
HIGH uncertainty and a nonblank gap. Empty gaps are still allowed for other
dispositions. Structural validation deliberately does not claim to certify factual
support, action ordering or semantic safety: an offline regression demonstrates
that unsafe but structurally valid free text still needs human review. No brittle
dangerous-word filter is presented as a safety proof.

The exact captured system prompt feeds both actual transport and cache hashing;
policy identity is also hashed. Tests exercise changed prompt and changed policy
identity, persistent refresh followed by verified replay, and retained old history.
New assessment metadata is recursively excluded from model-visible evidence.
Additive nullable database migrations preserve old rows and terminal outcome hashes;
repeat finalization remains idempotent. API Run, Attempts and Quality scopes retain
new metadata and abstention semantics. New cohorts record the disposition evaluator
and reject selection under an incompatible legacy evaluator declaration.

Dashboard verdicts show disposition/policy and clarify confidence; recommendations
carry an analyst-review/preservation warning. Metrics, CLI summaries and generated
reports disclose abstention and prediction-basis counts. The comparison report also
handles undefined specificity/FPR deltas without crashing when abstention leaves
no scored negative references.

### Files changed by the audit and approved implementation

- Policy and inference: `src/engine/triage_policy.py` (new), `llm.py`, `groq.py`.
- Models/scoring/storage: `src/models/triage.py`, `src/models/evaluation.py`,
  `src/engine/evaluation.py`, `database.py`, `provenance.py`, `metric_scopes.py`.
- Operator output: `src/cli.py`, `scripts/run_evaluation.py`, `scripts/compare_models.py`.
- Dashboard: `dashboard/src/api/apiService.ts`,
  `dashboard/src/components/MetricsOverview.tsx`, `dashboard/src/pages/TimelineView.tsx`.
- Tests: `tests/test_triage_policy.py` (new), `tests/conftest.py`,
  `tests/test_groq.py`, `tests/test_unavailable_persistence.py`,
  `dashboard/tests/metrics.test.mjs`.
- Documentation: `AGENTS.md`, `ARCHITECTURE.md`, `DECISIONS.md`, `README.md`,
  `TASKS.md`, this audit/implementation record and a follow-up notice in
  `docs/results/groq_evaluation_report.md`.

### Executed verification

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
652 passed, 1 warning in 40.08s

cd dashboard
npm test
49 passed, 0 failed
npm run build
TypeScript and Vite production build passed
```

Backend runs used `DATABASE_PATH=:memory:` for default application initialization;
database regressions used temporary isolated files. Existing network guards were
unchanged. The one warning is the existing Starlette/HTTPX TestClient deprecation.
The 33 new backend cases include actual Groq transport with injected completions,
report generation and persisted API comparisons, not live model quality tests.
The benchmark SHA-256 remains
`b1135aa73b7b8a61bcd86ee7b57f7f18d21dffac7df974d8eea5da2a366d8fb9`.
Local Markdown links and diff whitespace checks passed.

To reproduce offline tests, set `DATABASE_PATH=:memory:` in the shell, run pytest
with the existing virtual environment, then restore the previous setting. Do not
change `.env` or use a production database for regression testing.

### Limits and next verification

No live API requests, production database changes, new dependencies, reference-label
edits, commit or push were made. The six-case live report remains pre-policy
development evidence. Schema/provider acceptance and actual new-policy reasoning
quality still require a bounded live check, followed by untouched-case evaluation
under a new inference-policy/cohort identity. Injection resistance, normal manual
CLI workflow and interactive dashboard QA remain separate pending checks.
