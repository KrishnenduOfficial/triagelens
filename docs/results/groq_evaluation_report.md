# Groq six-case synthetic evaluation - 2026-11-08

## Scope and reproducibility

This is an actual agent-executed live evaluation authorized by the user's "go on",
following the agreed small balanced sample. It is a functional and initial quality
check, not an unbiased or real-world benchmark. Reference labels predate the run
and stayed separate from model predictions.

- Provider/model: Groq / `openai/gpt-oss-120b`.
- Time: 2026-11-08 21:23:49 to 21:26:27 IST (UTC+05:30).
- Source: `data/eval_benchmark_70.json`; zero-based indices `[0, 4, 10, 35, 39, 45]`.
- Selection, made before outputs: credential dumping, C2, ransomware, Git workflow,
  Windows Update and backup; three malicious and three benign cases.
- Dataset SHA-256: `b1135aa73b7b8a61bcd86ee7b57f7f18d21dffac7df974d8eea5da2a366d8fb9`.
- Run ID: `6942654e-55ba-4efc-ab19-6538cc4035e1`.
- Inference-policy hash: `25c55bd8b22eac89f39c343a23f32e2777482a24d7b17038aea347c534fe7e9d`.
- Six requests, no cache, retry, fallback or intelligence calls; 30-second spacing
  after completed requests and a 30-second per-I/O timeout.
- Generation: strict schema, temperature 0.1, low reasoning, completion cap 4096.

The normal engine, evaluator and run/observation persistence were used by a bounded
subset orchestration. No production code was patched or model outputs replaced.
It would stop on the first unavailable result; no such stop occurred.

## Per-case observations

| Index | Scenario | Reference severity | Groq severity | Binary outcome | Confidence | Elapsed ms |
|---|---|---|---|---|---|---|
| 0 | M01 Credential dumping / Mimikatz | CRITICAL | HIGH | True Positive | 0.92 | 1738.8 |
| 4 | M05 C2 / Cobalt Strike | HIGH | HIGH | True Positive | 0.85 | 1296.2 |
| 10 | M11 Ransomware / mass encryption | CRITICAL | HIGH | True Positive | 0.92 | 1203.5 |
| 35 | B01 Git workflow | INFORMATIONAL | LOW | True Negative | 0.78 | 1054.4 |
| 39 | B05 Windows Update | INFORMATIONAL | LOW | True Negative | 0.60 | 1008.6 |
| 45 | B11 Veeam backup | INFORMATIONAL | LOW | True Negative | 0.65 | 1133.6 |

Reference severities are author-assigned synthetic labels, not adjudicated real
incidents. The evaluator maps MEDIUM/HIGH/CRITICAL to malicious and LOW/INFORMATIONAL
to benign. Exact severity mismatch is distinct from a binary false negative.

## Aggregate results

| Measure | Observed result / denominator |
|---|---|
| Schema-valid availability | 6/6 fresh attempts |
| Binary accuracy | 6/6 labelled cases |
| Confusion counts | TP=3, TN=3, FP=0, FN=0 |
| Exact severity agreement | 1/6 (16.7%) |
| Precision / recall / specificity | 3/3 each |
| Evaluator's accuracy Wilson interval | 60.97%-100% |
| Evaluator's precision/recall Wilson interval | 43.85%-100% |
| Brier score | 0.0610 over six predictions |
| Expected calibration error | 0.2133; five bins, only two occupied |
| Latency | Mean 1239.2ms; median 1168.55ms; range 1008.6-1738.8ms |
| Provider-reported usage | 7,122 prompt + 1,709 completion = 8,831 tokens |

Intervals describe the existing evaluator's calculation, not established population
performance: this sample was purposively selected and synthetic. Six successful
paced calls do not establish uptime or sustained-load performance. Calibration is
unstable at this size. Repeated history rows must not be pooled as independent cases.

## Explanation and recommendation review

- Credential dumping: HIGH versus CRITICAL. The response recommended deleting the
  LSASS dump without specifying evidence preservation first. This must not become
  an automatic action; collection, authorization and preservation precede cleanup.
- C2: HIGH matched HIGH. TCP port 443 was described as TLS, which the supplied
  evidence alone does not establish. The user was called low-privilege without
  privilege telemetry. Missing reputation was correctly identified as a gap,
  although no actual intelligence lookup was performed.
- Ransomware: HIGH versus CRITICAL. Reasoning cited supplied `.locked` and ransom-note
  indicators. Full `Path` fields were excluded by the current allowlist; evidence
  normalization merits a separate audit.
- All benign cases were LOW versus INFORMATIONAL. Some summaries described accounts
  or hosts as known and activity as legitimate without independent baseline or
  authorization evidence. These remain hypotheses for analyst review.
- Missing-information lists were nonempty for malicious cases but empty for benign
  cases despite unverified authorization/baseline context. Severity criteria and
  evidence-qualified language need review. Injection resistance was not tested.

These findings do not prove that every reference severity is preferable to the
model's severity. A shared rubric is needed. No prompt, reference label, policy,
allowlist or recommendation was silently changed during this evaluation.

## Persistence, API and dashboard verification

Isolated ignored database: `data/groq_validation_20261108.db`.
Ignored raw verdict/usage/API artifact: `data/cache/groq_validation_20261108.json`.
The six outcomes were not inserted into normal dashboard evaluation history.
Importing the API also initialized its default database schema, as that module
normally does; the six outcomes were written only to the isolated database.

The run is completed: six completed observations, six unique fresh attempt IDs,
six unique evidence hashes, no replay and no missing outcomes. Real in-process API
requests returned HTTP 200 for History, explicit Run and explicit Fresh attempts;
their confusion and availability totals match the evaluator. All six timeline-detail
endpoints returned the expected model's saved verdict.

The three actual API payloads passed the dashboard response contract and rendered
through the real React MetricResults component with 100.0% binary accuracy and
16.7% severity agreement. This was offline server rendering, not interactive browser
QA. This already-correlated subset did not exercise normal CLI intake/enrichment.

For manual review, start a separate backend with
`DATABASE_PATH=data/groq_validation_20261108.db` and select Run or Fresh attempts
using the ID above. Restart when switching databases; a CLI path does not reconfigure
an existing API process. Do not merge or delete historical databases.

## Next step

Audit severity criteria, evidence-qualified assertions and preservation-first
recommendations offline before changing prompts or running a larger benchmark.
Evaluate future changes against untouched cases. Full CLI/browser workflow and
prompt-injection evaluation remain pending. No commit or push was performed.
