# Offline evidence-qualification and abstention audit - 2026-11-08

Follow-up: the operator requested contract agreement before implementation.
[ADR-057](../../DECISIONS.md#adr-057-versioned-evidence-basis-contract-and-visible-uncertainty)
records the accepted `triage-v2` / `evidence-basis-v1` contract and display states.
The operator subsequently authorized offline implementation, now verified below in
[the implementation follow-up](#adr-057-offline-implementation-follow-up).
The original audit and proposals remain historical evidence.

## Result and scope

**Original audit result: semantic contract gaps reproduced; no runtime fix was
part of that audit.** The six saved
`triage-v1` responses still pass the real engine's structural validation. Their
generated request bodies match the original recorded fingerprints, including the
system instructions. The original binary/severity/calibration metrics reproduce.
The failures are not explained by an omitted policy or the old severity proxy.

This audit used saved synthetic data, fake credentials and injected completions.
Explicit HTTPX/socket denial recorded zero network attempts. No real API calls,
production database writes, reference-label edits, policy changes or live reruns
were made. This is project-local contract review, not external-standard compliance
or a measurement of how often Groq will generate these failures.

Source commit: `9a81aa8d1fca30253f829510ce0fe2dfec8cc0a7`.
Saved live run: `5952dc2d-7f8e-4ad0-a408-d07480c431d1`.
Evidence: [triage-v1 live development check](triage_v1_live_check_20261108.md).

Inspected paths include the [policy](../../src/engine/triage_policy.py),
[shared prompt/evidence pipeline](../../src/engine/llm.py),
[Groq schema/validator](../../src/engine/groq.py),
[verdict model](../../src/models/triage.py),
[evaluator](../../src/engine/evaluation.py),
[timeline presentation](../../dashboard/src/pages/TimelineView.tsx),
[frontend verdict type](../../dashboard/src/api/apiService.ts), and policy,
isolation, cache, evaluation and metric-scope regressions.

## Findings

### 1. High: evidence qualifications are instructions, not an enforced claim contract

`triage_policy.py` already explicitly forbids treating a command invocation as
success, TCP/443 as proof of TLS, and ordinary names/commands as verified
authorization. It also requires observations, hypotheses and gaps to be separated.
The schema in `GroqAssessment` represents those concepts as free-text summary and
string lists, without claim types, evidence references or a recorded decision basis.
`_validate_assessment` applies types, ranges, nonblank content and one abstention
cross-field rule; it does not check evidential support or contradictions in prose.

| Saved case | Supplied evidence | Accepted conclusion | Assessment |
|---|---|---|---|
| M01 | ProcessCreate command lines for credential-dumping tools | Summary says Procdump created a dump, while gaps ask whether it was successfully written | Success is unsupported and contradicts the response's own gap |
| Sparse network | NetworkConnect, Protocol TCP, destination port 443; no enrichment | Reason calls it an outbound TLS connection; a gap describes lookup_status as unavailable | TLS and a specific lookup outcome are not supplied facts |
| B01 | Conventional Git commands and user/host strings | Summary calls operations legitimate; gaps are empty | Binary reference matches, but verified authorization/baseline is not established |

The six request-body hashes were reproduced exactly offline, so the explicit
policy reached the wire contract. All six saved completions remained accepted.
Changing only prompt delivery or adding the same prohibitions again would not
address the missing machine-checkable relationships. Keyword matching would also
misclassify valid statements such as "TLS is unverified" or a hypothesis mentioning
TLS; absence of a keyword is not evidence of factual correctness.

### 2. High: the abstention rule is one-way and does not record sufficiency

`require_abstention_explanation` enforces:

```text
UNDETERMINED -> HIGH uncertainty and at least one nonblank gap
```

It does not establish the converse, identify a material unresolved decision gap,
or require a binary disposition to record the evidence that justifies it.
HIGH uncertainty is allowed with a binary answer; that is not automatically wrong,
but the current contract cannot distinguish a justified uncertain judgment from
a binary answer whose own reasoning admits that intent cannot be determined.

Five offline completion mutations on the same sparse-network evidence demonstrate
the structural boundary. They are injected probes, not new model generations:

| Probe | Result |
|---|---|
| Change the saved abstention to BENIGN; retain admitted missing context/HIGH uncertainty | Accepted |
| Change it to MALICIOUS without adding support | Accepted |
| Keep UNDETERMINED but replace all gaps with only `context` | Accepted |
| Keep UNDETERMINED and remove all gaps | Rejected |
| Keep UNDETERMINED and set uncertainty LOW | Rejected |

The last two rejections show that the implemented rule works. The first three
show its limits: nonblank text is not necessarily a concrete evidence gap, and
disposition/evidence consistency is not represented structurally.

M23 is the observed behavioral example. Groq chose BENIGN with confidence 0.92,
LOW uncertainty and no gaps, then asked the analyst to verify authorization after
documenting the activity as benign. The absence of additional malicious indicators
was used as benign support without resolving the material intent/context question.

Do not repair this by requiring every unknown authorization to force UNDETERMINED.
Missing authorization alone establishes neither disposition; other supplied
evidence may independently justify a conclusion. Nor should every HIGH-uncertainty
answer be rejected. The missing contract is about material evidence sufficiency
and the basis for the selected disposition, not a universal confidence threshold.

### 3. Not reproduced: ground-truth leakage or an abstention accounting defect

M23's explicit BENIGN is a false negative against its existing malicious label;
LOW severity independently matches its reference. This is not the old evaluator
inferring benignness from LOW. An offline counterfactual changed only reference
labels while replaying the same completion:

| Reference binary | Outgoing model request | Prediction/category from evaluator |
|---|---|---|
| Malicious | Identical | BENIGN / False Negative |
| Benign | Identical | BENIGN / True Negative |
| Unknown | Identical | BENIGN / Unknown |

The full outgoing bodies were identical across these three probes. The saved
sample's metrics also reproduced: TP=3/TN=1/FP=0/FN=1 across five labelled cases,
one unlabelled abstention, severity 3/5, Brier 0.1808 and ECE 0.1960. UNDETERMINED
remains available and excluded from binary/calibration scoring. The six-way saved
sample is descriptive development evidence, not a population error estimate.

A hidden malicious label does not make intent observable in administrative command
lines. Do not relabel M23 or force its inference to MALICIOUS to improve a score.
An evidence-qualified abstention may be preferable on that limited input, but it
is unscored rather than a recovered true positive. Report coverage alongside
accuracy so that more abstentions cannot masquerade as an accuracy improvement.

### 4. Medium: the analyst view omits stored qualifications

The backend verdict model and database retain `uncertainty_level` and
`missing_information`; the timeline API returns the stored verdict dictionary.
However, the frontend `TriageVerdict` interface does not declare either field, and
`TimelineView.tsx` does not render either. It displays summary, reasoning, actions,
disposition/policy and a confidence label, with analyst-review and preservation
warnings. Those warnings are useful but do not reveal case-specific evidence gaps.

This is verified by code inspection, not interactive browser QA. It is a separate
presentation gap: it does not explain why Groq invented TLS, but it limits how
easily analysts can review uncertainty and contradictions. Confidence must not
become the most visible substitute for missing context.

### 5. Medium, separate follow-up: context projection depends on source shape

An isolated serializer probe added top-level `AuthorizationContext`, `TLSVersion`,
`Signed`, `ExitCode` and `Path`. All five are omitted by the current allowlist.
Putting the same values inside allowed `Details` retains them. The serializer is
consistent with its current rules, but there is no general normalization contract
for several useful forms of corroborating evidence.

These are synthetic field-shape probes, not examples of authorization/TLS evidence
that was present and lost in the saved live sample. The saved cases lack that
corroboration at source; this finding does not explain away their unsupported claims.
It also does not justify accepting an attacker-controlled `approved: true` as
trusted authorization. A later adapter/normalization audit should define canonical
observable fields and separately sourced, attributable analyst/authorization
context, preserving recursive label/provenance isolation and secret masking.
Do not broadly expand the allowlist as part of an inference-only fix.

### 6. Recommendation qualification remains related but distinct

The first three saved cases recommend isolation and collection. They do not order
dump deletion/log clearing before preservation, but do not consistently express
analyst authorization or emergency-containment evidence-loss tradeoffs. Existing
dashboard warnings do not rewrite or certify those action lists. This remains an
open recommendation-policy concern; network isolation should not be treated as
destructive cleanup, or preservation as a reason to delay justified urgent response.
It is not an abstention accounting failure.

## Proposed scoped next implementation - not approved or implemented by this audit

Adopt an additive, versioned **evidence-basis contract**, with the exact fields and
version agreed before implementation. A prompt-only retry or a dangerous-word
filter is not the proposed fix. A concrete design should include:

1. Application-generated local evidence references, tied only to the sanitized
   request's events/intelligence fields. Do not expose file/source labels, hidden
   reference classes or evaluation provenance as evidence identifiers.
2. A structured disposition basis distinguishing evidence supporting malicious
   behavior, evidence supporting benign activity, and insufficient evidence.
   Represent material unresolved gaps and supporting references separately from
   summary prose. Separate observed facts from hypotheses; neither ordinary binary
   names nor the absence of other alerts establishes verified legitimacy.
3. Deterministic consistency checks: referenced events/fields must exist; declared
   insufficient evidence requires UNDETERMINED/HIGH uncertainty with useful gap
   structure; binary dispositions require the corresponding declared support basis.
   Validate known relationships, and retain schema failures as unavailable outcomes.
   Do not silently coerce an unsupported answer into a successful abstention or
   claim semantic entailment merely because a model supplies a valid reference.
4. A concise prompt revision with paired observations/hypotheses and examples of
   attempt versus outcome, TCP versus verified TLS, not-performed versus failed
   intelligence lookups, and benign-appearing versus authorized activity. Use
   generic examples, not M23's hidden label. Improve disposition-basis and action
   wording together without manufacturing certainty or unnecessary remediation.
5. Display stored uncertainty and missing information beside verdict reasoning,
   with legacy unavailable fields explicitly unrecorded. Continue authorized
   analyst review and preservation/emergency-containment warnings.
6. Record a new policy/schema identity in requests, verdicts, cache contracts and
   evaluator/cohort metadata as required by the eventual design. Preserve old
   records and counters. If binary scoring rules themselves are unchanged, do not
   invent a new evaluator merely to relabel old outcomes; distinguish policy from
   scoring identity. No prior snapshot is upgraded to the new contract.

Structured support can be self-reported incorrectly. Existence/type/consistency
checks improve auditability but cannot certify an arbitrary natural-language claim
or safe action. Any unsupported-claim checker beyond those relationships needs a
separately specified, testable capability and honest limitations.

### Acceptance criteria for that implementation

- Contradictory basis/disposition combinations and nonexistent evidence references
  fail locally; control cases and correctly expressed hypotheses remain valid.
- Clear malicious evidence and supported benign evidence need not abstain merely
  because unrelated context is missing. Insufficient evidence is represented as
  such; no shortcut forces M23's hidden label.
- New fixtures cover attempts without outcome, TCP/443 without TLS evidence,
  absent versus unavailable lookups, authorization ambiguity and appropriately
  corroborated controls. Their offline expectations test the contract; they do not
  prove that live model prose will always comply.
- Ground-truth changes leave outgoing evidence unchanged. New fields do not create
  nested metadata leakage. New policy inputs invalidate cache reuse safely.
- New assessments preserve availability, abstention and calibration semantics;
  legacy history and repeat-finalization behavior remain intact.
- The actual analyst view shows uncertainty/gaps and differentiates legacy absence.
- Any later live evaluation declares cases and criteria first, uses a new policy
  identity, and reports binary coverage, abstentions and unknown labels alongside
  accuracy. Do not optimize a selective score by hiding difficult labelled cases.

The telemetry-normalization concern and the broader YARA/MITRE/PostgreSQL roadmap
remain separately scoped work. This audit does not defer or remove those phases.

## Executed offline verification

```text
python -B -m pytest tests/test_triage_policy.py tests/test_groq.py tests/test_prompt_isolation.py tests/test_evaluation_adversarial.py tests/test_metric_scopes.py tests/test_verdict_cache_validity.py tests/test_network_isolation.py -q -p no:cacheprovider --tb=short
228 passed, 1 warning in 12.91s
```

Default test database selection was `DATABASE_PATH=:memory:`; persistence tests
used temporary isolated databases. Existing HTTPX/socket pytest guards were not
changed. The one warning is the existing Starlette/HTTPX TestClient deprecation.

The additional audit script executed 14 local injected sends: six saved-response
replays, five completion mutations and three reference-label counterfactuals.
Network denial recorded zero attempts. Serializer shape checks required no sends.
The script and machine-readable output remain ignored in `data/cache/`:

```text
data/cache/evidence_abstention_audit_20261108.py
data/cache/evidence_abstention_audit_20261108.json
```

Script SHA-256:
`11c06928e6bc6fa229f457c79591bdb0e13846d75b803a7647e9aa913174fd00`.
Saved live artifact SHA-256, unchanged by this audit:
`209f0a6a0c33d3959ecf883cbe066114d3d997be566b3c129dae70b4bbd2b9a7`.
Benchmark SHA-256 remains
`b1135aa73b7b8a61bcd86ee7b57f7f18d21dffac7df974d8eea5da2a366d8fb9`.

At the audit stage, only this report and current-status notes were changed; no
permanent tests, runtime code or dependencies were added. No commit or push was
performed by that audit. The separately authorized implementation follows.

## ADR-057 offline implementation follow-up

**Implemented and verified offline:** active `triage-v2` / `evidence-basis-v1`.
This is structural enforcement and traceability, not a semantic safety sign-off.
No actual Groq request was made for this implementation. The earlier six live
assessments remain `triage-v1` development evidence and were not upgraded or rescored.

### Implemented behavior

- The ninth model-authored field is a strict evidence basis: decision support,
  observations, hypotheses and typed blocking/nonblocking gaps. The existing
  summary/reasoning/action fields remain readable, and accepted raw completions
  remain unchanged alongside normalized stored values.
- Generated E/I identifiers annotate only the final sanitized event/intelligence
  records after privacy filtering, secret masking and compact-summary budgeting.
  New metadata keys are recursively excluded from untrusted structured inputs.
  No absent intelligence lookup or status is invented by the application.
- References resolve only exact keys/indexes in captured sanitized records and
  must target non-null nonblank scalars. Duplicates, missing fields, invalid
  indexes, generated-ID support and references outside the request are rejected.
  Decision references must occur in observations. False and zero remain usable
  data values; arbitrary evaluation or external/source-data lookup is never used.
- Declared basis and disposition must agree. Binary answers need observations
  and decision references without blocking gaps. A blocking gap requires
  UNDETERMINED/HIGH; unrelated gaps do not force abstention. The top-level gap list
  must equal the structured descriptions. Inconsistency is unavailable, not a
  coerced abstention, repair or implicit retry.
- Three nullable verdict columns store `evidence_basis`, application-owned
  `evidence_context` and `evidence_contract_version`. Legacy values remain null.
  Stored evidence resolves citations independently of later source-record changes.
  New metadata enters cache/provenance identity and new terminal hashes; null new
  metadata is omitted from old terminal hash computation to preserve idempotency.
- Fresh output and cache return validate reference relationships. A cached snapshot
  must match current policy, contract and captured context, even if someone produces
  a matching cache-body fingerprint around a wrong context or older policy record.
  Existing History/replay counting, `explicit_disposition_v1` and
  `AccuracyTracker-disposition-v1` stay unchanged.
- The timeline API derives `missing_information_recorded` before null-to-empty
  normalization. The flag is presentation-only, not a verdict/evaluation field or
  database column. Invalid stored qualifications remain detectably invalid rather
  than becoming an assessed empty list.
- The real timeline page includes `VerdictQualifications` before summary/actions.
  It displays uncertainty, missing information, declared basis, observations,
  hypotheses, blocking gaps and cited saved scalar values. Explicit empty lists,
  legacy absence, older API nonempty lists and malformed values are distinct.
  React escapes displayed model/evidence text; references cannot resolve inherited
  object properties or arbitrary current/global data. Analyst/preservation warnings
  remain; references are explicitly not proof of correctness or safe actions.
- Additive metrics, CLI summaries, evaluation/comparison reports and dashboard
  disclose labelled binary coverage (`labelled_binary / labelled_available`),
  labelled abstentions and available unknown truth. Known-label unavailable outcomes
  and unknown-truth responses are excluded from that coverage denominator; it is
  null when no labelled available outcomes exist. All original scoring formulas
  and persisted categories are unchanged.

### Verification and changed files

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
728 passed, 1 warning in 50.70s

cd dashboard
npm test
79 passed, 0 failed
npm run build
TypeScript and Vite production build passed
```

The default test database was `DATABASE_PATH=:memory:` and database regressions
used temporary files. Existing network-denial guards remain intact. The warning
is the existing Starlette/HTTPX TestClient deprecation. Tests cover every
basis/disposition pairing, invalid shapes/references, unavailable handling,
unsupported-but-structurally-valid prose, privacy, post-scrub identity/snapshots,
cache tampering/replay, wrong/missing versions, nullable migration, old terminal
hashes and idempotency. Actual local API and all four metric scopes verify
roundtrip, replay counting, abstention/severity/calibration and saved evidence.
Real React server-rendering tests cover qualifications, citations, malformed/null
states and escaping. This is not interactive browser QA or model-quality evidence.

Files added for implementation:

- `src/models/evidence.py` — strict nested contract and safe reference resolution.
- `dashboard/src/components/VerdictQualifications.tsx` — analyst qualifications view.
- `tests/test_evidence_basis.py` — 76 offline backend cases.
- `dashboard/tests/verdict.test.mjs` — 29 rendered qualification cases.

Existing files changed:

- Runtime: `src/models/triage.py`, `src/engine/groq.py`, `src/engine/llm.py`,
  `src/engine/triage_policy.py`, `src/engine/database.py`,
  `src/engine/verdict_cache.py`, `src/engine/evaluation.py`, `src/cli.py`.
- Reports: `scripts/run_evaluation.py`, `scripts/compare_models.py`.
- Dashboard: `dashboard/src/api/apiService.ts`,
  `dashboard/src/pages/TimelineView.tsx`,
  `dashboard/src/components/MetricsOverview.tsx`,
  `dashboard/src/metrics/presentation.ts`.
- Existing tests: `tests/test_groq.py`, `tests/test_triage_policy.py`,
  `dashboard/tests/metrics.test.mjs` (one added coverage case).
- Documentation including the preceding audit/design work: `AGENTS.md`,
  `ARCHITECTURE.md`, `DECISIONS.md`, `README.md`, `TASKS.md` and this report.

No dependency additions, production database changes, benchmark/reference-label
edits, live requests, commit or push were performed. The previous live artifact
and benchmark hashes recorded above remain unchanged. Local Markdown links and
diff whitespace checks pass. Raw local audit artifacts remain ignored.

### Remaining verification

A separately authorized, bounded live check must establish provider acceptance of
the new strict schema and inspect actual v2 conclusions/actions. It must not reuse
old v1 outputs as v2 results. Then evaluate cases not used to develop the policy,
reporting coverage and abstention alongside accuracy. A model may still cite an
irrelevant field, choose a wrong basis, hide a blocking gap or make unsupported
claims in free text; local structural checks do not prove entailment or safety.
Telemetry normalization, trusted authorization context, prompt-injection evaluation,
normal CLI workflow, interactive visual QA and broader roadmap phases remain open.
