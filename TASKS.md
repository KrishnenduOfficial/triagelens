# TriageLens Tasks

## Current status ? 2026-11-08

Groq is the sole runtime AI provider (ADR-055), default `openai/gpt-oss-120b`.
The operator verified one full synthetic triage: HTTP 200, schema-valid output,
1248.8ms, one request, no cache and no fallback. This does not establish benchmark
accuracy or sustained availability. See [verification](docs/results/groq_migration_20261108.md).

A subsequent authorized agent-run six-case sample produced six schema-valid
verdicts, TP=3/TN=3/FP=0/FN=0, and exact severity agreement 1/6. Saved API metrics and
static dashboard rendering matched. This selected synthetic sample is not a
general performance claim. See [evaluation](docs/results/groq_evaluation_report.md).

The later `triage-v1` development check completed six live requests: TP=3/TN=1/FN=1
on five labelled cases, one unlabelled abstention, and severity agreement 3/5. All
four API scopes and static dashboard rendering matched saved metrics. Semantic
policy compliance remains incomplete; see
[new-policy evidence](docs/results/triage_v1_live_check_20261108.md).

Gemini WIRE-11 is **retired / superseded by provider replacement**. Its upstream
cause was not established or repaired. It is not an active blocker or a task to
resume. Prior benchmark reports and stored outcomes retain historical attribution.

## Current provider and verified status — 2026-11-08

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
`docs/results/groq_evaluation_report.md`. The offline rubric/preservation audit is
complete: `docs/results/severity_safety_audit_20261108.md`. It reproduced M23's
malicious/LOW scoring conflict and structural validation accepting unsafe or
unsupported advice. The operator subsequently approved and implemented ADR-056:
`triage-v1` separates disposition from severity, adds an evidence-qualified,
preservation-first policy and structural content checks, and preserves legacy
history with explicit prediction-basis metadata. The subsequent authorized
`triage-v1` live development check made six requests: six valid outcomes, TP=3,
TN=1/FN=1 on five labelled cases, one unlabelled abstention, and severity 3/5.
Saved metrics matched all four API scopes and static dashboard rendering. Review
still found unsupported TLS/success/legitimacy claims and incomplete containment
qualification. See `docs/results/triage_v1_live_check_20261108.md`. The earlier six
outcomes remain pre-policy evidence. No live calls were made by the offline audit
or implementation themselves.

Follow-up evidence/abstention audit is complete:
`docs/results/evidence_abstention_audit_20261108.md`. Six saved completions replay
with matching request-body hashes; 14 injected local probes made zero network
attempts, and 228 targeted regressions passed. Structural checks do not enforce
evidence sufficiency or prose support, and the audit found missing uncertainty/gap
presentation. ADR-057 is now implemented offline: active `triage-v2` /
`evidence-basis-v1`, structured basis/observation/hypothesis/gap checks, validated
references to immutable sanitized snapshots, and legacy-safe uncertainty display.
Labelled coverage is reported separately from abstentions and unknown truth.
Live v2 acceptance/semantic quality remains unmeasured. Normalization is a separate
follow-up. Preserve all previous
labels, metrics and policy identities; do not claim the semantic gaps are fixed.
This does not close interactive UI, full CLI or prompt-injection verification.

Gemini runtime code, settings and diagnostics are removed. WIRE-11 is retired
as superseded by the provider replacement, not repaired upstream. Historical
benchmark reports and stored records retain their true model attribution.
Do not ask the operator to resume Gemini diagnostics as a current project task.
See README.md, TASKS.md, DECISIONS.md and docs/results/groq_migration_20261108.md.

Current offline verification: 728 backend tests passed (one existing warning),
79 dashboard tests passed and production build succeeded; local Markdown links and
diff whitespace checks passed. Removed-provider tests were retired; the new policy
added 33 backend cases; ADR-057 adds 76 backend and 30 dashboard cases. References
establish traceability, not semantic proof. The earlier bounded live check used v1;
v2 live acceptance and untouched-case evaluation remain pending.

## Roadmap progress

- [x] T5.2 local Compose stack: PostgreSQL, API and dashboard run as non-root
  with health checks, separate database logins and 2.625 GiB combined memory
  limits. Fresh startup, localhost routes, role boundaries, repeated startup and
  synthetic saved-hunt persistence across restart were verified. Offline checks:
  1,320 backend tests passed, four PostgreSQL cases skipped without a test DSN,
  88 dashboard tests passed, and the dashboard build passed. One existing
  Starlette warning remains; no live provider calls. Docker overhead is extra.

- [x] T5.1 PostgreSQL baseline (G9, ADR-067): SQLite stays the default. Alembic
  provisions a fresh PostgreSQL database with raw JSONB and a GIN index. Ground
  truth and evaluations use a protected schema. The inference cache uses a
  restricted login and hunts use a separate read-only, time-bounded connection.
  The same storage and hunting tests ran on both engines. The six focused cases
  and all 1,321 backend tests passed against disposable PostgreSQL 17.11 and SQLite
  (one existing Starlette/HTTPX warning). Verified upgrade, downgrade, role grants,
  rollback, timeout, and synthetic CLI-to-API parity. Time partitioning is disabled.

- [x] S4 dashboard redesign follow-up: responsive workspace navigation, a prominent
  investigation queue, separate assessment and analyst review panels, and consistent
  forms, tables and ATT&CK annotations. Verified with 88 dashboard tests, the
  production build, and two Playwright tests in Edge using synthetic data.
  Usability follow-up: inline alert details and a filter reset, source-event and
  coverage shortcuts, and per-record hunting inspection using the stored alert ID.
  Browser checks exercise all six views at desktop and phone widths.
  The Enterprise 17.1 matrix now uses ordered tactic columns, expandable
  sub-techniques, technique search, and a recorded-hit filter with separate
  Sigma and YARA markers. Shared spacing and heading styles were refined.
  The two Edge checks passed alongside the running practice dashboard on
  separate loopback ports. The dashboard suite (88 tests) and build passed.

- [x] T4.7 dashboard smoke test: Playwright exercised all views against an isolated
  synthetic database, including analyst review, saved hunts, Sigma and YARA records.
  Fixed CORS for saved-query PUT/DELETE; README includes synthetic screenshots and
  run instructions. Offline verification: 1,315 backend tests, 88 dashboard tests,
  one Edge browser smoke test and the dashboard build passed. No live provider calls.
  Chromium installation did not finish; a React hunting list key warning remains.

- [x] T4.6 dashboard quality: explicit human-review notice, retryable detection loading/error and empty-coverage states, and stale timeline suppression. Offline API contract and safe-rendering checks passed; 1,314 backend tests and 88 dashboard tests passed, and the dashboard build passed (one existing backend warning). Interactive QA remains T4.7; no live provider calls.

- [x] T4.5 analyst disposition: final per-verdict confirmation or override stored separately from AI output and ground truth. Identical retries are accepted and superseded verdicts rejected. Offline verification: 1,314 backend tests and 86 dashboard tests passed, dashboard build passed (one existing backend warning). Interactive dashboard QA remains pending. No live provider calls.

- [x] T4.4 detections and coverage: curated Sigma rules and load issues,
  paginated recorded rule hits and YARA scans, and an ATT&CK 17.1 matrix of
  explicit mappings on persisted Sigma/YARA hits. Annotation coverage is not
  detection effectiveness; unmatched YARA scans remain visible independently.
  Offline verification: 1,313 backend tests and 85 dashboard tests passed;
  dashboard build passed (one existing backend warning). Interactive QA remains
  pending. No live provider calls.

- [x] T4.3 hunting UI: grammar help, persisted named query controls and JSON
  export of up to 500 returned records, with raw telemetry/label disclosure.
  Offline verification: 85 hunting tests, 1,312 backend tests and 84 dashboard
  tests passed; dashboard build passed (one existing backend warning).
  Interactive QA remains pending. No live provider calls.

- [x] T4.2 threat intelligence view: recorded provider statuses, compact summaries
  and lookup times; unavailable outcomes are distinguished from clean findings.
  Offline verification: 1,311 backend tests and 81 dashboard tests passed; dashboard
  build succeeded. Interactive QA remains pending. No live calls.

- [x] T4.1 alert management: paginated alert API and
  dashboard search, filters, sorting and plain-text detail. Host/user filters use
  canonical mappings; time bounds are inclusive and timezone-aware. Substring
  filters use SQLite case folding and scans; timestamps missing or invalid do not
  match time filters. Offline verification: 9 new backend and 1 dashboard test;
  1,310 backend tests and 80 dashboard tests passed, and the dashboard build
  succeeded (one existing backend warning). No live calls. Interactive dashboard
  QA remains pending.

- [x] T0.1 token hygiene: ADR index, concise agent rules, Markdown encoding check, and scratch ignore rule. The operator reported 728 backend tests passed (one warning); 79 dashboard tests passed.
- [x] T0.2 config leftovers: removed the generic URLhaus key alias, set the VirusTotal threshold to 3, retained wait mode off, and documented that the per-run lookup environment variable is currently unused.
- [ ] T0.3 terminology: describe the hunting feature as a KQL-style hunting filter across docs, API, engine documentation, and dashboard; confirm unchanged behavior with the targeted tests (pending: Python cannot launch in this environment).
- [x] T0.5 Groq pacing: per-engine rolling-minute request and estimated-token limits, bounded waits and 429 Retry-After handling; 748 offline backend tests passed (one existing warning). Daily quotas and cross-process coordination are not enforced; see ADR-058.
- [x] T0.6 workflow check: README documents the CLI, database, API and dashboard sequence and same-run comparison; operator screenshots confirmed stored counts on a populated database on 2026-11-09.
  An authorized synthetic CLI run was interrupted after repeated Groq 429s; it
  produced no final CLI summary, so it cannot establish dashboard parity.
  A later bounded three-timeline run completed without 429s; all three verdicts
  were withheld by validation. Operator screenshots 229-231 confirm dashboard/API/
  CLI parity for that run: three unavailable, zero scored, zero confusion counts,
  and 0% availability. This checks unavailable-outcome display, not AI quality or
  successful-verdict display; broader interactive dashboard QA remains pending.
  Pacing follow-up and the full offline backend suite passed (760 tests; one
  existing warning); dashboard tests passed (79) and the production build passed.

- [x] T1.1 EVTX adapter: 38 offline EVTX tests passed, including synthetic native
  files, corruption recovery, prompt provenance exclusion and bounded batching.
  A 128 MiB synthetic native-parser check emitted 2,048 events with zero errors;
  observed working-set growth after warm-up was 0.50 MiB (batch 25, one thread).
  Full offline backend suite passed: 798 tests, one existing Starlette/HTTPX warning.
  G4 approved `evtx==0.15.0` (MIT);
  see ADR-059. CLI correlation still collects alerts; real-data evaluation is pending.

- [x] T1.2 ground truth mapping: 36 new offline mapping/leakage cases passed;
  targeted regressions passed (212 tests), and the full offline backend suite
  passed (834 tests; one existing Starlette/HTTPX deprecation warning).
  Explicit folder/file rules and supplied annotations remain separate from event
  telemetry; unknown/conflicting truth is not inferred from ATT&CK IDs. See ADR-060.
  Initial validation used synthetic fixtures; reviewed binary labels and automatic
  metadata-file ingestion are not provided by this task.
  Bounded clone validation (2026-11-09): three smallest EVTX files from three tactic
  folders (68 KiB each), capped at 200 events/file, completed with 1/8/1 events;
  no parser/normalization errors, missing/invalid timestamps, or failed files.
  All 10 timestamps were UTC and all binary labels remained unknown; one event
  gained a filename-derived technique annotation. Ten intercepted prompts and
  captured logs had no introduced dataset metadata; a folder-word overlap was
  confined to fixed prompt instructions. Twenty memory/SQLite cache comparisons
  and 20 SQLite roundtrips passed. Network attempts: zero; source hashes unchanged.
  Limits: metadata README only; larger notebook/CSV unopened. No indicators were
  emitted, so real-data enrichment dispatch and binary label correctness remain
  unverified. Counterfactual labels tested isolation only, not dataset truth.
  Follow-up regressions: 74 EVTX/mapping tests and the full 834-test offline backend
  suite passed (one existing Starlette/HTTPX warning). Re-run the bounded check with
  `.\.venv\Scripts\python.exe scratch/validate_clone_offline.py` while the local,
  ignored harness is available; no sample records or validation database are saved.

- [ ] T1.3 benign data: the owner chose a mix of reviewed local Windows logs and
  a public baseline. An opt-in EVTX adapter requires a whole-file benign review;
  the offline shortcut check compares mapped classes without exposing artifact
  values. A synthetic two-event check detected complete separation by channel,
  filename, filename token, field presence and time, but not extension. This is
  a demonstration. An offline, source-group comparison of 200 baseline events
  from two files and 92 attack-associated events from three files found complete
  separation by filename and time range, overlapping channels (variation 0.2935),
  and no perfect single field-presence or filename-token separator. No parser,
  normalization, or timestamp errors occurred. Samples were capped at 100 events
  per file; these groups are not independently verified event labels. The public
  baseline and attack samples are not representative of all data. Own Windows logs
  and reviewed labels remain needed for the chosen mixed cohort; see ADR-061.

- [ ] T1.4 evaluation protocol (partial): offline reviewed-EVTX intake, fixed
  source/duplicate-event grouping, persisted split/freeze checks, fresh repeated
  inference, bounded request estimates and per-run metrics are implemented; see
  ADR-062. Real reviewed cohorts, a separately approved live run, complete analyst
  review of every FP/FN and end-to-end enrichment/latency remain outstanding.
  Event-level review/import is available; a 14-event local prefix sample is pending
  independent review. Source category alone is not a binary label.

- [ ] T1.5 results report (partial): [real-data status](docs/results/real_data_evaluation_20261109.md)
  summarizes recorded intake and source-comparison evidence and explicitly leaves
  real-data performance unmeasured. Reviewed cohorts, real inference, intervals and
  analyst error review remain outstanding; the README links to these limits.

- [x] T2.1 hunting DSL: bounded AST parser and SQLite dialect compiler,
  explicit type/substring semantics, cooperative execution deadlines, saved query
  definitions and offline differential checks. See `docs/HUNTING_DSL.md` and ADR-015.
  Verification: 84 hunting tests (including 800 seeded differential queries), 43
  API/database regressions and the full 921-test offline backend suite passed;
  one existing Starlette/HTTPX warning. No dependencies or live provider calls.
  PostgreSQL, saved-query UI/API and hard real-time cancellation are not provided.

- [x] T2.2 canonical fields: 15 table-driven OCSF-inspired Windows telemetry
  fields shared by hunting and correlation, with a reusable resolver for future
  Sigma. Explicit alias precedence and scalar types, Security 4688 child/creator
  PID separation, and distinct subject/target accounts preserve source records
  and independent metadata. Existing databases need no migration or reingestion.
  Verification: 64 new offline mapping/consumer cases passed; hunting, timeline
  and EVTX regressions passed; full offline backend suite passed (985 tests,
  one existing Starlette/HTTPX warning). See `docs/HUNTING_DSL.md` and ADR-015.
  Limits: declared paths/events only; canonical scans use unindexed Python
  callbacks and cooperative deadlines. Sigma evaluation and real-data quality
  measurements remain separate work. No new dependencies or live calls.

- [x] T2.3 Sigma: bounded validated pySigma loader and local AST evaluator using
  the canonical fields, explicit Windows logsource gates and unsupported-rule
  diagnostics. Subset, semantics, limits and usage: [module documentation](src/engine/sigma.py).
  The pinned three-rule SigmaHQ pack has two supported rules and one explicitly
  unsupported OriginalFileName rule; original authors, source links, hashes and
  DRL-1.1 attribution are retained, including authors in match results. See ADR-063.
  Verification: 130 offline Sigma cases and 175 related regressions passed;
  full offline backend suite passed (1,115 tests, one existing Starlette/HTTPX
  warning), and pip check found no broken requirements. A synthetic hostname
  demo returned one attributed match with unchanged ground truth.
  Limits: documented subset and bounded single-event evaluation only; no real-data
  detection-quality claim, detection persistence, CLI/API wiring or prompt expansion.
  G5 and dependency pins were owner-approved; no live provider calls were made.

- [x] T2.4 detections store: separate SQLite rule hits and foreign-keyed alert
  references, with timeline membership derived from current alert links. Sources
  are restricted to Sigma, hunt and YARA; caller-supplied detection time is UTC.
  G6 policy keeps hits out of all LLM prompts. A synthetic Sigma match was stored
  and retrieved by timeline; mocked provider requests stayed identical. Nine new
  cases and 181 targeted tests passed; full offline backend suite: 1,124 passed,
  one existing Starlette/HTTPX warning. See ADR-063's T2.4 note.
  Limits: explicit caller persistence only; no CLI/API/dashboard wiring or live calls.

- [x] T2.5 ATT&CK: pinned Enterprise 17.1 catalog, independent dataset/AI/rule
  technique sets, exact/parent/tactic comparison, coverage and Navigator export.
  The reviewed-cohort report keeps technique metrics separate from binary metrics;
  missing truth or predictions are unavailable. See ADR-064 and `src/engine/attack.py`.
  Verification: 206 targeted offline tests and 1,134 full backend tests passed;
  the full run had one existing Starlette/HTTPX deprecation warning.
  Limits: active Enterprise techniques only; rule mappings require explicit caller
  persistence, no dashboard or live validation, and no real-data accuracy claim.

- [ ] T2.6 rule evaluation (partial): reviewed-cohort reports compare exact-tag
  Sigma detections with recorded AI binary predictions on paired timelines, with
  benign false positives, per-rule counts, Wilson intervals, unavailable outcomes
  and unsupported-rule diagnostics. Three new offline tests passed; 160 targeted
  and 1,137 full backend tests passed (one existing Starlette/HTTPX warning).
  A four-timeline synthetic check showed one Sigma-only and one AI-only detection;
  each flagged 1/2 benign cases (95% Wilson interval 0.0945-0.9055). This is not
  real-data performance. Independently reviewed technique-labelled S1 cohorts and
  AI outcomes remain outstanding; no live calls were made. The protocol produces
  comparisons during a future separately approved run, not from saved past runs.

- [x] T2.7 rule fragility: offline synthetic field rename, UTF-8 base64 and case
  mutations report per-rule lost-match fractions, family counts, unavailable results
  and unsupported-rule diagnostics. The selected demo yielded 2/3 lost matches for
  each of two supported rules; these perturbations need not preserve semantics and
  do not establish real-world evasion or detection rates. Nine new tests, 139 focused
  tests and 1,146 full backend tests passed (one existing Starlette/HTTPX warning).
  See README and ADR-063.

- [x] T3.1 YARA design report only (2026-11-10): workflow and proposed limits below;
  G7 owner-approved `yara-x==1.22.1` (BSD-3-Clause), optional in T3.2. See ADR-065.
  No scanner, package installation, rules, migrations or scan endpoint added.

- [x] T3.2 optional YARA snapshot scanner (2026-11-10): byte-only scanning in a
  fresh AppContainer/Job Object, bounded IPC/results and explicit missing-engine,
  isolation, compile, timeout, resource and truncation states. G7's pinned optional
  wheel installed with owner-authorized network access; no provider calls.
  Native harmless tests verified match/no-match, compiler diagnostics, local
  TCP/UDP delivery denial against working receivers, outside-canary read denial,
  runtime write denial, minimal environment, memory/CPU/process limits, deadline/
  malformed-IPC cleanup and worker termination after abrupt parent exit. Added
  72 offline cases; focused regressions passed (89), then the full backend suite
  passed (1,218; one existing Starlette/HTTPX warning). README demo: `match 26
  yara-x 1.22.1`, both digests recorded, absent ATT&CK annotation reported explicitly.
  `pip check`: no broken requirements; 28 Markdown files checked with zero encoding
  errors; ADR-065 remains unique and 12 lines. No detection-quality measurement.
  Limits: Windows runtime verified here only; CPU enforcement is periodic, staging
  I/O is not preemptible, admission is per Python process. Abrupt parent exit can
  leave the empty AppContainer profile/trusted runtime copies. Safe registered-root
  file acquisition, extension checks and persistence/API/hash linking remain T3.4;
  licensed rule packs and broader file adversarial tests remain T3.3/T3.5.

- [x] T3.3 rule pack: two original MIT rules and two metadata-adapted MIT rules
  from Marcin Ulikowski's yara-rulz; upstream copyright/license retained. Upstream
  URL follows a moving branch; source dates are not immutable commits. Four harmless
  match/no-match checks and one combined-pack compilation check passed; 63 focused
  and 1,223 full offline backend tests passed (one existing Starlette warning).
  Harmless full-pack demo: `match ['powershell_encoded_command_text']`.
  These text matches and ATT&CK mappings do not prove execution, maliciousness or
  real-world detection quality. No provider calls; source/license lookup was approved.

- [x] T3.4 integration: opt-in registered Windows roots, pinned handle snapshots,
  bounded offline directory scans, persisted scan results and atomic exact-SHA-256
  links to existing alert indicators. Explicit hash-only enrichment uses the existing
  provider cache and quotas; scans do not initiate it. API job IDs support retry
  deduplication; detections remain separate from labels and AI prompts. A harmless
  native scan linked a matching alert; mocked enrichment made no provider calls.
  Verification: 16 new integration cases; 21 focused integration/documentation
  checks passed; full offline backend suite passed (1,239 tests, one existing
  Starlette/HTTPX warning). See README and ADR-065. Limits: Windows only, file and
  database I/O cannot be preempted, scan admission spans one Windows logon session,
  and interrupted jobs need a new ID; broader adversarial checks remain T3.5.

- [x] T3.5 harmless/adversarial acceptance (2026-11-10): 62 new
  cases cover the standard EICAR snapshot and benign control, native slow-rule
  timeout/cleanup, API traversal/root admission, pinned-handle replacement denial,
  junctions/hardlinks, oversized reads, archives without extraction, and directory,
  file, depth, byte and job-time bounds. A nested-directory test exposed a shared
  entry-budget defect; enumeration now reserves entries against the global 1,000
  limit, including queued siblings. Exact-budget completion is also checked.
  Focused offline verification: 155 passed; full backend suite: 1,301 passed,
  each with one existing Starlette/HTTPX warning. EICAR stays in memory and uses a
  test-only signature; this does not measure production-pack EICAR coverage.
  Limits: Windows-specific native checks; total-byte/job-time boundary probes use
  injected snapshots/clocks. No real-data detection-quality measurement or provider
  calls; blocking I/O, periodic CPU checks and interrupted-job limits remain.

T3.5 verification commands (offline, harmless fixtures):
```powershell
.\.venv\Scripts\python.exe -m pytest -q -x --tb=short tests/test_yara.py tests/test_yara_windows.py tests/test_yara_pack.py tests/test_yara_integration.py tests/test_yara_adversarial.py
# 155 passed, 1 warning in 75.26s (0:01:15)
.\.venv\Scripts\python.exe -m pytest -q -x --tb=short
# 1301 passed, 1 warning in 153.10s (0:02:33)
```

T3.2 verification (offline; harmless fixtures, no external test hosts):
```text
.\.venv\Scripts\python.exe -m pytest -q -x --tb=short tests/test_yara.py tests/test_yara_windows.py tests/test_attack.py tests/test_detections.py
89 passed in 35.46s
.\.venv\Scripts\python.exe -m pytest -q -x --tb=short
1218 passed, 1 warning in 92.15s (0:01:32)
.\.venv\Scripts\python.exe -m pip check
No broken requirements found.
```

### T3.1 design report — proposed contract for S3

Workflow: operator registers a narrow local input root outside the repository;
request names its registration ID and a relative path, never an arbitrary root.
There are no default roots or background scans. Enumerate deterministically within
the limits below, validate/open a regular file, read one bounded immutable byte
snapshot, calculate SHA-256, scan those same bytes in a worker, validate its bounded
result, then offer explicit hash-to-alert linking in T3.4. Samples are never
executed, imported, unpacked, modified, quarantined or deleted. No process-memory
scans, automatic downloads, file uploads or external enrichment occur in a scan.
Real malware remains outside the repository in an isolated VM; local development
uses harmless fixtures only. Human analysts retain response authority.

Allowed paths: explicit absolute local roots only; reject drive roots, system,
application, credential and repository directories. Reject traversal, absolute or
drive-relative request paths, UNC/device paths, mapped network drives, alternate
data streams, symlinks, junctions, other reparse points and multiply linked files.
Validate root identity and ancestors, then verify the opened handle's final path,
volume/file identity and containment before reading; string-prefix checks alone
are insufficient. Open without write/delete sharing, cap the read, and reject
identity/size/time changes instead of scanning a replacement. Never reopen by
path for hashing or scanning. Paths stay local provenance and out of prompts/logs.
Reject recognized archives by extension/signature; other bytes remain opaque,
with no extraction even for unrecognized or disguised containers.

| Proposed initial bound | Value / behavior |
| --- | --- |
| Admission | One scan job and one worker at a time; reject busy requests |
| Enumeration | 1,000 entries, depth 4, 100 files; report unvisited/truncated scope |
| Input | 16 MiB/file, 128 MiB/job; enforce while reading, not only from stat |
| Rule pack | 30 reviewed rules, 1 MiB total source, 10,000 total patterns |
| Worker time | Compile 10 s; engine scan 5 s/file; parent wall deadline 20 s/worker |
| Job time | 60 s wall time including enumeration, reads, startup and IPC |
| Worker resources | 512 MiB committed memory; 10 s CPU time; one active process |
| Results | 100 occurrences/pattern, 1,000/file; 256 KiB response/file |

Start a fresh worker per file with a minimal environment (no inherited secrets),
bounded byte/JSON IPC, no shell, and no database or input-root access. Disable rule
includes and initially reject all module imports; accept reviewed text sources,
never supplied native code or serialized compiled rules. Compiler diagnostics
identify rule/line/category without source snippets, sample bytes or private paths.
Set Windows Job Object memory/CPU/process limits before releasing the worker;
kill the job on deadline, parent exit or malformed/oversized IPC, then reap it.
Use an AppContainer with no network capabilities or loopback exemption; grant only
required runtime reads and IPC. A Job Object is resource control, not an egress
barrier. If containment or limits cannot be established, return unavailable and
do not run an unrestricted fallback. AppContainer/Python/JIT compatibility and all
numeric defaults require implementation checks; none are measured guarantees.

Result contract: scan ID, SHA-256/size (nullable before a complete snapshot), UTC
start/end, engine/version, rule-pack digest, applied limits, completion status,
diagnostics and matches. Each match carries namespace/rule ID, source digest,
author/license/source reference, validated technique IDs, and bounded pattern
IDs/offsets/lengths, never matched bytes. Distinguish completed match/no-match,
rejected/skipped, missing engine, compile error, timeout, resource exhaustion,
file change, worker failure and result truncation. An incomplete run is never a
clean result; completed no-match means only no hit from that exact pack/snapshot.

T3.4 linking: match exact lowercase 64-hex SHA-256 against validated observable
alert hash indicators; do not join on MD5/SHA-1, names, paths, labels or technique
annotations. Link every matching existing alert explicitly, with no implied
execution/causality claim. Keep unmatched scan results separate; do not fabricate
alerts to satisfy the detection store's required references. Persist successful
linked hits through `insert_detection(source="yara", event_ids=..., ...)`, using
scan UTC time and a rule identity qualified by pack digest/namespace. The current
detections table cannot store full scan provenance or no-match/failure history;
T3.4 needs a separate scan/result record and scan-to-detection association, with
atomic linking and retry deduplication. This task makes no schema changes.

Rule metadata: require stable ID, author, source URL/revision and license; optional
`mitre_attack` is a comma-separated list of technique IDs, parsed into a collection
for `rule_techniques("yara", ...)` against the pinned Enterprise 17.1 catalog.
Report absent/unknown/inactive IDs; retain an unmapped hit without silently
discarding metadata errors or inventing techniques. Rule mappings remain separate
from dataset truth, AI predictions and analyst dispositions. Hits and metadata
never enter prompts or verdict caches; file bytes and paths never leave the scan.
Any future hash-only enrichment is a separate explicit T3.4 action under existing
masking, quotas and unavailable-result behavior, with no file upload.

G7 evidence: [YARA-X 1.22.1 files](https://pypi.org/project/yara-x/1.22.1/#files)
include `yara_x-1.22.1-cp39-abi3-win_amd64.whl`; the local interpreter reports
CPython 3.14.7, win-amd64, non-free-threaded. Tags support compatibility in principle;
no installation/import/scan was tested. Justification: optional `yara-x==1.22.1`,
[BSD-3-Clause](https://github.com/VirusTotal/yara-x/blob/v1.22.1/LICENSE), supplies
the scanner without a local Rust build. The considered alternative,
[yara-python 4.5.4](https://pypi.org/project/yara-python/4.5.4/#files) (Apache-2.0),
lists Windows wheels through CPython 3.13, with no CPython 3.14 wheel listed.
[YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/) documents
timeouts and include controls; [language differences](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)
require explicit compatibility diagnostics, with no engine fallback. Windows design
references: [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[committed-memory limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information),
and [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation).

Future offline acceptance (T3.2–T3.5): base install without YARA; wheel import and
harmless match/no-match; invalid rules/metadata/includes/modules; traversal,
reparse/hardlink/ADS/network paths and replacement races; archive/size/enumeration
limits; compile/scan/IPC deadlines, memory exhaustion and parent-exit cleanup;
actual OS network denial; bounded/redacted results; exact hash links, unmatched
files, retry deduplication, and prompt/cache/label isolation. Use harmless fixtures
and the EICAR test string only; no fixture is executed. Performance and security
enforcement remain unverified until those tests run. G7 authorizes the library
choice; each later task still needs its own roadmap plan approval.

T3.1 verification (2026-11-10, existing interpreter; tests offline):
```text
.\.venv\Scripts\python.exe -m pytest -q -x --tb=short tests/test_detections.py tests/test_attack.py tests/test_wire7_docs_and_health.py
22 passed, 1 warning in 3.57s
.\.venv\Scripts\python.exe -m pytest -q -x --tb=short
1146 passed, 1 warning in 38.80s
node scripts/check_markdown_encoding.js
Checked 28 Markdown files; 0 file(s) with encoding errors.
```
Both pytest runs reported the existing Starlette/HTTPX deprecation warning.
An inline local-link/anchor check passed all 76 links and verified ADR-065 is
unique and 12 lines. `git diff --check` passed. No new tests were added for this
documentation-only task; these results do not validate a YARA scanner.

## Implemented

- [x] JSON/CSV alert intake, normalization, indicator extraction and source preservation.
- [x] VirusTotal, AbuseIPDB and URLhaus enrichment with explicit unavailable states.
- [x] Enrichment cache expiry, per-attempt provider quota accounting and rate limits.
- [x] Correlated security timelines with bounded events and compact intelligence summaries.
- [x] Recursive ground-truth/provenance filtering and PII/credential masking before egress.
- [x] Groq chat completions, strict assessment schema, local validation and actual model attribution.
- [x] Single-attempt Groq synthetic diagnostics, metadata-only trace and safe dry run.
- [x] Groq smoke checks; fallback remains explicitly opt-in and provider-local.
- [x] Live primary-model integration accepted for the operator's successful request.
- [x] Remove retired provider engine, credential settings, diagnostics and exclusive tests.
- [x] Keep shared privacy/cache/provenance regressions using a test-only neutral transport.
- [x] Shared CLI/API database path resolution and SQLite legacy-compatible migrations.
- [x] Severity/availability persistence, run-observation lifecycle and idempotent outcomes.
- [x] Provenance-aware memory/SQLite verdict cache policy and expiry checks.
- [x] History, run, quality and attempts metric scopes with validated cohorts.
- [x] Dashboard scope selection, unavailable values, coverage and stale-request protection.
- [x] Replace provider-specific project rules with AGENTS.md and correct current Markdown claims.
- [x] Remove unused dashboard starter assets and the empty rule file; remove 14
  obsolete dependency pins and protect environment variants, SQLite sidecars and
  TypeScript build metadata from accidental commits.
- [x] Correct remaining README drift: prerequisites, dependency/test versions,
  dashboard routes, metric-scope checks, input folder examples, enrichment network
  behavior and actual directory paths. Verified 13 documentation/config/API parity
  tests and all listed repository paths; application behavior unchanged.

## Next work

- [x] Run a small sanitized Groq evaluation using independent labels. Inspect severity,
  false negatives, unsupported reasoning, missing-information handling and calibration.
- [x] Audit severity criteria, evidence-qualified assertions and preservation-first
  recommendations offline before changing prompts or running a larger benchmark.
- [x] Agree and implement independent disposition, response-priority severity,
  binary-confidence meaning and legacy compatibility (ADR-056). `triage-v1` adds
  a versioned rubric, preservation-first/evidence-qualified analyst recommendations,
  nonblank content checks, abstention accounting, additive persistence, exact
  prompt/cache identity and evaluator-aware cohorts. See the
  [audit and implementation verification](docs/results/severity_safety_audit_20261108.md).
- [x] Verify new-policy Groq output on a bounded development sample under a new
  explicit inference-policy/cohort identity. Six valid responses include one
  unlabelled abstention, but review found a high-confidence false negative and
  unsupported assertions; this is not a semantic-safety sign-off.
- [x] Audit evidence-qualified conclusions and abstention consistency offline.
  Six saved completions replay with matching request fingerprints; structural
  probes reproduce missing sufficiency/claim checks. Abstention accounting and
  label isolation remain correct. The analyst view omits stored uncertainty/gaps;
  telemetry context projection also needs a separately scoped review. See the
  [audit and proposed contract](docs/results/evidence_abstention_audit_20261108.md)
  (228 targeted regressions passed; 14 local probes, zero network attempts).
- [x] Agree the versioned evidence-basis contract and uncertainty/gap presentation
  before runtime changes (ADR-057). Target `triage-v2` / `evidence-basis-v1` adds
  referenced observations, hypotheses and blocking gaps, with legacy-safe display.
- [x] Implement and verify ADR-057 offline: active `triage-v2` / `evidence-basis-v1`,
  deterministic references/basis checks, immutable sanitized snapshots, nullable
  legacy migration/cache validation, visible uncertainty/gaps/citations, and labelled
  coverage disclosure. Existing scoring identities and history counts are preserved.
- [ ] Perform a separately bounded `triage-v2` live acceptance and quality check;
  offline structural validation does not certify factual support or action safety.
- [ ] Evaluate untouched cases after addressing the development findings. Preserve
  labels, earlier scores and policy attribution; do not tune to hidden intent.
- [ ] Measure Groq prompt-injection resistance and availability; report sample size and scope.
- [x] Verify the normal CLI -> shared SQLite -> API -> dashboard workflow manually
  for the T0.6 unavailable-outcome run (operator screenshots confirmed counts).
  Preserve default History behavior and select explicit run/cohort IDs for provider comparisons.
- [ ] Complete interactive dashboard visual QA; previous browser access was unavailable.
- [ ] Audit operator-report metric-scope wording; do not infer real-time provider status from history.

Repository publication requires an explicit operator request; actual commits and
remote publication are recorded in Git history.

## Deferred

Authentication/roles, deployment/containerization, advanced hunting/YARA/MITRE
features and larger real-world datasets remain separate work. Do not implement
these without a scoped request. Human analysts retain final response authority.

## Verification rules

Latest offline verification: **728 backend tests passed**, with one existing
Starlette/HTTPX deprecation warning; **79 dashboard tests passed** and production
build succeeded. Local Markdown
link checks and `git diff --check` passed. Removed-provider tests explain the change
from the pre-retirement 688-case suite; ADR-056 added 33 backend cases and ADR-057
adds 76 backend / 30 dashboard cases. Those offline checks made no provider
requests; two separate live development evaluations made six authorized requests
each, using different policy identities and sample compositions.

Ordinary pytest stays offline, including with local credentials configured. Use
injected transports and temporary databases. Never weaken security tests or claim
model quality from schema validation alone. Keep .env and generated databases out
of Git. Historical audit documents in docs/results are snapshots, not current tasks.
