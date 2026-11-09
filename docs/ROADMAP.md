# ROADMAP.md — TriageLens build plan for Codex

Status date: 2026-11-09. Owner: Krishnendu (the human who approves every plan). Save this file as `docs/ROADMAP.md`.

Goal: take TriageLens from a verified prototype to a detection-engineering platform with Sigma, KQL-style hunting, MITRE ATT&CK mapping, YARA, PostgreSQL, and Go and Rust workers, validated on real data. Ambition is high; rigor must stay higher.

---

## 1. Session protocol (read this first, every session, and nothing else outside the active step)

Token and usage saving rules:
1. Read only: this section, section 2, and the one step section you were told to work on (for example `## S1`). Do not read other steps.
2. Do not read `DECISIONS.md` in full. Read `docs/ADR_INDEX.md` (created in T0.1) and open only the ADR ids a task names, using search (`rg "ADR-0xx"`).
3. Do not open `docs/results/*` unless the task names a file.
4. Inspect only the files a task lists, plus what a search shows is directly involved. Never scan the whole repository.
5. Plans are at most 15 lines: files to touch, tests to write, risks, questions. Then stop for approval.
6. Use patches and small edits. Never regenerate whole files.
7. Run the narrowest tests first (`pytest -q -x --tb=short tests/test_<area>.py`), then the full suite once at the end.
8. Report with trimmed output (last lines of test output, `git diff --stat`). Never paste long logs or full diffs.
9. Create no new documents unless the task says so. Put evidence in the report and one short ADR (at most 12 lines). Do not create per-task files under `docs/results/`.
10. One task id per session. Finish, print the git block (section 2b) when the task is done, stop. The owner starts a fresh session for the next task.
11. Never make live network or API calls unless the task says so, and ask the owner first. Ordinary tests stay offline.
12. If a task needs a file outside the ones it lists, say which file and why, then read it. Do not guess.
13. If a rule or limit in this file seems to block the correct solution, stop and ask the owner. Do not work around it silently.

Starter prompt the owner will use:
`Read AGENTS.md rules, docs/ROADMAP.md sections 1, 2 and S<n>. Do task T<n.m> only. Plan first (max 15 lines) and wait for approval.`

---

## 2. Rules specific to this plan

- ADR-008 stays absolute. Four kinds of information must never be mixed in one field or leak into a prompt: (a) dataset ground truth, (b) AI predictions, (c) rule detections (Sigma, YARA, hunts), (d) analyst dispositions.
- Never claim a test, command, live call or result unless it was run and the output is shown.
- Never delete, skip or loosen a test to make it pass. Never import test frameworks in production code.
- No secrets in code, logs, commits or reports. Never print `.env` contents or keys.
- New dependency: write one line of justification (name, version, license, why) in the plan and get approval.
- Safety for security content: never store or run real malware in the repository. Samples live outside the repo, in an isolated VM. Log-level mutations for rule testing are allowed. Never generate working attack tooling.
- Do not add policy layers or new ADRs beyond what a task needs. Each step ends with a demo, tests and a short "limits" note.
- Honest wording: no "military-grade", "production-ready" or "industry-grade" claims. Allowed: "aligned with OWASP ASVS and NIST SSDF" with evidence links.
- Git safety (details in section 2b): never commit or push on your own. Print the commands for the owner to review and run.

Report block (end every task with exactly this, max 15 lines, no secrets, no real log data):
```
REPORT
Task: T<id>   Result: done / partial / blocked
Files changed (git diff --stat):
Commands + key output (trimmed):
Tests added (names) + totals (pass/fail):
Docs updated:
Limits / open questions:
Next task:
Git block: printed after this report (only when Result is done)
```

Commit message format: `T<id>: <what changed>` (one line, plus ADR id if any).

---

## 2b. Git: commits and pushes (terminal commands for the owner)

Codex never runs `git commit` or `git push` on its own, unless the owner explicitly asks in that session. When a task finishes with Result `done` and tests passing, Codex prints this block after the report. The owner reviews it and runs it in PowerShell from the project root.

Template (fill in the real file paths and message; the checks marked "prints nothing" must print nothing):
```
git status --short
git add <path1> <path2> <path3>
git diff --cached --stat
git diff --cached --name-only | Select-String '^\.env$|\.db$|\.sqlite|^scratch/|^node_modules/'
git diff --cached | Select-String 'AIza|AQ\.[A-Za-z0-9_-]{20}|gsk_[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{20}|AKIA|ghp_'
git commit -m "T<id>: <message>"
$b = git branch --show-current; git push origin $b
git log --oneline -3
```
Notes for the owner: the two `Select-String` lines should print nothing. Known fake keys used inside tests can match the second one; if a match is a test fixture you recognize, that is fine, otherwise stop. Review `git diff --cached --stat` before the commit line.

Rules for Codex:
- Add files by explicit path only. Never `git add .` or `git add -A`.
- List any untracked file that is not in the approved plan and ask the owner whether to delete it, ignore it or commit it. Never commit it silently.
- Never commit `.env`, database files, datasets, `scratch/`, `node_modules` or generated reports not named in the plan.
- Never use `git push --force`, `git reset --hard`, `git clean -fd`, `git commit --amend` on pushed commits, or rebase. If history needs fixing, explain and ask.
- If the result is `partial` or `blocked`, do not print a commit block. Print only `git status --short` and say what is left.
- One commit per task id. Docs-only tasks follow the same block.
- Before a risky task (T2.1, T3.2, T5.1, T6.2, T6.3, T7.2, T7.3, T7.4), first ask the owner to confirm `git status --short` prints nothing, so a clean point exists to return to.
- If `.gitignore` does not already ignore `scratch/`, `.env`, database files and `node_modules`, add those lines in the first task that touches the repository (T0.1 for now).

---

## 3. Known facts at 2026-11-09 (from the repository, verified by reading code and the owner's pasted output)

- Pipeline in Python: intake, enrichment (VirusTotal, AbuseIPDB, URLhaus), timeline builder, Groq triage (`openai/gpt-oss-120b`), evaluation, SQLite, FastAPI, React and TypeScript dashboard. About 728 backend tests and 79 dashboard tests reported passing.
- Gemini is removed from runtime. Groq is the only AI provider. Triage policy `triage-v2` / `evidence-basis-v1` is implemented offline. Its live acceptance is not done.
- Real evaluation so far: six-case and six-case-with-new-policy runs on synthetic data only. Not a performance claim.
- Hunting engine is a KQL-style filter translated to SQLite SQL, not real KQL.
- No EVTX ingestion, no Sigma, no MITRE mapping, no YARA code, no PostgreSQL, no Docker, no CI, no authentication, no audit log, no Go or Rust.
- Leftover issues: generic `AUTH_KEY` alias in `src/config.py`; VirusTotal threshold default 1 detection; `.env.example` says URLhaus is keyless (unverified); enrichment wait mode off by default; broken UTF-8 characters in several `.md` files; `AGENTS.md` carries a long status block and mentions an old coding tool.
- Hardware: Windows laptop, 8 GB RAM. Docker must be memory-capped. Rust builds are heavy: use CI for release builds.
- Key files: `src/engine/{groq,llm,enrichment,evaluation,database,hunting,intake,timeline}.py`, `src/utils/{masking,extraction}.py`, `src/{config,cli}.py`, `src/api/main.py`, `scripts/{run_evaluation,check_connections,diagnose_groq,compare_models}.py`, `dashboard/src/`. Locate anything else with a search.

---

## 4. Decision gates (ask the owner one short question; do not decide for them)

| Gate | Question | Needed before |
| --- | --- | --- |
| G1 | VirusTotal threshold (1, 3 or other) and wait-mode default? | T0.2 |
| G2 | Groq limits for the model (requests and tokens per minute and per day)? | T0.5 |
| G3 | Benign data source: own clean Windows logs, a public baseline, or a mix? | T1.3 |
| G4 | Approve new dependencies for EVTX parsing (for example the `evtx` Python package) | T1.1 |
| G5 | Sigma approach: use pySigma for parsing and our own evaluator, or a pySigma backend? (Check what exists.) | T2.3 |
| G6 | May the LLM see rule hits? Default: no in evaluation cohorts (circularity); a separate labelled cohort may allow it | T2.4 |
| G7 | YARA library: `yara-x` Python package or `yara-python` (check Windows wheels)? | T3.2 |
| G8 | End-to-end dashboard test tool (for example Playwright) | T4.7 |
| G9 | PostgreSQL migration approach and test setup | T5.1 |
| G10 | Local or on-prem model option for sensitive data: yes or no? | T6.5 |
| G11 | Go and Rust toolchain installation on the owner's machine, and CI builds | S7 |

---

## S0 — Stabilize (1 to 2 weeks)

Goal: a clean, cheap-to-work-in repository and a trustworthy baseline.

- T0.1 Token hygiene. Create `docs/ADR_INDEX.md` (one line per ADR: id, title, status, anchor). Rewrite the reading rules in `AGENTS.md` to: read the rules, `docs/ROADMAP.md` active step, `TASKS.md`, and use the ADR index with targeted search. Move the long status block out of `AGENTS.md` into `TASKS.md` (keep `AGENTS.md` under 150 lines). Replace mentions of the old coding tool with neutral wording. Fix broken UTF-8 characters in all `.md` files. Also confirm `.gitignore` covers `.env`, database files, `scratch/` and `node_modules` (see section 2b). Done when: `AGENTS.md` is short, the index covers every ADR, `.gitignore` is checked, and a check script confirms no mojibake sequences remain.
- T0.2 Config leftovers (gate G1). Remove the generic `AUTH_KEY` alias. Set and document the VirusTotal threshold. Confirm what `ENRICHMENT_MAX_LOOKUPS_PER_RUN=0` means and document it. Update `.env.example` and README names. Do not change URLhaus claims until the owner reports a live status code. Done when: tests cover each variable and docs match code.
- T0.3 Rename "KQL" to "KQL-style hunting filter" in README, `ARCHITECTURE.md`, API summaries and docstrings, dashboard labels and user-facing errors. No behavior change. Add a superseding note to the relevant ADR. Done when: a search for stand-alone "KQL" claims finds only intentional uses.
- T0.4 Confirm `LICENSE` exists and the README badge and link work.
- T0.5 Groq pacing (gate G2). Add provider-level pacing that respects requests and tokens per minute (estimate about 1,500 tokens per case from earlier runs) and honors `Retry-After`. Injectable clock and sleep; tests never really sleep. Done when: offline tests cover 429 with `Retry-After`, token-per-minute pacing and a maximum total wait.
- T0.6 Workflow check. Add exact README steps for CLI, then database, then API, then dashboard, and a manual click-through checklist. The owner runs it and sends screenshots. Done when: the owner confirms the dashboard numbers equal the CLI summary on a populated database.
- T0.7 Freeze. Add one line to `TASKS.md`: no new policy layers before S1 results. Run one bounded `triage-v2` live acceptance only as part of S1.

Step-end teach-back: list five questions about config loading, the provider interface, the cache identity, pacing and the label-isolation tests that the owner should be able to answer.

---

## S1 — Real data foundation (3 to 4 weeks)

Goal: the first credible results on public Windows event data.

- T1.1 EVTX adapter (gate G4). New intake module that reads `.evtx` files in batches and emits normalized alerts: EventID, channel, computer, user, time (UTC), flattened event data, source file as provenance (never sent to the LLM). Handle huge files, corrupt records and unknown channels. Prefer the Rust-backed Python package; justify any dependency. Done when: tests with tiny synthetic `.evtx` fixtures or recorded parser output pass offline, memory stays bounded, and errors are counted not hidden.
- T1.2 Ground truth mapping. Read dataset labels (folder, file name, metadata) into ground-truth fields only. Extend the leakage tests so file names, folder names and technique ids can never appear in a prompt, enrichment lookup, log line or cache key. Done when: tests use real-looking names and prove no leakage.
- T1.3 Benign data (gate G3). Add the benign adapter and a shortcut check: confirm classes are not separable by format artifacts (channel mix, field presence, time ranges, file naming). Done when: the check runs and its result is recorded in the report.
- T1.4 Evaluation protocol. Fixed split by stored seed or hash (development and test). Tune only on development. Run end to end with pacing, repeated runs, Wilson 95% intervals, class balance, per-technique breakdown, latency, availability, and error analysis of every false positive and false negative. Ask the owner before any live calls and estimate token use first.
- T1.5 Results report. One file `docs/results/real_data_evaluation_<date>.md` and an honest README summary including limits (public dataset, label quality, small classes).

Done when: results on real EVTX data with intervals exist, the leakage tests pass, and the README quotes numbers honestly.

Step-end teach-back: five questions on EVTX parsing, label isolation, the split, interval meaning and what the benign set can and cannot show.

---

## S2 — Detection engineering: KQL-style, Sigma, MITRE (8 to 10 weeks)

Goal: rules and queries that run on the same normalized events, mapped to ATT&CK, evaluated separately from the AI.

- T2.1 KQL-style hunting DSL. Write `docs/HUNTING_DSL.md` (grammar, operators, quoting, precedence, field paths, limits, errors). Parser to syntax tree to parameterized SQL compiler with a dialect interface (SQLite now, PostgreSQL later). Keep injection protections, row limits, timeouts. Differential test: random queries run through the engine and a plain Python evaluator over the same records must agree. Saved queries table.
- T2.2 Canonical field layer. A small mapping (OCSF-inspired subset) from EVTX, Sysmon and Security fields to canonical names, used by hunting, Sigma and correlation. Table-driven, tested.
- T2.3 Sigma (gate G5). Rule loader with validation; logsource to field mapping; evaluator for a documented subset: modifiers (`contains`, `startswith`, `endswith`, `re`, `all`), selections, conditions (`and`, `or`, `not`, `1 of`, `all of`). Report unsupported rules explicitly instead of ignoring them. Start with a curated pack of at most 30 rules from SigmaHQ; check the current rule license and keep attribution. Done when: a test runs rules against fixture events and unsupported features are listed.
- T2.4 Detections store (gate G6). A `detections` table: rule id, source (`sigma`, `hunt`, `yara`), event references, time. It is separate from AI verdicts and ground truth. Link detections to timelines. By default rule hits are not given to the LLM in evaluation cohorts.
- T2.5 MITRE ATT&CK. A pinned ATT&CK Enterprise snapshot reduced to a compact JSON (technique id, name, tactics, parent) with the ATT&CK version recorded; no runtime download; check terms and keep attribution. Three separate label sets: dataset ground-truth techniques, AI-predicted techniques (validated against the list, flagged as predictions), rule-mapped techniques (Sigma tags, YARA metadata). Technique-level evaluation (exact, parent, tactic) reported apart from the malicious/benign metrics. Coverage matrix and an ATT&CK Navigator layer export.
- T2.6 Rule evaluation. Per-technique detection rate and false positives of Sigma rules on the S1 data, side by side with AI triage. Report where each wins.
- T2.7 Stretch: rule fragility. Safe log-level mutations of synthetic events (renamed fields, encoding changes, case changes) to measure how fast each Sigma rule breaks. Output a fragility score per rule.

Done when: the DSL, Sigma and MITRE features all run on EVTX-derived data with tests, documented limits, and separate metrics for rules and AI.

Step-end teach-back: five questions on the DSL grammar, why the canonical field layer exists, Sigma condition handling, the three label sets, and why rule hits are hidden from the LLM by default.

---

## S3 — YARA (4 to 6 weeks)

Goal: safe file scanning linked to alerts and ATT&CK.

- T3.1 Design (report only). Workflow, limits, allowed directories, no execution, no archive extraction, resource limits, how results link to alerts by hash, how rules carry ATT&CK metadata. Ask gate G7.
- T3.2 Scanner module as an optional extra (the base install must work without it). Compile errors surfaced clearly; per-file size limit; timeout; scan runs in a separate process with limits; no network. Done when: it degrades gracefully when YARA is not installed.
- T3.3 Rule pack. Original simple rules plus a small curated set from licensed sources (check licenses). Rule metadata includes technique ids.
- T3.4 Integration. File hash to enrichment lookup; matches stored in `detections` (source `yara`); API endpoint for scanning a registered directory with limits (upload only with strict limits); dashboard display comes in S4.
- T3.5 Tests with harmless files only (the standard EICAR test string, benign files). Adversarial tests: path traversal, oversized files, archives, slow rules (timeouts).

Done when: scans work offline on harmless samples, limits are enforced, matches appear in the investigation data, and no malware exists in the repository.

Step-end teach-back: five questions on why files are never executed, how limits and timeouts protect the host, rule licensing, hash linking, and the optional-dependency design.

---

## S4 — Dashboard completeness (3 to 4 weeks)

- T4.1 Alert management: backend `GET /api/alerts` with pagination caps and filters (dataset, event type, host, user, time range); view with search, sort and detail panel; raw data shown as plain text, never HTML.
- T4.2 Threat intelligence view: per-provider status (`ok`, `not_found`, `rate_limited`, `unavailable`), compact summary, lookup time; wording must say "unavailable is not clean".
- T4.3 Hunting UI: query editor with grammar help, saved queries, result export.
- T4.4 Detections and coverage: Sigma rule list and hits, ATT&CK matrix heatmap, YARA results.
- T4.5 Analyst disposition: confirm or override a verdict, stored separately from AI output and ground truth.
- T4.6 Quality: loading, empty and error states, safe rendering, API contract tests, a visible "AI output needs human review" notice.
- T4.7 End-to-end smoke test (gate G8) and screenshots for the README.

Done when: every view works on a populated database, tests and build pass, and screenshots exist.

---

## S5 — Platform: PostgreSQL, Docker, CI (4 to 6 weeks)

- T5.1 Database abstraction and Alembic baseline (gate G9). PostgreSQL schema with JSONB and GIN index for raw records, optional time partitioning, a separate schema and role for ground truth so the triage service cannot read labels, a read-only role with `statement_timeout` for hunting. Run the same tests on SQLite and PostgreSQL.
- T5.2 Docker compose for API, dashboard and PostgreSQL with memory caps (about 3 GB total), non-root users, no secrets in images, health checks.
- T5.3 CI (GitHub Actions): backend and dashboard tests, lint, type check (`ruff`, `mypy`), `bandit`, `pip-audit`, secret scanning, SBOM. Any dev-only tool needs a one-line justification.
- T5.4 Job queue in PostgreSQL (`FOR UPDATE SKIP LOCKED`) and a worker process; idempotent jobs; retries with backoff.
- T5.5 Backup and restore notes with a tested restore.

Done when: a fresh clone starts with one compose command, CI is green, and tests pass on both databases.

---

## S6 — Security and governance (4 to 6 weeks)

- T6.1 Threat model (STRIDE) and a data-flow diagram of TriageLens itself, in `docs/THREAT_MODEL.md`. Report first, then fixes.
- T6.2 Authentication and roles: `read-only`, `analyst`, `admin`; strong password hashing (argon2id); token or session handling; login rate limiting; every route protected except health; localhost by default; a test per role per route.
- T6.3 Audit log: append-only and hash-chained (views, verdicts, overrides, logins, configuration changes); a verification command that detects tampering; database permissions that forbid updates and deletes.
- T6.4 Hardening: request size limits, API rate limits, SSRF guard (allowlist) for enrichment calls, secret handling review.
- T6.5 LLM safety (gate G10): extend the prompt-injection suite and measure results with sample sizes; optional local or on-prem provider through the existing provider interface; an egress policy for sensitive data; quota and cost guard.
- T6.6 Observability: structured JSON logs with request ids, a metrics endpoint, a readiness check that verifies the database.

Done when: unauthorized access is blocked and tested on every route, the audit chain verifies, and the threat model has a mitigation or accepted risk for every item.

---

## S7 — Go and Rust components (6 to 8 weeks; gate G11 first)

Rule: each component gets a written contract first, a Python reference implementation to compare against, and a measurement that justifies it. If a measurement shows no benefit, record that honestly in an ADR.

- T7.1 Contracts (report only): message schema (JSON), queue handoff through PostgreSQL, authentication between services, backpressure behavior.
- T7.2 Rust EVTX worker (`services/evtx-worker`): uses the `evtx` crate, emits normalized NDJSON; differential test against the Python adapter on the same files; fuzz-style tests with corrupt files; no network access.
- T7.3 Rust YARA worker (`services/yara-worker`): uses YARA-X in a sandboxed process with CPU, memory and time limits; same results as the Python scanner on the test samples.
- T7.4 Go ingestion gateway (`services/gateway`): HTTP receiver and syslog receiver, token or mutual TLS authentication, batching, backpressure, writes to the PostgreSQL queue; a minimal file-tail collector; static binary; unit and load tests.
- T7.5 Load test and decision record: compare Python only against Go and Rust paths on throughput, memory and latency on the 8 GB machine; keep what earns its place.
- T7.6 CI builds for both toolchains (release builds in CI, not on the laptop).

Done when: each worker passes differential tests, contracts are documented and tested, and the ADR states measured results.

---

## S8 — Assurance and release (3 to 4 weeks)

- T8.1 Web scan (for example OWASP ZAP baseline) against the compose stack; fix or accept findings with reasons.
- T8.2 Container and dependency scans; publish the SBOM.
- T8.3 Performance report with real numbers and limits.
- T8.4 Standards mapping table (OWASP ASVS, OWASP LLM Top 10, NIST SSDF) with evidence links for each claimed control, and a list of controls not met.
- T8.5 Runbooks: backup and restore, key rotation, incident response for TriageLens itself.
- T8.6 Docs consolidation: updated ADR index, README rewrite (architecture, setup, real results, limits), architecture diagram, `TASKS.md` current.
- T8.7 Demo video and screenshots.
- T8.8 Release tag `v1.0`, license and attribution check for rules, data and ATT&CK.

Done when: a stranger can clone, start and verify the project from the README, and every claim in it has evidence.

---

## 5. Anti-patterns (stop and ask the owner if you notice one)

- Adding a policy layer, cohort type or ADR the task did not ask for.
- Test frameworks or mocks in production code.
- A result quoted without its sample size and interval.
- Rule detections or dataset labels reaching a prompt.
- Silent fallbacks (a different model, provider or parser) without recording what actually ran.
- Reports with summaries but no real command output.
- Reading large documents "for context" when a search would do.
