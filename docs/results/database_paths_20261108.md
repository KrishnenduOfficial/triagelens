> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Shared database paths - 2026-11-08

Status: **FIXED+VERIFIED** for offline CLI/API/evaluation path resolution
(WIRE-6 follow-up, ADR-044), following explicit implementation approval.
Full operator/live WIRE-6 completion remains pending WIRE-11. No live API calls
were made. Existing databases were not moved, merged, or populated by this task.

## Audit evidence

Read-only checks before implementation found the configured target was
`data/triagelens.db`. Its alerts, timelines, verdicts, and evaluations were all zero.
The separate root `triagelens.db` contained 75 alerts, 18 timelines, 16 verdicts,
and 16 evaluations. In-process API calls using read-only connections returned
HTTP 200 for each: root metrics had total=16, TP=9, TN=6, FP=0, FN=1 and
accuracy=0.9375; the configured file returned zero evaluations. Both database
file hashes were unchanged by those audit reads. These are historical observations,
not successful current primary-model verification.

Actual CLI/API entry-point probes agreed with the same cwd or an absolute shared
environment path. Different cwd values or a separate CLI override selected
different physical files. Whitespace canonical settings returned an empty filename
and ignored the alias; SQLite treated it as temporary storage. Explicit overrides
with missing parent directories failed to open.

## Implemented contract

`config.get_database_path(override=None)` is the shared resolver. CLI and the
evaluation runner now pass explicit overrides through it. API startup already used
the helper and therefore inherits the same rules without separate API path logic.

1. A supplied override wins; an explicit empty/whitespace override raises ValueError.
2. Otherwise choose the first nonblank trimmed DATABASE_PATH or TRIAGELENS_DB_PATH;
   if neither is usable, select data/triagelens.db.
3. Preserve the exact trimmed :memory: sentinel. Each connection has independent
   ephemeral state; it cannot share disk persistence between CLI and API.
4. Resolve disk paths to absolute paths. Relative paths use the source project root
   derived from src/config.py, never the launch working directory. Fully qualified
   absolute paths retain their target. Ambiguous Windows drive-relative/root-relative
   forms are rejected before filesystem operations.
5. Create disk-path parents consistently. Filesystem errors propagate before SQLite
   opens. Resolution creates no database file and never rewrites existing contents.

An override affects only its invocation. To share it with the API, independently
set the API's configuration to that target and restart the API. Injected database
instances and direct low-level DatabaseManager paths retain their original behavior.
The comparison-model script's intentionally separate cache databases are unchanged.

Relative path behavior intentionally changes for launches outside the source root.
Use an absolute path for storage elsewhere. Existing files are preserved without
automatic migration, fallback to populated files, or merging. The default still
selects data/triagelens.db even if the root file contains history. To deliberately
select the latter, configure DATABASE_PATH=triagelens.db in both process environments
(and avoid a conflicting CLI override). No such configuration change was made here.

## Tests and real outputs

Initial new regression file, before implementation:

```text
20 failed, 2 passed, 1 warning in 2.89s
```

First focused verification after the shared resolver:

```text
python -B -m pytest tests/test_database_paths.py tests/test_config.py tests/test_api_wire6.py -q -p no:cacheprovider --tb=short
34 passed, 1 warning in 4.54s
```

Preservation/evaluation cases expanded the complete suite to 430 passing cases.
Final review then reproduced Windows partial-path ambiguity before adding its guard:

```text
2 failed, 25 deselected, 1 warning in 1.29s
```

Final complete offline suite:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
432 passed, 1 warning in 18.33s
```

The warning is the existing Starlette HTTPX TestClient deprecation. All tests run
with the default external-network guard. No dependencies or schema changes were
added. The existing default-path assertion was changed from a relative literal
to an exact absolute project-root path to reflect the approved contract; no
assertion was removed, loosened, or skipped.

New test names in tests/test_database_paths.py (27 parametrized cases):

- test_config_paths_are_absolute_and_independent_of_cwd
- test_blank_canonical_uses_nonblank_alias
- test_blank_environment_paths_use_persistent_default
- test_nonblank_canonical_precedes_alias
- test_explicit_override_precedes_environment_and_creates_parent
- test_explicit_blank_path_is_rejected
- test_explicit_memory_override_remains_memory
- test_windows_partial_paths_cannot_depend_on_current_drive
- test_directory_creation_error_is_not_silenced
- test_resolution_preserves_existing_databases_and_default_selection
- test_evaluation_runner_uses_same_resolver
- test_real_cli_and_api_persist_to_resolved_paths

Five entry-point cases retain real JSON intake, timeline creation, SQLite writes,
and API reads; only external triage and provider dependencies are injected. Fresh
shared databases have one alert, timeline, verdict, and evaluation, and CLI/API
both report TP=1, total=1, accuracy=1.0 across different working directories.
A separate explicit CLI override deliberately leaves the API's configured file
empty, proving overrides do not silently redirect other processes. Evaluation
runner checks use empty timelines and an injected engine, making no model calls.

## Remaining boundaries

An empty selected database still produces zero metrics. Resolving paths does not
import historical data. CLI metrics describe the current run; API metrics describe
persisted history, so equality on a multi-run database is not generally expected.
Operator/live verification with a successful primary-model response remains
pending the paused Gemini quota issue. No new successful model claim is made.
