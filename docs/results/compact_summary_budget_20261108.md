> Historical verification snapshot. Groq is now the sole runtime provider
> (ADR-055). References below to Gemini, removed tools or unresolved WIRE-11
> describe that earlier state; WIRE-11 is retired from active work after provider
> replacement. Prior model scores are not Groq scores. See
> [current Groq verification](groq_migration_20261108.md).

# Compact intelligence byte budget — 2026-11-08

Status: **FIXED+VERIFIED** within the per-summary contract (WIRE-4, ADR-042).
WIRE-11 remains paused and unresolved. No live API calls were made for this task.

## Reproduced gap

Provider summaries had no serialized byte check. Long VirusTotal labels, AbuseIPDB
country/ISP fields, URLhaus tags/threat fields, unknown-provider fields, and large
numeric counters all exceeded the documented limit in intercepted prompts.
The 100-character ISP cap was insufficient for escaped Unicode. A repeated-email
fixture also showed that masking can expand a fitting projection beyond the cap.

New tests before implementation:

```text
26 failed, 3 passed in 0.42s
```

## Exact contract and implementation

Each `intel_summary` object must occupy **fewer than 800 UTF-8 bytes** from its
opening `{` through closing `}` inside the final evidence JSON string. Measurement
includes the current two-space formatting, ASCII escaping, and six-column nesting.
It excludes the field name, indicator/provider wrapper, surrounding prompt, and
extra quoting/escaping when the prompt is encoded into the outer HTTP JSON body.
Multiple providers each have their own budget. This is not a total token budget.

Complete projected values are redacted before string truncation, using the engine's
scrubber or a default scrubber for standalone utility calls. The ISP cap also follows
redaction so a cut cannot hide a recognizable secret from the masker. One shared
limiter handles every projection branch and the final post-masking payload.
Fitting safe summaries remain unchanged. Oversized summaries reserve space
for `summary_truncated: true`, prioritize counters/scores/reputation/status, and
retain a deterministic fitting subset of optional text and tags. Truncated strings
use complete code points and a `...` suffix; JSON escaping determines byte cost.
Existing ISP/tag count caps now mark their omissions as well.

Numeric signals are not shortened or clamped to fit; oversized/non-finite signals
are omitted and marked. Invalid supplied counters are omitted instead of crashing
triage. Existing defaults for missing counter fields remain unchanged. Full raw
provider records are not modified by projection, budgeting, or masking.

After both masking layers, the engine validates the resulting JSON and enrichment
structure, applies the final limit, and serializes it before computing the response
cache key. Invalid JSON, a non-object payload, non-list enrichments, non-object
entries, or non-object summaries withhold the model request. There is no further
masking transform after final budgeting that could expand the result again.

## Verification

Thirty-six new cases cover both utility output and actual outbound prompt
fragments, all provider branches, Unicode, quotes/backslashes/newlines, masking
growth, 798/799/800/801-byte boundaries, priority preservation, oversized/invalid
counts, unchanged raw records, normal-result repeatability, and fail-closed payloads.
They also verify that redaction precedes truncation, preventing a fake API key
from becoming an unmasked prefix.

The first focused selection passed after the limiter implementation:

```text
90 passed in 0.52s
```

Additional serialization-guard cases reproduced non-object handling before its fix:

```text
2 failed, 1 passed in 0.34s
```

Final review caught that redaction/truncation ordering regression before correction:

```text
1 failed in 0.40s
```

Final complete suite, including all expanded guard and ordering cases:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
376 passed, 1 warning in 8.82s
```

Tests use injected senders with the built-in pytest network guard enabled. Existing
tests were not deleted, skipped, or loosened. The warning is the existing Starlette
HTTPX TestClient deprecation. No dependency or database migration was added.
