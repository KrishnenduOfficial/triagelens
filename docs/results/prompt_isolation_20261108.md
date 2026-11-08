# Recursive structured prompt isolation — 2026-11-08

Status: **FIXED+VERIFIED within the structured telemetry boundary** (ADR-040).
WIRE-11 remains paused and unresolved. This task made no live API calls.

## Reproduced defect

The original prompt builder removed metadata only one dictionary level below an
allow-listed root. Deeper dictionaries and lists could send ground-truth labels,
technique IDs, source filenames, and source IDs to the model. Case/separator
variants also bypassed exclusions. Reproduction intercepted the actual outbound
request through an injected sender; no provider was contacted.

New regression tests before implementation:

```text
26 failed, 1 passed in 0.49s
```

## Change and guarantees tested

The root allow-list remains in place. A recursive copy filters structured values
under accepted telemetry fields. Forbidden key matching handles case and separator
variants and includes source IDs and grouping keys. Complete standalone technique
IDs and classification values are omitted at every traversed level. Containers
left empty by filtering are removed while their event remains available.

The tests capture the prompt after the ordinary structural/string secret-masking
steps. They verify retained telemetry and independent VirusTotal detection counts,
and compare the entire source timeline before/after analysis to detect mutation.
False, zero, null, large identifiers, relative/absolute paths, command lines, and
addresses remain intact. The filter is scoped to alert telemetry so independent
provider statistics such as `stats.malicious` retain their evidentiary meaning.

A preservation edge case caught overbroad punctuation normalization of `./benign`:

```text
1 failed in 0.29s
```

Value normalization now handles classification separators (spaces, underscores,
hyphens) without stripping path punctuation. The final suite verifies that case.

## Scope and limitations

Filtering recognizes known structured metadata and standalone label/ID values.
Free-form strings are preserved, including encoded JSON strings and prose that
mentions technique IDs or labels. Ingestion adapters remain responsible for
keeping evaluation/provenance metadata out of observable text. Independent
provider summaries use their existing separate projection. This fix does not
claim universal protection against arbitrary aliases or metadata embedded in text,
nor validate historical benchmark accuracy or future dataset adapters.

## Final verification

```text
python -B -m pytest -q -p no:cacheprovider --tb=short
326 passed, 1 warning in 9.42s
```

All 27 new cases in `tests/test_prompt_isolation.py` passed. Existing tests were
preserved. The default pytest network guard was enabled. The remaining warning is
the existing Starlette HTTPX TestClient deprecation. No dependencies were added.
