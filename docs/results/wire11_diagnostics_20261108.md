# WIRE-11 diagnostic evidence — 2026-11-08

Status: **REPRODUCED — underlying generation failure unresolved**.
Diagnostic support is implemented; a primary-model transport fix is not claimed.

## Latest finding: daily quota exhaustion confirmed

After the operator requested continued investigation unless quota was explicitly
exhausted, a bounded primary-only check was prepared to retry transient 5xx/network
failures, but its **first** attempt returned confirmed daily quota exhaustion.
No retry was made:

```text
PRIMARY_ATTEMPT={"attempt": 1, "diagnostic": {"mode": "primary_only_triage", "requested_model": "gemini-3.8-flash", "answering_model": null, "success": false, "schema_valid": false, "failure_category": "http_error", "http_status": 429, "elapsed_ms": 1087.5, "timeout_seconds": 30, "cache_enabled": false, "fallback_count": 0, "request_count": 1}, "service": {"http_status": 429, "quota_scopes": ["daily"], "quota_limits": [{"scope": "daily", "limit": 20}], "retry_after_seconds": 26847.0, "service_status": "RESOURCE_EXHAUSTED", "mentions_capacity": false}}
STOP_REASON=confirmed_http_429_no_more_live_requests
```

Live validation pauses under the operator's explicit quota condition. This does
not prove that earlier 503 responses were quota errors. Google's guidance treats
503 as transient service overload and recommends bounded backoff/retry:
[Google's 429/503 guidance](https://discuss.ai.google.dev/t/handling-429-503-errors-from-the-gemini-api/124640).
No new transport workaround, quota bypass, or unverified fix was introduced.

A subsequent single primary-model request returned this safe, derived metadata;
raw response messages, credentials, project identifiers, and generated text were
not printed:

```text
QUOTA_METADATA={"http_status": 429, "elapsed_ms": 1110.7, "quota_scopes": ["daily"], "quota_limits": [{"scope": "daily", "limit": 20}], "retry_after_seconds": 28163.0, "service_status": "RESOURCE_EXHAUSTED", "mentions_free_tier": true, "mentions_billing": true, "mentions_capacity": false, "has_candidate_text": false}
```

This confirms the **current** blocker: an exhausted daily free-tier request quota
with limit 20. The service supplied a retry delay of 28163 seconds (7h 49m 23s).
That delay is guidance from this response, not a guarantee of later availability.
Further live probes are paused to avoid unnecessary requests. No code change can
replenish the provider's quota. Preserve the configured primary and verify actual
primary-only triage once quota becomes available, or after an operator-approved
quota/account change. No account or billing changes were made.

This evidence supersedes the earlier statement that quota scope was unknown. It
does not establish the causes of earlier 503 responses or response-read timeouts.

## Live observations before the diagnostic patch

Requests used configured credentials without printing keys, response bodies, or
verdict content. Triage checks used synthetic telemetry, no cache, and no fallback.

| Probe | Observed result |
|---|---|
| HTTPX primary minimal generation | ReadTimeout, 15.710s |
| Windows curl, matching primary payload | Exit 28, HTTP 000, 20.012s, TLS verify result 0 |
| Primary model metadata | HTTP 200, 1.236s, matching model name |
| Fallback model metadata | HTTP 200, 1.232s, matching model name |
| Fallback generation | HTTP 200, 1.563s, candidates present |
| Primary generation, extended read budget | ReadTimeout, 45.557s |
| Primary generation, forced IPv4 | ReadTimeout, 20.537s |
| Primary plain ping without generation settings | HTTP 200, 9.034s, candidates present (one observation) |
| Actual primary-only triage, 15-second timeout | No valid verdict, 15.500s |
| Actual primary-only triage, 30-second timeout | No valid verdict, 30.173s |
| Actual triage payload without generation settings | ReadTimeout, 30.333s |
| Minimal JSON mode | ReadTimeout, 30.332s |
| Minimal temperature-only mode | ReadTimeout, 30.334s |

HTTPX traces showed successful TCP, TLS, and request transmission followed by a
response-header wait. HTTP/2 was already disabled; no environment proxy/certificate
overrides or discovered proxy schemes were present. DNS returned IPv4 and IPv6.

These observations do not prove an upstream root cause or rule out local network
interception. They contradict treating this as an established Python-only block.
The isolated ping success does not prove that removing generation settings fixes
triage. The engine returned `None` during the 15s/30s checks with detailed logging
suppressed; those two checks alone do not distinguish transport from schema failure.

## Implemented diagnostic contract

`python scripts/diagnose_gemini.py` calls the existing engine with a fixed synthetic
event and explicit `fallback_models=[]`, `enable_cache=False`. It sends one request,
does not persist records, and succeeds only for a validated verdict attributed to
the requested primary. `--dry-run` makes no request. The default timeout remains 15s;
`--timeout` changes only this invocation and must be positive and finite.

Output reports total elapsed time, HTTP status when available, failure category,
schema validity, answering model, request count, and disabled cache/fallback state.
Categories distinguish connection/read/other timeouts, network errors, HTTP errors,
invalid response JSON/envelopes, invalid verdicts, missing credentials, invalid
configuration, model mismatch, and unexpected failures. Exception text and payloads
are withheld, including in the engine's detailed error logs for this invocation.

The initial diagnostic patch left connectivity-probe request behavior unchanged.
The subsequent request corrections below supersede that initial behavior. No IPv4
forcing, proxy bypass, TLS disabling, or automatic retry was introduced.

## Verification

New tests were run before implementation and failed collection with
`ModuleNotFoundError: No module named 'scripts.diagnose_gemini'`.
After initial implementation, the diagnostic, LLM, and connectivity regression
selection reported `50 passed in 0.91s`. Final verification is recorded below.

The final complete suite used the audit's external-connection guard (allowing only
Windows asyncio's internal socket pair), an in-memory default API database, and
`pytest.main(['-q', '-p', 'no:cacheprovider', '--tb=short'])`:

```text
FAILED tests/test_api_wire6.py::test_run_evaluation_end_to_end_mode_with_enrichment
1 failed, 280 passed, 1 warning in 16.16s
AUDIT_NETWORK_ATTEMPTS_BLOCKED=1
```

All 18 new diagnostic cases passed. The one failure is the same pre-existing
credential-dependent enrichment attempt reproduced before this patch; it was not
skipped, relaxed, or fixed as part of this scope. The warning is the existing
Starlette HTTPX TestClient deprecation. No live generation check ran during pytest.

The real CLI dry-run (`python -B scripts/diagnose_gemini.py --dry-run`) exited 0:

```json
{"mode": "dry_run", "key_configured": true, "cache_enabled": false, "fallback_count": 0, "request_count": 0}
```

## Remaining work

* Run the operator diagnostic on the affected machine and a comparison network to
  collect repeatable primary-only results. No post-patch live success is claimed.
* Resolve the actual primary failure before closing WIRE-11 or WIRE-5.
* The separate end-to-end test isolation issue is now fixed; see the final
  verification below. Keep the built-in pytest network guard enabled.

## Follow-up: request corrections and live provider failures

The actual primary-only diagnostic returned HTTP 503 in 8836.6ms. Supported request
comparisons produced HTTP 503 with low thinking (5699.0ms), HTTP 503 with low
thinking and JSON mode removed (5273.5ms), and ReadTimeout with temperature removed
(30239.8ms). The streaming endpoint returned HTTP 429 in 1032.6ms. These observations
do not establish that changing generation settings fixes upstream availability.

Google's current migration guidance recommends default sampling for Gemini 3.
Its thinking guide explains that output-token limits include reasoning tokens.
The local corrections therefore remove the Gemini 3 triage temperature override,
remove the smoke probe's two-token cap, request low thinking for the Gemini 3 smoke
probe, and set its default timeout to 30s. Intelligence probes remain at 5s; explicit
`--timeout` and `--gemini-timeout` overrides are honored. Empty or thought-only
responses no longer count as successful generation. Production triage thinking
effort, default timeout, fallback policy, and TLS verification remain unchanged.

The new regression tests failed before implementation:

```text
10 failed, 1 passed in 0.58s
```

After the changes, the focused Gemini selection reported:

```text
63 passed in 0.82s
```

The corrected real `python -B scripts/check_connections.py` still exited 1:

```text
Google Gemini (gemini-3.8-flash): HTTP 429 | latency: 810.1ms | parsing: FAILED | failure: quota_or_rate_limit
VirusTotal: HTTP 200 | latency: 902.5ms | parsing: OK
AbuseIPDB: HTTP 200 | latency: 2073.3ms | parsing: OK
URLhaus: SKIPPED (no API key configured)
One or more connection probes failed.
```

A subsequent safe quota-metadata probe returned `QUOTA_PROBE_ERROR=ReadTimeout`;
daily versus per-minute quota scope is not known. No primary-only valid verdict
has been obtained. WIRE-11 remains open pending provider availability/quota and
successful real triage. No fallback or metadata success is substituted for this.

Sources: [migration](https://ai.google.dev/gemini-api/docs/latest-model),
[thinking](https://ai.google.dev/gemini-api/docs/generate-content/thinking).

Final guarded suite after request corrections:

```text
FAILED tests/test_api_wire6.py::test_run_evaluation_end_to_end_mode_with_enrichment
1 failed, 291 passed, 1 warning in 9.16s
AUDIT_NETWORK_ATTEMPTS_BLOCKED=1
```

All 11 request-correction cases and 18 diagnostic cases passed. No existing tests
were deleted, skipped, or loosened. Browser inventory reported
`Browsers: Error: The browser access host is unavailable`, so an authenticated
project quota dashboard could not be inspected. Further account-specific diagnosis
requires the operator's model RPM/RPD limit and usage values; no raw key is needed.

## Final follow-up: pytest network isolation fixed

No live API calls were made for this task. Before the fix, the end-to-end test with
dummy credentials failed at the new network guard:

```text
AssertionError: External network disabled during pytest; inject a test sender or provider.
1 failed, 1 warning in 1.34s
```

The test now injects two explicit providers into the real enrichment engine, runs
with credentials absent and present, and verifies provider calls, attached results,
and persisted enrichment rows in addition to its original evaluation assertions.
Six new guard cases cover sync/async HTTP transports, direct TCP connection paths,
and usable injected transports. The guard preserves Windows asyncio's internal
socketpair operation. Production code was unchanged for this isolation fix.

```text
python -B -m pytest tests/test_api_wire6.py tests/test_network_isolation.py -q -p no:cacheprovider --tb=short
10 passed, 1 warning in 1.35s

python -B -m pytest -q -p no:cacheprovider --tb=short
299 passed, 1 warning in 11.52s
```

The full run used the normal pytest entry point without the temporary audit guard.
The remaining warning is Starlette's existing HTTPX TestClient deprecation.
Earlier 280/291-pass results above are historical, pre-isolation-fix observations.
WIRE-11 remains unresolved independently of this successful offline verification.
