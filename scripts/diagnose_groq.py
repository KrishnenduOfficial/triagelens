#!/usr/bin/env python3
"""Operator-only, single-attempt Groq triage verification with synthetic evidence."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from src.config import get_groq_api_key, get_groq_model
from src.engine.groq import GroqTriageEngine
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from scripts.diagnostic_transport import TransportTrace, _withhold_transport_logs, positive_timeout


def diagnose_groq(api_key, model, timeout=30.0, *, trace=False, request_sender=None,
                  clock=time.perf_counter):
    """Return metadata only; retain the full prompt and strict verdict validation."""
    positive_timeout(str(timeout))
    result = {
        "mode": "primary_only_triage", "provider": "groq",
        "requested_model": model if model in GroqTriageEngine.SUPPORTED_MODELS else "unsupported",
        "answering_model": None, "success": False, "schema_valid": False,
        "failure_category": None, "http_status": None, "elapsed_ms": 0.0,
        "timeout_seconds": timeout, "cache_enabled": False, "fallback_count": 0, "request_count": 0,
        "transport_trace": {"enabled": trace, "status": "no_events" if trace else "disabled",
                            "events": [], "failure_phase": None,
                            "response_headers_received": False, "truncated": False},
    }
    if not api_key:
        result["failure_category"] = "missing_key"
        return result
    start = clock()
    observer = TransportTrace(result["transport_trace"], clock, start) if trace else None

    def received_headers(response):
        result["http_status"] = response.status_code
        result["transport_trace"]["response_headers_received"] = True

    def send(url, **kwargs):
        result["request_count"] += 1
        try:
            with _withhold_transport_logs():
                if request_sender is not None:
                    if observer is not None:
                        kwargs["extensions"] = {"trace": observer}
                    response = request_sender(url, **kwargs)
                    received_headers(response)
                else:
                    with httpx.Client(http1=True, http2=False, follow_redirects=False,
                                      event_hooks={"response": [received_headers]}) as client:
                        request = client.build_request("POST", url, **kwargs)
                        if observer is not None:
                            request.extensions["trace"] = observer
                        response = client.send(request)
            if response.status_code != 200:
                result["failure_category"] = {
                    401: "auth_error", 403: "permission_denied", 404: "model_not_found",
                    429: "quota_or_rate_limit", 503: "service_unavailable",
                }.get(response.status_code, "http_error")
            return response
        except httpx.RequestError as exc:
            result["failure_category"] = (
                "read_timeout" if isinstance(exc, httpx.ReadTimeout) else
                "connect_timeout" if isinstance(exc, httpx.ConnectTimeout) else
                "timeout" if isinstance(exc, httpx.TimeoutException) else "network_error")
            if observer is not None:
                observer.note_failure()
            raise

    try:
        engine = GroqTriageEngine(api_key=api_key, model=model, timeout=timeout,
                                 fallback_models=[], enable_cache=False, request_sender=send)
    except (ValueError, TypeError):
        result["failure_category"] = "invalid_configuration"
        return result
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    timeline = ThreatTimeline(
        timeline_id=UUID("00000000-0000-4000-8000-000000000054"),
        grouping_key="synthetic-diagnostic",
        alerts=[NormalizedAlert(source_dataset="synthetic", source_file="diagnostic",
                                event_type="ProcessCreate", timestamp=now,
                                original_record={"ProcessName": "diagnostic.exe"})],
        start_time=now, end_time=now, total_events=1,
    )
    try:
        verdict = engine.analyze_timeline(timeline)
        if verdict is not None:
            result["answering_model"] = verdict.model_name
            result["schema_valid"] = True
            result["success"] = verdict.model_name == model
            result["failure_category"] = None if result["success"] else "model_mismatch"
        elif result["failure_category"] is None:
            result["failure_category"] = "invalid_verdict"
    except Exception:
        result["failure_category"] = result["failure_category"] or "unexpected_error"
    finally:
        result["elapsed_ms"] = round(max(0, clock() - start) * 1000, 1)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Check configuration without a request.")
    parser.add_argument("--timeout", type=positive_timeout, default=30.0)
    parser.add_argument("--trace", action="store_true", help="Record only safe transport phases.")
    args = parser.parse_args(argv)
    key, model = get_groq_api_key(), get_groq_model()
    if args.dry_run:
        try:
            GroqTriageEngine(api_key=key or "", model=model, fallback_models=[], enable_cache=False)
            valid = True
        except (ValueError, TypeError):
            valid = False
        print(json.dumps({"mode": "dry_run", "provider": "groq", "key_configured": bool(key),
                          "configuration_valid": valid, "request_count": 0,
                          "cache_enabled": False, "fallback_count": 0}))
        return 0 if valid else 1
    result = diagnose_groq(key or "", model, args.timeout, trace=args.trace)
    print(json.dumps(result))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
