#!/usr/bin/env python3
"""Operator-only primary Gemini triage check (WIRE-11).

Uses synthetic evidence, the real engine, no cache, no fallback, and one request.
Unlike the lightweight connectivity probe, success requires a validated verdict.
Tests must inject a sender; live requests belong only in manual operator runs.
"""

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from src.config import get_gemini_api_key, get_gemini_model
from src.engine.llm import GeminiTriageEngine
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline


def diagnose_gemini(
    api_key: str,
    model: str,
    timeout: float,
    *,
    request_sender: Optional[Callable[..., httpx.Response]] = None,
    clock: Callable[[], float] = time.perf_counter,
) -> Dict[str, Any]:
    """Return metadata only; never return exception messages or response content."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be finite and greater than zero.")
    result: Dict[str, Any] = {
        "mode": "primary_only_triage",
        "requested_model": model.replace(api_key, "[redacted]") if api_key else model,
        "answering_model": None,
        "success": False,
        "schema_valid": False,
        "failure_category": None,
        "http_status": None,
        "elapsed_ms": 0.0,
        "timeout_seconds": timeout,
        "cache_enabled": False,
        "fallback_count": 0,
        "request_count": 0,
    }
    if not api_key:
        result["failure_category"] = "missing_api_key"
        return result
    if api_key in model:
        result["failure_category"] = "invalid_configuration"
        return result

    def send(url: str, **kwargs: Any) -> httpx.Response:
        result["request_count"] += 1
        sender = request_sender if request_sender is not None else httpx.post
        try:
            response = sender(url, **kwargs)
        except httpx.ReadTimeout:
            result["failure_category"] = "read_timeout"
            raise
        except httpx.ConnectTimeout:
            result["failure_category"] = "connect_timeout"
            raise
        except httpx.TimeoutException:
            result["failure_category"] = "other_timeout"
            raise
        except httpx.RequestError:
            result["failure_category"] = "network_error"
            raise
        result["http_status"] = response.status_code
        if response.status_code != 200:
            result["failure_category"] = "http_error"
        else:
            try:
                data = response.json()
                if not isinstance(data, dict):
                    result["failure_category"] = "invalid_response"
            except (ValueError, TypeError):
                result["failure_category"] = "invalid_response"
        return response

    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alert = NormalizedAlert(
        source_dataset="connectivity_diagnostic",
        source_file="synthetic-memory",
        timestamp=timestamp,
        event_type="ProcessCreate",
        original_record={
            "ProcessName": "explorer.exe", "CommandLine": "explorer.exe",
            "host": "DIAGNOSTIC-HOST", "user": "diagnostic-user",
        },
    )
    timeline = ThreatTimeline(
        grouping_key="diagnostic", alerts=[alert], total_events=1,
        start_time=timestamp, end_time=timestamp,
    )
    engine = GeminiTriageEngine(
        api_key=api_key, model=model, timeout=timeout,
        fallback_models=[], enable_cache=False, request_sender=send,
        include_error_details=False,
    )
    start = clock()
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
        if result["failure_category"] is None:
            result["failure_category"] = "unexpected_error"
    finally:
        result["elapsed_ms"] = round(max(0.0, clock() - start) * 1000, 1)
    return result


def positive_timeout(value: str) -> float:
    """Reject invalid budgets without echoing potentially sensitive input."""
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Timeout must be a positive finite number.") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("Timeout must be a positive finite number.")
    return timeout


def main(
    argv: Optional[List[str]] = None,
    *,
    request_sender: Optional[Callable[..., httpx.Response]] = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Inspect configuration without a request.")
    parser.add_argument("--timeout", type=positive_timeout, default=15.0,
                        help="HTTP timeout in seconds (default: engine's 15 seconds).")
    args = parser.parse_args(argv)
    key = get_gemini_api_key()
    if args.dry_run:
        print(json.dumps({"mode": "dry_run", "key_configured": bool(key),
                          "cache_enabled": False, "fallback_count": 0, "request_count": 0}))
        return 0
    result = diagnose_gemini(key or "", get_gemini_model(), args.timeout,
                             request_sender=request_sender)
    print(json.dumps(result))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
