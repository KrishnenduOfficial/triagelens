#!/usr/bin/env python3
"""Live connection smoke test utility for TriageLens (WIRE-5).

Verifies live API connectivity and schema parsing for configured threat
intelligence and AI providers.

CRITICAL SECURITY AND OPERATIONAL MANDATES:
1. NEVER prints, logs, or returns raw API keys or secrets.
2. NEVER prints raw response bodies or payloads (preventing token/reflection leaks).
3. Makes exactly ONE minimal lookup per configured provider using a benign indicator.
4. Supports --dry-run to audit credential presence without network calls.
5. Exits non-zero (1) on any failure; exits 0 on complete success or dry-run.
6. This script is intended solely for manual execution by operators and MUST NEVER
   be executed during automated testing or inside pytest.
"""

import argparse
import math
import os
from pathlib import Path
import sys
import time
from typing import List, Optional, Tuple

# Ensure project root is in sys.path when invoked directly as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
import httpx

from src.config import (
    get_abuseipdb_api_key,
    get_groq_api_key,
    get_groq_model,
    get_urlhaus_api_key,
    get_virustotal_api_key,
)

# Load environment variables from .env
load_dotenv()


def check_groq(api_key: str, model: str, timeout: float) -> Tuple[bool, str]:
    """One minimal generation probe; a successful probe is not a triage verdict."""
    from src.engine.groq import GroqTriageEngine
    from scripts.diagnostic_transport import _withhold_transport_logs

    start = time.perf_counter()
    try:
        engine = GroqTriageEngine(api_key=api_key, model=model, timeout=timeout,
                                 fallback_models=[], enable_cache=False)
        payload = {"model": model, "messages": [{"role": "user", "content": "Reply with OK."}],
                   "max_completion_tokens": 2048}
        if model.startswith("openai/gpt-oss-"):
            payload["reasoning_effort"] = "low"
        with _withhold_transport_logs():
            response = httpx.post(engine.ENDPOINT,
                                  headers={"Authorization": f"Bearer {api_key}"},
                                  json=payload, timeout=timeout)
        ok = False
        if response.status_code == 200:
            try:
                ok = bool(engine._response_text(response.json(), model).strip())
            except (ValueError, TypeError, KeyError, IndexError, AttributeError):
                pass
        elapsed = (time.perf_counter() - start) * 1000
        category = {429: "quota_or_rate_limit", 503: "service_unavailable",
                    401: "auth_error", 403: "permission_denied", 404: "model_not_found"}.get(
                        response.status_code, "invalid_response" if response.status_code == 200 else "http_error")
        suffix = "" if ok else f" | failure: {category}"
        return ok, (f"Groq ({model}): HTTP {response.status_code} | latency: {elapsed:.1f}ms"
                    f" | parsing: {'OK' if ok else 'FAILED'}{suffix}")
    except Exception as exc:
        # Neither response content nor exception text is safe operator output.
        return False, f"Groq: ERROR ({type(exc).__name__}) | parsing: FAILED"


def check_virustotal(api_key: str, indicator: str, timeout: float) -> Tuple[bool, str]:
    """Tests VirusTotal v3 API connectivity with an IP address report."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    start = time.perf_counter()
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        latency_ms = (time.perf_counter() - start) * 1000.0
        status_code = resp.status_code

        parsing_ok = False
        if status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict) and "data" in data and isinstance(data.get("data"), dict):
                    parsing_ok = True
            except Exception:
                parsing_ok = False

        status_str = f"HTTP {status_code}"
        parse_str = "OK" if parsing_ok else "FAILED"
        success = (status_code == 200 and parsing_ok)
        return success, f"VirusTotal: {status_str} | latency: {latency_ms:.1f}ms | parsing: {parse_str}"

    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000.0
        exc_name = type(exc).__name__
        return False, f"VirusTotal: ERROR ({exc_name}) | latency: {latency_ms:.1f}ms | parsing: FAILED"


def check_abuseipdb(api_key: str, indicator: str, timeout: float) -> Tuple[bool, str]:
    """Tests AbuseIPDB API v2 connectivity with an IP check."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": indicator,
        "maxAgeInDays": "90",
    }

    start = time.perf_counter()
    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=timeout)
        latency_ms = (time.perf_counter() - start) * 1000.0
        status_code = resp.status_code

        parsing_ok = False
        if status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict) and "data" in data and isinstance(data.get("data"), dict):
                    parsing_ok = True
            except Exception:
                parsing_ok = False

        status_str = f"HTTP {status_code}"
        parse_str = "OK" if parsing_ok else "FAILED"
        success = (status_code == 200 and parsing_ok)
        return success, f"AbuseIPDB: {status_str} | latency: {latency_ms:.1f}ms | parsing: {parse_str}"

    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000.0
        exc_name = type(exc).__name__
        return False, f"AbuseIPDB: ERROR ({exc_name}) | latency: {latency_ms:.1f}ms | parsing: FAILED"


def check_urlhaus(api_key: Optional[str], indicator: str, timeout: float) -> Tuple[bool, str]:
    """Tests URLhaus API connectivity with a host lookup."""
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Auth-Key"] = api_key
    payload = {"host": indicator}

    start = time.perf_counter()
    try:
        resp = httpx.post(url, headers=headers, data=payload, timeout=timeout)
        latency_ms = (time.perf_counter() - start) * 1000.0
        status_code = resp.status_code

        parsing_ok = False
        if status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict) and "query_status" in data:
                    parsing_ok = True
            except Exception:
                parsing_ok = False

        status_str = f"HTTP {status_code}"
        parse_str = "OK" if parsing_ok else "FAILED"
        success = (status_code == 200 and parsing_ok)
        return success, f"URLhaus: {status_str} | latency: {latency_ms:.1f}ms | parsing: {parse_str}"

    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000.0
        exc_name = type(exc).__name__
        return False, f"URLhaus: ERROR ({exc_name}) | latency: {latency_ms:.1f}ms | parsing: FAILED"


def positive_timeout(value: str) -> float:
    """Validate a bounded caller-selected timeout without echoing input."""
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Timeout must be positive and finite.") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("Timeout must be positive and finite.")
    return timeout


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for connection smoke testing."""
    parser = argparse.ArgumentParser(
        description="Safe live connection smoke test for TriageLens configured providers."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Inspects configured API keys without making external network requests.",
    )
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=None,
        help="Override timeout for all probes (defaults: Groq 30s, other providers 5s).",
    )
    parser.add_argument(
        "--groq-timeout", type=positive_timeout, default=None,
        help="Groq-specific timeout override, taking precedence over --timeout.",
    )
    parser.add_argument(
        "--indicator",
        type=str,
        default="8.8.8.8",
        help="Benign public test indicator for queries (default: 8.8.8.8).",
    )

    args = parser.parse_args(argv)
    provider_timeout = args.timeout if args.timeout is not None else 5.0
    groq_timeout = args.groq_timeout if args.groq_timeout is not None else (
        args.timeout if args.timeout is not None else 30.0
    )

    print("=" * 65)
    print("TriageLens Live Connection Smoke Test")
    print("Connectivity probes only; primary-model triage is verified separately with diagnose_groq.py.")
    print("=" * 65)

    groq_key = get_groq_api_key()
    groq_model = get_groq_model()
    vt_key = get_virustotal_api_key()
    abuse_key = get_abuseipdb_api_key()
    urlhaus_key = get_urlhaus_api_key()

    if args.dry_run:
        print("[DRY-RUN] Checking configured credentials (no network calls):")
        print(f"Groq: {'CONFIGURED (dry-run)' if groq_key else 'SKIPPED (no API key configured)'}")
        print(f"VirusTotal: {'CONFIGURED (dry-run)' if vt_key else 'SKIPPED (no API key configured)'}")
        print(f"AbuseIPDB: {'CONFIGURED (dry-run)' if abuse_key else 'SKIPPED (no API key configured)'}")
        print(f"URLhaus: {'CONFIGURED (Auth-Key present, dry-run)' if urlhaus_key else 'SKIPPED (no API key configured)'}")
        print("Dry run completed cleanly.")
        return 0

    all_passed = True
    tested_count = 0

    # 1. Groq
    if groq_key:
        tested_count += 1
        ok, msg = check_groq(groq_key, groq_model, groq_timeout)
        print(msg)
        if not ok:
            all_passed = False
    else:
        print("Groq: SKIPPED (no API key configured)")

    # 2. VirusTotal
    if vt_key:
        tested_count += 1
        ok, msg = check_virustotal(vt_key, args.indicator, provider_timeout)
        print(msg)
        if not ok:
            all_passed = False
    else:
        print("VirusTotal: SKIPPED (no API key configured)")

    # 3. AbuseIPDB
    if abuse_key:
        tested_count += 1
        ok, msg = check_abuseipdb(abuse_key, args.indicator, provider_timeout)
        print(msg)
        if not ok:
            all_passed = False
    else:
        print("AbuseIPDB: SKIPPED (no API key configured)")

    # 4. URLhaus
    if urlhaus_key:
        tested_count += 1
        ok, msg = check_urlhaus(urlhaus_key, args.indicator, provider_timeout)
        print(msg)
        if not ok:
            all_passed = False
    else:
        print("URLhaus: SKIPPED (no API key configured)")

    print("-" * 65)
    if tested_count == 0:
        print("Notice: No providers had API keys configured; 0 network calls executed.")
        return 0

    if all_passed:
        print(f"All {tested_count} tested connection probes passed successfully.")
        return 0
    else:
        print("One or more connection probes failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
