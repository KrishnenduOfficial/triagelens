"""Offline regressions for Gemini request compatibility and smoke checks."""

import httpx
import pytest

from scripts.check_connections import check_gemini, main
from scripts.diagnose_gemini import diagnose_gemini


def test_smoke_does_not_truncate_thinking_and_requires_actual_text(monkeypatch):
    calls = []

    def send(url, **kwargs):
        calls.append(kwargs)
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": "OK"}]}}]
        })

    monkeypatch.setattr(httpx, "post", send)
    ok, message = check_gemini("canary-key", "gemini-3.8-flash", 30)
    assert ok
    assert calls[0]["json"]["generationConfig"] == {
        "thinkingConfig": {"thinkingLevel": "low"}
    }
    assert "parsing: OK" in message


@pytest.mark.parametrize("body", [
    {"candidates": []}, {"text": "not a Gemini response"},
    {"candidates": [{"content": {"parts": []}}]},
    {"candidates": [{"content": {"parts": [{"thought": True, "text": "hidden"}]}}]},
])
def test_smoke_rejects_empty_or_thinking_only_responses(monkeypatch, body):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: httpx.Response(200, json=body))
    ok, message = check_gemini("canary-key", "gemini-3.8-flash", 30)
    assert not ok
    assert "parsing: FAILED" in message


@pytest.mark.parametrize("arguments,gemini_timeout,provider_timeout", [
    ([], 30, 5), (["--timeout", "9"], 9, 9),
    (["--gemini-timeout", "40"], 40, 5),
    (["--timeout", "9", "--gemini-timeout", "40"], 40, 9),
])
def test_gemini_default_budget_and_explicit_overrides(
    monkeypatch, arguments, gemini_timeout, provider_timeout
):
    from scripts import check_connections as checks
    monkeypatch.setattr(checks, "get_gemini_api_key", lambda: "canary-key")
    monkeypatch.setattr(checks, "get_virustotal_api_key", lambda: "canary-key")
    monkeypatch.setattr(checks, "get_abuseipdb_api_key", lambda: None)
    monkeypatch.setattr(checks, "get_urlhaus_api_key", lambda: None)
    budgets = {}

    def gemini(key, model, timeout):
        budgets["gemini"] = timeout
        return True, "OK"

    def vt(key, indicator, timeout):
        budgets["vt"] = timeout
        return True, "OK"

    monkeypatch.setattr(checks, "check_gemini", gemini)
    monkeypatch.setattr(checks, "check_virustotal", vt)
    assert main(arguments) == 0
    assert budgets == {"gemini": gemini_timeout, "vt": provider_timeout}


def test_gemini_3_triage_omits_custom_temperature():
    payloads = []

    def send(url, **kwargs):
        payloads.append(kwargs["json"])
        return httpx.Response(503, json={})

    result = diagnose_gemini("canary-key", "gemini-3.8-flash", 15, request_sender=send)
    assert result["http_status"] == 503
    assert payloads[0]["generationConfig"] == {"responseMimeType": "application/json"}


def test_smoke_identifies_unavailable_and_quota_without_body_leak(monkeypatch):
    for status, category in [(503, "service_unavailable"), (429, "quota_or_rate_limit")]:
        monkeypatch.setattr(httpx, "post", lambda *a, **k: httpx.Response(status, text="canary-secret"))
        ok, message = check_gemini("canary-secret", "gemini-3.8-flash", 30)
        assert not ok
        assert category in message
        assert "canary-secret" not in message
