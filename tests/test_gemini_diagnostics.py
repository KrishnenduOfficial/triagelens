"""Offline coverage for primary-only Gemini triage diagnostics."""

import json

import httpx
import pytest

from scripts.diagnose_gemini import diagnose_gemini, main


class StubSender:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def response_for(verdict):
    return httpx.Response(200, json={
        "candidates": [{"content": {"parts": [{"text": json.dumps(verdict)}]}}]
    })


def test_primary_only_valid_verdict_uses_real_prompt_and_no_cache(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "must-never-be-called")
    sender = StubSender(response_for({
        "severity": "LOW", "confidence_score": 0.7, "summary": "Synthetic test",
        "reasoning": ["Routine process"], "recommended_actions": ["Review"],
        "uncertainty_level": "HIGH", "missing_information": ["Parent process"],
    }))
    ticks = iter([10.0, 10.25])
    for index in range(2):
        result = diagnose_gemini("canary-secret", "primary-test", 7.0,
                                 request_sender=sender,
                                 clock=(lambda: next(ticks)) if index == 0 else (lambda: 20.0))
        assert result["success"] and result["schema_valid"]
        assert result["answering_model"] == "primary-test"
        assert result["cache_enabled"] is False
        assert result["fallback_count"] == 0
        assert result["elapsed_ms"] == (250.0 if index == 0 else 0.0)
    assert len(sender.calls) == 2
    url, kwargs = sender.calls[0]
    assert url.endswith("/primary-test:generateContent")
    assert kwargs["timeout"] == 7.0
    assert "FORENSIC_EVIDENCE" in kwargs["json"]["contents"][0]["parts"][0]["text"]
    assert "systemInstruction" in kwargs["json"]
    assert "ground_truth_label" not in json.dumps(kwargs["json"])
    assert "maxOutputTokens" not in kwargs["json"]["generationConfig"]


@pytest.mark.parametrize("error,category", [
    (httpx.ReadTimeout("canary-secret"), "read_timeout"),
    (httpx.ConnectTimeout("canary-secret"), "connect_timeout"),
    (httpx.ConnectError("canary-secret"), "network_error"),
    (RuntimeError("canary-secret"), "unexpected_error"),
])
def test_failure_categories_never_expose_exception_details(error, category, caplog):
    result = diagnose_gemini("canary-secret", "primary-test", 5,
                             request_sender=StubSender(error=error))
    assert not result["success"]
    assert result["failure_category"] == category
    assert "canary-secret" not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("response,category", [
    (httpx.Response(429, text="canary-secret"), "http_error"),
    (httpx.Response(200, text="canary-secret"), "invalid_response"),
    (httpx.Response(200, json=[]), "invalid_response"),
    (response_for({"severity": "INVALID", "summary": "canary-secret"}), "invalid_verdict"),
    (httpx.Response(200, json={"candidates": []}), "invalid_verdict"),
])
def test_http_and_schema_failures_are_safe(response, category, caplog):
    sender = StubSender(response)
    result = diagnose_gemini("canary-secret", "primary-test", 5, request_sender=sender)
    assert result["failure_category"] == category
    assert not result["schema_valid"]
    assert len(sender.calls) == 1
    assert "canary-secret" not in json.dumps(result) + caplog.text


def test_dry_run_does_not_send(monkeypatch, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "canary-secret")
    sender = StubSender(error=AssertionError("No requests allowed"))
    assert main(["--dry-run"], request_sender=sender) == 0
    assert not sender.calls
    output = capsys.readouterr().out
    assert json.loads(output)["mode"] == "dry_run"
    assert "canary-secret" not in output


def test_missing_key_is_failure_without_network(monkeypatch, capsys):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    sender = StubSender()
    assert main([], request_sender=sender) == 1
    assert not sender.calls
    assert json.loads(capsys.readouterr().out)["failure_category"] == "missing_api_key"


def test_cli_success_withholds_verdict_content(monkeypatch, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "canary-secret")
    monkeypatch.setenv("GEMINI_MODEL", "primary-test")
    sender = StubSender(response_for({
        "severity": "LOW", "confidence_score": 0.7, "summary": "canary-verdict-content",
        "reasoning": [], "recommended_actions": [],
    }))
    assert main(["--timeout", "8"], request_sender=sender) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["answering_model"] == "primary-test"
    assert "canary-verdict-content" not in output
    assert "canary-secret" not in output


def test_cli_timeout_fails_without_exposing_details(monkeypatch, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "canary-secret")
    sender = StubSender(error=httpx.ReadTimeout("canary-secret"))
    assert main([], request_sender=sender) == 1
    output = capsys.readouterr().out
    assert json.loads(output)["failure_category"] == "read_timeout"
    assert "canary-secret" not in output


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf"])
def test_invalid_timeout_rejected_before_network(timeout):
    sender = StubSender()
    with pytest.raises(SystemExit) as exc:
        main(["--timeout", timeout], request_sender=sender)
    assert exc.value.code == 2
    assert not sender.calls
