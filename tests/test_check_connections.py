"""Tests for live connection smoke test script (WIRE-5).

Verifies that scripts/check_connections.py:
1. Never prints secret API keys under any condition (success, error, or exception).
2. Never prints raw response bodies or payloads.
3. Respects --dry-run without making any network calls.
4. Returns exit code 0 when all tested providers pass.
5. Returns non-zero exit code when any tested provider fails.
6. Gracefully skips unconfigured providers.

CRITICAL MANDATE:
All external HTTP requests are strictly mocked with unittest.mock.
No real network or live API calls are ever executed in automated tests.
"""

import io
from unittest.mock import MagicMock, patch
import httpx
import pytest

from scripts.check_connections import main


CANARY_KEYS = {
    "GROQ_API_KEY": "gsk_FAKE_GROQ_TEST_SECRET_KEY_99999",
    "VIRUSTOTAL_API_KEY": "vt_fake_secret_key_88888888888888888888888888888888",
    "ABUSEIPDB_API_KEY": "abuseipdb_fake_secret_key_777777777777777777777777",
    "URLHAUS_API_KEY": "urlhaus_fake_secret_auth_key_6666666666666666",
}

CANARY_BODY_PAYLOAD = "TOP_SECRET_CANARY_PAYLOAD_LEAK_STRING_DO_NOT_PRINT"


def _setup_mock_env(monkeypatch):
    """Sets up canary keys in environment."""
    for k, v in CANARY_KEYS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")


def test_check_connections_never_prints_keys(capsys, monkeypatch):
    """Verify that under both success and failure, canary API keys are never printed."""
    _setup_mock_env(monkeypatch)

    mock_resp_success = MagicMock(spec=httpx.Response)
    mock_resp_success.status_code = 200
    mock_resp_success.json.return_value = {
        "model": "openai/gpt-oss-120b",
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "PONG"}}],
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0}}, "abuseConfidenceScore": 0},
        "query_status": "ok",
    }

    # Test under success
    with patch("httpx.post", return_value=mock_resp_success), patch("httpx.get", return_value=mock_resp_success):
        exit_code = main([])
        assert exit_code == 0

    out, err = capsys.readouterr()
    combined = out + err
    for key_name, key_val in CANARY_KEYS.items():
        assert key_val not in combined, f"Secret {key_name} was leaked in script output!"

    # Test under HTTP 401 Unauthorized and Exception
    mock_resp_error = MagicMock(spec=httpx.Response)
    mock_resp_error.status_code = 401
    mock_resp_error.json.return_value = {"error": "Invalid API key provided"}
    mock_resp_error.text = f"Error: Invalid key {CANARY_KEYS['VIRUSTOTAL_API_KEY']}"

    with patch("httpx.post", return_value=mock_resp_error), patch("httpx.get", side_effect=httpx.ConnectError("Network unreachable")):
        exit_code = main([])
        assert exit_code == 1

    out, err = capsys.readouterr()
    combined = out + err
    for key_name, key_val in CANARY_KEYS.items():
        assert key_val not in combined, f"Secret {key_name} was leaked during error handling!"


def test_check_connections_never_prints_response_body(capsys, monkeypatch):
    """Verify that response bodies containing arbitrary third-party data or leaks are withheld."""
    _setup_mock_env(monkeypatch)

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = f'{{"leak": "{CANARY_BODY_PAYLOAD}"}}'
    mock_resp.json.return_value = {
        "model": "openai/gpt-oss-120b",
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": CANARY_BODY_PAYLOAD}}],
        "data": {
            "attributes": {"last_analysis_stats": {"malicious": 0}},
            "abuseConfidenceScore": 0,
            "leak": CANARY_BODY_PAYLOAD,
        },
        "query_status": "ok",
    }

    with patch("httpx.post", return_value=mock_resp), patch("httpx.get", return_value=mock_resp):
        exit_code = main([])
        assert exit_code == 0

    out, err = capsys.readouterr()
    combined = out + err
    assert CANARY_BODY_PAYLOAD not in combined, "Raw response payload was leaked to stdout/stderr!"


def test_check_connections_dry_run_makes_no_network_calls(capsys, monkeypatch):
    """Verify that --dry-run checks key configuration without making any HTTP calls."""
    _setup_mock_env(monkeypatch)

    with patch("httpx.post") as mock_post, patch("httpx.get") as mock_get:
        exit_code = main(["--dry-run"])
        assert exit_code == 0
        mock_post.assert_not_called()
        mock_get.assert_not_called()

    out, err = capsys.readouterr()
    combined = out + err
    assert "dry-run" in combined.lower()
    for key_name, key_val in CANARY_KEYS.items():
        assert key_val not in combined, f"Secret {key_name} was leaked during dry-run!"


def test_check_connections_success_exit_code(capsys, monkeypatch):
    """Verify exit code 0 and proper summary when all configured providers pass."""
    _setup_mock_env(monkeypatch)

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": "openai/gpt-oss-120b",
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "PONG"}}],
        "data": {
            "attributes": {"last_analysis_stats": {"malicious": 0}},
            "abuseConfidenceScore": 0,
        },
        "query_status": "ok",
    }

    with patch("httpx.post", return_value=mock_resp), patch("httpx.get", return_value=mock_resp):
        exit_code = main([])
        assert exit_code == 0

    out, _ = capsys.readouterr()
    assert "HTTP 200" in out
    assert "parsing: OK" in out


def test_check_connections_failure_exit_code(capsys, monkeypatch):
    """Verify exit code 1 when a provider encounters HTTP error or parsing failure."""
    _setup_mock_env(monkeypatch)

    # Groq returns 500
    mock_500 = MagicMock(spec=httpx.Response)
    mock_500.status_code = 500
    mock_500.json.side_effect = ValueError("Invalid JSON")

    # VirusTotal returns 200
    mock_200 = MagicMock(spec=httpx.Response)
    mock_200.status_code = 200
    mock_200.json.return_value = {"data": {"attributes": {}}}

    def mock_post_dispatch(url, *args, **kwargs):
        if "api.groq.com" in url:
            return mock_500
        return mock_200

    with patch("httpx.post", side_effect=mock_post_dispatch), patch("httpx.get", return_value=mock_200):
        exit_code = main([])
        assert exit_code == 1

    out, _ = capsys.readouterr()
    assert "FAILED" in out


def test_check_connections_skips_unconfigured_providers(capsys, monkeypatch):
    """Verify that unconfigured providers are reported as SKIPPED and do not trigger failure."""
    for k in CANARY_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("AUTH_KEY", raising=False)

    exit_code = main([])
    assert exit_code == 0

    out, _ = capsys.readouterr()
    assert "SKIPPED (no API key configured)" in out


@pytest.mark.parametrize("arguments,groq_timeout,provider_timeout", [
    ([], 30, 5), (["--timeout", "9"], 9, 9),
    (["--groq-timeout", "40"], 40, 5),
    (["--timeout", "9", "--groq-timeout", "40"], 40, 9),
])
def test_groq_default_budget_and_explicit_overrides(monkeypatch, arguments, groq_timeout, provider_timeout):
    from scripts import check_connections as checks
    monkeypatch.setattr(checks, "get_groq_api_key", lambda: "canary-key")
    monkeypatch.setattr(checks, "get_virustotal_api_key", lambda: "canary-key")
    monkeypatch.setattr(checks, "get_abuseipdb_api_key", lambda: None)
    monkeypatch.setattr(checks, "get_urlhaus_api_key", lambda: None)
    budgets = {}
    def groq(key, model, timeout):
        budgets["groq"] = timeout
        return True, "OK"
    def vt(key, indicator, timeout):
        budgets["vt"] = timeout
        return True, "OK"
    monkeypatch.setattr(checks, "check_groq", groq)
    monkeypatch.setattr(checks, "check_virustotal", vt)
    assert main(arguments) == 0
    assert budgets == {"groq": groq_timeout, "vt": provider_timeout}

