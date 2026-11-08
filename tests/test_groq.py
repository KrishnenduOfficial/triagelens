"""Offline Groq integration, privacy, provenance and failure regressions."""

from copy import deepcopy
import json
import logging
from uuid import uuid4

import httpx
import pytest

from scripts import diagnose_groq as diagnostic
from src import config
from src.engine.groq import GroqTriageEngine
from src.engine.llm import LLMResponseCache
from conftest import PipelineTestEngine
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline


MODEL = "openai/gpt-oss-120b"
ASSESSMENT = {"severity": "LOW", "confidence_score": 0.7, "summary": "Synthetic alert",
              "reasoning": ["Routine process"], "recommended_actions": ["Review telemetry"],
              "uncertainty_level": "HIGH", "missing_information": ["Parent process"]}


def completion(assessment=None, *, model=MODEL, finish="stop"):
    return {"model": model, "choices": [{"finish_reason": finish, "message": {
        "role": "assistant", "content": json.dumps(assessment or ASSESSMENT)}}]}


def timeline():
    return ThreatTimeline(timeline_id=uuid4(), grouping_key="private-dataset-label",
                          alerts=[NormalizedAlert(source_dataset="secret-source", source_file="private-file",
                                                  event_type="ProcessCreate", ground_truth_label="malicious",
                                                  original_record={"ProcessName": "sample.exe",
                                                                   "CommandLine": "contact analyst@example.com",
                                                                   "Details": {"ground_truth": "malicious",
                                                                               "verdict": "CRITICAL"}})],
                          total_events=1)


def test_groq_wire_contract_and_prompt_privacy():
    calls = []
    def send(url, **kwargs):
        calls.append((url, kwargs))
        return httpx.Response(200, json=completion())
    engine = GroqTriageEngine(api_key="offline-canary-key", request_sender=send, enable_cache=False)
    verdict = engine.analyze_timeline(timeline())
    assert verdict and verdict.model_name == MODEL
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert kwargs["headers"]["Authorization"] == "Bearer offline-canary-key"
    assert "x-goog-api-key" not in kwargs["headers"]
    payload = kwargs["json"]
    assert payload["model"] == MODEL and payload["reasoning_effort"] == "low"
    assert payload["max_completion_tokens"] == 4096
    assert "generationConfig" not in payload and "contents" not in payload
    assert [message["role"] for message in payload["messages"]] == ["system", "user"]
    user = payload["messages"][1]["content"]
    assert "FORENSIC_EVIDENCE" in user and "sample.exe" in user
    for forbidden in ("private-dataset-label", "secret-source", "private-file", "ground_truth",
                      '"verdict"', "analyst@example.com", "offline-canary-key"):
        assert forbidden not in user
    schema = payload["response_format"]["json_schema"]
    assert schema["strict"] is True
    assert schema["schema"]["additionalProperties"] is False
    assert set(schema["schema"]["required"]) == set(ASSESSMENT)


@pytest.mark.parametrize("field,value", [
    ("severity", "unknown"), ("confidence_score", 1.1), ("confidence_score", "0.7"),
    ("summary", ""), ("reasoning", "invented"), ("missing_information", None),
    ("uncertainty_level", "unknown"), ("model_name", "forged-model"),
])
def test_invalid_assessments_are_unavailable(field, value):
    data = {**ASSESSMENT, field: value}
    engine = GroqTriageEngine(api_key="offline", request_sender=lambda *a, **k: httpx.Response(200, json=completion(data)))
    assert engine.analyze_timeline(timeline()) is None


@pytest.mark.parametrize("mutation", ["truncated", "refusal", "tools", "wrong_model", "empty",
                                      "no_choices", "bad_json", "markdown", "missing_field"])
def test_incomplete_or_mismatched_responses_are_unavailable(mutation):
    response = completion()
    message = response["choices"][0]["message"]
    if mutation == "truncated": response["choices"][0]["finish_reason"] = "length"
    elif mutation == "refusal": message["refusal"] = "refused"
    elif mutation == "tools": message["tool_calls"] = [{"id": "unexpected"}]
    elif mutation == "wrong_model": response["model"] = "other-model"
    elif mutation == "empty": message["content"] = None
    elif mutation == "no_choices": response["choices"] = []
    elif mutation == "bad_json": message["content"] = "not json"
    elif mutation == "markdown": message["content"] = "```json\n" + message["content"] + "\n```"
    else:
        data = deepcopy(ASSESSMENT)
        del data["missing_information"]
        message["content"] = json.dumps(data)
    engine = GroqTriageEngine(api_key="offline", request_sender=lambda *a, **k: httpx.Response(200, json=response))
    assert engine.analyze_timeline(timeline()) is None


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 503])
def test_errors_never_retry_by_default_or_leak_credentials(status, caplog):
    calls = []
    def send(*args, **kwargs):
        calls.append(args)
        return httpx.Response(status, text="offline-canary-secret patient@example.com")
    with caplog.at_level(logging.DEBUG):
        engine = GroqTriageEngine(api_key="offline-canary-secret", request_sender=send)
        assert engine.analyze_timeline(timeline()) is None
    assert len(calls) == 1
    assert "offline-canary-secret" not in caplog.text and "patient@example.com" not in caplog.text


def test_explicit_fallback_records_actual_model_and_cache_origin():
    calls = []
    def send(url, **kwargs):
        model = kwargs["json"]["model"]
        calls.append(model)
        return httpx.Response(429) if model == MODEL else httpx.Response(200, json=completion(model=model))
    engine = GroqTriageEngine(api_key="offline", request_sender=send, fallback_models=["openai/gpt-oss-20b"])
    sample = timeline()
    first = engine.analyze_timeline(sample)
    assert first and first.model_name == "openai/gpt-oss-20b"
    assert engine.analyze_timeline(sample).verdict_id == first.verdict_id
    assert calls == [MODEL, "openai/gpt-oss-20b"]


def test_provider_identity_separates_caches_even_with_same_model_name():
    cache = LLMResponseCache()
    sample = timeline()
    legacy = PipelineTestEngine(api_key="offline", model=MODEL, fallback_models=[], cache=cache,
        request_sender=lambda *a, **k: httpx.Response(200, json={"text": json.dumps(ASSESSMENT)}))
    old = legacy.analyze_timeline(sample)
    calls = []
    def send(*a, **k):
        calls.append(k)
        return httpx.Response(200, json=completion())
    engine = GroqTriageEngine(api_key="offline", cache=cache, request_sender=send)
    fresh = engine.analyze_timeline(sample)
    assert old and fresh and fresh.verdict_id != old.verdict_id
    assert engine.analyze_timeline(sample).verdict_id == fresh.verdict_id
    assert len(calls) == 1


def test_groq_configuration_is_independent_and_defaults_to_no_fallback(monkeypatch):
    for name in ("GROQ_API_KEY", "GROQ_MODEL", "GROQ_FALLBACK_MODELS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "must-not-be-used")
    monkeypatch.setenv("GEMINI_MODEL", "must-not-be-used")
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "must-not-be-used")
    assert config.get_groq_api_key() is None
    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        GroqTriageEngine()
    monkeypatch.setenv("GROQ_API_KEY", " offline-placeholder ")
    monkeypatch.setenv("GROQ_MODEL", " ")
    assert config.get_groq_api_key() == "offline-placeholder"
    assert GroqTriageEngine().model == MODEL
    assert GroqTriageEngine().fallback_models == []
    monkeypatch.setenv("GROQ_FALLBACK_MODELS", "openai/gpt-oss-20b, ,openai/gpt-oss-20b")
    assert config.get_groq_fallback_models() == ["openai/gpt-oss-20b"]


@pytest.mark.parametrize("kwargs", [{"model": "untrusted-model"}, {"api_key": "key\r\ninject"},
                                    {"timeout": 0}, {"timeout": float("inf")},
                                    {"fallback_models": ["unsupported-provider-model"]}])
def test_invalid_configuration_fails_before_request(kwargs):
    with pytest.raises(ValueError):
        GroqTriageEngine(**{"api_key": "offline", **kwargs})


@pytest.mark.parametrize("status,category", [(200, None), (401, "auth_error"),
    (403, "permission_denied"), (429, "quota_or_rate_limit"), (503, "service_unavailable")])
def test_diagnostic_single_attempt_metadata_only(status, category):
    calls = []
    def send(url, **kwargs):
        calls.append(kwargs)
        return httpx.Response(status, json=completion())
    result = diagnostic.diagnose_groq("canary-private-key", MODEL, request_sender=send)
    assert result["request_count"] == len(calls) == 1
    assert result["http_status"] == status
    assert result["success"] is (status == 200)
    assert result["failure_category"] == category
    assert not result["cache_enabled"] and result["fallback_count"] == 0
    assert "canary-private-key" not in json.dumps(result)
    assert "Synthetic alert" not in json.dumps(result)


def test_diagnostic_timeout_dry_run_and_config_logging(monkeypatch, capsys, caplog):
    def timeout(*a, **k): raise httpx.ReadTimeout("private-error-content")
    result = diagnostic.diagnose_groq("offline", MODEL, request_sender=timeout, trace=True)
    assert result["failure_category"] == "read_timeout" and result["request_count"] == 1
    assert not result["schema_valid"] and result["http_status"] is None
    monkeypatch.setenv("GROQ_API_KEY", "canary-private-key")
    monkeypatch.setenv("GROQ_MODEL", MODEL)
    assert diagnostic.main(["--dry-run"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["configuration_valid"] and output["request_count"] == 0
    with caplog.at_level(logging.INFO):
        summary = config.validate_config()
    assert summary["llm_provider"] == "groq" and summary["groq_configured"]
    assert "canary-private-key" not in caplog.text


def test_bare_groq_tokens_are_scrubbed_before_external_transmission():
    token = "gsk_" + "X" * 52
    sample = timeline()
    sample.alerts[0].original_record["CommandLine"] = "echo " + token
    calls = []
    def send(*args, **kwargs):
        calls.append(kwargs["json"])
        return httpx.Response(200, json=completion())
    assert GroqTriageEngine(api_key="offline", request_sender=send).analyze_timeline(sample)
    assert token not in json.dumps(calls)


@pytest.mark.parametrize("runner", ["cli", "evaluation", "comparison"])
def test_real_groq_engine_persists_results_visible_to_api(monkeypatch, tmp_path, runner):
    from fastapi.testclient import TestClient
    from src import cli
    from src.api.main import create_app
    from src.engine.database import DatabaseManager
    from src.engine.enrichment import EnrichmentEngine
    from scripts import run_evaluation, compare_models

    path = str(tmp_path / "groq.db")
    monkeypatch.setenv("DATABASE_PATH", path)
    monkeypatch.setenv("GROQ_API_KEY", "offline-placeholder")
    monkeypatch.setenv("GROQ_MODEL", MODEL)
    monkeypatch.delenv("GROQ_FALLBACK_MODELS", raising=False)
    calls = []
    def send(url, **kwargs):
        assert url == GroqTriageEngine.ENDPOINT
        calls.append(kwargs)
        return httpx.Response(200, json=completion())
    def engine(**kwargs):
        return GroqTriageEngine(**kwargs, request_sender=send)
    module = {"cli": cli, "evaluation": run_evaluation, "comparison": compare_models}[runner]
    monkeypatch.setattr(module, "GroqTriageEngine", engine)
    if runner == "cli":
        monkeypatch.setattr(cli, "EnrichmentEngine", lambda **kwargs: EnrichmentEngine(
            providers={}, daily_quotas={}, **kwargs))
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "fixture.json").write_text(json.dumps([
            {"event_type": "ProcessStart", "host": "offline", "user": "analyst",
             "is_malicious": False, "severity": "LOW"}]), encoding="utf-8")
        result = cli.run_pipeline(data_dir=str(input_dir))
    elif runner == "evaluation":
        result = run_evaluation.run_evaluation_pipeline(timelines=[timeline()])
    else:
        result, _, _ = compare_models.evaluate_model(MODEL, [timeline()], "offline-placeholder",
                                                     cache_db_path=path, pacing_seconds=0)
    assert result["total"] == 1 and len(calls) == 1
    db = DatabaseManager(path)
    try:
        verdict = db.connection.execute("SELECT model_name FROM verdicts").fetchone()
        assert verdict[0] == MODEL
        with TestClient(create_app(db=db)) as client:
            response = client.get("/api/metrics")
        assert response.status_code == 200
        # Model comparison intentionally stores verdict cache only, not evaluation
        # history. Preserve that scope rather than inventing dashboard outcomes.
        assert response.json()["total"] == (0 if runner == "comparison" else 1)
    finally:
        db.close()


def test_persistent_retired_provider_cache_is_preserved_but_not_replayed_as_groq(tmp_path):
    from src.engine.database import DatabaseManager
    from src.engine.provenance import acquire_triage
    db = DatabaseManager(str(tmp_path / "cache.db"))
    sample = timeline()
    try:
        db.init_db()
        db.insert_timeline(sample)
        legacy = PipelineTestEngine(api_key="offline", model=MODEL, fallback_models=[],
            request_sender=lambda *a, **k: httpx.Response(200, json={"text": json.dumps(ASSESSMENT)}))
        old = acquire_triage(legacy, sample, lambda origin: None, persistent_cache=db)
        assert old.verdict and old.cache_provenance
        db.persist_cached_verdict(old.verdict, old.cache_provenance)
        calls = []
        def send(*args, **kwargs):
            calls.append(kwargs)
            return httpx.Response(200, json=completion())
        engine = GroqTriageEngine(api_key="offline", request_sender=send)
        fresh = acquire_triage(engine, sample, lambda origin: None, persistent_cache=db)
        assert fresh.origin == "fresh" and fresh.cache_validation == "rejected"
        assert fresh.verdict and fresh.verdict.verdict_id != old.verdict.verdict_id
        db.persist_cached_verdict(fresh.verdict, fresh.cache_provenance)
        replay = acquire_triage(engine, sample, lambda origin: None, persistent_cache=db)
        assert replay.origin == "cache" and replay.cache_validation == "verified"
        assert replay.verdict.verdict_id == fresh.verdict.verdict_id
        assert len(calls) == 1
        assert db.connection.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0] == 2
    finally:
        db.close()


def test_diagnostic_actual_httpx_client_is_closed_and_refuses_redirect(monkeypatch):
    original = httpx.Client
    clients, calls = [], []
    def handle(request):
        calls.append(request)
        assert request.url == GroqTriageEngine.ENDPOINT
        return httpx.Response(302, headers={"location": "https://other.invalid/"})
    def client(**kwargs):
        assert kwargs["follow_redirects"] is False and kwargs["http2"] is False
        instance = original(transport=httpx.MockTransport(handle), **kwargs)
        clients.append(instance)
        return instance
    monkeypatch.setattr(httpx, "Client", client)
    result = diagnostic.diagnose_groq("offline", MODEL, trace=True)
    assert result["http_status"] == 302 and not result["success"]
    assert len(calls) == 1 and clients[0].is_closed
    assert result["transport_trace"]["response_headers_received"]


@pytest.mark.parametrize("key,model,category", [("", MODEL, "missing_key"),
    ("private-canary", "unsupported-private-canary", "invalid_configuration")])
def test_diagnostic_preflight_never_dispatches_or_echoes_invalid_model(key, model, category):
    def unexpected(*a, **k): pytest.fail("No request should be sent")
    result = diagnostic.diagnose_groq(key, model, request_sender=unexpected)
    assert result["request_count"] == 0 and result["failure_category"] == category
    assert "private-canary" not in json.dumps(result)
