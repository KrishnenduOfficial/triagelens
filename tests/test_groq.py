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
ASSESSMENT = {"disposition": "BENIGN", "severity": "LOW", "confidence_score": 0.7, "summary": "Synthetic alert",
              "reasoning": ["Routine process"], "recommended_actions": ["Review telemetry"],
              "uncertainty_level": "HIGH", "missing_information": ["Parent process"],
              "evidence_basis": {
                  "kind": "benign_support", "decision_refs": [{"evidence_id":"E1","field_path":["event_type"]}],
                  "observations": [{"statement":"Observed event type", "refs":[{"evidence_id":"E1","field_path":["event_type"]}]}],
                  "hypotheses": [], "gaps": [{"category":"process_context", "description":"Parent process",
                      "required_evidence":"Parent process record", "blocks_disposition":False}]}}


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


class FakePacingClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


def test_pacing_token_window_and_request_window_without_sleeping():
    for limits in ((30, 8000, 1500, 60), (2, 8000, 1500, 60)):
        fake = FakePacingClock()
        sends = []
        engine = GroqTriageEngine(api_key="offline", enable_cache=False,
            pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=limits,
            request_sender=lambda *a, **k: (sends.append(fake.now) or httpx.Response(200, json=completion())))
        count = min(limits[0], limits[1] // limits[2]) + 1
        for _ in range(count):
            assert engine.analyze_timeline(timeline())
        assert sends[-1] == 60 and fake.sleeps == [60]


def test_pacing_retry_after_waits_before_fallback_and_honors_budget():
    for budget, expected in ((10, [0, 7]), (6, [0])):
        fake = FakePacingClock()
        sends = []
        def send(*args, **kwargs):
            sends.append(fake.now)
            if len(sends) == 1:
                return httpx.Response(429, headers={"Retry-After": "7"})
            return httpx.Response(200, json=completion(model=kwargs["json"]["model"]))
        engine = GroqTriageEngine(api_key="offline", enable_cache=False,
            fallback_models=["openai/gpt-oss-20b"], request_sender=send,
            pacing_clock=fake.clock, pacing_sleep=fake.sleep,
            pacing_config=(30, 8000, 1500, budget))
        result = engine.analyze_timeline(timeline())
        assert bool(result) == (budget == 10)
        assert sends == expected
        assert fake.sleeps == ([7] if budget == 10 else [])


def test_pacing_retry_after_persists_for_later_analysis_and_accepts_http_date():
    fake = FakePacingClock()
    sends = []
    def send(*args, **kwargs):
        sends.append(fake.now)
        if len(sends) == 1:
            return httpx.Response(429, headers={"Retry-After": "Thu, 01 Jan 1970 00:00:12 GMT"})
        return httpx.Response(200, json=completion())
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_wall_clock=lambda: 0,
        pacing_config=(30, 8000, 1500, 60))
    assert engine.analyze_timeline(timeline()) is None
    assert engine.analyze_timeline(timeline())
    assert sends == [0, 12] and fake.sleeps == [12]


def test_pacing_bounds_cumulative_wait_across_fallbacks():
    fake = FakePacingClock()
    sends = []
    def send(*args, **kwargs):
        sends.append(fake.now)
        return httpx.Response(429, headers={"Retry-After": "4"})
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        fallback_models=["openai/gpt-oss-20b", "qwen/qwen3.8-27b"],
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=(30, 8000, 1500, 7))
    assert engine.analyze_timeline(timeline()) is None
    assert sends == [0, 4] and fake.sleeps == [4]


def test_invalid_retry_after_is_ignored_without_retry():
    fake = FakePacingClock()
    sends = []
    def send(*args, **kwargs):
        sends.append(fake.now)
        return httpx.Response(429, headers={"Retry-After": "invalid"})
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=(30, 8000, 1500, 60))
    assert engine.analyze_timeline(timeline()) is None
    assert sends == [0] and fake.sleeps == []


def test_pacing_accounts_for_actual_usage_even_when_verdict_is_invalid():
    fake = FakePacingClock()
    sends = []
    def send(*args, **kwargs):
        sends.append(fake.now)
        data = completion({**ASSESSMENT, "summary": ""})
        data["usage"] = {"total_tokens": 3500}
        return httpx.Response(200, json=data)
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=(30, 8000, 1500, 60))
    for _ in range(3):
        assert engine.analyze_timeline(timeline()) is None
    assert sends == [0, 0, 60] and fake.sleeps == [60]


@pytest.mark.parametrize("budget,expected", [(60, [0, 25.5]), (25, [0])])
def test_pacing_honors_success_token_headers_and_wait_budget(budget, expected):
    fake = FakePacingClock()
    sends = []
    def send(*args, **kwargs):
        sends.append(fake.now)
        return httpx.Response(200, json=completion(), headers={
            "x-ratelimit-remaining-tokens": "737", "x-ratelimit-reset-tokens": "25.5s"})
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=(30, 8000, 1500, budget))
    assert engine.analyze_timeline(timeline())
    assert bool(engine.analyze_timeline(timeline())) == (budget == 60)
    assert sends == expected
    assert fake.sleeps == ([25.5] if budget == 60 else [])


def test_pacing_uses_token_reset_when_429_has_no_retry_after():
    fake = FakePacingClock()
    sends = []
    def send(*args, **kwargs):
        sends.append(fake.now)
        if len(sends) == 1:
            return httpx.Response(429, headers={"x-ratelimit-reset-tokens": "1m2.5s"})
        return httpx.Response(200, json=completion())
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=(30, 8000, 1500, 63))
    assert engine.analyze_timeline(timeline()) is None
    assert engine.analyze_timeline(timeline())
    assert sends == [0, 62.5] and fake.sleeps == [62.5]


@pytest.mark.parametrize("usage,remaining,reset", [(True, "-1", "nan"),
    ("3500", "many", "1d"), (-1, "100", ""), (None, "100", "inf"),
    (3500.5, "100", "-5s"), ([], "100", "private-canary")])
def test_pacing_ignores_malformed_provider_metadata(usage, remaining, reset):
    fake = FakePacingClock()
    def send(*args, **kwargs):
        return httpx.Response(200, json={**completion(), "usage": {"total_tokens": usage}},
            headers={"x-ratelimit-remaining-tokens": remaining, "x-ratelimit-reset-tokens": reset})
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=(30, 8000, 1500, 60))
    assert engine.analyze_timeline(timeline())
    assert engine.analyze_timeline(timeline())
    assert engine._token_estimate == 1500 and fake.sleeps == []


def test_pacing_withholds_future_requests_after_usage_exceeds_window():
    fake = FakePacingClock()
    sends = []
    def send(*args, **kwargs):
        sends.append(fake.now)
        return httpx.Response(200, json={**completion(), "usage": {"total_tokens": 9000}})
    engine = GroqTriageEngine(api_key="offline", enable_cache=False, request_sender=send,
        pacing_clock=fake.clock, pacing_sleep=fake.sleep, pacing_config=(30, 8000, 1500, 60))
    assert engine.analyze_timeline(timeline())
    assert engine.analyze_timeline(timeline()) is None
    assert sends == [0] and fake.sleeps == []


def test_default_pacing_reserves_4000_tokens(monkeypatch):
    for name in ("GROQ_REQUESTS_PER_MINUTE", "GROQ_TOKENS_PER_MINUTE",
                 "GROQ_ESTIMATED_TOKENS_PER_REQUEST", "GROQ_MAX_WAIT_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    assert config.get_groq_pacing_config() == (30, 8000, 4000, 60.0)


@pytest.mark.parametrize("name,value", [("GROQ_REQUESTS_PER_MINUTE", "0"),
    ("GROQ_TOKENS_PER_MINUTE", "abc"), ("GROQ_ESTIMATED_TOKENS_PER_REQUEST", "8001"),
    ("GROQ_MAX_WAIT_SECONDS", "nan")])
def test_invalid_pacing_configuration_is_rejected(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="pacing"):
        GroqTriageEngine(api_key="offline")


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
