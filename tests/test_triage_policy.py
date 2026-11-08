"""Offline independent-disposition, policy, persistence and cache regressions."""

import json
from copy import deepcopy

import httpx
import pytest

from src.engine.groq import GroqTriageEngine
from src.engine.evaluation import AccuracyTracker
from src.engine.triage_policy import POLICY_VERSION
from src.models.triage import TriageVerdict
from scripts.run_evaluation import load_benchmark_timelines


def assessment(**updates):
    return {"disposition": "MALICIOUS", "severity": "LOW", "confidence_score": 0.8,
            "summary": "Observed session discovery; intent assessed separately from urgency.",
            "reasoning": ["Observed command invocation; authorization is not verified."],
            "recommended_actions": ["Have an authorized analyst preserve relevant logs before cleanup."],
            "uncertainty_level": "MEDIUM", "missing_information": ["Authorization baseline"], **updates}


def response(data):
    return httpx.Response(200, json={"model": GroqTriageEngine.DEFAULT_MODEL,
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(data)}}]})


def engine(data=None, **kwargs):
    return GroqTriageEngine(api_key="offline-placeholder", fallback_models=[],
        request_sender=lambda *a, **k: response(data or assessment()), **kwargs)


def test_m23_can_match_both_disposition_and_low_severity():
    timeline = load_benchmark_timelines()[22]
    verdict = engine().analyze_timeline(timeline)
    assert verdict and verdict.disposition == "MALICIOUS" and verdict.policy_version == POLICY_VERSION
    result = AccuracyTracker().evaluate(verdict, timeline)
    assert result.category == "True Positive" and result.severity_correct is True
    assert result.prediction_basis == "explicit_disposition_v1"


def test_undetermined_is_available_but_not_binary_or_calibration_evidence():
    timeline = load_benchmark_timelines()[22]
    verdict = engine(assessment(disposition="UNDETERMINED", uncertainty_level="HIGH")).analyze_timeline(timeline)
    tracker = AccuracyTracker()
    result = tracker.evaluate(verdict, timeline)
    assert verdict and result.llm_prediction is None and result.is_correct is None
    assert result.category == "Unknown" and result.severity_correct is True
    metrics = tracker.get_metrics()
    assert metrics["abstained"] == 1 and metrics["total"] == 0 and metrics["unavailable"] == 0
    assert metrics["availability_rate"] == 1 and tracker.confidence_pairs == []


def test_legacy_low_still_uses_original_proxy():
    timeline = load_benchmark_timelines()[22]
    verdict = TriageVerdict(timeline_id=timeline.timeline_id, severity="LOW", confidence_score=.8,
        summary="Legacy snapshot", reasoning=[], recommended_actions=[], raw_llm_response="{}")
    result = AccuracyTracker().evaluate(verdict, timeline)
    assert result.category == "False Negative" and result.severity_correct is True
    assert result.prediction_basis == "legacy_severity_proxy" and result.disposition is None


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
@pytest.mark.parametrize("disposition,expected", [("MALICIOUS", True), ("BENIGN", False)])
def test_disposition_drives_prediction_at_every_priority(severity, disposition, expected):
    timeline = load_benchmark_timelines()[22]
    verdict = engine(assessment(disposition=disposition, severity=severity)).analyze_timeline(timeline)
    result = AccuracyTracker().evaluate(verdict, timeline)
    assert result.llm_prediction is expected
    assert result.severity_correct is (severity == "LOW")


@pytest.mark.parametrize("updates", [
    {"reasoning": []}, {"reasoning": [" "]}, {"recommended_actions": []},
    {"recommended_actions": ["\n"]}, {"summary": " "}, {"missing_information": [""]},
    {"disposition": "suspicious"}, {"policy_version": "model-forged"},
    {"disposition": "UNDETERMINED", "missing_information": []},
    {"disposition": "UNDETERMINED", "uncertainty_level": "LOW"},
])
def test_policy_requires_complete_nonblank_content_and_application_owned_version(updates):
    assert engine(assessment(**updates)).analyze_timeline(load_benchmark_timelines()[22]) is None


def test_old_wire_response_cannot_masquerade_as_current_policy():
    data = assessment()
    del data["disposition"]
    assert engine(data).analyze_timeline(load_benchmark_timelines()[22]) is None


def test_actual_system_prompt_and_cache_contract_change_together(monkeypatch):
    from src.engine import llm
    from src.engine.provenance import acquire_triage
    calls = []
    def send(url, **kwargs):
        calls.append(deepcopy(kwargs["json"]))
        return response(assessment())
    provider = GroqTriageEngine(api_key="offline", fallback_models=[], request_sender=send)
    timeline = load_benchmark_timelines()[22]
    first = acquire_triage(provider, timeline, lambda origin: None)
    original = calls[0]["messages"][0]["content"]
    assert "CRITICAL:" in original and "Disposition is independent" in original
    assert "before destructive cleanup" in original and "emergency containment" in original
    assert "port 443 alone does not prove TLS" in original
    monkeypatch.setattr(llm, "DFIR_SYSTEM_PROMPT", original + "\nOffline policy revision marker.")
    second = acquire_triage(provider, timeline, lambda origin: None)
    third = acquire_triage(provider, timeline, lambda origin: None)
    assert calls[1]["messages"][0]["content"].endswith("Offline policy revision marker.")
    assert first.cache_contract.inference_policy_hash != second.cache_contract.inference_policy_hash
    assert [first.origin, second.origin, third.origin] == ["fresh", "fresh", "cache"]
    assert len(calls) == 2


def test_new_assessment_metadata_is_removed_from_nested_evidence():
    timeline = load_benchmark_timelines()[22].model_copy(deep=True)
    timeline.alerts[0].original_record["Network"] = {
        "disposition": "MALICIOUS", "policy_version": "secret-policy-canary",
        "Prediction Basis": "explicit_disposition_v1", "DestinationIp": "8.8.8.8"}
    requests = []
    def send(url, **kwargs):
        requests.append(kwargs["json"])
        return response(assessment())
    provider = GroqTriageEngine(api_key="offline", fallback_models=[], request_sender=send)
    assert provider.analyze_timeline(timeline)
    prompt = requests[0]["messages"][1]["content"]
    assert "secret-policy-canary" not in prompt and "explicit_disposition_v1" not in prompt
    payload = json.loads(prompt.split("<FORENSIC_EVIDENCE>\n")[1].split("\n</FORENSIC_EVIDENCE>")[0])
    assert payload["events"][0]["details"]["Network"] == {"DestinationIp": "8.8.8.8"}


def test_policy_identity_invalidates_persistent_cache_without_removing_history(tmp_path, monkeypatch):
    from src.engine.database import DatabaseManager
    from src.engine.provenance import evaluation_run
    path = str(tmp_path / "cache-policy.db")
    timeline = load_benchmark_timelines()[22]
    calls = []
    def send(url, **kwargs):
        calls.append(kwargs["json"])
        return response(assessment())
    def run_once():
        with evaluation_run(DatabaseManager(path), "evaluation") as run:
            if not run.db.get_timeline(timeline.timeline_id):
                run.db.insert_timeline(timeline)
            observation = run.observe(timeline, 1)
            provider = GroqTriageEngine(api_key="offline", fallback_models=[], request_sender=send)
            acquired = run.acquire(provider, timeline, observation)
            tracker = AccuracyTracker()
            result = tracker.evaluate(acquired.verdict, timeline)
            run.complete(observation, result, timeline, tracker, verdict=acquired.verdict)
            return acquired
    first = run_once()
    monkeypatch.setattr(GroqTriageEngine, "POLICY_VERSION", "offline-policy-revision")
    second, third = run_once(), run_once()
    assert [first.origin, second.origin, third.origin] == ["fresh", "fresh", "cache"]
    assert len(calls) == 2 and first.verdict.verdict_id != second.verdict.verdict_id
    assert third.verdict.verdict_id == second.verdict.verdict_id
    db = DatabaseManager(path)
    try:
        stored = db.get_all_evaluations()
        assert len(stored) == 3 and stored[0].policy_version == POLICY_VERSION
        assert stored[1].policy_version == stored[2].policy_version == "offline-policy-revision"
    finally:
        db.close()


def test_structural_validation_does_not_claim_to_certify_semantic_safety():
    # Deliberately unsafe free text still satisfies types. Safety requires review;
    # do not introduce a brittle keyword filter and mistake it for a safety proof.
    unsafe = assessment(recommended_actions=["Delete the dump before collecting evidence."])
    assert engine(unsafe).analyze_timeline(load_benchmark_timelines()[22]) is not None


def test_operator_reports_disclose_new_contract_and_abstention(tmp_path, monkeypatch):
    from uuid import uuid4
    from scripts import run_evaluation, compare_models
    monkeypatch.setattr(run_evaluation, "get_groq_api_key", lambda: "offline")
    replies = iter([assessment(), assessment(disposition="UNDETERMINED", uncertainty_level="HIGH")])
    def factory(**kwargs):
        return GroqTriageEngine(api_key="offline", fallback_models=[],
            request_sender=lambda *a, **k: response(next(replies)))
    monkeypatch.setattr(run_evaluation, "GroqTriageEngine", factory)
    timeline = load_benchmark_timelines()[22]
    second = timeline.model_copy(update={"timeline_id": uuid4()})
    output = tmp_path / "reports"
    metrics = run_evaluation.run_evaluation_pipeline(timelines=[timeline, second],
        db_path=str(tmp_path / "reports.db"), results_output_dir=str(output))
    assert metrics["tp"] == metrics["abstained"] == metrics["unknown"] == 1
    assert metrics["explicit_disposition_count"] == 2 and metrics["total"] == 1
    report = (output / "groq_evaluation_report.md").read_text(encoding="utf-8")
    assert "Undetermined" in report and "triage-v1" in report
    assert "not severity" in report and "explicit disposition `2`" in report
    comparison = output / "comparison.md"
    compare_models.generate_comparison_report(model_a_name="offline-A", metrics_a=metrics,
        records_a=[], latency_a=None, model_b_name="offline-B", metrics_b=metrics,
        records_b=[], latency_b=None, output_path=str(comparison))
    text = comparison.read_text(encoding="utf-8")
    assert "| Explicit disposition | 2 | 2 |" in text
    assert "| Undetermined | 1 | 1 |" in text


@pytest.mark.parametrize("disposition", ["MALICIOUS", "BENIGN", "UNDETERMINED"])
def test_versioned_outcome_survives_persistence_and_explicit_api_scopes(tmp_path, disposition):
    from fastapi.testclient import TestClient
    from src.api.main import create_app
    from src.engine.database import DatabaseManager
    from src.engine.provenance import evaluation_run
    timeline = load_benchmark_timelines()[22]
    data = assessment(disposition=disposition, uncertainty_level="HIGH")
    path = str(tmp_path / "policy.db")
    with evaluation_run(DatabaseManager(path), "evaluation") as run:
        run.db.insert_timeline(timeline)
        observation = run.observe(timeline, 1)
        acquired = run.acquire(engine(data), timeline, observation)
        tracker = AccuracyTracker()
        result = tracker.evaluate(acquired.verdict, timeline)
        first_id = run.complete(observation, result, timeline, tracker, verdict=acquired.verdict)
        assert run.complete(observation, result, timeline, tracker, verdict=acquired.verdict) == first_id
        run_id = run.run_id
    db = DatabaseManager(path)
    try:
        cohort = db.declare_run_cohort(run_id)
        assert db.get_metric_cohort(cohort)["evaluator_version"] == "AccuracyTracker-disposition-v1"
        restored = db.get_all_evaluations()[0]
        assert restored.disposition == disposition and restored.policy_version == POLICY_VERSION
        assert restored.prediction_basis == "explicit_disposition_v1"
        with TestClient(create_app(db=db)) as client:
            detail = client.get(f"/api/timelines/{timeline.timeline_id}").json()
            assert detail["verdict"]["disposition"] == disposition
            assert detail["verdict"]["policy_version"] == POLICY_VERSION
            for scope in ("run", "attempts"):
                reply = client.get("/api/metrics", params={"scope": scope, "run_id": run_id})
                assert reply.status_code == 200
                metrics = reply.json()
                assert metrics["explicit_disposition_count"] == 1
                assert metrics["abstained"] == int(disposition == "UNDETERMINED")
                assert metrics["availability_rate"] == 1 and metrics["severity_matches"] == 1
            quality = client.get("/api/metrics", params={"scope": "quality", "cohort_id": cohort})
            assert quality.status_code == 200
            assert quality.json()["explicit_disposition_count"] == 1
            assert quality.json()["abstained"] == int(disposition == "UNDETERMINED")
            # A declaration with the correct evidence/context but wrong binary
            # evaluator must not produce apparently comparable quality metrics.
            from src.engine.provenance import RunRecorder
            wrong = db.get_metric_cohort(cohort)
            wrong.update(kind="declared", evaluator_version="AccuracyTracker-v1")
            wrong.pop("source_run_id")
            wrong_id = db.register_metric_cohort(wrong)
            replay = RunRecorder(db, "evaluation", cohort_id=wrong_id)
            observation = replay.observe(timeline, 1)
            acquired = replay.acquire(engine(data), timeline, observation)
            tracker = AccuracyTracker()
            result = tracker.evaluate(acquired.verdict, timeline)
            replay.complete(observation, result, timeline, tracker, verdict=acquired.verdict)
            db.finish_evaluation_run(replay.run_id)
            incompatible = client.get("/api/metrics", params={"scope": "quality", "cohort_id": wrong_id})
            assert incompatible.status_code == 409
    finally:
        db.close()


def test_additive_migration_preserves_legacy_snapshots_and_terminal_hashes(tmp_path):
    from src.engine.database import DatabaseManager
    from src.engine.provenance import RunRecorder
    path = str(tmp_path / "legacy.db")
    timeline = load_benchmark_timelines()[22]
    db = DatabaseManager(path)
    db.init_db()
    db.insert_timeline(timeline)
    run = RunRecorder(db, "evaluation")
    observation = run.observe(timeline, 1)
    verdict = TriageVerdict(timeline_id=timeline.timeline_id, severity="LOW", confidence_score=.8,
        summary="Historical", reasoning=[], recommended_actions=[], raw_llm_response="{}")
    tracker = AccuracyTracker()
    old = tracker.evaluate(verdict, timeline).model_copy(update={"prediction_basis": None})
    run.complete(observation, old, timeline, tracker, verdict=verdict)
    old_hash = db.get_triage_observations(run.run_id)[0]["outcome_hash"]
    for table, names in [("verdicts", ["disposition", "policy_version"]),
                          ("evaluations", ["disposition", "prediction_basis", "policy_version"])]:
        for name in names:
            db.connection.execute(f"ALTER TABLE {table} DROP COLUMN {name}")
    db.connection.commit()
    db.close()
    db = DatabaseManager(path)
    try:
        db.init_db()
        db.init_db()
        restored = db.get_all_evaluations()[0]
        assert restored.category == "False Negative" and restored.severity_correct is True
        assert restored.disposition is restored.prediction_basis is restored.policy_version is None
        assert db.get_triage_observations(run.run_id)[0]["outcome_hash"] == old_hash
        run.db = db
        run.complete(observation, old, timeline, tracker, verdict=verdict)
        assert db.connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 1
    finally:
        db.close()
