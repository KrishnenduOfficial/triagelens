"""Offline stage-3 selection, immutable cohorts, and metric denominators."""

from copy import deepcopy
import sqlite3
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from fastapi.encoders import jsonable_encoder

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.evaluation import AccuracyTracker
from src.engine.metric_scopes import MetricSelectionError, scoped_metrics
from src.engine.provenance import RunRecorder
from src.engine.verdict_cache import CacheContract
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


@pytest.fixture
def db():
    database = DatabaseManager()
    database.init_db()
    yield database
    database.close()


def case(db, malicious=True, severity="HIGH", prediction="HIGH"):
    tl = ThreatTimeline(grouping_key=str(uuid4()), total_events=1, alerts=[NormalizedAlert(
        source_dataset="offline", source_file="fixture.json", event_type="ProcessStart",
        original_record={"is_malicious": malicious, "severity": severity},
    )])
    db.insert_timeline(tl)
    verdict = TriageVerdict(timeline_id=tl.timeline_id, severity=prediction,
        confidence_score=.9, summary="Fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")
    return tl, verdict


def complete(db, run, tl, verdict, ordinal=1, origin="fresh", evidence="a" * 64, policy="b" * 64,
             validation="unverified", changes=None):
    ob = run.observe(tl, ordinal)
    contract = CacheContract(str(tl.timeline_id), evidence, policy, ("offline-primary",), 60)
    db.mark_observation_acquisition(ob, origin, validation, contract)
    tracker = AccuracyTracker()
    result = tracker.evaluate(verdict, tl)
    if changes:
        result = result.model_copy(update=changes)
    run.complete(ob, result, tl, tracker, verdict=verdict,
                 failure_category="no_verdict" if verdict is None else None)
    return ob


def finish(db, run):
    db.finish_evaluation_run(run.run_id)
    return db.declare_run_cohort(run.run_id)


def test_history_run_quality_and_attempts_have_distinct_units(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    complete(db, run, tl, verdict, 2, "cache", validation="verified")
    complete(db, run, tl, None, 3)
    skipped = run.observe(tl, 4)
    db.skip_observation(skipped)
    cohort = finish(db, run)
    db.insert_evaluation(AccuracyTracker().evaluate(verdict, tl))
    history = scoped_metrics(db)
    occurrence = scoped_metrics(db, scope="run", run_id=run.run_id)
    quality = scoped_metrics(db, scope="quality", cohort_id=cohort)
    attempts = scoped_metrics(db, scope="attempts", run_id=run.run_id)
    assert history["total"] == 3 and history["unavailable"] == 1
    assert occurrence["total"] == 2 and occurrence["availability_rate"] == pytest.approx(2 / 3)
    assert quality["total"] == 1 and quality["availability_rate"] is None
    assert attempts["total"] == 1 and attempts["availability_rate"] == .5
    assert quality["selection"]["coverage"]["deduplicated"] == 1
    assert occurrence["selection"]["coverage"]["skipped"] == 1
    assert history["selection"]["coverage"]["legacy_unknown"] == 1
    assert quality["selection"]["denominators"]["severity"] == 1


def test_replay_only_attempts_are_null_not_available(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict, origin="cache", validation="verified")
    finish(db, run)
    metrics = scoped_metrics(db, scope="attempts", run_id=run.run_id)
    assert metrics["total"] == 0
    assert metrics["availability_rate"] is None
    assert metrics["selection"]["availability_status"] == "no_completed_fresh_attempts"
    assert metrics["selection"]["denominators"]["availability"] == 0


def test_manifest_includes_mixed_contexts_and_subset_replay(db):
    good, vg = case(db)
    benign, vb = case(db, False, "LOW", "LOW")
    run = RunRecorder(db, "evaluation")
    complete(db, run, good, vg)
    complete(db, run, benign, vb, 2, evidence="c" * 64)
    cohort = finish(db, run)
    replay = RunRecorder(db, "evaluation", cohort_id=cohort)
    complete(db, replay, good, vg, origin="cache", validation="verified")
    db.finish_evaluation_run(replay.run_id)
    metrics = scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert metrics["tp"] == metrics["tn"] == 1
    assert metrics["selection"]["coverage"]["manifest_cases"] == 2
    assert metrics["selection"]["coverage"]["deduplicated"] == 1
    assert metrics["severity_accuracy"] == 1


@pytest.mark.parametrize("params", [
    {"scope": "bad"}, {"scope": "run"}, {"scope": "quality"}, {"scope": "attempts"},
    {"scope": "run", "run_id": "invalid"}, {"scope": "history", "run_id": str(uuid4())},
    {"scope": "quality", "cohort_id": "invalid"},
    {"scope": "attempts", "run_id": str(uuid4()), "cohort_id": "a" * 64},
])
def test_api_rejects_invalid_selectors(db, params):
    with TestClient(create_app(db=db)) as client:
        assert client.get("/api/metrics", params=params).status_code == 422


def test_explicit_scope_never_falls_back_to_memory_or_global_history(db):
    tl, verdict = case(db)
    tracker = AccuracyTracker()
    tracker.evaluate(verdict, tl)
    empty = RunRecorder(db, "evaluation")
    db.finish_evaluation_run(empty.run_id)
    with TestClient(create_app(db=db, tracker=tracker)) as client:
        assert client.get("/api/metrics").json()["total"] == 1
        data = client.get("/api/metrics", params={"scope": "run", "run_id": empty.run_id}).json()
        assert data["total"] == 0 and data["selection"]["source"] == "database"
        assert client.get("/api/metrics", params={"scope": "run", "run_id": str(uuid4())}).status_code == 404


def test_failed_run_reports_completed_and_interrupted_work(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    ob = run.observe(tl, 2)
    db.mark_observation_acquisition(ob, "fresh")
    db.fail_evaluation_run(run.run_id)
    data = scoped_metrics(db, scope="attempts", run_id=run.run_id)
    assert data["total"] == 1 and data["unavailable"] == 0
    assert data["selection"]["coverage"]["interrupted"] == 1
    assert data["selection"]["run_status"] == "failed"


@pytest.mark.parametrize("field,value", [("confidence_score", .1), ("severity_correct", False)])
def test_quality_rejects_conflicting_canonical_snapshots(db, field, value):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    complete(db, run, tl, verdict, 2, "cache", validation="verified", changes={field: value})
    cohort = finish(db, run)
    with pytest.raises(MetricSelectionError, match="Conflicting canonical"):
        scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert scoped_metrics(db)["total"] == 2


def test_label_change_requires_new_cohort(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    tl.alerts[0].original_record["is_malicious"] = False
    complete(db, run, tl, verdict, 2, "cache", validation="verified")
    db.finish_evaluation_run(run.run_id)
    with pytest.raises(MetricSelectionError, match="Conflicting case"):
        db.declare_run_cohort(run.run_id)
    assert scoped_metrics(db)["total"] == 2


def test_legacy_cohort_namespace_does_not_certify_quality(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    ob = run.observe(tl, 1)
    db.mark_observation_acquisition(ob, "cache")
    run.complete(ob, AccuracyTracker().evaluate(verdict, tl), tl, AccuracyTracker(), verdict=verdict)
    db.finish_evaluation_run(run.run_id)
    with pytest.raises(MetricSelectionError):
        db.declare_run_cohort(run.run_id)
    with pytest.raises(MetricSelectionError):
        scoped_metrics(db, scope="quality", cohort_id=db.get_evaluation_run(run.run_id)["quality_cohort_hash"])


def test_unknown_binary_still_counts_severity_without_calibration(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict, changes={"ground_truth": None, "is_correct": None, "category": "Unknown"})
    cohort = finish(db, run)
    data = scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert data["total"] == 0 and data["unknown"] == 1
    assert data["severity_accuracy"] == 1
    assert data["selection"]["denominators"]["calibration"] == 0


def test_repeated_evidence_is_not_independent_quality_coverage(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    another = verdict.model_copy(update={"verdict_id": uuid4()})
    complete(db, run, tl, another, 2)
    cohort = finish(db, run)
    data = scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert data["total"] == 2
    assert data["selection"]["coverage"]["unique_evidence"] == 1
    assert data["selection"]["coverage"]["repeated_evidence"] == 1


def test_cohort_registration_is_canonical_immutable_and_bind_before_work(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    cohort = finish(db, run)
    manifest = db.get_metric_cohort(cohort)
    assert db.register_metric_cohort(deepcopy(manifest)) == cohort
    changed = deepcopy(manifest)
    changed["revision"] = "new"
    assert db.register_metric_cohort(changed) != cohort
    with pytest.raises(MetricSelectionError):
        db.bind_metric_cohort(run.run_id, cohort)
    assert db.connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("change", ["evidence", "context", "policy", "undeclared_case"])
def test_declared_cohort_rejects_incompatible_subset_outcomes(db, change):
    tl, verdict = case(db)
    initial = RunRecorder(db, "evaluation")
    complete(db, initial, tl, verdict)
    cohort = finish(db, initial)
    replay = RunRecorder(db, "evaluation", cohort_id=cohort)
    kwargs = {}
    if change == "evidence":
        kwargs["evidence"] = "c" * 64
    elif change == "policy":
        kwargs["policy"] = "c" * 64
    elif change == "context":
        tl.alerts[0].original_record["is_malicious"] = False
    else:
        tl, verdict = case(db)
    complete(db, replay, tl, verdict, origin="cache", validation="verified", **kwargs)
    db.finish_evaluation_run(replay.run_id)
    with pytest.raises(MetricSelectionError, match="declared cohort"):
        scoped_metrics(db, scope="quality", cohort_id=cohort)
    # Bad declarations cannot erase the completed history occurrence.
    assert scoped_metrics(db)["total"] == 2


def test_attempts_cohort_uses_fresh_denominator_and_retains_unavailable(db):
    tl, verdict = case(db)
    initial = RunRecorder(db, "evaluation")
    complete(db, initial, tl, verdict)
    cohort = finish(db, initial)
    replay = RunRecorder(db, "evaluation", cohort_id=cohort)
    complete(db, replay, tl, verdict, origin="cache", validation="verified")
    complete(db, replay, tl, None, 2)
    db.finish_evaluation_run(replay.run_id)
    data = scoped_metrics(db, scope="attempts", cohort_id=cohort)
    assert data["total"] == 1 and data["unavailable"] == 1
    assert data["availability_rate"] == .5
    assert data["selection"]["denominators"]["availability"] == 2


@pytest.mark.parametrize("validation", ["unverified", "rejected"])
def test_fresh_outcomes_do_not_require_a_cache_hit(db, validation):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict, validation=validation)
    cohort = finish(db, run)
    assert scoped_metrics(db, scope="quality", cohort_id=cohort)["total"] == 1
    assert scoped_metrics(db, scope="attempts", run_id=run.run_id)["total"] == 1


def test_unverified_replay_cannot_enter_declared_quality(db):
    tl, verdict = case(db)
    initial = RunRecorder(db, "evaluation")
    complete(db, initial, tl, verdict)
    cohort = finish(db, initial)
    run = RunRecorder(db, "evaluation", cohort_id=cohort)
    complete(db, run, tl, verdict, origin="cache", validation="unverified")
    db.finish_evaluation_run(run.run_id)
    data = scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert data["total"] == 1
    assert data["selection"]["coverage"]["excluded_unverifiable"] == 1


@pytest.mark.parametrize("mutation", ["missing_members", "duplicate_case", "bad_hash", "unknown_version", "extra_field"])
def test_malformed_manifests_are_rejected(db, mutation):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    cohort = finish(db, run)
    manifest = db.get_metric_cohort(cohort)
    if mutation == "missing_members":
        manifest["members"] = []
    elif mutation == "duplicate_case":
        manifest["members"].append(dict(manifest["members"][0]))
    elif mutation == "bad_hash":
        manifest["members"][0]["evidence_hash"] = "unknown"
    elif mutation == "unknown_version":
        manifest["version"] = 2
    else:
        manifest["unexpected"] = True
    with pytest.raises(MetricSelectionError):
        db.register_metric_cohort(manifest)


def test_registration_order_is_irrelevant_and_unbound_cohort_is_empty(db):
    tl, verdict = case(db)
    other, ov = case(db, False, "LOW", "LOW")
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    complete(db, run, other, ov, 2, evidence="c" * 64)
    cohort = finish(db, run)
    manifest = db.get_metric_cohort(cohort)
    manifest["members"].reverse()
    assert db.register_metric_cohort(manifest) == cohort
    manifest["kind"] = "declared"
    del manifest["source_run_id"]
    manifest["revision"] = "dataset-v2"
    declared = db.register_metric_cohort(manifest)
    data = scoped_metrics(db, scope="quality", cohort_id=declared)
    assert data["total"] == 0 and data["availability_rate"] is None
    assert data["selection"]["coverage"]["missing_cases"] == 2


def test_snapshot_survives_a_concurrent_file_database_writer(tmp_path):
    path = str(tmp_path / "scopes.db")
    writer = DatabaseManager(path)
    writer.init_db()
    tl, verdict = case(writer)
    writer.insert_verdict(verdict)
    result = AccuracyTracker().evaluate(verdict, tl)
    writer.insert_evaluation(result)

    class InterleavedReader(DatabaseManager):
        def get_all_evaluations(self):
            # metric_snapshot has already read raw rows. A separate WAL connection
            # commits between its raw-row and reconstructed-history queries.
            writer.insert_evaluation(result)
            return super().get_all_evaluations()

    reader = InterleavedReader(path)
    try:
        data = scoped_metrics(reader)
        assert data["total"] == data["selection"]["coverage"]["evaluation_rows"] == 1
        assert len(writer.get_all_evaluations()) == 2
    finally:
        reader.close()
        writer.close()


def test_real_engine_replay_quality_survives_cache_expiry_and_label_mutation(db):
    import json
    import httpx
    from conftest import PipelineTestEngine

    calls = []
    ticks = [1800000000.0]

    def sender(url, **kwargs):
        calls.append(kwargs)
        return httpx.Response(200, json={"outputs": [{"message": {"segments": [{"text": json.dumps({
            "severity": "HIGH", "confidence_score": .9, "summary": "Fixture", "reasoning": ["Evidence"],
            "recommended_actions": ["Review"], "uncertainty_level": "HIGH", "missing_information": [],
        })}]}}]})

    engine = PipelineTestEngine(api_key="offline-placeholder", model="offline-primary", fallback_models=[],
        request_sender=sender, utc_clock=lambda: ticks[0], cache_ttl_seconds=60)
    tl, _ = case(db)
    run = RunRecorder(db, "evaluation")
    for ordinal in (1, 2):
        ob = run.observe(tl, ordinal)
        acquisition = run.acquire(engine, tl, ob)
        tracker = AccuracyTracker()
        run.complete(ob, tracker.evaluate(acquisition.verdict, tl), tl, tracker, verdict=acquisition.verdict)
    cohort = finish(db, run)
    before = scoped_metrics(db, scope="quality", cohort_id=cohort)
    ticks[0] += 120
    tl.alerts[0].original_record["is_malicious"] = False
    after = scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert before == after
    assert after["total"] == 1 and len(calls) == 1
    assert [o["cache_validation"] for o in db.get_triage_observations(run.run_id)] == ["unverified", "verified"]


def test_migration_does_not_rewrite_outcomes_or_certify_old_namespaces(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    db.finish_evaluation_run(run.run_id)
    db.insert_evaluation(AccuracyTracker().evaluate(verdict, tl))
    before = [dict(row) for row in db.connection.execute("SELECT * FROM evaluations ORDER BY id")]
    db.init_db()
    db.init_db()
    assert before == [dict(row) for row in db.connection.execute("SELECT * FROM evaluations ORDER BY id")]
    assert db.connection.execute("SELECT COUNT(*) FROM metric_run_cohorts").fetchone()[0] == 0
    cohort = db.declare_run_cohort(run.run_id)
    assert before == [dict(row) for row in db.connection.execute("SELECT * FROM evaluations ORDER BY id")]
    with pytest.raises(sqlite3.IntegrityError, match="Immutable metric cohort"):
        db.connection.execute("UPDATE metric_cohorts SET manifest='{}' WHERE cohort_id=?", (cohort,))
    db.connection.rollback()


@pytest.mark.parametrize("query", ["scope=run&scope=history", "scope=history&typo=1", "cohort=wrong"])
def test_api_rejects_unknown_and_repeated_parameters(db, query):
    with TestClient(create_app(db=db)) as client:
        assert client.get("/api/metrics?" + query).status_code == 422


def test_one_canonical_selection_drives_all_quality_statistics(db):
    run = RunRecorder(db, "evaluation")
    expected_results = []
    for index, (malicious, prediction) in enumerate([(True, "HIGH"), (False, "LOW"),
                                                   (True, "LOW"), (False, "HIGH")]):
        tl, verdict = case(db, malicious, "HIGH" if malicious else "LOW", prediction)
        evidence = f"{index:064x}"
        complete(db, run, tl, verdict, index * 2 + 1, evidence=evidence)
        complete(db, run, tl, verdict, index * 2 + 2, origin="cache", validation="verified", evidence=evidence)
        expected_results.append(AccuracyTracker().evaluate(verdict, tl))
    cohort = finish(db, run)
    quality = scoped_metrics(db, scope="quality", cohort_id=cohort)
    expected = AccuracyTracker.from_evaluations(expected_results).get_metrics()
    expected["availability_rate"] = None
    assert {k: quality[k] for k in expected} == expected
    assert quality["selection"]["denominators"] == {"binary": 4, "severity": 4, "calibration": 4, "availability": None}
    assert quality["selection"]["coverage"]["deduplicated"] == 4


def test_running_run_reports_pending_and_cannot_freeze_cohort(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    run.observe(tl, 2)
    data = scoped_metrics(db, scope="run", run_id=run.run_id)
    assert data["total"] == 1 and data["unavailable"] == 0
    assert data["selection"]["coverage"]["pending"] == 1
    with pytest.raises(MetricSelectionError, match="terminal run"):
        db.declare_run_cohort(run.run_id)


def test_failed_run_can_freeze_known_completed_subset_with_missing_work_disclosed(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    run.observe(tl, 2)
    db.fail_evaluation_run(run.run_id)
    cohort = db.declare_run_cohort(run.run_id)
    data = scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert data["total"] == 1
    assert data["selection"]["cohort_kind"] == "ad_hoc"
    assert data["selection"]["coverage"]["interrupted"] == 1


def test_missing_completed_outcomes_are_integrity_errors_not_availability(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    cohort = finish(db, run)
    db.connection.execute("DELETE FROM evaluations")
    db.connection.commit()
    assert scoped_metrics(db, scope="run", run_id=run.run_id)["selection"]["coverage"]["missing_outcomes"] == 1
    for params in ({"scope": "attempts", "run_id": run.run_id}, {"scope": "quality", "cohort_id": cohort}):
        with pytest.raises(MetricSelectionError, match="missing evaluation"):
            scoped_metrics(db, **params)


def test_api_exposes_selection_errors_without_changing_history_keys(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    cohort = finish(db, run)
    complete_run = RunRecorder(db, "evaluation", cohort_id=cohort)
    complete(db, complete_run, tl, verdict, origin="cache", validation="verified", changes={"confidence_score": .1})
    db.finish_evaluation_run(complete_run.run_id)
    with TestClient(create_app(db=db)) as client:
        history = client.get("/api/metrics").json()
        expected = jsonable_encoder(AccuracyTracker.from_database(db).get_metrics())
        assert {key: history[key] for key in expected} == expected
        assert client.get("/api/metrics", params={"scope": "quality", "cohort_id": cohort}).status_code == 409


def test_unknown_cohort_rolls_back_run_creation(db):
    with pytest.raises(MetricSelectionError):
        RunRecorder(db, "evaluation", cohort_id="f" * 64)
    assert db.connection.execute("SELECT COUNT(*) FROM evaluation_runs").fetchone()[0] == 0


def test_unavailable_attempts_do_not_collapse_on_null_verdict_identity(db):
    tl, _ = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, None)
    complete(db, run, tl, None, 2)
    cohort = finish(db, run)
    attempts = scoped_metrics(db, scope="attempts", run_id=run.run_id)
    assert attempts["unavailable"] == 2 and attempts["availability_rate"] == 0
    assert attempts["selection"]["denominators"]["availability"] == 2
    quality = scoped_metrics(db, scope="quality", cohort_id=cohort)
    assert quality["unavailable"] == 0
    assert quality["selection"]["coverage"]["excluded_no_verdict"] == 2


def test_unknown_binary_fresh_result_is_available_but_not_calibration_sample(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict, changes={"ground_truth": None, "is_correct": None, "category": "Unknown"})
    db.finish_evaluation_run(run.run_id)
    data = scoped_metrics(db, scope="attempts", run_id=run.run_id)
    assert data["availability_rate"] == 1 and data["unknown"] == 1 and data["total"] == 0
    assert data["selection"]["denominators"] == {"binary": 0, "calibration": 0, "severity": 1, "availability": 1}


def test_ad_hoc_declarations_cannot_claim_unobserved_members(db):
    tl, verdict = case(db)
    run = RunRecorder(db, "evaluation")
    complete(db, run, tl, verdict)
    cohort = finish(db, run)
    manifest = db.get_metric_cohort(cohort)
    manifest["members"][0]["evaluation_context_hash"] = "f" * 64
    with pytest.raises(MetricSelectionError, match="terminal source run"):
        db.register_metric_cohort(manifest)
