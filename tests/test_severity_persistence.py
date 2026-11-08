"""Offline severity snapshots, legacy migration, and runner/API consistency."""

import json

from fastapi.testclient import TestClient
import pytest

from src import cli, config
from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.enrichment import EnrichmentEngine
from src.engine.evaluation import AccuracyTracker
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


CASES = [
    ("matched", "HIGH", "HIGH", True, True),
    ("same_binary_wrong_severity", "HIGH", "MEDIUM", True, False),
    ("unlabelled_severity", None, "HIGH", True, None),
    ("unknown_binary", "HIGH", "HIGH", None, True),
    ("unavailable", "HIGH", None, True, None),
]


@pytest.fixture
def db():
    database = DatabaseManager()
    database.init_db()
    yield database
    database.close()


def outcome(database, ground_severity="HIGH", prediction="HIGH", binary=True):
    record = {}
    if ground_severity is not None:
        record["severity"] = ground_severity
    if binary is not None:
        record["is_malicious"] = binary
    alert = NormalizedAlert(source_dataset="offline", source_file="fixture.json",
                            event_type="ProcessStart", original_record=record)
    tl = ThreatTimeline(grouping_key="offline-fixture", alerts=[alert], total_events=1)
    database.insert_timeline(tl)
    verdict = None
    if prediction is not None:
        verdict = TriageVerdict(timeline_id=tl.timeline_id, severity=prediction, confidence_score=0.9,
                               summary="Fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")
        database.insert_verdict(verdict)
    tracker = AccuracyTracker()
    result = tracker.evaluate(verdict, tl)
    return result, tracker, tl, verdict


@pytest.mark.parametrize("name,ground,prediction,binary,correct", CASES, ids=[case[0] for case in CASES])
def test_severity_snapshot_roundtrip_preserves_false_and_null(db, name, ground, prediction, binary, correct):
    result, tracker, tl, verdict = outcome(db, ground, prediction, binary)
    assert result.severity_correct is correct
    db.insert_evaluation(result)
    raw = db.connection.execute("SELECT severity_ground_truth,severity_prediction,severity_correct FROM evaluations").fetchone()
    assert tuple(raw) == (ground, prediction, int(correct) if correct is not None else None)
    loaded = db.get_all_evaluations()[0]
    assert loaded == result
    by_timeline = db.get_evaluations_for_timeline(tl.timeline_id)[0]
    assert by_timeline["severity_ground_truth"] == ground
    assert by_timeline["severity_prediction"] == prediction
    assert by_timeline["severity_correct"] is correct
    rebuilt = AccuracyTracker.from_database(db).get_metrics()
    assert rebuilt == tracker.get_metrics()


def test_api_severity_denominator_matches_mixed_in_memory_results(db):
    results = []
    for name, ground, prediction, binary, correct in CASES:
        result, _, _, _ = outcome(db, ground, prediction, binary)
        db.insert_evaluation(result)
        results.append(result)
    expected = AccuracyTracker.from_evaluations(results).get_metrics()
    with TestClient(create_app(db=db)) as client:
        response = client.get("/api/metrics")
    assert response.status_code == 200
    actual = response.json()
    assert actual["severity_evaluated"] == expected["severity_evaluated"] == 3
    assert actual["severity_matches"] == expected["severity_matches"] == 2
    assert actual["severity_accuracy"] == expected["severity_accuracy"] == 2 / 3
    for key in ("total", "tp", "unknown", "unavailable", "availability_rate", "brier_score"):
        assert actual[key] == expected[key]
    assert actual["availability_rate"] == 0.8


@pytest.mark.parametrize("nullable", [False, True])
@pytest.mark.parametrize("old_optional", [False, True])
def test_legacy_migration_is_additive_preserves_history_and_does_not_guess(tmp_path, nullable, old_optional):
    path = str(tmp_path / "legacy.db")
    database = DatabaseManager(path)
    try:
        database.init_db()
        result, _, tl, verdict = outcome(database, prediction="MEDIUM")
        conn = database.connection
        conn.execute("DROP TABLE evaluations")
        nullability = "" if nullable else " NOT NULL"
        optional = ",confidence_score REAL,severity_prediction TEXT" if old_optional else ""
        conn.execute("CREATE TABLE evaluations(id INTEGER PRIMARY KEY AUTOINCREMENT,timeline_id TEXT NOT NULL,verdict_id TEXT" + nullability + ",ground_truth INTEGER,llm_prediction INTEGER" + nullability + ",is_correct INTEGER,category TEXT NOT NULL,evaluated_at TEXT NOT NULL" + optional + ",FOREIGN KEY(timeline_id) REFERENCES timelines(id) ON DELETE CASCADE,FOREIGN KEY(verdict_id) REFERENCES verdicts(id) ON DELETE CASCADE)")
        conn.execute("INSERT INTO evaluations(id,timeline_id,verdict_id,ground_truth,llm_prediction,is_correct,category,evaluated_at) VALUES(7,?,?,1,1,1,'True Positive','2026-01-01')", (str(tl.timeline_id), str(verdict.verdict_id)))
        conn.execute("CREATE INDEX custom_severity_index ON evaluations(category)")
        conn.execute("CREATE TRIGGER custom_severity_trigger AFTER INSERT ON evaluations BEGIN SELECT 1; END")
        conn.execute("UPDATE sqlite_sequence SET seq=99 WHERE name='evaluations'")
        conn.commit()
        before = dict(conn.execute("SELECT * FROM evaluations").fetchone())
        database.close()
        database = DatabaseManager(path)
        database.init_db()
        database.init_db()
        conn = database.connection
        after = dict(conn.execute("SELECT * FROM evaluations WHERE id=7").fetchone())
        assert {key:after[key] for key in before} == before
        columns = {row["name"]:row["notnull"] for row in conn.execute("PRAGMA table_info(evaluations)")}
        assert columns["severity_ground_truth"] == columns["severity_correct"] == 0
        assert after["severity_ground_truth"] is after["severity_correct"] is None
        legacy = database.get_all_evaluations()[0]
        assert legacy.severity_ground_truth is legacy.severity_correct is None
        assert legacy.severity_prediction == "MEDIUM"  # existing verdict fallback remains supported
        assert AccuracyTracker.from_database(database).get_metrics()["severity_evaluated"] == 0
        assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('custom_severity_index','custom_severity_trigger')").fetchone()[0] == 2
        assert database.insert_evaluation(result) == 100
        assert database.get_all_evaluations()[-1].severity_correct is False
        assert not list(conn.execute("PRAGMA foreign_key_check"))
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        database.close()


@pytest.mark.parametrize("fields", [(), ("severity_ground_truth",), ("severity_correct",), ("severity_ground_truth", "severity_correct")])
def test_readers_handle_legacy_and_partially_extended_schema_without_migration(db, fields):
    result, _, tl, verdict = outcome(db)
    conn = db.connection
    conn.execute("DROP TABLE evaluations")
    extra = "".join("," + name + (" INTEGER" if name == "severity_correct" else " TEXT") for name in fields)
    conn.execute("CREATE TABLE evaluations(id INTEGER PRIMARY KEY AUTOINCREMENT,timeline_id TEXT,verdict_id TEXT,ground_truth INTEGER,llm_prediction INTEGER,is_correct INTEGER,category TEXT,evaluated_at TEXT" + extra + ")")
    conn.execute("INSERT INTO evaluations(timeline_id,verdict_id,ground_truth,llm_prediction,is_correct,category,evaluated_at) VALUES(?,?,1,1,1,'True Positive','2026-01-01')", (str(tl.timeline_id), str(verdict.verdict_id)))
    for name in fields:
        conn.execute("UPDATE evaluations SET " + name + "=?", (0 if name == "severity_correct" else "CRITICAL",))
    conn.commit()
    loaded = db.get_all_evaluations()[0]
    row = db.get_evaluations_for_timeline(tl.timeline_id)[0]
    for name in ("severity_ground_truth", "severity_correct"):
        expected = (False if name == "severity_correct" else "CRITICAL") if name in fields else None
        assert getattr(loaded, name) == expected
        if name == "severity_correct":
            assert row[name] is expected
        else:
            assert row[name] == expected


def test_stored_severity_result_does_not_change_when_verdict_is_updated(db):
    result, _, tl, verdict = outcome(db)
    db.insert_evaluation(result)
    db.connection.execute("UPDATE verdicts SET severity='LOW' WHERE id=?", (str(verdict.verdict_id),))
    db.connection.commit()
    tl.alerts[0].original_record["severity"] = "CRITICAL"
    loaded = db.get_all_evaluations()[0]
    assert loaded.severity_ground_truth == loaded.severity_prediction == "HIGH"
    assert loaded.severity_correct is True


@pytest.mark.parametrize("runner", ["cli", "evaluation"])
@pytest.mark.parametrize("prediction", ["HIGH", "MEDIUM"])
def test_runner_and_api_agree_on_persisted_severity(monkeypatch, tmp_path, runner, prediction):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "runner.db"))

    class OfflineEngine:
        model = "offline-fixture"
        fallback_models = []

        def __init__(self, **kwargs):
            pass

        def analyze_timeline(self, tl):
            return TriageVerdict(timeline_id=tl.timeline_id, severity=prediction, confidence_score=0.9,
                                 summary="Fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")

    opened = []

    class RecordedDatabase(DatabaseManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            opened.append(self)

    if runner == "cli":
        module = cli
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "alert.json").write_text(json.dumps([{"event_type":"ProcessStart", "is_malicious":True, "severity":"HIGH", "host":"offline-host", "user":"offline-user"}]), encoding="utf-8")
        monkeypatch.setattr(config, "get_groq_api_key", lambda: "offline-placeholder")
        monkeypatch.setattr(cli, "EnrichmentEngine", lambda **kwargs: EnrichmentEngine(providers={}, daily_quotas={}, **kwargs))

        def run():
            return cli.run_pipeline(data_dir=str(input_dir))
    else:
        from scripts import run_evaluation as module
        monkeypatch.setattr(module, "get_groq_api_key", lambda: "offline-placeholder")
        alert = NormalizedAlert(source_dataset="offline", source_file="fixture.json", event_type="ProcessStart",
                                original_record={"is_malicious":True,"severity":"HIGH"})

        def run():
            return module.run_evaluation_pipeline(timelines=[ThreatTimeline(grouping_key="offline", alerts=[alert], total_events=1)])

    monkeypatch.setattr(module, "DatabaseManager", RecordedDatabase)
    monkeypatch.setattr(module, "GroqTriageEngine", OfflineEngine)
    app = None
    try:
        metrics = run()
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/api/metrics")
        assert response.status_code == 200
        api = response.json()
        assert api["severity_evaluated"] == metrics["severity_evaluated"] == 1
        assert api["severity_matches"] == metrics["severity_matches"] == (prediction == "HIGH")
        assert api["severity_accuracy"] == metrics["severity_accuracy"] == float(prediction == "HIGH")
        assert api["tp"] == metrics["tp"] == 1
    finally:
        for database in opened:
            database.close()
        if app is not None:
            app.state.db.close()
