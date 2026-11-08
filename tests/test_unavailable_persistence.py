"""Offline persistence, legacy migration, and attempted-triage availability."""

import json
import sqlite3
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from src import cli, config
from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.enrichment import EnrichmentEngine
from src.engine.evaluation import AccuracyTracker
from src.models.alert import NormalizedAlert
from src.models.evaluation import EvaluationResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def timeline(label=True):
    return ThreatTimeline(grouping_key=str(uuid4()), total_events=1, alerts=[NormalizedAlert(
        source_dataset="offline", source_file="fixture.json", event_type="ProcessStart",
        original_record={} if label is None else {"is_malicious": label},
    )])


@pytest.fixture
def db():
    database = DatabaseManager()
    database.init_db()
    yield database
    database.close()


@pytest.mark.parametrize("label", [True, False, None])
def test_unavailable_roundtrip_preserves_sql_nulls_and_ground_truth(db, label):
    tl = timeline(label)
    db.insert_timeline(tl)
    tracker = AccuracyTracker()
    result = tracker.evaluate(None, tl)
    db.insert_evaluation(result)
    raw = db.connection.execute("SELECT verdict_id,llm_prediction,is_correct,confidence_score FROM evaluations").fetchone()
    assert tuple(raw) == (None, None, None, None)
    loaded = db.get_all_evaluations()
    assert len(loaded) == 1
    assert loaded[0].category == "Unavailable"
    assert loaded[0].ground_truth is label
    assert loaded[0].verdict_id is loaded[0].llm_prediction is loaded[0].is_correct is None
    by_timeline = db.get_evaluations_for_timeline(tl.timeline_id)
    assert by_timeline[0]["llm_prediction"] is None
    assert by_timeline[0]["verdict_id"] is None
    metrics = AccuracyTracker.from_database(db).get_metrics()
    assert metrics["unavailable"] == 1
    assert metrics["availability_rate"] == 0.0
    assert metrics["total"] == metrics["fp"] == metrics["fn"] == 0
    assert metrics["brier_score"] is None


def test_unavailable_keeps_timeline_foreign_key_enforced(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_evaluation(EvaluationResult(timeline_id=uuid4(), category="Unavailable"))
    assert db.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


@pytest.mark.parametrize("old_optional_columns", [False, True])
def test_legacy_migration_preserves_rows_ids_sequence_indexes_and_foreign_keys(tmp_path, old_optional_columns):
    path = str(tmp_path / "legacy.db")
    database = DatabaseManager(path)
    database.init_db()
    tl = timeline()
    database.insert_timeline(tl)
    verdict = TriageVerdict(timeline_id=tl.timeline_id, severity="HIGH", confidence_score=0.8,
                           summary="Fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")
    database.insert_verdict(verdict)
    conn = database.connection
    conn.execute("DROP TABLE evaluations")
    extras = ", confidence_score REAL, severity_prediction TEXT" if old_optional_columns else ""
    conn.execute("CREATE TABLE evaluations (id INTEGER PRIMARY KEY AUTOINCREMENT, timeline_id TEXT NOT NULL, verdict_id TEXT NOT NULL, ground_truth INTEGER, llm_prediction INTEGER NOT NULL, is_correct INTEGER, category TEXT NOT NULL, evaluated_at TEXT NOT NULL" + extras + ", FOREIGN KEY(timeline_id) REFERENCES timelines(id) ON DELETE CASCADE, FOREIGN KEY(verdict_id) REFERENCES verdicts(id) ON DELETE CASCADE)")
    conn.execute("INSERT INTO evaluations(id,timeline_id,verdict_id,ground_truth,llm_prediction,is_correct,category,evaluated_at) VALUES(7,?,?,1,1,1,'True Positive','2026-01-01')", (str(tl.timeline_id),str(verdict.verdict_id)))
    conn.execute("UPDATE sqlite_sequence SET seq=99 WHERE name='evaluations'")
    conn.execute("CREATE INDEX custom_eval_category ON evaluations(category)")
    conn.execute("CREATE TRIGGER custom_eval_trigger AFTER INSERT ON evaluations BEGIN SELECT 1; END")
    conn.commit()
    before = dict(conn.execute("SELECT * FROM evaluations").fetchone())
    database.close()
    database = DatabaseManager(path)
    try:
        database.init_db()
        database.init_db()  # migration is safe to repeat
        conn = database.connection
        columns = {row["name"]:row["notnull"] for row in conn.execute("PRAGMA table_info(evaluations)")}
        assert columns["verdict_id"] == columns["llm_prediction"] == 0
        after = dict(conn.execute("SELECT * FROM evaluations WHERE id=7").fetchone())
        assert {key:after[key] for key in before} == before
        assert "custom_eval_category" in {row["name"] for row in conn.execute("PRAGMA index_list(evaluations)")}
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name='custom_eval_trigger'").fetchone()
        assert not list(conn.execute("PRAGMA foreign_key_check"))
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        new_id = database.insert_evaluation(AccuracyTracker().evaluate(None, tl))
        assert new_id == 100
        with pytest.raises(sqlite3.IntegrityError):
            database.insert_evaluation(EvaluationResult(timeline_id=tl.timeline_id, verdict_id=uuid4(), category="True Positive", llm_prediction=True))
    finally:
        database.close()


def test_failed_legacy_migration_rolls_back_table_rebuild(db):
    conn = db.connection
    conn.execute("DROP TABLE evaluations")
    conn.execute("CREATE TABLE evaluations(id INTEGER PRIMARY KEY AUTOINCREMENT, timeline_id TEXT NOT NULL, verdict_id TEXT NOT NULL, ground_truth INTEGER, llm_prediction INTEGER NOT NULL, is_correct INTEGER, category TEXT NOT NULL, evaluated_at TEXT NOT NULL, confidence_score REAL, severity_prediction TEXT, FOREIGN KEY(timeline_id) REFERENCES timelines(id), FOREIGN KEY(verdict_id) REFERENCES verdicts(id))")
    conn.commit()
    tl = timeline()
    db.insert_timeline(tl)
    verdict = TriageVerdict(timeline_id=tl.timeline_id, severity="HIGH", confidence_score=0.8,
                           summary="Fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")
    db.insert_verdict(verdict)
    db.insert_evaluation(AccuracyTracker().evaluate(verdict, tl))
    before = tuple(conn.execute("SELECT * FROM evaluations").fetchone())

    def deny_drop(action, name, *args):
        if action == sqlite3.SQLITE_DROP_TABLE and name == "evaluations":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    conn.set_authorizer(deny_drop)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            db.init_db()
    finally:
        conn.set_authorizer(None)
    columns = {row["name"]:row["notnull"] for row in conn.execute("PRAGMA table_info(evaluations)")}
    assert columns["verdict_id"] == columns["llm_prediction"] == 1
    assert tuple(conn.execute("SELECT * FROM evaluations").fetchone()) == before
    assert not conn.execute("SELECT name FROM sqlite_master WHERE name='evaluations_nullable'").fetchone()
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    db.init_db()  # a later retry can complete after the failure is removed
    assert not list(conn.execute("PRAGMA foreign_key_check"))


def test_migration_refuses_custom_inbound_foreign_keys_without_losing_rows(db):
    conn = db.connection
    conn.execute("DROP TABLE evaluations")
    conn.execute("CREATE TABLE evaluations(id INTEGER PRIMARY KEY AUTOINCREMENT, timeline_id TEXT NOT NULL, verdict_id TEXT NOT NULL, ground_truth INTEGER, llm_prediction INTEGER NOT NULL, is_correct INTEGER, category TEXT NOT NULL, evaluated_at TEXT NOT NULL)")
    conn.execute("INSERT INTO evaluations(timeline_id,verdict_id,ground_truth,llm_prediction,is_correct,category,evaluated_at) VALUES('fixture','fixture',1,1,1,'True Positive','2026-01-01')")
    conn.execute("CREATE TABLE custom_notes(id INTEGER PRIMARY KEY, evaluation_id INTEGER REFERENCES evaluations(id) ON DELETE CASCADE)")
    conn.execute("INSERT INTO custom_notes VALUES(1,1)")
    conn.commit()
    with pytest.raises(ValueError, match="referenc"):
        db.init_db()
    assert conn.execute("SELECT COUNT(*) FROM custom_notes").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 1
    assert {row["name"]:row["notnull"] for row in conn.execute("PRAGMA table_info(evaluations)")}["verdict_id"] == 1


def test_evaluation_storage_failure_cannot_report_success(monkeypatch, tmp_path, capsys):
    from scripts import run_evaluation
    opened = []

    class FailingDatabase(DatabaseManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            opened.append(self)

        def insert_evaluation(self, result):
            raise sqlite3.OperationalError("offline outcome storage failure")

    monkeypatch.setattr(run_evaluation, "DatabaseManager", FailingDatabase)
    monkeypatch.setattr(run_evaluation, "get_gemini_api_key", lambda: "offline-placeholder")
    monkeypatch.setattr(run_evaluation, "GeminiTriageEngine", OfflineEngine)
    monkeypatch.setattr(OfflineEngine, "mode", "none")
    try:
        with pytest.raises(sqlite3.OperationalError, match="offline outcome storage failure"):
            run_evaluation.run_evaluation_pipeline(timelines=[timeline()], db_path=str(tmp_path / "failure.db"))
        assert "EVALUATION RUN COMPLETE" not in capsys.readouterr().out
    finally:
        for database in opened:
            database.close()


@pytest.mark.parametrize("label", [True, None])
def test_unavailable_report_does_not_label_missing_prediction_benign(monkeypatch, tmp_path, label):
    from scripts import run_evaluation
    monkeypatch.setattr(run_evaluation, "get_gemini_api_key", lambda: "offline-placeholder")
    monkeypatch.setattr(run_evaluation, "GeminiTriageEngine", OfflineEngine)
    monkeypatch.setattr(OfflineEngine, "mode", "none")
    output = tmp_path / "reports"
    metrics = run_evaluation.run_evaluation_pipeline(
        timelines=[timeline(label)], db_path=str(tmp_path / "report.db"), results_output_dir=str(output),
    )
    report = (output / "evaluation_report_20261106.md").read_text(encoding="utf-8")
    assert "| Unavailable | `N/A` | `Unavailable`" in report
    assert "| Benign | `N/A`" not in report
    assert ("**Unknown**" if label is None else "**Malicious**") in report
    assert metrics["unavailable"] == 1
    assert metrics["availability_rate"] == 0.0


def test_unknown_success_and_unavailable_have_distinct_availability_semantics(db):
    tracker = AccuracyTracker()
    unknown = timeline(None)
    failed = timeline()
    for tl in (unknown, failed):
        db.insert_timeline(tl)
    verdict = TriageVerdict(timeline_id=unknown.timeline_id, severity="LOW", confidence_score=0.8,
                           summary="Unknown fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")
    db.insert_verdict(verdict)
    db.insert_evaluation(tracker.evaluate(verdict, unknown))
    db.insert_evaluation(tracker.evaluate(None, failed))
    with TestClient(create_app(db=db)) as client:
        metrics = client.get("/api/metrics").json()
    assert metrics["total"] == 0
    assert metrics["unknown"] == metrics["unavailable"] == 1
    assert metrics["availability_rate"] == 0.5
    assert metrics["brier_score"] is None


def test_api_reads_only_unavailable_history_instead_of_fallback_tracker(db):
    tl = timeline()
    db.insert_timeline(tl)
    db.insert_evaluation(AccuracyTracker().evaluate(None, tl))
    stale_tracker = AccuracyTracker()
    stale_tracker.true_positives = stale_tracker.total_evaluated = 1
    with TestClient(create_app(db=db, tracker=stale_tracker)) as client:
        metrics = client.get("/api/metrics").json()
    assert metrics["unavailable"] == 1
    assert metrics["total"] == metrics["tp"] == 0
    assert metrics["availability_rate"] == 0.0


class OfflineEngine:
    mode = "ok"
    model = "offline-fixture"
    fallback_models = []

    def __init__(self, **kwargs):
        pass

    def analyze_timeline(self, tl):
        if self.mode == "none":
            return None
        if self.mode == "error":
            raise RuntimeError("offline fixture failure")
        return TriageVerdict(timeline_id=tl.timeline_id, severity="HIGH", confidence_score=0.9,
                             summary="Fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")


@pytest.mark.parametrize("runner", ["cli", "evaluation"])
@pytest.mark.parametrize("failure", ["none", "error"])
def test_repeated_runner_failures_are_persisted_and_in_api_denominator(monkeypatch, tmp_path, runner, failure):
    path = str(tmp_path / "attempts.db")
    monkeypatch.setenv("DATABASE_PATH", path)
    opened = []

    class RecordedDatabase(DatabaseManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            opened.append(self)

    if runner == "cli":
        module = cli
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "alert.json").write_text(json.dumps([{"event_type":"ProcessStart", "is_malicious":True, "host":"offline-host", "user":"offline-user"}]), encoding="utf-8")
        monkeypatch.setattr(config, "get_gemini_api_key", lambda: "offline-placeholder")
        monkeypatch.setattr(cli, "EnrichmentEngine", lambda **kwargs: EnrichmentEngine(providers={}, daily_quotas={}, **kwargs))

        def run():
            return cli.run_pipeline(data_dir=str(input_dir))
    else:
        from scripts import run_evaluation as module
        monkeypatch.setattr(module, "get_gemini_api_key", lambda: "offline-placeholder")

        def run():
            return module.run_evaluation_pipeline(timelines=[timeline()])

    monkeypatch.setattr(module, "DatabaseManager", RecordedDatabase)
    monkeypatch.setattr(module, "GeminiTriageEngine", OfflineEngine)
    app = create_app()
    try:
        with TestClient(app) as client:
            for index, mode in enumerate(("ok", failure, "ok"), start=1):
                monkeypatch.setattr(OfflineEngine, "mode", mode)
                metrics = run()
                assert metrics["unavailable"] == (1 if mode == failure else 0)
                assert metrics["availability_rate"] == (0.0 if mode == failure else 1.0)
                persisted = client.get("/api/metrics")
                assert persisted.status_code == 200
                values = persisted.json()
                assert values["total"] == (1 if index < 3 else 2)
                assert values["unavailable"] == (0 if index == 1 else 1)
                assert values["availability_rate"] == pytest.approx((index - (index > 1)) / index)
                assert values["fn"] == values["fp"] == 0
                assert app.state.db.connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == index
    finally:
        for database in opened:
            database.close()
        app.state.db.close()


@pytest.mark.parametrize("skip", ["flag", "no_key"])
def test_deliberately_inactive_cli_does_not_create_unavailable_outcome(monkeypatch, tmp_path, skip):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "skipped.db"))
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "alert.json").write_text('[{"event_type":"ProcessStart"}]', encoding="utf-8")
    monkeypatch.setattr(config, "get_gemini_api_key", lambda: None if skip == "no_key" else "offline-placeholder")
    monkeypatch.setattr(cli, "EnrichmentEngine", lambda **kwargs: EnrichmentEngine(providers={}, daily_quotas={}, **kwargs))
    opened = []

    class RecordedDatabase(DatabaseManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            opened.append(self)

    monkeypatch.setattr(cli, "DatabaseManager", RecordedDatabase)
    try:
        metrics = cli.run_pipeline(data_dir=str(input_dir), skip_llm=skip == "flag")
        assert metrics["unavailable"] == metrics["total"] == 0
        assert opened[0].connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 0
    finally:
        for database in opened:
            database.close()
