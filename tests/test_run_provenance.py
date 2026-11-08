"""Offline stage-1 provenance lifecycle, atomicity, and history compatibility."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import threading
from uuid import UUID

import pytest
import httpx

from src.engine.database import DatabaseManager
from src.engine.evaluation import AccuracyTracker
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


@pytest.fixture
def db():
    database = DatabaseManager()
    database.init_db()
    yield database
    database.close()


def outcome(db):
    tl = ThreatTimeline(grouping_key="offline", total_events=1, alerts=[NormalizedAlert(
        source_dataset="offline", source_file="fixture.json", event_type="ProcessStart",
        original_record={"is_malicious":True,"severity":"HIGH"},
    )])
    db.insert_timeline(tl)
    verdict = TriageVerdict(timeline_id=tl.timeline_id, severity="HIGH", confidence_score=0.9,
                           summary="Fixture", reasoning=[], recommended_actions=[], raw_llm_response="{}")
    return tl, verdict, AccuracyTracker().evaluate(verdict, tl)


def pending(db, tl, ordinal=1, run_id=None, origin="fresh"):
    run_id = run_id or db.create_evaluation_run("evaluation")
    observation_id = db.start_observation(run_id, ordinal, tl.timeline_id)
    db.mark_observation_acquisition(observation_id, origin)
    return run_id, observation_id


def test_terminal_outcome_is_idempotent_and_run_finishes(db):
    tl, verdict, result = outcome(db)
    run_id, observation_id = pending(db, tl)
    first = db.finalize_observation(observation_id, result, verdict=verdict)
    assert db.finalize_observation(observation_id, result, verdict=verdict) == first
    db.finish_evaluation_run(run_id)
    record = db.get_evaluation_run(run_id)
    observation = db.get_triage_observations(run_id)[0]
    assert record["status"] == "completed"
    assert observation["status"] == "completed"
    assert UUID(observation["attempt_id"])
    assert observation["origin"] == "fresh"
    assert db.connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 1
    stored = db.get_all_evaluations()[0]
    assert str(stored.observation_id) == observation_id
    assert stored.provenance_version == 1
    assert stored.severity_correct is True


@pytest.mark.parametrize("field,value", [("confidence_score",0.2),("severity_correct",False),("ground_truth",False)])
def test_conflicting_terminal_retry_is_rejected(db, field, value):
    tl, verdict, result = outcome(db)
    run_id, observation_id = pending(db, tl)
    db.finalize_observation(observation_id, result, verdict=verdict)
    with pytest.raises(ValueError, match="conflict"):
        db.finalize_observation(observation_id, result.model_copy(update={field:value}), verdict=verdict)
    assert db.connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 1


def test_replay_occurrences_preserve_history_counting(db):
    tl, verdict, result = outcome(db)
    run_id, first = pending(db, tl)
    db.finalize_observation(first, result, verdict=verdict)
    _, second = pending(db, tl, ordinal=2, run_id=run_id, origin="cache")
    db.finalize_observation(second, result, verdict=verdict)
    db.finish_evaluation_run(run_id)
    observations = db.get_triage_observations(run_id)
    assert len(observations) == 2
    assert observations[1]["attempt_id"] is None
    assert observations[1]["cache_validation"] == "unverified"
    assert AccuracyTracker.from_database(db).get_metrics()["total"] == 2


def test_atomic_failure_preserves_pending_observation_and_rolls_back_verdict(db):
    tl, verdict, result = outcome(db)
    run_id, observation_id = pending(db, tl)
    db.connection.execute("CREATE TRIGGER fail_outcome BEFORE UPDATE OF status ON triage_observations WHEN NEW.status='completed' BEGIN SELECT RAISE(ABORT,'offline failure'); END")
    db.connection.commit()
    with pytest.raises(sqlite3.IntegrityError, match="offline failure"):
        db.finalize_observation(observation_id, result, verdict=verdict)
    assert db.connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 0
    assert db.get_verdict(verdict.verdict_id) is None
    assert db.get_triage_observations(run_id)[0]["status"] == "pending"
    db.connection.execute("DROP TRIGGER fail_outcome")
    db.connection.commit()
    db.finalize_observation(observation_id, result, verdict=verdict)


@pytest.mark.parametrize('error_type',[RuntimeError,KeyboardInterrupt])
def test_run_error_marks_pending_work_interrupted_without_inventing_outcome(tmp_path,error_type):
    from src.engine.provenance import evaluation_run
    db = DatabaseManager(str(tmp_path / 'interrupted.db'))
    db.init_db()
    tl, _, _ = outcome(db)
    try:
        with pytest.raises(error_type, match="offline interruption"):
            with evaluation_run(db, "cli") as run:
                run_id = run.run_id
                run.observe(tl, 1)
                raise error_type("offline interruption")
        assert db.get_evaluation_run(run_id)['status'] == 'failed'
        assert db.get_triage_observations(run_id)[0]['status'] == 'interrupted'
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0] == 0
    finally:
        db.close()


def test_skips_and_opaque_acquisition_do_not_claim_fresh_attempts(db):
    tl, _, _ = outcome(db)
    run_id = db.create_evaluation_run("cli")
    skipped = db.start_observation(run_id, 1, tl.timeline_id)
    db.skip_observation(skipped)
    unknown = db.start_observation(run_id, 2, tl.timeline_id)
    db.mark_observation_acquisition(unknown, "unknown")
    db.finalize_observation(unknown, AccuracyTracker().evaluate(None, tl), failure_category="no_verdict")
    db.finish_evaluation_run(run_id)
    records = db.get_triage_observations(run_id)
    assert [row["status"] for row in records] == ["skipped","completed"]
    assert all(row["attempt_id"] is None for row in records)
    assert AccuracyTracker.from_database(db).get_metrics()["unavailable"] == 1


def test_run_cannot_complete_with_pending_work_or_accept_work_after_completion(db):
    tl, _, _ = outcome(db)
    run_id, observation_id = pending(db, tl)
    with pytest.raises(ValueError, match="pending"):
        db.finish_evaluation_run(run_id)
    db.fail_evaluation_run(run_id)
    assert db.get_triage_observations(run_id)[0]["status"] == "interrupted"
    assert db.get_evaluation_run(run_id)["status"] == "failed"
    with pytest.raises(ValueError, match="running"):
        db.start_observation(run_id, 2, tl.timeline_id)


def test_legacy_rows_remain_unknown_after_repeat_initialization(db):
    tl, verdict, result = outcome(db)
    db.insert_verdict(verdict)
    legacy_id = db.insert_evaluation(result)
    db.init_db()
    db.init_db()
    row = db.connection.execute("SELECT * FROM evaluations WHERE id=?",(legacy_id,)).fetchone()
    assert row["observation_id"] is row["provenance_version"] is None
    assert db.connection.execute("SELECT COUNT(*) FROM evaluation_runs").fetchone()[0] == 0
    coverage = db.get_provenance_coverage()
    assert coverage["legacy_unknown"] == coverage["evaluation_rows"] == 1


def test_independent_connections_finalize_one_observation_once(tmp_path):
    path = str(tmp_path / "concurrent.db")
    databases = [DatabaseManager(path),DatabaseManager(path)]
    for database in databases:
        database.init_db()
    tl, verdict, result = outcome(databases[0])
    run_id, observation_id = pending(databases[0], tl)
    barrier = threading.Barrier(2)

    def finalize(index):
        barrier.wait(timeout=5)
        return databases[index].finalize_observation(observation_id, result, verdict=verdict)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            ids = list(pool.map(finalize, range(2)))
        assert ids[0] == ids[1]
        assert databases[0].connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 1
        assert not list(databases[0].connection.execute("PRAGMA foreign_key_check"))
    finally:
        for database in databases:
            database.close()


def test_verdict_snapshot_conflicts_on_terminal_retry(db):
    tl, verdict, result = outcome(db)
    _, observation_id = pending(db, tl)
    db.finalize_observation(observation_id, result, verdict=verdict)
    with pytest.raises(ValueError, match='conflict'):
        db.finalize_observation(observation_id, result, verdict=verdict.model_copy(update={'summary':'changed'}))
    # Omitting the already-persisted verdict on retry is safe and idempotent.
    assert db.finalize_observation(observation_id, result) == 1


def test_observation_identity_and_foreign_keys_are_enforced(db):
    tl, verdict, result = outcome(db)
    run_id, observation_id = pending(db, tl)
    assert db.start_observation(run_id,1,tl.timeline_id) == observation_id
    other, _, _ = outcome(db)
    with pytest.raises(ValueError, match='conflict'):
        db.start_observation(run_id,1,other.timeline_id)
    with pytest.raises(sqlite3.IntegrityError):
        db.start_observation(run_id,2,UUID(int=1))
    with pytest.raises(ValueError, match='conflict'):
        db.finalize_observation(observation_id,result.model_copy(update={'timeline_id':other.timeline_id}),verdict=verdict)
    assert db.get_triage_observations(run_id)[0]['status'] == 'pending'


def test_lifecycle_uses_injected_clock(tmp_path):
    from src.engine.provenance import evaluation_run
    ticks = [datetime(2026,1,1,tzinfo=timezone.utc)]
    db = DatabaseManager(str(tmp_path / 'clock.db'), clock=lambda:ticks[0])
    try:
        with evaluation_run(db,'cli') as run:
            run_id = run.run_id
            tl, _, _ = outcome(db)
            observation_id = run.observe(tl,1)
            ticks[0] += timedelta(seconds=2)
            db.skip_observation(observation_id)
        record = db.get_evaluation_run(run_id)
        observation = db.get_triage_observations(run_id)[0]
        assert record['started_at'] == '2026-01-01T00:00:00+00:00'
        assert record['ended_at'] == observation['ended_at'] == ticks[0].isoformat()
    finally:
        db.close()


def successful_response():
    return httpx.Response(200,json={'outputs':[{'message':{'segments':[{'text':json.dumps({
        'severity':'HIGH','confidence_score':0.9,'summary':'Offline fixture',
        'reasoning':['Fixture'],'recommended_actions':['Review'],
        'uncertainty_level':'HIGH','missing_information':[],
    })}]}}]})


def test_real_engine_reports_fresh_then_memory_cache_and_keeps_evaluation_metadata_out(db):
    from conftest import PipelineTestEngine
    from src.engine.provenance import RunRecorder
    calls = []

    def send(url, **kwargs):
        calls.append(kwargs)
        record = db.connection.execute('SELECT origin,attempt_id,status FROM triage_observations ORDER BY ordinal DESC LIMIT 1').fetchone()
        assert record['origin'] == 'fresh' and record['attempt_id'] and record['status'] == 'pending'
        return successful_response()

    engine = PipelineTestEngine(api_key='offline-placeholder',model='offline-model',fallback_models=[],request_sender=send)
    tl, _, _ = outcome(db)
    run = RunRecorder(db,'evaluation')
    tracker = AccuracyTracker()
    for ordinal in (1,2):
        observation_id = run.observe(tl,ordinal)
        acquisition = run.acquire(engine,tl,observation_id)
        run.complete(observation_id,tracker.evaluate(acquisition.verdict,tl),tl,tracker,verdict=acquisition.verdict)
    db.finish_evaluation_run(run.run_id)
    assert [row['origin'] for row in db.get_triage_observations(run.run_id)] == ['fresh','cache']
    assert len(calls) == 1
    payload = json.dumps(calls[0]['json'])
    for name in ('observation_id','evaluation_context_hash','quality_cohort_hash','ground_truth','is_malicious'):
        assert name not in payload
    rows = db.get_all_evaluations()
    assert rows[0].evaluation_context_hash == rows[1].evaluation_context_hash
    assert rows[0].quality_cohort_hash == rows[1].quality_cohort_hash
    assert AccuracyTracker.from_database(db).get_metrics()['total'] == 2


def test_acquisition_storage_failure_stops_http_and_marks_run_failed(monkeypatch,tmp_path):
    from conftest import PipelineTestEngine
    from src.engine.provenance import AcquisitionPersistenceError, evaluation_run
    db = DatabaseManager(str(tmp_path / 'before-send.db'))
    calls = []
    engine = PipelineTestEngine(api_key='offline-placeholder',model='offline-model',fallback_models=[],
                               request_sender=lambda *args,**kwargs:calls.append(kwargs))
    try:
        with pytest.raises(AcquisitionPersistenceError):
            with evaluation_run(db,'evaluation') as run:
                run_id = run.run_id
                tl, _, _ = outcome(db)
                observation_id = run.observe(tl,1)

                def fail(*args,**kwargs):
                    raise sqlite3.OperationalError('offline storage failure')

                monkeypatch.setattr(db,'mark_observation_acquisition',fail)
                run.acquire(engine,tl,observation_id)
        assert calls == []
        assert db.get_evaluation_run(run_id)['status'] == 'failed'
        assert db.get_triage_observations(run_id)[0]['status'] == 'interrupted'
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0] == 0
    finally:
        db.close()


def test_provider_cannot_claim_fresh_after_work_without_notification():
    from src.engine.provenance import AcquisitionOutcome, acquire_triage

    class OpaqueMetadataProvider:
        def acquire_timeline(self, timeline, **kwargs):
            return AcquisitionOutcome(None,'fresh','no_verdict')

    with pytest.raises(ValueError,match='before'):
        acquire_triage(OpaqueMetadataProvider(),None,lambda origin:None)


@pytest.mark.parametrize('runner',['cli','evaluation'])
def test_real_runners_persist_lifecycle_but_keep_history_metrics(monkeypatch,tmp_path,runner):
    from fastapi.testclient import TestClient
    from src import cli, config
    from src.api.main import create_app
    from src.engine.enrichment import EnrichmentEngine
    from conftest import PipelineTestEngine
    path = str(tmp_path / 'runner.db')
    monkeypatch.setenv('DATABASE_PATH',path)
    calls = []

    def send(url,**kwargs):
        calls.append(kwargs)
        check = sqlite3.connect(path)
        try:
            row = check.execute("SELECT status,origin,attempt_id FROM triage_observations WHERE status='pending'").fetchone()
            assert row[0:2] == ('pending','fresh') and row[2]
        finally:
            check.close()
        return successful_response()

    def engine(**kwargs):
        return PipelineTestEngine(api_key='offline-placeholder',model='offline-model',fallback_models=[],request_sender=send)

    if runner == 'cli':
        module = cli
        monkeypatch.setattr(config,'get_groq_api_key',lambda:'offline-placeholder')
        monkeypatch.setattr(cli,'EnrichmentEngine',lambda **kwargs:EnrichmentEngine(providers={},daily_quotas={},**kwargs))
        input_dir = tmp_path / 'input'
        input_dir.mkdir()
        (input_dir / 'fixture.json').write_text('[{"event_type":"ProcessStart","host":"offline","user":"analyst","is_malicious":true,"severity":"HIGH"}]',encoding='utf-8')

        def run():
            return cli.run_pipeline(data_dir=str(input_dir))
    else:
        from scripts import run_evaluation as module
        monkeypatch.setattr(module,'get_groq_api_key',lambda:'offline-placeholder')
        alert = NormalizedAlert(source_dataset='offline',source_file='fixture.json',event_type='ProcessStart',original_record={'is_malicious':True,'severity':'HIGH'})
        tl = ThreatTimeline(grouping_key='offline',alerts=[alert],total_events=1)

        def run():
            return module.run_evaluation_pipeline(timelines=[tl])

    monkeypatch.setattr(module,'GroqTriageEngine',engine)
    for _ in range(2):
        assert run()['total'] == 1
    db = DatabaseManager(path)
    try:
        runs = list(db.connection.execute('SELECT * FROM evaluation_runs ORDER BY rowid'))
        assert len(runs) == 2 and all(row['status']=='completed' for row in runs)
        observations = [db.get_triage_observations(row['run_id'])[0] for row in runs]
        assert [row['origin'] for row in observations] == (['fresh','cache'] if runner=='evaluation' else ['fresh','fresh'])
        assert len(calls) == (1 if runner=='evaluation' else 2)
        assert [row['cache_validation'] for row in observations] == (
            ['unverified','verified'] if runner=='evaluation' else ['unverified','unverified'])
        assert len({row.quality_cohort_hash for row in db.get_all_evaluations()}) == 2
        with TestClient(create_app(db=db)) as client:
            response = client.get('/api/metrics')
        assert response.status_code == 200
        assert response.json()['total'] == response.json()['tp'] == 2
        assert db.get_provenance_coverage() == {'evaluation_rows':2,'legacy_unknown':0,'linked':2}
    finally:
        db.close()


def test_context_closes_database_even_when_run_creation_fails(monkeypatch,tmp_path):
    from src.engine.provenance import evaluation_run
    db = DatabaseManager(str(tmp_path / 'start-failure.db'))

    def fail(*args):
        raise RuntimeError('offline run start failure')

    monkeypatch.setattr(db,'create_evaluation_run',fail)
    with pytest.raises(RuntimeError,match='run start failure'):
        with evaluation_run(db,'cli'):
            pytest.fail('Run body must not execute')
    assert db._conn is None


def test_tracked_outcome_cannot_bypass_atomic_finalization(db):
    tl, verdict, result = outcome(db)
    _, observation_id = pending(db,tl)
    with pytest.raises(ValueError,match='finalize_observation'):
        db.insert_evaluation(result.model_copy(update={'observation_id':UUID(observation_id)}))
    assert db.get_verdict(verdict.verdict_id) is None
    assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0] == 0


def test_wrong_cohort_cannot_be_attached_to_an_observation(db):
    tl, verdict, result = outcome(db)
    run_id, observation_id = pending(db,tl)
    with pytest.raises(ValueError,match='cohort conflict'):
        db.finalize_observation(observation_id,result.model_copy(update={'quality_cohort_hash':'wrong-cohort'}),verdict=verdict)
    assert db.get_triage_observations(run_id)[0]['status'] == 'pending'
    assert db.get_verdict(verdict.verdict_id) is None


def test_fallback_http_calls_are_one_logical_fresh_attempt(db):
    from conftest import PipelineTestEngine
    from src.engine.provenance import RunRecorder, _ACQUISITION
    calls = []

    def send(url, **kwargs):
        calls.append(url)
        return httpx.Response(503,json={}) if len(calls)==1 else successful_response()

    engine = PipelineTestEngine(api_key='offline-placeholder',model='offline-primary',
                               fallback_models=['offline-fallback'],request_sender=send)
    run = RunRecorder(db,'evaluation')
    tl, _, _ = outcome(db)
    observation_id = run.observe(tl,1)
    acquisition = run.acquire(engine,tl,observation_id)
    tracker = AccuracyTracker()
    run.complete(observation_id,tracker.evaluate(acquisition.verdict,tl),tl,tracker,verdict=acquisition.verdict)
    db.finish_evaluation_run(run.run_id)
    assert len(calls) == 2
    records = db.get_triage_observations(run.run_id)
    assert len(records) == 1 and records[0]['attempt_id'] and records[0]['origin']=='fresh'
    assert acquisition.verdict.model_name == 'offline-fallback'
    assert _ACQUISITION.get() is None


@pytest.mark.parametrize('missing_input',[False,True])
def test_cli_skip_or_missing_input_has_honest_run_lifecycle(monkeypatch,tmp_path,missing_input):
    from src import cli, config
    from src.engine.enrichment import EnrichmentEngine
    path = str(tmp_path / 'cli-lifecycle.db')
    monkeypatch.setenv('DATABASE_PATH',path)
    monkeypatch.setattr(config,'get_groq_api_key',lambda:None)
    monkeypatch.setattr(cli,'EnrichmentEngine',lambda **kwargs:EnrichmentEngine(providers={},daily_quotas={},**kwargs))
    input_dir = tmp_path / 'input'
    if not missing_input:
        input_dir.mkdir()
        (input_dir / 'fixture.json').write_text('[{"event_type":"ProcessStart"}]',encoding='utf-8')
    if missing_input:
        with pytest.raises(FileNotFoundError):
            cli.run_pipeline(data_dir=str(input_dir))
    else:
        assert cli.run_pipeline(data_dir=str(input_dir),skip_llm=True)['total'] == 0
    db = DatabaseManager(path)
    try:
        runs = list(db.connection.execute('SELECT * FROM evaluation_runs'))
        assert len(runs) == 1
        assert runs[0]['status'] == ('failed' if missing_input else 'completed')
        observations = db.get_triage_observations(runs[0]['run_id'])
        if missing_input:
            assert observations == []
        else:
            assert len(observations) == 1 and observations[0]['status']=='skipped'
            assert observations[0]['attempt_id'] is None
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0] == 0
    finally:
        db.close()
