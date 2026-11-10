"""Shared persistence tests, with explicitly opt-in PostgreSQL on loopback."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from src.engine.database import DatabaseManager
from src.engine.hunting import HuntTimeoutError, ThreatHuntingEngine
from src.models.alert import GroundTruthMetadata, NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.evaluation import EvaluationResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


@pytest.fixture(scope='module')
def postgres_logins():
    test_dsn = os.getenv('TRIAGELENS_TEST_POSTGRES_DSN')
    if not test_dsn:
        pytest.skip('Set TRIAGELENS_TEST_POSTGRES_DSN for disposable loopback PostgreSQL tests')

    from alembic import command
    from alembic.config import Config
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from psycopg.sql import Identifier, Literal, SQL

    params = conninfo_to_dict(test_dsn)
    if params.get('host') != '127.0.0.1' or params.get('hostaddr', '127.0.0.1') != '127.0.0.1' or params.get('service'):
        pytest.fail('PostgreSQL test DSN must explicitly target loopback 127.0.0.1')
    admin_dsn = make_conninfo(test_dsn, hostaddr='127.0.0.1', connect_timeout=5)
    suffix = uuid4().hex[:12]
    name = f'triagelens_test_{suffix}'
    created_roles = []
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(SQL('CREATE DATABASE {}').format(Identifier(name)))
        try:
            migration_dsn = make_conninfo(admin_dsn, dbname=name)
            config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
            with pytest.MonkeyPatch.context() as env:
                env.setenv('TRIAGELENS_POSTGRES_MIGRATION_DSN', migration_dsn)
                command.upgrade(config, 'head')
                command.downgrade(config, 'base')
                command.upgrade(config, 'head')
            logins = {}
            for role in ('evaluator', 'analyst', 'triage', 'hunt'):
                username = f't51_{role}_{suffix}'
                login = Identifier(username)
                password = uuid4().hex
                admin.execute(SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(login, Literal(password)))
                created_roles.append(login)
                admin.execute(SQL('GRANT {} TO {}').format(Identifier(f'triagelens_{role}'), login))
                logins[role] = make_conninfo(migration_dsn, user=username, password=password)
            yield logins
        finally:
            admin.execute(SQL('DROP DATABASE {} WITH (FORCE)').format(Identifier(name)))
            for login in created_roles:
                admin.execute(SQL('DROP ROLE {}').format(login))


@pytest.fixture(params=('sqlite', 'postgresql'))
def databases(request, tmp_path):
    if request.param == 'sqlite':
        db = DatabaseManager(str(tmp_path / 'contract.db'))
        db.init_db()
        try:
            yield db, db
        finally:
            db.close()
    else:
        from src.engine.postgres import PostgresDatabase

        logins = request.getfixturevalue('postgres_logins')
        writer = PostgresDatabase(logins['evaluator'], 'evaluator', triage_dsn=logins['triage'])
        analyst = PostgresDatabase(logins['analyst'], 'analyst', hunt_dsn=logins['hunt'])
        try:
            writer.init_db()
            analyst.init_db()
            yield writer, analyst
        finally:
            analyst.close()
            writer.close()


def _alert(record, *, label=None, timestamp=None):
    return NormalizedAlert(source_dataset='synthetic', source_file='fixture.json', event_type='test-event',
                           original_record=record, ground_truth_label=label, timestamp=timestamp)


def test_alerts_timeline_labels_and_hunting(databases):
    writer, analyst = databases
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    token = uuid4().hex
    alert = _alert({'HostName': f'LAB_{token}', 'details': {'text': 'Literal_%', 'flag': True},
                    'raw_label': 'malicious', 'ports': {'0': 123}}, label='malicious', timestamp=now)
    alert.ground_truth_metadata = GroundTruthMetadata(relative_path='fixture.json', status='mapped')
    other = _alert({'details': {'text': 'Literal anything', 'flag': 'true'}, 'ports': [123]})
    timeline = ThreatTimeline(grouping_key=token, alerts=[alert, other], total_events=2)
    writer.insert_timeline(timeline)
    writer.insert_alert(alert.model_copy(update={'ground_truth_label': 'benign', 'ground_truth_metadata': None}))

    found = analyst.get_alert(alert.internal_id)
    assert found['original_record'] == alert.original_record
    assert found['ground_truth_label'] == 'malicious'
    assert found['ground_truth_metadata']['status'] == 'mapped'
    assert len(analyst.get_alerts_for_timeline(timeline.timeline_id)) == 2
    filtered = analyst.list_alerts(skip=0, limit=10, filters={'host': token, 'start': now.isoformat()},
                                   sort='timestamp', direction='asc')
    assert [row['id'] for row in filtered['items']] == [str(alert.internal_id)]

    hunter = ThreatHuntingEngine(analyst)
    selector = f'timeline_id == "{timeline.timeline_id}"'
    for condition in ('details.text contains "_%"', 'details.flag == true', 'ports.0 == 123',
                      'ground_truth_label == malicious', f'device.hostname contains "{token}"',
                      'NOT details.text !contains "_%"'):
        assert [row.internal_id for row in hunter.execute_hunt(f'{selector} AND {condition}')] == [alert.internal_id]
    assert hunter.execute_hunt(f'{selector} AND details.flag != true') == []
    assert hunter.execute_hunt(f'{selector} AND details.text == "O\'Reilly -- training notes"') == []
    hunter.save_query(token, selector)
    assert len(hunter.execute_saved_query(token)) == 2
    assert hunter.delete_saved_query(token)


def test_outcome_review_quota_and_atomic_rollback(databases):
    writer, analyst = databases
    timeline = ThreatTimeline(grouping_key='test-outcome')
    writer.insert_timeline(timeline)
    run = writer.create_evaluation_run('cli')
    observation = writer.start_observation(run, 1, timeline.timeline_id)
    writer.mark_observation_acquisition(observation, 'fresh')
    verdict = TriageVerdict(timeline_id=timeline.timeline_id, severity='LOW', confidence_score=0.25,
                            summary='Synthetic evidence', reasoning=['Synthetic observation'],
                            recommended_actions=['Review the fixture'], raw_llm_response='{}')
    outcome = EvaluationResult(timeline_id=timeline.timeline_id, verdict_id=verdict.verdict_id,
                               ground_truth=False, llm_prediction=False, is_correct=True, category='True Negative')
    with pytest.raises(RuntimeError, match='rollback probe'):
        with writer._atomic_write():
            writer.finalize_observation(observation, outcome, verdict)
            raise RuntimeError('rollback probe')
    assert writer.get_verdict(verdict.verdict_id) is None
    assert writer.get_evaluations_for_timeline(timeline.timeline_id) == []
    identity = writer.finalize_observation(observation, outcome, verdict)
    assert writer.finalize_observation(observation, outcome, verdict) == identity
    writer.finish_evaluation_run(run)
    assert analyst.metric_snapshot()['runs'][run]['status'] == 'completed'
    review = analyst.save_analyst_review(str(timeline.timeline_id), str(verdict.verdict_id),
                                        'confirm', None, 'Reviewed synthetic fixture')
    assert review['decision'] == 'confirm'

    provider = 'test-' + uuid4().hex
    assert writer.reserve_quota_request(provider, None)
    assert not writer.reserve_quota_request(provider, 1)
    assert writer.increment_quota_usage(provider, 2) == 3
    enrichment = EnrichmentResult(indicator='192.0.2.1', indicator_type='ip', provider=provider,
                                  is_malicious=False, raw_response={'fixture': True})
    assert writer.insert_enrichment(enrichment) > 0
    writer.set_cached_enrichment(provider, enrichment)
    assert analyst.get_cached_enrichment(provider).raw_response == {'fixture': True}


def test_postgresql_role_boundaries_and_timeout(postgres_logins):
    from psycopg.errors import InsufficientPrivilege
    import psycopg
    from src.engine.hunting_dsl import PostgresDialect
    from src.engine.postgres import PostgresDatabase

    with psycopg.connect(postgres_logins['triage'], autocommit=True) as triage:
        for relation in ('triagelens_truth.alert_labels', 'triagelens_truth.evaluations',
                         'triagelens.alerts', 'triagelens.hunting_alerts'):
            with pytest.raises(InsufficientPrivilege):
                triage.execute(f'SELECT * FROM {relation}')
        triage.execute('SELECT * FROM triagelens.verdicts')
    with psycopg.connect(postgres_logins['hunt'], autocommit=True) as hunter:
        hunter.execute('SELECT * FROM triagelens.hunting_alerts')
        assert hunter.execute("SELECT has_table_privilege('triagelens.hunting_alerts', 'DELETE')").fetchone() == (False,)
        with pytest.raises(InsufficientPrivilege):
            hunter.execute('DELETE FROM triagelens.alerts')
        with pytest.raises(InsufficientPrivilege):
            hunter.execute('SELECT * FROM triagelens_truth.evaluations')
    with psycopg.connect(postgres_logins['evaluator']) as evaluator:
        evaluator.execute('SELECT * FROM triagelens_truth.alert_labels')
        index = evaluator.execute('''
            SELECT indexdef FROM pg_indexes WHERE schemaname = 'triagelens' AND indexname = 'idx_alerts_raw_gin'
        ''').fetchone()
        assert 'USING gin (original_record)' in index[0]

    class SlowDialect(PostgresDialect):
        def select(self, predicate):
            return f"SELECT pg_sleep(1) FROM (SELECT 'x' AS event_type) AS probe WHERE {predicate} LIMIT ?"

    db = PostgresDatabase(postgres_logins['analyst'], 'analyst', hunt_dsn=postgres_logins['hunt'],
                          triage_dsn=postgres_logins['triage'])
    try:
        with pytest.raises(HuntTimeoutError):
            ThreatHuntingEngine(db, dialect=SlowDialect(), timeout=0.05).execute_hunt('event_type == x')
        assert ThreatHuntingEngine(db).execute_hunt('event_type == nonexistent') == []
        with db.triage_cache() as cache:
            assert cache.role == 'triage'
            assert cache.get_verdict_cache_candidates(uuid4()) == []
    finally:
        db.close()


def test_postgresql_cli_and_api(postgres_logins, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from src import cli, config
    from src.api.main import create_app
    from src.engine.enrichment import EnrichmentEngine

    monkeypatch.setenv('DATABASE_BACKEND', 'postgresql')
    for role, dsn in postgres_logins.items():
        monkeypatch.setenv(f'TRIAGELENS_POSTGRES_{role.upper()}_DSN', dsn)

    dataset = 't51-' + uuid4().hex
    (tmp_path / 'alerts.json').write_text(json.dumps([{
        'timestamp': '2026-01-01T00:00:00Z', 'event_type': 'ProcessStart', 'source_dataset': dataset,
        'host': 'offline-host', 'user': 'offline-user', 'ground_truth_label': 'malicious',
        'is_malicious': True, 'severity': 'HIGH', 'Details': {'GroundTruth': 'malicious', 'Count': 7},
    }]), encoding='utf-8')

    seen = []

    class OfflineTriage:
        def __init__(self, **kwargs):
            pass

        def analyze_timeline(self, timeline):
            seen.append(timeline)
            return TriageVerdict(timeline_id=timeline.timeline_id, severity='HIGH', confidence_score=0.9,
                                 summary='Synthetic assessment', reasoning=['Fixture evidence'],
                                 recommended_actions=['Review fixture'], raw_llm_response='{}')

    monkeypatch.setattr(cli, 'GroqTriageEngine', OfflineTriage)
    monkeypatch.setattr(config, 'get_groq_api_key', lambda: 'offline-fixture')
    monkeypatch.setattr(cli, 'EnrichmentEngine',
                        lambda **kwargs: EnrichmentEngine(providers={}, daily_quotas={}, **kwargs))

    assert cli.run_pipeline(data_dir=str(tmp_path))['tp'] == 1
    assert seen[0].alerts[0].ground_truth_label is None
    assert 'ground_truth_label' not in seen[0].alerts[0].original_record
    assert seen[0].alerts[0].original_record['Details'] == {'Count': 7}
    assert seen[0].alerts[0].source_file == ''

    app = create_app()
    try:
        with TestClient(app) as client:
            timeline = client.get(f'/api/timelines/{seen[0].timeline_id}').json()
            assert timeline['alerts'][0]['ground_truth_label'] == 'malicious'
            metrics = client.get('/api/metrics')
            assert metrics.status_code == 200 and metrics.json()['tp'] >= 1
            response = client.post('/api/hunt', json={'query': f'timeline_id == "{seen[0].timeline_id}"'})
            assert response.status_code == 200 and len(response.json()) == 1
    finally:
        app.state.db.close()
