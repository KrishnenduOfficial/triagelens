"""Offline stage-2 cache identity, policy, expiry, and history regressions."""

from datetime import datetime, timezone
import json

import httpx
import pytest

import src.engine.llm as llm
from conftest import PipelineTestEngine
from src.engine.database import DatabaseManager
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline


@pytest.fixture
def timeline():
    return ThreatTimeline(grouping_key='offline',correlation_reason='Fixture',total_events=1,
        alerts=[NormalizedAlert(source_dataset='offline',source_file='fixture.json',event_type='ProcessStart',
            original_record={'CommandLine':'fixture.exe','is_malicious':True,'severity':'HIGH'})])


class Sender:
    def __init__(self, fail_primary=False):
        self.calls = []
        self.fail_primary = fail_primary

    def __call__(self,url,**kwargs):
        self.calls.append((url,kwargs))
        if self.fail_primary and url.endswith('/offline-primary:triage'):
            return httpx.Response(503,json={})
        return httpx.Response(200,json={'outputs':[{'message':{'segments':[{'text':json.dumps({
            'severity':'HIGH','confidence_score':0.9,'summary':'Fixture','reasoning':['Fixture'],
            'recommended_actions':['Review'],'uncertainty_level':'HIGH','missing_information':[]})}]}}]})


def engine(sender, **kwargs):
    return PipelineTestEngine(api_key='offline-placeholder',model=kwargs.pop('model','offline-primary'),
                                  fallback_models=kwargs.pop('fallback_models',[]),request_sender=sender,**kwargs)


@pytest.mark.parametrize('change',['prompt','fallback_removal','fallback_order','serialization_version'])
def test_memory_cache_invalidates_changed_inference_policy(monkeypatch,timeline,change):
    sender = Sender(fail_primary=change.startswith('fallback'))
    provider = engine(sender,fallback_models=['offline-A','offline-B'] if sender.fail_primary else [])
    assert provider.analyze_timeline(timeline)
    before = len(sender.calls)
    if change=='prompt':
        monkeypatch.setattr(llm,'DFIR_SYSTEM_PROMPT',llm.DFIR_SYSTEM_PROMPT+'\nRevised policy.')
    elif change=='fallback_removal':
        provider.fallback_models=[]
    elif change=='fallback_order':
        provider.fallback_models=['offline-B','offline-A']
    else:
        monkeypatch.setattr(llm,'CACHE_PREPARATION_VERSION',999,raising=False)
    result = provider.analyze_timeline(timeline)
    assert len(sender.calls)>before
    if change=='fallback_removal':
        assert result is None
    elif change=='fallback_order':
        assert result.model_name=='offline-B'


def test_primary_only_cannot_reuse_shared_cache_fallback(timeline):
    cache = llm.LLMResponseCache()
    first = engine(Sender(fail_primary=True),cache=cache,fallback_models=['offline-fallback'])
    assert first.analyze_timeline(timeline).model_name=='offline-fallback'
    sender = Sender()
    second = engine(sender,cache=cache,fallback_models=[])
    assert second.analyze_timeline(timeline).model_name=='offline-primary'
    assert len(sender.calls)==1


def test_returned_verdict_mutation_does_not_corrupt_cache(timeline):
    sender = Sender()
    provider = engine(sender)
    first = provider.analyze_timeline(timeline)
    first.severity='INVALID'
    first.reasoning.append('caller mutation')
    second = provider.analyze_timeline(timeline)
    assert second.severity=='HIGH'
    assert second.reasoning==['Fixture']
    assert len(sender.calls)==1


def test_memory_cache_exact_deadline_and_no_replay_refresh(timeline):
    ticks = [datetime(2026,1,1,tzinfo=timezone.utc).timestamp()]
    sender = Sender()
    cache = llm.LLMResponseCache(ttl_seconds=60,clock=lambda:ticks[0])
    provider = engine(sender,cache=cache,cache_ttl_seconds=60,utc_clock=lambda:ticks[0])
    first = provider.analyze_timeline(timeline)
    ticks[0]+=30
    assert provider.analyze_timeline(timeline).verdict_id==first.verdict_id
    ticks[0]+=30
    assert provider.analyze_timeline(timeline).verdict_id!=first.verdict_id
    assert len(sender.calls)==2


def test_label_and_source_changes_do_not_invalidate_memory_cache(timeline):
    sender = Sender()
    provider = engine(sender)
    first = provider.analyze_timeline(timeline)
    timeline.alerts[0].original_record['is_malicious']=False
    timeline.alerts[0].ground_truth_label='benign'
    timeline.alerts[0].source_dataset='other-independent-label-source'
    timeline.alerts[0].source_file='different-label-file.json'
    assert provider.analyze_timeline(timeline).verdict_id==first.verdict_id
    assert len(sender.calls)==1


@pytest.mark.parametrize('change',['evidence','model','time_window'])
def test_memory_cache_refreshes_changed_model_visible_inputs(timeline,change):
    sender = Sender()
    provider = engine(sender)
    first = provider.analyze_timeline(timeline)
    if change=='evidence': timeline.alerts[0].original_record['CommandLine']='different.exe'
    elif change=='model': provider.model='offline-other'
    else: timeline.start_time=datetime(2026,1,1,tzinfo=timezone.utc)
    assert provider.analyze_timeline(timeline).verdict_id!=first.verdict_id
    assert len(sender.calls)==2


def test_credentials_and_transport_timeout_do_not_change_cache_policy(timeline):
    sender = Sender()
    provider = engine(sender)
    first = provider.analyze_timeline(timeline)
    provider.api_key='other-offline-placeholder'
    provider.timeout=90
    assert provider.analyze_timeline(timeline).verdict_id==first.verdict_id
    assert len(sender.calls)==1


def test_memory_cache_rejects_unsupported_provenance_version(timeline):
    from dataclasses import replace
    sender = Sender()
    provider = engine(sender)
    first = provider.acquire_timeline(timeline,on_acquisition=lambda origin:None)
    key = first.cache_contract.key
    encoded, timestamp, stamp = provider.cache._cache[key]
    provider.cache._cache[key]=(encoded,timestamp,replace(stamp,version=999))
    second = provider.acquire_timeline(timeline,on_acquisition=lambda origin:None)
    assert second.origin=='fresh' and second.cache_validation=='rejected'
    assert len(sender.calls)==2


@pytest.mark.parametrize('change',['unchanged','labels','evidence','model','prompt','expired','version','fingerprints','missing','malformed','tampered_body','future_generated','naive_expiry'])
def test_sqlite_validation_preserves_history_and_refreshes_invalid_candidates(monkeypatch,tmp_path,timeline,change):
    from scripts import run_evaluation
    path = str(tmp_path / 'cache.db')
    monkeypatch.setenv('DATABASE_PATH',path)
    monkeypatch.setattr(run_evaluation,'get_groq_api_key',lambda:'offline-placeholder')
    sender = Sender()
    selected = {'model':'offline-primary'}
    monkeypatch.setattr(run_evaluation,'GroqTriageEngine',lambda **kwargs:engine(sender,model=selected['model']))
    assert run_evaluation.run_evaluation_pipeline(timelines=[timeline])['total']==1
    db = DatabaseManager(path)
    try:
        old = db.get_verdict_for_timeline(timeline.timeline_id)
        assert old['cache_provenance_version']==1
        assert old['evidence_hash'] and old['inference_policy_hash'] and old['cache_expires_at']
        original_expiry = old['cache_expires_at']
        old_id = old['id']
        if change=='evidence': timeline.alerts[0].original_record['CommandLine']='different.exe'
        if change=='labels': timeline.alerts[0].original_record['is_malicious']=False
        if change=='model': selected['model']='offline-other'
        if change=='prompt': monkeypatch.setattr(llm,'DFIR_SYSTEM_PROMPT',llm.DFIR_SYSTEM_PROMPT+'\nNew policy.')
        if change=='expired': db.connection.execute("UPDATE verdicts SET cache_expires_at='2000-01-01T00:00:00+00:00'")
        if change=='version': db.connection.execute('UPDATE verdicts SET cache_provenance_version=999')
        if change=='fingerprints': db.connection.execute("UPDATE verdicts SET evidence_hash='wrong',inference_policy_hash='wrong'")
        if change=='missing': db.connection.execute('UPDATE verdicts SET evidence_hash=NULL,inference_policy_hash=NULL,cache_provenance_version=NULL,cache_expires_at=NULL')
        if change=='malformed': db.connection.execute("UPDATE verdicts SET reasoning='not-json'")
        if change=='tampered_body': db.connection.execute("UPDATE verdicts SET confidence_score=0.1")
        if change=='future_generated': db.connection.execute("UPDATE verdicts SET cache_generated_at='2099-01-01T00:00:00+00:00'")
        if change=='naive_expiry': db.connection.execute("UPDATE verdicts SET cache_expires_at='2099-01-01T00:00:00'")
        db.connection.commit()
        before = len(sender.calls)
        assert run_evaluation.run_evaluation_pipeline(timelines=[timeline])['total']==1
        replay = change in ('unchanged','labels')
        assert len(sender.calls)-before == (0 if replay else 1)
        observations = list(db.connection.execute('SELECT * FROM triage_observations ORDER BY rowid'))
        assert observations[-1]['origin']==('cache' if replay else 'fresh')
        assert observations[-1]['cache_validation']==('verified' if replay else 'rejected')
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]==2
        assert db.connection.execute('SELECT COUNT(*) FROM verdicts').fetchone()[0]==(1 if replay else 2)
        preserved = db.connection.execute('SELECT * FROM verdicts WHERE id=?',(old_id,)).fetchone()
        assert preserved is not None
        if replay:
            assert preserved['cache_expires_at']==original_expiry
        if change=='missing':
            assert preserved['cache_provenance_version'] is None
        assert db.connection.execute('PRAGMA foreign_keys').fetchone()[0]==1
    finally:
        db.close()


@pytest.mark.parametrize('value',[float('nan'),float('inf')])
def test_invalid_cache_clock_withholds_request(timeline,value):
    sender = Sender()
    provider = engine(sender,utc_clock=lambda:value)
    assert provider.analyze_timeline(timeline) is None
    assert sender.calls==[]


def test_persistent_expiry_honors_custom_ttl_and_does_not_refresh(monkeypatch,tmp_path,timeline):
    from scripts import run_evaluation
    path = str(tmp_path / 'deadline.db')
    ticks = [datetime(2026,1,1,tzinfo=timezone.utc).timestamp()]
    sender = Sender()
    monkeypatch.setenv('DATABASE_PATH',path)
    monkeypatch.setattr(run_evaluation,'get_groq_api_key',lambda:'offline-placeholder')
    monkeypatch.setattr(run_evaluation,'GroqTriageEngine',lambda **kwargs:engine(
        sender,utc_clock=lambda:ticks[0],cache=llm.LLMResponseCache(ttl_seconds=60,clock=lambda:ticks[0])))
    run_evaluation.run_evaluation_pipeline(timelines=[timeline])
    db = DatabaseManager(path)
    try:
        original = db.get_verdict_for_timeline(timeline.timeline_id)
        assert datetime.fromisoformat(original['cache_expires_at']).timestamp()==ticks[0]+60
        ticks[0]+=30
        run_evaluation.run_evaluation_pipeline(timelines=[timeline])
        assert db.get_verdict_for_timeline(timeline.timeline_id)['cache_expires_at']==original['cache_expires_at']
        assert len(sender.calls)==1
        ticks[0]+=30
        run_evaluation.run_evaluation_pipeline(timelines=[timeline])
        assert len(sender.calls)==2
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]==3
    finally:
        db.close()


def test_comparison_script_uses_shared_validation_without_adding_evaluation_rows(monkeypatch,tmp_path,timeline):
    from scripts import compare_models
    path = str(tmp_path / 'comparison.db')
    sender = Sender()
    monkeypatch.setattr(compare_models,'GroqTriageEngine',lambda **kwargs:engine(sender,model=kwargs['model']))
    # The final request must find an older matching candidate, not just the latest.
    for command in ('fixture.exe','fixture.exe','changed.exe','fixture.exe'):
        timeline.alerts[0].original_record['CommandLine']=command
        compare_models.evaluate_model('offline-primary',[timeline],'offline-placeholder',cache_db_path=path,pacing_seconds=0)
    assert len(sender.calls)==2
    db = DatabaseManager(path)
    try:
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]==0
        assert db.connection.execute('SELECT COUNT(*) FROM verdicts').fetchone()[0]==2
    finally:
        db.close()


def test_disallowed_fallback_cache_cannot_mask_a_fresh_primary_failure(monkeypatch,tmp_path,timeline):
    from scripts import run_evaluation
    path = str(tmp_path / 'primary.db')
    sender = Sender(fail_primary=True)
    policy = {'fallbacks':['offline-fallback']}
    monkeypatch.setenv('DATABASE_PATH',path)
    monkeypatch.setattr(run_evaluation,'get_groq_api_key',lambda:'offline-placeholder')
    monkeypatch.setattr(run_evaluation,'GroqTriageEngine',lambda **kwargs:engine(sender,fallback_models=policy['fallbacks']))
    assert run_evaluation.run_evaluation_pipeline(timelines=[timeline])['total']==1
    policy['fallbacks']=[]
    before = len(sender.calls)
    result = run_evaluation.run_evaluation_pipeline(timelines=[timeline])
    assert result['total']==0 and result['unavailable']==1
    assert len(sender.calls)-before==1
    db = DatabaseManager(path)
    try:
        assert db.connection.execute('SELECT COUNT(*) FROM verdicts').fetchone()[0]==1
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]==2
        row = db.connection.execute('SELECT origin,cache_validation FROM triage_observations ORDER BY rowid DESC LIMIT 1').fetchone()
        assert tuple(row)==('fresh','rejected')
    finally:
        db.close()


def test_historical_api_still_displays_unverified_legacy_verdict(tmp_path,timeline):
    from fastapi.testclient import TestClient
    from src.api.main import create_app
    from src.models.triage import TriageVerdict
    db = DatabaseManager(str(tmp_path / 'history.db'))
    try:
        db.init_db()
        db.insert_timeline(timeline)
        verdict = TriageVerdict(timeline_id=timeline.timeline_id,severity='HIGH',confidence_score=0.9,
            summary='Historical evidence',reasoning=[],recommended_actions=[],raw_llm_response='{}')
        db.insert_verdict(verdict)
        with TestClient(create_app(db=db)) as client:
            response = client.get('/api/timelines/'+str(timeline.timeline_id))
        assert response.status_code==200
        assert response.json()['verdict']['id']==str(verdict.verdict_id)
        assert response.json()['verdict']['cache_provenance_version'] is None
    finally:
        db.close()


def test_cache_stamp_failure_rolls_back_verdict_and_outcome(tmp_path,timeline):
    import sqlite3
    from src.engine.provenance import RunRecorder
    from src.engine.evaluation import AccuracyTracker
    db = DatabaseManager(str(tmp_path / 'stamp-failure.db'))
    try:
        db.init_db()
        db.insert_timeline(timeline)
        run = RunRecorder(db,'evaluation')
        observation = run.observe(timeline,1)
        acquisition = run.acquire(engine(Sender()),timeline,observation)
        db.connection.execute("CREATE TRIGGER fail_stamp BEFORE UPDATE OF cache_expires_at ON verdicts BEGIN SELECT RAISE(ABORT,'offline cache stamp failure'); END")
        db.connection.commit()
        tracker = AccuracyTracker()
        with pytest.raises(sqlite3.IntegrityError,match='offline cache stamp failure'):
            run.complete(observation,tracker.evaluate(acquisition.verdict,timeline),timeline,tracker,verdict=acquisition.verdict)
        assert db.connection.execute('SELECT COUNT(*) FROM verdicts').fetchone()[0]==0
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]==0
        assert db.get_triage_observations(run.run_id)[0]['status']=='pending'
    finally:
        db.close()
