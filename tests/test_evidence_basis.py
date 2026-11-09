"""ADR-057: real engine/SQLite/API paths with only injected offline completions."""

from copy import deepcopy
import hashlib
import json

import httpx
import pytest
from pydantic import ValidationError

from src.engine.database import DatabaseManager
from src.engine.evaluation import AccuracyTracker
from src.engine.groq import GroqTriageEngine
from src.engine.provenance import acquire_triage, evaluation_run, RunRecorder
from src.engine.verdict_cache import CacheProvenance, validated_candidate
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.evidence import EvidenceReference, resolve_reference
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def sample():
    return ThreatTimeline(grouping_key="private-source-name", alerts=[NormalizedAlert(
        source_dataset="offline", source_file="private-label.json", event_type="NetworkConnect",
        ground_truth_label="malicious", original_record={"Protocol":"tcp", "DestinationPort":443,
            "CommandLine":"contact analyst@example.com", "is_malicious":True, "severity":"LOW",
            "Details":{"values":[0,False,None,"",{"name":"supplied"}]}})], total_events=1)


def assessment(disposition="MALICIOUS"):
    ref = {"evidence_id":"E1", "field_path":["details","Protocol"]}
    gaps = [{"category":"process_context", "description":"Intent is not established",
             "required_evidence":"Command line and process context", "blocks_disposition":True}] if disposition == "UNDETERMINED" else []
    return {"disposition":disposition, "severity":"LOW", "confidence_score":.8, "predicted_techniques": [],
        "summary":"Observed transport; model assessment remains advisory", "uncertainty_level":"HIGH",
        "reasoning":["Recorded transport is TCP; successful TLS is unverified."],
        "recommended_actions":["Authorized analyst should preserve and review process/network records."],
        "missing_information":[g['description'] for g in gaps], "evidence_basis":{
            "kind":{"MALICIOUS":"malicious_support", "BENIGN":"benign_support", "UNDETERMINED":"insufficient_evidence"}[disposition],
            "decision_refs":[ref], "observations":[{"statement":"Transport recorded as TCP", "refs":[ref]}],
            "hypotheses":[{"statement":"TLS is a hypothesis requiring handshake evidence", "refs":[]}], "gaps":gaps}}


def provider(data=None, calls=None, **kwargs):
    def send(url, **options):
        if calls is not None:
            calls.append(deepcopy(options['json']))
        return httpx.Response(200, json={"model":options['json']['model'], "choices":[{
            "finish_reason":"stop", "message":{"role":"assistant", "content":json.dumps(data or assessment())}}]})
    return GroqTriageEngine(api_key="offline-evidence-fixture", fallback_models=[], request_sender=send, **kwargs)


@pytest.mark.parametrize('kind', ['malicious_support','benign_support','insufficient_evidence'])
@pytest.mark.parametrize('disposition', ['MALICIOUS','BENIGN','UNDETERMINED'])
def test_basis_disposition_matrix(kind, disposition):
    data = assessment(disposition)
    data['evidence_basis']['kind'] = kind
    calls = []
    verdict = provider(data, calls).analyze_timeline(sample())
    expected = dict(malicious_support='MALICIOUS',benign_support='BENIGN',insufficient_evidence='UNDETERMINED')[kind]
    assert (verdict is not None) is (expected == disposition)
    assert len(calls) == 1


@pytest.mark.parametrize('mutation', [
    'missing_basis','missing_array','extra_basis','extra_observation','extra_reference','extra_gap',
    'blocking_binary','no_blocking_abstention','low_abstention','no_observations','no_decision_refs',
    'duplicate_decision','duplicate_observation','duplicate_hypothesis','unobserved_decision',
    'wrong_gaps','blank_required','string_boolean','string_path','blank_path','forged_context',
    'forged_version', 'forged_policy', 'missing_disposition',
])
def test_structural_failures_are_unavailable_without_repair_or_retry(mutation):
    data = assessment('UNDETERMINED' if mutation in ('no_blocking_abstention','low_abstention','extra_gap','blank_required','string_boolean') else 'MALICIOUS')
    basis = data['evidence_basis']
    ref = basis['decision_refs'][0]
    if mutation == 'missing_basis': del data['evidence_basis']
    elif mutation == 'missing_array': del basis['hypotheses']
    elif mutation == 'extra_basis': basis['approved'] = True
    elif mutation == 'extra_observation': basis['observations'][0]['verified'] = True
    elif mutation == 'extra_reference': ref['value'] = 'invented'
    elif mutation == 'extra_gap': basis['gaps'][0]['source'] = 'invented'
    elif mutation == 'blocking_binary':
        basis['gaps'] = assessment('UNDETERMINED')['evidence_basis']['gaps']
        data['missing_information'] = [g['description'] for g in basis['gaps']]
    elif mutation == 'no_blocking_abstention': basis['gaps'][0]['blocks_disposition'] = False
    elif mutation == 'low_abstention': data['uncertainty_level'] = 'LOW'
    elif mutation == 'no_observations': basis['observations'] = []
    elif mutation == 'no_decision_refs': basis['decision_refs'] = []
    elif mutation == 'duplicate_decision': basis['decision_refs'].append(deepcopy(ref))
    elif mutation == 'duplicate_observation': basis['observations'][0]['refs'].append(deepcopy(ref))
    elif mutation == 'duplicate_hypothesis': basis['hypotheses'][0]['refs'] = [ref,deepcopy(ref)]
    elif mutation == 'unobserved_decision': basis['decision_refs'] = [{"evidence_id":"E1","field_path":["event_type"]}]
    elif mutation == 'wrong_gaps': data['missing_information'] = ['A different gap']
    elif mutation == 'blank_required': basis['gaps'][0]['required_evidence'] = '  '
    elif mutation == 'string_boolean': basis['gaps'][0]['blocks_disposition'] = 'true'
    elif mutation == 'string_path': ref['field_path'] = 'details.Protocol'
    elif mutation == 'blank_path': ref['field_path'] = [' ']
    elif mutation == 'forged_context': data['evidence_context'] = {}
    elif mutation == 'forged_version': data['evidence_contract_version'] = 'evidence-basis-v1'
    elif mutation == 'forged_policy': data['policy_version'] = 'triage-v2'
    else: del data['disposition']
    calls = []
    verdict = provider(data,calls).analyze_timeline(sample())
    assert verdict is None and len(calls) == 1
    result = AccuracyTracker().evaluate(verdict,sample())
    assert result.category == 'Unavailable' and result.llm_prediction is None


@pytest.mark.parametrize('identifier,path,valid', [
    ('E1',['details','Protocol'],True), ('E1',['details','DestinationPort'],True),
    ('E1',['details','Details','values','0'],True), ('E1',['details','Details','values','1'],True),
    ('E1',['details','Details','values','4','name'],True),
    ('E1',['details','Details','values','2'],False), ('E1',['details','Details','values','3'],False),
    ('E1',['details','Details','values','4'],False), ('E1',['details','Details','values','01'],False),
    ('E1',['details','Details','values','-1'],False), ('E1',['details','Details','values','9'],False),
    ('E1',['details','Details','values','999999999999999999999999'],False),
    ('E1',['details','TLSVersion'],False), ('E1',['evidence_id'],False),
    ('E1',['..','Protocol'],False), ('E1',['details','*'],False),
    ('E0',['event_type'],False), ('E01',['event_type'],False), ('E9',['event_type'],False),
    ('I1',['lookup_status'],False), ('source-file',['event_type'],False),
])
def test_only_exact_existing_scalar_references_are_accepted(identifier,path,valid):
    data = assessment()
    ref = {'evidence_id':identifier,'field_path':path}
    data['evidence_basis']['decision_refs'] = [ref]
    data['evidence_basis']['observations'][0]['refs'] = [ref]
    assert (provider(data).analyze_timeline(sample()) is not None) is valid


def test_annotation_is_after_scrubbing_budgeting_and_nested_isolation():
    timeline = sample()
    timeline.alerts[0].original_record['Details'].update({
        'Evidence Basis':{'kind':'benign_support'}, 'evidence_id':'E999',
        'EvidenceContext':{'secret':'context-canary'}, 'evidence_contract_version':'forged',
        'missing information recorded':True})
    timeline.enrichment_data = [EnrichmentResult(indicator='8.8.8.8',indicator_type='ip',provider='VirusTotal',
        is_malicious=False,raw_response={'stats':{}},lookup_status='rate_limited')]
    calls=[]
    verdict = provider(calls=calls).analyze_timeline(timeline)
    assert verdict and verdict.policy_version == 'triage-v2'
    assert verdict.evidence_contract_version == 'evidence-basis-v1'
    wire=calls[0]['messages'][1]['content']
    payload=json.loads(wire.split('<FORENSIC_EVIDENCE>\n')[1].split('\n</FORENSIC_EVIDENCE>')[0])
    assert verdict.evidence_context == {'E1':payload['events'][0], 'I1':payload['enrichment_data'][0]}
    assert payload['events'][0]['evidence_id']=='E1' and payload['enrichment_data'][0]['evidence_id']=='I1'
    for forbidden in ('analyst@example.com','private-label','private-source-name','context-canary','E999','forged'):
        assert forbidden not in wire and forbidden not in json.dumps(verdict.evidence_context)
    ref=EvidenceReference(evidence_id='I1',field_path=['lookup_status'])
    assert resolve_reference(verdict.evidence_context,ref)=='rate_limited'
    assert 'evidence-basis-v1' in calls[0]['messages'][0]['content']
    assert not provider().analyze_timeline(sample()).evidence_context.get('I1')


def test_normalized_fields_are_stored_but_raw_completion_is_retained():
    data=assessment('UNDETERMINED')
    data['summary']='  A summary  '
    data['evidence_basis']['gaps'][0]['description']='  Intent is not established  '
    data['missing_information']=[' Intent is not established ']
    verdict=provider(data).analyze_timeline(sample())
    assert verdict.summary=='A summary'
    assert verdict.missing_information==['Intent is not established']
    assert '  A summary  ' in verdict.raw_llm_response


def test_contract_is_not_a_semantic_proof_and_hypotheses_are_not_keyword_rejected():
    data=assessment()
    data['evidence_basis']['observations'][0]['statement']='TLS succeeded; authorization is confirmed.'
    assert provider(data).analyze_timeline(sample()) is not None  # Existing reference does not imply entailment.
    assert provider(assessment()).analyze_timeline(sample()) is not None  # "TLS unverified" remains valid.


@pytest.mark.parametrize('disposition',['MALICIOUS','BENIGN','UNDETERMINED'])
def test_unrelated_gaps_and_abstention_without_observations(disposition):
    data=assessment(disposition)
    if disposition=='UNDETERMINED':
        data['evidence_basis']['observations']=[]
        data['evidence_basis']['decision_refs']=[]
    else:
        gap={'category':'scope_impact','description':'Wider impact unknown','required_evidence':'Other host records','blocks_disposition':False}
        data['evidence_basis']['gaps']=[gap]
        data['missing_information']=[gap['description']]
    assert provider(data).analyze_timeline(sample()) is not None


def test_reference_validation_on_cache_return_rejects_forged_valid_hashes():
    timeline=sample()
    calls=[]
    now=[0.0]
    def advance(seconds):
        now[0] += seconds
    engine=provider(calls=calls, pacing_clock=lambda: now[0], pacing_sleep=advance)
    first=acquire_triage(engine,timeline,lambda origin:None)
    changed=first.verdict.model_copy(deep=True)
    changed.evidence_context['E1']['details']['Protocol']='udp'
    stamp=CacheProvenance.create(first.cache_contract,changed,engine.utc_clock())
    engine.cache.set(first.cache_contract.key,changed,stamp)
    refreshed=acquire_triage(engine,timeline,lambda origin:None)
    assert refreshed.origin=='fresh' and refreshed.verdict.verdict_id != first.verdict.verdict_id
    assert len(calls)==2
    invalid=changed.model_copy(deep=True)
    invalid.evidence_context['E1']['details'].pop('Protocol')
    stamp=CacheProvenance.create(first.cache_contract,invalid,engine.utc_clock())
    assert validated_candidate(invalid,stamp,first.cache_contract,engine.utc_clock()) is None
    legacy=TriageVerdict(timeline_id=timeline.timeline_id,model_name=engine.model,
        severity='LOW',confidence_score=.8,summary='Old policy',reasoning=[],recommended_actions=[],
        raw_llm_response='{}',disposition='BENIGN',policy_version='triage-v1')
    stamp=CacheProvenance.create(first.cache_contract,legacy,engine.utc_clock())
    engine.cache.set(first.cache_contract.key,legacy,stamp)
    assert acquire_triage(engine,timeline,lambda origin:None).origin=='fresh'
    assert len(calls)==3
    for name, value in [('summary',''),('recommended_actions',[])]:
        malformed=refreshed.verdict.model_copy(deep=True,update={name:value})
        stamp=CacheProvenance.create(first.cache_contract,malformed,engine.utc_clock())
        engine.cache.set(first.cache_contract.key,malformed,stamp)
        assert acquire_triage(engine,timeline,lambda origin:None).origin=='fresh'
    assert len(calls)==5


@pytest.mark.parametrize('mutation',['evidence_basis','evidence_context','evidence_contract_version','wrong_version'])
def test_v2_model_requires_complete_context_and_supported_contract(mutation):
    verdict=provider().analyze_timeline(sample()).model_dump(mode='json')
    verdict['evidence_contract_version' if mutation=='wrong_version' else mutation] = 'unknown' if mutation=='wrong_version' else None
    with pytest.raises(ValidationError): TriageVerdict.model_validate(verdict)


@pytest.mark.parametrize('disposition',['MALICIOUS','BENIGN','UNDETERMINED'])
def test_v2_roundtrip_replay_and_all_metric_scopes(tmp_path,disposition):
    from fastapi.testclient import TestClient
    from src.api.main import create_app
    path=str(tmp_path/'evidence.db')
    timeline=sample()
    calls=[]
    with evaluation_run(DatabaseManager(path),'evaluation') as run:
        run.db.insert_timeline(timeline)
        for ordinal in (1,2):
            observation=run.observe(timeline,ordinal)
            outcome=run.acquire(provider(assessment(disposition),calls),timeline,observation)
            tracker=AccuracyTracker()
            result=tracker.evaluate(outcome.verdict,timeline)
            identifier=run.complete(observation,result,timeline,tracker,verdict=outcome.verdict)
            assert run.complete(observation,result,timeline,tracker,verdict=outcome.verdict)==identifier
        run_id=run.run_id
    assert len(calls)==1  # A new engine verifies the persistent cache.
    db=DatabaseManager(path)
    try:
        cohort=db.declare_run_cohort(run_id)
        with TestClient(create_app(db=db)) as client:
            detail=client.get('/api/timelines/'+str(timeline.timeline_id)).json()['verdict']
            assert detail['missing_information_recorded'] is True
            assert detail['evidence_context']==outcome.verdict.evidence_context
            assert detail['evidence_basis']==outcome.verdict.evidence_basis.model_dump(mode='json')
            # A later change to stored source evidence cannot change the saved citation.
            db.connection.execute("UPDATE alerts SET original_record='{}'")
            db.connection.commit()
            assert client.get('/api/timelines/'+str(timeline.timeline_id)).json()['verdict']['evidence_context']==detail['evidence_context']
            for query,count in [({'scope':'history'},2),({'scope':'run','run_id':run_id},2),
                ({'scope':'attempts','run_id':run_id},1),({'scope':'quality','cohort_id':cohort},1)]:
                reply=client.get('/api/metrics',params=query)
                assert reply.status_code==200
                metrics=reply.json()
                assert metrics['explicit_disposition_count']==count
                assert metrics['abstained']==(count if disposition=='UNDETERMINED' else 0)
                assert metrics['total']==(0 if disposition=='UNDETERMINED' else count)
                assert metrics['severity_matches']==count
                assert metrics['labelled_available']==count
                assert metrics['labelled_binary']==(0 if disposition=='UNDETERMINED' else count)
                assert metrics['labelled_binary_coverage']==(0 if disposition=='UNDETERMINED' else 1)
                if disposition=='UNDETERMINED': assert metrics['brier_score'] is None
                assert metrics['availability_rate']==(None if query['scope']=='quality' else 1)
    finally:
        db.close()


def test_labelled_coverage_separates_abstention_unknown_truth_and_unavailability():
    timeline=sample()
    tracker=AccuracyTracker()
    tracker.evaluate(provider().analyze_timeline(timeline),timeline)
    tracker.evaluate(provider(assessment('UNDETERMINED')).analyze_timeline(timeline),timeline)
    unknown=sample()
    unknown.alerts[0].ground_truth_label=None
    unknown.alerts[0].original_record.pop('is_malicious')
    tracker.evaluate(provider(assessment('UNDETERMINED')).analyze_timeline(unknown),unknown)
    tracker.evaluate(None,timeline)
    metrics=tracker.get_metrics()
    assert metrics['labelled_binary']==1 and metrics['labelled_available']==2
    assert metrics['labelled_abstained']==1 and metrics['labelled_binary_coverage']==.5
    assert metrics['unknown_ground_truth']==1 and metrics['abstained']==2
    assert metrics['unavailable']==1 and metrics['total']==1


@pytest.mark.parametrize('raw,recorded,expected',[(None,False,[]),('[]',True,[]),
    ('["Authorization unknown"]',True,['Authorization unknown']),('broken',False,'broken'),
    ('null',False,'null'),('{}',False,'{}')])
def test_api_presence_flag_is_read_derived_and_not_part_of_model(tmp_path,raw,recorded,expected):
    db=DatabaseManager(str(tmp_path/'presence.db'))
    try:
        db.init_db()
        timeline=sample()
        db.insert_timeline(timeline)
        verdict=provider().analyze_timeline(timeline)
        db.insert_verdict(verdict)
        db.connection.execute('UPDATE verdicts SET missing_information=?',(raw,))
        db.connection.commit()
        detail=db.get_verdict_for_timeline(timeline.timeline_id)
        assert detail['missing_information_recorded'] is recorded
        assert detail['missing_information']==expected
        assert 'missing_information_recorded' not in TriageVerdict.model_fields
        assert 'missing_information_recorded' not in {r['name'] for r in db.connection.execute('PRAGMA table_info(verdicts)')}
    finally:
        db.close()


def test_pre_v2_terminal_hash_and_additive_migration_are_preserved(tmp_path):
    path=str(tmp_path/'old.db')
    db=DatabaseManager(path)
    db.init_db()
    timeline=sample()
    db.insert_timeline(timeline)
    old=TriageVerdict(timeline_id=timeline.timeline_id,severity='LOW',confidence_score=.7,
        summary='Old version',reasoning=['Recorded'],recommended_actions=['Review'],raw_llm_response='{}',
        disposition='MALICIOUS',policy_version='triage-v1')
    run=RunRecorder(db,'evaluation')
    observation=run.observe(timeline,1)
    tracker=AccuracyTracker()
    result=tracker.evaluate(old,timeline)
    run.complete(observation,result,timeline,tracker,verdict=old)
    snapshot=db.get_all_evaluations()[0].model_dump(mode='json')
    historical=old.model_dump(mode='json')
    for name in ('evidence_basis','evidence_context','evidence_contract_version'): historical.pop(name)
    for value in (snapshot,historical):
        for name in ('disposition','prediction_basis','policy_version'):
            if value.get(name) is None: value.pop(name,None)
    expected=hashlib.sha256(json.dumps({'outcome':snapshot,'verdict':historical,'cache':None,'failure':None},
        sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    assert db.get_triage_observations(run.run_id)[0]['outcome_hash']==expected
    for name in ('evidence_basis','evidence_context','evidence_contract_version'):
        db.connection.execute('ALTER TABLE verdicts DROP COLUMN '+name)
    db.connection.commit()
    db.close()
    db=DatabaseManager(path)
    try:
        db.init_db()
        db.init_db()
        restored=db.get_verdict(old.verdict_id)
        assert restored['evidence_basis'] is restored['evidence_context'] is restored['evidence_contract_version'] is None
        run.db=db
        run.complete(observation,result,timeline,tracker,verdict=old)
        assert db.connection.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]==1
        assert AccuracyTracker.from_database(db).get_metrics()['tp']==1
    finally:
        db.close()
