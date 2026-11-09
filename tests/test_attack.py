"""Offline ATT&CK catalog, isolation, persistence and metric contracts."""
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.engine.attack import (coverage_matrix, evaluate_techniques, evaluate_timeline,
                               navigator_layer, rule_techniques, summarize_comparisons, validate_techniques)
from src.engine.database import DatabaseManager
from src.engine.groq import GroqTriageEngine
from src.engine.llm import TriageEngineBase
from src.models.alert import GroundTruthMetadata, NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def verdict(timeline_id, predictions=None):
    return TriageVerdict(timeline_id=timeline_id, severity='LOW', confidence_score=.5,
                         summary='synthetic', reasoning=['test'], recommended_actions=['review'],
                         raw_llm_response='{}', predicted_techniques=predictions)


def test_catalog_and_rule_mapping():
    assert validate_techniques(['t1059.001', 'T1059.001', 'T9999']) == (['T1059.001'], ['T9999'])
    assert rule_techniques('sigma', ['attack.t1059.001', 'attack.execution', 'attack.t9999']) == (['T1059.001'], ['T9999'])
    assert rule_techniques('yara', ['T1059', 'T9999']) == (['T1059'], ['T9999'])
    with pytest.raises(ValueError):
        validate_techniques('T1059')


def test_exact_parent_and_tactic_are_distinct():
    result = evaluate_techniques(['T1059.001'], ['T1059'])
    assert result['exact']['matched'] == 0
    assert result['parent']['matched'] == 1
    assert result['tactic']['matched'] > 0
    assert evaluate_techniques(None, [])['status'] == 'unavailable'
    assert evaluate_techniques([], [])['exact']['recall'] is None
    with pytest.raises(ValueError):
        evaluate_techniques(['T9999'], [])


def test_aggregate_reports_missing_separately():
    summary = summarize_comparisons([evaluate_techniques(['T1059.001'], ['T1059']),
                                     evaluate_techniques(None, [])])
    assert (summary['total_timelines'], summary['scored_timelines'], summary['unavailable_timelines']) == (2, 1, 1)
    assert summary['exact']['precision'] == 0 and summary['parent']['recall'] == 1


def test_timeline_unreviewed_and_unknown_truth_are_not_negative():
    alert = NormalizedAlert(source_dataset='sample', source_file='local', event_type='process', original_record={},
                            ground_truth_metadata=GroundTruthMetadata(relative_path='local', status='mapped',
                                                                      technique_ids=['T1059.001']))
    timeline = ThreatTimeline(grouping_key='fixture', alerts=[alert])
    assert evaluate_timeline(timeline, verdict(timeline.timeline_id, ['T1059']))['parent']['matched'] == 1
    timeline.alerts.append(NormalizedAlert(source_dataset='sample', source_file='local', event_type='process', original_record={}))
    assert evaluate_timeline(timeline, verdict(timeline.timeline_id, []))['status'] == 'unavailable'
    timeline.alerts[0].ground_truth_metadata.technique_ids = ['T9999']
    assert evaluate_timeline(timeline, verdict(timeline.timeline_id, []))['unknown_ground_truth_ids'] == ['T9999']


def test_matrix_and_navigator_keep_source_labels():
    rows = coverage_matrix({'dataset': ['T1059.001'], 'ai': [], 'rules': None})
    row = next(r for r in rows if r['technique_id'] == 'T1059.001')
    assert row['sources'] == {'dataset': True, 'ai': False, 'rules': None}
    layer = navigator_layer('rule mappings', ['T1059.001'])
    assert layer['domain'] == 'enterprise-attack'
    assert layer['versions']['attack'] == '17.1'
    assert layer['techniques'] == [{'techniqueID': 'T1059.001', 'score': 1}]


def test_predictions_and_detections_roundtrip_separately(tmp_path):
    db = DatabaseManager(str(tmp_path / 'attack.sqlite'))
    db.init_db()
    alert = NormalizedAlert(source_dataset='sample', source_file='local', event_type='process', original_record={})
    timeline = ThreatTimeline(grouping_key='fixture', alerts=[alert])
    db.insert_timeline(timeline)
    item = verdict(timeline.timeline_id, ['t1059.001'])
    db.insert_verdict(item)
    db.insert_detection('rule', 'sigma', [alert.internal_id], datetime.now(timezone.utc), ['T1059'])
    assert db.get_verdict(item.verdict_id)['predicted_techniques'] == ['T1059.001']
    assert db.get_detections_for_timeline(timeline.timeline_id)[0]['technique_ids'] == ['T1059']
    legacy = verdict(timeline.timeline_id)
    db.insert_verdict(legacy)
    assert db.get_verdict(legacy.verdict_id)['predicted_techniques'] is None
    with pytest.raises(ValidationError):
        verdict(timeline.timeline_id, ['T9999'])
    db.close()


def test_groq_schema_requests_explicit_prediction_field():
    schema = GroqTriageEngine(api_key='offline')._generation_settings('openai/gpt-oss-120b')['response_format']['json_schema']['schema']
    assert 'predicted_techniques' in schema['required']
    assert 'default' not in schema['properties']['predicted_techniques']


def test_technique_metadata_never_enters_nested_evidence():
    payload = {'predicted_techniques': ['T1059.001'],
               'rule_mapped_techniques': ['T1059'], 'technique_ids': ['T1059.001'],
               'detections': [{'rule': 'private-rule'}], 'analyst_disposition': 'private-review',
               'image': 'safe.exe'}
    assert TriageEngineBase._sanitize_telemetry_value(payload) == {'image': 'safe.exe'}
