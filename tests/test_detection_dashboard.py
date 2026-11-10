"""Offline API contracts for the recorded detections dashboard."""
from datetime import datetime, timezone
from dataclasses import replace

from fastapi.testclient import TestClient

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.models.alert import NormalizedAlert
from test_yara_integration import sample_result


def test_recorded_results_and_coverage_are_separate(tmp_path):
    db = DatabaseManager(str(tmp_path / 'test.sqlite'))
    db.init_db()
    client = TestClient(create_app(db))
    assert client.get('/api/detections').json() == {'total': 0, 'items': []}
    assert client.get('/api/yara/scans').json() == {'total': 0, 'items': []}
    rules = client.get('/api/detections/rules').json()
    assert rules['rules'] and rules['issues']
    alert = NormalizedAlert(source_dataset='fixture', source_file='local', event_type='test', original_record={})
    db.insert_alert(alert)
    db.insert_detection('<rule>', 'sigma', [alert.internal_id], datetime.now(timezone.utc), ['T1082'])
    scan = sample_result()
    db.save_yara_scan(scan)  # No matching alert: scan exists without a detection.
    db.save_yara_scan(replace(scan, scan_id='other', status='timeout', matches=()))
    hits = client.get('/api/detections?limit=1').json()
    assert hits['total'] == 1 and hits['items'][0]['event_ids'] == [str(alert.internal_id)]
    scans = client.get('/api/yara/scans?limit=1').json()
    assert scans['total'] == 2 and scans['items'][0]['status'] == 'timeout'
    assert client.get('/api/yara/scans?skip=1&limit=1').json()['items'][0]['status'] == 'match'
    coverage = client.get('/api/detections/coverage').json()
    assert coverage['scope'] == 'persisted_rule_hits'
    row = next(item for item in coverage['rows'] if item['technique_id'] == 'T1082')
    assert row['sources'] == {'sigma': True, 'yara': False}
    db.insert_detection('yara-rule', 'yara', [alert.internal_id], datetime.now(timezone.utc), ['T1082'])
    row = next(item for item in client.get('/api/detections/coverage').json()['rows'] if item['technique_id'] == 'T1082')
    assert row['sources'] == {'sigma': True, 'yara': True}
    assert client.get('/api/detections?limit=101').status_code == 422
    assert client.get('/api/yara/scans?skip=-1').status_code == 422
    db.close()
