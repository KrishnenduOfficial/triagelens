"""Offline integration checks using harmless file bytes and mocked enrichment."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
import httpx

from conftest import PipelineTestEngine
from src.api.main import create_app
from src.engine import yara, yara_files
from src.engine.database import DatabaseManager
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline


@pytest.fixture
def db(tmp_path):
    db = DatabaseManager(str(tmp_path / 'test.sqlite'))
    db.init_db()
    yield db
    db.close()


def sample_result(data=b'harmless'):
    stamp = datetime.now(timezone.utc).isoformat()
    match = yara.Match(namespace='fixture', rule='demo', source_digest='a'*64,
                       metadata={'id':'demo', 'author':'fixture', 'source':'https://example.org',
                                 'revision':'1', 'license':'MIT'}, occurrences=[], technique_ids=['T1082'])
    return yara.ScanResult(str(uuid4()), 'match', hashlib.sha256(data).hexdigest(), len(data),
                           stamp, stamp, 'yara-x', '1.22.1', 'b'*64, yara.Limits(), (), (match,))


def alert(indicator):
    return NormalizedAlert(source_dataset='fixture', source_file='local', event_type='test',
                           original_record={}, extracted_indicators=[indicator], ground_truth_label='benign')


def test_atomic_exact_hash_linking_and_retry(db):
    result = sample_result()
    matching, uppercase, wrong = alert(result.sha256), alert(result.sha256.upper()), alert('c'*64)
    for item in (matching, uppercase, wrong):
        db.insert_alert(item)
    db.save_yara_scan(result)
    db.save_yara_scan(result)
    saved = db.get_yara_scan(result.scan_id)
    assert len(saved['detection_ids']) == 1
    detection = db.connection.execute('SELECT source, rule_id FROM detections').fetchone()
    assert detection['source'] == 'yara' and result.pack_digest in detection['rule_id']
    links = db.connection.execute('SELECT alert_id FROM detection_events').fetchall()
    assert [r[0] for r in links] == [str(matching.internal_id)]
    assert db.get_alert(matching.internal_id)['ground_truth_label'] == 'benign'
    with pytest.raises(ValueError):
        db.save_yara_scan(replace(result, status='no_match'))
    assert db.connection.execute('SELECT count(*) FROM detections').fetchone()[0] == 1


def test_unmatched_and_incomplete_scans_never_create_hits(db):
    match = sample_result()
    db.save_yara_scan(match)
    db.save_yara_scan(replace(match, scan_id=str(uuid4()), status='truncated'))
    assert db.connection.execute('SELECT count(*) FROM detections').fetchone()[0] == 0
    assert db.get_yara_scan(match.scan_id)['sha256'] == match.sha256


def test_scan_and_detection_roll_back_together(db, monkeypatch):
    result = sample_result()
    db.insert_alert(alert(result.sha256))
    def fail(*args, **kwargs):
        raise RuntimeError('failed persistence')
    monkeypatch.setattr(db, 'insert_detection', fail)
    with pytest.raises(RuntimeError):
        db.save_yara_scan(result)
    assert db.get_yara_scan(result.scan_id) is None
    assert db.connection.execute('SELECT count(*) FROM detections').fetchone()[0] == 0


def test_yara_hit_does_not_change_prompt_or_labels(db):
    result = sample_result()
    item = alert(result.sha256)
    timeline = ThreatTimeline(grouping_key='fixture', alerts=[item], total_events=1)
    db.insert_timeline(timeline)
    requests = []
    def send(url, **kwargs):
        requests.append(kwargs['json'])
        return httpx.Response(200, json={'outputs': [{'message': {'segments': [{'text': json.dumps({
            'severity': 'LOW', 'confidence_score': 0.6, 'summary': 'fixture',
            'reasoning': [], 'recommended_actions': []})}]}}]})
    engine = PipelineTestEngine(api_key='offline-placeholder', model='offline-model',
                                fallback_models=[], enable_cache=False, request_sender=send)
    engine.analyze_timeline(timeline)
    db.save_yara_scan(result)
    engine.analyze_timeline(timeline)
    assert requests[0] == requests[1]
    assert result.pack_digest not in str(requests[1])
    assert db.get_alert(item.internal_id)['ground_truth_label'] == 'benign'


@pytest.mark.parametrize('path', ['../file', 'C:thing', 'C:\\file', '\\\\server\\share',
                                  'dir/../file', 'file:stream', 'NUL.txt', 'dir//file'])
def test_bad_relative_paths_are_rejected(path):
    with pytest.raises(yara_files.FileRejected):
        yara_files.relative_parts(path)


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows handle admission')
def test_handle_snapshot_and_hardlink_rejection(tmp_path):
    root = tmp_path / 'samples'
    root.mkdir()
    target = root / 'safe.txt'
    target.write_bytes(b'harmless')
    assert yara_files.read_snapshot(str(root), ('safe.txt',), 100) == b'harmless'
    with pytest.raises(yara_files.FileRejected, match='size_limit'):
        yara_files.read_snapshot(str(root), ('safe.txt',), 2)
    os.link(target, root / 'second.txt')
    with pytest.raises(yara_files.FileRejected, match='hardlink'):
        yara_files.read_snapshot(str(root), ('safe.txt',), 100)


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows handle admission')
def test_scan_api_retry_and_separate_hash_lookup(tmp_path, db, monkeypatch):
    root = tmp_path / 'samples'
    root.mkdir()
    (root / 'safe.txt').write_bytes(b'harmless')
    expected = sample_result()
    monkeypatch.setattr('src.config.get_yara_scan_roots', lambda: {'safe': str(root)})
    monkeypatch.setattr(yara, 'scan_snapshot', lambda data, sources, **kw: expected)
    client = TestClient(create_app(db))
    calls = []
    def lookup(digest, kind):
        calls.append((digest, kind))
        return EnrichmentResult(indicator=digest, indicator_type=kind, provider='fixture',
                                is_malicious=False, raw_response={}, lookup_status='not_found')
    monkeypatch.setattr(client.app.state.yara_enrichment, 'lookup', lookup)
    request = {'job_id': str(uuid4()), 'root_id': 'safe', 'relative_path': ''}
    first = client.post('/api/yara/scans', json=request)
    assert first.status_code == 200 and first.json()['status'] == 'completed'
    assert first.json()['scan_ids'] == [expected.scan_id] and calls == []
    assert client.post('/api/yara/scans', json=request).json() == first.json()
    assert client.get('/api/yara/scans/' + expected.scan_id).status_code == 200
    response = client.post('/api/yara/scans/' + expected.scan_id + '/enrichment')
    assert response.json()['status'] == 'not_found'
    assert calls == [(expected.sha256, 'hash')]
    assert client.post('/api/yara/scans', json={**request, 'relative_path':'other'}).status_code == 409
    assert client.post('/api/yara/scans', json={**request, 'job_id':str(uuid4()), 'relative_path':'..'}).status_code == 400


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows handle admission')
def test_real_scanner_links_harmless_snapshot(tmp_path, db, monkeypatch):
    root = tmp_path / 'samples'
    root.mkdir()
    data = b'powershell -encodedcommand example'
    (root / 'sample.txt').write_bytes(data)
    item = alert(hashlib.sha256(data).hexdigest())
    db.insert_alert(item)
    monkeypatch.setattr('src.config.get_yara_scan_roots', lambda: {'safe': str(root)})
    client = TestClient(create_app(db))
    response = client.post('/api/yara/scans', json={'job_id': str(uuid4()), 'root_id': 'safe'})
    assert response.status_code == 200
    job = response.json()
    assert len(job['scan_ids']) == 1
    result = client.get('/api/yara/scans/' + job['scan_ids'][0]).json()
    if yara._engine_version() is None:
        assert result['status'] == 'missing_engine' and job['status'] == 'incomplete'
    else:
        assert result['status'] == 'match' and job['status'] == 'completed'
        assert result['detection_ids']
        assert db.connection.execute('SELECT alert_id FROM detection_events').fetchone()[0] == str(item.internal_id)


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows handle admission')
def test_missing_rule_pack_records_incomplete_job(tmp_path, db, monkeypatch):
    root = tmp_path / 'samples'
    root.mkdir()
    monkeypatch.setattr('src.config.get_yara_scan_roots', lambda: {'safe': str(root)})
    monkeypatch.setattr('src.engine.yara_service._RULES', tmp_path / 'missing')
    client = TestClient(create_app(db))
    job_id = str(uuid4())
    response = client.post('/api/yara/scans', json={'job_id': job_id, 'root_id': 'safe'})
    assert response.json()['status'] == 'incomplete'
    assert response.json()['errors'] == ['rule_pack_unavailable']
    assert client.get('/api/yara/jobs/' + job_id).json() == response.json()
