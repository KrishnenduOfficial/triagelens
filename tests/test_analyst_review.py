from uuid import uuid4

from fastapi.testclient import TestClient

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def test_review_persistence_validation_and_isolation(tmp_path):
    db = DatabaseManager(str(tmp_path / 'review.sqlite'))
    db.init_db()
    timeline = ThreatTimeline(grouping_key='fixture')
    db.insert_timeline(timeline)
    verdict = TriageVerdict(timeline_id=timeline.timeline_id, severity='HIGH', confidence_score=.5,
                            summary='review', reasoning=[], recommended_actions=[], raw_llm_response='{}')
    db.insert_verdict(verdict)
    client = TestClient(create_app(db))
    url = f'/api/timelines/{timeline.timeline_id}'
    before = client.get(url).json()
    payload = {'verdict_id': str(verdict.verdict_id), 'decision': 'override',
               'override_disposition': 'BENIGN', 'rationale': 'Reviewed evidence'}
    assert client.post(url + '/analyst-review', json={**payload, 'rationale': ' '}).status_code == 422
    assert client.post(url + '/analyst-review', json={**payload, 'decision': 'confirm'}).status_code == 422
    response = client.post(url + '/analyst-review', json=payload)
    assert response.status_code == 200
    assert client.post(url + '/analyst-review', json=payload).json() == response.json()
    assert client.post(url + '/analyst-review', json={**payload, 'decision': 'confirm', 'override_disposition': None}).status_code == 409
    after = client.get(url).json()
    assert after['verdict'] == before['verdict']
    assert after['alerts'] == before['alerts']
    assert after['analyst_review']['override_disposition'] == 'BENIGN'
    assert db.connect().execute('SELECT COUNT(*) FROM evaluations').fetchone()[0] == 0
    newer = verdict.model_copy(update={'verdict_id': uuid4()})
    db.insert_verdict(newer)
    assert client.post(url + '/analyst-review', json=payload).status_code == 409
    assert client.get(url).json()['analyst_review'] is None
    confirmation = {'verdict_id': str(newer.verdict_id), 'decision': 'confirm'}
    assert client.post(url + '/analyst-review', json=confirmation).status_code == 200
    assert client.get(url).json()['analyst_review']['decision'] == 'confirm'
    db.close()
