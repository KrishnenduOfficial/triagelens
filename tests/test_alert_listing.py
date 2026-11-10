from datetime import datetime, timezone

from fastapi.testclient import TestClient
import pytest

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.models.alert import NormalizedAlert


@pytest.fixture
def client(tmp_path):
    db = DatabaseManager(str(tmp_path / 'alerts.db'), check_same_thread=False)
    db.init_db()
    for dataset, event, host, user, hour in [
        ('Alpha', 'Login', 'HOST-A', 'Alice', 1),
        ('Beta', 'Process', 'host-b', 'Bob', 2),
        ('Alpha', 'Login', 'host-c', 'Alice', 3),
    ]:
        db.insert_alert(NormalizedAlert(source_dataset=dataset, source_file='file.evtx', event_type=event,
            timestamp=datetime(2026, 1, 1, hour, tzinfo=timezone.utc),
            original_record={'hostname': host, 'username': user, 'text': '<script>bad</script>'}))
    with TestClient(create_app(db=db)) as instance:
        yield instance


def test_filters_pagination_sort_and_literal_search(client):
    response = client.get('/api/alerts', params={'dataset': 'ALP', 'event_type': 'log', 'user': 'alice', 'host': 'host', 'limit': 1, 'sort': 'timestamp', 'direction': 'asc'})
    assert response.status_code == 200
    data = response.json()
    assert data['total'] == 2 and len(data['items']) == 1
    assert data['items'][0]['original_record']['hostname'] == 'HOST-A'
    assert client.get('/api/alerts', params={'host': 'host-c'}).json()['total'] == 1
    assert client.get('/api/alerts', params={'search': '%'}).json()['total'] == 0
    assert client.get('/api/alerts', params={'search': 'process'}).json()['total'] == 1
    assert client.get('/api/alerts', params={'skip': 1, 'limit': 1, 'sort': 'timestamp', 'direction': 'asc'}).json()['items'][0]['source_dataset'] == 'Beta'


def test_time_bounds_and_detail(client):
    result = client.get('/api/alerts', params={'start': '2026-01-01T02:00:00+00:00', 'end': '2026-01-01T08:30:00+05:30'}).json()
    assert result['total'] == 2
    item = result['items'][0]
    assert client.get('/api/alerts/' + item['id']).json()['original_record'] == item['original_record']
    assert item['original_record']['text'] == '<script>bad</script>'
    assert client.get('/api/alerts', params={'search': 'no-such-alert'}).json() == {'total': 0, 'items': [], 'skip': 0, 'limit': 50}


@pytest.mark.parametrize('params', [ {'limit': 101}, {'limit': 0}, {'skip': -1}, {'sort': 'id; DROP TABLE alerts'},
    {'direction': 'sideways'}, {'start': '2026-01-01T00:00:00'},
    {'start': '2026-01-02T00:00:00Z', 'end': '2026-01-01T00:00:00Z'} ])
def test_invalid_parameters_are_rejected(client, params):
    assert client.get('/api/alerts', params=params).status_code == 422
