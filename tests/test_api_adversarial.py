"""Military-grade adversarial and stress test suite for the FastAPI backend.

Tests:
- Pagination Abuse: Negative values, massive limits, type confusion, float strings.
- Malformed Path Parameters: Non-UUID strings, 'null', SQL injection fragments, path traversal.
- Resource Exhaustion / Read Stress: 500 rapid concurrent requests against /api/metrics.
- CORS Verification: OPTIONS preflight verification and cross-origin header checks.
- End-to-end data fidelity across timelines, alerts, verdicts, and accuracy metrics.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from uuid import uuid4
from fastapi.testclient import TestClient
import pytest

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.evaluation import AccuracyTracker
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


@pytest.fixture
def test_setup():
    """Sets up an isolated in-memory DatabaseManager, AccuracyTracker, and TestClient."""
    db = DatabaseManager(":memory:", check_same_thread=False)
    db.init_db()
    tracker = AccuracyTracker()
    app = create_app(db=db, tracker=tracker)
    client = TestClient(app)
    return {"db": db, "tracker": tracker, "client": client}


# =====================================================================
# 1. Pagination Abuse Tests
# =====================================================================


def test_pagination_abuse_negative_limit(test_setup):
    """Verify negative limit is rejected with HTTP 422 Unprocessable Entity."""
    client = test_setup["client"]
    response = client.get("/api/timelines?limit=-10")
    assert response.status_code == 422


def test_pagination_abuse_zero_limit(test_setup):
    """Verify limit=0 is rejected with HTTP 422 (minimum limit is 1)."""
    client = test_setup["client"]
    response = client.get("/api/timelines?limit=0")
    assert response.status_code == 422


def test_pagination_abuse_massive_limit(test_setup):
    """Verify massive limits (> 1000) are rejected with HTTP 422 to prevent DoS."""
    client = test_setup["client"]
    response = client.get("/api/timelines?limit=9999999")
    assert response.status_code == 422


def test_pagination_abuse_negative_skip(test_setup):
    """Verify negative skip is rejected with HTTP 422."""
    client = test_setup["client"]
    response = client.get("/api/timelines?skip=-5")
    assert response.status_code == 422


def test_pagination_abuse_type_confusion_drop(test_setup):
    """Verify non-integer string in limit parameter is rejected with HTTP 422."""
    client = test_setup["client"]
    response = client.get("/api/timelines?limit=DROP")
    assert response.status_code == 422


def test_pagination_abuse_skip_nan(test_setup):
    """Verify non-numeric skip is rejected with HTTP 422."""
    client = test_setup["client"]
    response = client.get("/api/timelines?skip=NaN")
    assert response.status_code == 422


def test_pagination_abuse_float_rejection(test_setup):
    """Verify float string in integer query param is rejected with HTTP 422."""
    client = test_setup["client"]
    response = client.get("/api/timelines?limit=10.5")
    assert response.status_code == 422


def test_pagination_valid_boundaries(test_setup):
    """Verify boundary limits (1 and 1000) and zero skip are accepted."""
    client = test_setup["client"]
    resp1 = client.get("/api/timelines?skip=0&limit=1")
    assert resp1.status_code == 200
    assert isinstance(resp1.json(), list)

    resp2 = client.get("/api/timelines?skip=0&limit=1000")
    assert resp2.status_code == 200
    assert isinstance(resp2.json(), list)


# =====================================================================
# 2. Malformed Path Parameter Tests
# =====================================================================


def test_malformed_path_not_a_uuid(test_setup):
    """Verify non-UUID string returns clean HTTP 404 without internal server error."""
    client = test_setup["client"]
    response = client.get("/api/timelines/not-a-uuid")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_malformed_path_null(test_setup):
    """Verify 'null' string returns clean HTTP 404."""
    client = test_setup["client"]
    response = client.get("/api/timelines/null")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_malformed_path_sql_injection(test_setup):
    """Verify SQL injection fragment in path returns HTTP 404 and does not execute."""
    client = test_setup["client"]
    response = client.get("/api/timelines/1' OR '1'='1")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_malformed_path_traversal(test_setup):
    """Verify path traversal pattern is rejected or not found without error."""
    client = test_setup["client"]
    response = client.get("/api/timelines/..%2F..%2Fetc%2Fpasswd")
    assert response.status_code in (404, 400)


# =====================================================================
# 3. CORS Preflight & Header Verification Tests
# =====================================================================


def test_cors_preflight_options_accepted(test_setup):
    """Verify cross-origin OPTIONS preflight requests receive HTTP 200 and CORS headers."""
    client = test_setup["client"]
    response = client.options(
        "/api/metrics",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "*"


def test_cors_get_origin_header_reflected(test_setup):
    """Verify standard GET requests include the CORS allow-origin header."""
    client = test_setup["client"]
    response = client.get(
        "/api/metrics",
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "*"


# =====================================================================
# 4. End-to-End Metrics & Timeline Detail Tests
# =====================================================================


def test_metrics_endpoint_values(test_setup):
    """Verify /api/metrics reflects tracker values with zero division defense."""
    tracker = test_setup["tracker"]
    client = test_setup["client"]

    # Initial state (0 events)
    resp_init = client.get("/api/metrics")
    assert resp_init.status_code == 200
    data_init = resp_init.json()
    assert data_init["accuracy"] == 0.0
    assert data_init["total"] == 0

    # Populated state
    tracker.tp = 80
    tracker.tn = 15
    tracker.fp = 5
    tracker.fn = 0

    resp_pop = client.get("/api/metrics")
    assert resp_pop.status_code == 200
    data_pop = resp_pop.json()
    assert data_pop["tp"] == 80
    assert data_pop["tn"] == 15
    assert data_pop["fp"] == 5
    assert data_pop["fn"] == 0
    assert data_pop["total"] == 100
    assert data_pop["accuracy"] == 0.95
    assert pytest.approx(data_pop["precision"], 0.01) == 0.941
    assert data_pop["recall"] == 1.0


def test_timeline_detail_endpoint_with_alerts_and_verdict(test_setup):
    """Verify /api/timelines/{id} returns the timeline, its alerts, and verdict."""
    db = test_setup["db"]
    client = test_setup["client"]

    # 1. Create and persist timeline
    alert = NormalizedAlert(
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="test.json",
        event_type="4624",
        original_record={"user": "admin", "ip": "10.0.0.1"},
        extracted_indicators=["10.0.0.1"],
    )
    timeline = ThreatTimeline(
        grouping_key="APT29_Campaign",
        alerts=[alert],
        total_events=1,
    )
    timeline_id = db.insert_timeline(timeline)

    # 2. Persist verdict
    verdict = TriageVerdict(
        timeline_id=timeline.timeline_id,
        severity="HIGH",
        confidence_score=0.92,
        summary="Suspicious logon activity",
        reasoning=["Off-hours administrative login"],
        recommended_actions=["Reset credentials"],
        raw_llm_response="{}",
    )
    db.insert_verdict(verdict)

    # 3. Query detail endpoint
    response = client.get(f"/api/timelines/{timeline_id}")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == timeline_id
    assert data["grouping_key"] == "APT29_Campaign"
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["event_type"] == "4624"
    assert data["verdict"] is not None
    assert data["verdict"]["severity"] == "HIGH"
    assert data["verdict"]["confidence_score"] == 0.92


def test_alert_detail_endpoint_success_and_404(test_setup):
    """Verify /api/alerts/{id} returns alert data or HTTP 404."""
    db = test_setup["db"]
    client = test_setup["client"]

    alert = NormalizedAlert(
        source_dataset="test_ds",
        source_file="auth.json",
        event_type="4625",
        original_record={"failure_reason": "bad_password"},
        extracted_indicators=["198.51.100.22"],
    )
    alert_id = db.insert_alert(alert)

    # 1. Successful lookup
    resp = client.get(f"/api/alerts/{alert_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == alert_id
    assert data["event_type"] == "4625"
    assert data["original_record"]["failure_reason"] == "bad_password"

    # 2. Missing alert lookup
    resp_404 = client.get(f"/api/alerts/{uuid4()}")
    assert resp_404.status_code == 404


def test_indicator_enrichment_endpoint(test_setup):
    """Verify /api/enrichments/{indicator} returns recorded lookups."""
    db = test_setup["db"]
    client = test_setup["client"]
    from src.models.enrichment import EnrichmentResult

    enrichment = EnrichmentResult(
        indicator="203.0.113.5",
        indicator_type="ip",
        provider="AbuseIPDB",
        is_malicious=True,
        raw_response={"score": 100},
    )
    db.insert_enrichment(enrichment)

    resp = client.get("/api/enrichments/203.0.113.5")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["indicator"] == "203.0.113.5"
    assert items[0]["is_malicious"] is True


def test_health_check_endpoint(test_setup):
    """Verify system health check endpoint."""
    client = test_setup["client"]
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# =====================================================================
# 5. Resource Exhaustion / Read Stress Tests (500 Rapid Requests)
# =====================================================================


def test_resource_exhaustion_500_rapid_requests(test_setup):
    """Fire a tight loop of 500 rapid concurrent requests against /api/metrics.

    Verifies the API and SQLite connection handle high read throughput without
    crashing, timing out, or raising HTTP 500 / database lock errors.
    """
    client = test_setup["client"]
    num_requests = 500
    workers = 25

    def send_request():
        resp = client.get("/api/metrics")
        return resp.status_code

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(send_request) for _ in range(num_requests)]
        status_codes = [f.result() for f in as_completed(futures)]

    assert len(status_codes) == num_requests
    assert all(code == 200 for code in status_codes)


def test_resource_exhaustion_rapid_timelines_reads(test_setup):
    """Fire 100 rapid concurrent requests against paginated /api/timelines."""
    client = test_setup["client"]
    num_requests = 100
    workers = 10

    def send_request():
        resp = client.get("/api/timelines?skip=0&limit=10")
        return resp.status_code

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(send_request) for _ in range(num_requests)]
        status_codes = [f.result() for f in as_completed(futures)]

    assert len(status_codes) == num_requests
    assert all(code == 200 for code in status_codes)
