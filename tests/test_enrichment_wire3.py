"""Tests for rate limiting, persistent caching, bounded retries, lookup statuses, and LLM prompt delivery (WIRE-3)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import httpx
import pytest

from src.engine.database import DatabaseManager
from src.engine.enrichment import (
    AbuseIPDBProvider,
    EnrichmentEngine,
    ProviderRateLimiter,
    URLhausProvider,
    VirusTotalProvider,
)
from conftest import PipelineTestEngine
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline


def test_http_429_retry_after_honored():
    """Verify that HTTP 429 with Retry-After header sets status to rate_limited and throttles subsequent requests."""
    vt = VirusTotalProvider(api_key="mock_vt_key")

    mock_resp_429 = MagicMock(spec=httpx.Response)
    mock_resp_429.status_code = 429
    mock_resp_429.headers = {"Retry-After": "60"}

    with patch("httpx.get", return_value=mock_resp_429) as mock_get:
        res1 = vt.lookup_with_status("198.51.100.1", "ip")
        assert res1 is not None
        assert res1.lookup_status == "rate_limited"
        assert res1.is_malicious is False
        assert mock_get.call_count == 1

        # Second call within rate limit penalty window should be throttled by client-side rate limiter
        res2 = vt.lookup_with_status("198.51.100.2", "ip")
        assert res2.lookup_status == "rate_limited"
        # No extra HTTP request made because rate limiter blocked it
        assert mock_get.call_count == 1


def test_bounded_retries_with_backoff():
    """Verify that transient 429 with small Retry-After or 5xx retries and recovers."""
    now = [0.0]

    def advance(seconds):
        now[0] += seconds

    vt = VirusTotalProvider(api_key="mock_vt_key", clock=lambda: now[0], sleep_func=advance)

    mock_429 = MagicMock(spec=httpx.Response)
    mock_429.status_code = 429
    mock_429.headers = {"Retry-After": "0.01"}

    mock_200 = MagicMock(spec=httpx.Response)
    mock_200.status_code = 200
    mock_200.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 20}
            }
        }
    }

    # First attempt returns 429 with tiny retry-after, second attempt succeeds with 200
    with patch("httpx.get", side_effect=[mock_429, mock_200]) as mock_get:
        res = vt.lookup_with_status("198.51.100.5", "ip")
        assert res.lookup_status == "ok"
        assert res.is_malicious is True
        assert mock_get.call_count == 2


def test_per_run_lookup_cap():
    """Verify that exceeding max_lookups_per_run returns lookup_status='skipped' without calling provider."""
    mock_vt = MagicMock()
    mock_vt.name = "virustotal"
    mock_vt.lookup_with_status.return_value = EnrichmentResult(
        indicator="1.1.1.1",
        indicator_type="ip",
        provider="virustotal",
        is_malicious=False,
        raw_response={"test": "ok"},
        lookup_status="ok",
    )

    engine = EnrichmentEngine(providers={"virustotal": mock_vt}, max_lookups_per_run=2)

    # 1st lookup -> succeeds
    r1 = engine.lookup("1.1.1.1", "ip", provider_name="virustotal")
    assert r1.lookup_status == "ok"
    assert mock_vt.lookup_with_status.call_count == 1

    # 2nd lookup -> succeeds
    r2 = engine.lookup("2.2.2.2", "ip", provider_name="virustotal")
    assert r2.lookup_status == "ok"
    assert mock_vt.lookup_with_status.call_count == 2

    # 3rd lookup -> exceeds cap, marked skipped without calling provider
    r3 = engine.lookup("3.3.3.3", "ip", provider_name="virustotal")
    assert r3.lookup_status == "skipped"
    assert r3.raw_response.get("reason") == "lookup_cap_exceeded"
    assert mock_vt.lookup_with_status.call_count == 2


def test_persistent_sqlite_cache_survives_two_runs(tmp_path):
    """Verify that a persistent SQLite cache stores results and survives across separate engine instances."""
    db_file = str(tmp_path / "cache_test.db")
    db = DatabaseManager(db_path=db_file)
    db.init_db()

    mock_vt = MagicMock()
    mock_vt.name = "virustotal"
    mock_vt.lookup_with_status.return_value = EnrichmentResult(
        indicator="44d88612fea8a8f36de82e1278abb02f",
        indicator_type="hash",
        provider="virustotal",
        is_malicious=True,
        raw_response={"malware": True},
        lookup_status="ok",
    )

    # Run 1: Look up and cache in SQLite
    engine_run1 = EnrichmentEngine(providers={"virustotal": mock_vt}, db=db)
    res1 = engine_run1.lookup("44d88612fea8a8f36de82e1278abb02f", "hash", provider_name="virustotal")
    assert res1.lookup_status == "ok"
    assert mock_vt.lookup_with_status.call_count == 1

    # Run 2: Completely new engine instance pointing to the same SQLite database
    mock_vt_run2 = MagicMock()
    mock_vt_run2.name = "virustotal"
    engine_run2 = EnrichmentEngine(providers={"virustotal": mock_vt_run2}, db=db)

    res2 = engine_run2.lookup("44d88612fea8a8f36de82e1278abb02f", "hash", provider_name="virustotal")
    assert res2.lookup_status == "ok"
    assert res2.indicator == "44d88612fea8a8f36de82e1278abb02f"
    assert res2.is_malicious is True
    # The provider in Run 2 should NEVER have been called due to SQLite cache hit!
    assert mock_vt_run2.lookup_with_status.call_count == 0


def test_cache_ttl_expiry_positive_and_negative(tmp_path):
    """Verify that positive (24h) and negative (short TTL) cache entries expire properly in SQLite."""
    db_file = str(tmp_path / "ttl_test.db")
    db = DatabaseManager(db_path=db_file)
    db.init_db()

    # 1. Set positive cached entry that has expired (expires_at in the past)
    expired_time = datetime.now(timezone.utc) - timedelta(hours=1)
    db.set_cached_enrichment(
        cache_key="virustotal:ip:8.8.8.8",
        result=EnrichmentResult(
            indicator="8.8.8.8",
            indicator_type="ip",
            provider="virustotal",
            is_malicious=False,
            raw_response={},
            lookup_status="ok",
        ),
        ttl_seconds=-10,  # Expired immediately
    )

    # Should return None because it is expired
    cached = db.get_cached_enrichment("virustotal:ip:8.8.8.8")
    assert cached is None

    # 2. Set negative cached entry (not_found) with valid TTL
    db.set_cached_enrichment(
        cache_key="virustotal:domain:unknown.test",
        result=EnrichmentResult(
            indicator="unknown.test",
            indicator_type="domain",
            provider="virustotal",
            is_malicious=False,
            raw_response={"status": "not_found"},
            lookup_status="not_found",
        ),
        ttl_seconds=900,  # 15 minutes
    )

    cached_neg = db.get_cached_enrichment("virustotal:domain:unknown.test")
    assert cached_neg is not None
    assert cached_neg.lookup_status == "not_found"


def test_unavailable_status_reaches_llm_payload():
    """Verify that missing intelligence (rate_limited, not_found, error) reaches the LLM prompt as unavailable."""
    engine = PipelineTestEngine(api_key="mock_test_transport_key_for_payload_test")

    alert = NormalizedAlert(
        source_dataset="test",
        source_file="test.json",
        event_type="network_flow",
        original_record={"processname": "powershell.exe", "destination_ip": "198.51.100.99"},
        extracted_indicators=["198.51.100.99"],
        ground_truth_label=None,
    )

    # Enrichment result that failed with rate_limited
    failed_enr = EnrichmentResult(
        indicator="198.51.100.99",
        indicator_type="ip",
        provider="VirusTotal",
        is_malicious=False,
        raw_response={"detail": "Quota exceeded"},
        lookup_status="rate_limited",
    )

    timeline = ThreatTimeline(
        grouping_key="test_host",
        alerts=[alert],
        enrichment_data=[failed_enr],
    )

    payload = engine._build_sanitized_triage_payload(timeline)
    enrichments = payload.get("enrichment_data", [])
    assert len(enrichments) == 1
    enr_entry = enrichments[0]

    # Must explicitly convey unavailable status and never clean
    assert enr_entry["intel_status"] == "unavailable"
    assert enr_entry["lookup_status"] == "rate_limited"
    assert "not assumed clean" in enr_entry.get("note", "").lower() or "unavailable" in enr_entry.get("note", "").lower()

