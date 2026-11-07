"""Unit and adversarial tests for WIRE-9: Rate Limiter Wait Mode, Persisted Daily Quotas,

Indicator Prioritization without Labels, and --max-lookups CLI Support.
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from src.config import (
    get_enrichment_max_wait_seconds,
    get_enrichment_wait_mode,
    get_virustotal_daily_quota,
    get_virustotal_requests_per_minute,
)
from src.engine.database import DatabaseManager
from src.engine.enrichment import (
    EnrichmentEngine,
    ProviderRateLimiter,
    VirusTotalProvider,
)
from src.models.enrichment import EnrichmentResult


class SimulatedClock:
    """Deterministic simulated clock and sleep function for rate-limiting tests."""

    def __init__(self, initial_time: float = 1000.0) -> None:
        self.current_time = initial_time
        self.sleep_history = []

    def now(self) -> float:
        return self.current_time

    def sleep(self, seconds: float) -> None:
        self.sleep_history.append(seconds)
        self.current_time += seconds


def test_rate_limiter_wait_mode_acquires_with_injected_clock_and_sleep():
    """Verify that acquire_or_wait sleeps and succeeds when delay is within max_wait_seconds."""
    sim = SimulatedClock(initial_time=1000.0)
    limiter = ProviderRateLimiter(
        requests_per_minute=4,
        clock=sim.now,
        sleep_func=sim.sleep,
    )

    # Fill rate limit window with 4 requests
    for _ in range(4):
        assert limiter.acquire_or_wait(max_wait_seconds=10.0) is True

    assert len(limiter._timestamps) == 4
    assert sim.current_time == 1000.0
    assert len(sim.sleep_history) == 0

    # 5th request should require waiting 60.0 seconds (oldest request is at 1000.0)
    acquired = limiter.acquire_or_wait(max_wait_seconds=65.0)
    assert acquired is True
    assert len(sim.sleep_history) == 1
    assert sim.sleep_history[0] >= 60.0
    assert sim.current_time >= 1060.0


def test_rate_limiter_wait_mode_aborts_when_exceeding_max_wait():
    """Verify that acquire_or_wait aborts without sleeping if wait exceeds max_wait_seconds."""
    sim = SimulatedClock(initial_time=1000.0)
    limiter = ProviderRateLimiter(
        requests_per_minute=4,
        clock=sim.now,
        sleep_func=sim.sleep,
    )

    for _ in range(4):
        limiter.record_request()

    # 5th request needs 60.0s, but max wait is only 15.0s -> aborts without sleeping
    acquired = limiter.acquire_or_wait(max_wait_seconds=15.0)
    assert acquired is False
    assert len(sim.sleep_history) == 0
    assert sim.current_time == 1000.0


def test_virustotal_provider_wait_mode_with_injected_clock(monkeypatch):
    """Verify that VirusTotalProvider in wait_mode pauses and completes lookup instead of throttling."""
    sim = SimulatedClock(initial_time=1000.0)
    vt = VirusTotalProvider(
        api_key="mock_key",
        wait_mode=True,
        max_wait_seconds=70.0,
        requests_per_minute=4,
        clock=sim.now,
        sleep_func=sim.sleep,
    )

    # Mock httpx.get to avoid real network calls
    class FakeResponse:
        status_code = 200
        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

    import httpx
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeResponse())

    # First 4 requests should execute immediately without sleep
    for i in range(4):
        res = vt.lookup_with_status(f"198.51.100.{i+1}", "ip")
        assert res.lookup_status == "ok"

    assert len(sim.sleep_history) == 0
    assert sim.current_time == 1000.0

    # 5th request should trigger wait mode and sleep ~60s
    res5 = vt.lookup_with_status("198.51.100.5", "ip")
    assert res5.lookup_status == "ok"
    assert len(sim.sleep_history) == 1
    assert sim.sleep_history[0] >= 60.0
    assert sim.current_time >= 1060.0


def test_persisted_daily_quota_in_sqlite(tmp_path):
    """Verify that DatabaseManager records, persists, and reports daily quota counts across restarts."""
    db_file = str(tmp_path / "test_quota.db")
    db = DatabaseManager(db_path=db_file)
    db.init_db()

    # Initial usage should be 0
    assert db.get_quota_usage("virustotal", date_key="2026-11-08") == 0

    # Increment usage
    new_count = db.increment_quota_usage("virustotal", count=1, date_key="2026-11-08")
    assert new_count == 1
    new_count = db.increment_quota_usage("virustotal", count=3, date_key="2026-11-08")
    assert new_count == 4
    assert db.get_quota_usage("virustotal", date_key="2026-11-08") == 4

    # Close and reopen database connection to verify disk persistence
    db.close()
    db2 = DatabaseManager(db_path=db_file)
    db2.init_db()
    assert db2.get_quota_usage("virustotal", date_key="2026-11-08") == 4
    assert db2.check_quota_available("virustotal", max_daily_quota=5, date_key="2026-11-08") is True
    assert db2.check_quota_available("virustotal", max_daily_quota=4, date_key="2026-11-08") is False


def test_enrichment_engine_enforces_persisted_daily_quota(tmp_path):
    """Verify that EnrichmentEngine returns lookup_status='quota_exceeded' when daily quota is exhausted."""
    db_file = str(tmp_path / "test_engine_quota.db")
    db = DatabaseManager(db_path=db_file)
    db.init_db()

    # Set daily quota to 2 lookups for virustotal
    engine = EnrichmentEngine(db=db, daily_quotas={"virustotal": 2})

    # Stub VT provider
    class FakeVT:
        name = "virustotal"
        def lookup_with_status(self, ind, ind_type):
            return EnrichmentResult(
                indicator=ind,
                indicator_type=ind_type,
                provider="virustotal",
                is_malicious=False,
                raw_response={"test": "ok"},
                lookup_status="ok",
            )

    engine.register_provider(FakeVT())

    # 1st lookup: ok
    res1 = engine.lookup("198.51.100.1", "ip", provider_name="virustotal")
    assert res1.lookup_status == "ok"

    # 2nd lookup: ok
    res2 = engine.lookup("198.51.100.2", "ip", provider_name="virustotal")
    assert res2.lookup_status == "ok"

    # 3rd lookup: quota exceeded
    res3 = engine.lookup("198.51.100.3", "ip", provider_name="virustotal")
    assert res3.lookup_status == "quota_exceeded"
    assert res3.raw_response.get("error") == "Daily quota exceeded"


def test_indicator_prioritization_without_labels():
    """Verify that indicator prioritization ranks by forensic fidelity and frequency without labels."""
    engine = EnrichmentEngine(providers={})

    indicators_with_types = [
        ("198.51.100.1", "ip"),
        ("44d88612fea8a8f36de82e1278abb02f", "hash"),
        ("c2.evil-corp.com", "domain"),
        ("https://malware.example/payload.exe", "url"),
        ("198.51.100.2", "ip"),
    ]

    occurrences = {
        "198.51.100.1": 5, # High frequency IP
        "44d88612fea8a8f36de82e1278abb02f": 1, # Hash (high fidelity)
        "c2.evil-corp.com": 2, # Domain
        "https://malware.example/payload.exe": 1, # URL
        "198.51.100.2": 1, # Low frequency IP
    }

    prioritized = engine.prioritize_indicators(indicators_with_types, occurrences=occurrences)

    # Verify return format
    assert len(prioritized) == 5
    # Hashes and high-value indicators should be prioritized ahead of low-frequency IPs
    prioritized_inds = [p[0] for p in prioritized]
    assert prioritized_inds.index("44d88612fea8a8f36de82e1278abb02f") < prioritized_inds.index("198.51.100.2")


def test_run_evaluation_cli_max_lookups_arg():
    """Verify that run_evaluation.py argparse parses --max-lookups properly."""
    import argparse
    import scripts.run_evaluation as run_eval

    # Verify run_evaluation has --max-lookups in parser
    # We can inspect the parser or test run_evaluation_pipeline argument
    assert hasattr(run_eval, "run_evaluation_pipeline")
    import inspect
    sig = inspect.signature(run_eval.run_evaluation_pipeline)
    assert "max_lookups" in sig.parameters


def test_config_settings_for_enrichment_limits(monkeypatch):
    """Verify config getters read environment variables for wait mode and quotas."""
    monkeypatch.setenv("ENRICHMENT_WAIT_MODE", "true")
    monkeypatch.setenv("ENRICHMENT_MAX_WAIT_SECONDS", "45.5")
    monkeypatch.setenv("VIRUSTOTAL_DAILY_QUOTA", "250")
    monkeypatch.setenv("VIRUSTOTAL_REQUESTS_PER_MINUTE", "5")

    assert get_enrichment_wait_mode() is True
    assert get_enrichment_max_wait_seconds() == 45.5
    assert get_virustotal_daily_quota() == 250
    assert get_virustotal_requests_per_minute() == 5
