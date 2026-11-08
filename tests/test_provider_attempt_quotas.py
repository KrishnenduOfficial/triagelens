"""Offline request-attempt accounting across retries, workers, and UTC days."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading

import httpx
import pytest

import src.engine.enrichment as enrichment_module
from src.engine.database import DatabaseManager
from src.engine.enrichment import AbuseIPDBProvider, EnrichmentEngine, ProviderRateLimiter, URLhausProvider, VirusTotalProvider


class Clock:
    def __init__(self):
        self.value = datetime(2026, 1, 1, 12, tzinfo=timezone.utc).timestamp()
        self.sleeps = []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()

    class FakeDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(clock.now(), tz=tz)

    monkeypatch.setattr("src.engine.database.datetime", FakeDateTime)
    monkeypatch.setattr(enrichment_module, "datetime", FakeDateTime)
    monkeypatch.setattr("time.sleep", clock.sleep)
    ledger = getattr(enrichment_module, "InMemoryQuotaLedger", None)
    if ledger is not None:
        monkeypatch.setattr(enrichment_module, "_MEMORY_QUOTA_LEDGER", ledger())
    return clock


@pytest.fixture
def db(clock):
    database = DatabaseManager()
    database.init_db()
    yield database
    database.close()


def provider_for(name, clock):
    classes = {"virustotal": VirusTotalProvider, "abuseipdb": AbuseIPDBProvider, "urlhaus": URLhausProvider}
    options = {"wait_mode": False} if name == "virustotal" else {}
    provider = classes[name](api_key="offline-placeholder", **options)
    provider.rate_limiter = ProviderRateLimiter(requests_per_minute=100, clock=clock.now, sleep_func=clock.sleep)
    return provider


def install_sender(monkeypatch, name, sequence, on_send=None):
    calls = []
    bodies = {
        "virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}},
        "abuseipdb": {"data": {"abuseConfidenceScore": 10, "totalReports": 1}},
        "urlhaus": {"query_status": "ok", "url_status": "online", "threat": "malware_download"},
    }

    def send(*args, **kwargs):
        calls.append(kwargs)
        if on_send:
            on_send()
        item = sequence[min(len(calls) - 1, len(sequence) - 1)]
        if isinstance(item, Exception):
            raise item
        return httpx.Response(item, json=bodies[name] if item == 200 else {},
                              headers={"Retry-After": "0.01"} if item == 429 else {})

    monkeypatch.setattr(httpx, "get", send)
    monkeypatch.setattr(httpx, "post", send)
    return calls


def lookup(engine, name, indicator=None, kind=None):
    return engine.lookup(indicator or ("example.org" if name == "urlhaus" else "8.8.8.8"),
                         kind or ("domain" if name == "urlhaus" else "ip"), name)


@pytest.mark.parametrize("name", ["virustotal", "abuseipdb", "urlhaus"])
def test_each_retry_reserves_daily_quota_and_rpm_slot(monkeypatch, db, clock, name):
    provider = provider_for(name, clock)
    calls = install_sender(monkeypatch, name, [503, 503, 200])
    engine = EnrichmentEngine(providers={name: provider}, db=db, daily_quotas={name: 3})
    assert lookup(engine, name).lookup_status == "ok"
    assert len(calls) == db.get_quota_usage(name) == len(provider.rate_limiter._timestamps) == 3
    assert engine.lookups_this_run == 1
    assert clock.sleeps == [0.02, 0.04]


@pytest.mark.parametrize("name", ["virustotal", "abuseipdb", "urlhaus"])
def test_retry_stops_before_send_when_daily_budget_exhausted(monkeypatch, db, clock, name):
    provider = provider_for(name, clock)
    calls = install_sender(monkeypatch, name, [503, 200])
    engine = EnrichmentEngine(providers={name: provider}, db=db, daily_quotas={name: 1})
    assert lookup(engine, name).lookup_status == "quota_exceeded"
    assert len(calls) == db.get_quota_usage(name) == len(provider.rate_limiter._timestamps) == 1


@pytest.mark.parametrize("name", ["virustotal", "abuseipdb", "urlhaus"])
def test_local_throttling_does_not_consume_daily_quota(monkeypatch, db, clock, name):
    provider = provider_for(name, clock)
    provider.rate_limiter.record_rate_limit(60)
    calls = install_sender(monkeypatch, name, [200])
    engine = EnrichmentEngine(providers={name: provider}, db=db, daily_quotas={name: 1})
    assert lookup(engine, name).lookup_status == "rate_limited"
    assert len(calls) == db.get_quota_usage(name) == 0


@pytest.mark.parametrize("name", ["virustotal", "abuseipdb", "urlhaus"])
def test_validation_rejection_does_not_consume_daily_quota(monkeypatch, db, clock, name):
    calls = install_sender(monkeypatch, name, [200])
    engine = EnrichmentEngine(providers={name: provider_for(name, clock)}, db=db, daily_quotas={name: 1})
    assert lookup(engine, name, kind="unsupported").lookup_status == "error"
    assert len(calls) == db.get_quota_usage(name) == 0


@pytest.mark.parametrize("name", ["virustotal", "abuseipdb", "urlhaus"])
def test_timeouts_conservatively_keep_each_attempt_reservation(monkeypatch, db, clock, name):
    provider = provider_for(name, clock)
    calls = install_sender(monkeypatch, name, [httpx.ReadTimeout("offline")])
    engine = EnrichmentEngine(providers={name: provider}, db=db, daily_quotas={name: 3})
    assert lookup(engine, name).lookup_status == "error"
    assert len(calls) == db.get_quota_usage(name) == len(provider.rate_limiter._timestamps) == 3


@pytest.mark.parametrize("name", ["virustotal", "abuseipdb", "urlhaus"])
def test_429_retry_and_cache_hit_have_correct_attempt_counts(monkeypatch, db, clock, name):
    calls = install_sender(monkeypatch, name, [429, 200])
    engine = EnrichmentEngine(providers={name: provider_for(name, clock)}, db=db, daily_quotas={name: 2})
    assert lookup(engine, name).lookup_status == "ok"
    assert lookup(engine, name).lookup_status == "ok"
    assert len(calls) == db.get_quota_usage(name) == 2
    assert engine.lookups_this_run == 1


def test_process_local_quota_shared_between_memory_only_engines(monkeypatch, clock):
    calls = install_sender(monkeypatch, "virustotal", [200])
    engines = [EnrichmentEngine(providers={"virustotal": provider_for("virustotal", clock)}, daily_quotas={"virustotal": 1}) for _ in range(2)]
    assert lookup(engines[0], "virustotal").lookup_status == "ok"
    assert lookup(engines[1], "virustotal", "1.1.1.1").lookup_status == "quota_exceeded"
    assert len(calls) == 1


def test_reservation_charged_to_dispatch_day_not_response_day(monkeypatch, db, clock):
    clock.value = datetime(2026, 1, 1, 23, 59, 59, tzinfo=timezone.utc).timestamp()
    calls = install_sender(monkeypatch, "virustotal", [200], on_send=lambda: clock.sleep(2))
    engine = EnrichmentEngine(providers={"virustotal": provider_for("virustotal", clock)}, db=db, daily_quotas={"virustotal": 1})
    assert lookup(engine, "virustotal").lookup_status == "ok"
    assert len(calls) == db.get_quota_usage("virustotal", "2026-01-01") == 1
    assert db.get_quota_usage("virustotal", "2026-01-02") == 0


@pytest.mark.parametrize("persistent", [False, True])
def test_quota_denial_does_not_poison_cache_after_day_reset(monkeypatch, db, clock, persistent):
    clock.value = datetime(2026, 1, 1, 23, 59, 59, tzinfo=timezone.utc).timestamp()
    calls = install_sender(monkeypatch, "virustotal", [200])
    engine = EnrichmentEngine(providers={"virustotal": provider_for("virustotal", clock)},
                             db=db if persistent else None, daily_quotas={"virustotal": 1})
    assert lookup(engine, "virustotal").lookup_status == "ok"
    assert lookup(engine, "virustotal", "1.1.1.1").lookup_status == "quota_exceeded"
    clock.sleep(2)
    assert lookup(engine, "virustotal", "1.1.1.1").lookup_status == "ok"
    assert len(calls) == 2


def test_atomic_reservation_across_independent_sqlite_connections(tmp_path, monkeypatch, clock):
    path = str(tmp_path / "shared-quota.db")
    databases = [DatabaseManager(path) for _ in range(2)]
    for database in databases:
        database.init_db()
    barrier = threading.Barrier(2)
    calls = install_sender(monkeypatch, "virustotal", [200])
    engines = [EnrichmentEngine(providers={"virustotal": provider_for("virustotal", clock)},
                               db=database, daily_quotas={"virustotal": 1}) for database in databases]

    def run(index):
        barrier.wait(timeout=5)
        return lookup(engines[index], "virustotal", "8.8.8." + str(index + 1)).lookup_status

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(run, range(2)))
        assert sorted(statuses) == ["ok", "quota_exceeded"]
        assert len(calls) == databases[0].get_quota_usage("virustotal") == 1
    finally:
        for database in databases:
            database.close()


@pytest.mark.parametrize("name", ["virustotal", "abuseipdb", "urlhaus"])
def test_injected_sender_clock_and_sleep_cover_every_retry(db, clock, name):
    calls = []

    def send(*args, **kwargs):
        calls.append(kwargs)
        return httpx.Response(503 if len(calls) == 1 else 404)

    classes = {"virustotal": VirusTotalProvider, "abuseipdb": AbuseIPDBProvider, "urlhaus": URLhausProvider}
    provider = classes[name](api_key="offline-placeholder", wait_mode=False,
                             clock=clock.now, sleep_func=clock.sleep, request_sender=send)
    engine = EnrichmentEngine(providers={name: provider}, db=db, daily_quotas={name: 2})
    assert lookup(engine, name).lookup_status == "not_found"
    assert len(calls) == db.get_quota_usage(name) == len(provider.rate_limiter._timestamps) == 2
    assert clock.sleeps == [0.02]


def test_shared_provider_uses_current_engine_quota_context(monkeypatch, clock):
    provider = provider_for("virustotal", clock)
    calls = install_sender(monkeypatch, "virustotal", [200])
    engines = [EnrichmentEngine(providers={"virustotal": provider}, daily_quotas={"virustotal": 1},
                               quota_ledger=enrichment_module.InMemoryQuotaLedger()) for _ in range(2)]
    assert lookup(engines[0], "virustotal").lookup_status == "ok"
    assert lookup(engines[1], "virustotal").lookup_status == "ok"
    assert lookup(engines[0], "virustotal", "1.1.1.1").lookup_status == "quota_exceeded"
    assert len(calls) == 2
    assert enrichment_module._ATTEMPT_QUOTA_GATE.get() is None


def test_reservation_failure_prevents_send_and_restores_context(monkeypatch, db, clock):
    provider = provider_for("virustotal", clock)
    calls = install_sender(monkeypatch, "virustotal", [200])
    engine = EnrichmentEngine(providers={"virustotal": provider}, db=db, daily_quotas={"virustotal": 1})

    def fail(*args):
        raise RuntimeError("offline storage failure")

    with monkeypatch.context() as patcher:
        patcher.setattr(db, "reserve_quota_request", fail)
        with pytest.raises(RuntimeError, match="offline storage failure"):
            lookup(engine, "virustotal")
    assert not calls
    assert not provider.rate_limiter._timestamps
    assert enrichment_module._ATTEMPT_QUOTA_GATE.get() is None
    assert lookup(engine, "virustotal").lookup_status == "ok"
    assert len(calls) == db.get_quota_usage("virustotal") == 1


def test_wait_reserves_on_day_after_rpm_delay(monkeypatch, db, clock):
    clock.value = datetime(2026, 1, 1, 23, 59, 59, tzinfo=timezone.utc).timestamp()
    provider = provider_for("virustotal", clock)
    provider.wait_mode = True
    provider.rate_limiter.requests_per_minute = 1
    provider.rate_limiter.record_request()
    calls = install_sender(monkeypatch, "virustotal", [200])
    engine = EnrichmentEngine(providers={"virustotal": provider}, db=db,
                             daily_quotas={"virustotal": 1}, quota_clock=clock.now)
    assert lookup(engine, "virustotal").lookup_status == "ok"
    assert clock.sleeps == [60.0]
    assert db.get_quota_usage("virustotal", "2026-01-01") == 0
    assert len(calls) == db.get_quota_usage("virustotal", "2026-01-02") == 1
