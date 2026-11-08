"""Offline TTL regressions across SQLite and memory-only enrichment caches."""

from datetime import datetime, timezone

import pytest

from src.engine.database import DatabaseManager
from src.engine.enrichment import EnrichmentEngine, ThreatIntelProvider
from src.models.enrichment import EnrichmentResult


class FakeClock:
    def __init__(self):
        self.value = 1767225600.0

    def now(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class StubProvider(ThreatIntelProvider):
    name = "audit"

    def __init__(self, initial_status="ok"):
        super().__init__()
        self.initial_status = initial_status
        self.calls = 0

    def lookup_with_status(self, indicator, indicator_type):
        self.calls += 1
        return EnrichmentResult(
            indicator=indicator, indicator_type=indicator_type, provider=self.name,
            is_malicious=self.calls > 1, raw_response={"revision": self.calls},
            lookup_status=self.initial_status if self.calls == 1 else "ok",
        )


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def db(monkeypatch, clock):
    class CacheDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(clock.now(), tz=tz)

    monkeypatch.setattr("src.engine.database.datetime", CacheDateTime)
    database = DatabaseManager()
    database.init_db()
    yield database
    database.close()


def lookup(engine):
    return engine.lookup("example.org", "domain", "audit")


@pytest.mark.parametrize("status,ttl", [("ok", 86400), ("not_found", 900), ("rate_limited", 900), ("error", 900)])
def test_memory_only_entries_expire_at_original_deadline(clock, status, ttl):
    provider = StubProvider(status)
    engine = EnrichmentEngine(providers={"audit": provider}, cache_clock=clock.now)
    first = lookup(engine)
    clock.advance(ttl - 1)
    assert lookup(engine) is first
    assert provider.calls == engine.lookups_this_run == 1
    clock.advance(1)
    refreshed = lookup(engine)
    assert refreshed.raw_response == {"revision": 2}
    assert refreshed.lookup_status == "ok"
    assert refreshed.is_malicious is True
    assert first.lookup_status == status
    assert first.is_malicious is False
    assert provider.calls == engine.lookups_this_run == 2


@pytest.mark.parametrize("status,ttl", [("ok", 86400), ("not_found", 900), ("rate_limited", 900), ("error", 900)])
def test_sqlite_expiry_cannot_fall_back_to_stale_memory(db, clock, status, ttl):
    provider = StubProvider(status)
    engine = EnrichmentEngine(providers={"audit": provider}, db=db, daily_quotas={})
    first = lookup(engine)
    clock.advance(ttl - 1)
    assert lookup(engine).raw_response == {"revision": 1}
    assert provider.calls == 1
    clock.advance(1)
    assert db.get_cached_enrichment("audit:domain:example.org") is None
    refreshed = lookup(engine)
    assert refreshed.raw_response == {"revision": 2}
    assert refreshed.lookup_status == "ok"
    assert refreshed.is_malicious is True
    assert first.is_malicious is False
    assert provider.calls == engine.lookups_this_run == 2
    assert db.get_cached_enrichment("audit:domain:example.org").raw_response == {"revision": 2}


def test_sqlite_warmed_engine_keeps_persisted_deadline(db, clock):
    provider = StubProvider()
    writer = EnrichmentEngine(providers={"audit": provider}, db=db, daily_quotas={})
    lookup(writer)
    clock.advance(86399)
    reader = EnrichmentEngine(providers={"audit": provider}, db=db, daily_quotas={})
    assert lookup(reader).raw_response == {"revision": 1}
    assert provider.calls == 1
    assert reader.lookups_this_run == 0
    clock.advance(1)
    assert lookup(reader).raw_response == {"revision": 2}
    assert provider.calls == 2
    assert reader.lookups_this_run == 1


def test_deleted_sqlite_entry_invalidates_memory_copy(db):
    provider = StubProvider()
    engine = EnrichmentEngine(providers={"audit": provider}, db=db, daily_quotas={})
    lookup(engine)
    db.execute("DELETE FROM enrichment_cache WHERE cache_key = ?", ("audit:domain:example.org",))
    assert lookup(engine).raw_response == {"revision": 2}
    assert provider.calls == 2


@pytest.mark.parametrize("persistent", [False, True])
def test_expired_entry_respects_per_run_cap(db, clock, persistent):
    provider = StubProvider()
    options = {"db": db} if persistent else {"cache_clock": clock.now}
    engine = EnrichmentEngine(providers={"audit": provider}, max_lookups_per_run=1, **options)
    engine.TTL_POSITIVE_SECONDS = 10
    assert lookup(engine).lookup_status == "ok"
    clock.advance(10)
    assert lookup(engine).lookup_status == "skipped"
    assert provider.calls == engine.lookups_this_run == 1
    assert "audit:domain:example.org" not in engine.cache


def test_expired_entry_respects_daily_quota_without_stale_result(db, clock):
    provider = StubProvider()
    engine = EnrichmentEngine(providers={"audit": provider}, db=db, daily_quotas={"audit": 1})
    engine.TTL_POSITIVE_SECONDS = 10
    assert lookup(engine).lookup_status == "ok"
    clock.advance(10)
    assert lookup(engine).lookup_status == "quota_exceeded"
    assert provider.calls == engine.lookups_this_run == 1
    assert db.get_quota_usage("audit") == 1
    assert "audit:domain:example.org" not in engine.cache


def test_fresh_sqlite_hit_does_not_consume_quota_or_lookup_budget(db, clock):
    provider = StubProvider()
    engine = EnrichmentEngine(
        providers={"audit": provider}, db=db, daily_quotas={"audit": 1}, max_lookups_per_run=1,
    )
    engine.TTL_POSITIVE_SECONDS = 10
    lookup(engine)
    clock.advance(9)
    assert lookup(engine).lookup_status == "ok"
    assert provider.calls == engine.lookups_this_run == db.get_quota_usage("audit") == 1
