"""Tests for indicator routing and credential-gated provider registration in EnrichmentEngine."""

import os
from typing import Optional
from unittest.mock import patch
import pytest

from src.cli import run_pipeline
from src.engine.database import DatabaseManager
from src.engine.enrichment import (
    AbuseIPDBProvider,
    EnrichmentEngine,
    ThreatIntelProvider,
    URLhausProvider,
    VirusTotalProvider,
)
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult


class StubThreatIntelProvider(ThreatIntelProvider):
    """Clean stub threat intelligence provider for testing dependency injection."""

    def __init__(
        self,
        provider_name: str,
        result: Optional[EnrichmentResult] = None,
        is_malicious: bool = False,
        raw_response: Optional[dict] = None,
    ) -> None:
        super().__init__()
        self._name = provider_name
        self.call_count = 0
        self._result = result
        self._is_malicious = is_malicious
        self._raw_response = raw_response or {}

    @property
    def name(self) -> str:
        return self._name

    def lookup_with_status(self, indicator: str, indicator_type: str) -> EnrichmentResult:
        self.call_count += 1
        if self._result is not None:
            return self._result
        return EnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self._name,
            is_malicious=self._is_malicious,
            raw_response=self._raw_response,
            lookup_status="ok",
        )

    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
        res = self.lookup_with_status(indicator, indicator_type)
        return res if res.lookup_status == "ok" else None

    def reset(self) -> None:
        self.call_count = 0


def test_default_engine_registers_only_keyed_providers(monkeypatch):
    """Verify that default EnrichmentEngine() only registers providers with usable API keys."""
    # Scenario 1: Empty environment -> only URLhaus registered (since it is keyless for now)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    engine_empty = EnrichmentEngine()
    assert "urlhaus" in engine_empty.providers
    assert "virustotal" not in engine_empty.providers
    assert "abuseipdb" not in engine_empty.providers

    # Scenario 2: VT key present (using VT_API_KEY alias)
    monkeypatch.setenv("VT_API_KEY", "vt_mock_test_key")
    engine_vt = EnrichmentEngine()
    assert "virustotal" in engine_vt.providers
    assert "urlhaus" in engine_vt.providers
    assert "abuseipdb" not in engine_vt.providers

    # Scenario 3: AbuseIPDB key present
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse_mock_test_key")
    engine_abuse = EnrichmentEngine()
    assert "abuseipdb" in engine_abuse.providers
    assert "urlhaus" in engine_abuse.providers
    assert "virustotal" not in engine_abuse.providers


def test_routing_ip_indicators():
    """Verify that IP indicators are routed to both VirusTotal and AbuseIPDB, not URLhaus."""
    engine = EnrichmentEngine(providers={})
    stub_vt = StubThreatIntelProvider("virustotal", is_malicious=False, raw_response={"vt": "clean"})
    stub_abuse = StubThreatIntelProvider("abuseipdb", is_malicious=True, raw_response={"abuse": "flagged"})
    stub_urlhaus = StubThreatIntelProvider("urlhaus", is_malicious=False, raw_response={"urlhaus": "none"})

    engine.register_provider(stub_vt)
    engine.register_provider(stub_abuse)
    engine.register_provider(stub_urlhaus)

    results = engine.lookup_indicator("198.51.100.1", indicator_type="ip")

    assert stub_vt.call_count == 1
    assert stub_abuse.call_count == 1
    assert stub_urlhaus.call_count == 0
    assert len(results) == 2
    providers_returned = {r.provider for r in results}
    assert providers_returned == {"virustotal", "abuseipdb"}


def test_routing_hash_indicators():
    """Verify that file hash indicators are routed strictly to VirusTotal."""
    engine = EnrichmentEngine(providers={})
    stub_vt = StubThreatIntelProvider("virustotal", is_malicious=True, raw_response={"vt": "malicious"})
    stub_abuse = StubThreatIntelProvider("abuseipdb")
    stub_urlhaus = StubThreatIntelProvider("urlhaus")

    engine.register_provider(stub_vt)
    engine.register_provider(stub_abuse)
    engine.register_provider(stub_urlhaus)

    results = engine.lookup_indicator("44d88612fea8a8f36de82e1278abb02f", indicator_type="hash")

    assert stub_vt.call_count == 1
    assert stub_abuse.call_count == 0
    assert stub_urlhaus.call_count == 0
    assert len(results) == 1
    assert results[0].provider == "virustotal"


def test_routing_domain_and_url_indicators():
    """Verify that domain and url indicators route to VirusTotal and URLhaus, not AbuseIPDB."""
    engine = EnrichmentEngine(providers={})
    stub_vt = StubThreatIntelProvider("virustotal", is_malicious=False)
    stub_urlhaus = StubThreatIntelProvider("urlhaus", is_malicious=True)
    stub_abuse = StubThreatIntelProvider("abuseipdb")

    engine.register_provider(stub_vt)
    engine.register_provider(stub_urlhaus)
    engine.register_provider(stub_abuse)

    # Test Domain
    res_domain = engine.lookup_indicator("evil.example.com", indicator_type="domain")
    assert stub_vt.call_count == 1
    assert stub_urlhaus.call_count == 1
    assert stub_abuse.call_count == 0
    assert len(res_domain) == 2

    # Test URL
    stub_vt.reset()
    stub_urlhaus.reset()
    stub_abuse.reset()

    res_url = engine.lookup_indicator("https://evil.example.com/mal.bin", indicator_type="url")
    assert stub_vt.call_count == 1
    assert stub_urlhaus.call_count == 1
    assert stub_abuse.call_count == 0
    assert len(res_url) == 2


def test_unregistered_provider_never_called():
    """Verify that if a provider is missing/unregistered, routing gracefully skips it."""
    engine = EnrichmentEngine(providers={})
    stub_urlhaus = StubThreatIntelProvider("urlhaus", is_malicious=True)
    engine.register_provider(stub_urlhaus)

    # Domain routes to [virustotal, urlhaus], but virustotal is unconfigured
    results = engine.lookup_indicator("evil.example.com", indicator_type="domain")
    assert len(results) == 1
    assert results[0].provider == "urlhaus"
    assert stub_urlhaus.call_count == 1


def test_pipeline_e2e_multi_provider_enrichment(tmp_path, monkeypatch):
    """End-to-end test through run_pipeline verifying multiple providers persist to SQLite."""
    # Setup test alert data in tmp_path / data
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    sample_file = data_dir / "alerts.json"
    sample_file.write_text(
        """[
            {
                "timestamp": "2026-11-06T08:00:00Z",
                "source_dataset": "synthetic_soc",
                "event_type": "network_connection",
                "original_record": {
                    "host": "WORKSTATION-01",
                    "user": "analyst1",
                    "destination_ip": "198.51.100.55"
                },
                "extracted_indicators": ["198.51.100.55"],
                "ground_truth_label": "malicious"
            }
        ]""",
        encoding="utf-8",
    )

    db_path = str(tmp_path / "test_pipeline.db")

    # Mock VT and AbuseIPDB keys in env
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "mock_vt_key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "mock_abuse_key")

    mock_vt_result = EnrichmentResult(
        indicator="198.51.100.55",
        indicator_type="ip",
        provider="virustotal",
        is_malicious=True,
        raw_response={"vt": "malicious_score_10"},
        lookup_status="ok",
    )
    mock_abuse_result = EnrichmentResult(
        indicator="198.51.100.55",
        indicator_type="ip",
        provider="abuseipdb",
        is_malicious=True,
        raw_response={"abuse_score": 100},
        lookup_status="ok",
    )

    with patch.object(VirusTotalProvider, "lookup_with_status", return_value=mock_vt_result) as mock_vt_call, \
         patch.object(AbuseIPDBProvider, "lookup_with_status", return_value=mock_abuse_result) as mock_abuse_call:

        run_pipeline(data_dir=str(data_dir), db_path=db_path, skip_llm=True)

        assert mock_vt_call.call_count >= 1
        assert mock_abuse_call.call_count >= 1

    # Verify SQLite database contains results from more than one provider for the indicator
    db = DatabaseManager(db_path=db_path)
    with db:
        rows = db.execute("SELECT indicator, provider, is_malicious FROM enrichments;").fetchall()
        assert len(rows) == 2
        providers = {r["provider"] for r in rows}
        assert providers == {"virustotal", "abuseipdb"}
        assert all(r["indicator"] == "198.51.100.55" for r in rows)


