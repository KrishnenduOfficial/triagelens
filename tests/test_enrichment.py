"""Tests for threat intelligence enrichment engine and VirusTotal integration."""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from src.engine.enrichment import EnrichmentEngine, VirusTotalProvider
from src.models.enrichment import EnrichmentResult


@pytest.fixture
def vt_provider():
    """Returns a VirusTotalProvider configured with a dummy API key."""
    return VirusTotalProvider(api_key="mock_vt_api_key_12345", timeout=5.0)


@pytest.fixture
def enrichment_engine(vt_provider):
    """Returns an EnrichmentEngine instance with VirusTotal registered."""
    engine = EnrichmentEngine()
    engine.register_provider(vt_provider)
    return engine


def test_virustotal_malicious_hash_lookup(vt_provider):
    """Verify that a malicious file hash is correctly parsed and marked as malicious."""
    test_hash = "44d88612fea8a8f36de82e1278abb02f"
    mock_payload = {
        "data": {
            "id": test_hash,
            "type": "file",
            "attributes": {
                "meaningful_name": "malware.exe",
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 2,
                    "undetected": 15,
                    "harmless": 0,
                },
            },
        }
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = mock_payload

    with patch("httpx.get", return_value=mock_response) as mock_get:
        result = vt_provider.lookup(test_hash, "hash")

        assert result is not None
        assert isinstance(result, EnrichmentResult)
        assert result.indicator == test_hash
        assert result.indicator_type == "hash"
        assert result.provider == "VirusTotal"
        assert result.is_malicious is True
        assert result.raw_response == mock_payload
        assert result.lookup_timestamp is not None

        # Verify correct URL and headers were used
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert called_url == f"https://www.virustotal.com/api/v3/files/{test_hash}"
        headers = mock_get.call_args[1]["headers"]
        assert headers["x-apikey"] == "mock_vt_api_key_12345"


def test_virustotal_clean_ip_lookup(vt_provider):
    """Verify that a benign IP address with 0 malicious detections is marked as clean."""
    clean_ip = "8.8.8.8"
    mock_payload = {
        "data": {
            "id": clean_ip,
            "type": "ip_address",
            "attributes": {
                "as_owner": "Google LLC",
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 5,
                    "harmless": 82,
                },
            },
        }
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = mock_payload

    with patch("httpx.get", return_value=mock_response):
        result = vt_provider.lookup(clean_ip, "ip")

        assert result is not None
        assert result.indicator == clean_ip
        assert result.indicator_type == "ip"
        assert result.is_malicious is False
        assert result.provider == "VirusTotal"


def test_virustotal_timeout_simulation(vt_provider):
    """Verify that HTTP timeouts return None gracefully without crashing."""
    with patch("httpx.get", side_effect=httpx.TimeoutException("Connection timed out")):
        result = vt_provider.lookup("198.51.100.1", "ip")
        assert result is None


def test_virustotal_rate_limit_429(vt_provider):
    """Verify that HTTP 429 rate limit responses return None gracefully."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 429

    with patch("httpx.get", return_value=mock_response):
        result = vt_provider.lookup("198.51.100.1", "ip")
        assert result is None


def test_virustotal_not_found_404(vt_provider):
    """Verify that HTTP 404 responses return None without exception."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 404

    with patch("httpx.get", return_value=mock_response):
        result = vt_provider.lookup("unknown-domain.xyz", "domain")
        assert result is None


def test_virustotal_missing_api_key():
    """Verify that provider returns None if no API key is provided."""
    with patch.dict("os.environ", {}, clear=True):
        provider = VirusTotalProvider(api_key=None)
        assert provider.lookup("8.8.8.8", "ip") is None


def test_enrichment_engine_caching(enrichment_engine):
    """Verify that duplicate lookups return cached results and only call API once."""
    test_ip = "1.1.1.1"
    mock_payload = {
        "data": {
            "id": test_ip,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "harmless": 80},
            },
        }
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = mock_payload

    with patch("httpx.get", return_value=mock_response) as mock_get:
        # First lookup -> should query provider
        res1 = enrichment_engine.lookup(test_ip, "ip", provider_name="virustotal")
        assert res1 is not None
        assert res1.indicator == test_ip
        assert mock_get.call_count == 1

        # Second lookup -> must hit cache, no additional HTTP call
        res2 = enrichment_engine.lookup(test_ip, "ip", provider_name="virustotal")
        assert res2 is not None
        assert res2 is res1  # Exact same cached instance
        assert mock_get.call_count == 1

        # Verify cache state
        assert len(enrichment_engine.cache) == 1


def test_enrichment_engine_enrich_indicators(enrichment_engine):
    """Verify batch indicator enrichment through the EnrichmentEngine."""
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 3, "harmless": 10},
            },
        }
    }
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = mock_payload

    with patch("httpx.get", return_value=mock_response):
        results = enrichment_engine.enrich_indicators(["1.1.1.1", "2.2.2.2"], indicator_type="ip")
        assert len(results) == 2
        assert all(r.is_malicious is True for r in results)

