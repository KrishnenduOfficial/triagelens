"""Adversarial resilience tests for threat intelligence providers against WAF blocks, data corruption, and schema violations."""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from src.engine.enrichment import AbuseIPDBProvider, URLhausProvider, VirusTotalProvider


@pytest.fixture
def vt():
    return VirusTotalProvider(api_key="test_key_vt")


@pytest.fixture
def abuseipdb():
    return AbuseIPDBProvider(api_key="test_key_abuse")


@pytest.fixture
def urlhaus():
    return URLhausProvider()


# ---------------------------------------------------------------------------
# 1. WAF Interference (HTTP 200 with HTML bodies)
# ---------------------------------------------------------------------------

def test_vt_waf_html_interference(vt):
    """VirusTotal returns HTTP 200 with Cloudflare/WAF HTML instead of JSON."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")

    with patch("httpx.get", return_value=mock_resp):
        assert vt.lookup("44d88612fea8a8f36de82e1278abb02f", "hash") is None


def test_abuseipdb_waf_html_interference(abuseipdb):
    """AbuseIPDB returns HTTP 200 with captive portal or HTML block page."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1")

    with patch("httpx.get", return_value=mock_resp):
        assert abuseipdb.lookup("198.51.100.1", "ip") is None


def test_urlhaus_waf_html_interference(urlhaus):
    """URLhaus returns HTTP 200 with gateway HTML error."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1")

    with patch("httpx.post", return_value=mock_resp):
        assert urlhaus.lookup("http://evil.com/payload.exe", "url") is None


# ---------------------------------------------------------------------------
# 2. Data Corruption (Truncated or Invalid JSON payloads)
# ---------------------------------------------------------------------------

def test_vt_corrupted_truncated_json(vt):
    """VirusTotal stream cuts off mid-transmission."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Unterminated string starting at line 1")

    with patch("httpx.get", return_value=mock_resp):
        assert vt.lookup("8.8.8.8", "ip") is None


def test_abuseipdb_corrupted_truncated_json(abuseipdb):
    """AbuseIPDB stream cuts off mid-transmission."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Unexpected end of JSON")

    with patch("httpx.get", return_value=mock_resp):
        assert abuseipdb.lookup("1.1.1.1", "ip") is None


def test_urlhaus_corrupted_truncated_json(urlhaus):
    """URLhaus stream cuts off mid-transmission."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Malformed JSON")

    with patch("httpx.post", return_value=mock_resp):
        assert urlhaus.lookup("evil.com", "domain") is None


# ---------------------------------------------------------------------------
# 3. Schema Violations (Missing required keys)
# ---------------------------------------------------------------------------

def test_vt_schema_violation_missing_data(vt):
    """VirusTotal returns JSON lacking the 'data' root object."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"error": "unexpected format"}

    with patch("httpx.get", return_value=mock_resp):
        assert vt.lookup("8.8.8.8", "ip") is None


def test_abuseipdb_schema_violation_missing_data(abuseipdb):
    """AbuseIPDB returns JSON lacking the 'data' object."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok"}

    with patch("httpx.get", return_value=mock_resp):
        assert abuseipdb.lookup("1.1.1.1", "ip") is None


def test_urlhaus_schema_violation_missing_query_status(urlhaus):
    """URLhaus returns JSON lacking the 'query_status' field."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"random_key": "val"}

    with patch("httpx.post", return_value=mock_resp):
        assert urlhaus.lookup("http://test.com", "url") is None


# ---------------------------------------------------------------------------
# 4. Type Confusion Handling
# ---------------------------------------------------------------------------

def test_abuseipdb_type_confusion_confidence_string(abuseipdb):
    """AbuseIPDB returns confidence score as a numeric string ('85')."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "198.51.100.2",
            "abuseConfidenceScore": "85",
        }
    }

    with patch("httpx.get", return_value=mock_resp):
        res = abuseipdb.lookup("198.51.100.2", "ip")
        assert res is not None
        assert res.is_malicious is True


def test_abuseipdb_type_confusion_non_numeric_confidence_string(abuseipdb):
    """AbuseIPDB returns confidence score as text string ('VERY_HIGH')."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "198.51.100.2",
            "abuseConfidenceScore": "VERY_HIGH",
        }
    }

    with patch("httpx.get", return_value=mock_resp):
        res = abuseipdb.lookup("198.51.100.2", "ip")
        assert res is not None
        assert res.is_malicious is False  # Defaults safely to 0 score


def test_vt_type_confusion_malicious_count_as_string(vt):
    """VirusTotal returns detection stats as a string instead of int."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": "15"},
            }
        }
    }

    with patch("httpx.get", return_value=mock_resp):
        res = vt.lookup("test_hash", "hash")
        assert res is not None
        assert res.is_malicious is True


# ---------------------------------------------------------------------------
# 5. Network Failures & Status Codes
# ---------------------------------------------------------------------------

def test_vt_500_server_error(vt):
    """VirusTotal returns HTTP 500."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 500

    with patch("httpx.get", return_value=mock_resp):
        assert vt.lookup("8.8.8.8", "ip") is None


def test_vt_502_bad_gateway(vt):
    """VirusTotal returns HTTP 502."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 502

    with patch("httpx.get", return_value=mock_resp):
        assert vt.lookup("8.8.8.8", "ip") is None


def test_abuseipdb_503_service_unavailable(abuseipdb):
    """AbuseIPDB returns HTTP 503."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 503

    with patch("httpx.get", return_value=mock_resp):
        assert abuseipdb.lookup("198.51.100.1", "ip") is None


def test_abuseipdb_rate_limit_429(abuseipdb):
    """AbuseIPDB returns HTTP 429 rate limit exceeded."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 429

    with patch("httpx.get", return_value=mock_resp):
        assert abuseipdb.lookup("198.51.100.1", "ip") is None


def test_urlhaus_timeout(urlhaus):
    """URLhaus request times out."""
    with patch("httpx.post", side_effect=httpx.TimeoutException("Read timed out")):
        assert urlhaus.lookup("http://evil.com", "url") is None


def test_urlhaus_500_error(urlhaus):
    """URLhaus returns HTTP 500."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 500

    with patch("httpx.post", return_value=mock_resp):
        assert urlhaus.lookup("http://evil.com", "url") is None


def test_urlhaus_successful_url_lookup(urlhaus):
    """URLhaus successfully verifies an online malicious URL."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
    }

    with patch("httpx.post", return_value=mock_resp):
        res = urlhaus.lookup("http://evil.com/trojan.exe", "url")
        assert res is not None
        assert res.is_malicious is True
        assert res.indicator == "http://evil.com/trojan.exe"
        assert res.provider == "URLhaus"


def test_urlhaus_successful_domain_lookup(urlhaus):
    """URLhaus successfully verifies an infected domain with payload URLs."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "host_status": "online",
        "urls": [{"url": "http://c2-domain.com/gate.php"}],
    }

    with patch("httpx.post", return_value=mock_resp):
        res = urlhaus.lookup("c2-domain.com", "domain")
        assert res is not None
        assert res.is_malicious is True
        assert res.indicator == "c2-domain.com"
        assert res.indicator_type == "domain"

