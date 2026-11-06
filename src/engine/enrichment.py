"""Threat intelligence enrichment engine and provider integrations."""

from abc import ABC, abstractmethod
import base64
from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional
import httpx

from src.config import get_abuseipdb_api_key, get_virustotal_api_key
from src.models.enrichment import EnrichmentResult

logger = logging.getLogger(__name__)


class ThreatIntelProvider(ABC):
    """Abstract Base Class for threat intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the provider name."""
        pass

    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
        """Performs a threat intelligence lookup for an indicator.

        Args:
            indicator: The IP address, domain, file hash, or URL.
            indicator_type: The type of indicator ('ip', 'domain', 'hash', 'url').

        Returns:
            An EnrichmentResult if the lookup succeeded, or None if failed/timed out/rate-limited.
        """
        pass


class VirusTotalProvider(ThreatIntelProvider):
    """Threat intelligence provider implementing VirusTotal API v3."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 5.0):
        """Initializes the VirusTotal provider.

        Args:
            api_key: Optional VirusTotal API key. Defaults to VT_API_KEY environment variable.
            timeout: HTTP request timeout in seconds (default: 5.0).
        """
        self.api_key = api_key or get_virustotal_api_key()
        self.timeout = timeout
        self.base_url = "https://www.virustotal.com/api/v3"

    @property
    def name(self) -> str:
        """Returns the provider name."""
        return "VirusTotal"

    def _get_endpoint(self, indicator: str, indicator_type: str) -> Optional[str]:
        """Maps an indicator and type to the corresponding VirusTotal v3 endpoint URL."""
        clean_type = indicator_type.strip().lower()
        clean_indicator = indicator.strip()

        if clean_type in ("ip", "ip_address"):
            return f"{self.base_url}/ip_addresses/{clean_indicator}"
        elif clean_type == "domain":
            return f"{self.base_url}/domains/{clean_indicator}"
        elif clean_type in ("hash", "file", "sha256", "md5", "sha1"):
            return f"{self.base_url}/files/{clean_indicator}"
        elif clean_type == "url":
            # VT v3 URL identifier is URL-safe base64 without padding
            url_id = base64.urlsafe_b64encode(clean_indicator.encode()).decode().strip("=")
            return f"{self.base_url}/urls/{url_id}"
        else:
            logger.warning("Unsupported indicator type for VirusTotal: %s", indicator_type)
            return None

    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
        """Queries VirusTotal API v3 for threat reputation.

        Args:
            indicator: The IP, domain, hash, or URL.
            indicator_type: Type of the indicator ('ip', 'domain', 'hash', 'url').

        Returns:
            EnrichmentResult on success, or None on failure, timeout, or rate-limiting.
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured (VT_API_KEY). Skipping lookup.")
            return None

        url = self._get_endpoint(indicator, indicator_type)
        if not url:
            return None

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            response = httpx.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                try:
                    raw_json = response.json()
                except Exception as exc:
                    logger.error("VirusTotal returned non-JSON/corrupt body: %s", exc)
                    return None

                if not isinstance(raw_json, dict):
                    logger.error("VirusTotal returned invalid JSON payload")
                    return None

                data = raw_json.get("data")
                if not isinstance(data, dict):
                    logger.error("VirusTotal schema violation: missing 'data' dict object")
                    return None

                attributes = data.get("attributes", {})
                analysis_stats = attributes.get("last_analysis_stats", {})

                # Type-safe parsing of malicious detections
                malicious_raw = analysis_stats.get("malicious", 0)
                try:
                    malicious_detections = int(malicious_raw)
                except (TypeError, ValueError):
                    malicious_detections = 0

                is_malicious = bool(malicious_detections > 0)

                return EnrichmentResult(
                    indicator=indicator,
                    indicator_type=indicator_type.strip().lower(),
                    provider=self.name,
                    is_malicious=is_malicious,
                    raw_response=raw_json,
                    lookup_timestamp=datetime.now(timezone.utc),
                )

            elif response.status_code == 429:
                logger.warning(
                    "VirusTotal rate limit exceeded (HTTP 429) for indicator: %s", indicator
                )
                return None

            elif response.status_code == 404:
                logger.info(
                    "Indicator not found on VirusTotal (HTTP 404): %s", indicator
                )
                return None

            else:
                logger.warning(
                    "VirusTotal lookup failed with HTTP %d for indicator: %s",
                    response.status_code,
                    indicator,
                )
                return None

        except httpx.TimeoutException:
            logger.error(
                "VirusTotal API request timed out after %.1f seconds for indicator: %s",
                self.timeout,
                indicator,
            )
            return None
        except httpx.HTTPError as exc:
            logger.error(
                "VirusTotal HTTP request error for indicator %s: %s", indicator, exc
            )
            return None


class AbuseIPDBProvider(ThreatIntelProvider):
    """Threat intelligence provider implementing AbuseIPDB API v2."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 5.0):
        """Initializes the AbuseIPDB provider.

        Args:
            api_key: Optional AbuseIPDB API key. Defaults to ABUSEIPDB_API_KEY environment variable.
            timeout: HTTP request timeout in seconds (default: 5.0).
        """
        self.api_key = api_key or get_abuseipdb_api_key()
        self.timeout = timeout
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    @property
    def name(self) -> str:
        """Returns the provider name."""
        return "AbuseIPDB"

    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
        """Queries AbuseIPDB API v2 for IP reputation.

        Args:
            indicator: The IP address to check.
            indicator_type: Indicator type (must be 'ip' or 'ip_address').

        Returns:
            EnrichmentResult on success, or None on failure, timeout, or rate-limiting.
        """
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured (ABUSEIPDB_API_KEY). Skipping lookup.")
            return None

        clean_type = indicator_type.strip().lower()
        if clean_type not in ("ip", "ip_address"):
            logger.warning("AbuseIPDB only supports 'ip' indicator type, got: %s", indicator_type)
            return None

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": indicator.strip(),
            "maxAgeInDays": "90",
        }

        try:
            response = httpx.get(
                self.base_url, headers=headers, params=params, timeout=self.timeout
            )

            if response.status_code == 200:
                try:
                    raw_json = response.json()
                except Exception as exc:
                    logger.error("AbuseIPDB returned non-JSON/corrupt body: %s", exc)
                    return None

                if not isinstance(raw_json, dict):
                    logger.error("AbuseIPDB returned non-dict JSON")
                    return None

                data = raw_json.get("data")
                if not isinstance(data, dict):
                    logger.error("AbuseIPDB schema violation: missing 'data' dict object")
                    return None

                score_raw = data.get("abuseConfidenceScore")
                try:
                    score = int(score_raw)
                except (TypeError, ValueError):
                    logger.warning("AbuseIPDB non-numeric confidence score: %s", score_raw)
                    score = 0

                is_malicious = score > 0

                return EnrichmentResult(
                    indicator=indicator.strip(),
                    indicator_type="ip",
                    provider=self.name,
                    is_malicious=is_malicious,
                    raw_response=raw_json,
                    lookup_timestamp=datetime.now(timezone.utc),
                )

            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded (HTTP 429) for IP: %s", indicator)
                return None
            else:
                logger.warning(
                    "AbuseIPDB request failed with HTTP %d for IP: %s",
                    response.status_code,
                    indicator,
                )
                return None

        except httpx.TimeoutException:
            logger.error(
                "AbuseIPDB request timed out after %.1f seconds for IP: %s",
                self.timeout,
                indicator,
            )
            return None
        except httpx.HTTPError as exc:
            logger.error("AbuseIPDB HTTP error for IP %s: %s", indicator, exc)
            return None


class URLhausProvider(ThreatIntelProvider):
    """Threat intelligence provider implementing abuse.ch URLhaus API."""

    def __init__(self, timeout: float = 5.0):
        """Initializes the URLhaus provider.

        Args:
            timeout: HTTP request timeout in seconds (default: 5.0).
        """
        self.timeout = timeout
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    @property
    def name(self) -> str:
        """Returns the provider name."""
        return "URLhaus"

    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentResult]:
        """Queries URLhaus API for malicious URLs and domains.

        Args:
            indicator: The URL or domain name.
            indicator_type: Indicator type ('url' or 'domain').

        Returns:
            EnrichmentResult on success, or None on failure, timeout, or rate-limiting.
        """
        clean_type = indicator_type.strip().lower()
        clean_indicator = indicator.strip()

        if clean_type == "url":
            endpoint = f"{self.base_url}/url/"
            payload = {"url": clean_indicator}
        elif clean_type in ("domain", "host"):
            endpoint = f"{self.base_url}/host/"
            payload = {"host": clean_indicator}
        else:
            logger.warning(
                "URLhaus only supports 'url' and 'domain' indicator types, got: %s",
                indicator_type,
            )
            return None

        headers = {"Accept": "application/json"}

        try:
            response = httpx.post(
                endpoint, data=payload, headers=headers, timeout=self.timeout
            )

            if response.status_code == 200:
                try:
                    raw_json = response.json()
                except Exception as exc:
                    logger.error("URLhaus returned non-JSON/corrupt body: %s", exc)
                    return None

                if not isinstance(raw_json, dict):
                    logger.error("URLhaus returned non-dict JSON")
                    return None

                query_status = raw_json.get("query_status")
                if query_status != "ok":
                    logger.info(
                        "URLhaus query returned status '%s' for %s",
                        query_status,
                        clean_indicator,
                    )
                    return None

                is_malicious = False
                if clean_type == "url":
                    status = str(raw_json.get("url_status", "")).strip().lower()
                    if status in ("online", "offline"):
                        is_malicious = True
                else:  # domain / host
                    status = str(raw_json.get("host_status", "")).strip().lower()
                    urls_list = raw_json.get("urls")
                    if status in ("online", "offline") or (
                        isinstance(urls_list, list) and len(urls_list) > 0
                    ):
                        is_malicious = True

                return EnrichmentResult(
                    indicator=clean_indicator,
                    indicator_type="url" if clean_type == "url" else "domain",
                    provider=self.name,
                    is_malicious=is_malicious,
                    raw_response=raw_json,
                    lookup_timestamp=datetime.now(timezone.utc),
                )

            elif response.status_code == 429:
                logger.warning("URLhaus rate limit exceeded (HTTP 429) for %s", clean_indicator)
                return None
            else:
                logger.warning(
                    "URLhaus lookup failed with HTTP %d for %s",
                    response.status_code,
                    clean_indicator,
                )
                return None

        except httpx.TimeoutException:
            logger.error(
                "URLhaus request timed out after %.1f seconds for %s",
                self.timeout,
                clean_indicator,
            )
            return None
        except httpx.HTTPError as exc:
            logger.error("URLhaus HTTP error for %s: %s", clean_indicator, exc)
            return None


class EnrichmentEngine:
    """Orchestrates threat intelligence lookups across registered providers with in-memory caching."""

    def __init__(self, providers: Optional[Dict[str, ThreatIntelProvider]] = None):
        """Initializes the enrichment engine.

        Args:
            providers: Optional dictionary mapping provider names to provider instances.
        """
        self.providers: Dict[str, ThreatIntelProvider] = {}
        if providers:
            for p in providers.values():
                self.register_provider(p)
        else:
            # Register default providers
            self.register_provider(VirusTotalProvider())
            self.register_provider(AbuseIPDBProvider())
            self.register_provider(URLhausProvider())

        # In-memory cache: (provider, indicator_type, indicator) -> EnrichmentResult
        self.cache: Dict[str, EnrichmentResult] = {}

    def register_provider(self, provider: ThreatIntelProvider) -> None:
        """Registers a threat intelligence provider."""
        self.providers[provider.name.lower()] = provider

    def _get_cache_key(self, indicator: str, indicator_type: str, provider_name: str) -> str:
        """Constructs a normalized cache key."""
        return f"{provider_name.strip().lower()}:{indicator_type.strip().lower()}:{indicator.strip().lower()}"

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
        provider_name: str = "virustotal",
    ) -> Optional[EnrichmentResult]:
        """Looks up an indicator using the specified provider with in-memory caching.

        Args:
            indicator: The IP, domain, hash, or URL to lookup.
            indicator_type: Indicator classification ('ip', 'domain', 'hash', 'url').
            provider_name: Provider name to use (default: 'virustotal').

        Returns:
            EnrichmentResult if successful, or None if unavailable/failed.
        """
        cache_key = self._get_cache_key(indicator, indicator_type, provider_name)

        if cache_key in self.cache:
            logger.debug("Enrichment cache hit for %s", cache_key)
            return self.cache[cache_key]

        provider = self.providers.get(provider_name.lower())
        if not provider:
            logger.error("Threat intelligence provider '%s' is not registered", provider_name)
            return None

        result = provider.lookup(indicator, indicator_type)
        if result is not None:
            self.cache[cache_key] = result

        return result

    def enrich_indicators(
        self,
        indicators: List[str],
        indicator_type: str = "ip",
        provider_name: str = "virustotal",
    ) -> List[EnrichmentResult]:
        """Enriches a collection of indicators using the specified provider.

        Args:
            indicators: List of indicator strings.
            indicator_type: Default indicator type.
            provider_name: Threat intelligence provider to query.

        Returns:
            List of successful EnrichmentResult instances.
        """
        results: List[EnrichmentResult] = []
        for ind in indicators:
            res = self.lookup(ind, indicator_type, provider_name)
            if res:
                results.append(res)
        return results
