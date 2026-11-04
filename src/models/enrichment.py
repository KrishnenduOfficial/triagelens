"""Data models for threat intelligence enrichment."""

from datetime import datetime, timezone
from typing import Any, Dict
from pydantic import BaseModel, Field


class EnrichmentResult(BaseModel):
    """Represents the threat intelligence lookup result for an indicator.

    Attributes:
        indicator: The indicator string (IP, domain, hash, or URL).
        indicator_type: The classified type of the indicator ('ip', 'domain', 'hash', 'url').
        provider: Name of the threat intelligence provider (e.g., 'VirusTotal').
        is_malicious: Boolean flag indicating if the indicator is classified as malicious.
        raw_response: Raw API response dictionary from the intelligence provider.
        lookup_timestamp: Time when the enrichment lookup occurred.
    """

    indicator: str
    indicator_type: str
    provider: str
    is_malicious: bool
    raw_response: Dict[str, Any]
    lookup_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

