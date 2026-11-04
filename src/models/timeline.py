"""Data models for incident timelines and event correlation."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult


class ThreatTimeline(BaseModel):
    """Represents a chronologically correlated investigation timeline of security alerts.

    Attributes:
        timeline_id: Unique identifier for the timeline.
        grouping_key: Identifier or attribute by which alerts were correlated (e.g., host, dataset).
        alerts: Chronologically ordered list of NormalizedAlert instances.
        enrichment_data: Threat intelligence enrichment results associated with timeline indicators.
        start_time: Timestamp of the earliest event in the timeline, if available.
        end_time: Timestamp of the latest event in the timeline, if available.
        total_events: Total number of alerts correlated in this timeline.
    """

    timeline_id: UUID = Field(default_factory=uuid4)
    grouping_key: str
    alerts: List[NormalizedAlert] = Field(default_factory=list)
    enrichment_data: List[EnrichmentResult] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_events: int = 0

