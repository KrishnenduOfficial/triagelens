"""Normalized alert data model for TriageLens."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class NormalizedAlert(BaseModel):
    """Represents a normalized security alert across diverse ingestion sources.

    Attributes:
        internal_id: Unique identifier for the ingested alert.
        timestamp: Event occurrence timestamp, if available in the source record.
        source_dataset: Name of the originating security dataset.
        source_file: Source file path or name from which the alert was ingested.
        event_type: Classification or category of the security event.
        original_record: Raw unprocessed record preserved for provenance and auditing.
        extracted_indicators: Suspicious indicators identified in the event.
        ground_truth_label: Independent ground truth label, if present in the dataset.
    """

    internal_id: UUID = Field(default_factory=uuid4)
    timestamp: Optional[datetime] = None
    source_dataset: str
    source_file: str
    event_type: str
    original_record: Dict[str, Any]
    extracted_indicators: List[str] = Field(default_factory=list)
    ground_truth_label: Optional[str] = None

