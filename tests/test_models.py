"""Tests for data models."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
from pydantic import ValidationError

from src.models.alert import NormalizedAlert


def test_normalized_alert_defaults():
    """Verify that default values and auto-generated fields work properly."""
    raw_event = {"EventID": 4688, "CommandLine": "powershell.exe -enc ..."}
    alert = NormalizedAlert(
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="process_creation.json",
        event_type="Process Creation",
        original_record=raw_event,
    )

    assert isinstance(alert.internal_id, UUID)
    assert alert.timestamp is None
    assert alert.source_dataset == "EVTX-ATTACK-SAMPLES"
    assert alert.source_file == "process_creation.json"
    assert alert.event_type == "Process Creation"
    assert alert.original_record == raw_event
    assert alert.extracted_indicators == []
    assert alert.ground_truth_label is None


def test_normalized_alert_explicit_values():
    """Verify that explicit values are correctly stored."""
    custom_id = uuid4()
    event_time = datetime(2026, 11, 5, 1, 0, 0, tzinfo=timezone.utc)
    raw_event = {"EventID": 4624, "TargetUserName": "admin"}
    indicators = ["192.168.1.100", "evil.corp"]

    alert = NormalizedAlert(
        internal_id=custom_id,
        timestamp=event_time,
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="logon_events.json",
        event_type="Logon",
        original_record=raw_event,
        extracted_indicators=indicators,
        ground_truth_label="malicious",
    )

    assert alert.internal_id == custom_id
    assert alert.timestamp == event_time
    assert alert.extracted_indicators == ["192.168.1.100", "evil.corp"]
    assert alert.ground_truth_label == "malicious"


def test_normalized_alert_missing_required_fields():
    """Verify validation error when required fields are missing."""
    with pytest.raises(ValidationError):
        NormalizedAlert(source_dataset="EVTX-ATTACK-SAMPLES")

