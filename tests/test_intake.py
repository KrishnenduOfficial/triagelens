"""Tests for alert intake engine."""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from src.engine.intake import AlertIntakeEngine
from src.models.alert import NormalizedAlert


def test_ingest_dummy_alerts_success():
    """Verify that ingest_json successfully parses data/dummy_alerts.json."""
    engine = AlertIntakeEngine()
    dummy_path = Path("data/dummy_alerts.json")

    alerts = engine.ingest_json(str(dummy_path))

    assert len(alerts) == 2
    assert all(isinstance(a, NormalizedAlert) for a in alerts)

    # First alert verification (Sysmon Process Creation)
    alert1 = alerts[0]
    assert alert1.event_type == "Sysmon Process Creation"
    assert alert1.source_dataset == "EVTX-ATTACK-SAMPLES"
    assert alert1.source_file == str(dummy_path)
    assert alert1.timestamp is not None
    assert alert1.timestamp.year == 2026
    assert alert1.ground_truth_label == "malicious"
    assert "198.51.100.45" in alert1.extracted_indicators
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in alert1.extracted_indicators
    assert alert1.original_record["mitre_technique"] == "T1059.001"
    assert alert1.original_record["process_name"] == "powershell.exe"

    # Second alert verification (Suspicious Logon)
    alert2 = alerts[1]
    assert alert2.event_type == "Suspicious Logon"
    assert alert2.source_dataset == "EVTX-ATTACK-SAMPLES"
    assert alert2.ground_truth_label == "suspicious"
    assert alert2.extracted_indicators == ["203.0.113.88"]
    assert alert2.original_record["mitre_technique"] == "T1078.003"
    assert alert2.original_record["user"] == "Administrator"

    # Ensure internal IDs are distinct
    assert alert1.internal_id != alert2.internal_id


def test_ingest_file_not_found():
    """Verify that a non-existent file path raises FileNotFoundError."""
    engine = AlertIntakeEngine()
    with pytest.raises(FileNotFoundError):
        engine.ingest_json("data/does_not_exist.json")


def test_ingest_malformed_json(tmp_path):
    """Verify that malformed JSON raises ValueError."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ unclosed json: ", encoding="utf-8")

    engine = AlertIntakeEngine()
    with pytest.raises(ValueError, match="Malformed JSON"):
        engine.ingest_json(str(bad_file))


def test_ingest_invalid_structure(tmp_path):
    """Verify that invalid top-level or item structure raises ValueError."""
    invalid_root = tmp_path / "invalid_root.json"
    invalid_root.write_text("12345", encoding="utf-8")

    engine = AlertIntakeEngine()
    with pytest.raises(ValueError, match="expected dict or list"):
        engine.ingest_json(str(invalid_root))

    invalid_items = tmp_path / "invalid_items.json"
    invalid_items.write_text('["not a dict"]', encoding="utf-8")
    with pytest.raises(ValueError, match="is not a JSON object"):
        engine.ingest_json(str(invalid_items))


def test_ingest_single_dict_json(tmp_path):
    """Verify that a JSON file with a single top-level dict is ingested as one alert."""
    single_alert = {
        "dataset_source": "EVTX-ATTACK-SAMPLES",
        "event_type": "Test Event",
        "indicators": ["10.0.0.1"],
    }
    single_file = tmp_path / "single.json"
    single_file.write_text(json.dumps(single_alert), encoding="utf-8")

    engine = AlertIntakeEngine()
    alerts = engine.ingest_json(str(single_file))

    assert len(alerts) == 1
    assert alerts[0].event_type == "Test Event"
    assert alerts[0].source_dataset == "EVTX-ATTACK-SAMPLES"
    assert alerts[0].extracted_indicators == ["10.0.0.1"]


def test_ingest_dummy_alerts_csv_success():
    """Verify that ingest_csv successfully parses data/dummy_alerts.csv."""
    engine = AlertIntakeEngine()
    dummy_csv_path = Path("data/dummy_alerts.csv")

    alerts = engine.ingest_csv(str(dummy_csv_path))

    assert len(alerts) == 2
    assert all(isinstance(a, NormalizedAlert) for a in alerts)

    # First alert verification (Network Connection)
    alert1 = alerts[0]
    assert alert1.event_type == "Network Connection"
    assert alert1.source_dataset == "EVTX-ATTACK-SAMPLES"
    assert alert1.source_file == str(dummy_csv_path)
    assert alert1.timestamp is not None
    assert alert1.timestamp.year == 2026
    assert alert1.ground_truth_label == "malicious"
    assert alert1.extracted_indicators == ["198.51.100.77", "evil-c2.com"]
    assert alert1.original_record["raw_message"] == "Outbound connection to known C2 server"

    # Second alert verification (Privilege Escalation)
    alert2 = alerts[1]
    assert alert2.event_type == "Privilege Escalation"
    assert alert2.source_dataset == "EVTX-ATTACK-SAMPLES"
    assert alert2.ground_truth_label == "suspicious"
    assert alert2.extracted_indicators == ["10.0.1.50"]
    assert alert2.original_record["raw_message"] == "User escalated to SYSTEM via suspicious service creation"

    assert alert1.internal_id != alert2.internal_id


def test_ingest_csv_file_not_found():
    """Verify that a non-existent CSV path raises FileNotFoundError."""
    engine = AlertIntakeEngine()
    with pytest.raises(FileNotFoundError):
        engine.ingest_csv("data/missing_alerts.csv")


def test_ingest_csv_empty_header(tmp_path):
    """Verify that an empty CSV file raises ValueError."""
    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("", encoding="utf-8")

    engine = AlertIntakeEngine()
    with pytest.raises(ValueError, match="Empty or headerless CSV"):
        engine.ingest_csv(str(empty_csv))


def test_normalize_timestamp():
    """Verify timestamp normalization for ISO 8601 strings and UNIX epochs."""
    engine = AlertIntakeEngine()

    # ISO 8601 string with Z
    ts_iso = engine._normalize_timestamp("2026-11-05T01:30:00Z")
    assert isinstance(ts_iso, datetime)
    assert ts_iso.year == 2026
    assert ts_iso.hour == 1

    # UNIX epoch integer
    ts_epoch_int = engine._normalize_timestamp(1700000000)
    assert isinstance(ts_epoch_int, datetime)
    assert ts_epoch_int.year == 2023

    # UNIX epoch float
    ts_epoch_float = engine._normalize_timestamp(1700000000.5)
    assert isinstance(ts_epoch_float, datetime)

    # UNIX epoch numeric string
    ts_epoch_str = engine._normalize_timestamp("1700000000")
    assert isinstance(ts_epoch_str, datetime)
    assert ts_epoch_str.year == 2023

    # UNIX epoch millisecond integer
    ts_epoch_ms = engine._normalize_timestamp(1700000000000)
    assert isinstance(ts_epoch_ms, datetime)
    assert ts_epoch_ms.year == 2023

    # Invalid / None handling
    assert engine._normalize_timestamp(None) is None
    assert engine._normalize_timestamp("") is None
    assert engine._normalize_timestamp("invalid-date-format") is None


def test_normalize_fields():
    """Verify field normalization maps common variations to expected canonical keys."""
    engine = AlertIntakeEngine()

    # Raw record with non-standard key names
    weird_record = {
        "EventID": 4688,
        "dataset": "EVTX-CUSTOM",
        "ts": "2026-11-05T12:00:00Z",
        "iocs": ["198.51.100.1", "198.51.100.2"],
        "verdict": "malicious",
    }

    norm = engine._normalize_fields(weird_record)
    assert norm["event_type"] == "4688"
    assert norm["source_dataset"] == "EVTX-CUSTOM"
    assert isinstance(norm["timestamp"], datetime)
    assert norm["indicators"] == ["198.51.100.1", "198.51.100.2"]
    assert norm["ground_truth_label"] == "malicious"

    # Pipe-delimited string indicator normalization
    delim_record = {
        "event_name": "Network Flow",
        "source": "Zeek",
        "ips": "10.0.0.1 | 10.0.0.2",
        "classification": "benign",
    }
    norm_delim = engine._normalize_fields(delim_record)
    assert norm_delim["event_type"] == "Network Flow"
    assert norm_delim["source_dataset"] == "Zeek"
    assert norm_delim["indicators"] == ["10.0.0.1", "10.0.0.2"]
    assert norm_delim["ground_truth_label"] == "benign"


def test_batch_directory_processing(tmp_path):
    """Verify that ingest_directory processes JSON and CSV files in batches."""
    engine = AlertIntakeEngine()

    # Create 2 JSON files and 1 CSV file (total 5 alerts)
    file1 = tmp_path / "alerts1.json"
    file1.write_text(
        json.dumps([
            {"event_type": "Alert 1", "source_dataset": "Test"},
            {"event_type": "Alert 2", "source_dataset": "Test"},
        ]),
        encoding="utf-8",
    )

    file2 = tmp_path / "alerts2.json"
    file2.write_text(
        json.dumps([
            {"event_type": "Alert 3", "source_dataset": "Test"},
        ]),
        encoding="utf-8",
    )

    file3 = tmp_path / "alerts3.csv"
    file3.write_text(
        "event_type,source_dataset\nAlert 4,Test\nAlert 5,Test\n",
        encoding="utf-8",
    )

    # Ingest in batches of 2
    batches = list(engine.ingest_directory(tmp_path, batch_size=2))

    assert len(batches) == 3
    assert len(batches[0]) == 2
    assert len(batches[1]) == 2
    assert len(batches[2]) == 1

    all_alerts = [alert for batch in batches for alert in batch]
    assert len(all_alerts) == 5
    assert [a.event_type for a in all_alerts] == [
        "Alert 1", "Alert 2", "Alert 3", "Alert 4", "Alert 5"
    ]

    # Non-existent directory raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        list(engine.ingest_directory(tmp_path / "non_existent"))

    # File path passed instead of directory raises NotADirectoryError
    with pytest.raises(NotADirectoryError):
        list(engine.ingest_directory(file1))

    # Invalid batch size raises ValueError
    with pytest.raises(ValueError):
        list(engine.ingest_directory(tmp_path, batch_size=0))


def test_missing_fields_handling(tmp_path):
    """Verify that missing fields do not crash the engine and use proper defaults."""
    engine = AlertIntakeEngine()

    # Minimal record with missing timestamp, indicators, labels, and event type
    empty_alert_file = tmp_path / "minimal.json"
    empty_alert_file.write_text(json.dumps([{}]), encoding="utf-8")

    alerts = engine.ingest_json(str(empty_alert_file))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.event_type == "Unknown"
    assert alert.source_dataset == "Unknown"
    assert alert.timestamp is None
    assert alert.extracted_indicators == []
    assert alert.ground_truth_label is None
    assert alert.original_record == {}
    assert alert.source_file == str(empty_alert_file)
