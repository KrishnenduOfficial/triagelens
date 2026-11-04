"""Adversarial and extreme edge-case tests for the Alert Intake Engine."""

from datetime import datetime, timezone
import json
import math
from pathlib import Path
import pytest

from src.engine.intake import AlertIntakeEngine
from src.models.alert import NormalizedAlert


@pytest.fixture
def intake_engine():
    """Returns a fresh instance of AlertIntakeEngine."""
    return AlertIntakeEngine()


# ---------------------------------------------------------------------------
# 1. Timestamp Manipulation Gauntlet
# ---------------------------------------------------------------------------

def test_adversarial_timestamp_negative_epoch(intake_engine):
    """Negative epoch (pre-1970) and extreme negative timestamps."""
    # -1000 seconds before epoch -> 1969-12-31 23:43:20+00:00
    ts = intake_engine._normalize_timestamp(-1000)
    assert ts is not None
    assert ts.year == 1969

    # Extreme negative epoch that exceeds platform limits -> returns None, never crashes
    assert intake_engine._normalize_timestamp(-1e25) is None


def test_adversarial_timestamp_far_future(intake_engine):
    """Far-future dates and out-of-bounds years."""
    # Year 3000 ISO string
    ts_3000 = intake_engine._normalize_timestamp("3000-01-01T12:00:00Z")
    assert ts_3000 is not None
    assert ts_3000.year == 3000

    # Year 3000 Epoch seconds (approx. 32503680000)
    ts_3000_epoch = intake_engine._normalize_timestamp(32503680000)
    assert ts_3000_epoch is not None
    assert ts_3000_epoch.year == 3000

    # Impossible date (year 10000+) beyond Python's MAXYEAR 9999
    assert intake_engine._normalize_timestamp("10000-01-01T00:00:00Z") is None
    assert intake_engine._normalize_timestamp(1e25) is None


def test_adversarial_timestamp_excessive_precision(intake_engine):
    """Floating-point epoch with excessive sub-second precision."""
    ts = intake_engine._normalize_timestamp(1700000000.1234567890123456789)
    assert ts is not None
    assert ts.year == 2023


def test_adversarial_timestamp_corrupted_random_strings(intake_engine):
    """Corrupted, random non-date strings must return None without throwing exceptions."""
    corrupted_inputs = [
        "SELECT * FROM alerts WHERE 1=1;",
        "!@#$%^&*()_+=-`~[]\\{}|;':\",./<>?",
        "2026-99-99T99:99:99Z",
        "yesterday at 5pm",
        "\x00\x00\x00",
        " ",
    ]
    for bad_ts in corrupted_inputs:
        assert intake_engine._normalize_timestamp(bad_ts) is None


def test_adversarial_timestamp_nan_and_infinity(intake_engine):
    """NaN and positive/negative infinity values must return None gracefully."""
    nan_inputs = [float("nan"), float("inf"), float("-inf"), "NaN", "Infinity", "-Infinity"]
    for val in nan_inputs:
        assert intake_engine._normalize_timestamp(val) is None


# ---------------------------------------------------------------------------
# 2. Malformed JSON / CSV & Parser Exploits
# ---------------------------------------------------------------------------

def test_adversarial_json_null_bytes(intake_engine, tmp_path):
    """JSON with null bytes (\x00) injected into keys and values."""
    null_byte_record = [
        {
            "event_\x00_type": "Suspicious\x00Process",
            "source_\x00_dataset": "EVTX-\x00-DATASET",
            "indicators": ["198.51.100.1\x00", "evil-\x00-host.com"],
            "ground_\x00_truth_label": "malicious\x00",
        }
    ]
    file_path = tmp_path / "null_bytes.json"
    file_path.write_text(json.dumps(null_byte_record), encoding="utf-8")

    alerts = intake_engine.ingest_json(str(file_path))
    assert len(alerts) == 1
    assert "Suspicious" in alerts[0].event_type
    assert len(alerts[0].extracted_indicators) == 2


def test_adversarial_csv_unescaped_quotes(intake_engine, tmp_path):
    """CSV containing unescaped quotes inside data fields."""
    raw_csv = (
        "event_type,source_dataset,raw_message\n"
        'Suspicious,EVTX,Executing "powershell.exe -enc AAAA without closing quote\n'
        'Logon,EVTX,Executing cmd.exe /c "dir "c:\\test"" inside\n'
    )
    file_path = tmp_path / "unescaped_quotes.csv"
    file_path.write_text(raw_csv, encoding="utf-8")

    alerts = intake_engine.ingest_csv(str(file_path))
    assert len(alerts) == 2
    assert alerts[0].event_type == "Suspicious"
    assert alerts[1].event_type == "Logon"


def test_adversarial_csv_delimiter_injection(intake_engine, tmp_path):
    """CSV with embedded commas, semicolons, and newlines inside quoted fields."""
    raw_csv = (
        'event_type,source_dataset,indicators,raw_message\n'
        '"Process, Injection",EVTX,"10.0.0.1;10.0.0.2","Line 1, with commas\nLine 2, with newlines"\n'
    )
    file_path = tmp_path / "delimiter_injection.csv"
    file_path.write_text(raw_csv, encoding="utf-8")

    alerts = intake_engine.ingest_csv(str(file_path))
    assert len(alerts) == 1
    assert alerts[0].event_type == "Process, Injection"
    assert "Line 1, with commas" in alerts[0].original_record["raw_message"]
    assert "10.0.0.1" in alerts[0].extracted_indicators
    assert "10.0.0.2" in alerts[0].extracted_indicators


def test_adversarial_json_deeply_nested(intake_engine, tmp_path):
    """Deeply nested JSON structure preserved in original_record without parser stack overflow."""
    nested = {"leaf": "deep_payload", "value": 999}
    for i in range(50):
        nested = {f"level_{i}": nested}

    deep_record = [
        {
            "event_type": "Deep Nesting Attack",
            "source_dataset": "EVTX-STRESS",
            "nested_data": nested,
        }
    ]
    file_path = tmp_path / "deep_nested.json"
    file_path.write_text(json.dumps(deep_record), encoding="utf-8")

    alerts = intake_engine.ingest_json(str(file_path))
    assert len(alerts) == 1
    assert alerts[0].event_type == "Deep Nesting Attack"
    assert "nested_data" in alerts[0].original_record


# ---------------------------------------------------------------------------
# 3. Type Confusion Gauntlet
# ---------------------------------------------------------------------------

def test_adversarial_type_confusion_indicators_as_int_float(intake_engine):
    """Passing integer or float where a list of indicator strings is expected."""
    # Integer as indicator
    record_int = {"indicators": 12345}
    norm_int = intake_engine._normalize_fields(record_int)
    assert norm_int["indicators"] == ["12345"]

    # Float as indicator
    record_float = {"iocs": 8080.0}
    norm_float = intake_engine._normalize_fields(record_float)
    assert norm_float["indicators"] == ["8080.0"]


def test_adversarial_type_confusion_booleans_for_strings(intake_engine):
    """Passing booleans for string fields like event_type, source_dataset, and ground_truth_label."""
    record = {
        "event_type": True,
        "source_dataset": False,
        "ground_truth_label": True,
        "indicators": True,  # Boolean indicators should be discarded
    }
    norm = intake_engine._normalize_fields(record)
    assert norm["event_type"] == "True"
    assert norm["source_dataset"] == "False"
    assert norm["ground_truth_label"] == "True"
    assert norm["indicators"] == []


def test_adversarial_type_confusion_mixed_indicators(intake_engine):
    """Passing a list containing mixed types: dicts, None, booleans, and valid strings."""
    record = {
        "indicators": [
            "192.168.1.1",
            None,
            True,
            False,
            {"unexpected": "object"},
            ["nested", "list"],
            "10.0.0.5",
            "",
            "   ",
            "null",
        ]
    }
    norm = intake_engine._normalize_fields(record)
    # Only valid non-empty indicator strings should be retained
    assert norm["indicators"] == ["192.168.1.1", "10.0.0.5"]


def test_adversarial_field_mapping_task_and_variations(intake_engine):
    """Mapping 'Task', 'task', 'EventID', 'id' to event_type."""
    # Using 'Task'
    assert intake_engine._normalize_fields({"Task": "Process Start"})["event_type"] == "Process Start"
    # Using 'task'
    assert intake_engine._normalize_fields({"task": "Network Connect"})["event_type"] == "Network Connect"
    # Using 'EventID'
    assert intake_engine._normalize_fields({"EventID": 4688})["event_type"] == "4688"
    # Using 'id'
    assert intake_engine._normalize_fields({"id": "SYS-001"})["event_type"] == "SYS-001"


# ---------------------------------------------------------------------------
# 4. Pathological Batching
# ---------------------------------------------------------------------------

def test_adversarial_batching_1000_empty_files(intake_engine, tmp_path):
    """Directory containing 1,000 empty JSON and CSV files and 1 valid file."""
    # Create 500 empty JSON and 500 empty CSV files
    for i in range(500):
        (tmp_path / f"empty_{i}.json").touch()
        (tmp_path / f"empty_{i}.csv").touch()

    # Create 1 valid file
    valid_file = tmp_path / "valid_alert.json"
    valid_file.write_text(
        json.dumps([{"event_type": "Survivor Alert", "source_dataset": "StressTest"}]),
        encoding="utf-8",
    )

    batches = list(intake_engine.ingest_directory(tmp_path, batch_size=10))
    all_alerts = [alert for b in batches for alert in b]

    # Exactly 1 survivor alert yielded, 1000 empty files skipped without halting or crashing
    assert len(all_alerts) == 1
    assert all_alerts[0].event_type == "Survivor Alert"


def test_adversarial_batching_unrecognized_extensions_and_dirs(intake_engine, tmp_path):
    """Directory with unsupported extensions (.txt, .exe, .evtx) and subdirectories."""
    # Create subdirectories and unsupported files
    (tmp_path / "subdir").mkdir()
    (tmp_path / "notes.txt").write_text("Not an alert", encoding="utf-8")
    (tmp_path / "binary.exe").write_bytes(b"\x4d\x5a\x90\x00")
    (tmp_path / "security.evtx").write_bytes(b"ElfFile\x00")

    # Valid alert
    (tmp_path / "alert.json").write_text(
        json.dumps([{"event_type": "Valid Extension Alert", "source_dataset": "Test"}]),
        encoding="utf-8",
    )

    batches = list(intake_engine.ingest_directory(tmp_path, batch_size=5))
    all_alerts = [alert for b in batches for alert in b]

    assert len(all_alerts) == 1
    assert all_alerts[0].event_type == "Valid Extension Alert"


# ---------------------------------------------------------------------------
# 5. Weird Encodings & Multilingual Unicode
# ---------------------------------------------------------------------------

def test_adversarial_encoding_utf16_json(intake_engine, tmp_path):
    """JSON alert file encoded in UTF-16 with BOM."""
    alert_data = [{"event_type": "UTF16 Event", "source_dataset": "EVTX-UTF16"}]
    file_path = tmp_path / "utf16_alert.json"
    file_path.write_bytes(json.dumps(alert_data).encode("utf-16"))

    alerts = intake_engine.ingest_json(str(file_path))
    assert len(alerts) == 1
    assert alerts[0].event_type == "UTF16 Event"


def test_adversarial_encoding_utf8_bom_csv(intake_engine, tmp_path):
    """CSV alert file with UTF-8 BOM (\xef\xbb\xbf)."""
    csv_text = "timestamp,event_type,source_dataset\n2026-11-05T01:00:00Z,BOM Alert,EVTX\n"
    file_path = tmp_path / "utf8_bom.csv"
    file_path.write_bytes(csv_text.encode("utf-8-sig"))

    alerts = intake_engine.ingest_csv(str(file_path))
    assert len(alerts) == 1
    assert alerts[0].event_type == "BOM Alert"
    assert alerts[0].timestamp is not None


def test_adversarial_unicode_and_emojis(intake_engine, tmp_path):
    """Unicode emojis, non-Latin scripts (Cyrillic, Arabic, CJK) in events and indicators."""
    alert_record = [
        {
            "event_type": "🚨 Phishing Email 🎣",
            "source_dataset": "🛡️ SOC-DATASET 🛡️",
            "indicators": [
                "evil-domain-💀.com",
                "русский-домен.рф",
                "شركة-خبيثة.com",
                "恶意软件.cn",
            ],
            "ground_truth_label": "☠️ MALICIOUS ☠️",
        }
    ]
    file_path = tmp_path / "unicode_alert.json"
    file_path.write_text(json.dumps(alert_record, ensure_ascii=False), encoding="utf-8")

    alerts = intake_engine.ingest_json(str(file_path))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.event_type == "🚨 Phishing Email 🎣"
    assert "evil-domain-💀.com" in alert.extracted_indicators
    assert "русский-домен.рф" in alert.extracted_indicators
    assert "شركة-خبيثة.com" in alert.extracted_indicators
    assert "恶意软件.cn" in alert.extracted_indicators
    assert alert.ground_truth_label == "☠️ MALICIOUS ☠️"

