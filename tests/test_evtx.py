"""Offline synthetic EVTX files and synthetic native-parser output fixtures."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
import struct
import tracemalloc
from xml.sax.saxutils import escape
import zlib

import httpx
import pytest

from conftest import PipelineTestEngine
from src.engine.evtx import EvtxIntakeEngine
from src.engine.intake import AlertIntakeEngine
from src.models.timeline import ThreatTimeline


def record(*, timestamp="2026-01-02T03:04:05.1234567Z", channel="Security", data=None):
    """Synthetic XML in the public PyEvtxParser.records() envelope format."""
    data = data if data is not None else '<Data Name="TargetUserName">analyst</Data><Data Name="ProcessId">42</Data>'
    time = f'<TimeCreated SystemTime="{escape(timestamp)}"/>' if timestamp is not None else ""
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID Qualifiers="0">4624</EventID>' + time +
        f'<Channel>{escape(channel)}</Channel><Computer>fixture-host</Computer>'
        '<Security UserID="S-1-5-18"/></System><EventData>' + data + '</EventData></Event>'
    )
    return {"event_record_id": 1, "timestamp": "2026-01-02 03:04:05 UTC", "data": xml, "recovered": False}


class ResumableRecords:
    def __init__(self, values):
        self.values = iter(values)

    def __iter__(self):
        return self

    def __next__(self):
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value


class Parser:
    def __init__(self, values):
        self.values = values

    def records(self):
        return ResumableRecords(self.values)


def adapter(tmp_path, values):
    path = tmp_path / "dataset-path-canary.evtx"
    path.touch()
    return EvtxIntakeEngine(lambda stream: Parser(values)), path


def empty_evtx():
    """Minimal synthetic EVTX header; no host records or dataset content."""
    header = bytearray(4096)
    header[:8] = b"ElfFile\0"
    struct.pack_into("<QQQIHHHH", header, 8, 0, 0, 1, 128, 1, 3, 4096, 0)
    struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
    return bytes(header)


def synthetic_chunk(record_id=1):
    """One synthetic Event encoded as direct BinXML, without templates.

    Layout: chunk header/string table, record header, fragment/element/value
    tokens, trailing record size. All fields are invented and CRC32s are valid.
    Direct element starts omit the template-only dependency identifier.
    """
    tokens = bytearray(b"\x0f\x01\x01\x00")
    name_offsets = []

    def start(name):
        offset = 512 + 24 + len(tokens) + 9
        tokens.extend(b"\x01" + struct.pack("<II", 0, offset))
        name_offsets.append(offset)
        tokens.extend(struct.pack("<IHH", 0, 0, len(name)))
        tokens.extend(name.encode("utf-16le") + b"\x00\x00\x02")

    def leaf(name, value):
        start(name)
        tokens.extend(b"\x05\x01" + struct.pack("<H", len(value)))
        tokens.extend(value.encode("utf-16le") + b"\x04")

    start("Event")
    start("System")
    leaf("EventID", "4624")
    leaf("Channel", "Synthetic/Channel")
    leaf("Computer", "fixture-host")
    tokens.extend(b"\x04")
    start("EventData")
    leaf("TargetUserName", "analyst")
    leaf("ProcessId", "42")
    tokens.extend(b"\x04\x04\x00")
    size = 24 + len(tokens) + 4
    padding = -size % 8
    size += padding
    record_bytes = (b"\x2a\x2a\x00\x00" + struct.pack("<IQQ", size, record_id, 134119694450000000)
                    + tokens + bytes(padding) + struct.pack("<I", size))
    chunk = bytearray(65536)
    chunk[:8] = b"ElfChnk\x00"
    struct.pack_into("<QQQQIIII", chunk, 8, record_id, record_id, record_id, record_id,
                     128, 512, 512 + len(record_bytes), 0)
    chunk[512:512 + len(record_bytes)] = record_bytes
    struct.pack_into("<I", chunk, 128, name_offsets[0])
    for current, following in zip(name_offsets, name_offsets[1:]):
        struct.pack_into("<I", chunk, current, following)
    struct.pack_into("<I", chunk, 52, zlib.crc32(chunk[512:512 + len(record_bytes)]))
    struct.pack_into("<I", chunk, 124, zlib.crc32(chunk[:120] + chunk[128:512]))
    return bytes(chunk)


def evtx_header(chunk_count):
    header = bytearray(empty_evtx())
    struct.pack_into("<Q", header, 16, max(0, chunk_count - 1))
    struct.pack_into("<Q", header, 24, chunk_count + 1)
    struct.pack_into("<H", header, 42, chunk_count)
    struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
    return header


def test_normalizes_fields_and_preserves_local_provenance(tmp_path):
    source = record()
    engine, path = adapter(tmp_path, [source])
    alert = next(engine.ingest_evtx(path))[0]
    assert alert.timestamp == datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)
    assert alert.event_type == "4624"
    assert alert.original_record["EventID"] == 4624
    assert alert.original_record["Channel"] == "Security"
    assert alert.original_record["ComputerName"] == "fixture-host"
    assert alert.original_record["User"] == "analyst"
    assert alert.original_record["Details"] == {"EventData.TargetUserName": "analyst", "EventData.ProcessId": "42"}
    assert alert.original_record["raw_xml"] == source["data"]
    assert alert.source_file == str(path)
    assert alert.source_dataset == "Windows EVTX"
    assert alert.ground_truth_label is None
    assert str(path) not in json.dumps(alert.original_record)
    assert asdict(engine.stats) == dict(files_seen=1, files_failed=0, records_seen=1, alerts_emitted=1,
                                      parser_errors=0, normalization_errors=0,
                                      missing_timestamps=0, invalid_timestamps=0)


@pytest.mark.parametrize("timestamp,expected,missing,invalid", [
    ("2026-01-02T05:34:05+02:30", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc), 0, 0),
    ("2026-01-02T03:04:05", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc), 0, 0),
    (None, None, 1, 0), ("not-a-time", None, 0, 1),
    ("0001-01-01T00:00:00+01:00", None, 0, 1),
])
def test_utc_and_missing_invalid_times_are_explicit(tmp_path, timestamp, expected, missing, invalid):
    engine, path = adapter(tmp_path, [record(timestamp=timestamp)])
    alert = next(engine.ingest_evtx(path))[0]
    assert alert.timestamp == expected
    assert engine.stats.missing_timestamps == missing
    assert engine.stats.invalid_timestamps == invalid


def test_unknown_channels_and_sid_fallback(tmp_path):
    engine, path = adapter(tmp_path, [record(channel="Vendor/Unrecognized", data="")])
    alert = next(engine.ingest_evtx(path))[0]
    assert alert.original_record["Channel"] == "Vendor/Unrecognized"
    assert alert.original_record["User"] == "S-1-5-18"
    assert alert.original_record["Details"] == {}


def test_user_selection_has_explicit_precedence_independent_of_field_order(tmp_path):
    engine, path = adapter(tmp_path, [record(data='<Data Name="SubjectUserName">subject</Data>'
                                           '<Data Name="TargetUserName">target</Data>')])
    assert next(engine.ingest_evtx(path))[0].original_record["User"] == "target"


def test_flatten_duplicate_unnamed_and_nested_fields_without_collisions(tmp_path):
    source = record(data='<Data Name="Value">one</Data><Data Name="Value">two</Data>'
                         '<Data>unnamed</Data><Outer><Inner>nested</Inner></Outer>'
                         '<Data Name="Outer.Inner">literal</Data><Data Name="Value[0]">bracket</Data>')
    source["data"] = source["data"].replace('</Event>', '<UserData><Custom><Port>443</Port></Custom></UserData></Event>')
    engine, path = adapter(tmp_path, [source])
    details = next(engine.ingest_evtx(path))[0].original_record["Details"]
    assert details == {
        "EventData.Value[0]": "one", "EventData.Value[1]": "two",
        "EventData.Data": "unnamed", "EventData.Outer.Inner": "nested",
        r"EventData.Outer\.Inner": "literal", r"EventData.Value\[0\]": "bracket",
        "UserData.Custom.Port": "443",
    }


def test_parser_errors_resume_and_normalization_errors_are_counted_without_content_logs(tmp_path, caplog):
    canary = "DO_NOT_LOG_SOURCE_OR_RECORD"
    engine, path = adapter(tmp_path, [record(), RuntimeError(canary), {"data": canary}, None, record()])
    batches = list(engine.ingest_evtx(path, batch_size=2))
    assert [len(batch) for batch in batches] == [2]
    assert engine.stats.parser_errors == 1
    assert engine.stats.normalization_errors == 2
    assert engine.stats.records_seen == 4
    assert engine.stats.files_failed == 0
    assert canary not in caplog.text
    assert path.name not in caplog.text


def test_stuck_parser_has_a_bounded_error_budget(tmp_path):
    class Stuck:
        def __iter__(self):
            return self

        def __next__(self):
            raise RuntimeError("stuck")

    engine, path = adapter(tmp_path, [])
    engine._parser_factory = lambda stream: Parser(Stuck())
    assert list(engine.ingest_evtx(path)) == []
    assert engine.stats.parser_errors == engine.MAX_CONSECUTIVE_PARSER_ERRORS
    assert engine.stats.files_failed == 1


@pytest.mark.parametrize("bad_record", [
    {"data": "<Event/>"}, {"data": "<Event><System><EventID>bad</EventID></System></Event>"},
    {"data": 42}, {}, {"data": "x" * (EvtxIntakeEngine.MAX_RECORD_CHARACTERS + 1)},
    {"data": "<Event><System><EventID>1</EventID></System><EventData>" + "<N>" * 34 + "x" + "</N>" * 34 + "</EventData></Event>"},
])
def test_malformed_and_oversized_records_are_counted(tmp_path, bad_record):
    engine, path = adapter(tmp_path, [bad_record, record()])
    assert len(list(engine.ingest_evtx(path))[0]) == 1
    assert engine.stats.normalization_errors == 1


@pytest.mark.parametrize("batch_size", [0, -1, True, 1.5, "2"])
def test_batch_size_must_be_a_positive_integer(tmp_path, batch_size):
    engine, path = adapter(tmp_path, [])
    with pytest.raises(ValueError, match="positive integer"):
        list(engine.ingest_evtx(path, batch_size))
    assert engine.stats.files_seen == 0


def test_batches_are_lazy_and_closing_generator_closes_file(tmp_path):
    streams = []
    consumed = []

    def values():
        for i in range(10):
            consumed.append(i)
            yield record()

    def factory(stream):
        streams.append(stream)
        return Parser(values())

    engine, path = adapter(tmp_path, [])
    engine._parser_factory = factory
    batches = engine.ingest_evtx(path, batch_size=3)
    assert consumed == []
    assert len(next(batches)) == 3
    assert consumed == [0, 1, 2]
    batches.close()
    assert streams[0].closed


def test_python_memory_does_not_grow_with_total_record_count(tmp_path):
    def peak(count):
        engine, path = adapter(tmp_path, (record() for _ in range(count)))
        tracemalloc.start()
        try:
            total = 0
            for batch in engine.ingest_evtx(path, batch_size=25):
                total += len(batch)
                assert len(batch) <= 25
            assert total == count
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    small = peak(200)
    large = peak(10_000)
    assert large < small + 512_000
    assert large < 4_000_000


def test_native_parser_configuration_and_stream_lifetime(tmp_path, monkeypatch):
    import evtx

    calls = []

    def factory(stream, **kwargs):
        calls.append((stream, kwargs))
        return Parser([record()])

    monkeypatch.setattr(evtx, "PyEvtxParser", factory)
    path = tmp_path / "fixture.evtx"
    path.touch()
    assert len(list(EvtxIntakeEngine().ingest_evtx(path))[0]) == 1
    assert calls[0][0].closed
    assert calls[0][1] == dict(number_of_threads=1, skip_errors=False, recover_records=False, validate_checksums=True)


def test_native_parser_reads_synthetic_empty_evtx(tmp_path):
    path = tmp_path / "empty.evtx"
    path.write_bytes(empty_evtx())
    engine = EvtxIntakeEngine()
    assert list(engine.ingest_evtx(path)) == []
    assert engine.stats.files_failed == 0
    assert engine.stats.parser_errors == 0


def test_native_nonempty_synthetic_evtx_normalizes_end_to_end(tmp_path):
    path = tmp_path / "synthetic.evtx"
    path.write_bytes(evtx_header(3) + synthetic_chunk(1) + synthetic_chunk(2) + synthetic_chunk(3))
    engine = EvtxIntakeEngine()
    batches = list(engine.ingest_evtx(path, batch_size=2))
    assert [len(batch) for batch in batches] == [2, 1]
    alert = batches[0][0]
    assert alert.event_type == "4624"
    assert alert.original_record["Channel"] == "Synthetic/Channel"
    assert alert.original_record["ComputerName"] == "fixture-host"
    assert alert.original_record["User"] == "analyst"
    assert alert.original_record["Details"]["EventData.ProcessId"] == "42"
    assert engine.stats.records_seen == engine.stats.alerts_emitted == 3
    assert engine.stats.parser_errors == engine.stats.normalization_errors == 0


@pytest.mark.parametrize("corruption", ["chunk", "record", "checksum"])
def test_native_corruption_does_not_hide_later_valid_events(tmp_path, corruption):
    broken = bytearray(synthetic_chunk(2))
    if corruption == "chunk":
        broken[:8] = b"BadMagic"
    else:
        broken[536] = 0xff
        if corruption == "record":
            end = struct.unpack_from("<I", broken, 48)[0]
            struct.pack_into("<I", broken, 52, zlib.crc32(broken[512:end]))
            struct.pack_into("<I", broken, 124, zlib.crc32(broken[:120] + broken[128:512]))
    path = tmp_path / "mixed-native.evtx"
    path.write_bytes(evtx_header(3) + synthetic_chunk(1) + broken + synthetic_chunk(3))
    engine = EvtxIntakeEngine()
    batches = list(engine.ingest_evtx(path, batch_size=2))
    assert [len(batch) for batch in batches] == [2]
    assert engine.stats.parser_errors == 1
    assert engine.stats.alerts_emitted == 2
    assert engine.stats.files_failed == 0


def test_native_corrupt_chunks_are_counted_and_iteration_resumes(tmp_path):
    header = bytearray(empty_evtx())
    struct.pack_into("<Q", header, 16, 1)
    struct.pack_into("<H", header, 42, 2)
    struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
    chunk = bytearray(65536)
    chunk[:8] = b"BadMagic"
    struct.pack_into("<QQQQ", chunk, 8, 1, 1, 1, 1)
    path = tmp_path / "corrupt-chunks.evtx"
    path.write_bytes(header + chunk + chunk)
    engine = EvtxIntakeEngine()
    assert list(engine.ingest_evtx(path)) == []
    assert engine.stats.parser_errors == 2
    assert engine.stats.files_failed == 0
    assert engine.stats.records_seen == 0


@pytest.mark.parametrize("content", [b"", b"not-an-evtx-file"])
def test_native_corrupt_file_is_counted(tmp_path, content, caplog):
    path = tmp_path / "private-source-name.evtx"
    path.write_bytes(content)
    engine = EvtxIntakeEngine()
    assert list(engine.ingest_evtx(path)) == []
    assert engine.stats.files_failed == 1
    assert path.name not in caplog.text


def test_missing_and_unreadable_files_are_counted(tmp_path):
    engine = EvtxIntakeEngine()
    assert list(engine.ingest_evtx(tmp_path / "missing.evtx")) == []
    assert list(engine.ingest_evtx(tmp_path)) == []
    assert engine.stats.files_failed == 2


def test_io_failure_preserves_partial_batch_and_closes_file(tmp_path):
    engine, path = adapter(tmp_path, [record(), OSError("private-content")])
    assert len(list(engine.ingest_evtx(path, batch_size=10))[0]) == 1
    assert engine.stats.files_failed == 1


def test_missing_dependency_is_not_hidden_as_corrupt_data(tmp_path):
    engine, path = adapter(tmp_path, [])

    def missing(stream):
        raise ImportError("evtx is required")

    engine._parser_factory = missing
    with pytest.raises(ImportError, match="evtx is required"):
        list(engine.ingest_evtx(path))


def test_evtx_source_path_and_raw_xml_are_excluded_from_outbound_prompt(tmp_path):
    engine, path = adapter(tmp_path, [record()])
    alert = next(engine.ingest_evtx(path))[0]
    sent = []

    def send(url, **kwargs):
        sent.append(kwargs["json"])
        return httpx.Response(200, json={"text": json.dumps({
            "severity": "LOW", "confidence_score": 0.5, "summary": "Offline fixture",
            "reasoning": [], "recommended_actions": [],
        })})

    triage = PipelineTestEngine(api_key="offline-placeholder", fallback_models=[], enable_cache=False, request_sender=send)
    timeline = ThreatTimeline(grouping_key="local-group", alerts=[alert], total_events=1)
    assert triage.analyze_timeline(timeline) is not None
    outbound = json.dumps(sent)
    assert path.name not in outbound
    assert str(path) not in outbound
    assert "Windows EVTX" not in outbound
    assert "raw_xml" not in outbound
    assert "ProcessId" in outbound
    assert alert.source_file == str(path)


def test_mixed_directory_streams_evtx_and_keeps_existing_json_csv(tmp_path):
    (tmp_path / "a.json").write_text('{"EventID": 10}', encoding="utf-8")
    (tmp_path / "b.EVTX").touch()
    (tmp_path / "c.csv").write_text("EventID\n20\n", encoding="utf-8")
    engine = AlertIntakeEngine()
    engine.evtx = EvtxIntakeEngine(lambda stream: Parser([record(), record(), record()]))
    batches = list(engine.ingest_directory(tmp_path, batch_size=2))
    assert [len(batch) for batch in batches] == [2, 2, 1]
    assert [alert.event_type for batch in batches for alert in batch] == ["10", "4624", "4624", "4624", "20"]
    assert engine.evtx.stats.alerts_emitted == 3
