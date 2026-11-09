"""Offline Windows field mapping and shared-consumer contract checks."""

from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from conftest import PipelineTestEngine
from src.engine.database import DatabaseManager
from src.engine.evtx import EvtxIntakeEngine
from src.engine.fields import FIELD_MAPPINGS, canonical_fields, resolve_field
from src.engine.hunting import HuntTimeoutError, ThreatHuntingEngine
from src.engine.timeline import TimelineBuilder
from src.models.alert import GroundTruthMetadata, NormalizedAlert


SYSMON = {
    "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
    "ComputerName": "workstation-01", "User": "DOMAIN\\alice",
    "Details": {
        "EventData.Image": r"C:\Windows\System32\cmd.exe",
        "EventData.CommandLine": 'cmd.exe /c "echo fixture"',
        "EventData.ProcessId": "42", "EventData.ParentProcessId": "7",
        "EventData.ParentImage": r"C:\Windows\explorer.exe",
        "EventData.SourceIp": "192.0.2.1", "EventData.SourcePort": "0",
        "EventData.DestinationIp": "198.51.100.2", "EventData.DestinationPort": "443",
    },
}
SYSMON_VIEW = {
    "metadata.event_code": "1", "metadata.log_name": "Microsoft-Windows-Sysmon/Operational",
    "device.hostname": "workstation-01",
    "user.name": "DOMAIN\\alice", "process.file.path": r"C:\Windows\System32\cmd.exe",
    "process.cmd_line": 'cmd.exe /c "echo fixture"', "process.pid": 42,
    "process.parent_process.file.path": r"C:\Windows\explorer.exe",
    "process.parent_process.pid": 7,
    "src_endpoint.ip": "192.0.2.1", "src_endpoint.port": 0,
    "dst_endpoint.ip": "198.51.100.2", "dst_endpoint.port": 443,
}
SECURITY = {
    "EventID": 4688, "Channel": "Security", "ComputerName": "workstation-01",
    "Details": {
        "EventData.SubjectUserName": "creator", "EventData.TargetUserName": "target",
        "EventData.NewProcessId": "0x2a", "EventData.ProcessId": "0x7",
        "EventData.NewProcessName": r"C:\Windows\System32\cmd.exe",
        "EventData.ParentProcessName": r"C:\Windows\explorer.exe",
    },
}


def alert(record, **kwargs):
    return NormalizedAlert(source_dataset="synthetic", source_file="fixture.evtx",
                           event_type="fixture", original_record=record, **kwargs)


@pytest.fixture
def db():
    manager = DatabaseManager()
    manager.init_db()
    yield manager
    manager.close()


@pytest.mark.parametrize("name,expected", SYSMON_VIEW.items())
def test_sysmon_adapter_fields(name, expected):
    assert resolve_field(SYSMON, name) == expected


def test_security_process_creation_and_separate_account_roles():
    assert canonical_fields(SECURITY) == {
        "metadata.event_code": "4688", "metadata.log_name": "Security", "device.hostname": "workstation-01",
        "user.name": "target", "actor.user.name": "creator", "target.user.name": "target",
        "process.file.path": r"C:\Windows\System32\cmd.exe", "process.pid": 42,
        "process.parent_process.file.path": r"C:\Windows\explorer.exe",
        "process.parent_process.pid": 7,
    }
    missing_child = deepcopy(SECURITY)
    del missing_child["Details"]["EventData.NewProcessId"]
    assert resolve_field(missing_child, "process.pid") is None
    assert resolve_field(missing_child, "process.parent_process.pid") == 7


@pytest.mark.parametrize("record", [
    {"Image": "fixture.exe", "ProcessId": 42},
    {"EventData": {"Image": "fixture.exe", "ProcessId": "42"}},
    {"Event": {"System": {"EventID": 1},
               "EventData": {"Image": "fixture.exe", "ProcessId": "42"}}},
    {"Details": {"EventData.Image": "fixture.exe", "EventData.ProcessId": "42"}},
    {"process": {"file": {"path": "fixture.exe"}, "pid": 42}},
    {"process.file.path": "fixture.exe", "process.pid": "42"},
    {"eventdata": {"IMAGE": "fixture.exe", "PROCESSID": "42"}},
])
def test_declared_flat_nested_and_canonical_shapes(record):
    assert resolve_field(record, "PROCESS.FILE.PATH") == "fixture.exe"
    assert resolve_field(record, "process.pid") == 42


@pytest.mark.parametrize("record", [
    {"Event": {"System": {"EventID": 4624, "Computer": "host"}}},
    {"System": {"EventID": "4624", "Computer": "host"}},
    {"EventCode": 4624, "Hostname": "host"},
])
def test_evtx_system_fields(record):
    assert resolve_field(record, "metadata.event_code") == "4624"
    assert resolve_field(record, "device.hostname") == "host"


def test_security_logon_network_fields_and_literal_dotted_key():
    record = {"EventID": 4624, "Details": {
        "EventData.IpAddress": "192.0.2.1", "EventData.IpPort": "53100",
        "EventData.TargetUserName": "alice",
        "EventData": {"IpAddress": "unmapped nested key"},
    }}
    assert canonical_fields(record) == {
        "metadata.event_code": "4624", "user.name": "alice", "target.user.name": "alice",
        "src_endpoint.ip": "192.0.2.1", "src_endpoint.port": 53100,
    }


@pytest.mark.parametrize("name,value,expected", [
    ("process.pid", 0, 0), ("process.pid", " 0X2a ", 42),
    ("process.pid", str(2**63 - 1), 2**63 - 1),
    ("process.pid", 2**63, None), ("process.pid", -1, None),
    ("process.pid", True, None), ("process.pid", 42.0, None),
    ("process.pid", "42.0", None), ("process.pid", "+42", None),
    ("process.pid", "٤٢", None), ("process.pid", "0x", None),
    ("process.pid", "9" * 5000, None), ("process.pid", "0x" + "f" * 19, None),
    ("src_endpoint.port", "65535", 65535), ("src_endpoint.port", 65536, None),
    ("src_endpoint.port", "0x50", None), ("src_endpoint.port", False, None),
    ("user.name", " alice ", " alice "), ("user.name", 42, None),
    ("user.name", "  ", None), ("process.cmd_line", " cmd /c echo  ", " cmd /c echo  "),
    ("metadata.event_code", 4624, "4624"), ("metadata.event_code", True, None),
    ("metadata.event_code", {}, None),
])
def test_explicit_types_and_numeric_bounds(name, value, expected):
    assert resolve_field({name: value}, name) == expected


@pytest.mark.parametrize("value", [None, [], {}, {"unexpected": "nested"}, ["alice"]])
def test_missing_null_container_and_unknown_fields(value):
    assert resolve_field({"User": value}, "user.name") is None
    assert resolve_field({"User": "alice"}, "unknown") is None
    assert canonical_fields({}) == {}


def test_alias_conflict_precedence_and_case_collisions():
    assert resolve_field({"host": "first", "ComputerName": "second"}, "device.hostname") == "first"
    assert resolve_field({"Image": "flat", "Details": {"EventData.Image": "detail"}},
                         "process.file.path") == "flat"
    assert resolve_field({"process.pid": 9, "ProcessId": "42"}, "process.pid") == 9
    assert resolve_field({"process.pid": [], "ProcessId": "42"}, "process.pid") == 42
    assert resolve_field({"IMAGE": "one", "image": "two"}, "process.file.path") is None
    assert resolve_field({"Image": "exact", "IMAGE": "other"}, "process.file.path") == "exact"
    assert resolve_field({"User": "primary", "TargetUserName": "target", "SubjectUserName": "actor"},
                         "user.name") == "primary"


def test_projection_does_not_copy_metadata_or_mutate_source():
    record = deepcopy(SYSMON)
    record.update({key: {"Image": "metadata-canary", "User": "metadata-canary"} for key in (
        "ground_truth_metadata", "detections", "ai_predictions", "analyst_disposition", "raw_xml",
    )})
    record["source_file"] = "metadata-canary-T1003.001-malicious.evtx"
    record["Details"]["EventData.GroundTruthLabel"] = "metadata-canary"
    before = deepcopy(record)
    view = canonical_fields(record)
    assert view == SYSMON_VIEW
    assert record == before
    assert "metadata-canary" not in json.dumps(view)
    view["device.hostname"] = "changed"
    assert record == before
    assert canonical_fields({key: value for key, value in record.items()
                             if key not in SYSMON}) == {}


def test_hunting_and_python_projection_agree_for_all_fields(db):
    record = deepcopy(SYSMON)
    record["Details"].update({"EventData.SubjectUserName": "actor", "EventData.TargetUserName": "target"})
    stored = alert(record)
    db.insert_alert(stored)
    db.insert_alert(alert({}))
    engine = ThreatHuntingEngine(db)
    view = canonical_fields(record)
    assert view.keys() == FIELD_MAPPINGS.keys()
    for field, expected in view.items():
        matches = engine.execute_hunt(f"{field.upper()} == {json.dumps(expected)}")
        assert [item.internal_id for item in matches] == [stored.internal_id]
        incompatible = "42" if isinstance(expected, int) else 42
        assert engine.execute_hunt(f"{field} == {json.dumps(incompatible)}") == []


def test_hunting_canonical_negation_types_injection_and_legacy_access(db):
    record = deepcopy(SECURITY)
    record["Details"]["EventData.CommandLine"] = "echo 100%_fixture"
    stored = alert(record)
    db.insert_alert(stored)
    db.insert_alert(alert({"ProcessId": [], "CommandLine": None}))
    engine = ThreatHuntingEngine(db)
    for query in ('process.pid == 42 AND process.parent_process.pid == 7',
                  'process.cmd_line contains "100%_"',
                  'NOT process.pid == 7', 'EventID == 4688'):
        assert [item.internal_id for item in engine.execute_hunt(query)] == [stored.internal_id]
    assert engine.execute_hunt('NOT process.pid == 42') == []
    sql, params = engine.translate_kql_to_sql('user.name == "\'; DROP TABLE alerts; --"')
    assert "DROP TABLE" not in sql and params[0] == "'; DROP TABLE alerts; --"
    assert engine.execute_hunt('user.name == "\'; DROP TABLE alerts; --"') == []
    # The per-hunt callback and decoded record do not remain installed/retained.
    with pytest.raises(sqlite3.OperationalError):
        db.connect().execute("SELECT triagelens_field('{}', 'process.pid')")
    assert len(engine.execute_hunt('process.pid == 42')) == 1


def test_existing_database_is_searchable_without_reingestion(tmp_path):
    path = str(tmp_path / "legacy.sqlite")
    manager = DatabaseManager(path)
    manager.init_db()
    stored = alert(SECURITY)
    manager.insert_alert(stored)
    columns = list(manager.connect().execute("PRAGMA table_info(alerts)"))
    manager.close()
    with DatabaseManager(path) as reopened:
        matches = ThreatHuntingEngine(reopened).execute_hunt('process.pid == 42')
        assert [item.internal_id for item in matches] == [stored.internal_id]
        assert [tuple(row) for row in reopened.connect().execute("PRAGMA table_info(alerts)")] == [
            tuple(row) for row in columns]
        assert matches[0].original_record == SECURITY


def test_canonical_callback_error_cleans_up_and_connection_recovers(db):
    db.insert_alert(alert(SYSMON))
    db.connect().execute("UPDATE alerts SET original_record = 'invalid-json-canary'")
    with pytest.raises(sqlite3.OperationalError) as caught:
        ThreatHuntingEngine(db).execute_hunt('process.pid == 42')
    assert "invalid-json-canary" not in str(caught.value)
    with pytest.raises(sqlite3.OperationalError):
        db.connect().execute("SELECT triagelens_field('{}', 'process.pid')")
    assert db.connect().execute("PRAGMA busy_timeout").fetchone()[0] == 60000
    db.connect().execute("UPDATE alerts SET original_record = ?", (json.dumps(SYSMON),))
    assert len(ThreatHuntingEngine(db).execute_hunt('process.pid == 42')) == 1


def test_canonical_timeout_withholds_results_and_cleans_up(db):
    db.insert_alert(alert(SYSMON))
    times = iter([0, 0, 3])  # Initial deadline, pre-query check, post-fetch expiry.
    with pytest.raises(HuntTimeoutError):
        ThreatHuntingEngine(db, clock=lambda: next(times)).execute_hunt('process.pid == 42')
    with pytest.raises(sqlite3.OperationalError):
        db.connect().execute("SELECT triagelens_field('{}', 'process.pid')")
    assert db.connect().execute("PRAGMA busy_timeout").fetchone()[0] == 60000
    assert len(ThreatHuntingEngine(db).execute_hunt('process.pid == 42')) == 1


def test_correlation_uses_same_identities_across_shapes_and_explicit_groups():
    builder = TimelineBuilder()
    records = [SYSMON, {"host": "workstation-01", "user": "DOMAIN\\alice"},
               {"Event": {"System": {"Computer": "workstation-01"},
                          "EventData": {"User": "DOMAIN\\alice"}}}]
    events = [alert(record) for record in records]
    timelines = builder.build_timelines(events)
    assert len(timelines) == 1 and timelines[0].total_events == 3
    assert timelines[0].grouping_key == "workstation-01:DOMAIN\\alice"
    for field, expected in (("device.hostname", "workstation-01"), ("process.pid", "42")):
        groups = builder.build_timelines(events, group_by=field)
        assert expected in {group.grouping_key for group in groups}
    # A list/dict is not an identity merely because it has a string representation.
    grouping = builder._extract_auto_grouping(alert({"host": ["host"], "user": {"unexpected": "user"}}))
    assert grouping == ("ungrouped", "potential", "time_proximity_fallback")


def test_mapping_and_hunts_do_not_change_labels_or_prompt_input(db):
    metadata = GroundTruthMetadata(relative_path="label-canary-T1003.001.evtx", status="mapped",
                                   label_sources={"review": "benign"})
    event = alert(SYSMON, ground_truth_label="benign", ground_truth_metadata=metadata)
    before = event.model_dump()
    triage = PipelineTestEngine(api_key="offline-placeholder", fallback_models=[], enable_cache=False)
    timeline = TimelineBuilder().build_timelines([event])[0]
    payload_before = triage._build_sanitized_triage_payload(timeline)
    canonical_fields(event.original_record)
    db.insert_alert(event)
    found = ThreatHuntingEngine(db).execute_hunt('process.pid == 42')[0]
    payload_after = triage._build_sanitized_triage_payload(TimelineBuilder().build_timelines([found])[0])
    # Timeline UUID is local identity, not telemetry; compare event projections.
    assert payload_after["events"] == payload_before["events"]
    assert event.model_dump() == before
    assert found.ground_truth_metadata == metadata and found.ground_truth_label == "benign"
    assert "label-canary" not in json.dumps(payload_after)


def test_evtx_normalization_to_hunt_and_correlation(db):
    xml = ('<Event><System><EventID>4688</EventID><Channel>Security</Channel>'
           '<Computer>fixture-host</Computer></System><EventData>'
           '<Data Name="NewProcessId">0x2a</Data><Data Name="ProcessId">0x7</Data>'
           '<Data Name="NewProcessName">fixture.exe</Data>'
           '<Data Name="SubjectUserName">creator</Data>'
           '<Data Name="TargetUserName">target</Data></EventData></Event>')
    event = EvtxIntakeEngine()._normalize({"data": xml}, Path("fixture.evtx"))
    db.insert_alert(event)
    hits = ThreatHuntingEngine(db).execute_hunt(
        'metadata.event_code == "4688" AND process.pid == 42 AND actor.user.name == "creator"')
    assert [item.internal_id for item in hits] == [event.internal_id]
    assert TimelineBuilder().build_timelines(hits)[0].grouping_key == "fixture-host:target"
