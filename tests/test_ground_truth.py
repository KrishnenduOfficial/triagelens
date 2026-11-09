"""Offline T1.2 mappings and boundary tests; no public dataset files are read."""

import copy
import json
import logging
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from pydantic import ValidationError

from conftest import PipelineTestEngine
from test_evtx import Parser, record
from src.engine.database import DatabaseManager
from src.engine.enrichment import EnrichmentEngine
from src.engine.evaluation import AccuracyTracker
from src.engine.evtx import EvtxIntakeEngine
from src.engine.ground_truth import DatasetGroundTruthMapper
from src.engine.intake import AlertIntakeEngine
from src.models.alert import GroundTruthAnnotation, NormalizedAlert
from src.models.timeline import ThreatTimeline


RELATIVE = "Credential Access/LSASS-T1003.001_attack.example.evtx"
CANARIES = ("EVTX-ATTACK-SAMPLES", "Credential Access", "LSASS-T1003.001_attack.example.evtx",
            "T1003.001", "attack.example", "Defense Evasion", "T1055", "benign.example")


def source_alert(root, relative=RELATIVE):
    return NormalizedAlert(
        source_dataset="Windows EVTX", source_file=str(root / relative), event_type="4624",
        original_record={"EventID": 4624, "ComputerName": "fixture-host",
                         "Details": {"EventData.ProcessId": "42", "DestinationIp": "8.8.8.8"}},
        extracted_indicators=["8.8.8.8"],
    )


def test_folder_filename_and_supplied_metadata_are_ground_truth_only(tmp_path):
    original = source_alert(tmp_path)
    before = original.model_dump()
    mapper = DatasetGroundTruthMapper(
        tmp_path, folder_labels={"Credential Access": "malicious"},
        file_labels={RELATIVE: "malicious"},
        metadata={RELATIVE: {"label": "malicious", "technique_ids": ["t1055"], "severity": "HIGH"}},
    )
    alert = mapper.map_alert(original)
    assert original.model_dump() == before
    assert alert.original_record == original.original_record
    assert alert.extracted_indicators == ["8.8.8.8"]
    assert alert.ground_truth_label == "malicious"
    truth = alert.ground_truth_metadata
    assert truth.status == "mapped" and truth.relative_path == RELATIVE
    assert truth.technique_ids == ["T1003.001", "T1055"]
    assert truth.severity == "HIGH"
    assert set(truth.label_sources) == {"folder:Credential Access", f"file:{RELATIVE}", f"metadata:{RELATIVE}"}
    assert AccuracyTracker()._classify_alert_label(alert) is True
    timeline = ThreatTimeline(grouping_key="fixture", alerts=[alert], total_events=1)
    assert AccuracyTracker()._extract_ground_truth_severity(timeline) == "HIGH"


@pytest.mark.parametrize("kind", ["folder", "file", "metadata"])
@pytest.mark.parametrize("label,expected", [("malicious", True), ("benign", False)])
def test_each_explicit_label_source_is_supported(tmp_path, kind, label, expected):
    kwargs = {"folder_labels": {"Credential Access": label}} if kind == "folder" else (
        {"file_labels": {RELATIVE: label}} if kind == "file" else
        {"metadata": {RELATIVE: {"label": label}}})
    alert = DatasetGroundTruthMapper(tmp_path, **kwargs).map_alert(source_alert(tmp_path))
    assert AccuracyTracker()._classify_alert_label(alert) is expected


@pytest.mark.parametrize("relative", [RELATIVE, "Other/T1055.evtx", "malicious/T1003.evtx"])
def test_technique_ids_and_attack_names_do_not_imply_binary_truth(tmp_path, relative):
    alert = source_alert(tmp_path, relative)
    # Even legacy label-like telemetry cannot override explicit unknown mapping.
    alert.original_record.update({"mitre_technique": "T1003", "is_malicious": True, "severity": "HIGH"})
    mapped = DatasetGroundTruthMapper(tmp_path).map_alert(alert)
    tracker = AccuracyTracker()
    assert mapped.ground_truth_label is None and mapped.ground_truth_metadata.status == "unknown"
    assert tracker._classify_alert_label(mapped) is None
    timeline = ThreatTimeline(grouping_key="fixture", alerts=[mapped], total_events=1)
    assert tracker._extract_ground_truth_severity(timeline) is None


@pytest.mark.parametrize("conflict", ["file", "metadata", "nested_folder", "existing"])
def test_conflicting_sources_stay_unknown_without_telemetry_fallback(tmp_path, conflict):
    relative = "Credential Access/reviewed/LSASS-T1003.001.evtx"
    kwargs = {"folder_labels": {"Credential Access": "malicious"}}
    alert = source_alert(tmp_path, relative)
    alert.original_record["is_malicious"] = True
    if conflict == "file":
        kwargs["file_labels"] = {relative: "benign"}
    elif conflict == "metadata":
        kwargs["metadata"] = {relative: {"label": "benign", "severity": "LOW"}}
    elif conflict == "nested_folder":
        kwargs["folder_labels"]["Credential Access/reviewed"] = "benign"
    else:
        alert.ground_truth_label = "benign"
    mapped = DatasetGroundTruthMapper(tmp_path, **kwargs).map_alert(alert)
    assert mapped.ground_truth_metadata.status == "conflict"
    assert mapped.ground_truth_metadata.severity is None
    assert mapped.ground_truth_label is None
    assert AccuracyTracker()._classify_alert_label(mapped) is None


def test_exact_root_relative_matching_and_windows_separators(tmp_path):
    mapper = DatasetGroundTruthMapper(
        tmp_path, folder_labels={"Credential Access": "malicious"},
        file_labels={RELATIVE.replace("/", "\\"): "benign"},
    )
    assert mapper.map_alert(source_alert(tmp_path)).ground_truth_metadata.status == "conflict"
    assert mapper.map_alert(source_alert(tmp_path, "Credential Access extra/a.evtx")).ground_truth_label is None
    assert mapper.map_alert(source_alert(tmp_path, "Other/LSASS-T1003.001_attack.example.evtx")).ground_truth_label is None


@pytest.mark.parametrize("key", ["../escape.evtx", "C:\\private.evtx", "/absolute.evtx", ""])
def test_invalid_mapping_paths_are_rejected_without_echoing_names(tmp_path, key):
    with pytest.raises(ValueError, match="dataset-relative paths") as caught:
        DatasetGroundTruthMapper(tmp_path, file_labels={key: "malicious"})
    if key:
        assert key not in str(caught.value)


def test_source_outside_root_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="outside the configured dataset root"):
        DatasetGroundTruthMapper(tmp_path / "dataset").map_alert(source_alert(tmp_path))


@pytest.mark.parametrize("kwargs", [
    {"folder_labels": {"Other": "suspicious"}},
    {"metadata": {RELATIVE: {"label": "suspicious"}}},
    {"metadata": {RELATIVE: {"technique_ids": ["not-a-technique"]}}},
    {"metadata": {RELATIVE: {"ai_prediction": "malicious"}}},
])
def test_invalid_or_prediction_metadata_is_not_accepted(tmp_path, kwargs):
    with pytest.raises((ValueError, ValidationError)):
        DatasetGroundTruthMapper(tmp_path, **kwargs)


def test_metadata_is_copied_from_caller_and_id_matching_is_bounded(tmp_path):
    annotation = GroundTruthAnnotation(label="benign", technique_ids=["T1055"])
    relative = "Other/T10030_T1003.0012_XT1003_T1003.001.evtx"
    mapper = DatasetGroundTruthMapper(tmp_path, metadata={relative: annotation})
    annotation.label = "malicious"
    annotation.technique_ids.append("T1111")
    mapped = mapper.map_alert(source_alert(tmp_path, relative))
    assert mapped.ground_truth_label == "benign"
    assert mapped.ground_truth_metadata.technique_ids == ["T1003.001", "T1055"]


def test_evtx_mapping_is_opt_in_and_metadata_never_becomes_telemetry(tmp_path, caplog):
    root = tmp_path / "EVTX-ATTACK-SAMPLES"
    path = root / RELATIVE
    path.parent.mkdir(parents=True)
    path.touch()
    mapper = DatasetGroundTruthMapper(root, file_labels={RELATIVE: "malicious"})
    intake = AlertIntakeEngine(ground_truth_mapper=mapper)
    intake.evtx._parser_factory = lambda stream: Parser([record()])
    with caplog.at_level(logging.DEBUG):
        mapped = next(intake.ingest_directory(path.parent))[0]
    baseline = EvtxIntakeEngine(lambda stream: Parser([record()]))
    plain = next(baseline.ingest_evtx(path))[0]
    assert plain.ground_truth_metadata is None and plain.ground_truth_label is None
    assert mapped.ground_truth_label == "malicious"
    assert mapped.original_record == plain.original_record
    assert mapped.extracted_indicators == plain.extracted_indicators == []
    for name in CANARIES:
        assert name not in caplog.text


def test_metadata_roundtrip_and_conflict_can_clear_previously_stored_label(tmp_path):
    alert = DatasetGroundTruthMapper(tmp_path, file_labels={RELATIVE: "malicious"}).map_alert(source_alert(tmp_path))
    db = DatabaseManager()
    db.init_db()
    db.insert_alert(alert)
    stored = db.get_alert(alert.internal_id)
    assert stored["ground_truth_metadata"] == alert.ground_truth_metadata.model_dump()
    assert stored["original_record"] == alert.original_record
    conflict = DatasetGroundTruthMapper(tmp_path, file_labels={RELATIVE: "benign"}).map_alert(alert)
    db.insert_alert(conflict)
    assert db.get_alert(alert.internal_id)["ground_truth_label"] is None
    # A legacy linking/upsert call cannot restore a stale label over mapped truth.
    db.insert_alert(alert.model_copy(update={"ground_truth_metadata": None}))
    assert db.get_alert(alert.internal_id)["ground_truth_label"] is None
    timeline = ThreatTimeline(grouping_key="fixture", alerts=[conflict], total_events=1)
    db.insert_timeline(timeline)
    stored = db.get_alerts_for_timeline(timeline.timeline_id)[0]
    reloaded = NormalizedAlert.model_validate({**stored, "internal_id": stored["id"]})
    assert reloaded.ground_truth_metadata == conflict.ground_truth_metadata
    assert AccuracyTracker()._classify_alert_label(reloaded) is None
    db.close()


def test_legacy_alert_table_migration_is_nullable_and_idempotent():
    db = DatabaseManager()
    db.connection.execute("""CREATE TABLE alerts (
        id TEXT PRIMARY KEY, timeline_id TEXT, timestamp TEXT, source_dataset TEXT NOT NULL,
        source_file TEXT NOT NULL, event_type TEXT NOT NULL, original_record TEXT NOT NULL,
        extracted_indicators TEXT NOT NULL, ground_truth_label TEXT, created_at TEXT NOT NULL)""")
    legacy = NormalizedAlert(source_dataset="old", source_file="old.json", event_type="1", original_record={})
    db.connection.execute("INSERT INTO alerts VALUES (?,NULL,NULL,'old','old.json','1','{}','[]',NULL,'2026-01-01')",
                          (str(legacy.internal_id),))
    db.init_db()
    db.init_db()
    assert db.get_alert(legacy.internal_id)["ground_truth_metadata"] is None
    db.insert_alert(legacy)
    assert db.count_alerts() == 1
    db.close()


def sender(calls):
    def send(url, **kwargs):
        calls.append(kwargs["json"])
        return httpx.Response(200, json={"text": json.dumps({
            "severity": "LOW", "confidence_score": 0.5, "summary": "Offline fixture",
            "reasoning": [], "recommended_actions": [],
        })})
    return send


@pytest.mark.parametrize("persistent", [False, True])
def test_realistic_names_cannot_change_prompt_enrichment_or_cache_identity(tmp_path, caplog, persistent):
    root = tmp_path / "EVTX-ATTACK-SAMPLES"
    original = source_alert(root)
    first = DatasetGroundTruthMapper(root, file_labels={RELATIVE: "malicious"}).map_alert(original)
    changed = original.model_copy(update={"source_file": str(root / "Defense Evasion/T1055_benign.example.evtx")})
    changed = DatasetGroundTruthMapper(root, metadata={
        "Defense Evasion/T1055_benign.example.evtx": {"label": "benign", "severity": "LOW"}
    }, dataset_name="different-dataset").map_alert(changed)
    timeline = ThreatTimeline(grouping_key=first.source_file, alerts=[first], total_events=1)
    before = copy.deepcopy(timeline.model_dump())
    calls = []
    engine = PipelineTestEngine(api_key="offline-placeholder", model="offline-model", fallback_models=[],
                                request_sender=sender(calls))
    db = DatabaseManager()
    db.init_db()
    db.insert_timeline(timeline)
    with caplog.at_level(logging.DEBUG):
        initial = engine.acquire_timeline(timeline, on_acquisition=lambda origin: None,
                                          persistent_cache=db if persistent else None)
        assert initial.verdict is not None and initial.origin == "fresh"
        assert timeline.model_dump() == before
        if persistent:
            db.persist_cached_verdict(initial.verdict, initial.cache_provenance)
        timeline.alerts = [changed]
        timeline.grouping_key = changed.source_file
        repeat = engine.acquire_timeline(timeline, on_acquisition=lambda origin: None,
                                         persistent_cache=db if persistent else None)
        assert repeat.origin == "cache" and len(calls) == 1
        assert repeat.cache_contract.key == initial.cache_contract.key
        assert repeat.cache_contract.evidence_hash == initial.cache_contract.evidence_hash
        # Exercise actual provider lookup and enrichment key construction with the
        # existing indicator contract; mapping cannot introduce new indicators.
        enrichment = EnrichmentEngine()
        provider = Mock(spec=["name", "lookup"])
        provider.name = "virustotal"
        provider.lookup.return_value = None
        enrichment.providers = {"virustotal": provider}
        for alert in (first, changed):
            enrichment.enrich_indicators(alert.extracted_indicators)
        assert [call.args for call in provider.lookup.call_args_list] == [("8.8.8.8", "ip")]
        assert set(enrichment.cache) == {"virustotal:ip:8.8.8.8"}
        changed_calls = []
        uncached = PipelineTestEngine(api_key="offline-placeholder", model="offline-model", fallback_models=[],
                                     request_sender=sender(changed_calls), enable_cache=False)
        assert uncached.analyze_timeline(timeline) is not None
        assert changed_calls == calls
    encoded = json.dumps(calls) + caplog.text + repr(initial.cache_contract) + repr(enrichment.cache)
    for name in CANARIES:
        assert name not in encoded
    assert "DestinationIp" in json.dumps(calls) and "8.8.8.8" in json.dumps(calls)
    assert AccuracyTracker()._classify_alert_label(first) is True
    assert AccuracyTracker()._classify_alert_label(changed) is False
    db.close()


@pytest.mark.parametrize("failure", ["missing_directory", "not_directory", "bad_evtx", "bad_json", "empty_csv"])
def test_intake_failure_logs_never_contain_dataset_names(tmp_path, caplog, failure):
    folder = tmp_path / "EVTX-ATTACK-SAMPLES" / "Credential Access"
    folder.mkdir(parents=True)
    intake = AlertIntakeEngine()
    with caplog.at_level(logging.DEBUG):
        if failure == "missing_directory":
            with pytest.raises(FileNotFoundError):
                list(intake.ingest_directory(folder / "T1003.001-missing"))
        elif failure == "not_directory":
            path = folder / "T1003.001.evtx"
            path.touch()
            with pytest.raises(NotADirectoryError):
                list(intake.ingest_directory(path))
        else:
            suffix = {"bad_evtx": ".evtx", "bad_json": ".json", "empty_csv": ".csv"}[failure]
            path = folder / ("LSASS-T1003.001_attack.example" + suffix)
            path.write_bytes(b"broken" if failure != "empty_csv" else b"")
            list(intake.ingest_directory(folder))
    for name in CANARIES:
        assert name not in caplog.text


def test_cli_does_not_log_dataset_path_or_provenance_grouping(tmp_path, caplog, monkeypatch):
    import src.cli as cli

    folder = tmp_path / "EVTX-ATTACK-SAMPLES" / "Credential Access"
    folder.mkdir(parents=True)
    path = folder / Path(RELATIVE).name
    path.touch()
    intake = AlertIntakeEngine(ground_truth_mapper=DatasetGroundTruthMapper(folder.parent,
                                     file_labels={RELATIVE: "malicious"}))
    intake.evtx._parser_factory = lambda stream: Parser([record()])
    monkeypatch.setattr(cli, "AlertIntakeEngine", lambda: intake)
    enrichment = EnrichmentEngine()
    enrichment.providers = {}
    monkeypatch.setattr(cli, "EnrichmentEngine", lambda **kwargs: enrichment)
    with caplog.at_level(logging.DEBUG):
        cli.run_pipeline(str(folder), db_path=str(tmp_path / "test.sqlite"), group_by="source_file", skip_llm=True)
    for name in CANARIES:
        assert name not in caplog.text
