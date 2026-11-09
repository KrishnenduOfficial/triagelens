"""Offline detection persistence and AI isolation contracts."""
from datetime import datetime, timezone
import json
import sqlite3
from uuid import uuid4

import pytest
import httpx

from conftest import PipelineTestEngine
from src.engine.database import DatabaseManager
from src.engine.attack import rule_techniques
from src.engine.sigma import load_curated_rules
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline


@pytest.fixture
def db(tmp_path):
    database = DatabaseManager(str(tmp_path / "test.sqlite"))
    database.init_db()
    yield database
    database.close()


def event():
    return NormalizedAlert(source_dataset="fixture", source_file="fixture.evtx",
                           event_type="process", ground_truth_label="benign",
                           original_record={"Channel": "Microsoft-Windows-Sysmon/Operational",
                                            "EventID": 1, "Image": r"C:\Windows\System32\hostname.exe"})


def test_sigma_detection_roundtrip_and_prompt_isolation(db):
    alert = event()
    timeline = ThreatTimeline(grouping_key="fixture", alerts=[alert], total_events=1)
    db.insert_timeline(timeline)
    matches = load_curated_rules().evaluate(alert)
    assert matches
    match = matches[0]
    requests = []
    def send(url, **kwargs):
        requests.append(kwargs["json"])
        return httpx.Response(200, json={"outputs": [{"message": {"segments": [{"text": json.dumps({
            "severity": "LOW", "confidence_score": 0.6, "summary": "fixture",
            "reasoning": [], "recommended_actions": []})}]}}]})

    engine = PipelineTestEngine(api_key="offline-placeholder", model="offline-model",
                                fallback_models=[], enable_cache=False, request_sender=send)
    engine.analyze_timeline(timeline)
    before = requests[-1]
    techniques, invalid = rule_techniques('sigma', match.tags)
    assert techniques == ['T1082'] and not invalid
    detection_id = db.insert_detection(match.rule_id, "sigma", [match.event_id],
                                       datetime(2026, 1, 1, tzinfo=timezone.utc), techniques)
    db.close()
    db.init_db()
    hits = db.get_detections_for_timeline(timeline.timeline_id)
    assert hits == [{"id": detection_id, "rule_id": match.rule_id, "source": "sigma",
                     "detected_at": "2026-01-01T00:00:00+00:00", "technique_ids": ['T1082'],
                     "event_ids": [str(alert.internal_id)]}]
    assert db.get_alert(alert.internal_id)["ground_truth_label"] == "benign"
    assert db.get_verdict_for_timeline(timeline.timeline_id) is None
    engine.analyze_timeline(timeline)
    assert requests[-1] == before
    assert match.rule_id not in str(before)


def test_multi_event_membership_tracks_timeline_and_returns_distinct_hits(db):
    a, b = event(), event()
    t1 = ThreatTimeline(grouping_key="one", alerts=[a], total_events=1)
    t2 = ThreatTimeline(grouping_key="two", alerts=[b], total_events=1)
    db.insert_timeline(t1)
    db.insert_timeline(t2)
    hit = db.insert_detection("rule", "hunt", [a.internal_id, b.internal_id], datetime.now(timezone.utc))
    for timeline in (t1, t2):
        results = db.get_detections_for_timeline(timeline.timeline_id)
        assert len(results) == 1 and results[0]["id"] == hit
        assert set(results[0]["event_ids"]) == {str(a.internal_id), str(b.internal_id)}
    assert db.get_detections_for_timeline(uuid4()) == []


@pytest.mark.parametrize("rule,source,ids,when", [
    (" ", "sigma", [uuid4()], datetime.now(timezone.utc)),
    ("r", "other", [uuid4()], datetime.now(timezone.utc)),
    ("r", "yara", [], datetime.now(timezone.utc)),
    ("r", "yara", ["same", "same"], datetime.now(timezone.utc)),
    ("r", "yara", [uuid4()], datetime(2026, 1, 1)),
])
def test_invalid_detections_rejected(db, rule, source, ids, when):
    with pytest.raises(ValueError):
        db.insert_detection(rule, source, ids, when)
    assert db.connection.execute("SELECT count(*) FROM detections").fetchone()[0] == 0


def test_missing_event_rolls_back_entire_detection(db):
    alert = event()
    db.insert_alert(alert)
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_detection("rule", "yara", [alert.internal_id, uuid4()], datetime.now(timezone.utc))
    assert db.connection.execute("SELECT count(*) FROM detections").fetchone()[0] == 0
    assert db.connection.execute("SELECT count(*) FROM detection_events").fetchone()[0] == 0


def test_existing_database_initialization_is_idempotent(db):
    alert = event()
    db.insert_alert(alert)
    db.connection.execute("DROP TABLE detection_events")
    db.connection.execute("DROP TABLE detections")
    db.connection.commit()
    db.init_db()
    db.init_db()
    assert db.get_alert(alert.internal_id)["ground_truth_label"] == "benign"
    assert db.connection.execute("SELECT count(*) FROM detections").fetchone()[0] == 0
