"""Offline class-artifact audit with fabricated events."""

from datetime import datetime, timezone
import json

from src.engine.ground_truth import DatasetGroundTruthMapper
from src.engine.shortcut_check import check_shortcuts, check_source_shortcuts
from src.models.alert import NormalizedAlert


def alert(root, name, label, channel="Security", details=None, day=1):
    obj = NormalizedAlert(source_dataset="fixture", source_file=str(root / name), event_type="1",
                          timestamp=datetime(2026, 1, day, tzinfo=timezone.utc) if day else None,
                          original_record={"Channel": channel, "Details": details or {}})
    return DatasetGroundTruthMapper(root, file_labels={name: label}).map_alert(obj)


def test_detects_perfect_artifact_separation_without_disclosing_artifacts(tmp_path):
    left = alert(tmp_path, "private-baseline.evtx", "benign", "Security", {"User": "x"}, 1)
    right = alert(tmp_path, "secret-attack.evtx", "malicious", "Sysmon", {"Process": "x"}, 2)
    result = check_shortcuts([left, right])
    assert result["status"] == "checked"
    for name in ("channel", "filename", "filename_token", "field_presence", "time_range"):
        assert result["checks"][name]["perfect_separation"]
    assert not result["checks"]["extension"]["perfect_separation"]
    assert result["checks"]["channel"]["total_variation"] == 1
    assert all(value not in json.dumps(result) for value in ("private", "secret", "Sysmon", "Process"))


def test_overlap_does_not_prove_no_shortcuts_and_incomplete_time_is_explicit(tmp_path):
    left = alert(tmp_path, "same.evtx", "benign", day=None)
    right = alert(tmp_path, "same.evtx", "malicious", day=1)
    result = check_shortcuts([left, right])
    assert result["checks"]["channel"]["total_variation"] == 0
    assert not result["checks"]["filename"]["perfect_separation"]
    assert not result["checks"]["field_presence"]["perfect_separation"]
    assert result["checks"]["time_range"] == {"status": "incomplete", "missing": {"benign": 1, "malicious": 0}}


def test_unreviewed_and_conflicting_truth_are_excluded(tmp_path):
    known = alert(tmp_path, "known.evtx", "benign")
    unknown = known.model_copy(update={"ground_truth_metadata": None, "ground_truth_label": "malicious"})
    conflict = known.model_copy(update={"ground_truth_metadata": known.ground_truth_metadata.model_copy(
        update={"status": "conflict"}), "ground_truth_label": "malicious"})
    result = check_shortcuts(iter([known, unknown, conflict]))
    assert result == {"counts": {"benign": 1, "malicious": 0}, "excluded_unmapped": 2,
                      "checks": {}, "status": "insufficient_classes"}


def test_partial_channel_difference_is_quantified(tmp_path):
    events = [alert(tmp_path, "b.evtx", "benign"), alert(tmp_path, "b.evtx", "benign"),
              alert(tmp_path, "m.evtx", "malicious"), alert(tmp_path, "m.evtx", "malicious", "Other")]
    result = check_shortcuts(events)
    assert result["checks"]["channel"] == {"perfect_separation": False, "total_variation": 0.5}


def test_source_comparison_accepts_unknown_labels_without_mutating_them(tmp_path):
    baseline = alert(tmp_path, "baseline.evtx", "benign").model_copy(
        update={"ground_truth_metadata": None, "ground_truth_label": None})
    attack = alert(tmp_path, "attack.evtx", "malicious", "Sysmon").model_copy(
        update={"ground_truth_metadata": None, "ground_truth_label": None})
    before = [a.model_dump() for a in (baseline, attack)]
    result = check_source_shortcuts(iter([baseline]), iter([attack]))
    assert result["counts"] == {"baseline": 1, "attack_associated": 1}
    assert result["checks"]["channel"]["perfect_separation"]
    assert [a.model_dump() for a in (baseline, attack)] == before
    assert check_shortcuts([baseline, attack])["status"] == "insufficient_classes"
