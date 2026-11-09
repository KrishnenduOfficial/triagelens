"""Offline tests for fixed cohort partitioning and evaluation repetitions."""

from copy import deepcopy
import csv
import io
import json
from types import SimpleNamespace

import pytest

from scripts.run_evaluation import protocol_command, protocol_intake, protocol_settings, run_protocol
from src.engine.evtx import EvtxIntakeEngine
from test_evtx import Parser, record
from src.engine.evaluation_protocol import (frozen_configuration, make_manifest,
                                             select_split, summarize, timeline_identity,
                                             import_review, write_review_csv, collect_review_samples)
from src.engine.provenance import AcquisitionOutcome
from conftest import PipelineTestEngine
from src.models.alert import GroundTruthMetadata, NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def case(i, *, source=None, event=None, label="benign"):
    source = source or f"reviewed/{i}.evtx"
    truth = GroundTruthMetadata(relative_path=source, status="mapped",
                                label_sources={"review": label}, technique_ids=["T1059"])
    alert = NormalizedAlert(source_dataset="reviewed", source_file=source, event_type="1",
                            original_record={"EventID": 1, "Value": i if event is None else event},
                            ground_truth_label=label, ground_truth_metadata=truth)
    return ThreatTimeline(grouping_key=f"host-{i}", alerts=[alert], total_events=1)


def cohort():
    return [case(i, label="malicious" if i % 2 else "benign") for i in range(30)]


class OfflineEngine:
    PROVIDER_ID = "fixture"
    POLICY_VERSION = "triage-v1"
    EVIDENCE_CONTRACT_VERSION = "fixture"
    model = "fixture"
    fallback_models = []
    timeout = 5
    _rpm, _tpm, _token_estimate, _max_wait = 5, 10000, 1000, 0
    enable_cache = False

    def __init__(self, origin="fresh"):
        self.origin = origin
        self.calls = 0

    def _system_prompt(self):
        return "fixture"

    def _generation_settings(self, model):
        return {"model": model}

    def acquire_timeline(self, timeline, *, on_acquisition):
        self.calls += 1
        on_acquisition(self.origin)
        verdict = TriageVerdict(timeline_id=timeline.timeline_id, severity="HIGH",
                                confidence_score=0.8, summary="fixture", reasoning=[],
                                recommended_actions=[], raw_llm_response="{}")
        return AcquisitionOutcome(verdict, self.origin)


def test_split_is_stable_grouped_and_rejects_mutation():
    timelines = cohort()
    timelines.append(case(100, source="reviewed/0.evtx"))
    timelines.append(case(101, source="reviewed/101.evtx", event=1))
    manifest = make_manifest(timelines, "fixed-seed")
    assert manifest == make_manifest(list(reversed(timelines)), "fixed-seed")
    assignments = manifest["assignments"]
    assert assignments[timeline_identity(timelines[0])] == assignments[timeline_identity(timelines[-2])]
    assert assignments[timeline_identity(timelines[1])] == assignments[timeline_identity(timelines[-1])]
    altered = deepcopy(timelines)
    altered[0].alerts[0].ground_truth_label = "malicious"
    with pytest.raises(ValueError, match="changed"):
        select_split(altered, manifest, "test")


def test_test_run_requires_freeze_and_fresh_repetitions(tmp_path):
    timelines = cohort()
    manifest = make_manifest(timelines, "fixed-seed")
    engine = OfflineEngine()
    settings = protocol_settings(engine)
    frozen = frozen_configuration(manifest, settings)
    with pytest.raises(ValueError, match="frozen"):
        run_protocol(timelines, manifest, "test", settings, {}, engine, tmp_path / "test.db")
    assert engine.calls == 0
    reports = run_protocol(timelines, manifest, "test", settings, frozen, engine,
                           tmp_path / "test.db", repetitions=2)
    count = len(select_split(timelines, manifest, "test"))
    assert engine.calls == 2 * count
    assert reports[0]["run_id"] != reports[1]["run_id"]
    assert reports[0]["acquisition_origins"] == {"fresh": count}
    assert reports[0]["metrics"]["total"] == count
    assert len(reports[0]["errors"]) == reports[0]["metrics"]["fp"]
    assert all(r["review_status"] == "pending analyst review" for r in reports[0]["errors"])


def test_cached_and_changed_settings_are_rejected(tmp_path):
    timelines = cohort()
    manifest = make_manifest(timelines, "fixed-seed")
    engine = OfflineEngine("cache")
    settings = protocol_settings(engine)
    with pytest.raises(ValueError, match="settings"):
        run_protocol(timelines, manifest, "development", {**settings, "model": "other"}, None,
                     engine, tmp_path / "changed.db")
    with pytest.raises(ValueError, match="Cached"):
        run_protocol(timelines, manifest, "development", settings, None, engine, tmp_path / "cache.db")


def test_undefined_metrics_and_empty_latency_are_explicit():
    report = summarize([])
    assert report["metrics"]["accuracy"] is None
    assert report["metrics"]["accuracy_ci95"] is None
    assert report["latency_seconds"]["mean"] is None


def test_offline_cli_prepares_and_estimates_without_sending(tmp_path, monkeypatch):
    timelines = cohort()
    cohort_file, manifest_file, estimate_file = (tmp_path / name for name in
                                                 ("cohort.json", "manifest.json", "estimate.json"))
    cohort_file.write_text(json.dumps([t.model_dump(mode="json") for t in timelines]), encoding="utf-8")
    monkeypatch.setattr("scripts.run_evaluation.GroqTriageEngine", lambda **kw: OfflineEngine())
    args = SimpleNamespace(protocol_cohort=str(cohort_file), protocol_out=str(manifest_file),
                           protocol_mode="prepare", protocol_seed="fixed-seed", protocol_test_percent=20,
                           protocol_manifest=None, protocol_split="test", protocol_repetitions=3,
                           end_to_end=False, max_lookups=None, pacing=2.0)
    protocol_command(args)
    args.protocol_mode, args.protocol_manifest, args.protocol_out = "estimate", str(manifest_file), str(estimate_file)
    protocol_command(args)
    estimate = json.loads(estimate_file.read_text(encoding="utf-8"))
    assert estimate["max_provider_attempts"] == estimate["timelines"] * 3
    assert estimate["estimated_tokens"] == estimate["max_provider_attempts"] * 1000
    assert estimate["token_estimate_is_not_a_cap"] is True
    with pytest.raises(FileExistsError):
        protocol_command(args)


def test_intake_requires_review_and_enforces_event_cap(tmp_path, monkeypatch):
    (tmp_path / "sample.evtx").touch()
    factory = lambda **kwargs: EvtxIntakeEngine(lambda stream: Parser([record(), record()]), **kwargs)
    monkeypatch.setattr("scripts.run_evaluation.EvtxIntakeEngine", factory)
    source = {"root": str(tmp_path), "file": "sample.evtx", "source": "attack",
              "label": "malicious", "reviewed": True}
    timelines, counts = protocol_intake([source], 2)
    assert counts["events"] == 2
    assert all(a.ground_truth_label == "malicious" for t in timelines for a in t.alerts)
    with pytest.raises(ValueError, match="cap"):
        protocol_intake([source], 1)
    with pytest.raises(ValueError, match="review"):
        protocol_intake([{**source, "reviewed": False}], 2)
    with pytest.raises(ValueError, match="only once"):
        protocol_intake([source, source], 5)


def review_csv(alerts, decisions):
    stream = io.StringIO(newline="")
    write_review_csv(stream, alerts)
    stream.seek(0)
    reader = csv.DictReader(stream)
    rows = list(reader)
    for row, decision in zip(rows, decisions):
        row.update(decision=decision, reason="Independent evidence reviewed", reviewer="analyst")
    result = io.StringIO(newline="")
    writer = csv.DictWriter(result, fieldnames=reader.fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    result.seek(0)
    return result


def test_event_review_import_preserves_evidence_and_excludes_uncertain():
    alerts = [case(i).alerts[0].model_copy(update={"ground_truth_label": None,
                                                  "ground_truth_metadata": None}) for i in range(3)]
    timelines, uncertain = import_review(alerts, review_csv(alerts, ["malicious", "benign", "uncertain"]))
    assert uncertain == 1 and len(timelines) == 2
    assert [t.alerts[0].ground_truth_label for t in timelines] == ["malicious", "benign"]
    assert timelines[0].alerts[0].original_record == alerts[0].original_record
    assert "analyst" not in str(timelines[0].alerts[0].original_record)
    assert all(len(t.alerts) == 1 for t in timelines)


def test_imported_review_truth_cannot_change_inference_payload():
    alert = case(1, source="secret_provenance_file.evtx").alerts[0].model_copy(
        update={"ground_truth_label": None, "ground_truth_metadata": None})
    malicious = import_review([alert], review_csv([alert], ["malicious"]))[0][0]
    benign = import_review([alert], review_csv([alert], ["benign"]))[0][0]
    benign.timeline_id = malicious.timeline_id
    engine = PipelineTestEngine(api_key="offline")
    payload = engine._build_sanitized_triage_payload(malicious)
    assert payload == engine._build_sanitized_triage_payload(benign)
    assert "secret_provenance_file" not in json.dumps(payload)
    assert "Independent evidence reviewed" not in json.dumps(payload)


def test_event_review_requires_complete_rationale_and_unchanged_evidence():
    alert = case(1).alerts[0].model_copy(update={"ground_truth_label": None,
                                               "ground_truth_metadata": None})
    for decision in ("unreviewed", "unknown", ""):
        with pytest.raises(ValueError, match="decision"):
            import_review([alert], review_csv([alert], [decision]))
    stream = review_csv([alert], ["benign"])
    changed = alert.model_copy(update={"event_type": "999"})
    with pytest.raises(ValueError, match="exactly one"):
        import_review([changed], stream)
    stream = review_csv([alert], ["malicious"])
    text = stream.getvalue().replace("Independent evidence reviewed", "")
    with pytest.raises(ValueError, match="reviewer"):
        import_review([alert], io.StringIO(text))


def test_review_sampling_is_bounded_and_unlabelled(tmp_path, monkeypatch):
    path = tmp_path / "review.evtx"
    path.touch()
    factory = lambda: EvtxIntakeEngine(lambda stream: Parser([record(), record(), record()]))
    monkeypatch.setattr("src.engine.evaluation_protocol.EvtxIntakeEngine", factory)
    alerts, stats = collect_review_samples([path], per_file=2)
    assert stats[0]["events"] == 2
    assert all(alert.ground_truth_label is None and alert.ground_truth_metadata is None for alert in alerts)
