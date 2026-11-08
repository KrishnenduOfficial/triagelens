"""Offline prompt-boundary regressions for structured evaluation metadata."""

import copy
import json

import httpx
import pytest

from src.engine.llm import GeminiTriageEngine
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline


def capture_evidence(record, enrichments=None):
    """Intercept the real outbound prompt, including the normal masking steps."""
    alert = NormalizedAlert(
        source_dataset="DATASET_CANARY", source_file="SOURCE_CANARY.evtx",
        event_type="ProcessCreate", original_record=record,
        ground_truth_label="malicious", extracted_indicators=["8.8.8.8"],
    )
    timeline = ThreatTimeline(
        grouping_key="GROUP_CANARY", alerts=[alert], total_events=1,
        enrichment_data=enrichments or [],
    )
    before = copy.deepcopy(timeline.model_dump())
    requests = []

    def send(url, **kwargs):
        requests.append(kwargs["json"])
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{
            "text": json.dumps({
                "severity": "LOW", "confidence_score": 0.6, "summary": "Offline fixture",
                "reasoning": [], "recommended_actions": [],
            })
        }]}}]})

    engine = GeminiTriageEngine(
        api_key="offline-placeholder", model="offline-model", fallback_models=[],
        enable_cache=False, request_sender=send,
    )
    assert engine.analyze_timeline(timeline) is not None
    assert len(requests) == 1
    prompt = requests[0]["contents"][0]["parts"][0]["text"]
    evidence = json.loads(prompt.split("<FORENSIC_EVIDENCE>\n", 1)[1].split("\n</FORENSIC_EVIDENCE>", 1)[0])
    assert timeline.model_dump() == before, "Sanitization must not mutate independent evidence or labels"
    assert "DATASET_CANARY" not in prompt
    assert "SOURCE_CANARY.evtx" not in prompt
    assert "GROUP_CANARY" not in prompt
    return evidence


def test_deep_metadata_removed_from_actual_prompt_with_source_records_preserved():
    evidence = capture_evidence({
        "Network": {"sessions": [{"observations": {
            "ground_truth_label": "malicious", "mitre_technique": "T1003.001",
            "source_file": "NESTED_SOURCE_CANARY.evtx", "source_id": "NESTED_ID_CANARY",
            "DestinationIp": "8.8.8.8", "DestinationPort": 443,
        }}]},
    })
    observed = evidence["events"][0]["details"]["Network"]["sessions"][0]["observations"]
    assert observed == {"DestinationIp": "8.8.8.8", "DestinationPort": 443}
    assert "CANARY" not in json.dumps(evidence)


@pytest.mark.parametrize("key", [
    "GroundTruthLabel", "ground-truth-label", " ground.truth.label ",
    "SourceFile", "source-file", "source.file", "sourceId", "source_id",
    "Classification", "verdictStatus", "mitreTechniqueId", "attack_technique",
    "groupingKey",
])
def test_metadata_key_variants_cannot_bypass_filter(key):
    evidence = capture_evidence({"Details": [{"nested": {key: "METADATA_CANARY", "ProcessId": 42}}]})
    observed = evidence["events"][0]["details"]["Details"]
    assert observed == [{"nested": {"ProcessId": 42}}]
    assert "METADATA_CANARY" not in json.dumps(evidence)


@pytest.mark.parametrize("value", [
    "malicious", " BENIGN ", "attack", "Suspicious", "true_positive", "false-positive",
    "True Negative", "FALSE_NEGATIVE", "T1003", " t1003.001 ",
])
def test_standalone_labels_and_technique_ids_removed_at_every_depth(value):
    evidence = capture_evidence({
        "Details": {"direct": value, "nested": [{"value": value, "Port": 0}, [value, "keep-this-observation"]]},
        "Action": value,
    })
    details = evidence["events"][0]["details"]
    assert "Action" not in details
    assert details["Details"] == {"nested": [{"Port": 0}, ["keep-this-observation"]]}


def test_forensic_strings_and_false_zero_null_values_remain_intact():
    record = {
        "CommandLine": r'cmd.exe /c echo benign > C:\attack-analysis\T1003-notes.txt',
        "FilePath": "./benign",
        "ImagePath": r'C:\Tools\benign.exe',
        "Network": {
            "SourceIp": "8.8.8.8", "SourcePort": 0,
            "protocol": "TCP", "blocked": False, "optional": None,
            "nested": [{"ProcessId": 1234567890123456, "bytes": 0}],
        },
        "unknown_top_level": "must-remain-excluded",
    }
    evidence = capture_evidence(record)
    details = evidence["events"][0]["details"]
    assert details == {k: v for k, v in record.items() if k != "unknown_top_level"}
    assert evidence["events"][0]["indicators"] == ["8.8.8.8"]


def test_independent_provider_detections_preserved_while_alert_labels_removed():
    intel = EnrichmentResult(
        indicator="8.8.8.8", indicator_type="ip", provider="VirusTotal",
        lookup_status="ok", is_malicious=True,
        raw_response={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 8, "suspicious": 2, "undetected": 3, "harmless": 1},
            "reputation": -5,
        }}},
    )
    evidence = capture_evidence({"Network": {"nested": {"is_malicious": True, "SourceIp": "8.8.8.8"}}}, [intel])
    assert evidence["events"][0]["details"]["Network"] == {"nested": {"SourceIp": "8.8.8.8"}}
    summary = evidence["enrichment_data"][0]
    assert summary["is_malicious"] is True
    assert summary["intel_summary"]["stats"] == {"malicious": 8, "suspicious": 2, "undetected": 3, "harmless": 1}
    assert summary["intel_summary"]["reputation"] == -5


def test_omitting_all_metadata_keeps_event_without_empty_detail_containers():
    evidence = capture_evidence({"Network": {"nested": [{"source_file": "NESTED_SOURCE_CANARY.evtx"}]}})
    assert "details" not in evidence["events"][0]
    assert evidence["total_events"] == 1
