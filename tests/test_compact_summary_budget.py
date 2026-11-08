"""Offline byte-budget checks at the actual masked prompt boundary."""

import copy
import json

import httpx
import pytest

from src.engine.llm import GeminiTriageEngine, summarize_enrichment
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline
from src.utils.masking import PIIScrubber


def enrichment(provider, raw):
    return EnrichmentResult(
        indicator="example.org", indicator_type="domain", provider=provider,
        lookup_status="ok", is_malicious=True, raw_response=raw,
    )


def capture_summary(provider, raw):
    result = enrichment(provider, raw)
    before = copy.deepcopy(result.model_dump())
    requests = []

    def send(url, **kwargs):
        requests.append(kwargs["json"])
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{
            "text": json.dumps({"severity": "LOW", "confidence_score": 0.6,
                                "summary": "Offline fixture", "reasoning": [], "recommended_actions": []})
        }]}}]})

    engine = GeminiTriageEngine(
        api_key="offline-placeholder", model="offline-model", fallback_models=[],
        enable_cache=False, request_sender=send,
    )
    assert engine.analyze_timeline(ThreatTimeline(grouping_key="test", enrichment_data=[result])) is not None
    assert len(requests) == 1
    prompt = requests[0]["contents"][0]["parts"][0]["text"]
    start = prompt.index('"intel_summary": ') + len('"intel_summary": ')
    summary, end = json.JSONDecoder().raw_decode(prompt, start)
    fragment = prompt[start:end]
    assert len(fragment.encode("utf-8")) < 800, "Count the actual formatted, escaped prompt fragment"
    assert result.model_dump() == before
    return summary, prompt


OVERSIZED = [
    ("VirusTotal", {"data": {"attributes": {"last_analysis_stats": {"malicious": 8},
        "popular_threat_classification": {"suggested_threat_label": "x" * 10000}}}}),
    ("VirusTotal", {"data": {"attributes": {"meaningful_name": "x" * 10000}}}),
    ("AbuseIPDB", {"data": {"abuseConfidenceScore": 90, "totalReports": 4, "countryCode": "x" * 10000}}),
    ("AbuseIPDB", {"data": {"abuseConfidenceScore": 90, "totalReports": 4, "isp": chr(0x1f600) * 100}}),
    ("URLhaus", {"query_status": "ok", "tags": ["x" * 1000] * 10}),
    ("URLhaus", {"query_status": "ok", "threat": "x" * 10000}),
    ("custom", {"field_" + str(i): "x" * 30 for i in range(50)}),
    ("VirusTotal", {"data": {"attributes": {"last_analysis_stats": {"malicious": 10**1000}}}}),
    ("URLhaus", {"query_status": "ok", "tags": ['"\\\n' * 1000]}),
]


@pytest.mark.parametrize("provider,raw", OVERSIZED)
def test_all_provider_branches_enforce_budget_in_actual_prompt(provider, raw):
    summary, _ = capture_summary(provider, raw)
    assert summary["summary_truncated"] is True


@pytest.mark.parametrize("provider,raw", OVERSIZED)
def test_standalone_summary_utility_also_enforces_budget(provider, raw):
    source = enrichment(provider, raw)
    before = copy.deepcopy(source.model_dump())
    summary = summarize_enrichment(source)
    assert len(json.dumps(summary, indent=2).encode("utf-8")) < 800
    assert summary["summary_truncated"] is True
    assert source.model_dump() == before


def test_masking_expansion_cannot_bypass_final_budget():
    raw = {"note": "a@b.co " * 75}
    assert len(json.dumps(raw, indent=2).encode("utf-8")) < 800
    summary, prompt = capture_summary("custom", raw)
    assert summary["summary_truncated"] is True
    assert "a@b.co" not in prompt
    assert "[EMAIL_REDACTED]" in summary["note"]


def test_secret_redaction_precedes_string_truncation():
    key = "AIza" + "Z" * 35
    summary, prompt = capture_summary("custom", {"note": "x" * 699 + " " + key, "z": "y" * 1000})
    assert "AIza" not in prompt, "Truncation must not turn a recognizable key into an unmasked prefix"
    assert summary["summary_truncated"] is True


@pytest.mark.parametrize("target_size", [798, 799, 800, 801])
def test_strict_boundary_includes_escaping_and_nested_indentation(target_size):
    # An intel_summary object starts six columns into the evidence JSON.
    empty = json.dumps({"note": ""}, indent=2)
    overhead = len(empty.encode("utf-8")) + 6 * empty.count("\n")
    text = "x" * (target_size - overhead)
    summary, _ = capture_summary("custom", {"note": text})
    if target_size < 800:
        assert summary == {"note": text}
    else:
        assert summary["summary_truncated"] is True
        assert len(summary["note"]) < len(text)


def test_numeric_and_status_evidence_prioritized_over_optional_text():
    summary, _ = capture_summary("VirusTotal", {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 72, "suspicious": 1, "undetected": 7, "harmless": 0},
        "reputation": -50, "popular_threat_classification": {"suggested_threat_label": "x" * 10000},
        "comments": [{"text": "COMMENT_CANARY"}], "scans": {"SCAN_CANARY": "x" * 5000},
    }}})
    assert summary["stats"] == {"malicious": 72, "suspicious": 1, "undetected": 7, "harmless": 0}
    assert summary["reputation"] == -50
    assert "COMMENT_CANARY" not in json.dumps(summary)
    assert "SCAN_CANARY" not in json.dumps(summary)
    urlhaus, _ = capture_summary("URLhaus", {"query_status": "ok", "url_status": "online", "tags": ["x" * 1000] * 10})
    assert urlhaus["query_status"] == "ok"
    assert urlhaus["url_status"] == "online"


def test_oversized_numeric_evidence_is_omitted_without_fabricated_counts():
    summary, _ = capture_summary("VirusTotal", {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 10**1000, "suspicious": 2, "undetected": 3, "harmless": 4},
    }}})
    assert "malicious" not in summary["stats"]
    assert summary["stats"]["suspicious"] == 2
    assert summary["summary_truncated"] is True


@pytest.mark.parametrize("value", [float("nan"), float("inf"), "not-a-count"])
def test_invalid_counts_are_omitted_without_breaking_triage(value):
    source = enrichment("VirusTotal", {"data": {"attributes": {
        "last_analysis_stats": {"malicious": value, "suspicious": 2},
    }}})
    summary = summarize_enrichment(source)
    assert "malicious" not in summary["stats"]
    assert summary["stats"]["suspicious"] == 2
    assert summary["summary_truncated"] is True


def test_normal_summary_stays_unchanged_and_repeatable():
    source = enrichment("URLhaus", {"query_status": "ok", "url_status": "online", "tags": ["mozi", "elf"]})
    expected = {"query_status": "ok", "url_status": "online", "tags": ["mozi", "elf"]}
    assert summarize_enrichment(source) == expected
    first, _ = capture_summary(source.provider, source.raw_response)
    second, _ = capture_summary(source.provider, source.raw_response)
    assert first == second == expected


@pytest.mark.parametrize("masked_payload", [
    "not-json", "[]", "null",
    pytest.param(json.dumps({"enrichment_data": "bad"}, indent=2), id="entries_not_list"),
    pytest.param(json.dumps({"enrichment_data": [1]}, indent=2), id="entry_not_object"),
    pytest.param(json.dumps({"enrichment_data": [{"intel_summary": "x" * 1000}]}, indent=2), id="summary_not_object"),
])
def test_invalid_final_masked_payload_withholds_request(masked_payload):
    class BrokenScrubber(PIIScrubber):
        def scrub(self, text):
            return masked_payload if text.startswith("{\n") else super().scrub(text)

    calls = []

    def send(*args, **kwargs):
        calls.append(kwargs)
        raise AssertionError("Invalid masked payload must never be sent")

    engine = GeminiTriageEngine(
        api_key="offline-placeholder", fallback_models=[], enable_cache=False,
        request_sender=send, scrubber=BrokenScrubber(),
    )
    assert engine.analyze_timeline(ThreatTimeline(grouping_key="test")) is None
    assert not calls
