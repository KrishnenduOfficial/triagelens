"""Adversarial and resilience test suite for LLM-Assisted Triage Engine.

Tests defense mechanisms against:
- Model hallucinations (markdown code fences, conversational fluff, trailing syntax)
- Schema violations and incomplete responses
- PII and credential leakage prevention
- Outages, rate limits (HTTP 429), server errors (HTTP 503), and network timeouts
"""

import os
from unittest.mock import MagicMock, patch
from uuid import uuid4
import httpx
import pytest

from src.engine.llm import GeminiTriageEngine
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline
from src.utils.masking import PIIScrubber


@pytest.fixture
def sample_timeline():
    """Generates a standard ThreatTimeline for testing."""
    alert1 = NormalizedAlert(
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="Security_4624.json",
        event_type="4624",
        original_record={"user": "attacker", "ip": "198.51.100.55"},
        extracted_indicators=["198.51.100.55"],
    )
    alert2 = NormalizedAlert(
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="Sysmon_1.json",
        event_type="ProcessCreate",
        original_record={"command_line": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6"},
        extracted_indicators=[],
    )
    enrichment = EnrichmentResult(
        indicator="198.51.100.55",
        indicator_type="ip",
        provider="AbuseIPDB",
        is_malicious=True,
        raw_response={"abuseConfidenceScore": 100},
    )
    return ThreatTimeline(
        grouping_key="EVTX-ATTACK-SAMPLES",
        alerts=[alert1, alert2],
        enrichment_data=[enrichment],
        total_events=2,
    )


def build_gemini_api_response(text: str, status_code: int = 200) -> MagicMock:
    """Helper to construct a mock httpx.Response mimicking Google Gemini generateContent."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = status_code
    mock_resp.text = text
    mock_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": text}],
                    "role": "model",
                },
                "finishReason": "STOP",
            }
        ]
    }
    return mock_resp


# =====================================================================
# 1. Initialization and Configuration Tests
# =====================================================================


def test_api_key_missing_raises_value_error(monkeypatch):
    """Verify engine refuses to initialize without an API key."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY is required"):
        GeminiTriageEngine()


def test_api_key_provided_explicitly():
    """Verify engine accepts explicit API key argument."""
    engine = GeminiTriageEngine(api_key="explicit_test_key_12345")
    assert engine.api_key == "explicit_test_key_12345"


# =====================================================================
# 2. Hallucination Defense Tests
# =====================================================================


def test_hallucination_defense_markdown_code_fences(sample_timeline):
    """Verify engine parses JSON enclosed in markdown fences (```json ... ```)."""
    raw_response = """```json
{
    "severity": "HIGH",
    "confidence_score": 0.88,
    "summary": "Credential dumping activity detected via PowerShell invocation.",
    "reasoning": [
        "Base64-encoded command line matches known offensive tooling",
        "Source IP address exhibits 100% AbuseIPDB malicious confidence"
    ],
    "recommended_actions": [
        "Isolate host from local subnet",
        "Revoke compromised user session tokens"
    ]
}
```"""
    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is not None
    assert verdict.timeline_id == sample_timeline.timeline_id
    assert verdict.severity == "HIGH"
    assert verdict.confidence_score == 0.88
    assert "Credential dumping" in verdict.summary
    assert len(verdict.reasoning) == 2
    assert len(verdict.recommended_actions) == 2
    assert verdict.raw_llm_response == raw_response


def test_hallucination_defense_conversational_fluff(sample_timeline):
    """Verify engine strips leading and trailing conversational commentary."""
    raw_response = """Hello analyst! I have evaluated the security events you submitted.
Here is the structured incident verdict:

{
    "severity": "CRITICAL",
    "confidence_score": 0.96,
    "summary": "Active ransomware payload execution confirmed across endpoints.",
    "reasoning": [
        "Mass file renaming detected",
        "Known C2 IP address communicated"
    ],
    "recommended_actions": [
        "Trigger immediate fleet-wide EDR network isolation",
        "Activate incident response team"
    ]
}

Please let me know if you would like me to drill down into any specific artifact."""

    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is not None
    assert verdict.severity == "CRITICAL"
    assert verdict.confidence_score == 0.96
    assert "ransomware" in verdict.summary.lower()


def test_hallucination_defense_trailing_commas(sample_timeline):
    """Verify engine recovers from common LLM syntax error: trailing commas."""
    raw_response = """{
    "severity": "LOW",
    "confidence_score": 0.35,
    "summary": "Benign external vulnerability scanning against edge firewall.",
    "reasoning": [
        "Single SYN packet to closed port",
    ],
    "recommended_actions": [
        "No action required; log retained",
    ],
}"""
    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is not None
    assert verdict.severity == "LOW"
    assert verdict.confidence_score == 0.35


# =====================================================================
# 3. Schema Violation and Malformed Output Defense Tests
# =====================================================================


def test_schema_violation_missing_severity(sample_timeline):
    """Verify engine catches missing required 'severity' field and returns None gracefully."""
    raw_response = """{
    "confidence_score": 0.9,
    "summary": "Missing severity level entirely",
    "reasoning": ["Incomplete payload"],
    "recommended_actions": ["None"]
}"""
    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


def test_schema_violation_missing_confidence(sample_timeline):
    """Verify engine catches missing confidence score."""
    raw_response = """{
    "severity": "HIGH",
    "summary": "Missing confidence score",
    "reasoning": ["Incomplete payload"],
    "recommended_actions": ["None"]
}"""
    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


def test_schema_violation_invalid_confidence_range(sample_timeline):
    """Verify engine catches confidence scores outside [0.0, 1.0]."""
    raw_response = """{
    "severity": "HIGH",
    "confidence_score": 1.5,
    "summary": "Confidence out of bounds",
    "reasoning": ["Confidence > 1.0"],
    "recommended_actions": ["None"]
}"""
    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


def test_schema_violation_invalid_severity_label(sample_timeline):
    """Verify engine catches invalid severity levels (not in Literal enum)."""
    raw_response = """{
    "severity": "SUPER_EXTREME_DANGER",
    "confidence_score": 0.95,
    "summary": "Non-standard severity string",
    "reasoning": ["Invalid severity value"],
    "recommended_actions": ["None"]
}"""
    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


def test_unparsable_non_json_response(sample_timeline):
    """Verify engine survives LLM refusal or garbage natural language response."""
    raw_response = "I am an AI assistant and cannot evaluate security events without authorization."
    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response(raw_response)

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


# =====================================================================
# 4. PII & Credential Leakage Prevention Tests
# =====================================================================


def test_pii_leakage_prevention_on_wire():
    """Verify that sensitive emails, credit cards, and AWS/GCP keys never leave unmasked."""
    # Alert loaded with sensitive PII and cloud credentials
    sensitive_alert = NormalizedAlert(
        source_dataset="EVTX-ATTACK-SAMPLES",
        source_file="Security_Sensitive.json",
        event_type="4624",
        original_record={
            "admin_contact": "soc_incident_lead@secret-corp.internal",
            "developer_email": "john.doe+aws-admin@cloudtech.org",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "gcp_api_key": "AIzaSyD-1234567890abcdefghijklmnopqrst",
            "customer_credit_card": "4532-0150-1234-5678",
            "customer_amex": "378282246310005",
            "target_ip": "198.51.100.77",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        extracted_indicators=["198.51.100.77"],
    )

    sensitive_timeline = ThreatTimeline(
        grouping_key="SENSITIVE_INVESTIGATION",
        alerts=[sensitive_alert],
        total_events=1,
    )

    engine = GeminiTriageEngine(api_key="mock_key")

    mock_resp = build_gemini_api_response("""{
        "severity": "INFORMATIONAL",
        "confidence_score": 0.99,
        "summary": "Scrubbing verification",
        "reasoning": ["All secrets sanitized"],
        "recommended_actions": ["None"]
    }""")

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        verdict = engine.analyze_timeline(sensitive_timeline)

    assert verdict is not None
    assert mock_post.called

    # Extract the payload transmitted in the simulated HTTP request
    call_kwargs = mock_post.call_args.kwargs
    sent_payload = call_kwargs["json"]
    sent_prompt_text = sent_payload["contents"][0]["parts"][0]["text"]

    # 1. Assert PII and Credentials are completely absent
    assert "soc_incident_lead@secret-corp.internal" not in sent_prompt_text
    assert "john.doe+aws-admin@cloudtech.org" not in sent_prompt_text
    assert "AKIAIOSFODNN7EXAMPLE" not in sent_prompt_text
    assert "AIzaSyD-1234567890abcdefghijklmnopqrst" not in sent_prompt_text
    assert "4532-0150-1234-5678" not in sent_prompt_text
    assert "378282246310005" not in sent_prompt_text

    # 2. Assert Redaction Tokens are present
    assert "[EMAIL_REDACTED]" in sent_prompt_text
    assert "[SECRET_REDACTED]" in sent_prompt_text
    assert "[CC_REDACTED]" in sent_prompt_text

    # 3. Assert Benign Security Indicators were NOT destroyed
    assert "198.51.100.77" in sent_prompt_text
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in sent_prompt_text


# =====================================================================
# 5. Outage, Rate Limit, and Network Resilience Tests
# =====================================================================


def test_outage_simulation_http_503(sample_timeline):
    """Verify engine handles Gemini 503 Service Unavailable gracefully without crashing."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 503
    mock_resp.text = "Service Temporarily Unavailable"

    engine = GeminiTriageEngine(api_key="mock_key")

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


def test_fallback_on_primary_model_http_503(sample_timeline):
    """Verify engine falls back to secondary model when primary returns 503."""
    import json
    mock_503 = MagicMock(spec=httpx.Response)
    mock_503.status_code = 503
    mock_503.text = json.dumps({"error": {"code": 503, "message": "High demand"}})

    mock_200 = build_gemini_api_response("""{
        "severity": "HIGH",
        "confidence_score": 0.85,
        "summary": "Fallback model triage",
        "reasoning": ["Primary 503, secondary recovered"],
        "recommended_actions": ["Isolate host"]
    }""")

    engine = GeminiTriageEngine(
        api_key="mock_key",
        model="gemini-3.8-flash",
        fallback_models=["gemini-flash-lite-latest"],
    )

    with patch("httpx.post", side_effect=[mock_503, mock_200]) as mock_post:
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is not None
    assert verdict.severity == "HIGH"
    assert verdict.confidence_score == 0.85
    assert mock_post.call_count == 2


def test_outage_simulation_http_429_rate_limit(sample_timeline):
    """Verify engine handles Gemini 429 Resource Exhausted gracefully without crashing."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 429
    mock_resp.text = "Resource exhausted: Rate limit exceeded."

    engine = GeminiTriageEngine(api_key="mock_key")

    with patch("httpx.post", return_value=mock_resp):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


def test_outage_simulation_timeout_exception(sample_timeline):
    """Verify engine handles connection or read timeout cleanly without crashing."""
    engine = GeminiTriageEngine(api_key="mock_key", timeout=5.0)

    with patch("httpx.post", side_effect=httpx.TimeoutException("Read timed out")):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


def test_outage_simulation_network_request_error(sample_timeline):
    """Verify engine handles socket/DNS network errors cleanly."""
    engine = GeminiTriageEngine(api_key="mock_key")

    with patch("httpx.post", side_effect=httpx.ConnectError("Connection refused by peer")):
        verdict = engine.analyze_timeline(sample_timeline)

    assert verdict is None


# =====================================================================
# 6. Direct PIIScrubber Adversarial Tests
# =====================================================================


def test_pii_scrubber_adversarial_patterns():
    """Verify PIIScrubber against diverse adversarial and edge-case patterns."""
    scrubber = PIIScrubber()

    # Emails
    assert scrubber.scrub("user@corp.com") == "[EMAIL_REDACTED]"
    assert scrubber.scrub("user+tag.123@sub-domain.co.uk") == "[EMAIL_REDACTED]"
    assert scrubber.scrub("Contact <admin@test.org> immediately") == "Contact <[EMAIL_REDACTED]> immediately"

    # Credit Cards
    assert scrubber.scrub("Visa: 4111-2222-3333-4444") == "Visa: [CC_REDACTED]"
    assert scrubber.scrub("Mastercard: 5500 0000 0000 0004") == "Mastercard: [CC_REDACTED]"
    assert scrubber.scrub("Amex: 3782-822463-10005") == "Amex: [CC_REDACTED]"
    assert scrubber.scrub("Raw digits: 4111222233334444") == "Raw digits: [CC_REDACTED]"

    # AWS & GCP Secrets
    assert scrubber.scrub("Key AKIA1234567890ABCDEF in log") == "Key [SECRET_REDACTED] in log"
    assert scrubber.scrub("GCP AIzaSyD-1234567890abcdefghijklmnopqrst key") == "GCP [SECRET_REDACTED] key"
    assert scrubber.scrub("Token ghp_123456789012345678901234567890123456") == "Token [SECRET_REDACTED]"

    # Bearer tokens
    assert scrubber.scrub("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz") == (
        "Authorization: Bearer [SECRET_REDACTED]"
    )

    # Key-value secrets
    assert scrubber.scrub('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"') == (
        'aws_secret_access_key = "[SECRET_REDACTED]"'
    )
    assert scrubber.scrub('api_key: "super_secret_token_12345"') == 'api_key: "[SECRET_REDACTED]"'

    # Empty and None values
    assert scrubber.scrub("") == ""
    assert scrubber.scrub(None) == ""


# =====================================================================
# 7. Ground Truth & Provenance Isolation Tests (ADR-008)
# =====================================================================


def test_no_ground_truth_or_provenance_leakage_in_prompt():
    """Verify that no ground truth labels, technique IDs, or provenance metadata reach the LLM prompt.

    Enforces ADR-008: AI predictions and ground truth must remain completely independent.
    """
    classified_keys = [
        "ground_truth_label",
        "mitre_technique",
        "technique",
        "mitre",
        "attack_technique",
        "is_malicious",
        "malicious",
        "ground_truth",
        "label",
        "verdict",
    ]

    leak_alert = NormalizedAlert(
        source_dataset="attack_apt29_samples",
        source_file="attack_lsass_dump.json",
        event_type="ProcessCreate",
        timestamp="2026-11-05T08:00:00Z",
        original_record={
            "ProcessName": "powershell.exe",
            "CommandLine": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6",
            "User": "SYSTEM",
            "mitre_technique": "T1003.001",
            "technique": "T1003",
            "attack_technique": "Credential Dumping",
            "is_malicious": True,
            "malicious": "yes",
            "ground_truth": "malicious",
            "label": "malicious",
            "verdict": "malicious",
        },
        extracted_indicators=["powershell.exe"],
        ground_truth_label="malicious",
    )

    leak_timeline = ThreatTimeline(
        grouping_key="attack_apt29_samples",
        alerts=[leak_alert],
        total_events=1,
    )

    engine = GeminiTriageEngine(api_key="mock_key")
    mock_resp = build_gemini_api_response("""{
        "severity": "CRITICAL",
        "confidence_score": 0.99,
        "summary": "Mimikatz detected",
        "reasoning": ["Offensive tool"],
        "recommended_actions": ["Isolate"]
    }""")

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        engine.analyze_timeline(leak_timeline)

    assert mock_post.called
    call_args = mock_post.call_args
    sent_payload = call_args.kwargs["json"]
    sent_prompt = sent_payload["contents"][0]["parts"][0]["text"]

    # 1. Assert label values and keywords are absent
    for forbidden_val in ("malicious", "attack", "benign", "T1003.001", "T1003", "Credential Dumping"):
        assert forbidden_val.lower() not in sent_prompt.lower(), f"Prompt leaked value: {forbidden_val}"

    # 2. Assert all _classify_alert_label keys are absent
    for forbidden_key in classified_keys:
        assert f'"{forbidden_key}"' not in sent_prompt, f"Prompt leaked key: {forbidden_key}"

    # 3. Assert provenance names and dataset indicators are neutralized
    assert "attack_apt29_samples" not in sent_prompt, "Prompt leaked source_dataset / grouping_key"
    assert "attack_lsass_dump.json" not in sent_prompt, "Prompt leaked source_file"


