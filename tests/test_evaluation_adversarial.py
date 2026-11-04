"""Military-grade adversarial and statistical test suite for the Accuracy and Validation Engine.

Tests:
- Division by Zero Defense: Zero events, pure FP, pure FN, pure TN, and pure TP.
- Extreme Imbalanced Data Defense: 9,999 TN and 1 FN with high-precision statistical verification.
- Mapping Defense: Conflict resolution across alerts within a timeline (benign vs malicious precedence).
- Missing Data Handling: Unlabeled alerts safely categorized as "Unknown" without polluting confusion matrix.
- Severity Boundary Defense: Mapping of CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL to binary predictions.
"""

from uuid import uuid4
import pytest

from src.engine.evaluation import AccuracyTracker
from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def create_verdict(severity: str) -> TriageVerdict:
    """Helper to construct a valid TriageVerdict for testing."""
    return TriageVerdict(
        timeline_id=uuid4(),
        severity=severity,
        confidence_score=0.9,
        summary="Test verdict",
        reasoning=["Test finding"],
        recommended_actions=["Test action"],
        raw_llm_response="{}",
    )


def create_timeline(alerts: list) -> ThreatTimeline:
    """Helper to construct a valid ThreatTimeline with given alerts."""
    return ThreatTimeline(
        grouping_key="test_group",
        alerts=alerts,
        total_events=len(alerts),
    )


# =====================================================================
# 1. Division by Zero Defense Tests
# =====================================================================


def test_div_by_zero_zero_events():
    """Verify get_metrics() returns clean 0.0 values with 0 events without throwing ZeroDivisionError."""
    tracker = AccuracyTracker()
    metrics = tracker.get_metrics()

    assert metrics["accuracy"] == 0.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 0.0
    assert metrics["total"] == 0
    assert metrics["unknown"] == 0


def test_div_by_zero_only_false_positives():
    """Verify get_metrics() safely handles only False Positives (TP=0, TN=0, FN=0)."""
    tracker = AccuracyTracker()
    tracker.fp = 10
    metrics = tracker.get_metrics()

    assert metrics["accuracy"] == 0.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["false_positive_rate"] == 1.0
    assert metrics["total"] == 10


def test_div_by_zero_only_false_negatives():
    """Verify get_metrics() safely handles only False Negatives (TP=0, TN=0, FP=0)."""
    tracker = AccuracyTracker()
    tracker.fn = 10
    metrics = tracker.get_metrics()

    assert metrics["accuracy"] == 0.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["false_negative_rate"] == 1.0
    assert metrics["total"] == 10


def test_div_by_zero_only_true_negatives():
    """Verify get_metrics() safely handles only True Negatives (TP=0, FP=0, FN=0)."""
    tracker = AccuracyTracker()
    tracker.tn = 50
    metrics = tracker.get_metrics()

    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["total"] == 50


def test_div_by_zero_only_true_positives():
    """Verify get_metrics() safely handles only True Positives (TN=0, FP=0, FN=0)."""
    tracker = AccuracyTracker()
    tracker.tp = 25
    metrics = tracker.get_metrics()

    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["false_negative_rate"] == 0.0
    assert metrics["total"] == 25


# =====================================================================
# 2. Imbalanced Data Defense Tests
# =====================================================================


def test_imbalanced_data_9999_tn_and_1_fn():
    """Feed the tracker 9,999 True Negatives and 1 False Negative.

    Verifies the statistical metrics calculate correctly:
    - Precision: 0.0 (no true positives)
    - Recall: 0.0 (missed the only malicious event)
    - Accuracy: 99.99% (0.9999)
    - F1-Score: 0.0
    - False Negative Rate: 100% (1.0)
    """
    tracker = AccuracyTracker()
    tracker.tn = 9999
    tracker.fn = 1

    metrics = tracker.get_metrics()

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["accuracy"] == 0.9999
    assert metrics["accuracy_pct"] == 99.99
    assert metrics["false_negative_rate"] == 1.0
    assert metrics["total"] == 10000


def test_imbalanced_data_9999_tp_and_1_fp():
    """Feed the tracker 9,999 True Positives and 1 False Positive.

    Verifies:
    - Recall: 1.0 (caught all malicious events)
    - Precision: 9999 / 10000 = 0.9999
    - Accuracy: 99.99% (0.9999)
    - False Positive Rate: 1.0 (since TN=0)
    """
    tracker = AccuracyTracker()
    tracker.tp = 9999
    tracker.fp = 1

    metrics = tracker.get_metrics()

    assert metrics["recall"] == 1.0
    assert pytest.approx(metrics["precision"], 0.0001) == 0.9999
    assert pytest.approx(metrics["accuracy"], 0.0001) == 0.9999
    assert metrics["total"] == 10000


# =====================================================================
# 3. Mapping Defense & Conflict Resolution Tests
# =====================================================================


def test_mapping_defense_conflicting_alerts_defaults_to_malicious():
    """Verify that if a timeline contains 1 benign and 1 malicious alert, it defaults to malicious."""
    tracker = AccuracyTracker()

    benign_alert = NormalizedAlert(
        source_dataset="test",
        source_file="file1.json",
        event_type="4624",
        original_record={"user": "alice"},
        ground_truth_label="benign",
    )
    malicious_alert = NormalizedAlert(
        source_dataset="test",
        source_file="file2.json",
        event_type="ProcessCreate",
        original_record={"command_line": "mimikatz.exe"},
        ground_truth_label="malicious",
    )

    timeline = create_timeline([benign_alert, malicious_alert])
    verdict = create_verdict(severity="HIGH")

    result = tracker.evaluate(verdict, timeline)

    assert result.ground_truth is True  # Malicious wins
    assert result.llm_prediction is True
    assert result.is_correct is True
    assert result.category == "True Positive"
    assert tracker.tp == 1
    assert tracker.total_evaluated == 1


def test_mapping_defense_mitre_technique_in_original_record():
    """Verify that a MITRE technique inside original_record classifies as malicious."""
    tracker = AccuracyTracker()

    mitre_alert = NormalizedAlert(
        source_dataset="test",
        source_file="file1.json",
        event_type="ProcessCreate",
        original_record={"mitre_technique": "T1059.001", "name": "PowerShell Execution"},
    )
    timeline = create_timeline([mitre_alert])

    # LLM predicted LOW -> Missed detection -> False Negative
    verdict = create_verdict(severity="LOW")
    result = tracker.evaluate(verdict, timeline)

    assert result.ground_truth is True
    assert result.llm_prediction is False
    assert result.is_correct is False
    assert result.category == "False Negative"
    assert tracker.fn == 1


def test_mapping_defense_all_benign_alerts():
    """Verify timeline with only benign alerts is evaluated as benign."""
    tracker = AccuracyTracker()

    benign1 = NormalizedAlert(
        source_dataset="test",
        source_file="file1.json",
        event_type="4624",
        original_record={"is_malicious": False},
    )
    benign2 = NormalizedAlert(
        source_dataset="test",
        source_file="file2.json",
        event_type="4634",
        original_record={},
        ground_truth_label="clean",
    )
    timeline = create_timeline([benign1, benign2])

    # Case A: LLM correctly predicts LOW -> True Negative
    verdict_low = create_verdict(severity="INFORMATIONAL")
    result_tn = tracker.evaluate(verdict_low, timeline)

    assert result_tn.ground_truth is False
    assert result_tn.llm_prediction is False
    assert result_tn.is_correct is True
    assert result_tn.category == "True Negative"
    assert tracker.tn == 1

    # Case B: LLM hallucinates CRITICAL -> False Positive
    verdict_crit = create_verdict(severity="CRITICAL")
    result_fp = tracker.evaluate(verdict_crit, timeline)

    assert result_fp.ground_truth is False
    assert result_fp.llm_prediction is True
    assert result_fp.is_correct is False
    assert result_fp.category == "False Positive"
    assert tracker.fp == 1


# =====================================================================
# 4. Missing Data & Unknown Labels Defense Tests
# =====================================================================


def test_missing_data_unlabeled_timeline_categorized_as_unknown():
    """Verify unlabeled timeline is safely categorized as Unknown without polluting confusion matrix."""
    tracker = AccuracyTracker()

    unlabeled_alert = NormalizedAlert(
        source_dataset="unlabeled_stream",
        source_file="stream.json",
        event_type="NetworkConnection",
        original_record={"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"},
    )
    timeline = create_timeline([unlabeled_alert])
    verdict = create_verdict(severity="MEDIUM")

    result = tracker.evaluate(verdict, timeline)

    assert result.ground_truth is None
    assert result.is_correct is None
    assert result.category == "Unknown"
    assert result.llm_prediction is True

    # Crucial: Confusion matrix counters must NOT be incremented
    assert tracker.tp == 0
    assert tracker.tn == 0
    assert tracker.fp == 0
    assert tracker.fn == 0
    assert tracker.total_evaluated == 0
    assert tracker.unknown_count == 1

    # Metrics remain safe
    metrics = tracker.get_metrics()
    assert metrics["total"] == 0
    assert metrics["unknown"] == 1


def test_missing_data_empty_timeline():
    """Verify empty timeline with zero alerts is safely categorized as Unknown."""
    tracker = AccuracyTracker()
    empty_timeline = create_timeline([])
    verdict = create_verdict(severity="LOW")

    result = tracker.evaluate(verdict, empty_timeline)

    assert result.ground_truth is None
    assert result.category == "Unknown"
    assert tracker.unknown_count == 1
    assert tracker.total_evaluated == 0


# =====================================================================
# 5. Severity Level Boundary Defense Tests
# =====================================================================


@pytest.mark.parametrize(
    "severity, expected_prediction",
    [
        ("CRITICAL", True),
        ("HIGH", True),
        ("MEDIUM", True),
        ("LOW", False),
        ("INFORMATIONAL", False),
        ("critical", True),
        ("high", True),
        ("medium", True),
        ("low", False),
        ("informational", False),
    ],
)
def test_severity_prediction_mapping(severity, expected_prediction):
    """Verify all severity levels map strictly to binary prediction boundaries."""
    tracker = AccuracyTracker()
    alert = NormalizedAlert(
        source_dataset="test",
        source_file="test.json",
        event_type="test",
        original_record={},
        ground_truth_label="malicious",
    )
    timeline = create_timeline([alert])
    verdict = create_verdict(severity=severity)

    result = tracker.evaluate(verdict, timeline)
    assert result.llm_prediction is expected_prediction


# =====================================================================
# 6. Reset and History Tracking
# =====================================================================


def test_tracker_reset_and_history():
    """Verify evaluation history is preserved and reset() clears all state."""
    tracker = AccuracyTracker()

    alert = NormalizedAlert(
        source_dataset="test",
        source_file="test.json",
        event_type="test",
        original_record={},
        ground_truth_label="malicious",
    )
    timeline = create_timeline([alert])
    verdict = create_verdict(severity="HIGH")

    tracker.evaluate(verdict, timeline)
    assert len(tracker.history) == 1
    assert tracker.tp == 1

    tracker.reset()
    assert len(tracker.history) == 0
    assert tracker.tp == 0
    assert tracker.tn == 0
    assert tracker.fp == 0
    assert tracker.fn == 0
    assert tracker.unknown_count == 0
    assert tracker.total_evaluated == 0
