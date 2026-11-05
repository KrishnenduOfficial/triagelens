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


# =====================================================================
# 7. Hand-Computed Metrics, Class Balance, and Availability (Task F5 & F8)
# =====================================================================


def test_hand_computed_balanced_metrics():
    """Verify get_metrics() against hand-computed values: TP=40, FP=10, FN=5, TN=45."""
    tracker = AccuracyTracker()
    tracker.tp = 40
    tracker.fp = 10
    tracker.fn = 5
    tracker.tn = 45

    metrics = tracker.get_metrics()

    # Hand-computed reference:
    # Total = 100
    # Accuracy = (40 + 45) / 100 = 0.85 (85.0%)
    # Precision = 40 / 50 = 0.80 (80.0%)
    # Recall = 40 / 45 = 8/9 = 0.888888...
    # Specificity = 45 / 55 = 9/11 = 0.818181...
    # FPR = 10 / 55 = 2/11 = 0.181818...
    # FNR = 5 / 45 = 1/9 = 0.111111...
    # F1 = 2 * (0.80 * 8/9) / (0.80 + 8/9) = 16/19 = 0.842105...
    assert metrics["accuracy"] == 0.85
    assert metrics["precision"] == 0.80
    assert metrics["recall"] == pytest.approx(40 / 45, abs=1e-3)
    assert metrics["specificity"] == pytest.approx(45 / 55, abs=1e-3)
    assert metrics["false_positive_rate"] == pytest.approx(10 / 55, abs=1e-3)
    assert metrics["false_negative_rate"] == pytest.approx(5 / 45, abs=1e-3)
    assert metrics["f1_score"] == pytest.approx(16 / 19, abs=1e-3)


    # Class balance reporting
    assert metrics["positive_samples"] == 45
    assert metrics["negative_samples"] == 55
    assert metrics["positive_ratio"] == 0.45
    assert metrics["negative_ratio"] == 0.55
    assert metrics["is_imbalanced"] is False
    assert metrics["fpr_valid"] is True
    assert metrics["specificity_valid"] is True


def test_hand_computed_zero_benign_metrics():
    """Verify get_metrics() in zero-benign scenario (TP=10, FN=2, FP=0, TN=0).

    In zero-benign attack datasets:
    - Specificity is undefined (None / invalid) because negative_samples = 0
    - FPR is flagged as invalid (cannot measure false positives without negatives)
    - Class balance shows 100% positive, 0% negative (extreme imbalance)
    """
    tracker = AccuracyTracker()
    tracker.tp = 10
    tracker.fn = 2
    tracker.fp = 0
    tracker.tn = 0

    metrics = tracker.get_metrics()

    assert pytest.approx(metrics["accuracy"], 0.0001) == 0.8333
    assert metrics["precision"] == 1.0
    assert pytest.approx(metrics["recall"], 0.0001) == 0.8333
    assert pytest.approx(metrics["f1_score"], 0.0001) == 0.9091

    # Specificity and FPR validity flags
    assert metrics["specificity"] is None
    assert metrics["specificity_valid"] is False
    assert metrics["fpr_valid"] is False
    assert "undefined" in metrics.get("fpr_note", "").lower()

    # Class balance reporting
    assert metrics["positive_samples"] == 12
    assert metrics["negative_samples"] == 0
    assert metrics["positive_ratio"] == 1.0
    assert metrics["negative_ratio"] == 0.0
    assert metrics["is_imbalanced"] is True


def test_unavailable_ai_prediction_handled_safely():
    """Verify evaluate(None, timeline) handles unavailable predictions safely without crashing."""
    tracker = AccuracyTracker()
    alert = NormalizedAlert(
        source_dataset="test",
        source_file="test.json",
        event_type="test",
        original_record={},
        ground_truth_label="malicious",
    )
    timeline = create_timeline([alert])

    # Passing None verdict (e.g., API timeout, quota exhausted, offline run)
    result = tracker.evaluate(None, timeline)

    assert result.category == "Unavailable"
    assert result.llm_prediction is None
    assert result.is_correct is None
    assert result.verdict_id is None
    assert result.ground_truth is True

    # Confusion matrix counters must NOT be incremented
    assert tracker.tp == 0
    assert tracker.tn == 0
    assert tracker.fp == 0
    assert tracker.fn == 0
    assert tracker.unavailable_count == 1

    metrics = tracker.get_metrics()
    assert metrics["unavailable"] == 1
    assert "availability_rate" in metrics


def test_severity_evaluation_where_labels_permit():
    """Verify evaluation tracks suggested severity matching against ground-truth severity."""
    tracker = AccuracyTracker()

    alert1 = NormalizedAlert(
        source_dataset="test",
        source_file="test1.json",
        event_type="test",
        original_record={"severity": "HIGH", "is_malicious": True},
        ground_truth_label="malicious",
    )
    timeline1 = create_timeline([alert1])
    verdict1 = create_verdict(severity="HIGH")

    # Correct binary (TP) and correct severity (HIGH == HIGH)
    res1 = tracker.evaluate(verdict1, timeline1)
    assert res1.severity_correct is True
    assert res1.severity_ground_truth == "HIGH"

    alert2 = NormalizedAlert(
        source_dataset="test",
        source_file="test2.json",
        event_type="test",
        original_record={"severity": "CRITICAL", "is_malicious": True},
        ground_truth_label="malicious",
    )
    timeline2 = create_timeline([alert2])
    verdict2 = create_verdict(severity="LOW")

    # Incorrect binary (FN) and incorrect severity (LOW != CRITICAL)
    res2 = tracker.evaluate(verdict2, timeline2)
    assert res2.severity_correct is False
    assert res2.severity_ground_truth == "CRITICAL"

    metrics = tracker.get_metrics()
    assert metrics["severity_evaluated"] == 2
    assert metrics["severity_matches"] == 1
    assert metrics["severity_accuracy"] == 0.5


def test_explicit_dataset_ground_truth_mapping():
    """Verify explicit dataset configs do not treat 'suspicious' as confirmed malicious."""
    tracker = AccuracyTracker()

    # Raw log has 'status': 'suspicious' (triage flag, not confirmed ground truth)
    alert = NormalizedAlert(
        source_dataset="suricata",
        source_file="eve.json",
        event_type="Alert",
        original_record={"status": "suspicious"},
    )
    timeline = create_timeline([alert])
    verdict = create_verdict(severity="MEDIUM")

    # With explicit dataset mapping, 'suspicious' is unconfirmed -> ground_truth is None (Unknown)
    res = tracker.evaluate(verdict, timeline)
    assert res.ground_truth is None
    assert res.category == "Unknown"


def test_benign_timeline_generation():
    """Verify benign timeline generator creates realistic baseline data with negative ground truth."""
    from src.engine.evaluation import generate_benign_timeline

    tl = generate_benign_timeline(num_events=5, host="FIN-WS-09", user="clerk")
    assert tl.total_events == 5
    assert tl.grouping_key == "FIN-WS-09:clerk"
    assert all(a.ground_truth_label == "benign" for a in tl.alerts)

    tracker = AccuracyTracker()
    verdict_low = create_verdict(severity="INFORMATIONAL")
    res = tracker.evaluate(verdict_low, tl)
    assert res.ground_truth is False
    assert res.llm_prediction is False
    assert res.category == "True Negative"


def test_reproducible_evaluation_report():
    """Verify generate_reproducible_report() outputs deterministic metrics with cryptographic digest."""
    tracker = AccuracyTracker()
    tracker.tp = 5
    tracker.tn = 5
    tracker.fp = 1
    tracker.fn = 1

    report1 = tracker.generate_reproducible_report(seed=42)
    report2 = tracker.generate_reproducible_report(seed=42)

    assert "integrity_hash" in report1
    assert report1["integrity_hash"] == report2["integrity_hash"]
    assert report1["metrics"]["accuracy"] == pytest.approx(10 / 12, 0.0001)
    assert report1["class_balance"]["positive_samples"] == 6
    assert report1["class_balance"]["negative_samples"] == 6


