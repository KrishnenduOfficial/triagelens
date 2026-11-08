"""Evaluation and Accuracy Tracking Engine.

Compares AI-generated triage verdicts against independent ground truth,
tracks confusion matrix metrics (TP, TN, FP, FN), and calculates robust statistical
performance indicators with division-by-zero protection.

Assumptions & Design Rules (ADR-008, ADR-022):
1. Ground Truth Independence: AI predictions never evaluate or influence ground truth.
2. Label Extraction: Documented and explicit per dataset (removing ambiguous strings like 'suspicious').
3. Multi-Alert Timeline Conflict Resolution: If any alert is malicious, the timeline is malicious.
4. Unavailable Predictions: Handled safely without crashes, categorized as 'Unavailable'.
5. Specificity & Class Balance: Specificity is explicitly calculated; class balance is reported.
6. Severity Evaluation: Evaluates suggested severity against ground truth where labels permit.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import math
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from src.models.alert import NormalizedAlert
from src.models.evaluation import EvaluationCategory, EvaluationResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict

logger = logging.getLogger(__name__)


@dataclass
class DatasetGroundTruthConfig:
    """Explicit ground-truth extraction mapping configuration per dataset."""

    name: str
    malicious_labels: Set[str] = field(
        default_factory=lambda: {
            "malicious",
            "true",
            "1",
            "attack",
            "threat",
            "evil",
            "bad",
            "compromised",
        }
    )
    benign_labels: Set[str] = field(
        default_factory=lambda: {
            "benign",
            "false",
            "0",
            "clean",
            "normal",
            "safe",
            "harmless",
            "legitimate",
        }
    )
    technique_keys: Tuple[str, ...] = (
        "mitre_technique",
        "technique",
        "mitre",
        "attack_technique",
    )
    label_keys: Tuple[str, ...] = (
        "is_malicious",
        "malicious",
        "ground_truth",
        "label",
        "verdict",
    )
    severity_keys: Tuple[str, ...] = (
        "severity",
        "alert_severity",
        "priority",
        "threat_level",
    )


def generate_benign_timeline(
    num_events: int = 5,
    host: str = "WORKSTATION-01",
    user: str = "corp_user",
    source_dataset: str = "benign_baseline",
) -> ThreatTimeline:
    """Generates a realistic, deterministic baseline benign timeline for balanced benchmarking.

    Produces standard enterprise telemetry (e.g., Logon EventID 4624, Process Explorer,
    routine DNS lookups) with verified benign ground truth labels.
    """
    base_time = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    sample_events = [
        ("UserLogon", {"action": "Logon", "logon_type": 2, "user": user, "host": host}),
        ("ProcessStart", {"image": "explorer.exe", "command_line": "explorer.exe", "user": user, "host": host}),
        ("NetworkDNS", {"query": "portal.internal.corp", "record_type": "A", "user": user, "host": host}),
        ("FileAccess", {"path": "C:\\Users\\user\\Documents\\report.docx", "access": "read", "user": user, "host": host}),
        ("ScheduledTask", {"task_name": "GoogleUpdate", "action": "check", "user": "SYSTEM", "host": host}),
    ]

    alerts: List[NormalizedAlert] = []
    for i in range(num_events):
        ev_type, rec = sample_events[i % len(sample_events)]
        rec_copy = dict(rec)
        rec_copy["is_malicious"] = False
        rec_copy["severity"] = "INFORMATIONAL"

        alert = NormalizedAlert(
            source_dataset=source_dataset,
            source_file="benign_audit.log",
            event_type=ev_type,
            original_record=rec_copy,
            ground_truth_label="benign",
            timestamp=base_time + timedelta(minutes=i * 2),
        )
        alerts.append(alert)

    return ThreatTimeline(
        grouping_key=f"{host}:{user}",
        alerts=alerts,
        start_time=alerts[0].timestamp if alerts else None,
        end_time=alerts[-1].timestamp if alerts else None,
        total_events=len(alerts),
        correlation_type="confirmed",
        correlation_reason="benign_baseline_session",
    )


def wilson_score_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
    z: float = 1.96,
) -> Tuple[float, float]:
    """Calculates the Wilson score confidence interval for a binomial proportion.

    Args:
        successes: Number of positive outcomes / successes (k).
        total: Total number of trials (n).
        confidence: Confidence level (default 0.95).
        z: Quantile of normal distribution (default 1.96 for 95% confidence).

    Returns:
        (lower_bound, upper_bound) rounded to 4 decimal places.
    """
    if total <= 0:
        return (0.0, 0.0)
    p_hat = successes / total
    denom = 1.0 + (z**2) / total
    center = (p_hat + (z**2) / (2.0 * total)) / denom
    margin = (z * math.sqrt((p_hat * (1.0 - p_hat) / total) + (z**2) / (4.0 * (total**2)))) / denom
    lower = max(0.0, round(center - margin, 4))
    upper = min(1.0, round(center + margin, 4))
    return (lower, upper)


class AccuracyTracker:
    """Tracks and evaluates LLM triage predictions against deterministic ground truth.

    Maintains running counts of:
    - True Positives (TP): Malicious ground truth, LLM predicted malicious
    - True Negatives (TN): Benign ground truth, LLM predicted benign
    - False Positives (FP): Benign ground truth, LLM predicted malicious
    - False Negatives (FN): Malicious ground truth, LLM predicted benign
    - Unknown: Missing ground truth or abstained disposition, excluded from binary metrics
    - Unavailable: AI prediction missing/failed, excluded from confusion matrix metrics
    """

    SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")

    def __init__(self) -> None:
        """Initializes the running confusion matrix counters and configuration registry."""
        self.true_positives: int = 0
        self.true_negatives: int = 0
        self.false_positives: int = 0
        self.false_negatives: int = 0
        self.unknown_count: int = 0
        self.unavailable_count: int = 0
        self.total_evaluated: int = 0
        self.severity_evaluated: int = 0
        self.severity_matches: int = 0
        self.history: List[EvaluationResult] = []
        self.confidence_pairs: List[Tuple[float, bool]] = []
        self.dataset_configs: Dict[str, DatasetGroundTruthConfig] = {}
        self._default_config = DatasetGroundTruthConfig(name="default")

    @property
    def tp(self) -> int:
        return self.true_positives

    @tp.setter
    def tp(self, val: int) -> None:
        self.true_positives = val

    @property
    def tn(self) -> int:
        return self.true_negatives

    @tn.setter
    def tn(self, val: int) -> None:
        self.true_negatives = val

    @property
    def fp(self) -> int:
        return self.false_positives

    @fp.setter
    def fp(self, val: int) -> None:
        self.false_positives = val

    @property
    def fn(self) -> int:
        return self.false_negatives

    @fn.setter
    def fn(self, val: int) -> None:
        self.false_negatives = val

    def register_dataset_config(self, config: DatasetGroundTruthConfig) -> None:
        """Registers an explicit ground-truth extraction mapping for a specific dataset."""
        self.dataset_configs[config.name.lower()] = config

    def _get_config(self, dataset_name: Optional[str]) -> DatasetGroundTruthConfig:
        """Retrieves explicit dataset configuration or falls back to default."""
        if not dataset_name:
            return self._default_config
        return self.dataset_configs.get(dataset_name.strip().lower(), self._default_config)

    def reset(self) -> None:
        """Resets all running counters and history."""
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        self.unknown_count = 0
        self.unavailable_count = 0
        self.total_evaluated = 0
        self.severity_evaluated = 0
        self.severity_matches = 0
        self.history.clear()
        self.confidence_pairs.clear()

    @classmethod
    def from_evaluations(cls, evaluations: List[EvaluationResult]) -> "AccuracyTracker":
        """Reconstructs an AccuracyTracker instance from a collection of EvaluationResult records."""
        tracker = cls()
        for res in evaluations:
            cat = res.category
            if cat == "True Positive":
                tracker.true_positives += 1
                tracker.total_evaluated += 1
            elif cat == "True Negative":
                tracker.true_negatives += 1
                tracker.total_evaluated += 1
            elif cat == "False Positive":
                tracker.false_positives += 1
                tracker.total_evaluated += 1
            elif cat == "False Negative":
                tracker.false_negatives += 1
                tracker.total_evaluated += 1
            elif cat == "Unknown":
                tracker.unknown_count += 1
            elif cat == "Unavailable":
                tracker.unavailable_count += 1

            if res.confidence_score is not None and res.is_correct is not None:
                tracker.confidence_pairs.append((float(res.confidence_score), bool(res.is_correct)))

            if res.severity_correct is not None:
                tracker.severity_evaluated += 1
                if res.severity_correct:
                    tracker.severity_matches += 1

            tracker.history.append(res)
        return tracker

    @classmethod
    def from_database(cls, db: Any) -> "AccuracyTracker":
        """Reconstructs an AccuracyTracker instance by loading all evaluations from SQLite."""
        if hasattr(db, "get_all_evaluations"):
            evaluations = db.get_all_evaluations()
        else:
            evaluations = []
        return cls.from_evaluations(evaluations)

    def _classify_alert_label(self, alert: NormalizedAlert) -> Optional[bool]:
        """Classifies an individual alert's ground truth using dataset-specific rules.

        Returns:
            True: Confirmed malicious.
            False: Confirmed benign.
            None: Unlabeled / unknown.
        """
        cfg = self._get_config(alert.source_dataset)

        # 1. Check explicit ground_truth_label field
        if alert.ground_truth_label is not None:
            raw_label = str(alert.ground_truth_label).strip().lower()
            if raw_label in cfg.malicious_labels or raw_label.startswith(("mitre", "t1", "t0")):
                return True
            if raw_label in cfg.benign_labels:
                return False

        # 2. Check original_record fields
        rec = alert.original_record
        if isinstance(rec, dict):
            # Check MITRE technique indicators
            for tech_key in cfg.technique_keys:
                if tech_key in rec and rec[tech_key]:
                    val = str(rec[tech_key]).strip().lower()
                    if val not in ("none", "n/a", "null", "false", "0", ""):
                        return True

            # Check explicit malicious boolean or string flags
            for mal_key in cfg.label_keys:
                if mal_key in rec:
                    val = rec[mal_key]
                    if isinstance(val, bool):
                        return val
                    if isinstance(val, (int, float)):
                        return bool(val)
                    if isinstance(val, str):
                        clean_str = val.strip().lower()
                        if clean_str in cfg.malicious_labels or clean_str.startswith(("mitre", "t1", "t0")):
                            return True
                        if clean_str in cfg.benign_labels:
                            return False

        return None

    def _extract_ground_truth_severity(self, timeline: ThreatTimeline) -> Optional[str]:
        """Extracts deterministic ground-truth severity from timeline alerts.

        Standardizes to: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.
        Precedence follows severity rank: CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL.
        """
        highest_rank = len(self.SEVERITY_ORDER) + 1
        highest_sev: Optional[str] = None

        for alert in timeline.alerts:
            cfg = self._get_config(alert.source_dataset)
            rec = alert.original_record if isinstance(alert.original_record, dict) else {}

            for sev_key in cfg.severity_keys:
                if sev_key in rec and rec[sev_key]:
                    val_str = str(rec[sev_key]).strip().upper()
                    if val_str in self.SEVERITY_ORDER:
                        rank = self.SEVERITY_ORDER.index(val_str)
                        if rank < highest_rank:
                            highest_rank = rank
                            highest_sev = val_str

        return highest_sev

    def _extract_ground_truth(self, timeline: ThreatTimeline) -> Optional[bool]:
        """Extracts deterministic ground truth from a timeline.

        Conflict resolution rule:
        If ANY alert in the timeline is malicious, the entire timeline is
        classified as malicious (True).
        If NO alerts are malicious, but at least ONE alert is benign, it is classified
        as benign (False).
        Otherwise, if no alerts carry ground truth labels, returns None (Unknown).
        """
        has_malicious = False
        has_benign = False

        for alert in timeline.alerts:
            status = self._classify_alert_label(alert)
            if status is True:
                has_malicious = True
                break  # Malicious takes absolute precedence
            elif status is False:
                has_benign = True

        if has_malicious:
            return True
        if has_benign:
            return False
        return None

    def evaluate(
        self, verdict: Optional[TriageVerdict], timeline: ThreatTimeline
    ) -> EvaluationResult:
        """Evaluates an AI triage verdict against the deterministic ground truth of a timeline.

        Args:
            verdict: The AI-generated TriageVerdict (or None if unavailable/timed out).
            timeline: The underlying ThreatTimeline.

        Returns:
            EvaluationResult containing the classification, verification status, and severity accuracy.
        """
        ground_truth = self._extract_ground_truth(timeline)
        gt_severity = self._extract_ground_truth_severity(timeline)

        # Handle unavailable AI predictions safely without crashing
        if verdict is None:
            self.unavailable_count += 1
            result = EvaluationResult(
                timeline_id=timeline.timeline_id,
                verdict_id=None,
                ground_truth=ground_truth,
                llm_prediction=None,
                is_correct=None,
                category="Unavailable",
                severity_ground_truth=gt_severity,
                severity_prediction=None,
                severity_correct=None,
            )
            self.history.append(result)
            return result

        # Legacy verdicts retain the original severity proxy. New verdicts record
        # an independent disposition; abstention is available but not binary evidence.
        sev = str(verdict.severity).strip().upper()
        if verdict.disposition is None:
            llm_prediction = sev in ("CRITICAL", "HIGH", "MEDIUM")
            prediction_basis = "legacy_severity_proxy"
        else:
            llm_prediction = {"MALICIOUS": True, "BENIGN": False, "UNDETERMINED": None}[verdict.disposition]
            prediction_basis = "explicit_disposition_v1"

        # 2. Categorize against ground truth
        category: EvaluationCategory
        is_correct: Optional[bool]

        if ground_truth is None or llm_prediction is None:
            category = "Unknown"
            is_correct = None
            self.unknown_count += 1
        elif ground_truth is True and llm_prediction is True:
            category = "True Positive"
            is_correct = True
            self.true_positives += 1
            self.total_evaluated += 1
        elif ground_truth is False and llm_prediction is False:
            category = "True Negative"
            is_correct = True
            self.true_negatives += 1
            self.total_evaluated += 1
        elif ground_truth is False and llm_prediction is True:
            category = "False Positive"
            is_correct = False
            self.false_positives += 1
            self.total_evaluated += 1
        else:  # ground_truth is True and llm_prediction is False
            category = "False Negative"
            is_correct = False
            self.false_negatives += 1
            self.total_evaluated += 1

        # 3. Evaluate severity accuracy where ground truth permits
        severity_correct: Optional[bool] = None
        if gt_severity is not None:
            severity_correct = (sev == gt_severity)
            self.severity_evaluated += 1
            if severity_correct:
                self.severity_matches += 1

        conf = verdict.confidence_score if verdict else None
        if conf is not None and is_correct is not None:
            self.confidence_pairs.append((float(conf), bool(is_correct)))

        result = EvaluationResult(
            timeline_id=timeline.timeline_id,
            verdict_id=verdict.verdict_id,
            ground_truth=ground_truth,
            llm_prediction=llm_prediction,
            is_correct=is_correct,
            category=category,
            severity_ground_truth=gt_severity,
            severity_prediction=sev,
            severity_correct=severity_correct,
            confidence_score=conf,
            disposition=verdict.disposition,
            prediction_basis=prediction_basis,
            policy_version=verdict.policy_version,
        )
        self.history.append(result)
        return result

    def get_metrics(self) -> Dict[str, Any]:
        """Calculates statistical performance metrics with division-by-zero defense, class balance, and confidence calibration.

        Returns:
            Dictionary containing Accuracy, Precision, Recall, Specificity, F1-Score,
            False Positive Rate, False Negative Rate, Brier score, Expected Calibration Error,
            class balance metrics, and severity evaluation.
        """
        tp = self.true_positives
        tn = self.true_negatives
        fp = self.false_positives
        fn = self.false_negatives
        total = tp + tn + fp + fn

        # Class balance calculations
        positive_samples = tp + fn
        negative_samples = tn + fp
        positive_ratio = (positive_samples / total) if total > 0 else 0.0
        negative_ratio = (negative_samples / total) if total > 0 else 0.0
        is_imbalanced = (
            positive_samples == 0
            or negative_samples == 0
            or (max(positive_samples, negative_samples) / max(1, min(positive_samples, negative_samples))) > 10.0
        ) if total > 0 else False

        # 1. Accuracy: (TP + TN) / Total
        accuracy = (tp + tn) / total if total > 0 else 0.0

        # 2. Precision: TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        # 3. Recall: TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # 4. Specificity: TN / (TN + FP) (undefined when zero negative samples exist)
        specificity_valid = negative_samples > 0
        specificity = (tn / negative_samples) if specificity_valid else None

        # 5. F1-Score: 2 * (Precision * Recall) / (Precision + Recall)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # 6. False Positive Rate: FP / (FP + TN) (undefined when zero negative samples exist)
        fpr_valid = negative_samples > 0
        fpr = (fp / negative_samples) if fpr_valid else 0.0
        fpr_note = "Valid" if fpr_valid else "Undefined: zero negative samples in evaluation set"

        # 7. False Negative Rate: FN / (TP + FN)
        fnr_valid = positive_samples > 0
        fnr = (fn / positive_samples) if fnr_valid else 0.0

        # 8. Availability Rate: Evaluated / (Evaluated + Unavailable)
        total_eval_stream = total + self.unknown_count + self.unavailable_count
        availability_rate = (
            (total + self.unknown_count) / total_eval_stream if total_eval_stream > 0 else 1.0
        )

        # 8b. Wilson 95% Confidence Intervals (ADR-034)
        accuracy_ci95 = wilson_score_interval(tp + tn, total) if total > 0 else (0.0, 0.0)
        precision_ci95 = wilson_score_interval(tp, tp + fp) if (tp + fp) > 0 else (0.0, 0.0)
        recall_ci95 = wilson_score_interval(tp, tp + fn) if (tp + fn) > 0 else (0.0, 0.0)
        specificity_ci95 = wilson_score_interval(tn, negative_samples) if specificity_valid else None

        # 9. Severity Performance
        severity_accuracy = (
            self.severity_matches / self.severity_evaluated if self.severity_evaluated > 0 else 0.0
        )

        # 10. Confidence Calibration (Brier Score, ECE, Calibration Bins)
        if self.confidence_pairs:
            brier_score = round(
                sum((c - (1.0 if ok else 0.0)) ** 2 for c, ok in self.confidence_pairs)
                / len(self.confidence_pairs),
                4,
            )
            bin_defs = [
                (0.0, 0.2, "0.0 - 0.2"),
                (0.2, 0.4, "0.2 - 0.4"),
                (0.4, 0.6, "0.4 - 0.6"),
                (0.6, 0.8, "0.6 - 0.8"),
                (0.8, 1.0, "0.8 - 1.0"),
            ]
            calibration_bins = []
            ece_acc = 0.0
            total_pairs = len(self.confidence_pairs)

            for low, high, label in bin_defs:
                if high == 1.0:
                    bin_samples = [p for p in self.confidence_pairs if low <= p[0] <= high]
                else:
                    bin_samples = [p for p in self.confidence_pairs if low <= p[0] < high]

                count = len(bin_samples)
                if count > 0:
                    mean_conf = round(sum(p[0] for p in bin_samples) / count, 4)
                    emp_acc = round(sum(1 for p in bin_samples if p[1]) / count, 4)
                    gap = abs(mean_conf - emp_acc)
                    ece_acc += (count / total_pairs) * gap
                else:
                    mean_conf = 0.0
                    emp_acc = 0.0
                    gap = 0.0

                calibration_bins.append({
                    "bin": label,
                    "count": count,
                    "mean_confidence": mean_conf,
                    "accuracy": emp_acc,
                    "gap": round(gap, 4),
                })

            expected_calibration_error = round(ece_acc, 4)
        else:
            brier_score = None
            expected_calibration_error = None
            calibration_bins = []

        return {
            "accuracy": accuracy,
            "Accuracy": accuracy,
            "accuracy_pct": round(accuracy * 100, 2),
            "accuracy_ci95": accuracy_ci95,
            "precision": precision,
            "Precision": precision,
            "precision_ci95": precision_ci95,
            "recall": recall,
            "Recall": recall,
            "recall_ci95": recall_ci95,
            "specificity": specificity,
            "Specificity": specificity,
            "specificity_valid": specificity_valid,
            "specificity_pct": round(specificity * 100, 2) if specificity is not None else None,
            "specificity_ci95": specificity_ci95,
            "f1_score": f1,
            "F1-Score": f1,
            "f1": f1,
            "F1": f1,
            "false_positive_rate": fpr,
            "fpr_valid": fpr_valid,
            "fpr_note": fpr_note,
            "false_negative_rate": fnr,
            "fnr_valid": fnr_valid,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "total": total,
            "unknown": self.unknown_count,
            "abstained": sum(r.disposition == "UNDETERMINED" for r in self.history),
            "explicit_disposition_count": sum(r.prediction_basis == "explicit_disposition_v1" for r in self.history),
            "legacy_severity_proxy_count": sum(r.prediction_basis == "legacy_severity_proxy" for r in self.history),
            "prediction_basis_unknown_count": sum(r.prediction_basis is None for r in self.history),
            "unavailable": self.unavailable_count,
            "availability_rate": availability_rate,
            "positive_samples": positive_samples,
            "negative_samples": negative_samples,
            "positive_ratio": positive_ratio,
            "negative_ratio": negative_ratio,
            "is_imbalanced": is_imbalanced,
            "severity_evaluated": self.severity_evaluated,
            "severity_matches": self.severity_matches,
            "severity_accuracy": severity_accuracy,
            "brier_score": brier_score,
            "expected_calibration_error": expected_calibration_error,
            "ece": expected_calibration_error,
            "calibration_bins": calibration_bins,
        }

    def generate_reproducible_report(self, seed: Optional[int] = None) -> Dict[str, Any]:
        """Generates a deterministic evaluation report with a cryptographic SHA-256 integrity hash."""
        metrics = self.get_metrics()
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": seed,
            "total_timelines_evaluated": self.total_evaluated,
            "confusion_matrix": {
                "true_positives": self.true_positives,
                "true_negatives": self.true_negatives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
                "unknown": self.unknown_count,
                "unavailable": self.unavailable_count,
            },
            "class_balance": {
                "positive_samples": metrics["positive_samples"],
                "negative_samples": metrics["negative_samples"],
                "positive_ratio": metrics["positive_ratio"],
                "negative_ratio": metrics["negative_ratio"],
                "is_imbalanced": metrics["is_imbalanced"],
            },
            "metrics": metrics,
        }

        # Deterministic integrity hash over confusion matrix and key metrics
        digest_str = json.dumps(report["confusion_matrix"], sort_keys=True) + json.dumps(
            {k: str(v) for k, v in metrics.items()}, sort_keys=True
        )
        report["integrity_hash"] = hashlib.sha256(digest_str.encode("utf-8")).hexdigest()
        return report
