"""Evaluation and Accuracy Tracking Engine.

Compares AI-generated triage verdicts against independent ground truth,
tracks confusion matrix metrics (TP, TN, FP, FN), and calculates robust statistical
performance indicators with division-by-zero protection.
"""

import logging
from typing import Dict, List, Optional

from src.models.alert import NormalizedAlert
from src.models.evaluation import EvaluationCategory, EvaluationResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict

logger = logging.getLogger(__name__)


class AccuracyTracker:
    """Tracks and evaluates LLM triage predictions against deterministic ground truth.

    Maintains running counts of:
    - True Positives (TP): Malicious ground truth, LLM predicted malicious
    - True Negatives (TN): Benign ground truth, LLM predicted benign
    - False Positives (FP): Benign ground truth, LLM predicted malicious
    - False Negatives (FN): Malicious ground truth, LLM predicted benign
    - Unknown: Missing ground truth, excluded from confusion matrix metrics
    """

    # Malicious string indicators (case-insensitive)
    MALICIOUS_LABELS = {
        "malicious",
        "true",
        "1",
        "attack",
        "threat",
        "evil",
        "bad",
        "compromised",
        "suspicious",
    }

    # Benign string indicators (case-insensitive)
    BENIGN_LABELS = {
        "benign",
        "false",
        "0",
        "clean",
        "normal",
        "safe",
        "harmless",
        "legitimate",
    }

    def __init__(self) -> None:
        """Initializes the running confusion matrix counters."""
        self.true_positives: int = 0
        self.true_negatives: int = 0
        self.false_positives: int = 0
        self.false_negatives: int = 0
        self.unknown_count: int = 0
        self.total_evaluated: int = 0
        self.history: List[EvaluationResult] = []

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

    def reset(self) -> None:
        """Resets all running counters and history."""
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        self.unknown_count = 0
        self.total_evaluated = 0
        self.history.clear()

    def _classify_alert_label(self, alert: NormalizedAlert) -> Optional[bool]:
        """Classifies an individual alert's ground truth.

        Returns:
            True: Confirmed malicious.
            False: Confirmed benign.
            None: Unlabeled / unknown.
        """
        # 1. Check explicit ground_truth_label field
        if alert.ground_truth_label is not None:
            raw_label = str(alert.ground_truth_label).strip().lower()
            if raw_label in self.MALICIOUS_LABELS or raw_label.startswith(("mitre", "t1", "t0")):
                return True
            if raw_label in self.BENIGN_LABELS:
                return False

        # 2. Check original_record fields
        rec = alert.original_record
        if isinstance(rec, dict):
            # Check MITRE technique indicators
            for tech_key in ("mitre_technique", "technique", "mitre", "attack_technique"):
                if tech_key in rec and rec[tech_key]:
                    val = str(rec[tech_key]).strip().lower()
                    if val not in ("none", "n/a", "null", "false", "0", ""):
                        return True

            # Check explicit malicious boolean or string flags
            for mal_key in ("is_malicious", "malicious", "ground_truth", "label", "verdict"):
                if mal_key in rec:
                    val = rec[mal_key]
                    if isinstance(val, bool):
                        return val
                    if isinstance(val, (int, float)):
                        return bool(val)
                    if isinstance(val, str):
                        clean_str = val.strip().lower()
                        if clean_str in self.MALICIOUS_LABELS or clean_str.startswith(("mitre", "t1", "t0")):
                            return True
                        if clean_str in self.BENIGN_LABELS:
                            return False

        return None

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
        self, verdict: TriageVerdict, timeline: ThreatTimeline
    ) -> EvaluationResult:
        """Evaluates an AI triage verdict against the deterministic ground truth of a timeline.

        Args:
            verdict: The AI-generated TriageVerdict.
            timeline: The underlying ThreatTimeline.

        Returns:
            EvaluationResult containing the classification and verification status.
        """
        # 1. Determine LLM prediction (True if Critical/High/Medium, False if Low/Informational)
        sev = str(verdict.severity).strip().upper()
        llm_prediction = sev in ("CRITICAL", "HIGH", "MEDIUM")

        # 2. Extract deterministic ground truth
        ground_truth = self._extract_ground_truth(timeline)

        # 3. Categorize against ground truth
        category: EvaluationCategory
        is_correct: Optional[bool]

        if ground_truth is None:
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

        result = EvaluationResult(
            timeline_id=timeline.timeline_id,
            verdict_id=verdict.verdict_id,
            ground_truth=ground_truth,
            llm_prediction=llm_prediction,
            is_correct=is_correct,
            category=category,
        )
        self.history.append(result)
        return result

    def get_metrics(self) -> Dict[str, float]:
        """Calculates statistical performance metrics with division-by-zero defense.

        Returns:
            Dictionary containing Accuracy, Precision, Recall, F1-Score,
            False Positive Rate, False Negative Rate, and confusion matrix counts.
        """
        tp = self.true_positives
        tn = self.true_negatives
        fp = self.false_positives
        fn = self.false_negatives
        total = tp + tn + fp + fn

        # 1. Accuracy: (TP + TN) / Total
        accuracy = (tp + tn) / total if total > 0 else 0.0

        # 2. Precision: TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        # 3. Recall: TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # 4. F1-Score: 2 * (Precision * Recall) / (Precision + Recall)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # 5. False Positive Rate: FP / (FP + TN)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # 6. False Negative Rate: FN / (TP + FN)
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

        return {
            "accuracy": accuracy,
            "Accuracy": accuracy,
            "accuracy_pct": round(accuracy * 100, 2),
            "precision": precision,
            "Precision": precision,
            "recall": recall,
            "Recall": recall,
            "f1_score": f1,
            "F1-Score": f1,
            "f1": f1,
            "F1": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
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
        }

