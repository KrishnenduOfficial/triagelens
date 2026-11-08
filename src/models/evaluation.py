"""Data models for AI accuracy evaluation and validation against ground truth."""

from typing import Literal, Optional
from uuid import UUID
from pydantic import BaseModel
from src.models.triage import Disposition

EvaluationCategory = Literal[
    "True Positive",
    "True Negative",
    "False Positive",
    "False Negative",
    "Unknown",
    "Unavailable",
]


class EvaluationResult(BaseModel):
    """Represents the evaluation of an LLM triage verdict against deterministic ground truth.

    Attributes:
        timeline_id: Unique identifier of the evaluated threat timeline.
        verdict_id: Unique identifier of the evaluated AI triage verdict (None if unavailable).
        ground_truth: Ground truth label (True=malicious, False=benign, None=unknown).
        llm_prediction: Independent malicious/benign disposition, or the original
            severity proxy for legacy verdicts. None means abstained or unavailable.
        is_correct: Whether a binary prediction matched known ground truth.
            None means unknown truth, abstained, or unavailable.
        prediction_basis: Recorded evaluator rule; None for unrecorded legacy snapshots.
        policy_version: Application-owned assessment policy, absent on legacy records.
        category: Confusion matrix category.
        severity_ground_truth: Ground truth severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL), if available.
        severity_prediction: Suggested severity from AI triage verdict, if available.
        severity_correct: Whether AI suggested severity matched ground truth severity, if evaluated.
    """

    timeline_id: UUID
    verdict_id: Optional[UUID] = None
    ground_truth: Optional[bool] = None
    llm_prediction: Optional[bool] = None
    is_correct: Optional[bool] = None
    category: EvaluationCategory
    severity_ground_truth: Optional[str] = None
    severity_prediction: Optional[str] = None
    severity_correct: Optional[bool] = None
    confidence_score: Optional[float] = None
    disposition: Optional[Disposition] = None
    prediction_basis: Optional[Literal["explicit_disposition_v1", "legacy_severity_proxy"]] = None
    policy_version: Optional[str] = None
    observation_id: Optional[UUID] = None
    evaluation_context_hash: Optional[str] = None
    quality_cohort_hash: Optional[str] = None
    provenance_version: Optional[int] = None


