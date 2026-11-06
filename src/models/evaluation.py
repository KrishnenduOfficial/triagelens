"""Data models for AI accuracy evaluation and validation against ground truth."""

from typing import Literal, Optional
from uuid import UUID
from pydantic import BaseModel

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
        llm_prediction: Model prediction (True=Critical/High/Medium, False=Low/Informational, None=unavailable).
        is_correct: Whether the prediction matched ground truth (None if ground truth unknown or unavailable).
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


