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
]


class EvaluationResult(BaseModel):
    """Represents the evaluation of an LLM triage verdict against deterministic ground truth.

    Attributes:
        timeline_id: Unique identifier of the evaluated threat timeline.
        verdict_id: Unique identifier of the evaluated AI triage verdict.
        ground_truth: Ground truth label (True=malicious, False=benign, None=unknown).
        llm_prediction: Model prediction (True=Critical/High/Medium, False=Low/Informational).
        is_correct: Whether the prediction matched ground truth (None if ground truth is unknown).
        category: Confusion matrix category.
    """

    timeline_id: UUID
    verdict_id: UUID
    ground_truth: Optional[bool] = None
    llm_prediction: bool
    is_correct: Optional[bool] = None
    category: EvaluationCategory

