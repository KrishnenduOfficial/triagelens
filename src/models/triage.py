"""Data models for AI-assisted alert triage and analysis."""

from typing import List, Literal, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


class TriageVerdict(BaseModel):
    """Represents a structured AI-assisted triage assessment of a threat timeline.

    Attributes:
        verdict_id: Unique identifier for the triage verdict.
        timeline_id: Identifier of the threat timeline that was evaluated.
        severity: Assessed threat severity level.
        confidence_score: Model confidence score ranging from 0.0 to 1.0.
        summary: High-level incident summary and executive overview.
        reasoning: Concrete analytical reasons and supporting evidence.
        recommended_actions: Concrete investigation and remediation steps.
        raw_llm_response: Exact text returned by the LLM for auditing.
    """

    verdict_id: UUID = Field(default_factory=uuid4)
    timeline_id: UUID
    severity: SeverityLevel
    confidence_score: float = Field(ge=0.0, le=1.0)
    summary: str
    reasoning: List[str]
    recommended_actions: List[str]
    raw_llm_response: str
    model_name: Optional[str] = Field(
        default=None,
        description="The Gemini model identifier that generated this triage assessment",
    )
    uncertainty_level: Optional[Literal["LOW", "MEDIUM", "HIGH"]] = Field(
        default=None,
        description="Assessed degree of analytical uncertainty based on available telemetry",
    )
    missing_information: List[str] = Field(
        default_factory=list,
        description="Key telemetry gaps or unobserved investigation leads (e.g. missing parent process or egress)",
    )


    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """Normalizes severity strings to uppercase before validation."""
        if isinstance(v, str):
            clean = v.strip().upper()
            if clean in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                return clean
        raise ValueError(f"Invalid severity level: {v}")

