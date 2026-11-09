"""Data models for AI-assisted alert triage and analysis."""

from typing import Any, List, Literal, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator, model_validator
from src.models.evidence import EvidenceBasis, EVIDENCE_CONTRACT_VERSION
from src.engine.attack import validate_techniques

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
Disposition = Literal["MALICIOUS", "BENIGN", "UNDETERMINED"]


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
    disposition: Optional[Disposition] = None
    policy_version: Optional[str] = Field(default=None, min_length=1)
    evidence_basis: Optional[EvidenceBasis] = None
    evidence_context: Optional[dict[str, dict[str, Any]]] = None
    evidence_contract_version: Optional[str] = None
    model_name: Optional[str] = Field(
        default=None,
        description="The answering model identifier that generated this triage assessment",
    )
    uncertainty_level: Optional[Literal["LOW", "MEDIUM", "HIGH"]] = Field(
        default=None,
        description="Assessed degree of analytical uncertainty based on available telemetry",
    )
    missing_information: List[str] = Field(
        default_factory=list,
        description="Key telemetry gaps or unobserved investigation leads (e.g. missing parent process or egress)",
    )
    predicted_techniques: Optional[List[str]] = Field(
        default=None, description="Unverified AI-predicted ATT&CK Enterprise 17.1 IDs; null means unrecorded."
    )

    @field_validator('predicted_techniques')
    @classmethod
    def validate_predicted_techniques(cls, value):
        if value is None:
            return None
        valid, invalid = validate_techniques(value)
        if invalid:
            raise ValueError('Unknown or inactive ATT&CK technique ID')
        return valid


    @model_validator(mode="after")
    def require_versioned_disposition(self):
        if (self.disposition is None) != (self.policy_version is None):
            raise ValueError("Disposition and policy version must be recorded together")
        metadata = (self.evidence_basis, self.evidence_context, self.evidence_contract_version)
        if self.policy_version == "triage-v2" or any(value is not None for value in metadata):
            if (any(value is None for value in metadata) or self.policy_version in (None, "triage-v1")
                    or self.evidence_contract_version != EVIDENCE_CONTRACT_VERSION):
                raise ValueError("Versioned evidence contract is missing or unsupported")
            self.evidence_basis.validate_decision(self.disposition, self.uncertainty_level, self.missing_information)
            self.evidence_basis.validate_context(self.evidence_context)
        return self

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """Normalizes severity strings to uppercase before validation."""
        if isinstance(v, str):
            clean = v.strip().upper()
            if clean in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                return clean
        raise ValueError(f"Invalid severity level: {v}")

