"""Strict, traceable evidence-basis relationships; no semantic safety certification."""

import math
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

EVIDENCE_CONTRACT_VERSION = "evidence-basis-v1"
NonBlank = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class ContractObject(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EvidenceReference(ContractObject):
    evidence_id: NonBlank
    field_path: list[NonBlank] = Field(min_length=1)

    def key(self):
        return self.evidence_id, tuple(self.field_path)


def unique_refs(refs):
    if len({ref.key() for ref in refs}) != len(refs):
        raise ValueError("Duplicate evidence references")
    return refs


class Observation(ContractObject):
    statement: NonBlank
    refs: list[EvidenceReference] = Field(min_length=1)
    _unique = field_validator("refs")(unique_refs)


class Hypothesis(ContractObject):
    statement: NonBlank
    refs: list[EvidenceReference]
    _unique = field_validator("refs")(unique_refs)


class EvidenceGap(ContractObject):
    category: Literal["authorization", "execution_outcome", "protocol", "threat_intelligence",
                      "scope_impact", "process_context", "other"]
    description: NonBlank
    required_evidence: NonBlank
    blocks_disposition: bool


def resolve_reference(context: dict, ref: EvidenceReference):
    """Resolve exact keys/indexes inside one captured sanitized record only."""
    if not re.fullmatch(r"[EI][1-9][0-9]*", ref.evidence_id):
        raise ValueError("Invalid evidence identifier")
    value = context.get(ref.evidence_id)
    if not isinstance(value, dict) or value.get("evidence_id") != ref.evidence_id:
        raise ValueError("Missing evidence record")
    if ref.field_path[0] == "evidence_id":
        raise ValueError("Generated identity is not supporting evidence")
    for token in ref.field_path:
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token) and len(token) < 20:
            index = int(token)
            if index >= len(value):
                raise ValueError("Evidence index out of bounds")
            value = value[index]
        else:
            raise ValueError("Evidence field does not exist")
    if (value is None or type(value) not in (str, int, float, bool)
            or isinstance(value, str) and not value.strip()
            or isinstance(value, float) and not math.isfinite(value)):
        raise ValueError("Evidence target must be a non-null nonblank scalar")
    return value


class EvidenceBasis(ContractObject):
    kind: Literal["malicious_support", "benign_support", "insufficient_evidence"]
    decision_refs: list[EvidenceReference]
    observations: list[Observation]
    hypotheses: list[Hypothesis]
    gaps: list[EvidenceGap]
    _unique = field_validator("decision_refs")(unique_refs)

    def validate_decision(self, disposition, uncertainty, missing_information):
        expected = {"malicious_support": "MALICIOUS", "benign_support": "BENIGN",
                    "insufficient_evidence": "UNDETERMINED"}[self.kind]
        if disposition != expected:
            raise ValueError("Evidence basis and disposition disagree")
        blocking = any(gap.blocks_disposition for gap in self.gaps)
        if self.kind == "insufficient_evidence":
            if uncertainty != "HIGH" or not blocking:
                raise ValueError("Abstention requires high uncertainty and a blocking gap")
        elif blocking or not self.observations or not self.decision_refs:
            raise ValueError("Binary disposition requires observed support and no blocking gap")
        observed = {ref.key() for item in self.observations for ref in item.refs}
        if any(ref.key() not in observed for ref in self.decision_refs):
            raise ValueError("Decision references must occur in observations")
        if missing_information != [gap.description for gap in self.gaps]:
            raise ValueError("Missing-information list and structured gaps disagree")

    def validate_context(self, context: dict[str, dict[str, Any]]):
        for ref in self.decision_refs:
            resolve_reference(context, ref)
        for item in [*self.observations, *self.hypotheses]:
            for ref in item.refs:
                resolve_reference(context, ref)
