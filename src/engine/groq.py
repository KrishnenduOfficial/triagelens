"""Groq transport for the shared, privacy-preserving triage pipeline."""

import json
import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src import config
from src.engine.llm import DFIR_SYSTEM_PROMPT, TriageEngineBase
from src.models.triage import SeverityLevel


class GroqAssessment(BaseModel):
    """Only model-authored fields; identity/provenance remain application-owned."""

    model_config = ConfigDict(extra="forbid", strict=True)
    severity: SeverityLevel
    confidence_score: float = Field(ge=0, le=1)
    uncertainty_level: Literal["LOW", "MEDIUM", "HIGH"]
    summary: str = Field(min_length=1)
    reasoning: list[str]
    missing_information: list[str]
    recommended_actions: list[str]


class GroqTriageEngine(TriageEngineBase):
    """Strict-schema Groq completion; no implicit retries or model fallback."""

    DEFAULT_MODEL = "openai/gpt-oss-120b"
    DEFAULT_FALLBACK_MODELS = []
    ENV_KEY = "GROQ_API_KEY"
    ENV_MODEL = "GROQ_MODEL"
    ENV_FALLBACKS = "GROQ_FALLBACK_MODELS"
    PROVIDER_ID = "groq/openai/v1/chat/completions"
    PROVIDER_LABEL = "Groq"
    ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
    # Deliberately limited to models documented to support strict structured output.
    SUPPORTED_MODELS = frozenset({"openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"})

    def __init__(self, api_key=None, model=None, fallback_models=None, timeout=30.0, **kwargs):
        key = (api_key if api_key is not None else config.get_groq_api_key()) or ""
        if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise ValueError("A nonblank, header-safe GROQ_API_KEY is required.")
        selected = model if model is not None else config.get_groq_model()
        fallbacks = list(fallback_models) if fallback_models is not None else config.get_groq_fallback_models()
        if any(candidate not in self.SUPPORTED_MODELS for candidate in [selected, *fallbacks]):
            raise ValueError("Unsupported Groq model; use a documented strict-schema model.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Groq timeout must be positive and finite.")
        # Provider bodies and exception strings can contain sensitive telemetry.
        kwargs["include_error_details"] = False
        super().__init__(api_key=key, model=selected, fallback_models=fallbacks,
                         timeout=timeout, **kwargs)

    def _generation_settings(self, candidate):
        settings = {
            "temperature": 0.1,
            "max_completion_tokens": 4096,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "triage_assessment", "strict": True,
                                "schema": GroqAssessment.model_json_schema()},
            },
        }
        if candidate.startswith("openai/gpt-oss-"):
            settings["reasoning_effort"] = "low"
        return settings

    def _prepare_request(self, candidate, user_prompt, generation):
        return (
            self.ENDPOINT,
            {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            {"model": candidate, "messages": [
                {"role": "system", "content": DFIR_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ], **generation},
        )

    def _response_text(self, response, candidate):
        # A model mismatch, refusal, tool call or truncated generation is unavailable,
        # even if its content happens to contain a syntactically valid assessment.
        if response["model"] != candidate:
            raise ValueError("Unexpected answering model")
        choices = response["choices"]
        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError("Expected one completion")
        choice = choices[0]
        message = choice["message"]
        if (choice["finish_reason"] != "stop" or message.get("role") != "assistant"
                or message.get("refusal") or message.get("tool_calls")):
            raise ValueError("Incomplete or refused completion")
        if not isinstance(message["content"], str) or not message["content"].strip():
            raise ValueError("Missing assessment content")
        return message["content"]

    def _extract_json(self, raw_text):
        # Groq strict output must be exactly JSON; do not rescue prose or fences.
        try:
            result = json.loads(raw_text)
            return result if isinstance(result, dict) else None
        except (TypeError, ValueError):
            return None

    def _validate_assessment(self, assessment):
        try:
            GroqAssessment.model_validate(assessment)
            return True
        except (ValidationError, ValueError, TypeError):
            return False
