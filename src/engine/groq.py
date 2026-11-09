"""Groq transport for the shared, privacy-preserving triage pipeline."""

import json
import math
import re
import threading
import time
from collections import deque
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from src import config
from src.engine.llm import TriageEngineBase
from src.engine.triage_policy import POLICY_VERSION
from src.models.triage import Disposition, SeverityLevel
from src.models.evidence import EvidenceBasis, NonBlank, EVIDENCE_CONTRACT_VERSION


class GroqAssessment(BaseModel):
    """Only model-authored fields; identity/provenance remain application-owned."""

    model_config = ConfigDict(extra="forbid", strict=True)
    disposition: Disposition
    severity: SeverityLevel
    confidence_score: float = Field(ge=0, le=1)
    uncertainty_level: Literal["LOW", "MEDIUM", "HIGH"]
    summary: NonBlank
    reasoning: list[NonBlank] = Field(min_length=1)
    missing_information: list[NonBlank]
    recommended_actions: list[NonBlank] = Field(min_length=1)
    evidence_basis: EvidenceBasis

    @model_validator(mode="after")
    def require_abstention_explanation(self):
        self.evidence_basis.validate_decision(self.disposition, self.uncertainty_level, self.missing_information)
        return self


class GroqTriageEngine(TriageEngineBase):
    """Strict-schema Groq completion; no implicit retries or model fallback."""

    DEFAULT_MODEL = "openai/gpt-oss-120b"
    DEFAULT_FALLBACK_MODELS = []
    ENV_KEY = "GROQ_API_KEY"
    ENV_MODEL = "GROQ_MODEL"
    ENV_FALLBACKS = "GROQ_FALLBACK_MODELS"
    PROVIDER_ID = "groq/openai/v1/chat/completions"
    PROVIDER_LABEL = "Groq"
    POLICY_VERSION = POLICY_VERSION
    EVIDENCE_CONTRACT_VERSION = EVIDENCE_CONTRACT_VERSION
    ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
    # Deliberately limited to models documented to support strict structured output.
    SUPPORTED_MODELS = frozenset({"openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"})

    def __init__(self, api_key=None, model=None, fallback_models=None, timeout=30.0,
                 pacing_clock=None, pacing_sleep=None, pacing_wall_clock=None,
                 pacing_config=None, **kwargs):
        key = (api_key if api_key is not None else config.get_groq_api_key()) or ""
        if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise ValueError("A nonblank, header-safe GROQ_API_KEY is required.")
        selected = model if model is not None else config.get_groq_model()
        fallbacks = list(fallback_models) if fallback_models is not None else config.get_groq_fallback_models()
        if any(candidate not in self.SUPPORTED_MODELS for candidate in [selected, *fallbacks]):
            raise ValueError("Unsupported Groq model; use a documented strict-schema model.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Groq timeout must be positive and finite.")
        self._rpm, self._tpm, self._token_estimate, self._max_wait = (
            pacing_config if pacing_config is not None else config.get_groq_pacing_config())
        if (not all(isinstance(v, int) and not isinstance(v, bool) and v > 0
                    for v in (self._rpm, self._tpm, self._token_estimate))
                or self._token_estimate > self._tpm or not math.isfinite(self._max_wait)
                or self._max_wait < 0):
            raise ValueError("Invalid Groq pacing configuration")
        self._pacing_clock = pacing_clock or time.monotonic
        self._pacing_sleep = pacing_sleep or time.sleep
        self._pacing_wall_clock = pacing_wall_clock or time.time
        self._pacing_lock = threading.Lock()
        self._requests = deque()
        self._token_balance = None
        self._token_reset_at = 0.0
        self._blocked_until = 0.0
        self._waited = 0.0
        # Provider bodies and exception strings can contain sensitive telemetry.
        kwargs["include_error_details"] = False
        super().__init__(api_key=key, model=selected, fallback_models=fallbacks,
                         timeout=timeout, **kwargs)

    def analyze_timeline(self, timeline):
        # Serialize acquisition so reservations and the per-analysis wait budget
        # cannot race with another request through this engine instance.
        with self._pacing_lock:
            self._waited = 0.0
            return super().analyze_timeline(timeline)

    def _before_provider_request(self):
        while True:
            now = self._pacing_clock()
            while self._requests and self._requests[0][0] <= now - 60:
                self._requests.popleft()
            if self._token_estimate > self._tpm:
                return False
            due = self._blocked_until
            if (len(self._requests) >= self._rpm or
                    sum(tokens for _, tokens in self._requests) + self._token_estimate > self._tpm):
                due = max(due, self._requests[0][0] + 60)
            if (self._token_balance is not None and now < self._token_reset_at
                    and self._token_balance < self._token_estimate):
                due = max(due, self._token_reset_at)
            delay = max(0.0, due - now)
            if not delay:
                self._requests.append((now, self._token_estimate))
                if self._token_balance is not None and now < self._token_reset_at:
                    self._token_balance -= self._token_estimate
                return True
            if self._waited + delay > self._max_wait:
                return False
            self._pacing_sleep(delay)
            self._waited += delay

    def _after_provider_response(self, response):
        # Account for usage even when the completion later fails validation.
        try:
            usage = response.json().get("usage", {}).get("total_tokens")
        except (ValueError, AttributeError, TypeError):
            usage = None
        if isinstance(usage, int) and not isinstance(usage, bool) and usage > 0:
            if self._requests:
                stamp, reserved = self._requests[-1]
                self._requests[-1] = (stamp, max(reserved, usage))
            self._token_estimate = max(self._token_estimate, usage)
        # Groq's token headers describe TPM (request headers describe daily quota).
        remaining = response.headers.get("x-ratelimit-remaining-tokens", "")
        reset = self._reset_seconds(response.headers.get("x-ratelimit-reset-tokens", ""))
        if re.fullmatch(r"[0-9]{1,12}", remaining) and reset is not None:
            self._token_balance = int(remaining)
            self._token_reset_at = self._pacing_clock() + reset
        if response.status_code != 429:
            return
        if reset is not None:
            self._blocked_until = max(self._blocked_until, self._pacing_clock() + reset)
        value = response.headers.get("Retry-After", "").strip()
        try:
            delay = float(value)
        except ValueError:
            try:
                stamp = parsedate_to_datetime(value)
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                delay = stamp.timestamp() - self._pacing_wall_clock()
            except (TypeError, ValueError, OverflowError):
                return
        if math.isfinite(delay) and delay >= 0:
            self._blocked_until = max(self._blocked_until, self._pacing_clock() + delay)

    @staticmethod
    def _reset_seconds(value):
        """Parse only finite nonnegative Groq duration metadata, never error bodies."""
        if not isinstance(value, str) or len(value) > 80:
            return None
        match = re.fullmatch(r"(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?", value)
        if match is None or not any(match.groups()):
            return None
        delay = sum(float(part or 0) * scale for part, scale in zip(match.groups(), (3600, 60, 1)))
        return delay if math.isfinite(delay) else None

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

    def _prepare_evidence(self, payload):
        context = {}
        for name, prefix in (("events", "E"), ("enrichment_data", "I")):
            for index, record in enumerate(payload[name], 1):
                identifier = f"{prefix}{index}"
                record["evidence_id"] = identifier
                context[identifier] = deepcopy(record)
        return context

    def _verdict_metadata(self, assessment, evidence_context):
        return {"disposition": assessment["disposition"], "policy_version": self.POLICY_VERSION,
                "evidence_basis": assessment["evidence_basis"], "evidence_context": evidence_context,
                "evidence_contract_version": self.EVIDENCE_CONTRACT_VERSION}

    def _cache_compatible(self, verdict, evidence_context):
        data = verdict.model_dump(mode="json")
        assessment = {name: data[name] for name in GroqAssessment.model_fields}
        return (self._normalize_assessment(assessment) == assessment
                and verdict.policy_version == self.POLICY_VERSION
                and verdict.evidence_contract_version == self.EVIDENCE_CONTRACT_VERSION
                and verdict.evidence_context == evidence_context)

    def _prepare_request(self, candidate, user_prompt, generation, system_prompt):
        return (
            self.ENDPOINT,
            {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            {"model": candidate, "messages": [
                {"role": "system", "content": system_prompt},
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

    def _normalize_assessment(self, assessment):
        try:
            return GroqAssessment.model_validate(assessment).model_dump(mode="json")
        except (ValidationError, ValueError, TypeError):
            return None
