"""LLM-Assisted Triage Engine using the Google Gemini API.

Provides structured threat analysis, severity scoring, and investigative recommendations
while enforcing PII masking and defense against hallucinations.
"""

import json
import logging
import os
import re
from typing import Any, Dict, Optional
import httpx
from pydantic import ValidationError

from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict
from src.utils.masking import PIIScrubber

logger = logging.getLogger(__name__)

DFIR_SYSTEM_PROMPT = """You are an elite Tier-3 Digital Forensics and Incident Response (DFIR) security analyst.
Your mission is to perform automated security alert triage and threat analysis on chronological timelines.
Analyze the correlated events, original log attributes, and threat intelligence indicators provided.

You must deliver an objective, actionable, and rigorously structured triage assessment.
CRITICAL REQUIREMENT: Output MUST be a single valid JSON object strictly matching this schema:
{
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
    "confidence_score": <float between 0.0 and 1.0>,
    "summary": "<concise executive summary of observed threat activity>",
    "reasoning": [
        "<concrete analytical finding with supporting evidence>",
        "<another analytical point>"
    ],
    "recommended_actions": [
        "<immediate containment or response step>",
        "<further investigation or eradication action>"
    ]
}
Do not include any introductory remarks, markdown prose outside the JSON block, or post-analysis commentary. Output ONLY the JSON object.
"""


class GeminiTriageEngine:
    """Engine responsible for LLM-assisted alert triage and threat timeline analysis.

    Enforces PII/credential scrubbing before external transmission, communicates
    with the Gemini REST API, defends against formatting hallucinations,
    and validates LLM responses against structured Pydantic schemas.
    """

    DEFAULT_MODEL = "gemini-2.5-flash"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 15.0,
        scrubber: Optional[PIIScrubber] = None,
    ) -> None:
        """Initializes the GeminiTriageEngine.

        Args:
            api_key: Gemini API key. Defaults to the GEMINI_API_KEY environment variable.
            model: Gemini model identifier (e.g., 'gemini-2.5-flash').
            timeout: HTTP request timeout in seconds.
            scrubber: Optional custom PIIScrubber instance.

        Raises:
            ValueError: If no API key is provided and GEMINI_API_KEY is not set.
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY is required to initialize GeminiTriageEngine. "
                "Provide it directly or configure the GEMINI_API_KEY environment variable."
            )
        self.model = model or self.DEFAULT_MODEL
        self.timeout = timeout
        self.scrubber = scrubber or PIIScrubber()

    def _extract_json(self, raw_text: str) -> Optional[Dict[str, Any]]:
        """Extracts and parses a JSON object from raw LLM output.

        Defends against markdown fences (```json ... ```) and conversational fluff.

        Args:
            raw_text: Raw string returned by the LLM.

        Returns:
            Parsed dictionary or None if parsing fails.
        """
        if not raw_text or not isinstance(raw_text, str):
            return None

        # 1. Try direct JSON parsing
        try:
            return json.loads(raw_text.strip())
        except json.JSONDecodeError:
            pass

        # 2. Extract content within markdown code fences: ```json ... ``` or ``` ... ```
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", raw_text, re.IGNORECASE)
        if fence_match:
            candidate = fence_match.group(1).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # 3. Extract the outermost balanced or outermost braces: find first '{' and last '}'
        start_idx = raw_text.find("{")
        end_idx = raw_text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            candidate = raw_text[start_idx : end_idx + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # Clean trailing commas before closing braces/brackets
                cleaned = re.sub(r",\s*([\]}])", r"\1", candidate)
                try:
                    return json.loads(cleaned)
                except json.JSONDecodeError:
                    pass

        return None

    def analyze_timeline(self, timeline: ThreatTimeline) -> Optional[TriageVerdict]:
        """Performs AI-assisted triage analysis on a threat timeline.

        Aggressively scrubs PII and credentials, prompts the Gemini API,
        parses the response, and returns a validated TriageVerdict.

        Args:
            timeline: The ThreatTimeline to analyze.

        Returns:
            Validated TriageVerdict or None if the API fails or schema is violated.
        """
        if not isinstance(timeline, ThreatTimeline):
            logger.error("analyze_timeline requires a valid ThreatTimeline instance.")
            return None

        # 1. Serialize timeline and scrub all PII / credentials
        timeline_raw_json = timeline.model_dump_json(indent=2)
        sanitized_timeline_json = self.scrubber.scrub(timeline_raw_json)

        # 2. Construct API request payload
        user_prompt = (
            f"Analyze the following correlated security threat timeline and provide "
            f"a structured triage assessment:\n\n{sanitized_timeline_json}"
        )

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "systemInstruction": {
                "parts": [{"text": DFIR_SYSTEM_PROMPT}]
            },
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }

        # 3. Transmit request with resilience handling
        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=self.timeout)
        except httpx.TimeoutException as exc:
            logger.error(f"Gemini API request timed out after {self.timeout}s: {exc}")
            return None
        except httpx.RequestError as exc:
            logger.error(f"Gemini API network request error: {exc}")
            return None

        # 4. Handle HTTP status codes (outages, rate limits)
        if response.status_code == 429:
            logger.warning("Gemini API rate limit exceeded (HTTP 429).")
            return None
        elif response.status_code == 503:
            logger.error("Gemini API service temporarily unavailable (HTTP 503).")
            return None
        elif response.status_code != 200:
            logger.error(
                f"Gemini API request failed with HTTP {response.status_code}: {response.text}"
            )
            return None

        # 5. Extract raw text from Gemini response structure
        try:
            res_data = response.json()
        except Exception as exc:
            logger.error(f"Failed to decode Gemini response JSON: {exc}")
            return None

        raw_llm_text = ""
        try:
            candidates = res_data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    raw_llm_text = parts[0].get("text", "")
        except (KeyError, IndexError, TypeError) as exc:
            logger.error(f"Unexpected response structure from Gemini API: {exc}")
            return None

        # Fallback if mock or response provides text directly
        if not raw_llm_text:
            if "text" in res_data:
                raw_llm_text = res_data["text"]
            elif isinstance(res_data, str):
                raw_llm_text = res_data

        # 6. Parse JSON from raw output (defend against hallucinations / conversational fluff)
        parsed_dict = self._extract_json(raw_llm_text)
        if not parsed_dict or not isinstance(parsed_dict, dict):
            logger.error(f"Failed to extract valid JSON object from LLM response: {raw_llm_text}")
            return None

        # 7. Validate against Pydantic TriageVerdict schema
        try:
            verdict = TriageVerdict(
                timeline_id=timeline.timeline_id,
                severity=parsed_dict.get("severity"),
                confidence_score=parsed_dict.get("confidence_score"),
                summary=parsed_dict.get("summary"),
                reasoning=parsed_dict.get("reasoning", []),
                recommended_actions=parsed_dict.get("recommended_actions", []),
                raw_llm_response=raw_llm_text,
            )
            return verdict
        except ValidationError as val_err:
            logger.error(f"LLM triage response schema validation failed: {val_err}")
            return None
        except Exception as exc:
            logger.error(f"Unexpected error constructing TriageVerdict: {exc}")
            return None

