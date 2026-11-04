"""Utility module for scrubbing PII and sensitive credentials from log payloads."""

import re
from typing import Optional


class PIIScrubber:
    """Aggressively scrubs Personally Identifiable Information (PII) and credentials

    before sending data to external LLM providers or unvetted external services.
    Redacts:
    - Email addresses -> [EMAIL_REDACTED]
    - Credit card numbers -> [CC_REDACTED]
    - AWS/GCP API keys and secrets -> [SECRET_REDACTED]
    """

    # Email pattern: standard RFC 5322 simplified pattern
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # Credit card pattern: 13-16 digits with standard formatting or contiguous
    CC_PATTERN = re.compile(
        r"\b(?:"
        r"(?:4[0-9]{12}(?:[0-9]{3})?)|"  # Visa (13 or 16 digits)
        r"(?:5[1-5][0-9]{14})|"  # Mastercard (16 digits)
        r"(?:3[47][0-9]{13})|"  # Amex contiguous (15 digits)
        r"(?:3[47][0-9]{2}[- ][0-9]{6}[- ][0-9]{5})|"  # Amex formatted
        r"(?:6(?:011|5[0-9]{2})[0-9]{12})|"  # Discover (16 digits)
        r"(?:[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{4})|"  # Any 4x4 delimited
        r"(?:[0-9]{16})"  # Contiguous 16 digits
        r")\b"
    )

    # Cloud & Provider-Specific API Key Patterns
    AWS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
    GCP_KEY_PATTERN = re.compile(r"\bAIza[0-9A-Za-z\-_]{30,40}\b")
    TOKEN_PREFIX_PATTERN = re.compile(
        r"\b(?:"
        r"ghp_[a-zA-Z0-9]{36}|"  # GitHub personal token
        r"gho_[a-zA-Z0-9]{36}|"  # GitHub OAuth token
        r"xox[baprs]-[0-9a-zA-Z]{10,48}|"  # Slack token
        r"sk-[a-zA-Z0-9]{20,}|"  # OpenAI / generic sk
        r"sk_(?:live|test)_[0-9a-zA-Z]{20,}"  # Stripe API key
        r")\b"
    )

    # Key-value secret assignments: e.g. api_key="secret", aws_secret_access_key=...
    KV_SECRET_PATTERN = re.compile(
        r"(?i)\b((?:api[_-]?key|secret[_-]?key|aws_secret_access_key|access[_-]?token|"
        r"auth[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret|"
        r"password|passwd|pwd)\s*[:=]\s*[\"']?)([^\"'\s\r\n]{8,})([\"']?)"
    )

    # Authorization Bearer tokens
    BEARER_PATTERN = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9_\-\.]{20,}\b")

    # Private key blocks
    PRIVATE_KEY_PATTERN = re.compile(
        r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
    )

    def scrub(self, text: Optional[str]) -> str:
        """Scrubs emails, credit cards, and API secrets from the input text.

        Args:
            text: Raw string containing potential PII or secrets.

        Returns:
            Sanitized string with sensitive tokens replaced.
        """
        if not text or not isinstance(text, str):
            return ""

        result = text

        # 1. Redact Private Key blocks
        result = self.PRIVATE_KEY_PATTERN.sub("[SECRET_REDACTED]", result)

        # 2. Redact Provider API keys (AWS, GCP, etc.)
        result = self.AWS_KEY_PATTERN.sub("[SECRET_REDACTED]", result)
        result = self.GCP_KEY_PATTERN.sub("[SECRET_REDACTED]", result)
        result = self.TOKEN_PREFIX_PATTERN.sub("[SECRET_REDACTED]", result)

        # 3. Redact Bearer tokens
        result = self.BEARER_PATTERN.sub(r"\g<1>[SECRET_REDACTED]", result)

        # 4. Redact Key-Value secrets
        result = self.KV_SECRET_PATTERN.sub(r"\g<1>[SECRET_REDACTED]\g<3>", result)

        # 5. Redact Emails
        result = self.EMAIL_PATTERN.sub("[EMAIL_REDACTED]", result)

        # 6. Redact Credit Card numbers
        result = self.CC_PATTERN.sub("[CC_REDACTED]", result)

        return result
