"""Utility module for scrubbing PII and sensitive credentials from log payloads."""

import re
from typing import Any, Optional


def is_luhn_valid(number_str: str) -> bool:
    """Validates a number string using the Luhn checksum algorithm (mod 10).

    Args:
        number_str: String containing digits and optional delimiters.

    Returns:
        True if the number has a valid length (13 to 19 digits) and satisfies Luhn checksum.
    """
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d

    return checksum % 10 == 0


class PIIScrubber:
    """Aggressively scrubs Personally Identifiable Information (PII) and credentials

    before sending data to external LLM providers or unvetted external services.
    Redacts:
    - Email addresses -> [EMAIL_REDACTED]
    - Credit card numbers -> [CC_REDACTED] (verified via Luhn algorithm)
    - AWS/GCP API keys and secrets -> [SECRET_REDACTED]
    - Passwords and auth tokens in key-value, JSON, and dictionary structures -> [SECRET_REDACTED]
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
        r"(?:2(?:2[2-9][0-9]{2}|[3-6][0-9]{3}|7[01][0-9]{2}|720[0-9])[0-9]{10})|"  # Mastercard 2-series
        r"(?:3[47][0-9]{13})|"  # Amex contiguous (15 digits)
        r"(?:3[47][0-9]{2}[- ][0-9]{6}[- ][0-9]{5})|"  # Amex formatted
        r"(?:6(?:011|5[0-9]{2}|4[4-9][0-9])[0-9]{12})|"  # Discover (16 digits)
        r"(?:35[0-9]{14})|"  # JCB (16 digits)
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

    # Key-value secret assignments: supports quoted keys, escaped quotes, unquoted keys,
    # embedded/prefixed keys (e.g. db_password, admin_api_key), and '=' or ':' separators
    KV_SECRET_PATTERN = re.compile(
        r"(?i)((?:\\?[\"']|\b)(?:[a-zA-Z0-9_\-\.]+[_\-\.])?"
        r"(?:api[_-]?key|secret[_-]?key|aws_secret_access_key|[a-zA-Z0-9_\-\.]*[_-]?token|"
        r"private[_-]?key|client[_-]?secret|"
        r"[a-zA-Z0-9_\-\.]*[_-]?(?:password|passwd|pwd))(?:\\?[\"'])?\s*[:=]\s*\\?[\"']?)"
        r"([^\"'\s\r\n\\]{6,})"
        r"(\\?[\"']?)"
    )

    # Authorization Bearer tokens
    BEARER_PATTERN = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9_\-\.]{20,}\b")

    # Private key blocks
    PRIVATE_KEY_PATTERN = re.compile(
        r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
    )

    SECRET_KEY_PATTERN = re.compile(
        r"(?i)(?:^|[_-])(?:password|passwd|pwd|token|tokens|secret|secrets|apikey|apikeys|api_key|api_keys|private_key|client_secret)(?:$|[_-])"
    )

    def _replace_cc_if_valid(self, match: re.Match) -> str:
        """Callback for CC_PATTERN replacement that requires Luhn validation."""
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        has_delimiters = "-" in raw or " " in raw

        # If contiguous 16-digit number, require Luhn check AND card prefix
        if not has_delimiters:
            if not is_luhn_valid(digits):
                return raw
            if not any(digits.startswith(p) for p in ("4", "5", "3", "6", "2")):
                return raw
            return "[CC_REDACTED]"

        # If formatted with delimiters:
        if is_luhn_valid(digits) or any(digits.startswith(p) for p in ("4", "5", "3", "6")):
            return "[CC_REDACTED]"

        return raw

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

        # 4. Redact Key-Value secrets (JSON-aware, supports quotes, prefixes, separators)
        result = self.KV_SECRET_PATTERN.sub(r"\g<1>[SECRET_REDACTED]\g<3>", result)

        # 5. Redact Emails
        result = self.EMAIL_PATTERN.sub("[EMAIL_REDACTED]", result)

        # 6. Redact Credit Card numbers (with Luhn validation to protect IDs and timestamps)
        result = self.CC_PATTERN.sub(self._replace_cc_if_valid, result)

        return result

    def scrub_dict(self, data: Any) -> Any:
        """Recursively traverses dictionaries, lists, and values, scrubbing secrets and PII.

        Provides structural scrubbing prior to JSON serialization.
        """
        if isinstance(data, dict):
            scrubbed = {}
            for k, v in data.items():
                k_str = str(k)
                lower_k = k_str.lower()
                is_secret_key = (
                    self.SECRET_KEY_PATTERN.search(lower_k) is not None
                    or any(tok in lower_k for tok in ("password", "passwd", "pwd", "api_key", "secret_key", "token", "secret"))
                    or lower_k in {"secret", "secrets", "token", "tokens", "apikey", "apikeys"}
                )
                if is_secret_key:
                    if isinstance(v, list):
                        scrubbed[k] = ["[SECRET_REDACTED]" for _ in v]
                    elif isinstance(v, dict):
                        scrubbed[k] = self.scrub_dict(v)
                    else:
                        scrubbed[k] = "[SECRET_REDACTED]"
                elif isinstance(v, (dict, list)):
                    scrubbed[k] = self.scrub_dict(v)
                elif isinstance(v, str):
                    scrubbed[k] = self.scrub(v)
                else:
                    scrubbed[k] = v
            return scrubbed
        elif isinstance(data, list):
            return [self.scrub_dict(item) for item in data]
        elif isinstance(data, str):
            return self.scrub(data)
        else:
            return data
