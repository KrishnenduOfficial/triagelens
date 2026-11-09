"""Centralized configuration and environment variable loading for TriageLens (WIRE-1).

Provides canonical variable names with backward-compatible aliases, automated
parent directory creation for SQLite databases, and secure validation logging
that strictly guards against leaking credentials or secret values.
"""

import logging
import os
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Automatically load environment variables from .env on import
load_dotenv()

# Canonical configuration variable definitions
CANONICAL_CONFIG_VARS = [
    "GROQ_API_KEY",
    "GROQ_MODEL",
    "GROQ_FALLBACK_MODELS",
    "GROQ_REQUESTS_PER_MINUTE",
    "GROQ_TOKENS_PER_MINUTE",
    "GROQ_ESTIMATED_TOKENS_PER_REQUEST",
    "GROQ_MAX_WAIT_SECONDS",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "URLHAUS_API_KEY",
    "VIRUSTOTAL_MIN_DETECTIONS",
    "ABUSEIPDB_MIN_SCORE",
    "DATABASE_PATH",
    "BACKEND_HOST",
    "BACKEND_PORT",
    "ALLOWED_ORIGINS",
    "VITE_API_BASE_URL",
    "ENRICHMENT_WAIT_MODE",
    "ENRICHMENT_MAX_WAIT_SECONDS",
    "VIRUSTOTAL_DAILY_QUOTA",
    "VIRUSTOTAL_REQUESTS_PER_MINUTE",
    "ENRICHMENT_MAX_LOOKUPS_PER_RUN",
    "YARA_SCAN_ROOTS",
]

# Supported backward-compatible aliases
SUPPORTED_CONFIG_ALIASES = {
    "VT_API_KEY": "VIRUSTOTAL_API_KEY",
    "TRIAGELENS_DB_PATH": "DATABASE_PATH",
}


def get_yara_scan_roots() -> Dict[str, str]:
    """Read explicit local root registrations; an empty setting disables scans."""
    raw = os.getenv('YARA_SCAN_ROOTS', '').strip()
    if not raw:
        return {}
    try:
        roots = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError('Invalid YARA_SCAN_ROOTS configuration') from None
    if (not isinstance(roots, dict) or len(roots) > 20 or
            any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', k)
                or not isinstance(v, str) or len(v) > 1024 for k, v in roots.items())):
        raise ValueError('Invalid YARA_SCAN_ROOTS configuration')
    return roots


def get_database_path(override: Optional[str] = None) -> str:
    """Resolve a SQLite target consistently for CLI, API, and evaluation.

    Precedence: explicit override, nonblank DATABASE_PATH, nonblank alias,
    then data/triagelens.db. Relative paths use PROJECT_ROOT, never cwd.
    Disk paths are absolute and their parents are created before returning.
    Explicit blank overrides and filesystem errors fail before opening SQLite.
    The exact :memory: sentinel remains available for deliberate ephemeral use.
    """
    if override is not None:
        clean_path = override.strip()
        if not clean_path:
            raise ValueError("Explicit database path must not be blank or empty")
    else:
        clean_path = next(
            (value.strip() for value in (
                os.getenv("DATABASE_PATH", ""), os.getenv("TRIAGELENS_DB_PATH", "")
            ) if value.strip()),
            "data/triagelens.db",
        )
    if clean_path == ":memory:":
        return clean_path
    path = Path(clean_path)
    if not path.is_absolute():
        if path.drive or path.root:
            raise ValueError("Windows database paths must be fully qualified or project-relative")
        path = PROJECT_ROOT / path
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def get_groq_api_key() -> Optional[str]:
    """Return the Groq credential."""
    key = os.getenv("GROQ_API_KEY", "").strip()
    return key or None


def get_groq_model() -> str:
    """Return the active Groq model, with a nonblank default."""
    return os.getenv("GROQ_MODEL", "").strip() or "openai/gpt-oss-120b"


def get_groq_fallback_models() -> List[str]:
    """Fallback is opt-in; no automatic model or provider substitution."""
    return list(dict.fromkeys(
        item.strip() for item in os.getenv("GROQ_FALLBACK_MODELS", "").split(",")
        if item.strip()
    ))


def get_groq_pacing_config() -> tuple[int, int, int, float]:
    """Return explicitly bounded per-engine pacing settings."""
    import math
    try:
        rpm = int(os.getenv("GROQ_REQUESTS_PER_MINUTE", "30"))
        tpm = int(os.getenv("GROQ_TOKENS_PER_MINUTE", "8000"))
        estimate = int(os.getenv("GROQ_ESTIMATED_TOKENS_PER_REQUEST", "4000"))
        wait = float(os.getenv("GROQ_MAX_WAIT_SECONDS", "60"))
    except ValueError as exc:
        raise ValueError("Invalid Groq pacing configuration") from exc
    if rpm <= 0 or tpm <= 0 or not 0 < estimate <= tpm or not math.isfinite(wait) or wait < 0:
        raise ValueError("Invalid Groq pacing configuration")
    return rpm, tpm, estimate, wait


def get_virustotal_api_key() -> Optional[str]:
    """Returns the VirusTotal API key.

    Checks canonical VIRUSTOTAL_API_KEY first, falling back to legacy VT_API_KEY alias.
    """
    key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    return key.strip() if key else None


def get_abuseipdb_api_key() -> Optional[str]:
    """Returns the AbuseIPDB API key if configured."""
    key = os.getenv("ABUSEIPDB_API_KEY")
    return key.strip() if key else None


def get_urlhaus_api_key() -> Optional[str]:
    """Returns the URLhaus / abuse.ch API Auth-Key if configured."""
    key = os.getenv("URLHAUS_API_KEY")
    return key.strip() if key else None


def get_virustotal_min_detections() -> int:
    """Return the malicious engine detection threshold (default: 3)."""
    raw = os.getenv("VIRUSTOTAL_MIN_DETECTIONS", "3").strip()
    try:
        val = int(raw)
        return val if val >= 1 else 3
    except ValueError:
        logger.warning("Invalid VIRUSTOTAL_MIN_DETECTIONS '%s', defaulting to 3", raw)
        return 3


def get_abuseipdb_min_score() -> int:
    """Returns the minimum AbuseIPDB confidence score required for a malicious verdict (default: 25)."""
    raw = os.getenv("ABUSEIPDB_MIN_SCORE", "25").strip()
    try:
        val = int(raw)
        return val if 0 <= val <= 100 else 25
    except ValueError:
        logger.warning("Invalid ABUSEIPDB_MIN_SCORE '%s', defaulting to 25", raw)
        return 25


def get_backend_host() -> str:
    """Returns the backend binding host (default: 127.0.0.1)."""
    return os.getenv("BACKEND_HOST", "127.0.0.1").strip()


def get_backend_port() -> int:
    """Returns the backend listening port (default: 8000)."""
    raw_port = os.getenv("BACKEND_PORT", "8000").strip()
    try:
        return int(raw_port)
    except ValueError:
        logger.warning("Invalid BACKEND_PORT '%s', defaulting to 8000", raw_port)
        return 8000


def get_allowed_origins() -> List[str]:
    """Returns the list of allowed CORS origins for local frontend communication."""
    default_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    env_origins = os.getenv("ALLOWED_ORIGINS")
    if env_origins:
        extra = [o.strip() for o in env_origins.split(",") if o.strip()]
        for o in extra:
            if o not in default_origins:
                default_origins.append(o)
    return default_origins


def get_vite_api_base_url() -> str:
    """Returns the frontend API base URL (default: http://localhost:8000)."""
    return os.getenv("VITE_API_BASE_URL", "http://localhost:8000").strip()


def get_enrichment_wait_mode() -> bool:
    """Returns True if threat intelligence enrichment rate limiting is in wait mode."""
    raw = os.getenv("ENRICHMENT_WAIT_MODE", "false").strip().lower()
    return raw in ("true", "1", "yes", "on")


def get_enrichment_max_wait_seconds() -> float:
    """Returns maximum allowed wait time in seconds for rate limiter pausing (default: 60.0)."""
    raw = os.getenv("ENRICHMENT_MAX_WAIT_SECONDS", "60.0").strip()
    try:
        val = float(raw)
        return max(0.0, val)
    except ValueError:
        logger.warning("Invalid ENRICHMENT_MAX_WAIT_SECONDS '%s', defaulting to 60.0", raw)
        return 60.0


def get_virustotal_daily_quota() -> Optional[int]:
    """Returns the VirusTotal daily request quota (default: 500 for free tier)."""
    raw = os.getenv("VIRUSTOTAL_DAILY_QUOTA", "500").strip()
    if not raw or raw.lower() in ("none", "null", "0", "unlimited"):
        return None
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("Invalid VIRUSTOTAL_DAILY_QUOTA '%s', defaulting to 500", raw)
        return 500


def get_virustotal_requests_per_minute() -> int:
    """Returns the VirusTotal requests per minute limit (default: 4 for free tier)."""
    raw = os.getenv("VIRUSTOTAL_REQUESTS_PER_MINUTE", "4").strip()
    try:
        val = int(raw)
        return max(1, val)
    except ValueError:
        logger.warning("Invalid VIRUSTOTAL_REQUESTS_PER_MINUTE '%s', defaulting to 4", raw)
        return 4


def get_enrichment_max_lookups() -> Optional[int]:
    """Parse the configured cap; currently no runtime caller uses this getter."""
    raw = os.getenv("ENRICHMENT_MAX_LOOKUPS_PER_RUN")
    if not raw or raw.strip().lower() in ("none", "null", "0", "unlimited"):
        return None
    try:
        return max(1, int(raw.strip()))
    except ValueError:
        return None


def validate_config() -> Dict[str, Any]:
    """Validates configuration at startup and logs safe status messages.

    CRITICAL SECURITY MANDATE:
    Never prints, logs, or returns raw API keys or secret values.
    """
    db_path = get_database_path()
    groq_key = get_groq_api_key()
    groq_model = get_groq_model()
    groq_fallbacks = get_groq_fallback_models()
    vt_key = get_virustotal_api_key()
    abuse_key = get_abuseipdb_api_key()
    urlhaus_key = get_urlhaus_api_key()
    vt_threshold = get_virustotal_min_detections()
    abuse_threshold = get_abuseipdb_min_score()
    wait_mode = get_enrichment_wait_mode()
    max_wait = get_enrichment_max_wait_seconds()
    vt_quota = get_virustotal_daily_quota()
    vt_rpm = get_virustotal_requests_per_minute()

    status_summary = {
        "database_path": db_path,
        "llm_provider": "groq",
        "groq_model": groq_model,
        "groq_fallbacks": groq_fallbacks,
        "groq_configured": bool(groq_key),
        "virustotal_configured": bool(vt_key),
        "abuseipdb_configured": bool(abuse_key),
        "urlhaus_configured": bool(urlhaus_key),
        "virustotal_min_detections": vt_threshold,
        "abuseipdb_min_score": abuse_threshold,
        "enrichment_wait_mode": wait_mode,
        "enrichment_max_wait_seconds": max_wait,
        "virustotal_daily_quota": vt_quota,
        "virustotal_requests_per_minute": vt_rpm,
    }

    logger.info("[Config] Target SQLite Database: %s", db_path)
    logger.info(
        "[Config] Groq Triage Engine : Model='%s', Fallbacks=%s, API Key=%s",
        groq_model,
        groq_fallbacks,
        "configured" if groq_key else "not configured",
    )
    logger.info(
        "[Config] Threat Intelligence : VirusTotal=%s (min_detections=%d), AbuseIPDB=%s (min_score=%d), URLhaus=%s",
        "configured" if vt_key else "not configured",
        vt_threshold,
        "configured" if abuse_key else "not configured",
        abuse_threshold,
        "configured (Auth-Key)" if urlhaus_key else "public/keyless",
    )

    return status_summary
