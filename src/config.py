"""Centralized configuration and environment variable loading for TriageLens (WIRE-1).

Provides canonical variable names with backward-compatible aliases, automated
parent directory creation for SQLite databases, and secure validation logging
that strictly guards against leaking credentials or secret values.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Automatically load environment variables from .env on import
load_dotenv()

# Canonical configuration variable definitions
CANONICAL_CONFIG_VARS = [
    "GEMINI_API_KEY",
    "GEMINI_MODEL",
    "GEMINI_FALLBACK_MODELS",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "DATABASE_PATH",
    "BACKEND_HOST",
    "BACKEND_PORT",
    "ALLOWED_ORIGINS",
    "VITE_API_BASE_URL",
]

# Supported backward-compatible aliases
SUPPORTED_CONFIG_ALIASES = {
    "VT_API_KEY": "VIRUSTOTAL_API_KEY",
    "TRIAGELENS_DB_PATH": "DATABASE_PATH",
}


def get_database_path() -> str:
    """Returns the configured SQLite database file path.

    Checks canonical DATABASE_PATH, then TRIAGELENS_DB_PATH alias,
    defaulting to 'data/triagelens.db'. Automatically creates parent
    directories if not an in-memory database.
    """
    path = os.getenv("DATABASE_PATH") or os.getenv("TRIAGELENS_DB_PATH") or "data/triagelens.db"
    clean_path = path.strip()
    if clean_path != ":memory:":
        try:
            Path(clean_path).parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning("Could not create parent directory for database path '%s': %s", clean_path, e)
    return clean_path


def get_gemini_api_key() -> Optional[str]:
    """Returns the Gemini API key if configured."""
    key = os.getenv("GEMINI_API_KEY")
    return key.strip() if key else None


def get_gemini_model() -> str:
    """Returns the configured primary Gemini model identifier."""
    return os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()


def get_gemini_fallback_models() -> List[str]:
    """Returns the candidate fallback model identifiers to try on quota or error."""
    raw = os.getenv("GEMINI_FALLBACK_MODELS")
    if raw:
        models = [m.strip() for m in raw.split(",") if m.strip()]
        if models:
            return models
    return ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite"]


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


def validate_config() -> Dict[str, Any]:
    """Validates configuration at startup and logs safe status messages.

    CRITICAL SECURITY MANDATE:
    Never prints, logs, or returns raw API keys or secret values.
    """
    db_path = get_database_path()
    gemini_key = get_gemini_api_key()
    gemini_model = get_gemini_model()
    gemini_fallbacks = get_gemini_fallback_models()
    vt_key = get_virustotal_api_key()
    abuse_key = get_abuseipdb_api_key()

    status_summary = {
        "database_path": db_path,
        "gemini_model": gemini_model,
        "gemini_fallbacks": gemini_fallbacks,
        "gemini_configured": bool(gemini_key),
        "virustotal_configured": bool(vt_key),
        "abuseipdb_configured": bool(abuse_key),
    }

    logger.info("[Config] Target SQLite Database: %s", db_path)
    logger.info(
        "[Config] Gemini Triage Engine : Model='%s', Fallbacks=%s, API Key=%s",
        gemini_model,
        gemini_fallbacks,
        "configured" if gemini_key else "not configured",
    )
    logger.info(
        "[Config] Threat Intelligence : VirusTotal=%s, AbuseIPDB=%s, URLhaus=public/keyless",
        "configured" if vt_key else "not configured",
        "configured" if abuse_key else "not configured",
    )

    return status_summary
