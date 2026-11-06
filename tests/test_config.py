"""Tests for centralized configuration, environment variable loading, and README parity (WIRE-1)."""

import os
from pathlib import Path
import re
import pytest

from src.config import (
    CANONICAL_CONFIG_VARS,
    SUPPORTED_CONFIG_ALIASES,
    get_abuseipdb_api_key,
    get_backend_host,
    get_backend_port,
    get_database_path,
    get_gemini_api_key,
    get_gemini_fallback_models,
    get_gemini_model,
    get_virustotal_api_key,
    validate_config,
)
from src.engine.enrichment import AbuseIPDBProvider, VirusTotalProvider
from src.api.main import create_app


def test_virustotal_canonical_and_alias(monkeypatch):
    """Verify VirusTotal API key loading supports canonical name and VT_API_KEY alias."""
    # 1. Canonical VIRUSTOTAL_API_KEY
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "canonical-vt-key-12345")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert get_virustotal_api_key() == "canonical-vt-key-12345"
    vt = VirusTotalProvider()
    assert vt.api_key == "canonical-vt-key-12345"

    # 2. Legacy VT_API_KEY fallback alias
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setenv("VT_API_KEY", "legacy-vt-key-67890")
    assert get_virustotal_api_key() == "legacy-vt-key-67890"
    vt_alias = VirusTotalProvider()
    assert vt_alias.api_key == "legacy-vt-key-67890"

    # 3. Canonical takes precedence over alias
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "primary-vt-key")
    monkeypatch.setenv("VT_API_KEY", "secondary-vt-key")
    assert get_virustotal_api_key() == "primary-vt-key"


def test_abuseipdb_api_key(monkeypatch):
    """Verify AbuseIPDB API key is properly loaded by config and provider."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-key-xyz")
    assert get_abuseipdb_api_key() == "abuse-key-xyz"
    provider = AbuseIPDBProvider()
    assert provider.api_key == "abuse-key-xyz"


def test_database_path_canonical_and_alias(monkeypatch, tmp_path):
    """Verify database path loading supports DATABASE_PATH and TRIAGELENS_DB_PATH alias."""
    custom_db = str(tmp_path / "custom.db")
    monkeypatch.setenv("DATABASE_PATH", custom_db)
    monkeypatch.delenv("TRIAGELENS_DB_PATH", raising=False)
    assert get_database_path() == custom_db

    alias_db = str(tmp_path / "alias.db")
    monkeypatch.delenv("DATABASE_PATH", raising=False)
    monkeypatch.setenv("TRIAGELENS_DB_PATH", alias_db)
    assert get_database_path() == alias_db

    # Default fallback when neither is set
    monkeypatch.delenv("DATABASE_PATH", raising=False)
    monkeypatch.delenv("TRIAGELENS_DB_PATH", raising=False)
    assert get_database_path() == "data/triagelens.db"


def test_api_uses_file_database_by_default(monkeypatch, tmp_path):
    """Verify API initializes with configured file database, NOT an empty in-memory DB."""
    test_db = str(tmp_path / "api_test.db")
    monkeypatch.setenv("DATABASE_PATH", test_db)
    app = create_app()
    assert getattr(app.state.db, "db_path", None) == test_db
    assert getattr(app.state.db, "db_path", None) != ":memory:"


def test_gemini_config_and_fallbacks(monkeypatch):
    """Verify Gemini primary model and fallback candidate parsing."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "gemini-3.5-flash-lite,gemini-3.1-flash-lite")

    assert get_gemini_api_key() == "test-gemini-key"
    assert get_gemini_model() == "gemini-3.8-flash"
    assert get_gemini_fallback_models() == ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite"]


def test_backend_host_and_port(monkeypatch):
    """Verify backend host and port configuration."""
    monkeypatch.setenv("BACKEND_HOST", "0.0.0.0")
    monkeypatch.setenv("BACKEND_PORT", "9000")
    assert get_backend_host() == "0.0.0.0"
    assert get_backend_port() == 9000


def test_safe_validation_logging_never_prints_secrets(caplog, monkeypatch):
    """Verify validate_config() logs configuration status without printing secret keys."""
    raw_secret_gemini = "AIzaSyD-super-secret-gemini-key"
    raw_secret_vt = "vt-secret-token-abcdef12345"

    monkeypatch.setenv("GEMINI_API_KEY", raw_secret_gemini)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", raw_secret_vt)

    import logging
    with caplog.at_level(logging.INFO):
        summary = validate_config()

    assert raw_secret_gemini not in caplog.text
    assert raw_secret_vt not in caplog.text
    assert "configured" in caplog.text or summary.get("gemini_configured") is True


def test_env_example_and_readme_parity():
    """Verify exact parity between .env.example, README.md, and code configuration variables."""
    root_dir = Path(__file__).resolve().parent.parent
    env_example_path = root_dir / ".env.example"
    readme_path = root_dir / "README.md"

    assert env_example_path.exists(), ".env.example must exist"
    assert readme_path.exists(), "README.md must exist"

    # Extract variable names from .env.example
    env_example_text = env_example_path.read_text(encoding="utf-8")
    env_example_vars = set(
        re.findall(r"^[A-Z0-9_]+(?==)", env_example_text, re.MULTILINE)
    )

    # Extract variable names from README.md env code blocks
    readme_text = readme_path.read_text(encoding="utf-8")
    readme_env_matches = re.findall(r"```env\s*([\s\S]*?)```", readme_text)
    readme_vars = set()
    for block in readme_env_matches:
        for var in re.findall(r"^\s*([A-Z0-9_]+)(?==)", block, re.MULTILINE):
            readme_vars.add(var)

    all_supported_vars = set(CANONICAL_CONFIG_VARS).union(SUPPORTED_CONFIG_ALIASES.keys())

    # Assert .env.example variables are all supported
    for var in env_example_vars:
        assert var in all_supported_vars, f"Variable '{var}' in .env.example is not supported by src.config"

    # Assert README variables are all supported
    for var in readme_vars:
        assert var in all_supported_vars, f"Variable '{var}' in README.md is not supported by src.config"

    # Assert canonical variables in .env.example match README.md canonical variables
    assert "GEMINI_API_KEY" in env_example_vars and "GEMINI_API_KEY" in readme_vars
    assert "GEMINI_MODEL" in env_example_vars and "GEMINI_MODEL" in readme_vars
    assert "GEMINI_FALLBACK_MODELS" in env_example_vars and "GEMINI_FALLBACK_MODELS" in readme_vars
    assert "DATABASE_PATH" in env_example_vars or "TRIAGELENS_DB_PATH" in env_example_vars
