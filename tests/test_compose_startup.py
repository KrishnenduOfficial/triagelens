"""Offline checks for the Compose startup boundary."""
import importlib.util
from pathlib import Path

import pytest
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("compose_start", ROOT / "deploy" / "start.py")
startup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(startup)


def test_dsn_preserves_special_characters():
    result = conninfo_to_dict(startup.dsn("tl_hunt_login", "space ' and \\ characters"))
    assert result["password"] == "space ' and \\ characters"
    assert result["user"] == "tl_hunt_login"
    assert result["host"] == "db"


def test_migration_rejects_shared_password_before_connecting(monkeypatch):
    for name in ("POSTGRES_PASSWORD", "TL_ANALYST_PASSWORD", "TL_HUNT_PASSWORD",
                 "TL_EVALUATOR_PASSWORD", "TL_TRIAGE_PASSWORD"):
        monkeypatch.setenv(name, "same")
    with pytest.raises(ValueError, match="distinct"):
        startup.migrate()


def test_api_uses_only_analyst_and_hunt_credentials(monkeypatch):
    monkeypatch.setenv("TL_ANALYST_PASSWORD", "analyst-password")
    monkeypatch.setenv("TL_HUNT_PASSWORD", "hunt-password")
    for name in ("DATABASE_BACKEND", "TRIAGELENS_POSTGRES_ANALYST_DSN",
                 "TRIAGELENS_POSTGRES_HUNT_DSN"):
        monkeypatch.setenv(name, "temporary")
    invoked = []
    monkeypatch.setattr(startup.os, "execvp", lambda *args: invoked.append(args))
    startup.api()
    for role in ("ANALYST", "HUNT"):
        parsed = conninfo_to_dict(startup.os.environ[f"TRIAGELENS_POSTGRES_{role}_DSN"])
        assert parsed["user"] == f"tl_{role.lower()}_login"
    assert startup.os.environ["DATABASE_BACKEND"] == "postgresql"
    assert invoked[0][0] == "uvicorn"
