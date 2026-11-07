"""Tests for Task WIRE-7: Documentation parity, MIT license, and /health database check."""

from pathlib import Path
import re
import sqlite3
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from src.api.main import create_app
from src.engine.database import DatabaseManager


def test_readme_api_table_matches_app_routes():
    """Verify that every route documented in README.md Section 6 exactly matches

    the real operational routes in FastAPI app.routes (bidirectional parity).
    """
    readme_path = Path("README.md")
    assert readme_path.exists(), "README.md must exist."

    content = readme_path.read_text(encoding="utf-8")

    # Extract Section 6: API Reference table
    sec6_match = re.search(r"## 6\.\s+API Reference(.*?)(?=\n## |\Z)", content, re.DOTALL)
    assert sec6_match is not None, "README.md must contain Section 6. API Reference."
    sec6_text = sec6_match.group(1)

    # Parse rows like: | `GET` | `/api/metrics` | ... |
    row_pattern = re.compile(r"^\|\s*`([A-Z]+)`\s*\|\s*`([^`]+)`\s*\|", re.MULTILINE)
    documented_routes = set(row_pattern.findall(sec6_text))

    assert len(documented_routes) > 0, "No documented routes found in README Section 6 table."

    # Extract actual application routes
    app = create_app(db=DatabaseManager(":memory:"))
    ignored_paths = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
    actual_routes = set()

    for route in app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if not methods or not path or path in ignored_paths:
            continue
        for method in methods:
            if method in ("HEAD", "OPTIONS"):
                continue
            actual_routes.add((method, path))

    # Bidirectional assertions
    missing_from_readme = actual_routes - documented_routes
    extra_in_readme = documented_routes - actual_routes

    assert not missing_from_readme, f"Routes in app.routes but missing from README.md: {missing_from_readme}"
    assert not extra_in_readme, f"Routes in README.md but not in app.routes: {extra_in_readme}"
    assert documented_routes == actual_routes


def test_health_check_healthy_database():
    """Verify /health returns 200 and confirms database connectivity when healthy."""
    db = DatabaseManager(":memory:")
    db.init_db()
    app = create_app(db=db)
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"


def test_health_check_database_failure_returns_503():
    """Verify /health returns 503 Service Unavailable when the database is unreachable."""
    db = MagicMock(spec=DatabaseManager)
    # Simulate DB operational failure on connection execution
    db.connection.execute.side_effect = sqlite3.OperationalError("disk I/O error or closed connection")

    app = create_app(db=db)
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Database unhealthy"


def test_mit_license_file_exists_and_valid():
    """Verify that the MIT LICENSE file exists at project root and contains standard MIT text."""
    license_path = Path("LICENSE")
    assert license_path.exists(), "LICENSE file must exist at project root."
    text = license_path.read_text(encoding="utf-8")
    assert "MIT License" in text
    assert "Permission is hereby granted, free of charge" in text
