"""Offline shared-path regressions using real CLI persistence and API reads."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from src import cli, config
from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.enrichment import EnrichmentEngine
from src.models.triage import TriageVerdict


@pytest.fixture
def project(monkeypatch, tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    work = tmp_path / "working-directory"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setattr(config, "PROJECT_ROOT", root, raising=False)
    monkeypatch.delenv("DATABASE_PATH", raising=False)
    monkeypatch.delenv("TRIAGELENS_DB_PATH", raising=False)
    return root


@pytest.mark.parametrize("source", ["default", "canonical", "alias", "absolute", "memory"])
def test_config_paths_are_absolute_and_independent_of_cwd(monkeypatch, project, source):
    expected = project / "data" / "triagelens.db"
    if source in ("canonical", "alias"):
        variable = "DATABASE_PATH" if source == "canonical" else "TRIAGELENS_DB_PATH"
        monkeypatch.setenv(variable, "storage/shared.db")
        expected = project / "storage" / "shared.db"
    elif source == "absolute":
        expected = project.parent / "external" / "shared.db"
        monkeypatch.setenv("DATABASE_PATH", str(expected))
    elif source == "memory":
        monkeypatch.setenv("DATABASE_PATH", " :memory: ")
    first = config.get_database_path()
    monkeypatch.chdir(project)
    second = config.get_database_path()
    assert first == second == (":memory:" if source == "memory" else str(expected))
    if source != "memory":
        assert expected.parent.is_dir()
        assert not expected.exists()  # resolving creates directories, never a database


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_canonical_uses_nonblank_alias(monkeypatch, project, blank):
    monkeypatch.setenv("DATABASE_PATH", blank)
    monkeypatch.setenv("TRIAGELENS_DB_PATH", " alias/shared.db ")
    assert config.get_database_path() == str(project / "alias" / "shared.db")


def test_blank_environment_paths_use_persistent_default(monkeypatch, project):
    monkeypatch.setenv("DATABASE_PATH", " ")
    monkeypatch.setenv("TRIAGELENS_DB_PATH", "\t")
    assert config.get_database_path() == str(project / "data" / "triagelens.db")


def test_nonblank_canonical_precedes_alias(monkeypatch, project):
    monkeypatch.setenv("DATABASE_PATH", " canonical.db ")
    monkeypatch.setenv("TRIAGELENS_DB_PATH", "alias.db")
    assert config.get_database_path() == str(project / "canonical.db")


@pytest.mark.parametrize("absolute", [False, True])
def test_explicit_override_precedes_environment_and_creates_parent(monkeypatch, project, absolute):
    monkeypatch.setenv("DATABASE_PATH", "environment.db")
    target = project.parent / "outside" / "cli.db" if absolute else project / "nested" / "cli.db"
    supplied = str(target) if absolute else " nested/cli.db "
    assert config.get_database_path(supplied) == str(target)
    assert target.parent.is_dir()
    assert not (project / "environment.db").exists()


@pytest.mark.parametrize("blank", ["", " ", "\t\n"])
def test_explicit_blank_path_is_rejected(project, blank):
    with pytest.raises(ValueError, match="empty|blank"):
        config.get_database_path(blank)


def test_explicit_memory_override_remains_memory(monkeypatch, project):
    monkeypatch.setenv("DATABASE_PATH", "environment.db")
    assert config.get_database_path(" :memory: ") == ":memory:"
    assert not (project / ":memory:").exists()


@pytest.mark.parametrize("supplied", ["D:relative.db", "\\relative.db"])
def test_windows_partial_paths_cannot_depend_on_current_drive(project, supplied):
    path = Path(supplied)
    if path.drive or path.root:
        with pytest.raises(ValueError, match="fully qualified"):
            config.get_database_path(supplied)
    else:
        # On POSIX these are ordinary relative filenames, not drive/root syntax.
        assert config.get_database_path(supplied) == str(project / supplied)


def test_directory_creation_error_is_not_silenced(monkeypatch, project):
    def deny(*args, **kwargs):
        raise PermissionError("offline denied directory")

    monkeypatch.setattr(Path, "mkdir", deny)
    with pytest.raises(PermissionError, match="offline denied directory"):
        config.get_database_path()


def test_resolution_preserves_existing_databases_and_default_selection(project):
    # Resolving must never select, move, overwrite, or merge the legacy root file.
    legacy = project / "triagelens.db"
    current = project / "data" / "triagelens.db"
    current.parent.mkdir()
    legacy.write_bytes(b"legacy database evidence fixture")
    current.write_bytes(b"configured database evidence fixture")
    before = {path: path.read_bytes() for path in (legacy, current)}
    assert config.get_database_path() == str(current)
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize("explicit", [False, True])
def test_evaluation_runner_uses_same_resolver(monkeypatch, project, explicit):
    from scripts import run_evaluation

    class OfflineEngine:
        model = "offline-fixture"
        fallback_models = []

        def __init__(self, **kwargs):
            pass

        def analyze_timeline(self, timeline):
            raise AssertionError("No timelines should be submitted")

    monkeypatch.setattr(run_evaluation, "get_groq_api_key", lambda: "offline-placeholder")
    monkeypatch.setattr(run_evaluation, "GroqTriageEngine", OfflineEngine)
    if explicit:
        monkeypatch.setenv("DATABASE_PATH", "nested/evaluation.db")
    metrics = run_evaluation.run_evaluation_pipeline(
        timelines=[], db_path="nested/evaluation.db" if explicit else None,
    )
    assert metrics["total"] == 0
    selected = project / ("nested/evaluation.db" if explicit else "data/triagelens.db")
    assert selected.is_file()
    app = create_app()
    try:
        assert app.state.db.db_path == str(selected)
        assert app.state.db.connection.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0] == 0
    finally:
        app.state.db.close()


@pytest.mark.parametrize("source", ["default", "canonical", "alias", "matching_override", "separate_override"])
def test_real_cli_and_api_persist_to_resolved_paths(monkeypatch, project, source):
    selected = "data/triagelens.db" if source == "default" else "nested/shared.db"
    override = None
    if source == "alias":
        monkeypatch.setenv("TRIAGELENS_DB_PATH", selected)
    elif source != "default":
        monkeypatch.setenv("DATABASE_PATH", selected)
    if source == "matching_override":
        override = selected
    elif source == "separate_override":
        override = "separate/cli.db"

    input_dir = project / "input"
    input_dir.mkdir()
    (input_dir / "alerts.json").write_text(json.dumps([{
        "timestamp": "2026-01-01T00:00:00Z", "event_type": "ProcessStart",
        "host": "offline-host", "user": "offline-user", "is_malicious": True,
        "ground_truth_label": "malicious", "severity": "HIGH",
    }]), encoding="utf-8")

    class OfflineTriage:
        def __init__(self, **kwargs):
            pass

        def analyze_timeline(self, timeline):
            return TriageVerdict(
                timeline_id=timeline.timeline_id, severity="HIGH", confidence_score=0.9,
                summary="Offline fixture verdict", reasoning=["Fixture evidence"],
                recommended_actions=["Review fixture"], raw_llm_response="{}",
            )

    opened = []

    class RecordedDatabase(DatabaseManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            opened.append(self)

    monkeypatch.setattr(cli, "DatabaseManager", RecordedDatabase)
    monkeypatch.setattr(cli, "GroqTriageEngine", OfflineTriage)
    monkeypatch.setattr(config, "get_groq_api_key", lambda: "offline-placeholder")
    monkeypatch.setattr(cli, "EnrichmentEngine", lambda **kwargs: EnrichmentEngine(providers={}, daily_quotas={}, **kwargs))
    app = None
    try:
        metrics = cli.run_pipeline(data_dir=str(input_dir), db_path=override)
        assert metrics["tp"] == metrics["total"] == 1
        assert opened[0].db_path == str(project / (override or selected))
        monkeypatch.chdir(project)  # API starts from a different cwd than CLI
        app = create_app()
        assert app.state.db.db_path == str(project / selected)
        with TestClient(app) as client:
            response = client.get("/api/metrics")
            assert response.status_code == 200
            api_metrics = response.json()
            if source == "separate_override":
                assert api_metrics["total"] == 0
                assert opened[0].db_path != app.state.db.db_path
            else:
                assert api_metrics["total"] == api_metrics["tp"] == 1
                assert api_metrics["accuracy"] == metrics["accuracy"] == 1.0
                for table in ("alerts", "timelines", "verdicts", "evaluations"):
                    assert app.state.db.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 1
    finally:
        for database in opened:
            database.close()
        if app is not None:
            app.state.db.close()
