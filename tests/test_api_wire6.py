"""Tests for end-to-end wiring: CLI, SQLite database, API metrics, and dashboard alignment (WIRE-6).

Verifies:
1. /api/metrics dynamically computes statistics from stored evaluations in SQLite.
2. Starting the API on a file-backed database containing evaluations returns non-zero metrics
   matching the evaluations table.
3. Metrics returned by /api/metrics match AccuracyTracker metrics recomputed from stored evaluations.
4. scripts/run_evaluation.py supports an end-to-end mode running through real pipeline stages.
"""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import uuid
from fastapi.testclient import TestClient
import pytest

from src.api.main import create_app
from src.engine.database import DatabaseManager
from src.engine.evaluation import AccuracyTracker
from src.engine.enrichment import EnrichmentEngine, ThreatIntelProvider
from src.models.alert import NormalizedAlert
from src.models.evaluation import EvaluationResult
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


def test_api_metrics_computed_from_file_database(tmp_path: Path):
    """Verify that /api/metrics dynamically computes metrics from a file-backed SQLite database containing evaluations."""
    db_file = tmp_path / "triagelens_file_test.db"
    db = DatabaseManager(db_path=str(db_file), check_same_thread=False)
    db.init_db()

    # Create 4 timelines with verdicts and evaluations:
    # 2 True Positives, 1 True Negative, 1 False Positive
    # Total = 4, Accuracy = 3/4 = 0.75, Precision = 2/3 = 0.6667, Recall = 2/2 = 1.0, F1 = 0.8
    test_cases = [
        ("TP-1", "HIGH", 0.92, True, True, "True Positive"),
        ("TP-2", "CRITICAL", 0.95, True, True, "True Positive"),
        ("TN-1", "LOW", 0.90, False, False, "True Negative"),
        ("FP-1", "MEDIUM", 0.75, False, True, "False Positive"),
    ]

    for name, sev, conf, gt, pred, cat in test_cases:
        t_id = uuid.uuid4()
        v_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        tl = ThreatTimeline(
            timeline_id=t_id,
            grouping_key=f"host:{name}",
            total_events=1,
            start_time=now,
            end_time=now,
        )
        db.insert_timeline(tl)

        verd = TriageVerdict(
            verdict_id=v_id,
            timeline_id=t_id,
            severity=sev,
            confidence_score=conf,
            summary=f"Summary for {name}",
            reasoning=[f"Reason for {name}"],
            recommended_actions=["Isolate host"],
            raw_llm_response="{}",
            created_at=now,
        )
        db.insert_verdict(verd)

        eval_res = EvaluationResult(
            timeline_id=t_id,
            verdict_id=v_id,
            ground_truth=gt,
            llm_prediction=pred,
            is_correct=(gt == pred),
            category=cat,
            confidence_score=conf,
            severity_prediction=sev,
        )
        db.insert_evaluation(eval_res)

    # Initialize FastAPI application with ONLY the file-backed database (no in-memory tracker)
    app = create_app(db=db)
    client = TestClient(app)

    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    data = resp.json()

    # Assert that metrics are computed directly from the stored evaluations
    assert data.get("total") == 4
    assert data.get("tp") == 2
    assert data.get("tn") == 1
    assert data.get("fp") == 1
    assert data.get("fn") == 0
    assert data.get("accuracy") == pytest.approx(0.75, abs=1e-3)
    assert data.get("precision") == pytest.approx(2 / 3, abs=1e-3)
    assert data.get("recall") == pytest.approx(1.0, abs=1e-3)
    assert data.get("f1_score") == pytest.approx(0.8, abs=1e-3)


def test_api_metrics_equals_recomputed_tracker_metrics(tmp_path: Path):
    """Verify that /api/metrics output exactly matches AccuracyTracker.from_database(db).get_metrics()."""
    db_file = tmp_path / "triagelens_recompute.db"
    db = DatabaseManager(db_path=str(db_file), check_same_thread=False)
    db.init_db()

    # Insert sample records
    t_id = uuid.uuid4()
    v_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    db.insert_timeline(ThreatTimeline(timeline_id=t_id, grouping_key="workstation:alice", total_events=2))
    db.insert_verdict(TriageVerdict(
        verdict_id=v_id,
        timeline_id=t_id,
        severity="CRITICAL",
        confidence_score=0.98,
        summary="Ransomware execution observed",
        reasoning=["vssadmin shadow copy deletion"],
        recommended_actions=["Disconnect network interface"],
        raw_llm_response="{}",
    ))
    db.insert_evaluation(EvaluationResult(
        timeline_id=t_id,
        verdict_id=v_id,
        ground_truth=True,
        llm_prediction=True,
        is_correct=True,
        category="True Positive",
        confidence_score=0.98,
        severity_prediction="CRITICAL",
    ))

    # Recompute tracker directly from database
    db_tracker = AccuracyTracker.from_database(db)
    expected_metrics = db_tracker.get_metrics()

    # Query API
    app = create_app(db=db)
    client = TestClient(app)
    api_metrics = client.get("/api/metrics").json()

    assert api_metrics["tp"] == expected_metrics["tp"] == 1
    assert api_metrics["accuracy"] == expected_metrics["accuracy"] == 1.0
    assert api_metrics["total"] == expected_metrics["total"] == 1


@pytest.mark.parametrize("credentials_configured", [False, True])
def test_run_evaluation_end_to_end_mode_with_enrichment(tmp_path: Path, monkeypatch, credentials_configured):
    """Verify that scripts/run_evaluation.py end-to-end mode runs through enrichment and persists evaluations."""
    from scripts.run_evaluation import run_evaluation_pipeline

    # Test both local credential states using placeholders, never real secrets.
    for name in ("VIRUSTOTAL_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY", "URLHAUS_API_KEY", "AUTH_KEY"):
        if credentials_configured:
            monkeypatch.setenv(name, "offline-placeholder")
        else:
            monkeypatch.delenv(name, raising=False)

    class StubProvider(ThreatIntelProvider):
        def __init__(self, provider_name):
            super().__init__()
            self.provider_name = provider_name
            self.calls = []

        @property
        def name(self):
            return self.provider_name

        def lookup_with_status(self, indicator, indicator_type):
            self.calls.append((indicator, indicator_type))
            return EnrichmentResult(
                indicator=indicator, indicator_type=indicator_type, provider=self.name,
                is_malicious=True, lookup_status="ok", raw_response={"fixture": True},
            )

    providers = {name: StubProvider(name) for name in ("virustotal", "abuseipdb")}

    def create_offline_enrichment(**kwargs):
        return EnrichmentEngine(providers=providers, daily_quotas={}, **kwargs)

    # Retain real routing, caching, pipeline attachment, and SQLite persistence.
    monkeypatch.setattr("scripts.run_evaluation.EnrichmentEngine", create_offline_enrichment)

    db_file = tmp_path / "eval_e2e.db"

    # Create one labelled fixture alert with an indicator.
    alerts = [
        NormalizedAlert(
            source_dataset="test",
            source_file="test.json",
            event_type="network_traffic",
            extracted_indicators=["198.51.100.55"],
            ground_truth_label="malicious",
            original_record={"process": "mal.exe", "is_malicious": True, "severity": "HIGH"},
        )
    ]
    tl = ThreatTimeline(
        timeline_id=uuid.uuid4(),
        grouping_key="e2e_host:user",
        alerts=alerts,
        total_events=1,
    )

    mock_verdict = TriageVerdict(
        verdict_id=uuid.uuid4(),
        timeline_id=tl.timeline_id,
        severity="HIGH",
        confidence_score=0.90,
        summary="High severity malware detection",
        reasoning=["Suspicious network connection"],
        recommended_actions=["Block IP"],
        raw_llm_response="{}",
    )

    with patch("scripts.run_evaluation.get_groq_api_key", return_value="mock_groq_key"), \
         patch("scripts.run_evaluation.GroqTriageEngine.analyze_timeline", return_value=mock_verdict):
        metrics = run_evaluation_pipeline(
            timelines=[tl],
            db_path=str(db_file),
            end_to_end=True,
        )

    assert metrics["tp"] == 1
    assert metrics["total"] == 1

    # Verify that evaluations were persisted into the SQLite database
    db = DatabaseManager(str(db_file))
    conn = db.connect()
    count = conn.execute("SELECT COUNT(*) FROM evaluations;").fetchone()[0]
    assert count == 1
    assert all(provider.calls == [("198.51.100.55", "ip")] for provider in providers.values())
    assert {result.provider for result in tl.enrichment_data} == set(providers)
    enrichments = db.get_enrichments("198.51.100.55")
    assert len(enrichments) == 2
    assert {row["provider"] for row in enrichments} == set(providers)
    assert all(row["lookup_status"] == "ok" for row in enrichments)
    db.close()

