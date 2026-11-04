"""Adversarial and concurrency test suite for SQLite DatabaseManager.

Tests:
- SQL Injection Defense: Malicious payloads in alert, timeline, and verdict fields.
- High-Concurrency Threading: 100 simultaneous threads inserting records into :memory:.
- Foreign Key Enforcement: Strict rejection of orphaned verdicts and evaluations.
- Context Manager Semantics: Transaction commit on success, rollback on error.
- Deep JSON Serialization: Verification of nested dictionaries without corruption.
"""

import concurrent.futures
import sqlite3
import threading
from uuid import uuid4
import pytest

from src.engine.database import DatabaseManager
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.evaluation import EvaluationResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict


@pytest.fixture
def in_memory_db():
    """Provides an initialized in-memory DatabaseManager."""
    db = DatabaseManager(":memory:", check_same_thread=False)
    db.init_db()
    return db


# =====================================================================
# 1. SQL Injection Defense Tests
# =====================================================================


def test_sql_injection_defense_event_type_drop_table(in_memory_db):
    """Verify parameterized queries prevent SQL injection payloads from executing.

    Attempts to inject: '; DROP TABLE alerts; --
    """
    injection_alert = NormalizedAlert(
        source_dataset="test_feed",
        source_file="test_log.json",
        event_type="'; DROP TABLE alerts; --",
        original_record={"payload": "'; DROP TABLE timelines; --", "nested": {"key": "' OR 1=1; --"}},
        extracted_indicators=["198.51.100.1"],
        ground_truth_label="' OR '1'='1",
    )

    alert_id = in_memory_db.insert_alert(injection_alert)

    # 1. Assert alerts table still exists and has count == 1
    cursor = in_memory_db.connection.execute("SELECT COUNT(*) FROM alerts;")
    assert cursor.fetchone()[0] == 1

    # 2. Retrieve alert and verify string was stored literally without truncation or execution
    retrieved = in_memory_db.get_alert(alert_id)
    assert retrieved is not None
    assert retrieved["event_type"] == "'; DROP TABLE alerts; --"
    assert retrieved["ground_truth_label"] == "' OR '1'='1"
    assert retrieved["original_record"]["payload"] == "'; DROP TABLE timelines; --"


def test_sql_injection_defense_timeline_and_verdict(in_memory_db):
    """Verify parameterized queries protect timelines and verdicts against injection."""
    timeline = ThreatTimeline(
        grouping_key="admin' UNION SELECT * FROM sqlite_master; --",
        alerts=[],
        total_events=0,
    )
    timeline_id = in_memory_db.insert_timeline(timeline)

    retrieved_tl = in_memory_db.get_timeline(timeline_id)
    assert retrieved_tl is not None
    assert retrieved_tl["grouping_key"] == "admin' UNION SELECT * FROM sqlite_master; --"

    verdict = TriageVerdict(
        timeline_id=timeline.timeline_id,
        severity="HIGH",
        confidence_score=0.9,
        summary="'; DELETE FROM verdicts; --",
        reasoning=["Finding '; DROP TABLE evaluations; --"],
        recommended_actions=["Action 1"],
        raw_llm_response="raw",
    )
    verdict_id = in_memory_db.insert_verdict(verdict)

    retrieved_v = in_memory_db.get_verdict(verdict_id)
    assert retrieved_v is not None
    assert retrieved_v["summary"] == "'; DELETE FROM verdicts; --"
    assert retrieved_v["reasoning"] == ["Finding '; DROP TABLE evaluations; --"]


# =====================================================================
# 2. Foreign Key Constraint Violation Tests
# =====================================================================


def test_foreign_key_violation_verdict_without_timeline(in_memory_db):
    """Verify sqlite3.IntegrityError is raised when inserting a verdict for a non-existent timeline."""
    fake_timeline_id = uuid4()
    orphaned_verdict = TriageVerdict(
        timeline_id=fake_timeline_id,
        severity="CRITICAL",
        confidence_score=0.95,
        summary="Orphaned verdict",
        reasoning=["No timeline exists"],
        recommended_actions=["None"],
        raw_llm_response="{}",
    )

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        in_memory_db.insert_verdict(orphaned_verdict)


def test_foreign_key_violation_evaluation_without_verdict(in_memory_db):
    """Verify sqlite3.IntegrityError when inserting evaluation referencing non-existent verdict."""
    timeline = ThreatTimeline(grouping_key="group_a", alerts=[], total_events=0)
    in_memory_db.insert_timeline(timeline)

    orphaned_evaluation = EvaluationResult(
        timeline_id=timeline.timeline_id,
        verdict_id=uuid4(),  # Non-existent verdict ID
        ground_truth=True,
        llm_prediction=True,
        is_correct=True,
        category="True Positive",
    )

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        in_memory_db.insert_evaluation(orphaned_evaluation)


def test_foreign_key_valid_relational_chain(in_memory_db):
    """Verify successful relational inserts across timeline -> alert -> verdict -> evaluation."""
    timeline = ThreatTimeline(grouping_key="group_1", alerts=[], total_events=0)
    in_memory_db.insert_timeline(timeline)

    alert = NormalizedAlert(
        source_dataset="ds",
        source_file="f.json",
        event_type="login",
        original_record={"user": "admin"},
    )
    in_memory_db.insert_alert(alert, timeline_id=timeline.timeline_id)

    verdict = TriageVerdict(
        timeline_id=timeline.timeline_id,
        severity="MEDIUM",
        confidence_score=0.75,
        summary="Valid verdict",
        reasoning=["Observed login"],
        recommended_actions=["Verify user"],
        raw_llm_response="{}",
    )
    in_memory_db.insert_verdict(verdict)

    eval_result = EvaluationResult(
        timeline_id=timeline.timeline_id,
        verdict_id=verdict.verdict_id,
        ground_truth=True,
        llm_prediction=True,
        is_correct=True,
        category="True Positive",
    )
    eval_id = in_memory_db.insert_evaluation(eval_result)
    assert eval_id > 0

    # Retrieve and verify relationship
    evaluations = in_memory_db.get_evaluations_for_timeline(timeline.timeline_id)
    assert len(evaluations) == 1
    assert evaluations[0]["category"] == "True Positive"
    assert evaluations[0]["verdict_id"] == str(verdict.verdict_id)


# =====================================================================
# 3. Concurrency & Locking Tests (100 Threads)
# =====================================================================


def test_concurrency_and_locking_100_threads(in_memory_db):
    """Simulate 100 simultaneous threads inserting alerts into in-memory SQLite.

    Verifies check_same_thread=False, RLock serialization, and busy_timeout
    prevent 'sqlite3.OperationalError: database is locked'.
    """
    num_threads = 100
    errors = []
    inserted_ids = []
    lock = threading.Lock()

    def worker_insert(thread_idx: int):
        try:
            alert = NormalizedAlert(
                source_dataset=f"dataset_{thread_idx}",
                source_file=f"file_{thread_idx}.json",
                event_type=f"event_{thread_idx}",
                original_record={"thread_id": thread_idx, "data": "concurrent_test"},
                extracted_indicators=[f"10.0.0.{thread_idx}"],
                ground_truth_label="benign",
            )
            aid = in_memory_db.insert_alert(alert)
            with lock:
                inserted_ids.append(aid)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(target=worker_insert, args=(i,)) for i in range(num_threads)
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join(timeout=10.0)

    # 1. Assert zero exceptions across all 100 threads
    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"

    # 2. Assert all 100 alerts were inserted
    assert len(inserted_ids) == num_threads
    assert in_memory_db.count_alerts() == num_threads


# =====================================================================
# 4. Context Manager Semantics (Commit & Rollback)
# =====================================================================


def test_context_manager_commit_on_success(in_memory_db):
    """Verify operations inside a 'with' block are committed on normal exit."""
    with in_memory_db:
        alert = NormalizedAlert(
            source_dataset="cm_test",
            source_file="f.json",
            event_type="test_cm",
            original_record={"key": "val"},
        )
        in_memory_db.insert_alert(alert)

    assert in_memory_db.count_alerts() == 1


def test_context_manager_rollback_on_error(in_memory_db):
    """Verify operations are rolled back when an unhandled exception occurs."""
    initial_count = in_memory_db.count_alerts()

    with pytest.raises(RuntimeError, match="Simulated pipeline failure"):
        with in_memory_db:
            # Direct execute on connection inside context
            in_memory_db.connection.execute(
                """
                INSERT INTO alerts (
                    id, timeline_id, timestamp, source_dataset, source_file,
                    event_type, original_record, extracted_indicators,
                    ground_truth_label, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                ("temp_id", None, None, "ds", "f", "ev", "{}", "[]", None, "now"),
            )
            # Raise exception before exit to trigger rollback
            raise RuntimeError("Simulated pipeline failure")

    assert in_memory_db.count_alerts() == initial_count


# =====================================================================
# 5. Enrichment Persistence Tests
# =====================================================================


def test_enrichment_persistence_and_retrieval(in_memory_db):
    """Verify EnrichmentResult insertion and retrieval by indicator."""
    enrichment = EnrichmentResult(
        indicator="198.51.100.99",
        indicator_type="ip",
        provider="VirusTotal",
        is_malicious=True,
        raw_response={"malicious_votes": 42},
    )

    row_id = in_memory_db.insert_enrichment(enrichment)
    assert row_id > 0

    results = in_memory_db.get_enrichments("198.51.100.99")
    assert len(results) == 1
    assert results[0]["provider"] == "VirusTotal"
    assert results[0]["is_malicious"] is True
    assert results[0]["raw_response"] == {"malicious_votes": 42}


# =====================================================================
# 6. Deep JSON Data Preservation Tests
# =====================================================================


def test_deep_json_data_preservation(in_memory_db):
    """Verify complex nested dictionaries survive database serialization and retrieval."""
    complex_record = {
        "network": {
            "source": {"ip": "10.0.0.1", "port": 443},
            "destination": {"ip": "198.51.100.1", "port": 53},
            "protocols": ["TCP", "TLSv1.3"],
        },
        "flags": [True, False, None],
        "metrics": {"entropy": 7.92, "packet_count": 1045},
    }

    alert = NormalizedAlert(
        source_dataset="deep_ds",
        source_file="deep.json",
        event_type="ComplexEvent",
        original_record=complex_record,
        extracted_indicators=["10.0.0.1", "198.51.100.1"],
    )

    alert_id = in_memory_db.insert_alert(alert)
    retrieved = in_memory_db.get_alert(alert_id)

    assert retrieved is not None
    assert retrieved["original_record"] == complex_record
    assert retrieved["extracted_indicators"] == ["10.0.0.1", "198.51.100.1"]

