"""SQLite persistence and storage engine for TriageLens.

Provides connection management, schema initialization, parameterized queries,
foreign key enforcement, and thread-safe concurrent execution.
"""

from datetime import datetime, timedelta, timezone
import json
import logging
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.evaluation import EvaluationResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite persistent storage for alerts, timelines, enrichments,

    AI triage verdicts, and accuracy evaluation metrics.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        timeout: float = 60.0,
        check_same_thread: bool = False,
    ) -> None:
        """Initializes DatabaseManager with path and concurrency settings.

        Args:
            db_path: Path to the SQLite database file, or ':memory:'.
            timeout: Busy timeout in seconds before raising OperationalError.
            check_same_thread: If False, allows sharing connection across threads.
        """
        self.db_path = db_path
        self.timeout = timeout
        self.check_same_thread = check_same_thread
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        """Opens or returns the active SQLite connection with Foreign Keys enabled.

        Returns:
            Active sqlite3.Connection instance.
        """
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(
                    self.db_path,
                    timeout=self.timeout,
                    check_same_thread=self.check_same_thread,
                )
                self._conn.row_factory = sqlite3.Row
                # Strictly enforce Foreign Keys on every connection
                self._conn.execute("PRAGMA foreign_keys = ON;")
                # Set busy timeout in milliseconds to prevent database is locked
                busy_timeout_ms = int(self.timeout * 1000)
                self._conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms};")
                # Enable Write-Ahead Logging (WAL) for disk-backed database concurrency
                if self.db_path != ":memory:":
                    self._conn.execute("PRAGMA journal_mode = WAL;")
            return self._conn

    @property
    def connection(self) -> sqlite3.Connection:
        """Direct access to the underlying connection."""
        return self.connect()

    def __enter__(self) -> "DatabaseManager":
        """Context manager entry point."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        """Context manager exit point: commits on success, rollbacks on error."""
        with self._lock:
            if self._conn is not None:
                if exc_type is None:
                    self._conn.commit()
                else:
                    self._conn.rollback()

    def close(self) -> None:
        """Closes the underlying SQLite connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def init_db(self) -> None:
        """Initializes the database schema if tables do not exist."""
        with self._lock:
            conn = self.connect()
            cursor = conn.cursor()

            # 1. Timelines Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS timelines (
                    id TEXT PRIMARY KEY,
                    grouping_key TEXT NOT NULL,
                    start_time TEXT,
                    end_time TEXT,
                    total_events INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    correlation_type TEXT DEFAULT 'confirmed',
                    correlation_reason TEXT
                );
            """)

            # Migration: ensure correlation columns exist if table was previously created
            cursor.execute("PRAGMA table_info(timelines);")
            existing_tl_cols = {row["name"] for row in cursor.fetchall()}
            if "correlation_type" not in existing_tl_cols:
                cursor.execute("ALTER TABLE timelines ADD COLUMN correlation_type TEXT DEFAULT 'confirmed';")
            if "correlation_reason" not in existing_tl_cols:
                cursor.execute("ALTER TABLE timelines ADD COLUMN correlation_reason TEXT;")


            # 2. Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timeline_id TEXT,
                    timestamp TEXT,
                    source_dataset TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    original_record TEXT NOT NULL,
                    extracted_indicators TEXT NOT NULL,
                    ground_truth_label TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE SET NULL
                );
            """)

            # 3. Enrichments Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS enrichments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    is_malicious INTEGER NOT NULL,
                    raw_response TEXT NOT NULL,
                    lookup_timestamp TEXT NOT NULL
                );
            """)

            cursor.execute("PRAGMA table_info(enrichments);")
            existing_enrich_cols = {row["name"] for row in cursor.fetchall()}
            if "lookup_status" not in existing_enrich_cols:
                cursor.execute("ALTER TABLE enrichments ADD COLUMN lookup_status TEXT DEFAULT 'ok';")

            # 3b. Enrichment Persistent Cache Table (ADR-029)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    cache_key TEXT PRIMARY KEY,
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    lookup_status TEXT NOT NULL,
                    is_malicious INTEGER NOT NULL,
                    raw_response TEXT NOT NULL,
                    cached_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires ON enrichment_cache(expires_at);")

            # 3c. Enrichment Daily Quotas Table (WIRE-9)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS enrichment_quotas (
                    provider TEXT NOT NULL,
                    date_key TEXT NOT NULL,
                    request_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (provider, date_key)
                );
            """)

            # 4. Triage Verdicts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verdicts (
                    id TEXT PRIMARY KEY,
                    timeline_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    summary TEXT NOT NULL,
                    reasoning TEXT NOT NULL,
                    recommended_actions TEXT NOT NULL,
                    raw_llm_response TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    model_name TEXT,
                    uncertainty_level TEXT,
                    missing_information TEXT,
                    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE CASCADE
                );
            """)

            # Migration: ensure model_name and uncertainty columns exist in verdicts table
            cursor.execute("PRAGMA table_info(verdicts);")
            existing_verdict_cols = {row["name"] for row in cursor.fetchall()}
            if "model_name" not in existing_verdict_cols:
                cursor.execute("ALTER TABLE verdicts ADD COLUMN model_name TEXT;")
            if "uncertainty_level" not in existing_verdict_cols:
                cursor.execute("ALTER TABLE verdicts ADD COLUMN uncertainty_level TEXT;")
            if "missing_information" not in existing_verdict_cols:
                cursor.execute("ALTER TABLE verdicts ADD COLUMN missing_information TEXT;")


            # 5. Evaluations Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evaluations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timeline_id TEXT NOT NULL,
                    verdict_id TEXT NOT NULL,
                    ground_truth INTEGER,
                    llm_prediction INTEGER NOT NULL,
                    is_correct INTEGER,
                    category TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    confidence_score REAL,
                    severity_prediction TEXT,
                    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE CASCADE,
                    FOREIGN KEY (verdict_id) REFERENCES verdicts(id) ON DELETE CASCADE
                );
            """)

            # Migration: ensure confidence_score and severity_prediction columns exist in evaluations
            cursor.execute("PRAGMA table_info(evaluations);")
            existing_eval_cols = {row["name"] for row in cursor.fetchall()}
            if "confidence_score" not in existing_eval_cols:
                cursor.execute("ALTER TABLE evaluations ADD COLUMN confidence_score REAL;")
            if "severity_prediction" not in existing_eval_cols:
                cursor.execute("ALTER TABLE evaluations ADD COLUMN severity_prediction TEXT;")

            # Create Indexes for Query Performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timeline ON alerts(timeline_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_enrichments_indicator ON enrichments(indicator);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_timeline ON verdicts(timeline_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evaluations_timeline ON evaluations(timeline_id);")

            conn.commit()
            logger.info("Database schema initialized successfully.")

    # =====================================================================
    # Generic Parameterized Query Helpers
    # =====================================================================

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Executes a parameterized query safely under the thread lock."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor

    # =====================================================================
    # Alert Persistence
    # =====================================================================

    def insert_alert(
        self, alert: NormalizedAlert, timeline_id: Optional[Union[UUID, str]] = None
    ) -> str:
        """Inserts a NormalizedAlert using parameterized queries.

        Args:
            alert: NormalizedAlert instance.
            timeline_id: Optional UUID/str of associated ThreatTimeline.

        Returns:
            String representation of the alert's internal_id.
        """
        with self._lock:
            conn = self.connect()
            alert_id_str = str(alert.internal_id)
            timeline_id_str = str(timeline_id) if timeline_id else None
            ts_str = alert.timestamp.isoformat() if alert.timestamp else None
            now_str = datetime.now(timezone.utc).isoformat()

            orig_json = json.dumps(alert.original_record)
            indicators_json = json.dumps(alert.extracted_indicators)

            conn.execute(
                """
                INSERT INTO alerts (
                    id, timeline_id, timestamp, source_dataset, source_file,
                    event_type, original_record, extracted_indicators,
                    ground_truth_label, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    timeline_id = COALESCE(excluded.timeline_id, alerts.timeline_id),
                    ground_truth_label = COALESCE(excluded.ground_truth_label, alerts.ground_truth_label);
                """,
                (
                    alert_id_str,
                    timeline_id_str,
                    ts_str,
                    alert.source_dataset,
                    alert.source_file,
                    alert.event_type,
                    orig_json,
                    indicators_json,
                    alert.ground_truth_label,
                    now_str,
                ),
            )
            conn.commit()
            return alert_id_str

    def get_alert(self, alert_id: Union[UUID, str]) -> Optional[Dict[str, Any]]:
        """Retrieves a single alert by ID, parsing stored JSON fields."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute("SELECT * FROM alerts WHERE id = ?;", (str(alert_id),))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            data["original_record"] = json.loads(data["original_record"])
            data["extracted_indicators"] = json.loads(data["extracted_indicators"])
            return data

    def count_alerts(self) -> int:
        """Returns the total number of alerts stored."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute("SELECT COUNT(*) FROM alerts;")
            return cursor.fetchone()[0]

    # =====================================================================
    # Timeline Persistence
    # =====================================================================

    def insert_timeline(self, timeline: ThreatTimeline) -> str:
        """Inserts a ThreatTimeline record and links its constituent alerts.

        Args:
            timeline: ThreatTimeline instance.

        Returns:
            String representation of timeline_id.
        """
        with self._lock:
            conn = self.connect()
            timeline_id_str = str(timeline.timeline_id)
            start_str = timeline.start_time.isoformat() if timeline.start_time else None
            end_str = timeline.end_time.isoformat() if timeline.end_time else None
            now_str = datetime.now(timezone.utc).isoformat()
            corr_type = getattr(timeline, "correlation_type", "confirmed") or "confirmed"
            corr_reason = getattr(timeline, "correlation_reason", None)

            conn.execute(
                """
                INSERT INTO timelines (
                    id, grouping_key, start_time, end_time, total_events, created_at,
                    correlation_type, correlation_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    timeline_id_str,
                    timeline.grouping_key,
                    start_str,
                    end_str,
                    timeline.total_events,
                    now_str,
                    corr_type,
                    corr_reason,
                ),
            )

            # Insert or associate any alerts provided directly in the timeline
            for alert in timeline.alerts:
                self.insert_alert(alert, timeline_id=timeline.timeline_id)

            conn.commit()
            return timeline_id_str

    def get_timeline(self, timeline_id: Union[UUID, str]) -> Optional[Dict[str, Any]]:
        """Retrieves a timeline by ID and includes its associated alert IDs."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT * FROM timelines WHERE id = ?;", (str(timeline_id),)
            )
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            # Fetch associated alerts
            alert_cursor = conn.execute(
                "SELECT id FROM alerts WHERE timeline_id = ? ORDER BY timestamp ASC;",
                (str(timeline_id),),
            )
            data["alert_ids"] = [r[0] for r in alert_cursor.fetchall()]
            return data

    def get_timelines(self, skip: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves a paginated list of timelines ordered by creation time descending."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT * FROM timelines ORDER BY created_at DESC LIMIT ? OFFSET ?;",
                (limit, skip),
            )
            results = []
            for row in cursor.fetchall():
                data = dict(row)
                alert_cursor = conn.execute(
                    "SELECT id FROM alerts WHERE timeline_id = ? ORDER BY timestamp ASC;",
                    (data["id"],),
                )
                data["alert_ids"] = [r[0] for r in alert_cursor.fetchall()]
                results.append(data)
            return results

    def count_timelines(self) -> int:
        """Returns the total number of timelines stored."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute("SELECT COUNT(*) FROM timelines;")
            return cursor.fetchone()[0]

    def get_alerts_for_timeline(
        self, timeline_id: Union[UUID, str]
    ) -> List[Dict[str, Any]]:
        """Retrieves all full alerts associated with a specific timeline."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT * FROM alerts WHERE timeline_id = ? ORDER BY timestamp ASC;",
                (str(timeline_id),),
            )
            results = []
            for row in cursor.fetchall():
                data = dict(row)
                data["original_record"] = json.loads(data["original_record"])
                data["extracted_indicators"] = json.loads(data["extracted_indicators"])
                results.append(data)
            return results

    # =====================================================================
    # Enrichment Persistence
    # =====================================================================

    def insert_enrichment(self, enrichment: EnrichmentResult) -> int:
        """Inserts an EnrichmentResult record.

        Args:
            enrichment: EnrichmentResult instance.

        Returns:
            Auto-incremented integer ID.
        """
        with self._lock:
            conn = self.connect()
            ts_str = enrichment.lookup_timestamp.isoformat()
            raw_json = json.dumps(enrichment.raw_response, default=str)
            is_malicious_int = 1 if enrichment.is_malicious else 0
            lookup_status_str = getattr(enrichment, "lookup_status", "ok") or "ok"

            cursor = conn.execute(
                """
                INSERT INTO enrichments (
                    indicator, indicator_type, provider, is_malicious,
                    raw_response, lookup_timestamp, lookup_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    enrichment.indicator,
                    enrichment.indicator_type,
                    enrichment.provider,
                    is_malicious_int,
                    raw_json,
                    ts_str,
                    lookup_status_str,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_enrichments(self, indicator: str) -> List[Dict[str, Any]]:
        """Retrieves all enrichment results for a specific indicator."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT * FROM enrichments WHERE indicator = ? ORDER BY id DESC;",
                (indicator,),
            )
            results = []
            for row in cursor.fetchall():
                data = dict(row)
                data["raw_response"] = json.loads(data["raw_response"])
                data["is_malicious"] = bool(data["is_malicious"])
                data["lookup_status"] = data.get("lookup_status", "ok") or "ok"
                results.append(data)
            return results

    def get_cached_enrichment(self, cache_key: str) -> Optional[EnrichmentResult]:
        """Retrieves a non-expired enrichment result from the persistent SQLite cache."""
        with self._lock:
            conn = self.connect()
            now_str = datetime.now(timezone.utc).isoformat()
            cursor = conn.execute(
                """
                SELECT * FROM enrichment_cache
                WHERE cache_key = ? AND expires_at > ?;
                """,
                (cache_key, now_str),
            )
            row = cursor.fetchone()
            if not row:
                return None

            data = dict(row)
            return EnrichmentResult(
                indicator=data["indicator"],
                indicator_type=data["indicator_type"],
                provider=data["provider"],
                is_malicious=bool(data["is_malicious"]),
                raw_response=json.loads(data["raw_response"]),
                lookup_timestamp=datetime.fromisoformat(data["cached_at"]),
                lookup_status=data["lookup_status"],
            )

    def set_cached_enrichment(
        self,
        cache_key: str,
        result: EnrichmentResult,
        ttl_seconds: int = 86400,
    ) -> None:
        """Stores an EnrichmentResult in the persistent SQLite cache with a defined TTL."""
        with self._lock:
            conn = self.connect()
            now = datetime.now(timezone.utc)
            cached_at_str = now.isoformat()
            expires_at_str = (now + timedelta(seconds=ttl_seconds)).isoformat()
            raw_json = json.dumps(result.raw_response, default=str)
            is_malicious_int = 1 if result.is_malicious else 0
            lookup_status_str = getattr(result, "lookup_status", "ok") or "ok"

            conn.execute(
                """
                INSERT OR REPLACE INTO enrichment_cache (
                    cache_key, indicator, indicator_type, provider, lookup_status,
                    is_malicious, raw_response, cached_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    cache_key,
                    result.indicator,
                    result.indicator_type,
                    result.provider,
                    lookup_status_str,
                    is_malicious_int,
                    raw_json,
                    cached_at_str,
                    expires_at_str,
                ),
            )
            conn.commit()

    # =====================================================================
    # Enrichment Daily Quota Persistence (WIRE-9)
    # =====================================================================

    def get_quota_usage(self, provider: str, date_key: Optional[str] = None) -> int:
        """Retrieves total requests recorded for a provider on a given UTC date (YYYY-MM-DD)."""
        target_date = date_key or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        provider_norm = provider.strip().lower()
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                """
                SELECT request_count FROM enrichment_quotas
                WHERE provider = ? AND date_key = ?;
                """,
                (provider_norm, target_date),
            )
            row = cursor.fetchone()
            return int(row["request_count"]) if row else 0

    def increment_quota_usage(
        self, provider: str, count: int = 1, date_key: Optional[str] = None
    ) -> int:
        """Increments request counter for a provider on a given UTC date (default: today)."""
        target_date = date_key or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        provider_norm = provider.strip().lower()
        with self._lock:
            conn = self.connect()
            conn.execute(
                """
                INSERT INTO enrichment_quotas (provider, date_key, request_count)
                VALUES (?, ?, ?)
                ON CONFLICT(provider, date_key) DO UPDATE SET
                    request_count = enrichment_quotas.request_count + excluded.request_count;
                """,
                (provider_norm, target_date, max(0, int(count))),
            )
            conn.commit()
            return self.get_quota_usage(provider_norm, target_date)

    def check_quota_available(
        self, provider: str, max_daily_quota: Optional[int], date_key: Optional[str] = None
    ) -> bool:
        """Checks if a provider has remaining quota for the given date. Returns True if available or quota is None/<=0."""
        if max_daily_quota is None or max_daily_quota <= 0:
            return True
        current_usage = self.get_quota_usage(provider, date_key)
        return current_usage < max_daily_quota

    # =====================================================================
    # Triage Verdict Persistence
    # =====================================================================

    def insert_verdict(self, verdict: TriageVerdict) -> str:
        """Inserts an AI TriageVerdict record.

        Strict Foreign Key: verdict.timeline_id must exist in timelines.

        Args:
            verdict: TriageVerdict instance.

        Returns:
            String representation of verdict_id.
        """
        with self._lock:
            conn = self.connect()
            verdict_id_str = str(verdict.verdict_id)
            timeline_id_str = str(verdict.timeline_id)
            now_str = datetime.now(timezone.utc).isoformat()

            reasoning_json = json.dumps(verdict.reasoning)
            actions_json = json.dumps(verdict.recommended_actions)
            model_name = getattr(verdict, "model_name", None)
            uncertainty_level = getattr(verdict, "uncertainty_level", None)
            missing_info_json = json.dumps(getattr(verdict, "missing_information", []))

            conn.execute(
                """
                INSERT INTO verdicts (
                    id, timeline_id, severity, confidence_score, summary,
                    reasoning, recommended_actions, raw_llm_response, created_at,
                    model_name, uncertainty_level, missing_information
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    verdict_id_str,
                    timeline_id_str,
                    verdict.severity,
                    verdict.confidence_score,
                    verdict.summary,
                    reasoning_json,
                    actions_json,
                    verdict.raw_llm_response,
                    now_str,
                    model_name,
                    uncertainty_level,
                    missing_info_json,
                ),
            )
            conn.commit()
            return verdict_id_str

    def get_verdict(self, verdict_id: Union[UUID, str]) -> Optional[Dict[str, Any]]:
        """Retrieves a triage verdict by ID, parsing stored JSON fields."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT * FROM verdicts WHERE id = ?;", (str(verdict_id),)
            )
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            data["reasoning"] = json.loads(data["reasoning"])
            data["recommended_actions"] = json.loads(data["recommended_actions"])
            data["missing_information"] = json.loads(data.get("missing_information") or "[]")
            return data

    def get_verdict_for_timeline(
        self, timeline_id: Union[UUID, str]
    ) -> Optional[Dict[str, Any]]:
        """Retrieves the latest triage verdict for a specific timeline."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT * FROM verdicts WHERE timeline_id = ? ORDER BY created_at DESC LIMIT 1;",
                (str(timeline_id),),
            )
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            data["reasoning"] = json.loads(data["reasoning"])
            data["recommended_actions"] = json.loads(data["recommended_actions"])
            data["missing_information"] = json.loads(data.get("missing_information") or "[]")
            return data

    # =====================================================================
    # Evaluation Persistence
    # =====================================================================

    def insert_evaluation(self, evaluation: EvaluationResult) -> int:
        """Inserts an EvaluationResult record.

        Strict Foreign Keys: timeline_id must exist in timelines,
        and verdict_id must exist in verdicts.

        Args:
            evaluation: EvaluationResult instance.

        Returns:
            Auto-incremented integer ID.
        """
        with self._lock:
            conn = self.connect()
            timeline_id_str = str(evaluation.timeline_id)
            verdict_id_str = str(evaluation.verdict_id)
            now_str = datetime.now(timezone.utc).isoformat()

            gt_int = (
                (1 if evaluation.ground_truth else 0)
                if evaluation.ground_truth is not None
                else None
            )
            pred_int = 1 if evaluation.llm_prediction else 0
            correct_int = (
                (1 if evaluation.is_correct else 0)
                if evaluation.is_correct is not None
                else None
            )

            conf_val = float(evaluation.confidence_score) if evaluation.confidence_score is not None else None
            sev_pred = evaluation.severity_prediction

            cursor = conn.execute(
                """
                INSERT INTO evaluations (
                    timeline_id, verdict_id, ground_truth, llm_prediction,
                    is_correct, category, evaluated_at, confidence_score, severity_prediction
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    timeline_id_str,
                    verdict_id_str,
                    gt_int,
                    pred_int,
                    correct_int,
                    evaluation.category,
                    now_str,
                    conf_val,
                    sev_pred,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_evaluations_for_timeline(
        self, timeline_id: Union[UUID, str]
    ) -> List[Dict[str, Any]]:
        """Retrieves all evaluation results for a specific timeline."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT * FROM evaluations WHERE timeline_id = ? ORDER BY id DESC;",
                (str(timeline_id),),
            )
            results = []
            for row in cursor.fetchall():
                data = dict(row)
                data["ground_truth"] = (
                    bool(data["ground_truth"]) if data["ground_truth"] is not None else None
                )
                data["llm_prediction"] = bool(data["llm_prediction"])
                data["is_correct"] = (
                    bool(data["is_correct"]) if data["is_correct"] is not None else None
                )
                results.append(data)
            return results

    def get_all_evaluations(self) -> List[EvaluationResult]:
        """Retrieves all stored evaluation records joined with verdicts for metric recomputation."""
        with self._lock:
            conn = self.connect()
            cursor = conn.execute("PRAGMA table_info(evaluations);")
            cols = {row["name"] for row in cursor.fetchall()}
            has_conf = "confidence_score" in cols
            has_sev = "severity_prediction" in cols

            conf_select = "COALESCE(e.confidence_score, v.confidence_score)" if has_conf else "v.confidence_score"
            sev_select = "COALESCE(e.severity_prediction, v.severity)" if has_sev else "v.severity"

            query = f"""
                SELECT
                    e.id,
                    e.timeline_id,
                    e.verdict_id,
                    e.ground_truth,
                    e.llm_prediction,
                    e.is_correct,
                    e.category,
                    e.evaluated_at,
                    {conf_select} AS confidence_score,
                    {sev_select} AS verdict_severity
                FROM evaluations e
                LEFT JOIN verdicts v ON e.verdict_id = v.id
                ORDER BY e.id ASC;
            """
            cursor = conn.execute(query)
            results: List[EvaluationResult] = []
            for row in cursor.fetchall():
                data = dict(row)
                t_id = UUID(data["timeline_id"]) if data.get("timeline_id") else None
                v_id = UUID(data["verdict_id"]) if data.get("verdict_id") else None
                gt = bool(data["ground_truth"]) if data.get("ground_truth") is not None else None
                pred = bool(data["llm_prediction"]) if data.get("llm_prediction") is not None else None
                correct = bool(data["is_correct"]) if data.get("is_correct") is not None else None
                conf = float(data["confidence_score"]) if data.get("confidence_score") is not None else None
                sev_pred = data.get("verdict_severity")

                results.append(
                    EvaluationResult(
                        timeline_id=t_id,
                        verdict_id=v_id,
                        ground_truth=gt,
                        llm_prediction=pred,
                        is_correct=correct,
                        category=data["category"],
                        confidence_score=conf,
                        severity_prediction=sev_pred,
                    )
                )
            return results

