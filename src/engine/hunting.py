"""Threat hunting filter engine for TriageLens.

Translates the limited KQL-style hunting filter syntax into secure,
parameterized queries targeting relational columns and deep JSON telemetry.
"""

from datetime import datetime
from functools import lru_cache
import json
import logging
import math
import sqlite3
import time
from typing import Any, Callable, List, Optional, Tuple
from uuid import UUID

from src.engine.database import DatabaseManager
from src.engine.fields import resolve_field
from src.models.alert import NormalizedAlert
from src.engine.hunting_dsl import (
    DIRECT_COLUMNS, KQLParseError, PostgresDialect, SQLDialect, SQLiteDialect, compile_query, parse_query,
)

logger = logging.getLogger(__name__)


class HuntTimeoutError(TimeoutError):
    """A hunt exceeded its execution deadline; partial results are withheld."""


class ThreatHuntingEngine:
    """Compile bounded hunting filters and execute them against stored alerts."""

    DIRECT_COLUMNS = DIRECT_COLUMNS
    DEFAULT_LIMIT = 500
    MAX_LIMIT = 1000
    DEFAULT_TIMEOUT = 2.0

    def __init__(
        self, db: DatabaseManager, *, dialect: Optional[SQLDialect] = None,
        timeout: float = DEFAULT_TIMEOUT, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 30:
            raise ValueError("Hunt timeout must be positive and at most 30 seconds.")
        self.db = db
        self.dialect = dialect if dialect is not None else (
            PostgresDialect() if db.backend == 'postgresql' else SQLiteDialect())
        self.timeout = timeout
        self._clock = clock

    def translate_kql_to_sql(
        self, kql_query: str, limit: Optional[int] = None,
    ) -> Tuple[str, List[Any]]:
        """Compatibility entry point: parse into an AST, then compile for the dialect."""
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int)):
            raise KQLParseError("Row limit must be an integer.")
        effective_limit = min(limit if limit is not None and limit > 0 else self.DEFAULT_LIMIT,
                              self.MAX_LIMIT)
        return compile_query(parse_query(kql_query), self.dialect, effective_limit)

    @staticmethod
    def _validate_name(name: str) -> str:
        if not isinstance(name, str) or not name.strip() or len(name) > 100:
            raise KQLParseError("Saved query name must contain 1-100 characters.")
        return name.strip()

    def save_query(self, name: str, query: str) -> dict[str, Any]:
        """Validate and upsert a named definition; never execute it or store hits."""
        name = self._validate_name(name)
        parse_query(query)
        with self.db._atomic_write() as conn:
            now = self.db._now_utc()
            conn.execute("""INSERT INTO saved_hunting_queries(name, query, created_at, updated_at)
                VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET
                query=excluded.query, updated_at=excluded.updated_at""", (name, query, now, now))
            return dict(conn.execute(
                "SELECT * FROM saved_hunting_queries WHERE name = ?", (name,)).fetchone())

    def list_saved_queries(self) -> list[dict[str, Any]]:
        """Return at most 1000 definitions in name order."""
        with self.db._lock:
            return [dict(row) for row in self.db.connect().execute(
                "SELECT * FROM saved_hunting_queries ORDER BY name LIMIT 1000")]

    def delete_saved_query(self, name: str) -> bool:
        name = self._validate_name(name)
        with self.db._atomic_write() as conn:
            return conn.execute("DELETE FROM saved_hunting_queries WHERE name = ?", (name,)).rowcount > 0

    def execute_saved_query(self, name: str, limit: Optional[int] = None) -> List[NormalizedAlert]:
        name = self._validate_name(name)
        with self.db._lock:
            row = self.db.connect().execute(
                "SELECT query FROM saved_hunting_queries WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise KQLParseError("Saved query does not exist.")
        return self.execute_hunt(row["query"], limit)

    def execute_hunt(
        self, kql_query: str, limit: Optional[int] = None
    ) -> List[NormalizedAlert]:
        """Executes a KQL-style hunting filter against the alerts table.

        Args:
            kql_query: KQL-style hunting filter expression.
            limit: Optional maximum number of matching alerts to return (default 500, max 1000).

        Returns:
            List of matching NormalizedAlert instances.
        """
        sql, params = self.translate_kql_to_sql(kql_query, limit=limit)
        if self.db.backend == 'postgresql':
            from src.engine.postgres import PostgresStorageError

            try:
                rows = self.db.hunt(sql, params, self.timeout)
            except PostgresStorageError as exc:
                if exc.sqlstate == '57014':
                    raise HuntTimeoutError('Hunting filter execution timed out.') from None
                raise
        else:
            rows = self._sqlite_hunt(sql, params)
        return self._decode_matches(rows)

    def _sqlite_hunt(self, sql, params):
        deadline = self._clock() + self.timeout
        if not self.db._lock.acquire(timeout=self.timeout):
            raise HuntTimeoutError("Hunting filter execution timed out.")
        try:
            conn = self.db.connect()
            busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
            cursor = None

            @lru_cache(maxsize=1)
            def record_view(raw: str) -> dict[str, Any]:
                # At most one decoded record retained, regardless of scan size.
                return json.loads(raw)

            def canonical_value(raw: str, name: str) -> str | int | None:
                return resolve_field(record_view(raw), name)

            def expired() -> bool:
                return self._clock() >= deadline

            try:
                conn.create_function("triagelens_field", 2, canonical_value, deterministic=True)
                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise HuntTimeoutError("Hunting filter execution timed out.")
                conn.execute(f"PRAGMA busy_timeout = {max(1, int(remaining * 1000))}")
                conn.set_progress_handler(expired, 100)
                cursor = conn.execute(sql, params)
                rows = cursor.fetchall()
                if expired():
                    raise HuntTimeoutError("Hunting filter execution timed out.")
            except sqlite3.OperationalError as exc:
                if expired() or getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_INTERRUPT:
                    raise HuntTimeoutError("Hunting filter execution timed out.") from None
                raise
            finally:
                conn.set_progress_handler(None, 0)
                if cursor is not None:
                    cursor.close()
                conn.create_function("triagelens_field", 2, None)
                record_view.cache_clear()
                conn.execute(f"PRAGMA busy_timeout = {busy_timeout}")
        finally:
            self.db._lock.release()
        return rows

    @staticmethod
    def _decode_matches(rows) -> List[NormalizedAlert]:
        matched_alerts: List[NormalizedAlert] = []
        for row in rows:
            data = dict(row)
            orig_rec = (
                json.loads(data["original_record"])
                if isinstance(data["original_record"], str)
                else data["original_record"]
            )
            indicators = (
                json.loads(data["extracted_indicators"])
                if isinstance(data["extracted_indicators"], str)
                else data["extracted_indicators"]
            )

            ts: Optional[datetime] = None
            if data.get("timestamp"):
                try:
                    ts = datetime.fromisoformat(data["timestamp"])
                except Exception:
                    ts = None

            alert = NormalizedAlert(
                internal_id=UUID(data["id"]) if isinstance(data["id"], str) else data["id"],
                timestamp=ts,
                source_dataset=data["source_dataset"],
                source_file=data["source_file"],
                event_type=data["event_type"],
                original_record=orig_rec,
                extracted_indicators=indicators,
                ground_truth_label=data.get("ground_truth_label"),
                ground_truth_metadata=json.loads(data["ground_truth_metadata"])
                if data.get("ground_truth_metadata") else None,
            )
            matched_alerts.append(alert)

        logger.info(
            "Threat hunt matched %d alerts.",
            len(matched_alerts),
        )
        return matched_alerts

