"""PostgreSQL implementation of the shared persistence contract."""

from contextlib import contextmanager
from datetime import timezone
import json
from math import ceil
from typing import Any

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb, set_json_loads

from src.engine.database import DatabaseManager
from src.engine.fields import canonical_fields


class PostgresStorageError(RuntimeError):
    """Database failure safe to report without DSNs, statements, or values."""

    def __init__(self, sqlstate: str | None) -> None:
        self.sqlstate = sqlstate
        super().__init__(f'PostgreSQL operation failed (SQLSTATE {sqlstate or "unavailable"}).')


class _Row(dict):
    def __getitem__(self, key):
        return tuple(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


def _row_factory(cursor):
    names = tuple(column.name for column in cursor.description or ())
    return lambda values: _Row(zip(names, values))


class _Connection:
    """Adapt shared internal SQL bind markers and preserve SQLite-style row access."""

    def __init__(self, connection) -> None:
        self.raw = connection

    @property
    def in_transaction(self) -> bool:
        return self.raw.info.transaction_status != TransactionStatus.IDLE

    @staticmethod
    def _bind(sql):
        # Shared statements reserve '?' for parameters and never accept raw user SQL.
        return sql.replace('%', '%%').replace('?', '%s')

    def execute(self, sql, params=()):
        try:
            return self.raw.execute(self._bind(sql) if params else sql, params or None)
        except psycopg.Error as exc:
            raise PostgresStorageError(exc.sqlstate) from None

    def executemany(self, sql, params):
        try:
            with self.raw.cursor() as cursor:
                cursor.executemany(self._bind(sql), params)
        except psycopg.Error as exc:
            raise PostgresStorageError(exc.sqlstate) from None

    def commit(self):
        if self.in_transaction:
            self.execute('COMMIT')

    def rollback(self):
        if not self.raw.closed and self.in_transaction:
            self.execute('ROLLBACK')

    def close(self):
        self.raw.close()


class PostgresDatabase(DatabaseManager):
    backend = 'postgresql'
    _alert_from = 'alerts LEFT JOIN triagelens_truth.alert_labels t ON t.alert_id = alerts.id'
    _alert_columns = ('alerts.id, timeline_id, timestamp, source_dataset, source_file, event_type, '
                      'original_record, extracted_indicators, created_at, '
                      't.ground_truth_label, t.ground_truth_metadata')
    _alert_time = 'timestamp_utc'
    _bound_time = 'CAST(? AS TIMESTAMPTZ)'
    _canonical_field = 'canonical_record ->> CAST(? AS TEXT)'
    _scan_order = 'scan_order'

    def __init__(self, dsn: str, role: str, *, hunt_dsn: str | None = None,
                 triage_dsn: str | None = None, clock=None) -> None:
        super().__init__(db_path='PostgreSQL', clock=clock)
        self._dsn = dsn
        self.role = role
        self._hunt_dsn = hunt_dsn
        self._triage_dsn = triage_dsn
        self._conn: _Connection | None = None

    def connect(self) -> _Connection:
        with self._lock:
            if self._conn is not None and not self._conn.raw.closed:
                return self._conn
            self._conn = self._open(self._dsn, self.role)
            return self._conn

    @staticmethod
    def _open(dsn: str, role: str, timeout: float = 5) -> _Connection:
        try:
            raw = psycopg.connect(dsn, autocommit=True, connect_timeout=max(2, ceil(timeout)),
                                  row_factory=_row_factory)
        except (psycopg.Error, ValueError) as exc:
            raise PostgresStorageError(getattr(exc, 'sqlstate', None)) from None
        conn = _Connection(raw)
        try:
            # Raw JSONB reads use the same decode path as SQLite JSON text.
            set_json_loads(bytes.decode, raw)
            conn.execute('SET search_path TO pg_catalog, triagelens, triagelens_truth')
            conn.execute("SET TIME ZONE 'UTC'")
            if role == 'hunt':
                conn.execute('SET default_transaction_read_only = on')
                conn.execute("SET statement_timeout = '2s'")
            PostgresDatabase._validate_role(conn, role)
        except BaseException:
            conn.close()
            raise
        return conn

    @staticmethod
    def _validate_role(conn: _Connection, role: str) -> None:
        row = conn.execute('''
            SELECT pg_has_role(current_user, role.oid, 'USAGE') AS expected_role,
                   NOT (account.rolsuper OR account.rolcreaterole OR account.rolcreatedb
                        OR account.rolreplication OR account.rolbypassrls) AS restricted,
                   has_schema_privilege(current_user, 'triagelens_truth', 'USAGE') AS can_read_truth,
                   has_any_column_privilege(current_user, 'triagelens.alerts', 'SELECT') AS can_read_alerts,
                   has_any_column_privilege(current_user, 'triagelens.hunting_alerts', 'SELECT') AS can_hunt,
                   has_schema_privilege(current_user, 'triagelens', 'CREATE') AS can_create,
                   EXISTS (SELECT 1 FROM pg_roles r
                           WHERE r.rolname IN ('triagelens_evaluator', 'triagelens_analyst', 'pg_read_all_data')
                           AND pg_has_role(current_user, r.oid, 'MEMBER')) AS member_of_trusted_role,
                   pg_has_role(current_user, 'triagelens_hunt', 'MEMBER') AS member_of_hunt_role
            FROM pg_roles account, pg_roles role
            WHERE account.rolname = current_user AND role.rolname = ?
        ''', (f'triagelens_{role}',)).fetchone()
        trusted = role in ('evaluator', 'analyst')
        if (not row or not row['expected_role'] or not row['restricted'] or row['can_create']
                or row['can_read_truth'] != trusted or row['can_read_alerts'] != trusted
                or row['member_of_trusted_role'] != trusted or row['can_hunt'] != (role != 'triage')
                or (role == 'triage' and row['member_of_hunt_role'])):
            raise RuntimeError(f'PostgreSQL login does not have the required {role} role privileges.')

    def init_db(self) -> None:
        try:
            row = self.connect().execute('SELECT version_num FROM triagelens.alembic_version').fetchone()
        except PostgresStorageError as exc:
            if exc.sqlstate in ('3F000', '42P01'):
                raise RuntimeError('PostgreSQL schema is missing. Run the Alembic upgrade first.') from None
            raise
        if not row or row[0] != '0001_postgresql':
            raise RuntimeError('PostgreSQL schema revision is unsupported. Run the Alembic upgrade first.')

    def _begin_write(self, conn: _Connection):
        conn.execute('BEGIN')
        try:
            # Match SQLite's single-writer check-and-write semantics across app connections.
            conn.execute('SELECT pg_advisory_xact_lock(1725589903, 1)')
        except BaseException:
            conn.rollback()
            raise

    @contextmanager
    def _read_snapshot(self):
        with self._lock:
            conn = self.connect()
            if conn.in_transaction:
                yield conn
            else:
                conn.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
                try:
                    yield conn
                finally:
                    conn.rollback()

    def _columns(self, table):
        return {row[0] for row in self.connect().execute('''
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'triagelens_truth' AND table_name = ?
        ''', (table,))}

    @staticmethod
    def _contains(column):
        return f'strpos(lower(({column}) COLLATE "C"), lower(CAST(? AS TEXT) COLLATE "C")) > 0'

    def _alert_order(self, sort, column, direction):
        expression = self._alert_time if sort == 'timestamp' else f'lower({column} COLLATE "C")'
        return f'{expression} {direction.upper()} NULLS {"FIRST" if direction == "asc" else "LAST"}'

    @staticmethod
    def _prepare_alert_list(conn):
        pass  # Canonical fields are projected at write time using the shared resolver.

    def insert_alert(self, alert, timeline_id=None) -> str:
        alert_id = str(alert.internal_id)
        ts = alert.timestamp
        utc = ts.replace(tzinfo=timezone.utc) if ts and ts.tzinfo is None else ts
        with self._atomic_write() as conn:
            conn.execute('''
                INSERT INTO alerts (id, timeline_id, timestamp, timestamp_utc, source_dataset, source_file,
                    event_type, original_record, canonical_record, extracted_indicators, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET timeline_id = COALESCE(excluded.timeline_id, alerts.timeline_id)
            ''', (alert_id, str(timeline_id) if timeline_id else None, ts.isoformat() if ts else None,
                  utc, alert.source_dataset, alert.source_file, alert.event_type, Jsonb(alert.original_record),
                  Jsonb(canonical_fields(alert.original_record)),
                  json.dumps(alert.extracted_indicators), self._now_utc()))
            if alert.ground_truth_label is not None or alert.ground_truth_metadata is not None:
                conn.execute('''
                    INSERT INTO triagelens_truth.alert_labels AS t VALUES (?, ?, ?)
                    ON CONFLICT(alert_id) DO UPDATE SET
                        ground_truth_label = CASE WHEN excluded.ground_truth_metadata IS NOT NULL
                            THEN excluded.ground_truth_label
                            WHEN t.ground_truth_metadata IS NOT NULL THEN t.ground_truth_label
                            ELSE COALESCE(excluded.ground_truth_label, t.ground_truth_label) END,
                        ground_truth_metadata = COALESCE(excluded.ground_truth_metadata, t.ground_truth_metadata)
                ''', (alert_id, alert.ground_truth_label,
                      alert.ground_truth_metadata.model_dump_json() if alert.ground_truth_metadata else None))
        return alert_id

    def hunt(self, sql: str, params: list[Any], timeout: float):
        if not self._hunt_dsn:
            raise RuntimeError('Configure a PostgreSQL hunting login to execute hunts.')
        conn = self._open(self._hunt_dsn, 'hunt', timeout)
        try:
            conn.execute('BEGIN READ ONLY')
            conn.execute("SELECT set_config('statement_timeout', ?, true)", (f'{max(1, int(timeout * 1000))}ms',))
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    @contextmanager
    def triage_cache(self):
        if not self._triage_dsn:
            raise RuntimeError('Configure a restricted PostgreSQL triage login for inference.')
        cache = PostgresDatabase(self._triage_dsn, 'triage')
        try:
            cache.init_db()
            yield cache
        finally:
            cache.close()
