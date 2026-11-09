"""SQLite persistence and storage engine for TriageLens.

Provides connection management, schema initialization, parameterized queries,
foreign key enforcement, and thread-safe concurrent execution.
"""

from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import hashlib
import json
import logging
import re
import sqlite3
import threading
from typing import Any, Callable, Dict, List, Optional, Union
from uuid import UUID, uuid4

from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.evaluation import EvaluationResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict
from src.engine.verdict_cache import CacheProvenance

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
        clock: Optional[Callable[[], datetime]] = None,
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
        self._atomic_depth = 0
        self._clock = clock

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
                    ground_truth_metadata TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE SET NULL
                );
            """)

            cursor.execute("PRAGMA table_info(alerts);")
            if "ground_truth_metadata" not in {row["name"] for row in cursor.fetchall()}:
                cursor.execute("ALTER TABLE alerts ADD COLUMN ground_truth_metadata TEXT;")

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
                    verdict_id TEXT,
                    ground_truth INTEGER,
                    llm_prediction INTEGER,
                    is_correct INTEGER,
                    category TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    confidence_score REAL,
                    severity_prediction TEXT,
                    severity_ground_truth TEXT,
                    severity_correct INTEGER,
                    FOREIGN KEY (timeline_id) REFERENCES timelines(id) ON DELETE CASCADE,
                    FOREIGN KEY (verdict_id) REFERENCES verdicts(id) ON DELETE CASCADE
                );
            """)

            # Add nullable result snapshots without guessing values for historical rows.
            cursor.execute("PRAGMA table_info(evaluations);")
            existing_eval_cols = {row["name"] for row in cursor.fetchall()}
            if "confidence_score" not in existing_eval_cols:
                cursor.execute("ALTER TABLE evaluations ADD COLUMN confidence_score REAL;")
            if "severity_prediction" not in existing_eval_cols:
                cursor.execute("ALTER TABLE evaluations ADD COLUMN severity_prediction TEXT;")
            if "severity_ground_truth" not in existing_eval_cols:
                cursor.execute("ALTER TABLE evaluations ADD COLUMN severity_ground_truth TEXT;")
            if "severity_correct" not in existing_eval_cols:
                cursor.execute("ALTER TABLE evaluations ADD COLUMN severity_correct INTEGER;")

            # Nullable snapshots; never infer historical disposition or policy.
            for table, names in (
                ('verdicts', ('disposition', 'policy_version', 'evidence_basis', 'evidence_context', 'evidence_contract_version')),
                ('evaluations', ('disposition', 'prediction_basis', 'policy_version')),
            ):
                existing = {row['name'] for row in conn.execute(f'PRAGMA table_info({table})')}
                for name in names:
                    if name not in existing:
                        conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} TEXT')

            self._migrate_unavailable_evaluations(conn)
            self._init_provenance(conn)

            # Query definitions are separate from detections, labels and AI verdicts.
            cursor.execute("""CREATE TABLE IF NOT EXISTS saved_hunting_queries (
                name TEXT PRIMARY KEY CHECK(length(name) BETWEEN 1 AND 100),
                query TEXT NOT NULL CHECK(length(query) BETWEEN 1 AND 2000),
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );""")

            # Create Indexes for Query Performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timeline ON alerts(timeline_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_enrichments_indicator ON enrichments(indicator);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdicts_timeline ON verdicts(timeline_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evaluations_timeline ON evaluations(timeline_id);")

            conn.commit()
            logger.info("Database schema initialized successfully.")

    def _now_utc(self) -> str:
        value = self._clock() if self._clock is not None else datetime.now(timezone.utc)
        if value.tzinfo is None:
            raise ValueError("Provenance clock must return an aware datetime")
        return value.astimezone(timezone.utc).isoformat()

    @contextmanager
    def _atomic_write(self):
        """Serialize check-and-write across connections without committing nested writes."""
        with self._lock:
            conn = self.connect()
            nested = conn.in_transaction
            name = f"provenance_{self._atomic_depth}"
            conn.execute(f"SAVEPOINT {name}" if nested else "BEGIN IMMEDIATE")
            self._atomic_depth += 1
            try:
                yield conn
                conn.execute(f"RELEASE SAVEPOINT {name}") if nested else conn.commit()
            except BaseException:
                if nested:
                    conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
                    conn.execute(f"RELEASE SAVEPOINT {name}")
                else:
                    conn.rollback()
                raise
            finally:
                self._atomic_depth -= 1

    def _init_provenance(self, conn: sqlite3.Connection) -> None:
        """Add lineage after legacy outcome rebuilding, leaving old rows unknown."""
        conn.execute("""CREATE TABLE IF NOT EXISTS evaluation_runs (
            run_id TEXT PRIMARY KEY, entrypoint TEXT NOT NULL CHECK(entrypoint IN ('cli','evaluation')),
            started_at TEXT NOT NULL, ended_at TEXT,
            status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
            inference_policy_hash TEXT, cohort_manifest TEXT NOT NULL,
            quality_cohort_hash TEXT NOT NULL, failure_category TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS triage_observations (
            observation_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>0),
            timeline_id TEXT NOT NULL, origin TEXT CHECK(origin IN ('fresh','cache','skipped','unknown')),
            attempt_id TEXT UNIQUE, started_at TEXT NOT NULL, ended_at TEXT,
            status TEXT NOT NULL CHECK(status IN ('pending','completed','skipped','interrupted')),
            evidence_hash TEXT, inference_policy_hash TEXT, verdict_id TEXT,
            cache_validation TEXT NOT NULL DEFAULT 'unverified' CHECK(cache_validation IN ('unverified','verified','rejected')),
            failure_category TEXT, outcome_hash TEXT,
            UNIQUE(run_id,ordinal),
            FOREIGN KEY(run_id) REFERENCES evaluation_runs(run_id),
            FOREIGN KEY(timeline_id) REFERENCES timelines(id) ON DELETE CASCADE,
            FOREIGN KEY(verdict_id) REFERENCES verdicts(id) ON DELETE CASCADE
        )""")
        existing = {row['name'] for row in conn.execute('PRAGMA table_info(evaluations)')}
        fields = {'observation_id':'TEXT REFERENCES triage_observations(observation_id)',
                  'evaluation_context_hash':'TEXT','quality_cohort_hash':'TEXT','provenance_version':'INTEGER'}
        for name, declaration in fields.items():
            if name not in existing:
                conn.execute(f'ALTER TABLE evaluations ADD COLUMN {name} {declaration}')
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_evaluation_observation ON evaluations(observation_id) WHERE observation_id IS NOT NULL')
        conn.execute("""CREATE TABLE IF NOT EXISTS metric_cohorts (
            cohort_id TEXT PRIMARY KEY, manifest TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS metric_run_cohorts (
            run_id TEXT PRIMARY KEY REFERENCES evaluation_runs(run_id),
            cohort_id TEXT NOT NULL REFERENCES metric_cohorts(cohort_id)
        )""")
        conn.execute('CREATE INDEX IF NOT EXISTS idx_metric_cohort_runs ON metric_run_cohorts(cohort_id)')
        for table in ('metric_cohorts', 'metric_run_cohorts'):
            for operation in ('UPDATE', 'DELETE'):
                conn.execute(f"CREATE TRIGGER IF NOT EXISTS immutable_{table}_{operation.lower()} "
                             f"BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'Immutable metric cohort'); END")
        existing_verdict = {row['name'] for row in conn.execute('PRAGMA table_info(verdicts)')}
        for name, declaration in {'evidence_hash':'TEXT','inference_policy_hash':'TEXT',
                                  'cache_provenance_version':'INTEGER','cache_expires_at':'TEXT',
                                  'cache_generated_at':'TEXT','cache_verdict_hash':'TEXT'}.items():
            if name not in existing_verdict:
                conn.execute(f'ALTER TABLE verdicts ADD COLUMN {name} {declaration}')

    def create_evaluation_run(self, entrypoint: str, cohort_id: Optional[str] = None) -> str:
        run_id = str(uuid4())
        manifest = json.dumps({'kind':'ad_hoc','run_id':run_id}, sort_keys=True, separators=(',',':'))
        cohort = hashlib.sha256(manifest.encode('utf-8')).hexdigest()
        with self._atomic_write() as conn:
            conn.execute("INSERT INTO evaluation_runs(run_id,entrypoint,started_at,status,cohort_manifest,quality_cohort_hash) VALUES(?,?,?,'running',?,?)",
                         (run_id,entrypoint,self._now_utc(),manifest,cohort))
            if cohort_id is not None:
                self.bind_metric_cohort(run_id, cohort_id)
        return run_id

    def metric_snapshot(self):
        """Copy metrics and coverage under one SQLite snapshot, including across writers."""
        with self._lock:
            conn = self.connect()
            conn.execute('SAVEPOINT metric_read_snapshot')
            try:
                rows = [dict(row) for row in conn.execute('SELECT * FROM evaluations ORDER BY id')]
                snapshot = {
                    'rows': rows, 'history': self.get_all_evaluations(),
                    'runs': {row['run_id']: dict(row) for row in conn.execute('SELECT * FROM evaluation_runs')},
                    'observations': {row['observation_id']: dict(row) for row in conn.execute('SELECT * FROM triage_observations')},
                    'cohorts': {row['cohort_id']: row['manifest'] for row in conn.execute('SELECT * FROM metric_cohorts')},
                    'bindings': {row['run_id']: row['cohort_id'] for row in conn.execute('SELECT * FROM metric_run_cohorts')},
                }
                return snapshot
            finally:
                conn.execute('RELEASE SAVEPOINT metric_read_snapshot')

    def register_metric_cohort(self, manifest) -> str:
        """Register an immutable declaration; identical canonical input is idempotent."""
        from src.engine.metric_scopes import MetricSelectionError, canonical, fingerprint, normalize_manifest, run_manifest
        normalized = normalize_manifest(manifest)
        cohort_id = fingerprint(normalized)
        with self._atomic_write() as conn:
            existing = conn.execute('SELECT manifest FROM metric_cohorts WHERE cohort_id=?', (cohort_id,)).fetchone()
            if existing:
                if existing['manifest'] != canonical(normalized):
                    raise MetricSelectionError('Cohort manifest integrity failure')
                return cohort_id
            if normalized['kind'] == 'ad_hoc':
                observed = run_manifest(self.metric_snapshot(), normalized['source_run_id'])
                observed['revision'] = normalized['revision']
                if observed != normalized:
                    raise MetricSelectionError('Ad hoc manifest must match its terminal source run')
            conn.execute('INSERT OR IGNORE INTO metric_cohorts(cohort_id,manifest) VALUES(?,?)',
                         (cohort_id, canonical(normalized)))
        return cohort_id

    def get_metric_cohort(self, cohort_id):
        from src.engine.metric_scopes import MetricSelectionError
        with self._lock:
            row = self.connect().execute('SELECT manifest FROM metric_cohorts WHERE cohort_id=?', (cohort_id,)).fetchone()
            if row is None:
                raise MetricSelectionError('Unknown or undeclared quality cohort', 404)
            return json.loads(row['manifest'])

    def bind_metric_cohort(self, run_id, cohort_id):
        """A declared/subset replay run binds before observations; never retag history."""
        from src.engine.metric_scopes import MetricSelectionError
        with self._atomic_write() as conn:
            manifest = self.get_metric_cohort(cohort_id)
            run = self.get_evaluation_run(run_id)
            if run is None:
                raise MetricSelectionError('Unknown run', 404)
            if run['status'] != 'running' or conn.execute('SELECT 1 FROM triage_observations WHERE run_id=? LIMIT 1', (run_id,)).fetchone():
                raise MetricSelectionError('Bind cohort before run observations')
            existing = conn.execute('SELECT cohort_id FROM metric_run_cohorts WHERE run_id=?', (run_id,)).fetchone()
            if existing and existing[0] != cohort_id:
                raise MetricSelectionError('Run already has an immutable cohort binding')
            conn.execute('INSERT OR IGNORE INTO metric_run_cohorts(run_id,cohort_id) VALUES(?,?)', (run_id,cohort_id))
            conn.execute('UPDATE evaluation_runs SET inference_policy_hash=? WHERE run_id=?',
                         (manifest['inference_policy_hash'],run_id))

    def declare_run_cohort(self, run_id) -> str:
        """Explicitly freeze known terminal outcomes as an ad hoc cohort, retaining snapshots."""
        from src.engine.metric_scopes import run_manifest
        with self._atomic_write() as conn:
            existing = conn.execute('SELECT cohort_id FROM metric_run_cohorts WHERE run_id=?', (run_id,)).fetchone()
            if existing:
                return existing[0]
            manifest = run_manifest(self.metric_snapshot(), run_id)
            cohort_id = self.register_metric_cohort(manifest)
            conn.execute('INSERT INTO metric_run_cohorts(run_id,cohort_id) VALUES(?,?)', (run_id,cohort_id))
            return cohort_id

    def get_evaluation_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.connect().execute('SELECT * FROM evaluation_runs WHERE run_id=?',(str(run_id),)).fetchone()
            return dict(row) if row else None

    def get_triage_observations(self, run_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self.connect().execute('SELECT * FROM triage_observations WHERE run_id=? ORDER BY ordinal',(str(run_id),))]

    def _pending_observation(self, conn, observation_id):
        row = conn.execute('SELECT o.*,r.status AS run_status FROM triage_observations o JOIN evaluation_runs r ON r.run_id=o.run_id WHERE observation_id=?',(str(observation_id),)).fetchone()
        if row is None:
            raise ValueError('Unknown observation')
        if row['status'] != 'pending' or row['run_status'] != 'running':
            raise ValueError('Observation must be pending in a running run')
        return row

    def start_observation(self, run_id: str, ordinal: int, timeline_id: Union[UUID,str]) -> str:
        with self._atomic_write() as conn:
            run = conn.execute('SELECT status FROM evaluation_runs WHERE run_id=?',(str(run_id),)).fetchone()
            if run is None or run['status'] != 'running':
                raise ValueError('Run must be running')
            previous = conn.execute('SELECT observation_id,timeline_id FROM triage_observations WHERE run_id=? AND ordinal=?',(str(run_id),ordinal)).fetchone()
            if previous:
                if previous['timeline_id'] != str(timeline_id):
                    raise ValueError('Observation ordinal conflict')
                return previous['observation_id']
            observation_id = str(uuid4())
            conn.execute("INSERT INTO triage_observations(observation_id,run_id,ordinal,timeline_id,started_at,status) VALUES(?,?,?,?,?,'pending')",
                         (observation_id,str(run_id),ordinal,str(timeline_id),self._now_utc()))
        return observation_id

    def mark_observation_acquisition(self, observation_id: str, origin: str,
                                     cache_validation: str = 'unverified', contract=None) -> None:
        if origin not in ('fresh','cache','unknown'):
            raise ValueError('Invalid acquisition origin')
        if cache_validation not in ('unverified','verified','rejected'):
            raise ValueError('Invalid cache validation state')
        if cache_validation=='verified' and (origin!='cache' or contract is None):
            raise ValueError('Verified cache origin requires a contract')
        evidence_hash = contract.evidence_hash if contract else None
        policy_hash = contract.inference_policy_hash if contract else None
        with self._atomic_write() as conn:
            row = self._pending_observation(conn, observation_id)
            if row['origin'] is not None:
                if (row['origin'],row['cache_validation'],row['evidence_hash'],row['inference_policy_hash']) != (origin,cache_validation,evidence_hash,policy_hash):
                    raise ValueError('Acquisition origin conflict')
                return
            conn.execute('UPDATE triage_observations SET origin=?,attempt_id=?,cache_validation=?,evidence_hash=?,inference_policy_hash=? WHERE observation_id=?',
                         (origin,str(uuid4()) if origin=='fresh' else None,cache_validation,evidence_hash,policy_hash,str(observation_id)))

    def skip_observation(self, observation_id: str) -> None:
        with self._atomic_write() as conn:
            row = self._pending_observation(conn, observation_id)
            if row['origin'] is not None:
                raise ValueError('Acquired work cannot be skipped')
            conn.execute("UPDATE triage_observations SET origin='skipped',status='skipped',ended_at=? WHERE observation_id=?",
                         (self._now_utc(),str(observation_id)))

    def finish_evaluation_run(self, run_id: str) -> None:
        with self._atomic_write() as conn:
            run = conn.execute('SELECT status FROM evaluation_runs WHERE run_id=?',(str(run_id),)).fetchone()
            if run is None or run['status'] != 'running':
                raise ValueError('Run must be running')
            if conn.execute("SELECT 1 FROM triage_observations WHERE run_id=? AND status='pending' LIMIT 1",(str(run_id),)).fetchone():
                raise ValueError('Run has pending work')
            conn.execute("UPDATE evaluation_runs SET status='completed',ended_at=? WHERE run_id=?",(self._now_utc(),str(run_id)))

    def fail_evaluation_run(self, run_id: str) -> None:
        with self._atomic_write() as conn:
            now = self._now_utc()
            conn.execute("UPDATE triage_observations SET status='interrupted',ended_at=?,failure_category='run_interrupted' WHERE run_id=? AND status='pending'",(now,str(run_id)))
            conn.execute("UPDATE evaluation_runs SET status='failed',ended_at=?,failure_category='run_failed' WHERE run_id=? AND status='running'",(now,str(run_id)))

    def finalize_observation(self, observation_id: str, result: EvaluationResult,
                             verdict: Optional[TriageVerdict] = None,
                             failure_category: Optional[str] = None,
                             cache_provenance: Optional[CacheProvenance] = None) -> int:
        if failure_category not in (None,'no_verdict','engine_error'):
            raise ValueError('Invalid failure category')
        if result.observation_id is not None and str(result.observation_id) != str(observation_id):
            raise ValueError('Observation identity conflict')
        with self._atomic_write() as conn:
            row = conn.execute('SELECT * FROM triage_observations WHERE observation_id=?',(str(observation_id),)).fetchone()
            if row is None or row['timeline_id'] != str(result.timeline_id):
                raise ValueError('Observation timeline conflict')
            run = self.get_evaluation_run(row['run_id'])
            if result.quality_cohort_hash is not None and result.quality_cohort_hash != run['quality_cohort_hash']:
                raise ValueError('Quality cohort conflict')
            snapshot = result.model_copy(update={'observation_id':UUID(str(observation_id)),
                                                 'provenance_version':1,'quality_cohort_hash':run['quality_cohort_hash']})
            existing = self.get_verdict(result.verdict_id) if result.verdict_id else None
            if verdict is not None:
                if verdict.timeline_id != result.timeline_id or verdict.verdict_id != result.verdict_id:
                    raise ValueError('Verdict identity conflict')
                if existing is not None:
                    stored = TriageVerdict(**{**existing,'verdict_id':existing['id']})
                    if stored != verdict:
                        raise ValueError('Verdict snapshot conflict')
            elif existing is not None:
                verdict = TriageVerdict(**{**existing,'verdict_id':existing['id']})
            if result.verdict_id is not None:
                if verdict is None or verdict.timeline_id != result.timeline_id:
                    raise ValueError('Verdict timeline conflict')
            def outcome_snapshot(model):
                data = model.model_dump(mode='json')
                # Preserve pre-policy terminal hashes for unchanged old snapshots.
                for name in ('disposition', 'prediction_basis', 'policy_version',
                             'evidence_basis', 'evidence_context', 'evidence_contract_version'):
                    if data.get(name) is None:
                        data.pop(name, None)
                return data
            digest = hashlib.sha256(json.dumps({'outcome':outcome_snapshot(snapshot),
                                               'verdict':outcome_snapshot(verdict) if verdict else None,
                                               'cache':cache_provenance.as_record() if cache_provenance else None,
                                               'failure':failure_category},sort_keys=True,separators=(',',':'),
                                              allow_nan=False).encode('utf-8')).hexdigest()
            if row['status'] == 'completed':
                if row['outcome_hash'] != digest:
                    raise ValueError('Terminal outcome conflict')
                stored_id = conn.execute('SELECT id FROM evaluations WHERE observation_id=?',(str(observation_id),)).fetchone()
                if stored_id is None:
                    raise ValueError('Completed observation is missing its outcome')
                return stored_id[0]
            self._pending_observation(conn, observation_id)
            if verdict is not None and existing is None:
                self.insert_verdict(verdict)
            if cache_provenance is not None:
                if verdict is None:
                    raise ValueError('Cache provenance requires a verdict')
                self._store_cache_provenance(conn,verdict.verdict_id,cache_provenance,existing is not None)
            evaluation_id = self.insert_evaluation(snapshot)
            conn.execute("UPDATE triage_observations SET status='completed',origin=COALESCE(origin,'unknown'),ended_at=?,verdict_id=?,failure_category=?,outcome_hash=? WHERE observation_id=?",
                         (self._now_utc(),str(result.verdict_id) if result.verdict_id else None,failure_category,digest,str(observation_id)))
            return evaluation_id

    def _store_cache_provenance(self, conn, verdict_id, provenance, existed):
        if not isinstance(provenance,CacheProvenance):
            raise ValueError('Invalid verdict cache provenance')
        if existed:
            row = conn.execute('SELECT * FROM verdicts WHERE id=?',(str(verdict_id),)).fetchone()
            try:
                if CacheProvenance.from_record(row)==provenance:
                    return
            except (ValueError,TypeError,KeyError,OverflowError):
                pass
            raise ValueError('Existing verdict cache provenance cannot be rewritten')
        fields = provenance.as_record()
        assignments = ','.join(f'{name}=?' for name in fields)
        conn.execute(f'UPDATE verdicts SET {assignments} WHERE id=?',(*fields.values(),str(verdict_id)))

    def persist_cached_verdict(self, verdict: TriageVerdict, provenance=None) -> None:
        """Cache-only writers retain history without creating evaluation rows."""
        with self._atomic_write() as conn:
            existing = self.get_verdict(verdict.verdict_id)
            if existing is None:
                self.insert_verdict(verdict)
            elif TriageVerdict(**{**existing,'verdict_id':existing['id']}) != verdict:
                raise ValueError('Verdict snapshot conflict')
            if provenance is not None:
                self._store_cache_provenance(conn,verdict.verdict_id,provenance,existing is not None)

    def get_verdict_cache_candidates(self, timeline_id):
        """Raw candidates for validation; historical display uses its existing getter."""
        with self._lock:
            return [dict(row) for row in self.connect().execute(
                'SELECT * FROM verdicts WHERE timeline_id=? ORDER BY created_at DESC,id DESC',(str(timeline_id),))]

    def get_provenance_coverage(self) -> Dict[str, int]:
        with self._lock:
            conn = self.connect()
            total = conn.execute('SELECT COUNT(*) FROM evaluations').fetchone()[0]
            columns = {row['name'] for row in conn.execute('PRAGMA table_info(evaluations)')}
            legacy = total if not {'observation_id','provenance_version'}.issubset(columns) else conn.execute('SELECT COUNT(*) FROM evaluations WHERE observation_id IS NULL OR provenance_version IS NULL').fetchone()[0]
            return {'evaluation_rows':total,'legacy_unknown':legacy,'linked':total-legacy}

    def _migrate_unavailable_evaluations(self, conn: sqlite3.Connection) -> None:
        """Make legacy outcome columns nullable atomically, retaining FK checks.

        Preserve the original table definition, columns, row IDs, indexes, triggers,
        and AUTOINCREMENT high-water mark. A failed copy/check restores the old table.
        """
        columns = list(conn.execute("PRAGMA table_info(evaluations)"))
        required = {row["name"] for row in columns if row["notnull"]}
        if not required.intersection({"verdict_id", "llm_prediction"}):
            return
        # Dropping a referenced child table could cascade into custom extensions.
        # Such schemas need an explicit migration rather than silent row loss.
        tables = list(conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        for table in tables:
            quoted = '"' + table["name"].replace('"', '""') + '"'
            if any(row["table"].lower() == "evaluations" for row in conn.execute(f"PRAGMA foreign_key_list({quoted})")):
                raise ValueError("Custom tables referencing evaluations require an explicit migration")
        original_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='evaluations'"
        ).fetchone()[0]
        definition = original_sql[original_sql.index("("):]
        for column in ("verdict_id", "llm_prediction"):
            if column in required:
                definition, changes = re.subn(
                    rf'(\b{column}\b["`\]]?\s+(?:TEXT|INTEGER))\s+NOT\s+NULL\b',
                    r'\1', definition, count=1, flags=re.IGNORECASE,
                )
                if changes != 1:
                    raise ValueError("Unsupported legacy evaluation column declaration")
        objects = [row[0] for row in conn.execute(
            "SELECT sql FROM sqlite_master WHERE tbl_name='evaluations' "
            "AND type IN ('index','trigger') AND sql IS NOT NULL"
        )]
        sequence = conn.execute("SELECT seq FROM sqlite_sequence WHERE name='evaluations'").fetchone()
        names = ", ".join('"' + row["name"].replace('"', '""') + '"' for row in columns)
        conn.execute("SAVEPOINT migrate_unavailable_evaluations")
        try:
            conn.execute('CREATE TABLE "evaluations_nullable" ' + definition)
            conn.execute(f'INSERT INTO evaluations_nullable ({names}) SELECT {names} FROM evaluations')
            if list(conn.execute("PRAGMA foreign_key_check(evaluations_nullable)")):
                raise sqlite3.IntegrityError("Legacy evaluation foreign-key check failed")
            conn.execute("DROP TABLE evaluations")
            conn.execute("ALTER TABLE evaluations_nullable RENAME TO evaluations")
            for sql in objects:
                conn.execute(sql)
            if sequence is not None:
                conn.execute("DELETE FROM sqlite_sequence WHERE name='evaluations'")
                conn.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('evaluations',?)", (sequence[0],))
            conn.execute("RELEASE SAVEPOINT migrate_unavailable_evaluations")
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT migrate_unavailable_evaluations")
            conn.execute("RELEASE SAVEPOINT migrate_unavailable_evaluations")
            raise

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
                    ground_truth_label, ground_truth_metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    timeline_id = COALESCE(excluded.timeline_id, alerts.timeline_id),
                    ground_truth_label = CASE WHEN excluded.ground_truth_metadata IS NOT NULL
                        THEN excluded.ground_truth_label
                        WHEN alerts.ground_truth_metadata IS NOT NULL THEN alerts.ground_truth_label
                        ELSE COALESCE(excluded.ground_truth_label, alerts.ground_truth_label) END,
                    ground_truth_metadata = COALESCE(excluded.ground_truth_metadata, alerts.ground_truth_metadata);
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
                    alert.ground_truth_metadata.model_dump_json() if alert.ground_truth_metadata else None,
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
            data["ground_truth_metadata"] = json.loads(data["ground_truth_metadata"]) if data["ground_truth_metadata"] else None
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
                data["ground_truth_metadata"] = json.loads(data["ground_truth_metadata"]) if data["ground_truth_metadata"] else None
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

    def reserve_quota_request(
        self, provider: str, max_daily_quota: Optional[int], date_key: Optional[str] = None
    ) -> bool:
        """Atomically reserve one outbound attempt, including across connections.

        The quota day is selected at reservation time, never after the response.
        Failed/ambiguous sends keep their reservation conservatively.
        """
        target_date = date_key or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        limit = max_daily_quota if max_daily_quota is not None and max_daily_quota > 0 else None
        with self._lock:
            conn = self.connect()
            cursor = conn.execute(
                """
                INSERT INTO enrichment_quotas (provider, date_key, request_count)
                VALUES (?, ?, 1)
                ON CONFLICT(provider, date_key) DO UPDATE SET
                    request_count = enrichment_quotas.request_count + 1
                WHERE ? IS NULL OR enrichment_quotas.request_count < ?;
                """,
                (provider.strip().lower(), target_date, limit, limit),
            )
            reserved = cursor.rowcount == 1
            conn.commit()
            return reserved

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
            verdict = TriageVerdict.model_validate(verdict.model_dump(mode='json'))
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
                    model_name, uncertainty_level, missing_information, disposition, policy_version,
                    evidence_basis, evidence_context, evidence_contract_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                    verdict.disposition,
                    verdict.policy_version,
                    json.dumps(verdict.evidence_basis.model_dump(mode='json')) if verdict.evidence_basis is not None else None,
                    json.dumps(verdict.evidence_context) if verdict.evidence_context is not None else None,
                    verdict.evidence_contract_version,
                ),
            )
            if not self._atomic_depth:
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
            return self._decode_verdict(row)

    @staticmethod
    def _decode_verdict(row, presentation=False):
        data = dict(row)
        for name in ('reasoning', 'recommended_actions', 'evidence_basis', 'evidence_context'):
            value = data.get(name)
            try:
                data[name] = json.loads(value) if value is not None else None
            except (ValueError, TypeError):
                if not presentation or name in ('reasoning', 'recommended_actions'):
                    raise
                data[name] = value  # Invalid new metadata is visible to the UI as a warning.
        raw = data.get('missing_information')
        if presentation:
            try:
                parsed = json.loads(raw) if raw is not None else []
                valid = isinstance(parsed, list) and all(isinstance(item, str) for item in parsed)
            except (ValueError, TypeError):
                parsed, valid = None, False
            data['missing_information_recorded'] = raw is not None and valid
            # Preserve malformed storage as a detectable invalid value, never [].
            data['missing_information'] = parsed if valid else raw
        else:
            data['missing_information'] = json.loads(raw or '[]')
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
            return self._decode_verdict(row, presentation=True)

    # =====================================================================
    # Evaluation Persistence
    # =====================================================================

    def insert_evaluation(self, evaluation: EvaluationResult) -> int:
        """Inserts an EvaluationResult record.

        Strict Foreign Keys: timeline_id must exist in timelines,
        and a non-null verdict_id must exist in verdicts. Unavailable predictions
        preserve SQL NULL for both verdict_id and llm_prediction. Severity label,
        prediction, and tri-state correctness are snapshots of this evaluation.

        Args:
            evaluation: EvaluationResult instance.

        Returns:
            Auto-incremented integer ID.
        """
        with self._lock:
            if evaluation.observation_id is not None and not self._atomic_depth:
                raise ValueError('Use finalize_observation for tracked outcomes')
            conn = self.connect()
            timeline_id_str = str(evaluation.timeline_id)
            verdict_id_str = str(evaluation.verdict_id) if evaluation.verdict_id is not None else None
            now_str = datetime.now(timezone.utc).isoformat()

            gt_int = (
                (1 if evaluation.ground_truth else 0)
                if evaluation.ground_truth is not None
                else None
            )
            pred_int = int(evaluation.llm_prediction) if evaluation.llm_prediction is not None else None
            correct_int = (
                (1 if evaluation.is_correct else 0)
                if evaluation.is_correct is not None
                else None
            )

            conf_val = float(evaluation.confidence_score) if evaluation.confidence_score is not None else None
            sev_pred = evaluation.severity_prediction
            sev_correct = int(evaluation.severity_correct) if evaluation.severity_correct is not None else None

            cursor = conn.execute(
                """
                INSERT INTO evaluations (
                    timeline_id, verdict_id, ground_truth, llm_prediction,
                    is_correct, category, evaluated_at, confidence_score, severity_prediction,
                    severity_ground_truth, severity_correct, observation_id,
                    evaluation_context_hash, quality_cohort_hash, provenance_version,
                    disposition, prediction_basis, policy_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                    evaluation.severity_ground_truth,
                    sev_correct,
                    str(evaluation.observation_id) if evaluation.observation_id else None,
                    evaluation.evaluation_context_hash,
                    evaluation.quality_cohort_hash,
                    evaluation.provenance_version,
                    evaluation.disposition,
                    evaluation.prediction_basis,
                    evaluation.policy_version,
                ),
            )
            if not self._atomic_depth:
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
                data["llm_prediction"] = (
                    bool(data["llm_prediction"]) if data["llm_prediction"] is not None else None
                )
                data["is_correct"] = (
                    bool(data["is_correct"]) if data["is_correct"] is not None else None
                )
                data.setdefault("severity_ground_truth", None)
                severity_correct = data.get("severity_correct")
                data["severity_correct"] = bool(severity_correct) if severity_correct is not None else None
                for name in ('observation_id','evaluation_context_hash','quality_cohort_hash','provenance_version',
                             'disposition','prediction_basis','policy_version'):
                    data.setdefault(name, None)
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
            severity_ground_truth_select = "e.severity_ground_truth" if "severity_ground_truth" in cols else "NULL"
            severity_correct_select = "e.severity_correct" if "severity_correct" in cols else "NULL"
            provenance_select = ', '.join(
                (f'e.{name}' if name in cols else 'NULL') + f' AS {name}'
                for name in ('observation_id','evaluation_context_hash','quality_cohort_hash','provenance_version',
                             'disposition','prediction_basis','policy_version')
            )

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
                    {sev_select} AS verdict_severity,
                    {severity_ground_truth_select} AS severity_ground_truth,
                    {severity_correct_select} AS severity_correct,
                    {provenance_select}
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
                        severity_ground_truth=data["severity_ground_truth"],
                        severity_correct=(
                            bool(data["severity_correct"]) if data["severity_correct"] is not None else None
                        ),
                        observation_id=data['observation_id'],
                        evaluation_context_hash=data['evaluation_context_hash'],
                        quality_cohort_hash=data['quality_cohort_hash'],
                        provenance_version=data['provenance_version'],
                        disposition=data['disposition'],
                        prediction_basis=data['prediction_basis'],
                        policy_version=data['policy_version'],
                    )
                )
            return results

