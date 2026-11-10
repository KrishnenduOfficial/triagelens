"""Durable PostgreSQL jobs for bounded, read-only saved hunts."""

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from src.engine.hunting import ThreatHuntingEngine
from src.engine.hunting_dsl import KQLParseError
from src.engine.postgres import PostgresDatabase, PostgresStorageError


# Lock the token's row before comparing the deadline, including after a lock wait.
_LOCK_LEASE = '''
    WITH active_lease AS MATERIALIZED (
        SELECT id, lease_until FROM triagelens.hunt_jobs WHERE id = ? AND lease_token = ? FOR UPDATE
    )
'''


@dataclass(frozen=True)
class HuntJob:
    id: UUID
    lease_token: UUID
    row_limit: int
    query: str = field(repr=False)


def retryable_storage_error(error: PostgresStorageError) -> bool:
    state = error.sqlstate
    return (state is None or state.startswith('08')
            or state in ('40001', '40P01', '55P03', '57P01', '57P02', '57P03'))


class HuntJobQueue:
    def __init__(self, db: PostgresDatabase) -> None:
        self.db = db

    def enqueue(self, job_id: UUID, name: str, limit: int) -> dict[str, Any]:
        name = ThreatHuntingEngine._validate_name(name)
        if type(limit) is not int or not 1 <= limit <= ThreatHuntingEngine.MAX_LIMIT:
            raise ValueError('Row limit must be between 1 and 1000.')
        self.db.connect().execute('''
            INSERT INTO triagelens.hunt_jobs (id, saved_name, query, row_limit)
            SELECT ?, name, query, ? FROM triagelens.saved_hunting_queries WHERE name = ?
            ON CONFLICT (id) DO NOTHING
        ''', (job_id, limit, name))
        # A separate statement can see a conflicting submission once it commits.
        job = self.status(job_id)
        if job is None:
            raise ValueError('Saved query does not exist.')
        if (job['saved_name'], job['row_limit']) != (name, limit):
            raise ValueError('Job ID already belongs to a different submission.')
        return job

    def status(self, job_id: UUID) -> dict[str, Any] | None:
        row = self.db.connect().execute('''
            SELECT id, saved_name, row_limit, state, attempts, created_at, ready_at, row_count, error_code
            FROM triagelens.hunt_jobs WHERE id = ?
        ''', (job_id,)).fetchone()
        return dict(row) if row is not None else None

    def claim(self) -> HuntJob | None:
        token = uuid4()
        # For running jobs, ready_at is the lease deadline plus the crash retry delay.
        # A final expired attempt is eligible at the deadline and becomes terminal.
        row = self.db.connect().execute('''
            WITH clock AS (SELECT clock_timestamp() AS now), candidate AS (
                SELECT id FROM triagelens.hunt_jobs, clock
                WHERE state IN ('queued', 'running') AND ready_at <= clock.now
                ORDER BY ready_at, id LIMIT 1 FOR UPDATE OF hunt_jobs SKIP LOCKED
            )
            UPDATE triagelens.hunt_jobs AS j SET
                state = CASE WHEN attempts = 3 THEN 'failed' ELSE 'running' END,
                attempts = LEAST(attempts + 1, 3),
                lease_token = CASE WHEN attempts < 3 THEN CAST(? AS uuid) END,
                lease_until = CASE WHEN attempts < 3 THEN clock.now + interval '30 seconds' END,
                ready_at = CASE WHEN attempts = 3 THEN clock.now ELSE clock.now + interval '30 seconds'
                    + CASE WHEN attempts < 2 THEN (5 << attempts) * interval '1 second' ELSE interval '0' END END,
                error_code = CASE WHEN attempts = 3 THEN 'lease_expired' END
            FROM candidate, clock WHERE j.id = candidate.id
            RETURNING j.id, lease_token, row_limit, query
        ''', (token,)).fetchone()
        if row is None or row['lease_token'] is None:
            return None
        return HuntJob(row['id'], token, row['row_limit'], row['query'])

    def complete(self, job: HuntJob, count: int) -> bool:
        return self.db.connect().execute(_LOCK_LEASE + '''
            UPDATE triagelens.hunt_jobs AS j SET state = 'succeeded', row_count = ?,
                ready_at = clock_timestamp(), lease_token = NULL, lease_until = NULL, error_code = NULL
            FROM active_lease WHERE j.id = active_lease.id AND active_lease.lease_until > clock_timestamp()
        ''', (job.id, job.lease_token, count)).rowcount == 1

    def fail(self, job: HuntJob, code: str, *, retry: bool) -> bool:
        return self.db.connect().execute(_LOCK_LEASE + '''
            UPDATE triagelens.hunt_jobs AS j SET
                state = CASE WHEN ? AND attempts < 3 THEN 'queued' ELSE 'failed' END,
                ready_at = clock_timestamp() + CASE WHEN ? AND attempts < 3
                    THEN j.ready_at - j.lease_until ELSE interval '0' END,
                lease_token = NULL, lease_until = NULL, error_code = ?
            FROM active_lease WHERE j.id = active_lease.id AND active_lease.lease_until > clock_timestamp()
        ''', (job.id, job.lease_token, retry, retry, code)).rowcount == 1

    def work_once(self) -> bool:
        job = self.claim()
        if job is None:
            return False
        engine = ThreatHuntingEngine(self.db)
        try:
            sql, params = engine.translate_kql_to_sql(job.query, job.row_limit)
            rows = self.db.hunt(f'SELECT count(*) AS count FROM ({sql}) AS matches', params, engine.timeout)
        except KQLParseError:
            self.fail(job, 'invalid_query', retry=False)
        except PostgresStorageError as exc:
            if exc.sqlstate == '57014':
                self.fail(job, 'hunt_timeout', retry=True)
            else:
                self.fail(job, 'storage_error', retry=retryable_storage_error(exc))
        else:
            self.complete(job, rows[0]['count'])
        return True
