"""Add the PostgreSQL saved-hunt job queue."""

from alembic import op

revision = '0002_hunt_jobs'
down_revision = '0001_postgresql'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('''
        CREATE TABLE triagelens.hunt_jobs (
            id uuid PRIMARY KEY,
            saved_name text NOT NULL CHECK (length(saved_name) BETWEEN 1 AND 100),
            query text NOT NULL CHECK (length(query) BETWEEN 1 AND 2000),
            row_limit integer NOT NULL CHECK (row_limit BETWEEN 1 AND 1000),
            state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            ready_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            lease_token uuid,
            lease_until timestamptz,
            row_count integer CHECK (row_count BETWEEN 0 AND row_limit),
            error_code text CHECK (error_code IN ('lease_expired', 'hunt_timeout', 'storage_error', 'invalid_query')),
            CHECK ((state = 'running') = (lease_token IS NOT NULL)),
            CHECK ((state = 'running') = (lease_until IS NOT NULL)),
            CHECK ((state = 'succeeded') = (row_count IS NOT NULL)),
            CHECK (state <> 'failed' OR error_code IS NOT NULL)
        )
    ''')
    op.execute('''
        CREATE INDEX idx_hunt_jobs_ready ON triagelens.hunt_jobs (ready_at, id)
        WHERE state IN ('queued', 'running')
    ''')
    op.execute('''
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'triagelens_queue') THEN
                CREATE ROLE triagelens_queue NOLOGIN;
            ELSIF EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'triagelens_queue'
                AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
            ) THEN
                RAISE EXCEPTION 'Unsafe existing TriageLens queue role';
            END IF;
        END;
        $$
    ''')
    op.execute('GRANT USAGE ON SCHEMA triagelens TO triagelens_queue')
    op.execute('GRANT SELECT ON triagelens.alembic_version TO triagelens_queue')
    op.execute('GRANT SELECT ON triagelens.hunt_jobs TO triagelens_queue')
    op.execute('''
        GRANT UPDATE (state, attempts, ready_at, lease_token, lease_until, row_count, error_code)
        ON triagelens.hunt_jobs TO triagelens_queue
    ''')
    op.execute('''
        GRANT INSERT (id, saved_name, query, row_limit) ON triagelens.hunt_jobs TO triagelens_analyst
    ''')
    op.execute('''
        GRANT SELECT (id, saved_name, row_limit, state, attempts, created_at, ready_at, row_count, error_code)
        ON triagelens.hunt_jobs TO triagelens_analyst
    ''')


def downgrade():
    op.execute('DROP TABLE triagelens.hunt_jobs')
    op.execute('REVOKE SELECT ON triagelens.alembic_version FROM triagelens_queue')
    op.execute('REVOKE USAGE ON SCHEMA triagelens FROM triagelens_queue')
