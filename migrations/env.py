"""Run PostgreSQL migrations with a separate owner credential."""

import os

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool


def migrate():
    dsn = os.environ.get('TRIAGELENS_POSTGRES_MIGRATION_DSN', '').strip()
    if not dsn or context.is_offline_mode():
        raise RuntimeError('Set TRIAGELENS_POSTGRES_MIGRATION_DSN and run against PostgreSQL.')
    try:
        # Pass the DSN directly to psycopg so credentials never enter Alembic config/logging.
        import psycopg

        engine = create_engine('postgresql+psycopg://', poolclass=NullPool,
                               creator=lambda: psycopg.connect(dsn, connect_timeout=5),
                               hide_parameters=True)
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql('CREATE SCHEMA IF NOT EXISTS triagelens')
                connection.exec_driver_sql('SET LOCAL search_path TO pg_catalog, triagelens, triagelens_truth')
                context.configure(connection=connection, version_table_schema='triagelens')
                with context.begin_transaction():
                    context.run_migrations()
        finally:
            engine.dispose()
    except SQLAlchemyError as exc:
        state = getattr(getattr(exc, 'orig', None), 'sqlstate', None) or 'unavailable'
        raise RuntimeError(f'PostgreSQL migration failed (SQLSTATE {state}).') from None


migrate()
