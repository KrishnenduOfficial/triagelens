"""Enqueue, inspect, or run PostgreSQL saved-hunt jobs."""

import argparse
import json
import os
import signal
import sys
from threading import Event
from uuid import UUID


def _dsn(role: str) -> str:
    key = f'TRIAGELENS_POSTGRES_{role.upper()}_DSN'
    value = os.getenv(key, '').strip()
    if not value:
        raise ValueError(f'Set {key} for saved-hunt jobs.')
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enqueue = commands.add_parser('enqueue', help='Submit an existing saved hunt')
    enqueue.add_argument('name')
    enqueue.add_argument('job_id', type=UUID)
    enqueue.add_argument('--limit', type=int, default=500)
    status = commands.add_parser('status', help='Show one job by ID')
    status.add_argument('job_id', type=UUID)
    run = commands.add_parser('run', help='Start the PostgreSQL worker')
    run.add_argument('--once', action='store_true', help='Poll for at most one job and exit')
    args = parser.parse_args()

    try:
        from src.engine.job_queue import HuntJobQueue, retryable_storage_error
        from src.engine.postgres import PostgresDatabase, PostgresStorageError
    except ImportError:
        print('Install requirements-postgres.txt to use saved-hunt jobs.', file=sys.stderr)
        return 1

    db = None
    try:
        if args.command == 'run':
            db = PostgresDatabase(_dsn('queue'), 'queue', hunt_dsn=_dsn('hunt'))
        else:
            db = PostgresDatabase(_dsn('analyst'), 'analyst')
        db.init_db()
        queue = HuntJobQueue(db)
        if args.command == 'run':
            db.hunt('SELECT 1', [], 2)
            if args.once:
                queue.work_once()
                return 0
            stop = Event()
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
            while not stop.is_set():
                try:
                    if not queue.work_once():
                        stop.wait(1)
                except PostgresStorageError as exc:
                    if not retryable_storage_error(exc):
                        raise
                    db.close()
                    stop.wait(1)
        else:
            job = (queue.enqueue(args.job_id, args.name, args.limit) if args.command == 'enqueue'
                   else queue.status(args.job_id))
            if job is None:
                raise ValueError('Job does not exist.')
            print(json.dumps(job, default=str))
    except KeyboardInterrupt:
        return 130
    except (ValueError, PostgresStorageError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f'Saved-hunt job command failed ({type(exc).__name__}).', file=sys.stderr)
        return 1
    finally:
        if db is not None:
            db.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
