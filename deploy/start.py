"""Compose-only database, API and worker startup, without printing credentials."""
import os
import sys

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo


def dsn(user, password):
    return make_conninfo(host="db", dbname="triagelens", user=user,
                         password=password, connect_timeout=5)


def credential(name):
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"Set {name} to a nonempty password")
    return value


def migrate():
    from alembic import command
    from alembic.config import Config

    admin = dsn("triagelens_admin", credential("POSTGRES_PASSWORD"))
    roles = ("analyst", "hunt", "evaluator", "triage")
    if os.environ.get("TL_QUEUE_PASSWORD"):
        roles += ("queue",)
    passwords = {role: credential(f"TL_{role.upper()}_PASSWORD") for role in roles}
    if len(set(passwords.values()) | {credential("POSTGRES_PASSWORD")}) != len(roles) + 1:
        raise ValueError("Database passwords must be distinct")
    os.environ["TRIAGELENS_POSTGRES_MIGRATION_DSN"] = admin
    command.upgrade(Config("alembic.ini"), "head")
    with psycopg.connect(admin) as connection:
        for role in roles:
            name = f"tl_{role}_login"
            existing = connection.execute(
                "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls "
                "FROM pg_roles WHERE rolname = %s", (name,)
            ).fetchone()
            if existing and existing[0]:
                raise RuntimeError("Existing application login has elevated privileges")
            memberships = connection.execute(
                "SELECT r.rolname FROM pg_auth_members m "
                "JOIN pg_roles r ON r.oid = m.roleid "
                "JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = %s", (name,)
            ).fetchall()
            if any(group[0] != f"triagelens_{role}" for group in memberships):
                raise RuntimeError("Existing application login has unexpected memberships")
            if existing is None:
                connection.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(name)))
            connection.execute(sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(name), sql.Literal(passwords[role])))
            connection.execute(sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(f"triagelens_{role}"), sql.Identifier(name)))


def configure_logins(*roles):
    for role in roles:
        os.environ[f"TRIAGELENS_POSTGRES_{role.upper()}_DSN"] = dsn(
            f"tl_{role}_login", credential(f"TL_{role.upper()}_PASSWORD"))


def api():
    configure_logins("analyst", "hunt")
    os.environ["DATABASE_BACKEND"] = "postgresql"
    os.execvp("uvicorn", ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"])


def worker(*args):
    configure_logins("queue", "hunt")
    os.execvp(sys.executable, [sys.executable, "-m", "src.worker", "run", *args])


def queue(*args):
    if not args or args[0] not in ("enqueue", "status"):
        raise ValueError("Expected enqueue or status")
    configure_logins("analyst")
    os.execvp(sys.executable, [sys.executable, "-m", "src.worker", *args])


if __name__ == "__main__":
    commands = {"migrate": migrate, "api": api, "worker": worker, "queue": queue}
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        raise SystemExit("Expected migrate, api, worker or queue")
    try:
        commands[sys.argv[1]](*sys.argv[2:])
    except Exception as exc:
        # Driver exceptions can contain connection details; report only their type.
        raise SystemExit(f"Startup failed: {type(exc).__name__}") from None
