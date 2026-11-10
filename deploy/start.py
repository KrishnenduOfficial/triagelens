"""Compose-only migration and API startup, without printing credentials."""
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
    passwords = {role: credential(f"TL_{role.upper()}_PASSWORD") for role in roles}
    if len(set(passwords.values()) | {credential("POSTGRES_PASSWORD")}) != 5:
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


def api():
    for role in ("analyst", "hunt"):
        os.environ[f"TRIAGELENS_POSTGRES_{role.upper()}_DSN"] = dsn(
            f"tl_{role}_login", credential(f"TL_{role.upper()}_PASSWORD"))
    os.environ["DATABASE_BACKEND"] = "postgresql"
    os.execvp("uvicorn", ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"])


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("migrate", "api"):
        raise SystemExit("Expected migrate or api")
    try:
        {"migrate": migrate, "api": api}[sys.argv[1]]()
    except Exception as exc:
        # Driver exceptions can contain connection details; report only their type.
        raise SystemExit(f"Startup failed: {type(exc).__name__}") from None
