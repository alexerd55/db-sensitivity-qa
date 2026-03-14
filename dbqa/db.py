"""Database connection utilities."""

from __future__ import annotations

from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine


def make_engine(dsn: str, timeout_seconds: int = 10) -> Engine:
    """Create a SQLAlchemy engine with statement timeout set per connection."""
    connect_args: dict[str, Any] = {
        "connect_timeout": timeout_seconds,
        "options": f"-c statement_timeout={timeout_seconds * 1000}",
    }
    engine = create_engine(
        dsn,
        connect_args=connect_args,
        pool_pre_ping=True,
        pool_size=1,
        max_overflow=0,
    )
    return engine


def fetchall(conn: Connection, query: str, params: dict | None = None) -> list[dict]:
    """Execute a query and return all rows as list of dicts."""
    result = conn.execute(text(query), params or {})
    keys = list(result.keys())
    return [dict(zip(keys, row)) for row in result.fetchall()]


def get_current_user(conn: Connection) -> str:
    rows = fetchall(conn, "SELECT current_user AS u")
    return rows[0]["u"] if rows else "unknown"


def get_current_database(conn: Connection) -> str:
    rows = fetchall(conn, "SELECT current_database() AS d")
    return rows[0]["d"] if rows else "unknown"


def get_db_host(engine: Engine) -> str:
    """Extract host from engine URL without credentials."""
    url = engine.url
    host = url.host or "unknown"
    port = url.port or 5432
    db = url.database or "unknown"
    return f"{host}:{port}/{db}"
