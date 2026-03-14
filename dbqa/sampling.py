"""Sample column values safely from PostgreSQL."""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.engine import Connection

from dbqa.db import fetchall
from dbqa.discovery import ColumnMeta, is_sampleable_column

logger = logging.getLogger(__name__)

MAX_STRING_LENGTH = 256  


def sample_column(
    conn: Connection,
    schema: str,
    table: str,
    column: ColumnMeta,
    sample_rows: int = 200,
) -> list[str]:
    """
    Sample non-null string values from a column.
    Returns a list of truncated string representations.
    Never raises — returns empty list on any error.
    """
    if not is_sampleable_column(column):
        return []

    q_schema = _quote_ident(schema)
    q_table = _quote_ident(table)
    q_col = _quote_ident(column.name)

    try:
        rows = fetchall(
            conn,
            f"""
            SELECT {q_col}::text AS v
            FROM {q_schema}.{q_table}
            WHERE {q_col} IS NOT NULL
            LIMIT :n
            """,
            {"n": sample_rows},
        )
        results = []
        for row in rows:
            val = row.get("v")
            if val is None:
                continue
            s = str(val)
            if len(s) > MAX_STRING_LENGTH:
                s = s[:MAX_STRING_LENGTH]
            results.append(s)
        return results

    except Exception as exc:
        logger.warning(
            "Skipped sampling %s.%s.%s: %s",
            schema,
            table,
            column.name,
            exc,
        )
        return []


def _quote_ident(name: str) -> str:
    """Simple PostgreSQL identifier quoting."""
    return '"' + name.replace('"', '""') + '"'
