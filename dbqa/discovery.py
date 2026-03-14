"""Discover tables and columns from PostgreSQL information_schema."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.engine import Connection

from dbqa.db import fetchall


@dataclass
class ColumnMeta:
    name: str
    data_type: str
    is_nullable: bool


@dataclass
class TableMeta:
    schema: str
    name: str
    columns: list[ColumnMeta] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.schema}.{self.name}"


_SKIP_SAMPLE_TYPES = frozenset(
    ["bytea", "oid", "json", "jsonb", "xml", "tsvector", "tsquery"]
)


def list_tables_and_columns(
    conn: Connection,
    schemas: list[str],
    include_regex: Optional[str] = None,
    exclude_regex: Optional[str] = None,
    max_columns: int = 5000,
) -> list[TableMeta]:
    """Return all tables and their columns from the given schemas."""
    inc_re = re.compile(include_regex) if include_regex else None
    exc_re = re.compile(exclude_regex) if exclude_regex else None

    rows = fetchall(
        conn,
        """
        SELECT
            table_schema,
            table_name,
            column_name,
            data_type,
            is_nullable
        FROM information_schema.columns
        WHERE table_schema = ANY(:schemas)
          AND table_schema NOT IN ('information_schema', 'pg_catalog')
        ORDER BY table_schema, table_name, ordinal_position
        """,
        {"schemas": schemas},
    )

    tables: dict[tuple[str, str], TableMeta] = {}
    total_columns = 0

    for row in rows:
        schema = row["table_schema"]
        table = row["table_name"]
        full = f"{schema}.{table}"

        if inc_re and not inc_re.search(table):
            continue
        if exc_re and exc_re.search(table):
            continue

        key = (schema, table)
        if key not in tables:
            tables[key] = TableMeta(schema=schema, name=table)

        if total_columns >= max_columns:
            continue

        col = ColumnMeta(
            name=row["column_name"],
            data_type=row["data_type"],
            is_nullable=row["is_nullable"] == "YES",
        )
        tables[key].columns.append(col)
        total_columns += 1

    return list(tables.values())


def is_sampleable_column(col: ColumnMeta) -> bool:
    """Return True if we should sample this column."""
    return col.data_type.lower() not in _SKIP_SAMPLE_TYPES


def is_log_table(table_name: str) -> bool:
    """Return True if table name suggests it's an audit/log table."""
    patterns = ["log", "audit", "event", "history", "trail", "changelog", "archive"]
    name_lower = table_name.lower()
    return any(p in name_lower for p in patterns)
