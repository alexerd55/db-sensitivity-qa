"""Configuration and validation for dbqa."""

from __future__ import annotations

import os
import re
from typing import Optional

from pydantic import BaseModel, field_validator, model_validator


class Config(BaseModel):
    dsn: str
    schemas: list[str] = ["public"]
    include_tables: Optional[str] = None   # regex string
    exclude_tables: Optional[str] = None   # regex string
    sample_rows: int = 200
    max_columns: int = 5000
    timeout_seconds: int = 10
    output_json: Optional[str] = "report.json"

    @field_validator("dsn")
    @classmethod
    def dsn_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("DSN must not be empty")
        if "postgresql" not in v and "postgres" not in v:
            raise ValueError("DSN must be a PostgreSQL connection string")
        return v

    @field_validator("sample_rows")
    @classmethod
    def sample_rows_range(cls, v: int) -> int:
        if not (1 <= v <= 10_000):
            raise ValueError("sample_rows must be between 1 and 10000")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def timeout_range(cls, v: int) -> int:
        if not (1 <= v <= 300):
            raise ValueError("timeout_seconds must be between 1 and 300")
        return v

    @field_validator("max_columns")
    @classmethod
    def max_columns_range(cls, v: int) -> int:
        if not (1 <= v <= 50_000):
            raise ValueError("max_columns must be between 1 and 50000")
        return v

    @model_validator(mode="after")
    def compile_regex(self) -> "Config":
        if self.include_tables:
            try:
                re.compile(self.include_tables)
            except re.error as e:
                raise ValueError(f"include_tables regex invalid: {e}") from e
        if self.exclude_tables:
            try:
                re.compile(self.exclude_tables)
            except re.error as e:
                raise ValueError(f"exclude_tables regex invalid: {e}") from e
        return self

    @classmethod
    def from_env_and_args(
        cls,
        dsn: Optional[str] = None,
        schemas: Optional[str] = None,
        include_tables: Optional[str] = None,
        exclude_tables: Optional[str] = None,
        sample_rows: int = 200,
        max_columns: int = 5000,
        timeout_seconds: int = 10,
        output_json: Optional[str] = "report.json",
        # FAZA 2 TODO: output_html: Optional[str] = "report.html",
    ) -> "Config":
        resolved_dsn = dsn or os.environ.get("DBQA_DSN", "")
        resolved_schemas = (
            [s.strip() for s in schemas.split(",")] if schemas else ["public"]
        )
        return cls(
            dsn=resolved_dsn,
            schemas=resolved_schemas,
            include_tables=include_tables,
            exclude_tables=exclude_tables,
            sample_rows=sample_rows,
            max_columns=max_columns,
            timeout_seconds=timeout_seconds,
            output_json=output_json,
        )

    def safe_dsn(self) -> str:
        """Return DSN with password redacted for logging."""
        import re
        return re.sub(r"(:)([^:@]+)(@)", r"\1***\3", self.dsn)
