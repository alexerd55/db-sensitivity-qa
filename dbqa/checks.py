"""
High-level checks: sensitive columns, privileges, auth fields.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.engine import Connection

from dbqa.db import fetchall, get_current_database, get_current_user
from dbqa.detectors import Tag, detect_by_name, detect_values
from dbqa.discovery import ColumnMeta, TableMeta, is_log_table, is_sampleable_column

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

class Severity:
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"
    INFO   = "INFO"


def _score_to_severity(score: int) -> str:
    if score >= 80:
        return Severity.HIGH
    if score >= 50:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str
    finding_type: str
    schema: str
    table: str
    column: Optional[str]
    details: str
    tags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)   # masked examples only
    score: int = 0

    @property
    def object_name(self) -> str:
        parts = [self.schema, self.table]
        if self.column:
            parts.append(self.column)
        return ".".join(parts)


# ---------------------------------------------------------------------------
# Column sensitivity scoring
# ---------------------------------------------------------------------------

def _compute_score(
    col: ColumnMeta,
    name_tags: set[str],
    value_results,
    in_log_table: bool,
) -> tuple[int, list[str]]:
    """Return (score 0-100, all_tags)."""
    score = 0
    all_tags: set[str] = set(name_tags)

    if name_tags:
        score += 40

    if in_log_table:
        score += 10

    text_types = {"character varying", "text", "character", "varchar"}
    if col.data_type.lower() in text_types and Tag.AUTH in name_tags:
        score += 10

    best_rate = 0.0
    for vr in value_results:
        all_tags.add(vr.tag)
        if vr.hit_rate > best_rate:
            best_rate = vr.hit_rate

    score += int(best_rate * 50)
    score = min(score, 100)

    return score, sorted(all_tags)


# ---------------------------------------------------------------------------
# Main checks
# ---------------------------------------------------------------------------

def check_sensitive_columns(
    table: TableMeta,
    samples: dict[str, list[str]], 
) -> list[Finding]:
    """Produce findings for sensitive columns in a table."""
    findings: list[Finding] = []
    log_table = is_log_table(table.name)

    for col in table.columns:
        name_tags = detect_by_name(col.name)
        values = samples.get(col.name, [])
        value_results = detect_values(values) if values else []

        if not name_tags and not value_results:
            continue

        score, all_tags = _compute_score(col, name_tags, value_results, log_table)
        severity = _score_to_severity(score)

        evidence: list[str] = []
        for vr in value_results:
            evidence.extend(vr.examples_masked)
        evidence = evidence[:9]  # cap total

        hit_summaries = [
            f"{vr.tag}: {vr.hit_count}/{vr.total} ({vr.hit_rate:.0%})"
            for vr in value_results
        ]
        detail_parts = []
        if name_tags:
            detail_parts.append(f"Column name suggests: {', '.join(sorted(name_tags))}")
        if hit_summaries:
            detail_parts.append("Value matches: " + "; ".join(hit_summaries))
        if log_table:
            detail_parts.append("Located in log/audit table")

        finding = Finding(
            severity=severity,
            finding_type="SENSITIVE_COLUMN",
            schema=table.schema,
            table=table.name,
            column=col.name,
            details=" | ".join(detail_parts),
            tags=all_tags,
            evidence=evidence,
            score=score,
        )
        findings.append(finding)

    return findings


def check_auth_fields(
    table: TableMeta,
    samples: dict[str, list[str]],
) -> list[Finding]:
    """
    Flag auth/secret columns where values don't look like hashes
    (potential plaintext storage — heuristic only, never conclusive).
    """
    findings: list[Finding] = []
    hash_like_types = {"bytea"}

    for col in table.columns:
        if Tag.AUTH not in detect_by_name(col.name):
            continue
        if col.data_type.lower() in hash_like_types:
            continue

        values = samples.get(col.name, [])
        if not values:
            continue

        value_results = detect_values(values)
        has_hash = any(vr.tag == Tag.HASH_LIKE for vr in value_results)
        has_jwt  = any(vr.tag == Tag.JWT for vr in value_results)

        if not has_hash and not has_jwt:
            finding = Finding(
                severity=Severity.MEDIUM,
                finding_type="POSSIBLE_PLAINTEXT_SECRET",
                schema=table.schema,
                table=table.name,
                column=col.name,
                details=(
                    f"Column '{col.name}' appears to store auth/secret data "
                    f"but sampled values ({len(values)}) do not resemble hashes or tokens. "
                    "Heuristic only — manual review required."
                ),
                tags=[Tag.AUTH],
                score=55,
            )
            findings.append(finding)

    return findings


def check_privileges(conn: Connection) -> list[Finding]:
    """Check current DB role privileges and flag overly broad grants."""
    findings: list[Finding] = []
    current_user = get_current_user(conn)
    current_db   = get_current_database(conn)

    try:
        roles = fetchall(
            conn,
            """
            SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin
            FROM pg_roles
            WHERE rolname = current_user
            """,
        )
    except Exception as exc:
        logger.warning("Could not query pg_roles: %s", exc)
        roles = []

    for role in roles:
        if role.get("rolsuper"):
            findings.append(Finding(
                severity=Severity.HIGH,
                finding_type="PRIVILEGE_SUPERUSER",
                schema="",
                table="",
                column=None,
                details=f"Role '{current_user}' is a PostgreSQL SUPERUSER. This grants unrestricted access.",
                tags=["PRIVILEGE"],
                score=100,
            ))
        if role.get("rolcreatedb"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                finding_type="PRIVILEGE_CREATEDB",
                schema="",
                table="",
                column=None,
                details=f"Role '{current_user}' has CREATEDB privilege.",
                tags=["PRIVILEGE"],
                score=60,
            ))
        if role.get("rolcreaterole"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                finding_type="PRIVILEGE_CREATEROLE",
                schema="",
                table="",
                column=None,
                details=f"Role '{current_user}' has CREATEROLE privilege.",
                tags=["PRIVILEGE"],
                score=60,
            ))

    db_privilege_checks = [
        ("CREATE",  Severity.MEDIUM, "PRIVILEGE_DB_CREATE",  60),
        ("TEMP",    Severity.LOW,    "PRIVILEGE_DB_TEMP",    30),
    ]
    for priv, sev, ftype, score in db_privilege_checks:
        try:
            rows = fetchall(
                conn,
                f"SELECT has_database_privilege(current_user, current_database(), :p) AS ok",
                {"p": priv},
            )
            if rows and rows[0]["ok"]:
                findings.append(Finding(
                    severity=sev,
                    finding_type=ftype,
                    schema="",
                    table="",
                    column=None,
                    details=(
                        f"Role '{current_user}' has {priv} privilege on database '{current_db}'. "
                        "Application users typically should not have this."
                    ),
                    tags=["PRIVILEGE"],
                    score=score,
                ))
        except Exception as exc:
            logger.warning("Privilege check %s failed: %s", priv, exc)

    return findings
