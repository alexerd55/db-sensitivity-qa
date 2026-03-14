"""Report generation: JSON output.

# FAZA 2 TODO: HTML report via Jinja2
# - Dodati: from jinja2 import Environment, FileSystemLoader
# - Dodati: write_html(report, out_path, template_path) funkciju
# - Template se nalazi u templates/report.html.j2
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from dbqa.checks import Finding, Severity


@dataclass
class ReportSummary:
    tables_scanned: int = 0
    columns_scanned: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    skipped_tables: int = 0

    @property
    def total_findings(self) -> int:
        return self.high_count + self.medium_count + self.low_count + self.info_count


@dataclass
class Report:
    scanned_at: str
    db_location: str   # host:port/dbname, no credentials
    db_user: str
    summary: ReportSummary = field(default_factory=ReportSummary)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)
        sev = f.severity
        if sev == Severity.HIGH:
            self.summary.high_count += 1
        elif sev == Severity.MEDIUM:
            self.summary.medium_count += 1
        elif sev == Severity.LOW:
            self.summary.low_count += 1
        else:
            self.summary.info_count += 1

    def top_risky(self, n: int = 10) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.score, reverse=True)[:n]


def make_report(db_location: str, db_user: str) -> Report:
    return Report(
        scanned_at=datetime.now(timezone.utc).isoformat(),
        db_location=db_location,
        db_user=db_user,
    )


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def _finding_to_dict(f: Finding) -> dict:
    return {
        "severity": f.severity,
        "type": f.finding_type,
        "object": f.object_name,
        "schema": f.schema,
        "table": f.table,
        "column": f.column,
        "tags": f.tags,
        "score": f.score,
        "details": f.details,
        "evidence_masked": f.evidence,
    }


def write_json(report: Report, path: str) -> None:
    data = {
        "scanned_at": report.scanned_at,
        "db_location": report.db_location,
        "db_user": report.db_user,
        "summary": {
            "tables_scanned": report.summary.tables_scanned,
            "columns_scanned": report.summary.columns_scanned,
            "high": report.summary.high_count,
            "medium": report.summary.medium_count,
            "low": report.summary.low_count,
            "info": report.summary.info_count,
            "total_findings": report.summary.total_findings,
            "skipped_tables": report.summary.skipped_tables,
        },
        "findings": [_finding_to_dict(f) for f in report.findings],
        "skipped": report.skipped,
    }
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# FAZA 2 TODO: HTML output
# ---------------------------------------------------------------------------
# def write_html(report: Report, out_path: str, template_path: Optional[str] = None) -> None:
#     Implementacija u fazi 2 — koristiti templates/report.html.j2
#     pass
