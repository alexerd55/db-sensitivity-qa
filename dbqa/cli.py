"""CLI entrypoint for dbqa."""

from __future__ import annotations

import logging
import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich import box

from dbqa.checks import Severity, check_auth_fields, check_privileges, check_sensitive_columns
from dbqa.config import Config
from dbqa.db import get_current_database, get_current_user, get_db_host, make_engine
from dbqa.discovery import list_tables_and_columns
from dbqa.reporting import make_report, write_json
from dbqa.sampling import sample_column

console = Console()
logger = logging.getLogger("dbqa")

_SEV_COLORS = {
    Severity.HIGH:   "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW:    "cyan",
    Severity.INFO:   "dim",
}


@click.group()
@click.version_option()
def cli():
    """DB Sensitivity QA — PostgreSQL PII & privilege scanner."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


@cli.command()
@click.option("--dsn",              default=None,        help="PostgreSQL DSN (or set DBQA_DSN env var)")
@click.option("--schemas",          default="public",    show_default=True, help="Comma-separated schema list")
@click.option("--include-tables",   default=None,        help="Regex to include tables")
@click.option("--exclude-tables",   default=None,        help="Regex to exclude tables")
@click.option("--sample-rows",      default=200,         show_default=True, type=int)
@click.option("--max-columns",      default=5000,        show_default=True, type=int)
@click.option("--timeout-seconds",  default=10,          show_default=True, type=int)
@click.option("--output",           default="report.json", show_default=True, help="JSON output path")
@click.option("--verbose", "-v",    is_flag=True,        help="Enable verbose logging")
def scan(
    dsn, schemas, include_tables, exclude_tables,
    sample_rows, max_columns, timeout_seconds,
    output, verbose,
):
    """Scan a PostgreSQL database for PII, sensitive data, and privilege issues."""
    if verbose:
        logging.getLogger("dbqa").setLevel(logging.DEBUG)

    # --- Config ---
    try:
        config = Config.from_env_and_args(
            dsn=dsn,
            schemas=schemas,
            include_tables=include_tables,
            exclude_tables=exclude_tables,
            sample_rows=sample_rows,
            max_columns=max_columns,
            timeout_seconds=timeout_seconds,
            output_json=output,
        )
    except Exception as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        sys.exit(1)

    if not config.dsn:
        console.print("[bold red]Error:[/bold red] No DSN provided. Use --dsn or set DBQA_DSN.")
        sys.exit(1)

    console.print(f"\n[bold]DB Sensitivity QA[/bold] — scanning [cyan]{config.safe_dsn()}[/cyan]")
    console.print(f"Schemas: {', '.join(config.schemas)}  |  sample-rows: {config.sample_rows}  |  timeout: {config.timeout_seconds}s\n")

    # --- Connect ---
    try:
        engine = make_engine(config.dsn, config.timeout_seconds)
    except Exception as exc:
        console.print(f"[bold red]Engine creation failed:[/bold red] {exc}")
        sys.exit(1)

    try:
        with engine.connect() as conn:
            db_host = get_db_host(engine)
            db_user = get_current_user(conn)
            report  = make_report(db_host, db_user)

            console.print(f"Connected as [bold]{db_user}[/bold] to [bold]{db_host}[/bold]\n")

            # --- Privilege checks ---
            console.print("[bold]Checking privileges…[/bold]")
            priv_findings = check_privileges(conn)
            for f in priv_findings:
                report.add_finding(f)
                color = _SEV_COLORS.get(f.severity, "white")
                console.print(f"  [{color}]{f.severity}[/{color}]  {f.details}")
            if not priv_findings:
                console.print("  [green]No obvious privilege issues found.[/green]")

            # --- Discovery ---
            console.print("\n[bold]Discovering tables…[/bold]")
            tables = list_tables_and_columns(
                conn,
                schemas=config.schemas,
                include_regex=config.include_tables,
                exclude_regex=config.exclude_tables,
                max_columns=config.max_columns,
            )
            total_cols = sum(len(t.columns) for t in tables)
            report.summary.tables_scanned = len(tables)
            report.summary.columns_scanned = total_cols
            console.print(f"  Found [bold]{len(tables)}[/bold] tables, [bold]{total_cols}[/bold] columns\n")

            if not tables:
                console.print("[yellow]No tables found. Check schema names and permissions.[/yellow]")

            # --- Sample + Detect ---
            console.print("[bold]Sampling and detecting sensitive data…[/bold]")
            with console.status("Scanning columns…") as status:
                for table in tables:
                    status.update(f"Scanning [cyan]{table.full_name}[/cyan]…")
                    samples: dict[str, list[str]] = {}

                    for col in table.columns:
                        try:
                            vals = sample_column(conn, table.schema, table.name, col, config.sample_rows)
                            samples[col.name] = vals
                        except Exception as exc:
                            logger.debug("Sampling failed for %s.%s: %s", table.full_name, col.name, exc)
                            report.skipped.append(f"{table.full_name}.{col.name}: {exc}")
                            report.summary.skipped_tables += 1

                    for finding in check_sensitive_columns(table, samples):
                        report.add_finding(finding)
                    for finding in check_auth_fields(table, samples):
                        # Only add if not already found by sensitive_columns for same col
                        existing_keys = {(f.schema, f.table, f.column) for f in report.findings}
                        key = (finding.schema, finding.table, finding.column)
                        if key not in existing_keys:
                            report.add_finding(finding)

            # --- Summary ---
            _print_summary(report)

            # --- Write outputs ---
            if output:
                write_json(report, output)
                console.print(f"\n[green]JSON report:[/green] {output}")

            # FAZA 2 TODO: HTML report
            # write_html(report, config.output_html)

    except Exception as exc:
        console.print(f"\n[bold red]Runtime error:[/bold red] {exc}")
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(1)

    # Exit code: 2 if HIGH findings, else 0
    if report.summary.high_count > 0:
        sys.exit(2)
    sys.exit(0)


def _print_summary(report) -> None:
    summary = report.summary

    # Summary counts
    console.print(f"\n[bold]Scan complete.[/bold]")
    console.print(
        f"  Tables: {summary.tables_scanned}  |  "
        f"Columns: {summary.columns_scanned}  |  "
        f"[bold red]HIGH: {summary.high_count}[/bold red]  "
        f"[yellow]MEDIUM: {summary.medium_count}[/yellow]  "
        f"[cyan]LOW: {summary.low_count}[/cyan]  "
        f"INFO: {summary.info_count}"
    )

    # Top risky columns table
    top = report.top_risky(10)
    if not top:
        console.print("\n[green]No sensitive findings detected.[/green]")
        return

    console.print("\n[bold]Top 10 Riskiest Columns:[/bold]")
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    tbl.add_column("Score", style="bold", width=6)
    tbl.add_column("Severity", width=8)
    tbl.add_column("Object", width=45)
    tbl.add_column("Tags", width=30)
    tbl.add_column("Details")

    for f in top:
        color = _SEV_COLORS.get(f.severity, "white")
        tbl.add_row(
            str(f.score),
            f"[{color}]{f.severity}[/{color}]",
            f.object_name,
            ", ".join(f.tags[:4]),
            f.details[:80] + ("…" if len(f.details) > 80 else ""),
        )

    console.print(tbl)

    # Privilege warnings
    priv_findings = [f for f in report.findings if "PRIVILEGE" in f.tags]
    if priv_findings:
        console.print("[bold yellow]!! Privilege warnings:[/bold yellow]")
        for pf in priv_findings:
            color = _SEV_COLORS.get(pf.severity, "white")
            console.print(f"  [{color}]{pf.severity}[/{color}]  {pf.details}")
