"""
aws_cost_analyzer.py
====================
Pulls AWS Cost Explorer data to generate per-service cost attribution reports.
Supports JSON and CSV output, configurable date ranges, cost anomaly detection,
and top-N service ranking. Useful for FinOps reviews and infrastructure cost audits.

Usage:
    python main.py cost-analyze run --days 30
    python main.py cost-analyze run --days 7 --output csv --file report.csv
    python main.py cost-analyze run --days 30 --top 10 --anomaly-threshold 20
"""

import csv
import io
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import typer
from botocore.exceptions import ClientError
from rich import box
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


# ── Data models ───────────────────────────────────────────────────────────────


@dataclass
class ServiceCost:
    service: str
    amount_usd: float
    unit: str
    period_start: str
    period_end: str
    pct_of_total: float = 0.0
    prev_amount_usd: float | None = None
    change_pct: float | None = None

    @property
    def is_anomaly(self) -> bool:
        if self.change_pct is None:
            return False
        return abs(self.change_pct) > 20  # >20% change = anomaly


@dataclass
class CostReport:
    period_start: str
    period_end: str
    total_usd: float
    prev_total_usd: float | None
    total_change_pct: float | None
    currency: str
    services: list[ServiceCost]
    anomalies: list[ServiceCost] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Cost Explorer fetcher ─────────────────────────────────────────────────────


def fetch_costs(
    start_date: str,
    end_date: str,
    granularity: str = "MONTHLY",
) -> list[dict]:
    """Fetch per-service costs from AWS Cost Explorer."""
    ce = boto3.client("ce", region_name="us-east-1")  # CE is global, us-east-1 endpoint
    try:
        response = ce.get_cost_and_usage(
            TimePeriod={"Start": start_date, "End": end_date},
            Granularity=granularity,
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        return response.get("ResultsByTime", [])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "DataUnavailableException":
            raise RuntimeError(
                "Cost Explorer data not available. "
                "Ensure Cost Explorer is enabled in your AWS account "
                "(Billing → Cost Explorer → Enable)."
            ) from e
        raise


def _date_range(days: int) -> tuple:
    """Return (start_date, end_date) strings for Cost Explorer."""
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days)
    return str(start), str(end)


def _parse_results(results: list[dict]) -> dict[str, float]:
    """Aggregate cost results into service -> total_usd mapping."""
    totals: dict[str, float] = {}
    for period in results:
        for group in period.get("Groups", []):
            service = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            totals[service] = totals.get(service, 0.0) + amount
    return totals


# ── Report builder ────────────────────────────────────────────────────────────


def build_report(
    days: int,
    top_n: int | None = None,
    anomaly_threshold: float = 20.0,
) -> CostReport:
    """Build a complete cost report with period-over-period comparison."""
    # Current period
    curr_start, curr_end = _date_range(days)
    curr_results = fetch_costs(curr_start, curr_end)
    curr_costs = _parse_results(curr_results)

    # Previous period (for comparison)
    prev_end = curr_start
    prev_start = str((datetime.strptime(curr_start, "%Y-%m-%d") - timedelta(days=days)).date())
    try:
        prev_results = fetch_costs(prev_start, prev_end)
        prev_costs = _parse_results(prev_results)
    except Exception:
        prev_costs = {}

    total_curr = sum(curr_costs.values())
    total_prev = sum(prev_costs.values()) if prev_costs else None
    total_change = (
        ((total_curr - total_prev) / total_prev * 100) if total_prev and total_prev > 0 else None
    )

    # Build per-service breakdown
    services: list[ServiceCost] = []
    for service, amount in sorted(curr_costs.items(), key=lambda x: x[1], reverse=True):
        prev_amount = prev_costs.get(service)
        change_pct = None
        if prev_amount is not None and prev_amount > 0:
            change_pct = (amount - prev_amount) / prev_amount * 100

        pct_of_total = (amount / total_curr * 100) if total_curr > 0 else 0.0

        services.append(
            ServiceCost(
                service=service,
                amount_usd=round(amount, 4),
                unit="USD",
                period_start=curr_start,
                period_end=curr_end,
                pct_of_total=round(pct_of_total, 2),
                prev_amount_usd=round(prev_amount, 4) if prev_amount is not None else None,
                change_pct=round(change_pct, 2) if change_pct is not None else None,
            )
        )

    # Filter zero-cost services and limit to top N
    services = [s for s in services if s.amount_usd > 0]
    if top_n:
        services = services[:top_n]

    anomalies = [
        s for s in services if s.change_pct is not None and abs(s.change_pct) >= anomaly_threshold
    ]

    return CostReport(
        period_start=curr_start,
        period_end=curr_end,
        total_usd=round(total_curr, 4),
        prev_total_usd=round(total_prev, 4) if total_prev else None,
        total_change_pct=round(total_change, 2) if total_change else None,
        currency="USD",
        services=services,
        anomalies=anomalies,
    )


# ── Output formatters ─────────────────────────────────────────────────────────


def print_cost_table(report: CostReport) -> None:
    # Summary header
    change_str = ""
    if report.total_change_pct is not None:
        colour = "red" if report.total_change_pct > 0 else "green"
        arrow = "↑" if report.total_change_pct > 0 else "↓"
        change_str = (
            f" [{colour}]{arrow} {abs(report.total_change_pct):.1f}% vs prior period[/{colour}]"
        )

    console.print(
        f"\n[bold]Total AWS spend:[/bold] [cyan]${report.total_usd:,.2f}[/cyan]{change_str}\n"
        f"[dim]Period: {report.period_start} → {report.period_end}[/dim]\n"
    )

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold blue")
    table.add_column("Service", width=38)
    table.add_column("Cost (USD)", width=14, justify="right")
    table.add_column("% of Total", width=12, justify="right")
    table.add_column("Prior Period", width=14, justify="right")
    table.add_column("Change", width=14, justify="right")

    for svc in report.services:
        change_col = "[dim]N/A[/dim]"
        if svc.change_pct is not None:
            colour = "red" if svc.change_pct > 0 else "green"
            arrow = "↑" if svc.change_pct > 0 else "↓"
            flag = " ⚠️" if svc.is_anomaly else ""
            change_col = f"[{colour}]{arrow} {abs(svc.change_pct):.1f}%{flag}[/{colour}]"

        prior_col = (
            f"${svc.prev_amount_usd:,.2f}" if svc.prev_amount_usd is not None else "[dim]N/A[/dim]"
        )

        table.add_row(
            svc.service,
            f"${svc.amount_usd:,.4f}",
            f"{svc.pct_of_total:.1f}%",
            prior_col,
            change_col,
        )

    console.print(table)

    if report.anomalies:
        console.print(
            f"\n[bold yellow]⚠️  Cost anomalies detected ({len(report.anomalies)}):[/bold yellow]"
        )
        for a in report.anomalies:
            direction = "increase" if a.change_pct > 0 else "decrease"
            console.print(
                f"  [yellow]{a.service}[/yellow]: "
                f"{abs(a.change_pct):.1f}% {direction} "
                f"(${a.prev_amount_usd:,.2f} → ${a.amount_usd:,.2f})"
            )
    console.print()


def to_csv(report: CostReport) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Service",
            "Amount_USD",
            "Pct_Of_Total",
            "Prior_Amount_USD",
            "Change_Pct",
            "Is_Anomaly",
            "Period_Start",
            "Period_End",
        ]
    )
    for svc in report.services:
        writer.writerow(
            [
                svc.service,
                svc.amount_usd,
                svc.pct_of_total,
                svc.prev_amount_usd,
                svc.change_pct,
                svc.is_anomaly,
                svc.period_start,
                svc.period_end,
            ]
        )
    return output.getvalue()


# ── CLI ───────────────────────────────────────────────────────────────────────


@app.command("run")
def run(
    days: int = typer.Option(30, "--days", "-d", help="Number of days to analyze (default: 30)"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table | json | csv"),
    file: str | None = typer.Option(None, "--file", "-f", help="Write output to file (optional)"),
    top: int | None = typer.Option(None, "--top", "-n", help="Limit to top N services by cost"),
    anomaly_threshold: float = typer.Option(
        20.0,
        "--anomaly-threshold",
        help="Percentage change to flag as a cost anomaly (default: 20.0)",
    ),
):
    """
    Generate a per-service AWS cost attribution report with period-over-period comparison.

    Examples:\n
        python main.py cost-analyze run --days 30\n
        python main.py cost-analyze run --days 7 --top 10\n
        python main.py cost-analyze run --days 30 --output csv --file costs.csv
    """
    console.print(
        f"\n[bold blue]💰 Fetching AWS cost data[/bold blue] — "
        f"last [cyan]{days}[/cyan] days · "
        f"anomaly threshold: [cyan]{anomaly_threshold}%[/cyan]\n"
    )

    try:
        report = build_report(days, top_n=top, anomaly_threshold=anomaly_threshold)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e

    if output == "json":
        content = json.dumps(asdict(report), indent=2, default=str)
    elif output == "csv":
        content = to_csv(report)
    else:
        print_cost_table(report)
        content = None

    if content:
        if file:
            Path(file).write_text(content, encoding="utf-8")
            console.print(f"[green]Report written to {file}[/green]")
        else:
            typer.echo(content)
