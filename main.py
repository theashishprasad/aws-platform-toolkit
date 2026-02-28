#!/usr/bin/env python3
"""
aws-platform-toolkit
====================
Production-grade CLI for AWS infrastructure operations.
Covers health checks, drift detection, cost analysis, and automated remediation.

Usage:
    python main.py healthcheck run --services eks,rds,elasticache,sqs
    python main.py drift-detect run --tfstate ./terraform.tfstate
    python main.py cost-analyze run --days 30 --output report.csv
    python main.py remediate run --action restart-unhealthy-pods --cluster my-cluster
"""

import typer
from commands.aws_healthcheck import app as healthcheck_app
from commands.aws_drift_detector import app as drift_app
from commands.aws_cost_analyzer import app as cost_app
from commands.aws_remediation import app as remediation_app

app = typer.Typer(
    name="aws-platform-toolkit",
    help="Production-grade CLI for AWS infrastructure operations.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

app.add_typer(healthcheck_app, name="healthcheck",  help="Run concurrent health checks across AWS services.")
app.add_typer(drift_app,       name="drift-detect", help="Detect drift between Terraform state and live AWS resources.")
app.add_typer(cost_app,        name="cost-analyze",  help="Generate per-service cost attribution reports.")
app.add_typer(remediation_app, name="remediate",     help="Automated remediation for known AWS failure modes.")

if __name__ == "__main__":
    app()
