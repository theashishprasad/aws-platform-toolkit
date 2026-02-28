"""
test_cli.py
===========
Integration tests for the CLI entry point using typer CliRunner.
Mocks the underlying command implementations to focus on CLI wiring.
"""

from typer.testing import CliRunner
from main import app
from unittest.mock import patch, MagicMock
from commands.aws_healthcheck import HealthReport, HealthStatus

runner = CliRunner()

@patch("commands.aws_healthcheck.run_checks")
def test_healthcheck_cli_success(mock_run):
    # Mock a healthy report
    mock_run.return_value = HealthReport(
        total=1, healthy=1, degraded=0, unhealthy=0, unknown=0,
        duration_seconds=1.0, checks=[]
    )
    
    result = runner.invoke(app, ["healthcheck", "run", "--services", "sqs"])
    assert result.exit_code == 0
    assert "Running health checks" in result.stdout
    assert "Overall: HEALTHY" in result.stdout


@patch("commands.aws_healthcheck.run_checks")
def test_healthcheck_cli_fail_on_unhealthy(mock_run):
    # Mock an unhealthy report
    mock_run.return_value = HealthReport(
        total=1, healthy=0, degraded=0, unhealthy=1, unknown=0,
        duration_seconds=1.0, checks=[]
    )
    
    result = runner.invoke(app, ["healthcheck", "run", "--fail-on-unhealthy"])
    assert result.exit_code == 1
    assert "Overall: UNHEALTHY" in result.stdout


@patch("commands.aws_drift_detector.load_tfstate")
@patch("commands.aws_drift_detector.extract_resources")
@patch("commands.aws_drift_detector.compare_resource")
def test_drift_detect_cli_no_drift(mock_compare, mock_extract, mock_load):
    mock_load.return_value = {"version": 4}
    mock_extract.return_value = [{"type": "aws_s3_bucket", "address": "s3.x", "attributes": {}}]
    mock_compare.return_value = (False, MagicMock(drift_type="MODIFIED")) # MODIFIED but not drifted bit
    
    # Actually mock_compare returns (is_drifted, ResourceDrift)
    # Let's be more precise
    from commands.aws_drift_detector import ResourceDrift, DriftType
    mock_compare.return_value = (False, ResourceDrift("aws_s3_bucket", "id", "s3.x", DriftType.MODIFIED))

    result = runner.invoke(app, ["drift-detect", "run", "--tfstate", "fake.tfstate"])
    assert result.exit_code == 0
    assert "Scanning for drift" in result.stdout
    assert "No drift detected" in result.stdout


@patch("commands.aws_cost_analyzer.build_report")
def test_cost_analyze_cli(mock_build):
    from commands.aws_cost_analyzer import CostReport
    mock_build.return_value = CostReport(
        period_start="2024-01-01", period_end="2024-01-02",
        total_usd=100.0, prev_total_usd=90.0, total_change_pct=11.1,
        currency="USD", services=[], anomalies=[]
    )
    
    result = runner.invoke(app, ["cost-analyze", "run", "--days", "7"])
    assert result.exit_code == 0
    assert "Fetching AWS cost data" in result.stdout
    assert "Total AWS spend: $100.00" in result.stdout


@patch("commands.aws_remediation.restart_unhealthy_pods")
def test_remediate_cli(mock_restart):
    from commands.aws_remediation import RemediationReport
    mock_restart.return_value = RemediationReport(
        action="restart-unhealthy-pods", dry_run=True,
        total=0, succeeded=0, skipped=0, failed=0, actions=[]
    )
    
    result = runner.invoke(app, ["remediate", "run", "--action", "restart-unhealthy-pods", "--cluster", "my-cluster"])
    assert result.exit_code == 0
    assert "DRY RUN MODE" in result.stdout
