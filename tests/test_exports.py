"""
test_exports.py
===============
Focused tests for export and printing functions to increase coverage.
"""

from commands.aws_healthcheck import HealthReport, ServiceHealth, HealthStatus
from commands.aws_remediation import RemediationReport, RemediationAction, RemediationStatus
from commands.aws_cost_analyzer import CostReport, ServiceCost
from commands.aws_drift_detector import ResourceDrift, DriftType, DriftReport, AttributeDiff
import json
import csv
from io import StringIO
from datetime import datetime, timezone

def test_health_report_outputs():
    report = HealthReport(
        total=1, healthy=1, degraded=0, unhealthy=0, unknown=0,
        duration_seconds=0.5, checks=[]
    )
    assert report.overall_status == HealthStatus.HEALTHY


def test_remediation_report_outputs():
    action = RemediationAction("test", "target", RemediationStatus.SUCCESS, "msg")
    report = RemediationReport("test", False, 1, 1, 0, 0, [action])
    assert report.succeeded == 1


def test_cost_analyzer_exports():
    from commands.aws_cost_analyzer import to_csv, print_cost_table
    sc = ServiceCost("EC2", 10.0, "USD", "S", "E", 100.0, 5.0, 100.0)
    report = CostReport("S", "E", 10.0, 5.0, 100.0, "USD", [sc], [])
    
    # CSV
    csv_out = to_csv(report)
    assert "EC2,10.0" in csv_out
    
    # Table (just verify it runs)
    print_cost_table(report)


def test_drift_detector_outputs():
    from commands.aws_drift_detector import print_drift_table
    diff = AttributeDiff("versioning", "Enabled", "Disabled")
    drift = ResourceDrift("aws_s3_bucket", "id", "addr", DriftType.MODIFIED, [diff])
    report = DriftReport(
        tfstate_source="local",
        checked_at=datetime.now(timezone.utc).isoformat(),
        total_resources=1, drifted=1, missing=0, clean=0,
        drifts=[drift]
    )
    # Just ensure the logic for printing doesn't crash
    print_drift_table(report)
