"""
test_cost_analyzer.py
=====================
Unit tests for aws_cost_analyzer.py using moto to mock Cost Explorer.
"""

from moto import mock_aws

from commands.aws_cost_analyzer import (
    CostReport,
    ServiceCost,
    _date_range,
    _parse_results,
    build_report,
)


def test_date_range_returns_correct_strings():
    start, end = _date_range(30)
    # Check YYYY-MM-DD format
    assert len(start) == 10
    assert len(end) == 10
    assert start < end


def test_parse_results_aggregates_costs():
    results = [
        {
            "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
            "Groups": [
                {
                    "Keys": ["Amazon EC2"],
                    "Metrics": {"UnblendedCost": {"Amount": "100.50", "Unit": "USD"}},
                },
                {
                    "Keys": ["Amazon S3"],
                    "Metrics": {"UnblendedCost": {"Amount": "50.25", "Unit": "USD"}},
                },
            ],
        }
    ]
    totals = _parse_results(results)
    assert totals["Amazon EC2"] == 100.50
    assert totals["Amazon S3"] == 50.25


def test_service_cost_anomaly_detection():
    # >20% change = anomaly
    sc = ServiceCost(
        service="EC2",
        amount_usd=120,
        unit="USD",
        period_start="S",
        period_end="E",
        prev_amount_usd=100,
        change_pct=20.0,
    )
    assert sc.is_anomaly is False  # Exactly 20 is not > 20

    sc.change_pct = 20.1
    assert sc.is_anomaly is True

    sc.change_pct = -21.0
    assert sc.is_anomaly is True


@mock_aws
def test_build_report_handles_empty_results():
    # moto-ce doesn't return data by default, so it should return a report with 0 total
    report = build_report(days=7)
    assert report.total_usd == 0
    assert len(report.services) == 0


def test_cost_report_structure():
    report = CostReport(
        period_start="2024-01-01",
        period_end="2024-01-08",
        total_usd=150.75,
        prev_total_usd=100.00,
        total_change_pct=50.75,
        currency="USD",
        services=[
            ServiceCost("EC2", 100.0, "USD", "S", "E", 66.3, 80.0, 25.0),
            ServiceCost("S3", 50.75, "USD", "S", "E", 33.7, 20.0, 153.75),
        ],
        anomalies=[],
    )
    assert report.total_usd == 150.75
    assert len(report.services) == 2
    assert report.total_change_pct == 50.75


def test_cost_to_csv():
    report = CostReport(
        period_start="2024-01-01",
        period_end="2024-01-02",
        total_usd=100.0,
        prev_total_usd=None,
        total_change_pct=None,
        currency="USD",
        services=[ServiceCost("EC2", 100.0, "USD", "S", "E", 100.0, None, None)],
    )
    from commands.aws_cost_analyzer import to_csv

    csv_data = to_csv(report)
    assert "EC2,100.0,100.0" in csv_data


def test_print_cost_table(capsys):
    from commands.aws_cost_analyzer import print_cost_table

    report = CostReport(
        period_start="2024-01-01",
        period_end="2024-01-02",
        total_usd=100.0,
        prev_total_usd=None,
        total_change_pct=None,
        currency="USD",
        services=[ServiceCost("EC2", 100.0, "USD", "S", "E", 100.0, None, None)],
    )
    print_cost_table(report)
    captured = capsys.readouterr()
    assert "Total AWS spend" in captured.out
    assert "EC2" in captured.out
