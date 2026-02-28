"""
test_healthcheck.py
===================
Unit tests for aws_healthcheck.py using moto to mock all AWS API calls.
"""

import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from datetime import datetime, timezone

from commands.aws_healthcheck import (
    HealthStatus,
    check_eks,
    check_rds,
    check_elasticache,
    check_sqs,
    run_checks,
)

REGION = "us-east-1"


# ── ElastiCache tests ─────────────────────────────────────────────────────────

@mock_aws
def test_elasticache_no_clusters_returns_unknown():
    results = check_elasticache(REGION)
    assert len(results) == 1
    assert results[0].status == HealthStatus.UNKNOWN


@mock_aws
def test_elasticache_available_rg_is_healthy():
    ec = boto3.client("elasticache", region_name=REGION)
    ec.create_replication_group(
        ReplicationGroupId="test-rg",
        ReplicationGroupDescription="test description",
    )
    results = check_elasticache(REGION)
    rg_result = next(r for r in results if r.resource == "test-rg")
    assert rg_result.status == HealthStatus.HEALTHY


# ── EKS tests ─────────────────────────────────────────────────────────────────

@mock_aws
def test_eks_no_clusters_returns_unknown():
    results = check_eks(REGION)
    assert len(results) == 1
    assert results[0].status == HealthStatus.UNKNOWN
    assert "no eks clusters" in results[0].message.lower()


@mock_aws
def test_eks_active_cluster_is_healthy():
    eks = boto3.client("eks", region_name=REGION)
    eks.create_cluster(
        name="test-cluster",
        version="1.28",
        roleArn="arn:aws:iam::123456789012:role/eks-role",
        resourcesVpcConfig={
            "subnetIds": ["subnet-12345"],
            "securityGroupIds": [],
        },
    )
    results = check_eks(REGION)
    assert len(results) == 1
    assert results[0].resource == "test-cluster"
    assert results[0].status == HealthStatus.HEALTHY
    assert results[0].service == "EKS"


@mock_aws
def test_eks_multiple_clusters():
    eks = boto3.client("eks", region_name=REGION)
    for name in ["cluster-a", "cluster-b"]:
        eks.create_cluster(
            name=name,
            version="1.28",
            roleArn="arn:aws:iam::123456789012:role/eks-role",
            resourcesVpcConfig={"subnetIds": ["subnet-12345"], "securityGroupIds": []},
        )
    results = check_eks(REGION)
    assert len(results) == 2
    assert all(r.status == HealthStatus.HEALTHY for r in results)


# ── RDS tests ─────────────────────────────────────────────────────────────────

@mock_aws
def test_rds_no_instances_returns_unknown():
    results = check_rds(REGION)
    assert len(results) == 1
    assert results[0].status == HealthStatus.UNKNOWN
    assert "no rds" in results[0].message.lower()


@mock_aws
def test_rds_available_instance_is_healthy():
    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="test-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
    )
    results = check_rds(REGION)
    assert len(results) >= 1
    db_result = next(r for r in results if r.resource == "test-db")
    assert db_result.service == "RDS"
    assert db_result.status == HealthStatus.HEALTHY


@mock_aws
def test_rds_result_has_details():
    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="detail-db",
        DBInstanceClass="db.t3.small",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
        MultiAZ=True,
    )
    results = check_rds(REGION)
    db_result = next(r for r in results if r.resource == "detail-db")
    assert "engine" in db_result.details
    assert db_result.details["multi_az"] is True


# ── SQS tests ─────────────────────────────────────────────────────────────────

@mock_aws
def test_sqs_no_queues_returns_unknown():
    results = check_sqs(REGION)
    assert len(results) == 1
    assert results[0].status == HealthStatus.UNKNOWN


@mock_aws
def test_sqs_empty_queue_is_healthy():
    sqs = boto3.client("sqs", region_name=REGION)
    sqs.create_queue(QueueName="my-queue")
    results = check_sqs(REGION)
    queue_result = next(r for r in results if "my-queue" in r.resource)
    assert queue_result.status == HealthStatus.HEALTHY
    assert queue_result.details["visible"] == 0


@mock_aws
def test_sqs_deep_queue_is_degraded():
    sqs = boto3.client("sqs", region_name=REGION)
    queue_url = sqs.create_queue(QueueName="deep-queue")["QueueUrl"]
    for i in range(5):
        sqs.send_message(QueueUrl=queue_url, MessageBody=f"msg-{i}")
    results = check_sqs(REGION, depth_threshold=3)
    queue_result = next(r for r in results if "deep-queue" in r.resource)
    assert queue_result.status == HealthStatus.DEGRADED


@mock_aws
def test_sqs_dlq_with_messages_is_unhealthy():
    sqs = boto3.client("sqs", region_name=REGION)
    dlq_url = sqs.create_queue(QueueName="my-service-dlq")["QueueUrl"]
    sqs.send_message(QueueUrl=dlq_url, MessageBody="failed-message")
    results = check_sqs(REGION, dlq_threshold=1)
    dlq_result = next(r for r in results if "dlq" in r.resource.lower())
    assert dlq_result.status == HealthStatus.UNHEALTHY
    assert dlq_result.details["is_dlq"] is True


@mock_aws
def test_sqs_multiple_queues():
    sqs = boto3.client("sqs", region_name=REGION)
    for name in ["queue-a", "queue-b", "queue-c"]:
        sqs.create_queue(QueueName=name)
    results = check_sqs(REGION)
    assert len(results) == 3
    assert all(r.status == HealthStatus.HEALTHY for r in results)


# ── Concurrent orchestrator tests ─────────────────────────────────────────────

@mock_aws
def test_run_checks_concurrent_returns_all_services():
    """Verify concurrent execution returns results for all requested services."""
    report = run_checks(["eks", "rds", "sqs"], REGION)
    services_in_report = {r.service for r in report.checks}
    assert "EKS" in services_in_report
    assert "RDS" in services_in_report
    assert "SQS" in services_in_report


@mock_aws
def test_run_checks_overall_healthy_when_all_healthy():
    report = run_checks(["sqs"], REGION)
    assert report.overall_status in (HealthStatus.HEALTHY, HealthStatus.UNKNOWN)


@mock_aws
def test_run_checks_overall_unhealthy_when_dlq_has_messages():
    sqs = boto3.client("sqs", region_name=REGION)
    dlq_url = sqs.create_queue(QueueName="critical-dlq")["QueueUrl"]
    sqs.send_message(QueueUrl=dlq_url, MessageBody="error")
    report = run_checks(["sqs"], REGION, dlq_threshold=1)
    assert report.overall_status == HealthStatus.UNHEALTHY


@mock_aws
def test_run_checks_invalid_service_excluded():
    report = run_checks(["sqs", "unknown_service"], REGION)
    services = {r.service for r in report.checks}
    assert "UNKNOWN_SERVICE" not in services


@mock_aws
def test_run_checks_duration_recorded():
    report = run_checks(["sqs"], REGION)
    assert report.duration_seconds >= 0.0


# ── Model tests ───────────────────────────────────────────────────────────────

def test_health_status_values():
    assert HealthStatus.HEALTHY == "HEALTHY"
    assert HealthStatus.UNHEALTHY == "UNHEALTHY"


def test_health_report_overall_unhealthy_if_any_unhealthy():
    from commands.aws_healthcheck import HealthReport, ServiceHealth
    h1 = ServiceHealth("S1", "R1", HealthStatus.HEALTHY, "ok", "us-east-1", datetime.now(timezone.utc).isoformat(), {})
    h2 = ServiceHealth("S2", "R2", HealthStatus.UNHEALTHY, "err", "us-east-1", datetime.now(timezone.utc).isoformat(), {})
    report = HealthReport(total=2, healthy=1, degraded=0, unhealthy=1, unknown=0, duration_seconds=0.1, checks=[h1, h2])
    assert report.overall_status == HealthStatus.UNHEALTHY


def test_health_report_overall_degraded_if_no_unhealthy():
    from commands.aws_healthcheck import HealthReport, ServiceHealth
    h1 = ServiceHealth("S1", "R1", HealthStatus.HEALTHY, "ok", "us-east-1", datetime.now(timezone.utc).isoformat(), {})
    h2 = ServiceHealth("S2", "R2", HealthStatus.DEGRADED, "warn", "us-east-1", datetime.now(timezone.utc).isoformat(), {})
    report = HealthReport(total=2, healthy=1, degraded=1, unhealthy=0, unknown=0, duration_seconds=0.1, checks=[h1, h2])
    assert report.overall_status == HealthStatus.DEGRADED


def test_health_report_overall_healthy_when_all_healthy():
    from commands.aws_healthcheck import HealthReport, ServiceHealth
    h1 = ServiceHealth("S1", "R1", HealthStatus.HEALTHY, "ok", "us-east-1", datetime.now(timezone.utc).isoformat(), {})
    report = HealthReport(total=1, healthy=1, degraded=0, unhealthy=0, unknown=0, duration_seconds=0.1, checks=[h1])
    assert report.overall_status == HealthStatus.HEALTHY
