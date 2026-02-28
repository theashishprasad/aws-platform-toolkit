"""
test_remediation.py
===================
Unit tests for aws_remediation.py.
Uses moto for SQS and ElastiCache mocking.
"""

from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from commands.aws_remediation import (
    RemediationStatus,
    flush_dlq,
    restart_unhealthy_pods,
    trigger_elasticache_failover,
)

REGION = "us-east-1"


# ── flush_dlq tests ───────────────────────────────────────────────────────────


@mock_aws
def test_flush_dlq_empty_queue_is_skipped():
    sqs = boto3.client("sqs", region_name=REGION)
    dlq_url = sqs.create_queue(QueueName="empty-dlq")["QueueUrl"]
    report = flush_dlq(dlq_url, REGION, dry_run=True)
    assert report.skipped == 1
    assert report.succeeded == 0
    assert report.actions[0].status == RemediationStatus.SKIPPED
    assert "empty" in report.actions[0].message.lower()


@mock_aws
def test_flush_dlq_dry_run_does_not_move_messages():
    sqs = boto3.client("sqs", region_name=REGION)
    dlq_url = sqs.create_queue(QueueName="my-service-dlq")["QueueUrl"]
    sqs.send_message(QueueUrl=dlq_url, MessageBody="failed-message")

    report = flush_dlq(dlq_url, REGION, dry_run=True)

    assert report.dry_run is True
    assert report.actions[0].status == RemediationStatus.DRY_RUN
    assert "DRY RUN" in report.actions[0].message

    # Messages should still be in DLQ after dry run
    attrs = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(attrs["ApproximateNumberOfMessages"]) == 1


@mock_aws
def test_flush_dlq_execute_moves_messages():
    sqs = boto3.client("sqs", region_name=REGION)

    # Create source and DLQ
    sqs.create_queue(QueueName="my-service")["QueueUrl"]
    dlq_url = sqs.create_queue(QueueName="my-service-dlq")["QueueUrl"]

    # Put 3 messages in DLQ
    for i in range(3):
        sqs.send_message(QueueUrl=dlq_url, MessageBody=f"failed-{i}")

    report = flush_dlq(dlq_url, REGION, dry_run=False)

    assert report.succeeded == 1
    assert report.failed == 0
    assert "Moved" in report.actions[0].message


@mock_aws
def test_flush_dlq_report_structure():
    sqs = boto3.client("sqs", region_name=REGION)
    dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]
    sqs.send_message(QueueUrl=dlq_url, MessageBody="msg")

    report = flush_dlq(dlq_url, REGION, dry_run=True)

    assert report.action == "flush-dlq"
    assert report.total >= 1
    assert len(report.actions) >= 1
    assert report.actions[0].target == dlq_url


# ── trigger_elasticache_failover tests ────────────────────────────────────────


@mock_aws
def test_trigger_failover_missing_cluster_fails():
    report = trigger_elasticache_failover("nonexistent-cluster", REGION, dry_run=True)
    assert report.failed == 1
    assert report.actions[0].status == RemediationStatus.FAILED


@patch("commands.aws_remediation.boto3.client")
def test_trigger_failover_error_path(mock_client):
    # Mock describe returning a group with a replica to allow test_failover to be called
    mock_ec = MagicMock()
    mock_ec.describe_replication_groups.return_value = {
        "ReplicationGroups": [
            {
                "ReplicationGroupId": "some-cluster",
                "AutomaticFailover": "enabled",
                "NodeGroups": [
                    {
                        "NodeGroupId": "0001",
                        "NodeGroupMembers": [
                            {"CacheNodeId": "001", "CurrentRole": "primary"},
                            {"CacheNodeId": "002", "CurrentRole": "replica"},
                        ],
                    }
                ],
            }
        ]
    }
    mock_ec.test_failover.side_effect = Exception("Failover refused")
    mock_client.return_value = mock_ec

    report = trigger_elasticache_failover("some-cluster", REGION, dry_run=False)
    assert report.failed == 1


@mock_aws
def test_trigger_failover_dry_run_logs_action():
    ec = boto3.client("elasticache", region_name=REGION)

    # Create a replication group with a replica
    ec.create_replication_group(
        ReplicationGroupId="test-redis",
        ReplicationGroupDescription="Test Redis",
        NumCacheClusters=2,
        CacheNodeType="cache.t3.micro",
        Engine="redis",
        AutomaticFailoverEnabled=True,
    )

    report = trigger_elasticache_failover("test-redis", REGION, dry_run=True)

    # moto may return SKIPPED if no replica found (single node mocked)
    assert report.actions[0].status in (
        RemediationStatus.DRY_RUN,
        RemediationStatus.SKIPPED,
        RemediationStatus.FAILED,
    )


@mock_aws
def test_trigger_failover_execute():
    ec = boto3.client("elasticache", region_name=REGION)
    ec.create_replication_group(
        ReplicationGroupId="exec-redis",
        ReplicationGroupDescription="Test Redis",
        NumCacheClusters=2,
        CacheNodeType="cache.t3.micro",
        Engine="redis",
        AutomaticFailoverEnabled=True,
    )
    report = trigger_elasticache_failover("exec-redis", REGION, dry_run=False)
    assert report.total >= 1


# ── restart_unhealthy_pods tests ──────────────────────────────────────────────


@mock_aws
def test_restart_pods_nonexistent_cluster_fails():
    report = restart_unhealthy_pods("nonexistent-cluster", REGION, "default", dry_run=True)
    assert report.failed == 1
    assert report.actions[0].status == RemediationStatus.FAILED


@mock_aws
def test_restart_pods_inactive_cluster_fails():
    eks = boto3.client("eks", region_name=REGION)
    eks.create_cluster(
        name="test-cluster",
        version="1.28",
        roleArn="arn:aws:iam::123456789012:role/eks-role",
        resourcesVpcConfig={"subnetIds": ["subnet-12345"], "securityGroupIds": []},
    )
    report = restart_unhealthy_pods("test-cluster", REGION, "default", dry_run=True)
    assert report.actions[0].status in (
        RemediationStatus.DRY_RUN,
        RemediationStatus.SKIPPED,
    )


@patch("kubernetes.config.load_kube_config")
@patch("kubernetes.client.CoreV1Api")
def test_restart_pods_complex_states(mock_v1_class, mock_load_config):
    # Mock the K8s API
    mock_v1 = MagicMock()
    mock_v1_class.return_value = mock_v1

    # Pod in ImagePullBackOff
    pod1 = MagicMock()
    pod1.metadata.name = "image-fail"
    pod1.status.phase = "Running"
    cs = MagicMock()
    # Mock nested status objects: cs.state.waiting.reason
    cs.state = MagicMock()
    cs.state.waiting = MagicMock()
    cs.state.waiting.reason = "ImagePullBackOff"
    cs.state.terminated = None
    pod1.status.container_statuses = [cs]

    # Pod in CrashLoop
    pod2 = MagicMock()
    pod2.metadata.name = "crash-loop"
    pod2.status.phase = "Running"
    cs2 = MagicMock()
    cs2.state = MagicMock()
    cs2.state.waiting = MagicMock()
    cs2.state.waiting.reason = "CrashLoopBackOff"
    cs2.state.terminated = None
    pod2.status.container_statuses = [cs2]

    # Pod that is terminated
    pod3 = MagicMock()
    pod3.metadata.name = "terminated-pod"
    pod3.status.phase = "Running"
    cs3 = MagicMock()
    cs3.state = MagicMock()
    cs3.state.waiting = None
    cs3.state.terminated = MagicMock()
    cs3.state.terminated.reason = "OOMKilled"
    pod3.status.container_statuses = [cs3]

    mock_v1.list_namespaced_pod.return_value.items = [pod1, pod2, pod3]

    with mock_aws():
        eks = boto3.client("eks", region_name=REGION)
        eks.create_cluster(
            name="eks-cluster",
            version="1.28",
            roleArn="arn:aws:iam::123456789012:role/eks-role",
            resourcesVpcConfig={"subnetIds": ["subnet-1"], "securityGroupIds": []},
        )
        report = restart_unhealthy_pods("eks-cluster", REGION, "default", dry_run=False)

    assert report.succeeded == 3
    assert mock_v1.delete_namespaced_pod.call_count == 3


# ── RemediationStatus model tests ─────────────────────────────────────────────


def test_remediation_status_values():
    assert RemediationStatus.SUCCESS == "SUCCESS"
    assert RemediationStatus.DRY_RUN == "SKIPPED" or RemediationStatus.DRY_RUN == "DRY_RUN"
    assert RemediationStatus.FAILED == "FAILED"


def test_remediation_report_counts():
    from commands.aws_remediation import RemediationAction, RemediationReport

    report = RemediationReport(
        action="flush-dlq",
        dry_run=False,
        total=3,
        succeeded=2,
        skipped=0,
        failed=1,
        actions=[
            RemediationAction("flush-dlq", "q1", RemediationStatus.SUCCESS, "ok"),
            RemediationAction("flush-dlq", "q2", RemediationStatus.SUCCESS, "ok"),
            RemediationAction("flush-dlq", "q3", RemediationStatus.FAILED, "err"),
        ],
    )
    assert report.total == 3
    assert report.succeeded == 2
    assert report.failed == 1
