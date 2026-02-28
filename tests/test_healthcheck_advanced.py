"""
test_healthcheck_advanced.py
============================
Advanced unit tests for aws_healthcheck.py covering edge cases and error paths
to reach maximum code coverage.
"""

from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from commands.aws_healthcheck import (
    HealthStatus,
    check_eks,
    check_elasticache,
    check_rds,
    check_sqs,
)

REGION = "us-east-1"

# ── EKS Advanced Tests ────────────────────────────────────────────────────────


@patch("commands.aws_healthcheck.boto3.client")
def test_eks_nodegroup_health_states(mock_client):
    """Test EKS nodegroup health logic: DEGRADED and FAILED states."""
    mock_eks = MagicMock()
    mock_client.return_value = mock_eks

    # 1. Mock list_clusters
    mock_eks.list_clusters.return_value = {"clusters": ["prod-cluster"]}

    # 2. Mock describe_cluster (ACTIVE)
    mock_eks.describe_cluster.return_value = {
        "cluster": {"name": "prod-cluster", "status": "ACTIVE", "version": "1.28"}
    }

    # 3. Mock list_nodegroups
    mock_eks.list_nodegroups.return_value = {"nodegroups": ["ng-degraded", "ng-failed"]}

    # 4. Mock describe_nodegroup side effects
    def describe_ng(clusterName, nodegroupName):  # noqa: N803
        if nodegroupName == "ng-degraded":
            return {"nodegroup": {"status": "DEGRADED"}}
        return {"nodegroup": {"status": "CREATE_FAILED"}}

    mock_eks.describe_nodegroup.side_effect = describe_ng

    results = check_eks(REGION)
    assert results[0].status == HealthStatus.UNHEALTHY
    assert "ng-failed" in results[0].message


@patch("commands.aws_healthcheck.boto3.client")
def test_eks_nodegroup_degraded_only(mock_client):
    """Test EKS nodegroup health logic: DEGRADED only."""
    mock_eks = MagicMock()
    mock_client.return_value = mock_eks
    mock_eks.list_clusters.return_value = {"clusters": ["prod-cluster"]}
    mock_eks.describe_cluster.return_value = {
        "cluster": {"name": "prod-cluster", "status": "ACTIVE", "version": "1.28"}
    }
    mock_eks.list_nodegroups.return_value = {"nodegroups": ["ng-degraded"]}
    mock_eks.describe_nodegroup.return_value = {"nodegroup": {"status": "DEGRADED"}}

    results = check_eks(REGION)
    assert results[0].status == HealthStatus.DEGRADED
    assert "degraded" in results[0].message.lower()


@patch("commands.aws_healthcheck.boto3.client")
def test_eks_inactive_cluster_is_unhealthy(mock_client):
    """Test EKS cluster in non-ACTIVE state."""
    mock_eks = MagicMock()
    mock_client.return_value = mock_eks
    mock_eks.list_clusters.return_value = {"clusters": ["creating-cluster"]}
    mock_eks.describe_cluster.return_value = {
        "cluster": {"name": "creating-cluster", "status": "CREATING"}
    }

    results = check_eks(REGION)
    assert results[0].status == HealthStatus.UNHEALTHY
    assert "CREATING" in results[0].message


# ── RDS Advanced Tests ────────────────────────────────────────────────────────


@mock_aws
def test_rds_single_az_is_healthy_but_noted():
    """Test RDS instance with Multi-AZ disabled."""
    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="single-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MultiAZ=False,
        AllocatedStorage=20,
    )

    results = check_rds(REGION)
    db_result = next(r for r in results if r.resource == "single-db")
    assert db_result.status == HealthStatus.HEALTHY
    assert db_result.details["multi_az"] is False


@mock_aws
def test_rds_degraded_status():
    """Test RDS instance in DEGRADED status."""
    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="degraded-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
    )
    # moto doesn't easily let us change status to 'storage-full', so we patch
    with patch("commands.aws_healthcheck.boto3.client") as mock_client:
        mock_rds = MagicMock()
        mock_client.return_value = mock_rds
        mock_paginator = MagicMock()
        mock_rds.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "degraded-db",
                        "DBInstanceStatus": "storage-full",
                        "MultiAZ": False,
                        "Engine": "postgres",
                    }
                ]
            }
        ]

        results = check_rds(REGION)
        assert results[0].status == HealthStatus.DEGRADED
        assert "storage-full" in results[0].message


@patch("commands.aws_healthcheck.boto3.client")
def test_rds_describe_instances_error(mock_client):
    """Test RDS describe_db_instances catch block with BotoCoreError."""
    mock_rds = MagicMock()
    mock_client.return_value = mock_rds
    # Use BotoCoreError which is caught by the check_rds try block
    mock_rds.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "GetPaginator"
    )

    results = check_rds(REGION)
    assert results[0].status == HealthStatus.UNKNOWN
    assert "Failed to describe" in results[0].message


# ── ElastiCache Advanced Tests ──────────────────────────────────────────────


@patch("commands.aws_healthcheck.boto3.client")
def test_elasticache_unhealthy_state(mock_client):
    """Test ElastiCache replication group in UNHEALTHY status."""
    mock_ec = MagicMock()
    mock_client.return_value = mock_ec
    mock_ec.describe_replication_groups.return_value = {
        "ReplicationGroups": [
            {
                "ReplicationGroupId": "creating-rg",
                "Status": "creating",
                "AutomaticFailover": "enabled",
                "NodeGroups": [],
            }
        ]
    }
    mock_ec.describe_cache_clusters.return_value = {"CacheClusters": []}

    results = check_elasticache(REGION)
    assert results[0].status == HealthStatus.UNHEALTHY
    assert "creating" in results[0].message


@patch("commands.aws_healthcheck.boto3.client")
def test_elasticache_memcached_health(mock_client):
    """Test Memcached cluster health logic."""
    mock_ec = MagicMock()
    mock_client.return_value = mock_ec
    mock_ec.describe_replication_groups.return_value = {"ReplicationGroups": []}
    mock_ec.describe_cache_clusters.return_value = {
        "CacheClusters": [
            {
                "CacheClusterId": "mem-cluster",
                "Engine": "memcached",
                "CacheClusterStatus": "available",
                "NumCacheNodes": 2,
                "CacheNodes": [
                    {"CacheNodeId": "001", "CacheNodeStatus": "available"},
                    {"CacheNodeId": "002", "CacheNodeStatus": "incompatible-network"},
                ],
            }
        ]
    }

    results = check_elasticache(REGION)
    mem_result = next(r for r in results if r.resource == "mem-cluster")
    assert mem_result.status == HealthStatus.DEGRADED
    assert "002" in mem_result.message


# ── SQS Advanced Tests ────────────────────────────────────────────────────────


@patch("commands.aws_healthcheck.boto3.client")
def test_sqs_get_attributes_error(mock_client):
    """Test SQS get_queue_attributes ClientError."""
    mock_sqs = MagicMock()
    mock_sqs.list_queues.return_value = {"QueueUrls": ["http://sqs.us-east-1/my-q"]}
    mock_sqs.get_queue_attributes.side_effect = ClientError(
        {"Error": {"Code": "NonExistentQueue", "Message": "Queue not found"}}, "GetQueueAttributes"
    )
    mock_client.return_value = mock_sqs

    results = check_sqs(REGION)
    assert results[0].status == HealthStatus.UNKNOWN
    assert "API error" in results[0].message
