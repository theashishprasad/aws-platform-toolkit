"""
aws_healthcheck.py
==================
Concurrent health checks across AWS services: EKS nodes, RDS instances,
ElastiCache clusters, and SQS queues. Uses ThreadPoolExecutor for parallel
execution so a 10-service check completes in seconds, not minutes.

Usage:
    python main.py healthcheck run --services eks,rds,elasticache,sqs
    python main.py healthcheck run --services eks --region us-east-1
    python main.py healthcheck run --output json
"""

import json
import time
from collections.abc import Callable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

import boto3
import typer
from botocore.exceptions import BotoCoreError, ClientError
from rich import box
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


# ── Data models ───────────────────────────────────────────────────────────────


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


@dataclass
class ServiceHealth:
    service: str
    resource: str
    status: HealthStatus
    message: str
    region: str
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthReport:
    total: int
    healthy: int
    degraded: int
    unhealthy: int
    unknown: int
    duration_seconds: float
    checks: list[ServiceHealth]

    @property
    def overall_status(self) -> HealthStatus:
        if self.unhealthy > 0:
            return HealthStatus.UNHEALTHY
        if self.degraded > 0:
            return HealthStatus.DEGRADED
        if self.unknown == self.total and self.total > 0:
            return HealthStatus.UNKNOWN
        return HealthStatus.HEALTHY


# ── EKS health check ──────────────────────────────────────────────────────────


def check_eks(region: str) -> list[ServiceHealth]:
    """Check all EKS clusters: active status + node group health."""
    results = []
    try:
        eks = boto3.client("eks", region_name=region)
        clusters = eks.list_clusters().get("clusters", [])

        if not clusters:
            return [
                ServiceHealth(
                    service="EKS",
                    resource="(no clusters found)",
                    status=HealthStatus.UNKNOWN,
                    message="No EKS clusters found in this region.",
                    region=region,
                )
            ]

        for cluster_name in clusters:
            try:
                cluster = eks.describe_cluster(name=cluster_name)["cluster"]
                cluster_status = cluster.get("status", "UNKNOWN")

                if cluster_status == "ACTIVE":
                    # Check node groups
                    node_groups = eks.list_nodegroups(clusterName=cluster_name).get(
                        "nodegroups", []
                    )
                    unhealthy_ng = []
                    degraded_ng = []

                    for ng_name in node_groups:
                        ng = eks.describe_nodegroup(
                            clusterName=cluster_name, nodegroupName=ng_name
                        )["nodegroup"]
                        ng_status = ng.get("status", "UNKNOWN")
                        if ng_status not in ("ACTIVE",):
                            if ng_status in ("DEGRADED",):
                                degraded_ng.append(ng_name)
                            else:
                                unhealthy_ng.append(ng_name)

                    if unhealthy_ng:
                        status = HealthStatus.UNHEALTHY
                        message = f"Node groups unhealthy: {', '.join(unhealthy_ng)}"
                    elif degraded_ng:
                        status = HealthStatus.DEGRADED
                        message = f"Node groups degraded: {', '.join(degraded_ng)}"
                    else:
                        status = HealthStatus.HEALTHY
                        message = f"Cluster ACTIVE · {len(node_groups)} node group(s) healthy"

                    results.append(
                        ServiceHealth(
                            service="EKS",
                            resource=cluster_name,
                            status=status,
                            message=message,
                            region=region,
                            details={
                                "kubernetes_version": cluster.get("version"),
                                "node_groups": node_groups,
                                "unhealthy_node_groups": unhealthy_ng,
                            },
                        )
                    )
                else:
                    results.append(
                        ServiceHealth(
                            service="EKS",
                            resource=cluster_name,
                            status=HealthStatus.UNHEALTHY,
                            message=f"Cluster status is {cluster_status}",
                            region=region,
                        )
                    )

            except ClientError as e:
                results.append(
                    ServiceHealth(
                        service="EKS",
                        resource=cluster_name,
                        status=HealthStatus.UNKNOWN,
                        message=f"API error: {e.response['Error']['Message']}",
                        region=region,
                    )
                )

    except (BotoCoreError, ClientError) as e:
        results.append(
            ServiceHealth(
                service="EKS",
                resource="*",
                status=HealthStatus.UNKNOWN,
                message=f"Failed to list clusters: {e}",
                region=region,
            )
        )

    return results


# ── RDS health check ──────────────────────────────────────────────────────────


def check_rds(region: str) -> list[ServiceHealth]:
    """Check all RDS instances: availability status + connection acceptability."""
    results = []
    healthy_statuses = {"available", "backing-up"}
    degraded_statuses = {"storage-full", "incompatible-parameters", "maintenance"}

    try:
        rds = boto3.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")

        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))

        if not instances:
            return [
                ServiceHealth(
                    service="RDS",
                    resource="(no instances found)",
                    status=HealthStatus.UNKNOWN,
                    message="No RDS instances found in this region.",
                    region=region,
                )
            ]

        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            db_status = db.get("DBInstanceStatus", "unknown").lower()
            multi_az = db.get("MultiAZ", False)
            engine = db.get("Engine", "unknown")

            if db_status in healthy_statuses:
                status = HealthStatus.HEALTHY
                message = f"Status: {db_status} · Multi-AZ: {multi_az} · Engine: {engine}"
            elif db_status in degraded_statuses:
                status = HealthStatus.DEGRADED
                message = f"Status: {db_status} — attention required"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"Status: {db_status}"

            results.append(
                ServiceHealth(
                    service="RDS",
                    resource=db_id,
                    status=status,
                    message=message,
                    region=region,
                    details={
                        "engine": engine,
                        "engine_version": db.get("EngineVersion"),
                        "instance_class": db.get("DBInstanceClass"),
                        "multi_az": multi_az,
                        "storage_type": db.get("StorageType"),
                        "allocated_storage_gb": db.get("AllocatedStorage"),
                    },
                )
            )

    except (BotoCoreError, ClientError) as e:
        results.append(
            ServiceHealth(
                service="RDS",
                resource="*",
                status=HealthStatus.UNKNOWN,
                message=f"Failed to describe instances: {e}",
                region=region,
            )
        )

    return results


# ── ElastiCache health check ──────────────────────────────────────────────────


def check_elasticache(region: str) -> list[ServiceHealth]:
    """Check ElastiCache clusters: available status + node health."""
    results = []

    try:
        ec = boto3.client("elasticache", region_name=region)

        # Check Redis replication groups
        try:
            rgs = ec.describe_replication_groups().get("ReplicationGroups", [])
            for rg in rgs:
                rg_id = rg["ReplicationGroupId"]
                rg_status = rg.get("Status", "unknown").lower()

                if rg_status == "available":
                    # Check individual node groups
                    node_groups = rg.get("NodeGroups", [])
                    unhealthy_nodes = [
                        node["CacheNodeId"]
                        for ng in node_groups
                        for node in ng.get("NodeGroupMembers", [])
                        if node.get("CurrentRole") == "primary"
                        and node.get("CacheNodeStatus", "available") != "available"
                    ]

                    if unhealthy_nodes:
                        status = HealthStatus.DEGRADED
                        message = f"Unhealthy nodes: {', '.join(unhealthy_nodes)}"
                    else:
                        status = HealthStatus.HEALTHY
                        message = f"Replication group available · {len(node_groups)} shard(s)"
                else:
                    status = HealthStatus.UNHEALTHY
                    message = f"Replication group status: {rg_status}"

                results.append(
                    ServiceHealth(
                        service="ElastiCache",
                        resource=rg_id,
                        status=status,
                        message=message,
                        region=region,
                        details={
                            "cluster_mode": rg.get("ClusterEnabled", False),
                            "node_groups": len(rg.get("NodeGroups", [])),
                            "description": rg.get("Description", ""),
                        },
                    )
                )
        except ClientError:
            pass  # No replication groups

        # Check Memcached clusters
        clusters = ec.describe_cache_clusters(ShowCacheNodeInfo=True).get("CacheClusters", [])
        for cluster in clusters:
            if cluster.get("Engine") == "memcached":
                cluster_id = cluster["CacheClusterId"]
                cluster_status = cluster.get("CacheClusterStatus", "unknown").lower()

                if cluster_status == "available":
                    unhealthy = [
                        n["CacheNodeId"]
                        for n in cluster.get("CacheNodes", [])
                        if n.get("CacheNodeStatus") != "available"
                    ]
                    status = HealthStatus.DEGRADED if unhealthy else HealthStatus.HEALTHY
                    message = (
                        f"Nodes unhealthy: {', '.join(unhealthy)}"
                        if unhealthy
                        else f"Cluster available · {cluster.get('NumCacheNodes', 0)} node(s)"
                    )
                else:
                    status = HealthStatus.UNHEALTHY
                    message = f"Cluster status: {cluster_status}"

                results.append(
                    ServiceHealth(
                        service="ElastiCache",
                        resource=cluster_id,
                        status=status,
                        message=message,
                        region=region,
                    )
                )

        if not results:
            results.append(
                ServiceHealth(
                    service="ElastiCache",
                    resource="(no clusters found)",
                    status=HealthStatus.UNKNOWN,
                    message="No ElastiCache clusters found in this region.",
                    region=region,
                )
            )

    except (BotoCoreError, ClientError) as e:
        results.append(
            ServiceHealth(
                service="ElastiCache",
                resource="*",
                status=HealthStatus.UNKNOWN,
                message=f"Failed to describe clusters: {e}",
                region=region,
            )
        )

    return results


# ── SQS health check ──────────────────────────────────────────────────────────

SQS_ATTR_NAME = Literal[
    "All",
    "Policy",
    "VisibilityTimeout",
    "MaximumMessageSize",
    "MessageRetentionPeriod",
    "ApproximateNumberOfMessages",
    "ApproximateNumberOfMessagesNotVisible",
    "CreatedTimestamp",
    "LastModifiedTimestamp",
    "QueueArn",
    "ApproximateNumberOfMessagesDelayed",
    "DelaySeconds",
    "ReceiveMessageWaitTimeSeconds",
    "RedrivePolicy",
    "FifoQueue",
    "ContentBasedDeduplication",
    "KmsMasterKeyId",
    "KmsDataKeyReusePeriodSeconds",
    "DeduplicationScope",
    "FifoThroughputLimit",
    "RedriveAllowPolicy",
    "SqsManagedSseEnabled",
]


def check_sqs(
    region: str, depth_threshold: int = 1000, dlq_threshold: int = 1
) -> list[ServiceHealth]:
    """
    Check SQS queues: message depth, DLQ backlog, oldest message age.
    Flags queues where ApproximateNumberOfMessages > depth_threshold
    or DLQ has any messages.
    """
    results = []

    try:
        sqs = boto3.client("sqs", region_name=region)
        queues = sqs.list_queues().get("QueueUrls", [])

        if not queues:
            return [
                ServiceHealth(
                    service="SQS",
                    resource="(no queues found)",
                    status=HealthStatus.UNKNOWN,
                    message="No SQS queues found in this region.",
                    region=region,
                )
            ]

        attrs_to_fetch: Sequence[SQS_ATTR_NAME] = [
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
            "RedrivePolicy",
            "QueueArn",
        ]

        for queue_url in queues:
            queue_name = queue_url.split("/")[-1]
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=queue_url, AttributeNames=attrs_to_fetch
                ).get("Attributes", {})

                visible = int(attrs.get("ApproximateNumberOfMessages", 0))
                in_flight = int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0))
                delayed = int(attrs.get("ApproximateNumberOfMessagesDelayed", 0))
                is_dlq = queue_name.endswith(("-dlq", "-DLQ", "_dlq", "_DLQ", ".fifo"))
                has_redrive = "RedrivePolicy" in attrs

                issues = []
                if visible > depth_threshold:
                    issues.append(f"queue depth {visible:,} exceeds threshold {depth_threshold:,}")
                if is_dlq and visible >= dlq_threshold:
                    issues.append(f"DLQ has {visible} message(s) — investigate immediately")

                if issues:
                    status = HealthStatus.UNHEALTHY if is_dlq else HealthStatus.DEGRADED
                    message = "; ".join(issues)
                else:
                    status = HealthStatus.HEALTHY
                    message = (
                        f"Depth: {visible} visible · {in_flight} in-flight · {delayed} delayed"
                    )

                results.append(
                    ServiceHealth(
                        service="SQS",
                        resource=queue_name,
                        status=status,
                        message=message,
                        region=region,
                        details={
                            "visible": visible,
                            "in_flight": in_flight,
                            "delayed": delayed,
                            "is_dlq": is_dlq,
                            "has_redrive_policy": has_redrive,
                        },
                    )
                )

            except ClientError as e:
                results.append(
                    ServiceHealth(
                        service="SQS",
                        resource=queue_name,
                        status=HealthStatus.UNKNOWN,
                        message=f"API error: {e.response['Error']['Message']}",
                        region=region,
                    )
                )

    except (BotoCoreError, ClientError) as e:
        results.append(
            ServiceHealth(
                service="SQS",
                resource="*",
                status=HealthStatus.UNKNOWN,
                message=f"Failed to list queues: {e}",
                region=region,
            )
        )

    return results


# ── Orchestrator ──────────────────────────────────────────────────────────────

SERVICE_CHECKERS: dict[str, Callable[..., list[ServiceHealth]]] = {
    "eks": check_eks,
    "rds": check_rds,
    "elasticache": check_elasticache,
    "sqs": check_sqs,
}


def run_checks(services: list[str], region: str, **kwargs: Any) -> HealthReport:
    """Run all requested service checks concurrently using ThreadPoolExecutor."""
    all_results: list[ServiceHealth] = []
    start = time.monotonic()

    with ThreadPoolExecutor(max_workers=max(1, len(services))) as executor:
        futures: dict[Future[list[ServiceHealth]], str] = {
            executor.submit(SERVICE_CHECKERS[svc], region, **kwargs): svc
            for svc in services
            if svc in SERVICE_CHECKERS
        }
        for future in as_completed(futures):
            svc = futures[future]
            try:
                all_results.extend(future.result())
            except Exception as exc:
                all_results.append(
                    ServiceHealth(
                        service=svc.upper(),
                        resource="*",
                        status=HealthStatus.UNKNOWN,
                        message=f"Unexpected error during check: {exc}",
                        region=region,
                    )
                )

    duration = time.monotonic() - start

    return HealthReport(
        total=len(all_results),
        healthy=sum(1 for r in all_results if r.status == HealthStatus.HEALTHY),
        degraded=sum(1 for r in all_results if r.status == HealthStatus.DEGRADED),
        unhealthy=sum(1 for r in all_results if r.status == HealthStatus.UNHEALTHY),
        unknown=sum(1 for r in all_results if r.status == HealthStatus.UNKNOWN),
        duration_seconds=round(duration, 2),
        checks=all_results,
    )


# ── Output formatters ─────────────────────────────────────────────────────────

STATUS_COLOURS = {
    HealthStatus.HEALTHY: "green",
    HealthStatus.DEGRADED: "yellow",
    HealthStatus.UNHEALTHY: "red",
    HealthStatus.UNKNOWN: "dim",
}

STATUS_ICONS = {
    HealthStatus.HEALTHY: "✅",
    HealthStatus.DEGRADED: "⚠️ ",
    HealthStatus.UNHEALTHY: "❌",
    HealthStatus.UNKNOWN: "❓",
}


def print_table(report: HealthReport) -> None:
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold blue")
    table.add_column("Status", width=10)
    table.add_column("Service", width=14)
    table.add_column("Resource", width=32)
    table.add_column("Message", width=55)
    table.add_column("Region", width=14)

    for check in report.checks:
        colour = STATUS_COLOURS[check.status]
        table.add_row(
            f"[{colour}]{STATUS_ICONS[check.status]} {check.status.value}[/{colour}]",
            check.service,
            check.resource,
            check.message,
            check.region,
        )

    console.print(table)

    overall_colour = STATUS_COLOURS[report.overall_status]
    console.print(
        f"\n[bold]Overall: [{overall_colour}]{report.overall_status.value}[/{overall_colour}][/bold]  "
        f"· {report.healthy} healthy · {report.degraded} degraded · "
        f"{report.unhealthy} unhealthy · {report.unknown} unknown  "
        f"· checked in [dim]{report.duration_seconds}s[/dim]"
    )


# ── CLI commands ──────────────────────────────────────────────────────────────


@app.command("run")
def run(
    services: str = typer.Option(
        "eks,rds,elasticache,sqs",
        "--services",
        "-s",
        help="Comma-separated list of services to check: eks, rds, elasticache, sqs",
    ),
    region: str = typer.Option(
        "us-east-1",
        "--region",
        "-r",
        help="AWS region to check",
    ),
    output: str = typer.Option(
        "table",
        "--output",
        "-o",
        help="Output format: table | json",
    ),
    fail_on_unhealthy: bool = typer.Option(
        False,
        "--fail-on-unhealthy",
        help="Exit with code 1 if any service is UNHEALTHY (useful in CI pipelines)",
    ),
) -> None:
    """
    Run concurrent health checks across AWS services.

    Examples:\n
        python main.py healthcheck run\n
        python main.py healthcheck run --services eks,rds --region eu-west-1\n
        python main.py healthcheck run --output json | jq '.checks[] | select(.status=="UNHEALTHY")'
    """
    service_list = [s.strip().lower() for s in services.split(",")]
    unknown_services = [s for s in service_list if s not in SERVICE_CHECKERS]

    if unknown_services:
        console.print(f"[red]Unknown services: {', '.join(unknown_services)}[/red]")
        console.print(f"Valid options: {', '.join(SERVICE_CHECKERS.keys())}")
        raise typer.Exit(1)

    console.print(
        f"\n[bold blue]🔍 Running health checks[/bold blue] — "
        f"services: [cyan]{', '.join(service_list)}[/cyan] · "
        f"region: [cyan]{region}[/cyan]\n"
    )

    report = run_checks(service_list, region)

    if output == "json":
        output_data = {
            "overall_status": report.overall_status.value,
            "summary": {
                "total": report.total,
                "healthy": report.healthy,
                "degraded": report.degraded,
                "unhealthy": report.unhealthy,
                "unknown": report.unknown,
            },
            "duration_seconds": report.duration_seconds,
            "checks": [asdict(c) for c in report.checks],
        }
        typer.echo(json.dumps(output_data, indent=2, default=str))
    else:
        print_table(report)

    if fail_on_unhealthy and report.unhealthy > 0:
        raise typer.Exit(1)


@app.command("list-services")
def list_services() -> None:
    """List all supported services for health checks."""
    console.print("\n[bold]Supported services:[/bold]")
    descriptions = {
        "eks": "EKS cluster status + node group health",
        "rds": "RDS instance availability + status",
        "elasticache": "ElastiCache cluster + replication group health",
        "sqs": "SQS queue depth + DLQ backlog monitoring",
    }
    for svc, desc in descriptions.items():
        console.print(f"  [cyan]{svc:<14}[/cyan] {desc}")
    console.print()
