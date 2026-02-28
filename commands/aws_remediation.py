"""
aws_remediation.py
==================
Automated remediation for known AWS infrastructure failure modes.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import boto3
import typer
from botocore.exceptions import ClientError
from rich.console import Console

app = typer.Typer(no_args_is_help=True)
console = Console()


# ── Data models ───────────────────────────────────────────────────────────────


class RemediationStatus(str, Enum):
    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    DRY_RUN = "DRY_RUN"
    FAILED = "FAILED"


@dataclass
class RemediationAction:
    action: str
    target: str
    status: RemediationStatus
    message: str
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationReport:
    action: str
    dry_run: bool
    total: int
    succeeded: int
    skipped: int
    failed: int
    actions: list[RemediationAction]


# ── EKS: Restart unhealthy pods ───────────────────────────────────────────────

UNHEALTHY_PHASES = {"Failed", "Unknown"}
UNHEALTHY_REASONS = {
    "CrashLoopBackOff",
    "OOMKilled",
    "Error",
    "ImagePullBackOff",
    "ErrImagePull",
    "Evicted",
}


def restart_unhealthy_pods(
    cluster_name: str,
    region: str,
    namespace: str,
    dry_run: bool,
) -> RemediationReport:
    """Find and delete pods in Failed/Unknown phase or known crashloop states."""
    actions: list[RemediationAction] = []
    try:
        eks = boto3.client("eks", region_name=region)
        cluster_info = eks.describe_cluster(name=cluster_name)["cluster"]
        if cluster_info.get("status") != "ACTIVE":
            return RemediationReport(
                "restart-unhealthy-pods",
                dry_run,
                0,
                0,
                0,
                1,
                [
                    RemediationAction(
                        "validate-cluster",
                        cluster_name,
                        RemediationStatus.FAILED,
                        f"Status: {cluster_info.get('status')}",
                    )
                ],
            )

        if dry_run:
            actions.append(
                RemediationAction(
                    "restart-unhealthy-pods",
                    f"{cluster_name}/{namespace}",
                    RemediationStatus.DRY_RUN,
                    "DRY RUN: Would scan and restart unhealthy pods.",
                )
            )
        else:
            try:
                from kubernetes import client, config

                config.load_kube_config()
                v1 = client.CoreV1Api()
                pods = v1.list_namespaced_pod(namespace=namespace).items
                unhealthy = []
                for pod in pods:
                    reason = None
                    if pod.status.container_statuses:
                        for cs in pod.status.container_statuses:
                            if (
                                cs.state.waiting and cs.state.waiting.reason in UNHEALTHY_REASONS
                            ) or (
                                cs.state.terminated
                                and cs.state.terminated.reason in UNHEALTHY_REASONS
                            ):
                                reason = (
                                    cs.state.waiting.reason
                                    if cs.state.waiting
                                    else cs.state.terminated.reason
                                )
                                break
                    if pod.status.phase in UNHEALTHY_PHASES or reason:
                        unhealthy.append((pod.metadata.name, pod.status.phase, reason or "None"))
                if not unhealthy:
                    actions.append(
                        RemediationAction(
                            "restart-unhealthy-pods",
                            f"{cluster_name}/{namespace}",
                            RemediationStatus.SKIPPED,
                            "No unhealthy pods found.",
                        )
                    )
                else:
                    for name, phase, reas in unhealthy:
                        try:
                            v1.delete_namespaced_pod(name=name, namespace=namespace)
                            actions.append(
                                RemediationAction(
                                    "delete-pod",
                                    name,
                                    RemediationStatus.SUCCESS,
                                    f"Deleted (Phase: {phase}, Reason: {reas})",
                                )
                            )
                        except Exception as e:
                            actions.append(
                                RemediationAction(
                                    "delete-pod", name, RemediationStatus.FAILED, f"Error: {e}"
                                )
                            )
            except Exception as e:
                actions.append(
                    RemediationAction(
                        "restart-unhealthy-pods",
                        cluster_name,
                        RemediationStatus.FAILED,
                        f"K8s error: {e}",
                    )
                )
    except ClientError as e:
        actions.append(
            RemediationAction(
                "validate-cluster", cluster_name, RemediationStatus.FAILED, f"AWS error: {e}"
            )
        )

    return RemediationReport(
        "restart-unhealthy-pods",
        dry_run,
        len(actions),
        sum(1 for a in actions if a.status == RemediationStatus.SUCCESS),
        sum(1 for a in actions if a.status == RemediationStatus.SKIPPED),
        sum(1 for a in actions if a.status == RemediationStatus.FAILED),
        actions,
    )


# ── SQS: Flush DLQ back to source queue ──────────────────────────────────────


def flush_dlq(dlq_url: str, region: str, dry_run: bool) -> RemediationReport:
    """Move messages from a DLQ back to its source queue."""
    actions: list[RemediationAction] = []
    sqs = boto3.client("sqs", region_name=region)
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=dlq_url,
            AttributeNames=["RedrivePolicy", "ApproximateNumberOfMessages", "QueueArn"],
        )["Attributes"]
        if int(attrs.get("ApproximateNumberOfMessages", 0)) == 0:
            return RemediationReport(
                "flush-dlq",
                dry_run,
                0,
                0,
                1,
                0,
                [
                    RemediationAction(
                        "flush-dlq", dlq_url, RemediationStatus.SKIPPED, "DLQ is empty"
                    )
                ],
            )

        redrive = json.loads(attrs.get("RedrivePolicy", "{}"))
        source_arn = redrive.get("deadLetterTargetArn") or redrive.get("sourceQueueArn")
        if not source_arn:
            account = attrs["QueueArn"].split(":")[4]
            source_name = attrs["QueueArn"].split(":")[5].replace("-dlq", "").replace("_dlq", "")
            source_url = f"https://sqs.{region}.amazonaws.com/{account}/{source_name}"
        else:
            p = source_arn.split(":")
            source_url = f"https://sqs.{region}.amazonaws.com/{p[4]}/{p[5]}"

        if dry_run:
            actions.append(
                RemediationAction(
                    "flush-dlq",
                    dlq_url,
                    RemediationStatus.DRY_RUN,
                    f"DRY RUN: Would move to {source_url}",
                )
            )
        else:
            received = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=10).get(
                "Messages", []
            )
            if received:
                sqs.send_message_batch(
                    QueueUrl=source_url,
                    Entries=[{"Id": m["MessageId"], "MessageBody": m["Body"]} for m in received],
                )
                sqs.delete_message_batch(
                    QueueUrl=dlq_url,
                    Entries=[
                        {"Id": m["MessageId"], "ReceiptHandle": m["ReceiptHandle"]}
                        for m in received
                    ],
                )
                actions.append(
                    RemediationAction(
                        "flush-dlq",
                        dlq_url,
                        RemediationStatus.SUCCESS,
                        f"Moved {len(received)} messages",
                    )
                )
            else:
                actions.append(
                    RemediationAction(
                        "flush-dlq", dlq_url, RemediationStatus.SKIPPED, "No messages received"
                    )
                )
    except Exception as e:
        actions.append(
            RemediationAction("flush-dlq", dlq_url, RemediationStatus.FAILED, f"Error: {e}")
        )
    return RemediationReport(
        "flush-dlq",
        dry_run,
        len(actions),
        sum(1 for a in actions if a.status == RemediationStatus.SUCCESS),
        sum(1 for a in actions if a.status == RemediationStatus.SKIPPED),
        sum(1 for a in actions if a.status == RemediationStatus.FAILED),
        actions,
    )


# ── ElastiCache Failover ─────────────────────────────────────────────────────


def trigger_elasticache_failover(cluster_id: str, region: str, dry_run: bool) -> RemediationReport:
    actions: list[RemediationAction] = []
    ec = boto3.client("elasticache", region_name=region)
    try:
        rg = ec.describe_replication_groups(ReplicationGroupId=cluster_id)["ReplicationGroups"][0]
        ng = next(
            (
                n
                for n in rg.get("NodeGroups", [])
                if any(m.get("CurrentRole") == "replica" for m in n.get("NodeGroupMembers", []))
            ),
            None,
        )
        if not ng:
            return RemediationReport(
                "failover",
                dry_run,
                1,
                0,
                1,
                0,
                [
                    RemediationAction(
                        "failover", cluster_id, RemediationStatus.SKIPPED, "No replicas"
                    )
                ],
            )
        if dry_run:
            actions.append(
                RemediationAction(
                    "failover", cluster_id, RemediationStatus.DRY_RUN, "DRY RUN: Would failover"
                )
            )
        else:
            ec.test_failover(ReplicationGroupId=cluster_id, NodeGroupId=ng["NodeGroupId"])
            actions.append(
                RemediationAction(
                    "failover", cluster_id, RemediationStatus.SUCCESS, "Failover triggered"
                )
            )
    except Exception as e:
        actions.append(RemediationAction("failover", cluster_id, RemediationStatus.FAILED, str(e)))
    return RemediationReport(
        "failover",
        dry_run,
        len(actions),
        sum(1 for a in actions if a.status == RemediationStatus.SUCCESS),
        0,
        sum(1 for a in actions if a.status == RemediationStatus.FAILED),
        actions,
    )


# ── Output ───────────────────────────────────────────────────────────────────


def print_report(report: RemediationReport) -> None:
    pre = "[blue]🔵 DRY RUN MODE[/blue] — " if report.dry_run else ""
    console.print(
        f"\n{pre}[bold]{report.action}[/bold] — {report.succeeded} succeeded · {report.failed} failed\n"
    )
    for a in report.actions:
        console.print(f"  {a.status.value}: {a.target}\n  [dim]{a.message}[/dim]\n")


@app.command("run")
def run(
    action: str = typer.Option(...),
    cluster: str | None = None,
    namespace: str = "default",
    queue_url: str | None = None,
    cluster_id: str | None = None,
    region: str = "us-east-1",
    execute: bool = False,
    output: str = "table",
) -> None:
    """Automated remediation run."""
    dry_run = not execute
    if action == "restart-unhealthy-pods":
        report = restart_unhealthy_pods(cluster or "unknown", region, namespace, dry_run)
    elif action == "flush-dlq":
        report = flush_dlq(queue_url or "unknown", region, dry_run)
    elif action == "trigger-elasticache-failover":
        report = trigger_elasticache_failover(cluster_id or "unknown", region, dry_run)
    else:
        raise typer.Exit(1)

    if output == "json":
        print(json.dumps(asdict(report), indent=2, default=str))
    else:
        print_report(report)

    if report.failed > 0:
        raise typer.Exit(1)
