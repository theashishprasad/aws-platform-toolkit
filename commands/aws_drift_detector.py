"""
aws_drift_detector.py
=====================
Detects infrastructure drift by comparing a Terraform state file against
live AWS resource attributes. Outputs a structured diff report showing
exactly what has changed outside of Terraform's control.

Usage:
    python main.py drift-detect run --tfstate ./terraform.tfstate
    python main.py drift-detect run --tfstate ./terraform.tfstate --output json
    python main.py drift-detect run --tfstate s3://my-bucket/prod/terraform.tfstate
"""

import json
import re
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
import typer
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich import box

app     = typer.Typer(no_args_is_help=True)
console = Console()


# ── Data models ───────────────────────────────────────────────────────────────

class DriftType(str, Enum):
    MODIFIED = "MODIFIED"   # Resource exists but attribute changed
    MISSING  = "MISSING"    # Resource in state but not in AWS
    UNKNOWN  = "UNKNOWN"    # Could not fetch live state


@dataclass
class AttributeDiff:
    attribute:    str
    state_value:  Any
    live_value:   Any


@dataclass
class ResourceDrift:
    resource_type:    str
    resource_id:      str
    terraform_address: str
    drift_type:       DriftType
    diffs:            List[AttributeDiff] = field(default_factory=list)
    message:          str = ""


@dataclass
class DriftReport:
    tfstate_source:  str
    checked_at:      str
    total_resources: int
    drifted:         int
    missing:         int
    clean:           int
    drifts:          List[ResourceDrift]

    @property
    def has_drift(self) -> bool:
        return self.drifted > 0 or self.missing > 0


# ── Terraform state parser ────────────────────────────────────────────────────

def load_tfstate(source: str) -> Dict:
    """Load Terraform state from local path or S3 URI."""
    if source.startswith("s3://"):
        return _load_from_s3(source)
    return _load_from_file(source)


def _load_from_file(path: str) -> Dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Terraform state file not found: {path}")
    with open(p) as f:
        return json.load(f)


def _load_from_s3(uri: str) -> Dict:
    # s3://bucket/key/path
    match = re.match(r"s3://([^/]+)/(.+)", uri)
    if not match:
        raise ValueError(f"Invalid S3 URI: {uri}")
    bucket, key = match.group(1), match.group(2)
    s3 = boto3.client("s3")
    with tempfile.NamedTemporaryFile(suffix=".tfstate") as tmp:
        s3.download_file(bucket, key, tmp.name)
        with open(tmp.name) as f:
            return json.load(f)


def extract_resources(tfstate: Dict) -> List[Dict]:
    """Extract all managed resources from Terraform state v4 format."""
    resources = []
    for resource in tfstate.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        for instance in resource.get("instances", []):
            resources.append({
                "type":    resource["type"],
                "name":    resource["name"],
                "address": f"{resource['type']}.{resource['name']}",
                "attributes": instance.get("attributes", {}),
            })
    return resources


# ── Live AWS fetchers ─────────────────────────────────────────────────────────

def fetch_live_ec2_instance(instance_id: str, region: str) -> Optional[Dict]:
    try:
        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return None
        instance = reservations[0]["Instances"][0]
        return {
            "instance_type":     instance.get("InstanceType"),
            "state":             instance["State"]["Name"],
            "subnet_id":         instance.get("SubnetId"),
            "vpc_id":            instance.get("VpcId"),
            "key_name":          instance.get("KeyName"),
            "iam_instance_profile": (
                instance.get("IamInstanceProfile", {}).get("Arn")
            ),
        }
    except ClientError:
        return None


def fetch_live_s3_bucket(bucket_name: str) -> Optional[Dict]:
    try:
        s3 = boto3.client("s3")
        # Check bucket exists
        s3.head_bucket(Bucket=bucket_name)

        # Versioning
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        versioning_status = versioning.get("Status", "Disabled")

        # Encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            encryption = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except ClientError:
            encryption = "None"

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            block_public = pab["PublicAccessBlockConfiguration"].get("BlockPublicAcls", False)
        except ClientError:
            block_public = False

        return {
            "versioning":   versioning_status,
            "encryption":   encryption,
            "block_public_acls": block_public,
        }
    except ClientError:
        return None


def fetch_live_rds_instance(db_identifier: str, region: str) -> Optional[Dict]:
    try:
        rds = boto3.client("rds", region_name=region)
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
        db = resp["DBInstances"][0]
        return {
            "db_instance_class":  db.get("DBInstanceClass"),
            "engine":             db.get("Engine"),
            "engine_version":     db.get("EngineVersion"),
            "multi_az":           db.get("MultiAZ"),
            "storage_type":       db.get("StorageType"),
            "allocated_storage":  db.get("AllocatedStorage"),
            "deletion_protection":db.get("DeletionProtection"),
        }
    except ClientError:
        return None


def fetch_live_security_group(sg_id: str, region: str) -> Optional[Dict]:
    try:
        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
        sgs = resp.get("SecurityGroups", [])
        if not sgs:
            return None
        sg = sgs[0]
        return {
            "group_name":  sg.get("GroupName"),
            "description": sg.get("Description"),
            "vpc_id":      sg.get("VpcId"),
            "ingress_rule_count": len(sg.get("IpPermissions", [])),
            "egress_rule_count":  len(sg.get("IpPermissionsEgress", [])),
        }
    except ClientError:
        return None


# ── Drift comparators ─────────────────────────────────────────────────────────

RESOURCE_FETCHERS = {
    "aws_instance":       lambda attrs, region: fetch_live_ec2_instance(
                              attrs.get("id", ""), region),
    "aws_s3_bucket":      lambda attrs, region: fetch_live_s3_bucket(
                              attrs.get("bucket", attrs.get("id", ""))),
    "aws_db_instance":    lambda attrs, region: fetch_live_rds_instance(
                              attrs.get("id", ""), region),
    "aws_security_group": lambda attrs, region: fetch_live_security_group(
                              attrs.get("id", ""), region),
}

# Attributes to compare per resource type (state_key -> live_key)
ATTRIBUTES_TO_CHECK = {
    "aws_instance": {
        "instance_type": "instance_type",
        "subnet_id":     "subnet_id",
    },
    "aws_s3_bucket": {
        "versioning": "versioning",
    },
    "aws_db_instance": {
        "instance_class":    "db_instance_class",
        "engine_version":    "engine_version",
        "multi_az":          "multi_az",
        "deletion_protection":"deletion_protection",
    },
    "aws_security_group": {
        "description": "description",
        "vpc_id":      "vpc_id",
    },
}


def compare_resource(
    resource: Dict,
    region: str,
) -> Tuple[bool, ResourceDrift]:
    """
    Compare a single resource from Terraform state against live AWS state.
    Returns (is_drifted, ResourceDrift).
    """
    rtype    = resource["type"]
    address  = resource["address"]
    attrs    = resource["attributes"]
    res_id   = attrs.get("id", attrs.get("bucket", address))

    if rtype not in RESOURCE_FETCHERS:
        # Resource type not supported for drift detection yet
        return False, ResourceDrift(
            resource_type=rtype,
            resource_id=res_id,
            terraform_address=address,
            drift_type=DriftType.UNKNOWN,
            message=f"Drift detection not yet implemented for {rtype}",
        )

    live = RESOURCE_FETCHERS[rtype](attrs, region)

    if live is None:
        return True, ResourceDrift(
            resource_type=rtype,
            resource_id=res_id,
            terraform_address=address,
            drift_type=DriftType.MISSING,
            message="Resource exists in Terraform state but NOT found in AWS",
        )

    # Compare known attributes
    checks = ATTRIBUTES_TO_CHECK.get(rtype, {})
    diffs  = []
    for state_key, live_key in checks.items():
        state_val = attrs.get(state_key)
        live_val  = live.get(live_key)
        if state_val != live_val and not (state_val is None and live_val is None):
            diffs.append(AttributeDiff(
                attribute=state_key,
                state_value=state_val,
                live_value=live_val,
            ))

    if diffs:
        return True, ResourceDrift(
            resource_type=rtype,
            resource_id=res_id,
            terraform_address=address,
            drift_type=DriftType.MODIFIED,
            diffs=diffs,
            message=f"{len(diffs)} attribute(s) differ from Terraform state",
        )

    return False, ResourceDrift(
        resource_type=rtype,
        resource_id=res_id,
        terraform_address=address,
        drift_type=DriftType.MODIFIED,  # placeholder, won't be used
        message="No drift detected",
    )


# ── Output formatters ─────────────────────────────────────────────────────────

def print_drift_table(report: DriftReport) -> None:
    if not report.has_drift:
        console.print("\n[bold green]✅ No drift detected.[/bold green] "
                      f"All {report.total_resources} resources match Terraform state.\n")
        return

    console.print(f"\n[bold red]⚠️  Drift detected[/bold red] — "
                  f"{report.drifted} modified · {report.missing} missing "
                  f"of {report.total_resources} total resources\n")

    for drift in report.drifts:
        colour = "red" if drift.drift_type == DriftType.MISSING else "yellow"
        console.print(
            f"[{colour}]{drift.drift_type.value}[/{colour}]  "
            f"[bold]{drift.terraform_address}[/bold]  [dim]({drift.resource_id})[/dim]"
        )
        if drift.diffs:
            for diff in drift.diffs:
                console.print(
                    f"   [dim]attribute:[/dim] {diff.attribute}\n"
                    f"   [red]  state: {diff.state_value}[/red]\n"
                    f"   [green]   live: {diff.live_value}[/green]"
                )
        else:
            console.print(f"   [dim]{drift.message}[/dim]")
        console.print()


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command("run")
def run(
    tfstate: str = typer.Option(
        ..., "--tfstate", "-t",
        help="Path to terraform.tfstate file or S3 URI (s3://bucket/key)"
    ),
    region: str = typer.Option(
        "us-east-1", "--region", "-r",
        help="AWS region to query for live resource state"
    ),
    output: str = typer.Option(
        "table", "--output", "-o",
        help="Output format: table | json"
    ),
    fail_on_drift: bool = typer.Option(
        False, "--fail-on-drift",
        help="Exit with code 1 if any drift is detected (useful in CI)"
    ),
):
    """
    Compare Terraform state against live AWS resources and report drift.

    Examples:\n
        python main.py drift-detect run --tfstate ./terraform.tfstate\n
        python main.py drift-detect run --tfstate s3://my-tfstate-bucket/prod/terraform.tfstate\n
        python main.py drift-detect run --tfstate ./terraform.tfstate --output json
    """
    console.print(f"\n[bold blue]🔎 Scanning for drift[/bold blue] — "
                  f"state: [cyan]{tfstate}[/cyan] · region: [cyan]{region}[/cyan]\n")

    try:
        state = load_tfstate(tfstate)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error loading state file: {e}[/red]")
        raise typer.Exit(1)

    resources = extract_resources(state)
    console.print(f"Found [cyan]{len(resources)}[/cyan] managed resources in state file\n")

    drifts     = []
    clean      = 0

    for resource in resources:
        is_drifted, result = compare_resource(resource, region)
        if is_drifted:
            drifts.append(result)
        else:
            clean += 1

    report = DriftReport(
        tfstate_source=tfstate,
        checked_at=datetime.now(timezone.utc).isoformat(),
        total_resources=len(resources),
        drifted=sum(1 for d in drifts if d.drift_type == DriftType.MODIFIED),
        missing=sum(1 for d in drifts if d.drift_type == DriftType.MISSING),
        clean=clean,
        drifts=drifts,
    )

    if output == "json":
        typer.echo(json.dumps(asdict(report), indent=2, default=str))
    else:
        print_drift_table(report)

    if fail_on_drift and report.has_drift:
        raise typer.Exit(1)
