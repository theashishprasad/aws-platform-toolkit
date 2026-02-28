"""
test_drift_detector.py
======================
Unit tests for aws_drift_detector.py using moto.
"""

import json

import boto3
import pytest
from moto import mock_aws

from commands.aws_drift_detector import (
    DriftType,
    compare_resource,
    extract_resources,
    fetch_live_s3_bucket,
    load_tfstate,
)

REGION = "us-east-1"


@mock_aws
def test_compare_rds_instance_no_drift():
    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="my-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        EngineVersion="15.3",
        MultiAZ=False,
        DeletionProtection=False,
        AllocatedStorage=20,
    )
    resource = {
        "type": "aws_db_instance",
        "name": "primary",
        "address": "aws_db_instance.primary",
        "attributes": {
            "id": "my-db",
            "instance_class": "db.t3.micro",
            "engine": "postgres",
            "engine_version": "15.3",
            "multi_az": False,
            "deletion_protection": False,
        },
    }
    is_drifted, result = compare_resource(resource, REGION)
    assert not is_drifted


@mock_aws
def test_compare_security_group_no_drift():
    ec2 = boto3.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="test-sg", Description="test")
    sg_id = sg["GroupId"]
    actual_sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    vpc_id = actual_sg["VpcId"]

    resource = {
        "type": "aws_security_group",
        "name": "allow_all",
        "address": "aws_security_group.allow_all",
        "attributes": {"id": sg_id, "description": "test", "vpc_id": vpc_id},
    }
    is_drifted, result = compare_resource(resource, REGION)
    assert not is_drifted


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_tfstate(tmp_path):
    d = tmp_path / "terraform.tfstate"
    content = {
        "version": 4,
        "resources": [
            {
                "type": "aws_instance",
                "name": "web",
                "instances": [{"attributes": {"id": "i-123", "instance_type": "t3.medium"}}],
            }
        ],
    }
    d.write_text(json.dumps(content))
    return str(d)


# ── load_tfstate tests ────────────────────────────────────────────────────────


def test_load_tfstate_from_file(sample_tfstate):
    state = load_tfstate(sample_tfstate)
    assert state["version"] == 4


def test_load_tfstate_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_tfstate("missing.tfstate")


def test_load_tfstate_invalid_s3_uri_raises():
    with pytest.raises(ValueError):
        load_tfstate("s3://invalid")


# ── extract_resources tests ───────────────────────────────────────────────────


def test_extract_resources_empty_state():
    state = {"resources": []}
    assert extract_resources(state) == []


def test_extract_resources_skips_data_sources():
    state = {"resources": [{"mode": "data", "type": "aws_ami", "name": "ubuntu", "instances": []}]}
    assert extract_resources(state) == []


def test_extract_resources_managed_resource():
    state = {
        "resources": [
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "logs",
                "instances": [{"attributes": {"id": "my-bucket"}}],
            }
        ]
    }
    res = extract_resources(state)
    assert len(res) == 1
    assert res[0]["type"] == "aws_s3_bucket"


def test_extract_resources_multiple_instances():
    state = {
        "resources": [
            {
                "mode": "managed",
                "type": "aws_instance",
                "name": "app",
                "instances": [
                    {"index_key": 0, "attributes": {"id": "i-0"}},
                    {"index_key": 1, "attributes": {"id": "i-1"}},
                ],
            }
        ]
    }
    res = extract_resources(state)
    assert len(res) == 2


# ── compare_resource tests ────────────────────────────────────────────────────


@mock_aws
def test_compare_s3_bucket_no_drift():
    """S3 bucket exists with same attributes as state — no drift."""
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="my-test-bucket")

    resource = {
        "type": "aws_s3_bucket",
        "name": "logs",
        "address": "aws_s3_bucket.logs",
        "attributes": {
            "id": "my-test-bucket",
            "bucket": "my-test-bucket",
            "versioning": "Disabled",
        },
    }
    is_drifted, result = compare_resource(resource, REGION)
    assert not is_drifted


@mock_aws
def test_compare_s3_bucket_drifted_versioning():
    """S3 bucket versioning is different from state."""
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="versioned-bucket")
    s3.put_bucket_versioning(
        Bucket="versioned-bucket", VersioningConfiguration={"Status": "Enabled"}
    )

    resource = {
        "type": "aws_s3_bucket",
        "name": "logs",
        "address": "aws_s3_bucket.logs",
        "attributes": {
            "id": "versioned-bucket",
            "bucket": "versioned-bucket",
            "versioning": "Disabled",
        },
    }
    is_drifted, result = compare_resource(resource, REGION)
    assert is_drifted is True
    assert result.drift_type == DriftType.MODIFIED


@mock_aws
def test_compare_s3_bucket_drifted_encryption():
    """S3 bucket encryption fetch coverage."""
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="encrypted-bucket")
    s3.put_bucket_encryption(
        Bucket="encrypted-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    live = fetch_live_s3_bucket("encrypted-bucket")
    assert live["encryption"] == "AES256"


@mock_aws
def test_compare_s3_bucket_public_block_fetch():
    """S3 public access block fetch coverage."""
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="public-bucket")
    s3.put_public_access_block(
        Bucket="public-bucket", PublicAccessBlockConfiguration={"BlockPublicAcls": True}
    )
    live = fetch_live_s3_bucket("public-bucket")
    assert live["block_public_acls"] is True


@mock_aws
def test_compare_s3_bucket_missing_in_aws():
    """Bucket in state but not in AWS — should be MISSING drift."""
    resource = {
        "type": "aws_s3_bucket",
        "id": "gone-bucket",
        "address": "aws_s3_bucket.gone",
        "attributes": {"id": "gone-bucket"},
    }
    is_drifted, result = compare_resource(resource, REGION)
    assert is_drifted is True
    assert result.drift_type == DriftType.MISSING


@mock_aws
def test_compare_ec2_missing_instance():
    """EC2 instance ID in state but not in AWS."""
    resource = {
        "type": "aws_instance",
        "address": "aws_instance.web",
        "attributes": {"id": "i-1234567890abcdef0"},
    }
    is_drifted, result = compare_resource(resource, REGION)
    assert is_drifted is True
    assert result.drift_type == DriftType.MISSING


def test_compare_unsupported_resource_type_returns_unknown():
    resource = {"type": "aws_unsupported", "address": "aws_unsupported.x", "attributes": {}}
    is_drifted, result = compare_resource(resource, REGION)
    assert is_drifted is False
    assert result.drift_type == DriftType.UNKNOWN


def test_extract_resources_preserves_all_attributes():
    state = {
        "resources": [
            {
                "mode": "managed",
                "type": "aws_db_instance",
                "name": "db",
                "instances": [{"attributes": {"id": "db-1", "engine": "postgres"}}],
            }
        ]
    }
    res = extract_resources(state)
    assert res[0]["attributes"]["engine"] == "postgres"
