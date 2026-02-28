# aws-platform-toolkit

> Production-grade Python CLI for AWS infrastructure operations.  
> Health checks · Drift detection · Cost analysis · Automated remediation.

[![CI](https://github.com/theashishprasad/aws-platform-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/theashishprasad/aws-platform-toolkit/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What this is

`aws-platform-toolkit` is a CLI tool built for platform and SRE engineers who
manage AWS infrastructure at scale. It eliminates the most common categories of
**on-call toil** — manually checking service health, hunting for configuration
drift, deciphering cost spikes, and executing known remediation steps — by
wrapping them in a single, well-tested, observable command-line interface.

Every command is designed with three principles:

- **Safe by default** — destructive actions require an explicit `--execute` flag; without it, they run in dry-run mode and show exactly what would change.
- **Observable** — structured JSON output on every command so results can be piped into jq, CloudWatch Logs, or Slack alerts.
- **Composable** — designed to be called from CI pipelines, Lambda functions, or cron jobs, not just human hands.

---

## Architecture

```
aws-platform-toolkit/
├── main.py                        # CLI entry point — registers all sub-commands
├── commands/
│   ├── aws_healthcheck.py         # Concurrent health checks (EKS, RDS, ElastiCache, SQS)
│   ├── aws_drift_detector.py      # Terraform state vs live AWS diff engine
│   ├── aws_cost_analyzer.py       # Cost Explorer per-service attribution reports
│   └── aws_remediation.py         # Automated remediation for known failure modes
├── tests/
│   ├── test_healthcheck.py        # moto-mocked unit tests
│   ├── test_drift_detector.py     # moto-mocked unit tests
│   └── test_remediation.py        # moto-mocked unit tests
└── .github/workflows/ci.yml       # GitHub Actions: test + lint + type-check + security scan
```

**Key design decisions:**
- `ThreadPoolExecutor` for concurrent health checks — a 4-service check completes in ~2s instead of ~8s sequential
- `dataclasses` for all report models — clean serialization to JSON, easy to extend
- `moto` for all tests — no real AWS account needed, CI runs in <30 seconds
- `typer` + `rich` for CLI — type-safe argument parsing and readable terminal output

---

## Quick start

```bash
# Clone and install
git clone https://github.com/theashishprasad/aws-platform-toolkit.git
cd aws-platform-toolkit

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Ensure AWS credentials are set (standard boto3 credential chain)
export AWS_PROFILE=my-profile   # or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY

# Run your first health check
python main.py healthcheck run --services eks,rds,sqs --region us-east-1
```

---

## Commands

### `healthcheck` — Concurrent service health checks

Runs health checks for EKS, RDS, ElastiCache, and SQS **concurrently** using
`ThreadPoolExecutor`. A complete 4-service check for an entire AWS region
typically completes in 2–4 seconds.

```bash
# Check all services in us-east-1 (default)
python main.py healthcheck run

# Check specific services in eu-west-1
python main.py healthcheck run --services eks,rds --region eu-west-1

# JSON output — pipe to jq for filtering
python main.py healthcheck run --output json | jq '.checks[] | select(.status=="UNHEALTHY")'

# Exit code 1 on UNHEALTHY — use in CI pipelines
python main.py healthcheck run --fail-on-unhealthy
```

**Example output:**
```
╭─────────────────────────────────────────────────────────────────────────────╮
│ Status      Service   Resource          Message                              │
├─────────────┼──────────┼──────────────────┼────────────────────────────────┤
│ ✅ HEALTHY  │ EKS      │ prod-cluster     │ ACTIVE · 3 node group(s) healthy│
│ ✅ HEALTHY  │ RDS      │ prod-postgres    │ Status: available · Multi-AZ: ✓ │
│ ⚠️  DEGRADED│ SQS      │ payments-queue   │ queue depth 1,847 exceeds 1,000 │
│ ❌ UNHEALTHY│ SQS      │ payments-dlq     │ DLQ has 23 messages             │
╰─────────────────────────────────────────────────────────────────────────────╯

Overall: UNHEALTHY · 2 healthy · 1 degraded · 1 unhealthy · checked in 1.84s
```

---

### `drift-detect` — Terraform state vs live AWS diff

Compares a Terraform state file against live AWS resource attributes and reports
what has changed outside of Terraform's control. Supports local files and S3 URIs.

```bash
# Local state file
python main.py drift-detect run --tfstate ./terraform.tfstate

# State stored in S3 (remote backend)
python main.py drift-detect run \
  --tfstate s3://my-tfstate-bucket/prod/terraform.tfstate \
  --region eu-west-1

# JSON output for programmatic processing
python main.py drift-detect run --tfstate ./terraform.tfstate --output json

# Exit 1 on drift — use in CI to block deployments on drifted infra
python main.py drift-detect run --tfstate ./terraform.tfstate --fail-on-drift
```

**Currently supported resource types:**
| Resource type | Attributes checked |
|---|---|
| `aws_instance` | instance_type, subnet_id |
| `aws_s3_bucket` | versioning, encryption |
| `aws_db_instance` | instance_class, engine_version, multi_az, deletion_protection |
| `aws_security_group` | description, vpc_id |

> More resource types are added incrementally — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

### `cost-analyze` — Per-service cost attribution

Pulls from AWS Cost Explorer to generate period-over-period cost reports,
ranked by spend, with anomaly detection for services with unexpected cost changes.

```bash
# Last 30 days, table output
python main.py cost-analyze run --days 30

# Last 7 days, top 10 services only
python main.py cost-analyze run --days 7 --top 10

# Export to CSV for finance review
python main.py cost-analyze run --days 30 --output csv --file costs.csv

# Flag services with >30% cost change (default: 20%)
python main.py cost-analyze run --days 30 --anomaly-threshold 30

# JSON output for Slack/PagerDuty integration
python main.py cost-analyze run --days 30 --output json
```

> **Note:** AWS Cost Explorer must be enabled in your account (Billing → Cost Explorer → Enable).
> Data is typically available with a 24-hour delay.

---

### `remediate` — Automated fixes for known failure modes

Executes automated remediation for common AWS failure patterns.
**Runs in dry-run mode by default** — add `--execute` to apply changes.

```bash
# Restart unhealthy EKS pods (dry run — shows what would happen)
python main.py remediate run \
  --action restart-unhealthy-pods \
  --cluster prod-cluster \
  --namespace payments

# Apply the restart
python main.py remediate run \
  --action restart-unhealthy-pods \
  --cluster prod-cluster \
  --namespace payments \
  --execute

# Flush DLQ messages back to source queue (dry run)
python main.py remediate run \
  --action flush-dlq \
  --queue-url https://sqs.us-east-1.amazonaws.com/123456789/payments-dlq

# Flush with execution
python main.py remediate run \
  --action flush-dlq \
  --queue-url https://sqs.us-east-1.amazonaws.com/123456789/payments-dlq \
  --execute

# Trigger ElastiCache primary failover (dry run)
python main.py remediate run \
  --action trigger-elasticache-failover \
  --cluster-id prod-redis
```

**Supported actions:**
| Action | Target | What it does |
|---|---|---|
| `restart-unhealthy-pods` | EKS cluster | Deletes pods in Failed/Unknown/CrashLoopBackOff state |
| `flush-dlq` | SQS DLQ URL | Moves DLQ messages back to source queue for reprocessing |
| `trigger-elasticache-failover` | ElastiCache replication group | Forces primary node failover |

---

## Using in CI/CD pipelines

### Pre-deployment health gate
```yaml
# GitHub Actions example
- name: Pre-deployment health check
  run: |
    python main.py healthcheck run \
      --services eks,rds \
      --region ${{ env.AWS_REGION }} \
      --fail-on-unhealthy \
      --output json | tee health-report.json
```

### Nightly drift detection
```yaml
- name: Detect infrastructure drift
  run: |
    python main.py drift-detect run \
      --tfstate s3://${{ env.TFSTATE_BUCKET }}/prod/terraform.tfstate \
      --output json | tee drift-report.json
    
    # Post to Slack if drift found
    if [ $? -ne 0 ]; then
      curl -X POST $SLACK_WEBHOOK -d @drift-report.json
    fi
```

---

## Running tests

Tests use **moto** to mock all AWS API calls. No real credentials needed.

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# With coverage (must be ≥80%)
pytest tests/ --cov=commands --cov-report=term-missing

# Run a specific test
pytest tests/test_healthcheck.py::test_sqs_dlq_with_messages_is_unhealthy -v
```

---

## AWS permissions required

The minimum IAM policy for read-only operations (healthcheck, drift-detect, cost-analyze):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup",
        "rds:DescribeDBInstances",
        "elasticache:DescribeReplicationGroups", "elasticache:DescribeCacheClusters",
        "sqs:ListQueues", "sqs:GetQueueAttributes",
        "s3:GetObject", "s3:HeadBucket", "s3:GetBucketVersioning",
        "s3:GetBucketEncryption", "s3:GetPublicAccessBlock",
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}
```

For remediation actions, additionally add:
```json
"sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:DeleteMessageBatch",
"sqs:SendMessage", "sqs:SendMessageBatch",
"elasticache:TestFailover"
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## About

Built by [Ashish Prasad](https://linkedin.com/in/ashishprasadoffic) — DevOps Engineer.  
This toolkit distills patterns from 3+ years of operating production AWS infrastructure at Nagarro.
