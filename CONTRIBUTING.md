# Contributing to aws-platform-toolkit

Thank you for your interest in contributing. This document covers how to set up
your development environment, run tests, and submit changes.

## Development setup

```bash
# 1. Clone the repo
git clone https://github.com/theashishprasad/aws-platform-toolkit
cd aws-platform-toolkit

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install all dependencies
pip install -r requirements.txt -r requirements-dev.txt

# 4. Verify tests pass
pytest tests/ -v
```

## Running tests

```bash
# All tests
pytest tests/

# With coverage report
pytest tests/ --cov=commands --cov-report=term-missing

# A single test file
pytest tests/test_healthcheck.py -v

# A single test
pytest tests/test_healthcheck.py::test_sqs_dlq_with_messages_is_unhealthy -v
```

Tests use **moto** to mock all AWS API calls — no real AWS account or credentials needed.

## Code style

```bash
# Lint
ruff check .

# Format (auto-fix)
black .

# Type check
mypy commands/ --ignore-missing-imports
```

All three must pass before submitting a PR. The CI pipeline enforces this.

## Adding a new command

1. Create `commands/aws_<name>.py` with a `typer.Typer()` app
2. Register it in `main.py` with `app.add_typer(...)`
3. Add tests in `tests/test_<name>.py` — aim for >80% coverage
4. Update `README.md` with usage examples
5. Open a PR with a clear description of what the command does and why

## Adding a new health check service

In `aws_healthcheck.py`:

1. Write a `check_<service>(region: str) -> List[ServiceHealth]` function
2. Register it in `SERVICE_CHECKERS` dict
3. Add moto-based tests in `test_healthcheck.py`

## Adding a new remediation action

In `aws_remediation.py`:

1. Write a function returning `RemediationReport`
2. Always implement `dry_run=True` path first — every action must be safe to preview
3. Make the action idempotent — running it twice should be safe
4. Register it in the `run()` CLI command's action dispatch
5. Add tests covering: dry_run, execute, error handling

## PR checklist

- [ ] Tests added for new functionality
- [ ] `pytest tests/` passes locally
- [ ] `ruff check .` passes
- [ ] `black --check .` passes
- [ ] README updated if adding a new command
- [ ] Dry-run mode implemented for any destructive action
