# Development setup

Tested on Ubuntu 22.04 (incl. WSL) with Python 3.11 and uv.

```bash
# with uv (recommended)
uv sync --extra dev
uv run --extra dev pytest
uv run --extra dev ruff check .
uv run --extra dev mypy src tests
uv run nulltrace demo
```

```bash
# or with pip
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check . && mypy src tests
```

## Rules

- Tests are deterministic and offline: HTTPX `MockTransport`, patched
  DNS, and the synthetic mock agent. Never add a test that performs a
  live network request or needs a paid API.
- Every new check needs true-positive **and** true-negative tests
  against the mock profiles (vulnerable must be detected, hardened must
  not produce findings), plus error-handling coverage.
- Every change to a security control (transport, URL validation,
  budgets, redaction) needs a regression test.
- `pytest`, `ruff check .`, and `mypy src tests` (strict) must all pass
  before a change is complete.
- Keep secrets out of source, fixtures, logs, and reports. Synthetic
  markers must be shaped so they cannot be mistaken for real
  credentials (e.g. `SYNTHETIC-SECRET-NT-…`).

## Smoke test sequence

```bash
uv run nulltrace doctor
uv run nulltrace modules
uv run nulltrace demo
uv run nulltrace assess --mode mock --mock-profile vulnerable \
    --profile full -o /tmp/r.json -m /tmp/r.md
uv run nulltrace report /tmp/r.json --format summary
uv run nulltrace findings /tmp/r.json
uv run nulltrace validate-target --base-url https://api.example.com/v1
```
