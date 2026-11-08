# Contributing to NullTrace AI

Thank you for your interest in improving NullTrace AI. This document covers
how to set up a development environment and the standards every change must
meet. For architecture and extension points, see the
[Developer Guide](docs/DEVELOPER_GUIDE.md).

## Principles

- **Evidence over assumptions.** Findings must be backed by attributable
  evidence; do not report a vulnerability from a heuristic alone.
- **Safety first.** No destructive actions, no real customer data, no live
  network calls in automated tests. Use mocked transports and synthetic
  fixtures.
- **Honesty.** Do not claim unimplemented features, external validation or
  certification. Distinguish synthetic demonstrations from real-world testing.
- **No secrets.** Never commit credentials, tokens or private data. Keep them
  out of source, fixtures, logs and reports.

## Development setup

```bash
uv sync --extra dev          # or: python3.11 -m venv .venv && pip install -e ".[dev]"
uv run nulltrace doctor

# frontend (optional)
cd frontend && npm install
```

## Before you open a pull request

All of the following must pass:

```bash
uv run --extra dev ruff check .
uv run --extra dev mypy src tests
uv run --extra dev pytest -q
cd frontend && npx tsc --noEmit && npm run build   # if you touched the frontend
```

Additional requirements:

- **New security checks** need true-positive **and** true-negative tests
  against the mock / Demo Lab profiles (vulnerable detected, secure variant
  clean).
- **Any change to a security control** (transport, URL validation, budgets,
  redaction, auth/RBAC) needs a regression test.
- Keep Python code fully type-annotated (Mypy strict) and documented with
  clear docstrings; keep functions small and modular.
- Update the relevant documentation to reflect actual behaviour, not intended
  behaviour.

## Commit and PR etiquette

- Keep changes focused; avoid unrelated refactoring.
- Write a clear description of what changed and why, and note any security
  implications.
- Do not weaken or delete tests to obtain a green build; if a test is wrong,
  explain why and replace it with a better one.

## Reporting bugs and security issues

- Functional bugs: open a GitHub issue with reproduction steps.
- Security issues in NullTrace AI itself: follow [SECURITY.md](SECURITY.md)
  and report privately.
