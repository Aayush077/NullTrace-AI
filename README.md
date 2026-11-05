# NullTrace AI

Evidence-first security assessment framework for LLM applications and AI agents.

**Version:** 0.1.0 — local MVP scaffold  
**Runtime:** Python 3.11+ / Ubuntu  
**Current scope:** local mock target, baseline checks, safe prompt-injection simulation, tool-permission boundary checks, JSON/Markdown reporting.

> This is a defensive testing tool. Only assess systems you own or have explicit written permission to test. The included demo uses synthetic data and never contacts an external target.

## Quick start (Ubuntu)

```bash
unzip nulltrace-ai.zip
cd nulltrace-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
nulltrace doctor
nulltrace demo
```

Run tests:

```bash
pytest
```

Run the local assessment:

```bash
nulltrace assess --output reports/demo-report.json
nulltrace report reports/demo-report.json
```

The demo target is deliberately local and synthetic. It simulates an agent that has a restricted tool policy. It does not connect to an LLM provider, internet endpoint, database, or real user account.

## Commands

- `nulltrace --help` — command help
- `nulltrace version` — installed version
- `nulltrace doctor` — environment check
- `nulltrace demo` — run the safe local demonstration
- `nulltrace assess --output PATH` — assess the bundled local mock target
- `nulltrace report PATH` — render a JSON report as readable Markdown

## Project layout

```text
src/nulltrace/
  cli/       CLI commands
  core/      data models and orchestration
  adapters/  local mock target
  checks/    initial security checks
  reporting/ report rendering
tests/       deterministic unit tests
docs/        architecture, threat model, safe-use and roadmap
```

## Important limitations

This MVP is a foundation, not a production-grade scanner. It does not prove that an AI system is secure, and its mock checks are not a substitute for testing a real deployment. A real HTTP/LLM adapter should only be added after scope controls, authentication handling, rate limits, timeouts, redaction, and explicit authorization are implemented and reviewed.
