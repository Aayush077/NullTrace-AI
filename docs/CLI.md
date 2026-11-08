# CLI usage guide

All commands: `nulltrace --help`.

## Commands

| Command | Purpose |
| --- | --- |
| `nulltrace version` | installed version |
| `nulltrace doctor` | environment check (Python, modules, profiles) |
| `nulltrace modules` | list modules, checks, and profiles |
| `nulltrace demo` | offline demonstration against the hardened mock |
| `nulltrace assess` | run an assessment (mock or api mode) |
| `nulltrace report PATH [--format markdown\|summary]` | render a JSON report |
| `nulltrace findings PATH [--severity LEVEL]` | list findings in a report |
| `nulltrace validate-target --base-url URL [--api-key-env NAME]` | validate configuration without any network request |

## `assess` options

| Option | Default | Notes |
| --- | --- | --- |
| `--mode` | `mock` | `mock` (offline) or `api` |
| `--mock-profile` | `hardened` | `hardened` or `vulnerable` (mock only) |
| `--profile` | `standard` | `quick`, `standard`, `full` |
| `--modules` | – | comma-separated module list; overrides `--profile` |
| `--model` | – | required in api mode |
| `--base-url` | `https://api.openai.com/v1` | validated strictly |
| `--api-key-env` | `OPENAI_API_KEY` | key is read from the environment, never printed |
| `--allow-network` | off | **required** for api mode (explicit consent) |
| `--max-requests` | 10 | outbound request budget |
| `--timeout` | 30 | per-request timeout (seconds) |
| `--output`, `-o` | `reports/assessment-report.json` | JSON report path |
| `--markdown-output`, `-m` | – | optional Markdown report path |

## Examples

```bash
# Quick offline run
nulltrace assess --mode mock --profile quick -o reports/quick.json

# Only RAG and agent modules against the vulnerable training fixture
nulltrace assess --mode mock --mock-profile vulnerable \
    --modules rag_security,agent_security -o reports/rag-agent.json

# Authorized API assessment with a tight budget
export MY_KEY=...
nulltrace assess --mode api --allow-network --model my-model \
    --base-url https://api.example.com/v1 --api-key-env MY_KEY \
    --max-requests 15 -o reports/api.json -m reports/api.md
```

## Behavior guarantees

- Mock mode never opens a network connection and needs no credentials.
- API mode refuses to run without `--allow-network`.
- API keys are never written to reports, logs, or the terminal; the key
  value is additionally registered with the redaction engine.
- Reports are schema-validated before they are written; a report that
  fails validation is not written.
