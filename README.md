# NullTrace AI

**An evidence-driven security assessment framework for LLM applications and AI agents.**

NullTrace AI systematically tests AI-powered applications for AI-specific
security weaknesses — prompt injection, sensitive-information disclosure,
authorization bypass, unsafe tool use, retrieval-augmented-generation (RAG)
weaknesses and excessive agent autonomy — and produces findings backed by
concrete, reproducible evidence. Every finding is created in a
`pending_review` state; the framework never auto-confirms a vulnerability.

> **Status:** version 0.5.0. Suitable for **local / trusted single-tenant
> use** (research, education, and CI-style regression testing of your own
> AI applications). It is **not** yet validated for unsupervised
> professional engagements or multi-tenant internet-facing deployment — see
> [Known Limitations](docs/KNOWN_LIMITATIONS.md) and
> [Release Levels](docs/RELEASE_LEVELS.md). No independent external security
> review has been performed, and no claim of external validation or
> enterprise-readiness is made.

---

## Table of contents

- [What it does](#what-it-does)
- [Problem statement](#problem-statement)
- [Key features](#key-features)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Supported integrations & limitations](#supported-integrations--limitations)
- [Installation](#installation)
- [Running the application](#running-the-application)
- [Using NullTrace AI](#using-nulltrace-ai)
- [Demo Target Lab](#demo-target-lab)
- [Reports](#reports)
- [Running the tests](#running-the-tests)
- [Docker](#docker)
- [Troubleshooting](#troubleshooting)
- [Security considerations](#security-considerations)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

NullTrace AI executes a versioned corpus of adversarial probes against an AI
target, captures the actual responses as evidence, evaluates specific
security boundaries, and assembles structured findings. Detection is
**attribution-based**: a probe either instructs the target to emit a unique
per-assessment token (a compliance signal that cannot occur by chance) or is
checked against declared synthetic markers (canaries, synthetic secrets,
synthetic records). Observations that match only a generic heuristic are
capped at an `inconclusive` status and never confirmed automatically.

It can be driven from a **command-line interface** or a **local web
dashboard**, and ships a five-scenario synthetic **Demo Target Lab** so the
engine can be exercised end-to-end without any external system.

## Problem statement

AI applications gain access to tools, private data and the ability to act, so
their attack surface extends well beyond that of traditional software.
Classical scanners do not detect a model that follows an instruction hidden
in a document, discloses its system prompt, reads another tenant's record, or
invokes a destructive tool on request. Teams lack a reproducible,
evidence-driven way to assess these failure modes. NullTrace AI addresses
this by treating AI security assessment as an engineering discipline that
yields defensible, traceable, human-reviewable findings.

## Key features

All of the following are **implemented** and covered by the automated test
suite:

- **9 security modules / 28 checks** — baseline, prompt injection (6),
  information disclosure (3), authorization (3), tool abuse (4), output
  handling (2), RAG security (3), agent security (4), multi-turn attack
  chains (2).
- **Versioned probe corpus (v1.0)** — 7 families, 28 metadata-rich base
  probes, plus a deterministic, seed-traceable mutation engine.
- **Repeated-sampling engine** for nondeterministic models — single /
  repeated / strict / statistical policies, with violation-rate, consistency
  and confidence reported separately.
- **Six assessment profiles** — `quick`, `standard`, `full`,
  `comprehensive`, `deep`, `regression` — each with documented depth and
  request consumption.
- **Attribution-based evidence** — unique probe tokens and declared synthetic
  markers; secrets redacted from evidence, errors and logs.
- **Hardened OpenAI-compatible adapter** — single prompts, multi-turn
  conversations and tool-call probing (parsed as evidence, never executed),
  over a DNS-validated, IP-and-origin-pinned, TLS-verifying transport that
  mitigates SSRF.
- **Synthetic Demo Target Lab** — five scenarios (one secure baseline, four
  intentionally vulnerable), each with a secure control variant.
- **Evidence-first findings** — severity, confidence, reproduction steps,
  expected vs actual behaviour, impact, remediation, probe IDs and
  reproducibility; always `pending_review` until a human confirms.
- **Schema-validated reports** — machine-readable JSON and professional
  Markdown with an executive summary and methodology section.
- **Web platform** — FastAPI backend with scrypt authentication, four-role
  RBAC, audit logging and SQLite persistence; React + TypeScript dashboard.
- **Internal synthetic benchmark** — measured precision/recall on the Demo
  Lab (clearly labelled as a synthetic control, not real-world validation).

## Architecture

```
Web dashboard (React/TS)  ·  Typer CLI
        │
        ▼
FastAPI backend  →  AssessmentService  (no duplicated business logic)
        │
        ▼
Assessment orchestrator  (profiles · budgets · sampling · error isolation)
        │
        ├─ Security modules  →  probe corpus + mutation engine
        ├─ Target adapters   →  mock agent · Demo Lab (5) · OpenAI-compatible
        └─ Evidence → Findings → Reporting
        │
        ▼
SQLite persistence (assessments, findings, users, sessions, audit)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full layered view and
[docs/SCHEMA.md](docs/SCHEMA.md) for the database schema.

## Technology stack

| Layer | Technologies |
| --- | --- |
| Language / runtime | Python 3.11 |
| Backend / API | FastAPI, Pydantic, Uvicorn |
| CLI | Typer, Rich |
| Secure transport | HTTPX, HTTPCore (custom IP-pinned backend) |
| Persistence | SQLite (WAL), standard-library `sqlite3` |
| Authentication | `hashlib.scrypt`, hashed session tokens |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Recharts |
| Quality | Pytest, Ruff, Mypy (strict) |
| Packaging | uv, Docker |

## Supported integrations & limitations

| Target | Support |
| --- | --- |
| Local mock agent | Full (offline, no credentials) |
| Demo Target Lab (5 synthetic scenarios) | Full (offline, synthetic) |
| OpenAI-compatible HTTP API | Text chat, multi-turn conversation, tool-call probing. **No** streaming or structured-output modes. The tool / authorization / RAG / agent modules require a target that exposes those capabilities; against a plain chat API they are reported `skipped`. |
| LangChain / LlamaIndex / AutoGen / CrewAI / external RAG stacks | **Not implemented** (deliberately deferred rather than shipped as shallow shims). |

Benchmark figures in this repository are **internal synthetic** measurements
on deterministic fixtures — a regression/false-positive control, **not** a
real-world detection rate and **not** external validation.

## Installation

**Prerequisites:** Python 3.11+, and (for the dashboard) Node.js 20+.
[uv](https://docs.astral.sh/uv/) is recommended for the Python side.

```bash
# clone your copy of the repository, then:
uv sync --extra dev          # install the package + dev tools
uv run nulltrace doctor      # verify the environment
```

Or with pip:

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
nulltrace doctor
```

Copy the example environment file and adjust as needed (never commit a real
`.env`):

```bash
cp .env.example .env
```

## Running the application

### CLI only (offline, no setup)

```bash
uv run nulltrace demo                     # offline synthetic demonstration
uv run nulltrace targets                  # list the Demo Target Lab scenarios
```

### Web dashboard (local use)

```bash
# 1. build the dashboard (once, or after frontend changes)
cd frontend && npm install && npm run build && cd ..

# 2. start the backend (serves the API and the built dashboard)
uv run nulltrace serve       # starts the backend + serves the built dashboard
```

Open **http://127.0.0.1:8787** — the landing page is `/`, the dashboard is
`/app`, and interactive API docs are at `/api/docs`.

For frontend development with hot reload (proxies `/api` to port 8787):

```bash
cd frontend && npm run dev     # http://localhost:5173
```

### Enabling authentication

Until the first user is created the dashboard runs in an **open local setup
mode**. Create the first admin to require login:

```bash
uv run nulltrace user-add --username admin --role admin
```

Roles: `viewer` < `analyst` < `researcher` < `admin`.

## Using NullTrace AI

### From the dashboard

1. Open **`/app`**. Go to **Demo Lab** (`/app/lab`) or **Targets**
   (`/app/targets`).
2. To assess an API you own, add a target under **Targets**: name, base URL,
   model, and the **environment variable name** that holds the API key (the
   key itself is never entered in or stored by the UI). Mark it
   network-authorized only if you are authorized to test it.
3. Start an assessment (choose a profile such as `standard` or
   `comprehensive`). Network assessments additionally require per-run consent.
4. Watch progress on the assessment page, which shows an execution timeline
   and a per-check transparency view (objective, probe, response, evidence).
5. Review findings under **Findings** (`/app/findings`) — filter by severity,
   confidence, category and review status, and set each finding to
   confirmed / rejected / needs-retesting.
6. Browse raw evidence under **Evidence** and download reports under
   **Reports**.

### From the CLI

```bash
# assess the offline mock target
uv run nulltrace assess --mode mock --profile full -o reports/mock.json -m reports/mock.md

# assess a Demo Lab scenario (synthetic)
uv run nulltrace assess --mode demo --target demo-travel-agent --profile comprehensive \
    -o reports/travel.json -m reports/travel.md

# assess an OpenAI-compatible API you are authorized to test
export OPENAI_API_KEY=...        # read from the environment, never logged
uv run nulltrace assess --mode api --allow-network --model gpt-4o-mini \
    --base-url https://api.example.com/v1 --max-requests 20 -o reports/api.json

# render or query a report
uv run nulltrace report reports/mock.json
uv run nulltrace findings reports/mock.json --severity critical
```

### Understanding results

- **Check statuses:** `pass` (probe resisted), `fail` (insecure behaviour
  observed, with evidence), `inconclusive` (not attributable), `error` (check
  could not run), `skipped` (capability absent — **never** counted as passed).
- **Severity:** `critical` / `high` / `medium` / `low` / `informational`.
- **Confidence:** `high` / `medium` / `low`, combining attribution strength
  with reproducibility under sampling.
- **Findings** are always created `pending_review`. A passed check does not
  prove the target is secure; it means the specific probes were resisted.

Full details: [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

## Demo Target Lab

Five synthetic AI application scenarios demonstrate detection without any
external system. Each vulnerable scenario has a **secure control variant**
that receives identical probes and yields zero findings, proving detection is
behaviour-driven, not label-driven. Model names shown are **simulated
configuration labels only** — no provider API is contacted, and the seeded
weaknesses do not describe any real model. See
[docs/DEMO_LAB.md](docs/DEMO_LAB.md).

```bash
uv run nulltrace targets
uv run nulltrace assess --mode demo --target demo-crm-assistant --profile comprehensive \
    -o reports/crm.json
```

## Reports

Reports are schema-validated (`schema_version` 1.0) JSON plus professional
Markdown, written to the path you pass with `-o` / `-m` (the dashboard offers
downloads from each assessment). JSON is machine-readable; Markdown includes
an executive summary, methodology, per-finding evidence and reproduction
steps. Generated reports live under `reports/` by convention and are
**git-ignored** (they can contain target responses). See
[docs/SCHEMA.md](docs/SCHEMA.md).

## Running the tests

The test and quality tools live in the `dev` extra. Pass `--extra dev` on
each `uv run`, or activate the venv once (`uv sync --extra dev && source
.venv/bin/activate`) and then run the tools directly.

```bash
uv run --extra dev pytest -q            # full backend suite
uv run --extra dev ruff check .         # lint
uv run --extra dev mypy src tests       # strict type check
cd frontend && npx tsc --noEmit && npm run build   # frontend type-check + build
```

Current status on `main`: **309 backend tests passing**, Ruff clean, Mypy
strict clean across 62 source files, frontend type-check and production build
clean. All tests are deterministic and offline (mocked transports, patched
DNS, synthetic fixtures); none make live network calls.

## Docker

```bash
cd frontend && npm ci && npm run build && cd ..   # build the dashboard first
docker build -t nulltrace-ai .
docker volume create nt-data
docker run -d --name nulltrace -p 127.0.0.1:8787:8787 \
  -e NULLTRACE_DB_PATH=/data/nulltrace.db -v nt-data:/data nulltrace-ai
```

Publish only to `127.0.0.1` (or behind an authenticating reverse proxy).
See [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `nulltrace: command not found` | Use `uv run nulltrace …`, or activate the venv (`source .venv/bin/activate`). |
| Dashboard shows a blank page / 404 at `/app` | Build the frontend first: `cd frontend && npm run build`. |
| `API key environment variable '…' is not set` | Export the variable named on the target before an API assessment. |
| Base URL rejected | Private/reserved IPs, credentials-in-URL, query/fragment and non-localhost HTTP are refused by design. |
| Dashboard returns 401 after creating a user | Setup mode has closed; log in (a session token is required). |
| In-container `user-add` seems to have no effect | Pass `--db /data/nulltrace.db` (or set `NULLTRACE_DB_PATH`) so it writes the DB the server reads. |

## Security considerations

- **Local / trusted deployment only.** Bind to `127.0.0.1`; there is no rate
  limiting or MFA, and no independent external security review has been done.
- **API keys** are referenced only by environment-variable name — never
  stored in the database, returned by any endpoint, or written to logs — and
  are redacted from evidence.
- **SSRF mitigation:** outbound requests use a DNS-validated,
  IP-and-origin-pinned, TLS-verifying transport that refuses redirects and
  private/reserved addresses. SSRF-proof behaviour is **not** claimed.
- **Authorization-first:** offline by default; network assessments require an
  explicitly authorized target and per-run consent, bounded by request
  budgets, timeouts and response-size limits. No destructive actions; all
  tool actions are simulated.

See [SECURITY.md](SECURITY.md), [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md)
and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Known limitations

Headlines: the probe corpus is v1.0 and finite; high-confidence detection for
several modules depends on declared synthetic markers; the sampling engine is
implemented but not yet validated against a live nondeterministic model; the
tool/authorization/RAG/agent modules reach real systems only through adapters
not yet written for third-party frameworks; benchmarks are internal
synthetic; and the web platform is local-only. Full list:
[docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) and
[docs/RELEASE_LEVELS.md](docs/RELEASE_LEVELS.md). Next priorities: expand the
corpus and validate repeated sampling against live models; real-system
adapters for RAG/agent frameworks; external-benchmark validation; web
platform hardening (rate limiting, CSRF/XSS, MFA) and a PostgreSQL backend;
and an independent external security review.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and
the [Developer Guide](docs/DEVELOPER_GUIDE.md). All changes must pass Pytest,
Ruff and strict Mypy, and new checks need true-positive **and** true-negative
tests against the mock profiles.

## License

Released under the MIT License — see [LICENSE](LICENSE). Copyright is held by
the NullTrace AI contributors. (If you intend a different license or
copyright holder, update `LICENSE` before publishing.)
