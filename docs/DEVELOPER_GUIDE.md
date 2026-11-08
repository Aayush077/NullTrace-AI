# NullTrace AI — Developer Guide

This guide explains how NullTrace AI is organised and how to extend it. All
paths and names refer to the actual code.

---

## Repository structure

```
.
├── README.md, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md, LICENSE
├── pyproject.toml, uv.lock          # Python package & locked deps
├── Dockerfile, .dockerignore        # container build
├── .env.example                     # environment template (no secrets)
├── .github/workflows/ci.yml         # CI: lint, types, tests, benchmark, build
├── src/nulltrace/                   # the Python package
│   ├── cli/app.py                   # Typer CLI (entry point: `nulltrace`)
│   ├── core/                        # models, runner, sampling, budget, redaction, context
│   ├── probes/                      # versioned probe corpus + mutation engine
│   ├── checks/                      # security modules + the module registry
│   ├── adapters/                    # target adapters + secure transport + capabilities
│   ├── targets/                     # Demo Target Lab (registry, scenarios, simulation)
│   ├── benchmark/                   # internal synthetic benchmark harness
│   ├── reporting/render.py          # report validation + Markdown rendering
│   └── web/                         # FastAPI backend (api, service, db, auth, main)
├── frontend/                        # React + TypeScript dashboard (Vite)
│   └── src/{pages,components,layouts,lib,styles}
├── tests/                           # Pytest suite (deterministic, offline)
└── docs/                            # architecture, guides, security, status
```

Git-ignored (local only, never published): `data/` (SQLite DB), `reports/`
(generated reports/evidence), `report/` (academic submission artifacts with
personal data), `.venv/`, `frontend/node_modules`, `frontend/dist`, caches.

## Entry points

| Interface | Entry point |
| --- | --- |
| CLI | `nulltrace.cli.app:app` (console script `nulltrace`, declared in `pyproject.toml`) |
| Web (ASGI) | `nulltrace.web.main:app` (start with `uv run nulltrace serve`, or `python -m uvicorn nulltrace.web.main:app`) |
| Python API | `nulltrace.core.runner.run_assessment(...)` |

## Core engine architecture

The engine is a layered pipeline with a single orchestrator shared by the CLI
and the web service (no duplicated business logic):

1. **Target adapter** (`adapters/base.py`, `adapters/capabilities.py`) —
   exposes an AI application behind `TargetAdapter.send_prompt` plus optional
   capability mix-ins: `ConversationCapability`, `ToolExecutionCapability`,
   `RetrievalCapability`, `ToolCallProbeCapability`. Adapters also *declare*
   their environment (`describe_tools()`, `describe_retrieval()`) so checks
   plan probes from what a target supports.
2. **Orchestrator** (`core/runner.py`) — `run_assessment()` resolves a
   profile to modules + an execution config, runs each check with error
   isolation, enforces the request budget, redacts evidence, deduplicates and
   links findings, and assembles an `AssessmentReport`.
3. **Checks** (`checks/*.py`) — each `Check` subclass returns a `CheckResult`
   (`core/models.py`) with a status and any `Finding`s.
4. **Probe corpus** (`probes/`) — `corpus.py` defines probe families;
   `mutation.py` adds deterministic variants; `model.py` is the data model.
5. **Sampling** (`core/sampling.py`) — repeated-sampling policies with
   violation-rate, consistency and confidence.
6. **Evidence / findings / reporting** — `core/models.py` (schema),
   `core/redaction.py` (secret redaction), `reporting/render.py` (validation
   + Markdown).
7. **Persistence & API** (`web/`) — `db.py` (SQLite), `service.py` (business
   logic over the orchestrator), `api.py` (FastAPI routes + RBAC), `auth.py`
   (scrypt + sessions + roles).

## Assessment lifecycle

```
run_assessment(target, profile=...) 
  → resolve profile → modules + ProfileExecution (depth, mutations, sampling)
  → build AssessmentContext (assessment id, probe tokens, target hints)
  → for each check:
        skip if required_capability absent  → CheckStatus.SKIPPED
        else run(target, context)           → CheckResult (+ Findings)
        redact evidence; isolate errors; stop safely if budget exhausted
  → assign finding ids, dedupe, link to assessment
  → assemble AssessmentReport (results, findings, notes, limitations, config)
```

## Probe execution and detection

A `CorpusCheck` (`checks/base.py`) runs a probe **family** at the profile's
depth. For each probe it builds the text (optionally mutated), executes it
under the sampling policy, and applies a detector keyed to the probe's
`detection` strategy:

- `token_compliance` — the unique per-assessment token appears in the
  response (black-box capable).
- `canary` / `secret_marker` / `private_data_marker` / `action_marker` — a
  declared synthetic marker appears (cooperative / hybrid).

The first variant whose sampling result counts as a violation fails the check,
with full evidence and the originating probe IDs recorded. Confidence combines
the attribution ceiling with reproducibility.

## Detection modules

Registered in `checks/registry.py` (`MODULES` maps module name → list of
check classes; `PROFILES` and `PROFILE_EXECUTION` define coverage and depth).
Modules: `baseline`, `prompt_injection`, `info_disclosure`, `authorization`,
`tool_abuse`, `output_handling`, `rag_security`, `agent_security`,
`attack_chains`.

## Adapter architecture

`TargetAdapter` is the base. `LocalMockAgent` (`adapters/mock_agent.py`)
implements all capabilities for offline testing. `OpenAICompatibleAdapter`
(`adapters/openai_compatible.py`) talks to a real API over the hardened
transport in `adapters/secure_transport.py` (DNS validation, IP+origin
pinning, TLS verification, redirect refusal). The Demo Lab adapters are built
in `targets/`.

## Database models

SQLite via `web/db.py` (standard-library `sqlite3`, WAL mode). Tables:
`assessments`, `findings` (FK → assessments, cascade), `targets`, `users`,
`sessions` (FK → users, cascade), `audit_log`. The stored report JSON is the
canonical assessment artifact. See [SCHEMA.md](SCHEMA.md).

## API architecture

FastAPI app built by `web/api.py:create_app()`. A `get_principal` dependency
resolves the caller from a session token (or grants local-admin in setup
mode); `require_role(min_role)` gates each write endpoint. Security-relevant
actions are written to the audit log. Routes are grouped: `/api/auth/*`,
`/api/users`, `/api/audit`, `/api/modules`, `/api/demo-targets`,
`/api/targets`, `/api/assessments`, `/api/findings`, `/api/dashboard/*`.
Interactive docs: `/api/docs`.

## Frontend architecture

React 18 + TypeScript + Vite + Tailwind. `src/lib/api.ts` is the typed API
client (sends the session token, handles errors); `src/lib/types.ts` mirrors
the backend schema. Pages live in `src/pages/app/*` and route from `App.tsx`
behind `AuthGate`. `components/charts.tsx` uses Recharts. Build with
`npm run build`; the backend serves `frontend/dist`.

## Testing strategy

All tests are deterministic and offline (mocked HTTP transports, patched DNS,
synthetic fixtures); none make live network calls. Each security-relevant
change needs a regression test, and new checks need **true-positive and
true-negative** tests against the mock/Demo Lab profiles. Run:

```bash
uv run --extra dev pytest -q
uv run --extra dev ruff check .
uv run --extra dev mypy src tests
cd frontend && npx tsc --noEmit && npm run build
```

---

## How to add a new security check

1. Create (or extend) a module file in `src/nulltrace/checks/`. For a
   corpus-driven check, subclass `CorpusCheck` and set `check_id`, `module`,
   `title`, `family`, `severity` and remediation text. For a custom check,
   subclass `Check` and implement `run(self, target, context) -> CheckResult`.
2. If it needs a capability, set `required_capability` (e.g.
   `ToolExecutionCapability`) so it is `SKIPPED` when absent.
3. Append the class to that module's `CHECKS` list; ensure the module is in
   `checks/registry.py:MODULES`.
4. Add true-positive and true-negative tests in `tests/` against the mock
   profiles.

## How to add a new probe

Edit `src/nulltrace/probes/corpus.py`: add a `ProbeSpec` (via the
`_token_probe`/`_*_probe` helpers) to the appropriate family tuple. Give it a
unique `probe_id`, an objective, the expected secure behaviour, a `detection`
strategy and a severity rationale. Probes compose a benign compliance
instruction with a named adversarial framing. Add/adjust tests in
`tests/test_probes.py`.

## How to add a new adapter

Implement `TargetAdapter` (and any capability interfaces from
`adapters/capabilities.py`) in `src/nulltrace/adapters/`. Implement
`send_prompt`, `assessment_hints()` (declared markers, for cooperative
detection), and `describe_tools()` / `describe_retrieval()` if it exposes
those. Add adapter tests using mocked transports/fixtures — never live calls.

## How to add a demo target

In `src/nulltrace/targets/scenarios.py`, compose a scenario from the shared
simulation engine (`targets/simulation.py`), declaring its weaknesses as
`SimulationWeaknesses` flags. Register a `DemoTargetDefinition` in
`targets/registry.py`. Add the standard test pair (vulnerable detected,
secure variant clean) in `tests/test_demo_targets.py`, and extend the
benchmark ground truth in `benchmark/ground_truth.py` if applicable.
