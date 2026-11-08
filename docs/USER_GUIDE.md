# NullTrace AI — User Guide

A step-by-step guide for someone using NullTrace AI for the first time. All
commands and routes below are taken from the current codebase.

> NullTrace AI is a **defensive** assessment tool. Only assess systems you
> own or are explicitly authorized to test. Offline mock and Demo Lab
> targets need no authorization; network assessments require explicit consent.

---

## A. Installation

### Prerequisites

- **Python 3.11 or newer** (the project targets 3.11).
- **Node.js 20 or newer** — only if you want the web dashboard.
- **[uv](https://docs.astral.sh/uv/)** — recommended for Python dependency
  management (pip also works).
- Optional: **Docker**, for containerised local deployment.

### Dependencies and environment

```bash
# with uv (recommended)
uv sync --extra dev

# or with pip
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Environment variables (copy the template; never commit a real `.env`):

```bash
cp .env.example .env
```

| Variable | Purpose | Default |
| --- | --- | --- |
| `NULLTRACE_DB_PATH` | SQLite database path | `data/nulltrace.db` |
| `NULLTRACE_FRONTEND_DIST` | Built dashboard directory | `frontend/dist` |
| `NULLTRACE_API_TOKEN` | Optional shared-secret guard for the open setup window | unset |
| `OPENAI_API_KEY` (or your target's variable) | Read by the backend at assessment time; never stored | unset |

### Database initialization

No manual step is needed. The SQLite database is created automatically on
first use at `NULLTRACE_DB_PATH` (default `data/nulltrace.db`). The schema
(assessments, findings, targets, users, sessions, audit log) is applied on
startup.

### Verify the installation

```bash
uv run nulltrace doctor
```

This prints the Python version, the registered modules and profiles, and
confirms that local mock mode is available offline.

---

## B. Starting the application

### Option 1 — CLI only (no web server)

Nothing to start; run commands directly, e.g. `uv run nulltrace demo`.

### Option 2 — Web dashboard

```bash
# Build the dashboard once (or after changing the frontend):
cd frontend && npm install && npm run build && cd ..

# Start the backend, which serves the API and the built dashboard:
uv run nulltrace serve
```

| URL | What it is |
| --- | --- |
| `http://127.0.0.1:8787/` | Marketing landing page |
| `http://127.0.0.1:8787/app` | Dashboard |
| `http://127.0.0.1:8787/api/docs` | Interactive API documentation |
| `http://127.0.0.1:8787/api/health` | Liveness check (returns `{"status":"ok"}`) |

**Verify it is running:**

```bash
curl -s http://127.0.0.1:8787/api/health      # {"status":"ok"}
curl -s http://127.0.0.1:8787/api/version     # {"project":"NullTrace AI","version":"0.5.0"}
```

### (Optional) enable login

Until the first user exists, the dashboard is open in **setup mode**. To
require authentication:

```bash
uv run nulltrace user-add --username admin --role admin
```

You will be prompted for a password (minimum 8 characters). After this, the
dashboard requires login. Roles, lowest to highest privilege: `viewer`,
`analyst`, `researcher`, `admin`.

---

## C. Your first assessment

### Supported target types

| Target | How to use | Needs credentials? |
| --- | --- | --- |
| Local mock agent | `--mode mock` (CLI) | No |
| Demo Target Lab (5 synthetic scenarios) | `--mode demo --target <id>` (CLI) or the **Demo Lab** page | No |
| OpenAI-compatible API | `--mode api` (CLI) or add a target in **Targets** | Yes (env var) |

### Via the dashboard

1. Open `http://127.0.0.1:8787/app`.
2. Go to **Demo Lab** (`/app/lab`) for a synthetic scenario, or **Targets**
   (`/app/targets`) to configure an API target.
3. To add an API target: provide a name, base URL (HTTPS; private/reserved
   addresses are rejected), model name, and the **name of the environment
   variable** that holds the API key. The key value itself is never entered
   in the UI. Tick "network authorized" only if you are authorized to test it.
4. Click **Run assessment** (or **Run Security Assessment** on a Demo Lab
   card). Choose a profile — start with `standard` or `comprehensive`.
5. For API targets, additionally confirm per-run network consent.

### Via the CLI

```bash
# offline mock
uv run nulltrace assess --mode mock --profile full -o reports/mock.json -m reports/mock.md

# a Demo Lab scenario
uv run nulltrace assess --mode demo --target demo-crm-assistant --profile comprehensive \
    -o reports/crm.json -m reports/crm.md

# an authorized API
export MY_KEY=...        # the key lives only in your shell/environment
uv run nulltrace assess --mode api --allow-network --model gpt-4o-mini \
    --base-url https://api.example.com/v1 --api-key-env MY_KEY \
    --max-requests 20 --timeout 30 -o reports/api.json
```

### Monitoring progress

In the dashboard, the assessment page shows an **execution timeline**
(initialised → capabilities identified → probes generated and executed →
evidence analysed → findings generated → completed) and refreshes
automatically while a network assessment runs in the background. On the CLI,
the run completes synchronously for mock/demo targets and prints a summary.

---

## D. Understanding results

### Check statuses

| Status | Meaning |
| --- | --- |
| `pass` | The target resisted the probes for this check. |
| `fail` | The insecure behaviour was observed, with attributable evidence (a finding is attached). |
| `inconclusive` | Behaviour could not be attributed with confidence (e.g. a black-box target without declared markers). |
| `error` | The check itself could not execute. |
| `skipped` | The target lacks a required capability (or the budget was exhausted). **Never counted as a pass.** |

### Severity, confidence, evidence

- **Severity:** `critical`, `high`, `medium`, `low`, `informational` —
  assigned from impact and the strength of the evidence.
- **Confidence:** `high`, `medium`, `low` — combines detection strength
  (attribution via a unique probe token or declared marker) with
  reproducibility under repeated sampling. A single sample is never treated
  as high-confidence for a nondeterministic target unless the detection is
  attribution-based.
- **Evidence:** each finding stores the probe sent and the response received
  (redacted; labelled synthetic for Demo Lab / mock targets), the originating
  probe IDs, and a reproducibility summary.

### Findings and review

Findings are always created in **`pending_review`**. A human reviewer sets
each finding to `confirmed`, `rejected` or `needs_retesting` from the finding
detail page (`/app/findings/:id`) or via the API. Automation never confirms a
finding. A passed assessment does **not** establish that a target is secure —
it means the executed probes were resisted.

### Reports

Every assessment yields a JSON report (and Markdown if requested). Reports
contain the assessment metadata, per-check results, deduplicated findings
with full evidence, notes and limitations.

---

## E. Demo Target Lab

The lab contains five synthetic scenarios. Run `uv run nulltrace targets` to
list them, or open `/app/lab`.

| Scenario (id) | Simulated model | Profile |
| --- | --- | --- |
| Secure Customer Support Assistant (`demo-secure-support`) | OpenAI GPT-4o | Secure baseline |
| Enterprise Knowledge Assistant (`demo-enterprise-rag`) | Anthropic Claude 3.7 Sonnet | Vulnerable (RAG) |
| Travel Booking AI Agent (`demo-travel-agent`) | Google Gemini 2.5 Pro | Vulnerable (tools/agent) |
| Multi-Tenant CRM Assistant (`demo-crm-assistant`) | OpenAI GPT-4o-mini | Vulnerable (authorization) |
| Developer Copilot Assistant (`demo-dev-copilot`) | Anthropic Claude 3.7 Sonnet | Vulnerable (disclosure/output) |

**Secure vs vulnerable.** Each vulnerable scenario has a **secure control
variant** that receives the identical probes and produces zero findings. In
the CLI, add `--secure-variant`; in the dashboard, tick "Run the secure
control variant" in the run dialog. Then select two assessments on the
Assessments page and press **Compare**.

**Why demo results are synthetic.** These targets are deterministic,
rule-based simulations. The model names are **simulated configuration labels
only**: no provider API is contacted, no real model is tested, and the seeded
weaknesses do not describe any real model or provider. Demo results
illustrate the engine's behaviour; they are **not** an assessment of any
commercial AI product.

```bash
# vulnerable profile vs its secure control
uv run nulltrace assess --mode demo --target demo-travel-agent --profile comprehensive -o reports/travel.json
uv run nulltrace assess --mode demo --target demo-travel-agent --secure-variant --profile comprehensive -o reports/travel-secure.json
```

---

## F. Reporting and evidence

### Viewing reports

- **Dashboard:** open an assessment and use the **JSON** / **Markdown**
  download buttons, or the **Reports** page (`/app/reports`).
- **CLI:** `uv run nulltrace report <file.json>` renders Markdown;
  `--format summary` prints a short summary; `uv run nulltrace findings
  <file.json> [--severity <level>]` lists findings.

### Exporting and storing

CLI reports are written to the `-o` (JSON) and `-m` (Markdown) paths you
provide; by convention these go under `reports/`. The `reports/` and `data/`
directories are **git-ignored** because they can contain assessment evidence
and user data. Dashboard downloads are generated from the stored assessment
and reflect the current human-review state of each finding.

### Preserving evidence

The canonical artifact is the JSON report (schema version 1.0). Archive the
JSON file to preserve an assessment's evidence; the Markdown is a rendered
view of the same data. The backing SQLite database (`data/nulltrace.db`) also
retains assessments and findings; back it up with
`sqlite3 data/nulltrace.db ".backup data/backup.db"`.

---

## Getting help

- Troubleshooting table: see the [README](../README.md#troubleshooting).
- Architecture and internals: [Developer Guide](DEVELOPER_GUIDE.md).
- Security posture and limitations: [SECURITY_REVIEW.md](SECURITY_REVIEW.md),
  [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
