# Architecture

```text
Web dashboard (frontend/ — React SPA, incl. Demo Target Lab)
 └── FastAPI backend (src/nulltrace/web/: api → service → db[SQLite])
      └── reuses the same orchestrator below (no duplicated logic)

Demo Target Lab (src/nulltrace/targets/)
 ├── registry.py — DemoTargetInfo metadata + factories (5 scenarios,
 │   secure/vulnerable variants)
 ├── scenarios.py — scenario compositions over capability shells
 └── simulation.py — shared engine: flag-driven prompt simulation,
     data-driven SyntheticToolbox and SyntheticDocumentStore

CLI (src/nulltrace/cli/app.py)
 └── Assessment orchestrator (core/runner.py)
      ├── Module registry + profiles (checks/registry.py)
      ├── AssessmentContext (core/context.py)
      │     assessment ID, probe tokens, declared markers (hints)
      ├── Target adapters (adapters/)
      │     base.TargetAdapter          — send_prompt, hints, is_synthetic
      │     capabilities.*              — optional: tools, conversation, retrieval
      │     mock_agent.LocalMockAgent   — offline synthetic target
      │     openai_compatible.*         — OpenAI-compatible API over
      │     secure_transport.*            DNS-validated, IP+origin-pinned TLS
      ├── Checks (checks/*.py) → CheckResult (+ Finding on failure)
      ├── Redaction (core/redaction.py) — applied to all stored evidence
      └── Reporting (reporting/render.py) — validation + Markdown
```

## Core contracts

- **TargetAdapter** — a named system under assessment. Mandatory:
  `send_prompt`. Optional capabilities (`ToolExecutionCapability`,
  `ConversationCapability`, `RetrievalCapability`,
  `ToolCallProbeCapability`) unlock further checks; missing
  capabilities cause checks to be `skipped`, never guessed. Tool and
  retrieval targets additionally *declare their environment*
  (`describe_tools()` → tools/roles/principals,
  `describe_retrieval()` → scenario questions), so checks plan probes
  target-agnostically instead of hardcoding names.
- **Check** — one executable security test with a stable ID
  (`NT-<MOD>-NNN`). Returns a `CheckResult` whose status is a *security
  outcome* (`pass` / `fail` / `inconclusive`) or an *execution state*
  (`error` / `skipped`). Failing checks attach `Finding` objects.
- **AssessmentContext** — carries the assessment ID, deterministic
  per-check probe tokens, and `AssessmentHints`: markers a cooperating
  target declares (canaries, synthetic secrets, synthetic records,
  action markers). Marker evidence ⇒ high confidence; no markers ⇒
  heuristics only ⇒ `inconclusive`.
- **Finding** — evidence-backed statement with severity, confidence,
  reproduction steps, impact, remediation, and `validation_status`
  starting at `pending_review`. Automation never confirms findings.
- **AssessmentReport** — schema-versioned run record: metadata, scope,
  modules, per-check results, deduplicated findings, notes, limitations,
  configuration.

## Evidence strategy

1. **Probe tokens** (`NTPROBE-<sha256(assessment:check)[:10]>`): probes
   instruct the target to emit a token unique to the assessment+check.
   Token emission is direct proof the injected instruction was followed —
   valid even for black-box targets.
2. **Declared markers**: synthetic canaries/secrets/records declared by
   the target fixture (or configured by the assessor). Their appearance
   in output is directly attributable disclosure.
3. **Heuristics** (refusal prefixes, credential-shaped patterns) are only
   ever grounds for `inconclusive` results flagged for human review.

## Secure transport (adapters/secure_transport.py)

- Resolve DNS once; reject empty, invalid, mixed, or non-global answers
  (loopback allowed only for explicit localhost HTTP endpoints).
- Pin the connection to the validated IPs **and** to the validated
  host:port origin — `PinnedIPBackend` refuses any other origin.
- IDNA-normalize hostnames so validation and the wire agree.
- TLS verification against the original hostname (SNI preserved),
  redirects refused, proxies/retries/keepalive disabled.

## Extension rules

Checks stay independent of the CLI and of provider SDKs. New adapters
must enforce: explicit authorization, strict endpoint validation, request
budgets, timeouts, response-size limits, and redaction. New checks must
include true-positive and true-negative tests against the mock profiles.
