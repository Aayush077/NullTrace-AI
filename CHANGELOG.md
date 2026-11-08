# Changelog

## 0.5.0 — 2026-11-06

Industry-readiness milestone. See INDUSTRY_READINESS_REPORT.md.

### Detection engine (Phase 1)
- Versioned probe corpus v1.0 (`src/nulltrace/probes/`): 7 families, 28
  metadata-rich probes (objective, expected secure behavior, detection
  strategy, severity rationale, references). Checks execute a
  depth-selected slice of a family instead of one fixed phrasing.
- Deterministic, seed-traceable mutation engine (4 strategies).
- Multi-turn attack chains module (`checks/attack_chains.py`, NT-CHAIN-001/002)
  with per-step transcript evidence; capability-gated.
- Repeated-sampling + consistency engine (`core/sampling.py`): single/
  repeated/strict/statistical policies, violation-rate, consistency, and
  a confidence that combines attribution strength with reproducibility,
  bounded by the request budget.
- New profiles: comprehensive, deep, regression (with documented depth
  and expected request consumption). Findings carry `probe_ids` and a
  `reproducibility` summary.
- Checks are target-agnostic and declare a `detection_mode`
  (black_box / cooperative / hybrid).

### Benchmarking (Phase 3)
- Internal synthetic benchmark harness (`src/nulltrace/benchmark/`):
  precision/recall/F1/confusion per module and overall, ground truth
  derived independently from declared weakness flags. `nulltrace
  benchmark` CLI; measured results in BENCHMARK_RESULTS.md (comprehensive:
  P=R=F1=1.0, 0 FP / 0 FN on deterministic fixtures — a control, not a
  real-world figure).

### Platform security (Phase 4)
- Authentication (stdlib scrypt, constant-time verify, salted), hashed
  session tokens with expiry, four-role RBAC (viewer<analyst<researcher<
  admin) enforced least-privilege on every write endpoint, audit logging
  of security events with secret redaction, and an "open until first
  admin" setup mode. CLI `nulltrace user-add`; frontend login gate +
  session controls (theme preserved).

### Product engineering (Phase 5)
- Professional report sections (executive summary, methodology, scope,
  per-finding probe/reproducibility traceability).
- Non-root Dockerfile (built and container-smoke-tested), expanded CI
  (backend, frontend, benchmark gate, docker smoke).

### Quality
- Test suite 258 → **309** (probes, sampling, attack chains, benchmark,
  auth/RBAC/audit). Ruff + strict mypy clean (62 files). Frontend
  type-check + build clean. Docker build + container verified.

### Fixed
- CLI `user-add` now honors `$NULLTRACE_DB_PATH` (container bootstrap).
- Login no longer leaks username existence via timing.

## 0.4.0 — 2026-11-06

### Demo Target Lab (new)

- Five synthetic AI application scenarios (`src/nulltrace/targets/`):
  Secure Customer Support Assistant (secure baseline), Enterprise
  Knowledge Assistant (RAG weaknesses), Travel Booking AI Agent
  (tool/agent weaknesses), Multi-Tenant CRM Assistant (IDOR /
  cross-tenant), Developer Copilot Assistant (disclosure / output).
  Built from one shared simulation engine (flag-driven behavior,
  data-driven toolbox and document store) — no duplicated scenario
  code. Every vulnerable scenario has a secure control variant with
  identical probes and genuinely different behavior; the secure
  baseline cannot be made vulnerable. Model names are simulated
  configuration labels only; no provider API is contacted.
- Per-target disjoint synthetic marker namespaces keep evidence
  attributable to exactly one environment (regression-tested).
- Dashboard: new Demo Lab page (cards, details modal, run launcher
  with recommended modules and secure-variant toggle), assessment
  comparison view, and an execution-transparency upgrade on the
  assessment page: per-check expandable rows (objective, exact probe,
  response, detection outcome, evidence, linked findings) plus an
  execution timeline. Assessments store and display simulated
  provider/model metadata and variant.
- CLI: `nulltrace targets` and `nulltrace assess --mode demo
  --target <id> [--secure-variant]`.
- API: `GET /api/demo-targets`; `POST /api/assessments` gains
  `secure_variant`; built-in target list now exposes the five lab
  scenarios.

### Framework

- Checks are now target-agnostic: tool checks plan probes from the
  target-declared `ToolEnvironment` (tool metadata, roles, principals)
  and RAG checks from `RetrievalEnvironment`, instead of hardcoded
  mock tool names. `CheckResult` carries the check `objective` for
  transparency views.

### Quality

- Test suite grown from 225 to 250, including the critical lab
  regressions: vulnerable behavior detected with linked synthetic
  evidence, secure variants produce zero findings on identical probes,
  partial-failure targets fail only their seeded weaknesses, skipped
  is never counted as passed, and findings are never created from
  target labels. Ruff + strict mypy clean (46 files); frontend
  type-check and production build verified; pages inspected in a real
  browser with zero console errors.

## 0.3.0 — 2026-11-06

### Web platform (new)

- FastAPI backend (`nulltrace.web`) wrapping the existing assessment
  engine: modules, targets, assessments, findings (with human-review
  PATCH), report downloads (JSON/Markdown), dashboard summary and
  analytics endpoints. SQLite persistence (stdlib, WAL). Mock
  assessments run synchronously; API-mode assessments run in a
  background thread under their request budget.
- React + TypeScript + Vite + Tailwind dashboard (`frontend/`):
  Overview (live stats and charts), Assessments (create/run/detail),
  Targets (built-in mocks + configured APIs), Security Modules,
  Findings (search/filter/review), Evidence explorer, Reports
  (downloads reflecting review state), Settings. Real backend data
  everywhere; proper empty/loading/error states; responsive layouts.
- Marketing landing page with honest feature/module/roadmap content.
- Security posture: local-only deployment, optional shared-token
  guard (`NULLTRACE_API_TOKEN`), double-gated network authorization
  (target flag AND per-run consent), API keys referenced by env-var
  name only and never stored/returned/logged, localhost-only CORS,
  path-confined static serving. Documented in `docs/WEB.md`.

### Adapter and checks

- `OpenAICompatibleAdapter` now implements `ConversationCapability`
  (multi-turn chat) — NT-PI-005 works against API targets — and
  `ToolCallProbeCapability`: synthetic tool definitions are presented
  and *attempted* tool calls are parsed as structured evidence (never
  executed).
- `LocalMockAgent` simulates tool-call probing in both profiles.
- New check NT-AG-004 "Destructive tool call triggered by untrusted
  content" (agent_security, 26 checks total).
- `ValidationStatus` gains `needs_retesting`; findings carry an
  optional `review_note` set during human review.

### Quality

- Test suite grown from 203 to 225 (adapter conversation/tool-call
  tests, mock simulation tests, 17 API tests incl. auth, review flow,
  and double-authorization). Ruff and strict mypy clean (41 files).
  Frontend: `tsc --noEmit` clean, production build verified, rendered
  pages inspected at desktop and mobile widths via Playwright.

## 0.2.0 — 2026-11-05

### Security

- **Fixed: pinned transport did not enforce the validated origin.**
  `PinnedIPBackend` previously connected any requested host/port to the
  pinned IP addresses. It is now bound to the validated host and port at
  construction and refuses connections for any other origin. Regression
  tests cover host and port mismatches.
- Added IDNA/punycode hostname normalization (`normalize_hostname`) so
  origin comparison, DNS validation, and the wire-level hostname agree;
  IPv6 literals are canonicalized.
- Added secret redaction (`core/redaction.py`) applied to all evidence,
  findings, and check errors: known secret values (e.g. the configured
  API key) plus common credential patterns (sk-, Bearer, AKIA, ghp_,
  key=value assignments).

### Assessment engine

- New finding schema: finding ID, category, severity, confidence,
  evidence (probe/response, synthetic-labeled), reproduction steps,
  expected/actual behavior, impact, remediation, references, assessment
  linkage, timestamp, and `validation_status` starting at
  `pending_review` (human review required; automation never confirms).
- Check outcomes are now explicit: `pass`, `fail`, `inconclusive`,
  `error`, `skipped` — separating security outcomes from execution
  problems.
- Orchestrator rewrite: module registry, assessment profiles
  (quick/standard/full), per-check error isolation, capability-based
  skipping, safe stop on budget exhaustion, finding deduplication,
  unique assessment IDs.
- Evidence attribution via markers: declared canaries/synthetic secrets
  and deterministic per-assessment probe tokens (`NTPROBE-…`). Checks
  without attributable evidence report `inconclusive` instead of
  fabricating findings.

### Modules

- Module 1 prompt injection: direct override, system-prompt extraction,
  role confusion, delimiter confusion, multi-turn persistence, indirect
  injection (6 checks).
- Module 2 sensitive information disclosure (3 checks).
- Module 3 authorization and access control (3 checks).
- Module 4 tool abuse and excessive agency (4 checks).
- Module 5 output handling (2 checks).
- Module 6 RAG security against the synthetic document store (3 checks).
- Module 7 agent security against the synthetic agent (3 checks).
- The previous `prompt_boundary` and `tool_permissions` checks were
  superseded by richer equivalents (NT-ID-002/NT-AZ-001) and removed.

### Adapters

- `LocalMockAgent` rewritten as a deterministic synthetic application
  with hardened and vulnerable profiles, conversation, tool, and
  retrieval capabilities, and declared synthetic markers. The vulnerable
  profile is a training fixture used to validate true-positive
  detection.
- New optional capabilities: `ConversationCapability`,
  `RetrievalCapability` (alongside `ToolExecutionCapability`, now with
  an `arguments` parameter).

### Reporting and CLI

- Report schema v1.0 with summary counts, limitations, scope, and
  configuration; reports are validated before writing and before
  rendering.
- Markdown reports: severity-sorted findings with full fields, check
  results table, notes, limitations.
- CLI: new `modules`, `findings`, `validate-target` commands; `assess`
  gains `--profile`, `--modules`, `--mock-profile`, `--timeout`,
  `--markdown-output`; `report` gains `--format summary`.

### Quality

- Test suite grown from 86 to 203 tests, including transport origin
  regression tests, true-positive/true-negative module tests, CLI tests,
  redaction and schema validation tests. Ruff and strict mypy clean
  across `src` and `tests`.

## 0.1.0

- Initial development MVP: CLI, local mock target, three basic checks,
  OpenAI-compatible adapter with hardened transport, request budget,
  JSON/Markdown reporting.
