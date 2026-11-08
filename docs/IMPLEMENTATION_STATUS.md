# Implementation Status — Industry-Readiness Milestone

Baseline: v0.4.0. This milestone targeted the gaps in
`GAP_ANALYSIS.md`. Status is reported per the phase order in the
execution brief. **Verified** means executed in this environment with
output; **Pending** means prepared but not genuinely completable with
available tools/credentials; **Deferred** means intentionally out of
scope with a documented reason.

Verification snapshot (this tree):
- `uv run pytest -q` → **309 passed**
- `uv run ruff check .` → clean
- `uv run mypy src tests` → clean (strict, 62 files)
- `cd frontend && npx tsc --noEmit` → clean; `npm run build` → success
- `docker build` + container smoke (health, assessment, auth bootstrap) → verified
- `nulltrace benchmark --profile comprehensive` → precision 1.0, recall 1.0 (internal synthetic)

## Phase 1 — Detection depth — **Verified**

| Capability | Status | Evidence |
| --- | --- | --- |
| Versioned probe corpus (v1.0, 7 families, 28 probes, full per-probe metadata) | Verified | `src/nulltrace/probes/corpus.py`; `tests/test_probes.py` (10) |
| Deterministic, traceable mutation engine (4 strategies, seed-recorded) | Verified | `src/nulltrace/probes/mutation.py`; `test_probes.py` |
| Depth-aware execution (1/2/3 → 1/3/full family), proven to scale probes 1→3→6 | Verified | `registry.PROFILE_EXECUTION`; runtime check in session |
| Multi-turn attack chains (2 chains, per-step evidence, capability-gated) | Verified | `src/nulltrace/checks/attack_chains.py`; `tests/test_attack_chains.py` (4) |
| Repeated sampling + consistency/confidence (4 policies, budget-bounded) | Verified | `src/nulltrace/core/sampling.py`; `tests/test_sampling.py` (9) |
| Confidence separates attribution strength from reproducibility | Verified | `SamplingResult.confidence`; sampling tests |
| Probe IDs + reproducibility recorded on findings | Verified | `Finding.probe_ids/reproducibility`; report renderer |

## Phase 2 — Real-world integrations — **Partial**

| Capability | Status | Notes |
| --- | --- | --- |
| Conversation adapter (multi-turn) | Verified (0.3.0) | `OpenAICompatibleAdapter` implements `ConversationCapability` |
| Function/tool-call probing adapter | Verified (0.3.0) | `ToolCallProbeCapability`; attempts parsed, never executed |
| Declared tool/retrieval environments (target-agnostic checks) | Verified | `describe_tools()`/`describe_retrieval()`; checks plan from these |
| Detection-mode labelling (cooperative / black-box / hybrid) per check | Verified | `detection_mode` on checks; documented in KNOWN_LIMITATIONS |
| Generic HTTP RAG / agent adapters for arbitrary real apps | **Deferred** | Needs a stable third-party contract to be meaningful; synthetic RAG/agent coverage remains |
| LangChain / LlamaIndex / AutoGen / CrewAI integrations | **Deferred** | Rejected as superficial without real assessment value; see KNOWN_LIMITATIONS |

## Phase 3 — Benchmarking — **Verified (internal synthetic only)**

| Capability | Status | Evidence |
| --- | --- | --- |
| Benchmark harness, metrics from real execution | Verified | `src/nulltrace/benchmark/`; `tests/test_benchmark.py` (8) |
| Ground truth derived independently from weakness flags | Verified | `benchmark/ground_truth.py` (flag→check mapping) |
| Precision / recall / F1 / confusion per module and overall | Verified | `nulltrace benchmark`; `reports/benchmark-*.json` |
| External vulnerable-app validation | **Pending** | No live external targets contacted in automated work; harness is ready, external runs require authorization + network and are not performed here |

## Phase 4 — Platform security — **Verified**

| Capability | Status | Evidence |
| --- | --- | --- |
| Authentication (scrypt, constant-time verify) | Verified | `src/nulltrace/web/auth.py`; `tests/test_auth.py` (16) |
| Session management (hashed tokens, expiry, logout) | Verified | `db.sessions`; auth tests |
| RBAC (viewer<analyst<researcher<admin), least-privilege gates | Verified | `require_role` in `api.py`; role-matrix tests |
| Setup mode → closes on first user; CLI bootstrap | Verified | `service.setup_mode`; `nulltrace user-add`; container test |
| Audit logging (login/fail, assessment, review, report, user, target) | Verified | `db.audit_log`; `service.audit`; secret-redaction test |
| PostgreSQL production backend | **Deferred** | SQLite retained; thin `Database` layer keeps migration open; documented |

## Phase 5 — Product engineering — **Verified**

| Capability | Status | Evidence |
| --- | --- | --- |
| Professional report (exec summary, methodology, scope, limitations, traceability) | Verified | `reporting/render.py`; `tests/test_reporting.py` (8) |
| Dockerfile, built + container-smoke-tested from clean env | Verified | `Dockerfile`; session build/run/bootstrap |
| CI (backend, frontend, benchmark gate, docker smoke) | Verified (authored) | `.github/workflows/ci.yml` |
| Deployment + security docs | Verified | `DEPLOYMENT_GUIDE.md`, `SECURITY_REVIEW.md` |
| PDF export | **Deferred** | JSON + Markdown shipped; PDF not required for this milestone |

## Phase 6 — Independent security review — **Pending (prepared)**

Internal transport re-audit and a reviewer-ready concern list are in
`SECURITY_REVIEW.md`. No third-party review has occurred; this is
explicitly not claimed. See SECURITY_AUDIT_REPORT.md.
