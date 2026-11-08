# Roadmap

Status values are based on implementation and test evidence only.

## Phase 1 — Foundation ✅ complete (0.1.0–0.2.0)

Project structure, CLI, local mock agent, adapter architecture, request
budget, reports, automated tests.

## Phase 2 — Secure API integration ✅ complete (0.2.0)

OpenAI-compatible adapter, endpoint validation, DNS/IP validation,
pinned transport **with origin binding**, timeout and response limits,
budget integration, security regression tests. *Text chat completions
only; see Phase 7 for tool calling/streaming.*

## Phase 3 — Core AI security testing ✅ complete (0.2.0)

Prompt injection (6 checks), sensitive information disclosure (3),
authorization (3), tool abuse (4), output handling (2). Tool and
authorization checks currently exercise the synthetic tool layer only.

## Phase 4 — Evidence and risk engine ✅ complete (0.2.0)

Structured findings, evidence redaction and validation, severity and
confidence model, deduplication, human-review status, report schema
v1.0 with validation.

## Phase 5 — RAG security 🟡 partial (0.2.0–0.4.0)

Done: synthetic RAG environments (mock + Enterprise Knowledge
Assistant lab scenario with secure/vulnerable variants), retrieval
access control, document injection, metadata leakage checks,
target-declared retrieval scenarios. Open: adapter for external RAG
systems, larger poisoned-corpus scenarios, embedding-level tests.

## Phase 6 — Agent security 🟡 partial (0.2.0–0.3.0)

Done: synthetic agent environment, tool permission testing, tool-output
trust, delegation, excessive-agency checks, multi-turn persistence,
injected tool-call detection via OpenAI-format function calling.
Open: real agent-framework adapters, instrumented tool-call traces,
agent memory and inter-agent trust scenarios.

## Phase 7 — Advanced platform 🟡 partial (0.3.0)

Done: FastAPI backend with SQLite-persisted assessment history,
findings review workflow, report downloads; React dashboard and
landing page (local use, optional shared-token guard); adapter
conversation support and tool-call probing (attempted calls parsed as
evidence, never executed).
Open: streaming, structured outputs, provider capability detection,
multi-user authentication, plugin architecture, PostgreSQL option,
additional providers.

## Phase 8 — Release preparation ⬜ not started

Complete regression suite review, installation validation on clean
machines, external security review of the transport layer, versioning
policy, release checklist.
