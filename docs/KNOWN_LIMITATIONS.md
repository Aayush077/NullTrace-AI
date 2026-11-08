# Known Limitations

Honest boundaries of the current implementation. Verified capabilities
are in IMPLEMENTATION_STATUS.md; this document is the counterweight.

## Detection

- **Probe corpus is v1.0 and finite.** 7 families / 28 base probes
  (plus deterministic mutations). It is broader than the previous
  single-phrasing checks and is versioned/extensible, but it is not an
  adversarial search and does not approach the breadth of a dedicated
  red-team. A target that resists the current corpus is reported as
  resisting *that corpus*, not as robust.
- **Attribution-dependent high confidence.** HIGH-confidence detection
  relies on either a unique per-assessment probe token (works black-box)
  or a declared synthetic marker (needs a cooperating/instrumented
  target). Against an arbitrary black-box target with no markers,
  marker-based checks degrade to INCONCLUSIVE by design. Per-check
  capability:
  - **Black-box capable** (token/structural): direct/role/boundary/
    indirect prompt injection, multi-turn chains, injected tool-call
    probe, structured-output validity.
  - **Cooperative/instrumented** (declared markers): system-prompt
    canary, secret disclosure, cross-user/RAG/authorization/tool-action
    detection.
- **Nondeterminism handling is implemented but unproven on real models.**
  The sampling engine (repeated/strict/statistical policies, consistency
  scoring) is tested on controlled responders. It has **not** been run
  against a live nondeterministic LLM in automated testing (no live
  calls permitted), so field reproducibility numbers are not yet
  measured.

## Target coverage

- **Tool / authorization / RAG / agent modules reach real systems only
  through adapters that implement the capability interfaces.** Today the
  concrete implementations are the synthetic Demo Lab and mock agent.
  The OpenAI-compatible adapter covers text chat, multi-turn
  conversation, and tool-call *probing* (never execution) — not
  streaming or structured-output modes, and it does not expose a
  server-side tool/retrieval environment, so against a real API the
  tool/authz/RAG checks SKIP.
- **No framework integrations** (LangChain, LlamaIndex, LangGraph,
  AutoGen, CrewAI). Intentionally deferred rather than shipped as
  shallow shims; a meaningful integration must drive real tool/retrieval
  assessment, which requires per-framework contracts.

## Benchmarking

- **Only internal synthetic benchmarks are measured.** Precision/recall
  of 1.0 is a control on deterministic fixtures, not a real-world
  detection rate. External validation against third-party vulnerable
  LLM apps is **pending** (requires authorized live targets).

## Platform

- **No rate limiting, CSRF/XSS hardening beyond header-token auth, MFA,
  account lockout, or session IP-binding.** Suitable for local/trusted
  single-tenant use; not for internet exposure. See
  `SECURITY_REVIEW.md`.
- **SQLite only.** PostgreSQL migration path is kept open but not
  implemented or load-tested. No organizations/projects multi-tenancy;
  RBAC is global, not per-project.
- **No password-reset flow, email, or SSO.** Admins manage accounts
  directly.
- **Transport uses private HTTPCore interfaces** pinned to specific
  dependency versions; SSRF-proof behavior is not claimed and the layer
  has not had an independent external review.

## Reporting

- JSON + Markdown only (no PDF). Reports clearly separate confirmed /
  pending / inconclusive, but "confirmed" always requires a human —
  automation never confirms.

## Process

- **No independent third-party security review has occurred.** All
  "audit"/"review" statements refer to internal self-review with
  regression tests.
- Automated tests never make live network calls or use real provider
  APIs; all coverage is offline and deterministic.
