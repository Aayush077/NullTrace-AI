# Release Levels

Four levels, each with explicit acceptance criteria. A level is claimed
only when every criterion is genuinely met and verifiable.

## Research Release — **MET**

For security research, education, and demos.
- [x] Broad-ish versioned probe corpus (v1.0) and depth profiles
- [x] Evidence-attributed findings; human-review gating
- [x] Deterministic offline test suite (309 tests), ruff, strict mypy
- [x] Internal synthetic benchmark with no false positives/negatives
- [x] CLI + local dashboard + Demo Lab
- [x] Honest documentation of limitations

## Internal Production Release — **MET (local/trusted)**

For a single team running it on a trusted local/VPN host.
- [x] Authentication + RBAC + sessions
- [x] Audit logging of security events
- [x] Reproducible install (uv) and Docker image, container-smoke-tested
- [x] Professional reports (exec summary, methodology, scope, limits)
- [x] CI gates (tests, lint, types, benchmark, frontend build, docker)
- [x] First-run auth bootstrap; secrets never stored/returned/logged
- Constraint: bind to localhost / private network only.

## Professional Engagement Release — **NOT MET (gaps listed)**

For authorized client security engagements.
- [x] Multi-turn attack chains; repeated-sampling confidence model
- [x] Black-box-capable checks documented and separated from
      instrumented ones
- [ ] **Expanded probe corpus** validated against external vulnerable
      LLM apps with **measured** precision/recall (currently internal
      synthetic only)
- [ ] **Repeated sampling validated against real nondeterministic
      models** (implemented, not field-measured)
- [ ] **Real-system adapters** for the tool/authz/RAG/agent modules
      (beyond synthetic)
- [ ] **Rate limiting, CSRF/XSS hardening, session hardening**
- [ ] **Independent external security review** of the transport and web
      platform

## Enterprise Deployment Release — **NOT MET (gaps listed)**

For multi-tenant, internet-facing, SLA-backed deployment.
- [ ] PostgreSQL backend + migrations + load testing + backup/restore
      tooling
- [ ] Organizations/projects, per-project RBAC, SSO/MFA, password reset
- [ ] Dependency-vulnerability scanning in CI; SBOM
- [ ] Horizontal scaling / background job durability
- [ ] Completed and remediated independent external review
- [ ] Operational runbooks, monitoring, incident response

## Current overall classification

**Internal Production Release (local/trusted).** The product meets the
Research and Internal Production criteria with verifiable evidence. It
does **not** yet meet Professional Engagement or Enterprise criteria;
the unchecked boxes above are the exact gates, each tracked in
IMPLEMENTATION_STATUS.md, KNOWN_LIMITATIONS.md, and
`SECURITY_REVIEW.md`.
