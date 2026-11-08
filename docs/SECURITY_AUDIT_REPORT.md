# Security Audit Report

Self-audit performed during the industry-readiness milestone. This is an
**internal** audit; no independent third-party review has been
performed. Issues found during development are listed with their fix and
the regression test that locks the fix.

## Issues found and fixed in this milestone

| # | Severity | Issue | Fix | Regression test |
| --- | --- | --- | --- | --- |
| A1 | Medium | CLI `user-add` defaulted to a relative DB path, mismatching the container's `NULLTRACE_DB_PATH`, so an in-container admin bootstrap silently wrote to the wrong database (auth would appear not to engage). | `user-add --db` now defaults to `$NULLTRACE_DB_PATH`. | Verified live: container bootstrap closes setup mode and anon → 401 (session log). |
| A2 | Low | Benchmark ground truth initially under-counted true detections, which would have mislabeled genuine detections as false positives (misleading metrics). | Ground truth re-derived from declared weakness flags, independent of tool output. | `tests/test_benchmark.py::test_benchmark_is_measured_and_clean` |
| A3 | Low | Username enumeration via login timing (early return when user absent). | `authenticate()` always runs a scrypt verification even when the user is absent. | `tests/test_auth.py::test_bad_credentials_rejected` |

## Controls verified (not just asserted)

- **AuthN/AuthZ:** scrypt hashing, constant-time verify, salted & unique
  hashes; RBAC least-privilege on every write path; disabled users
  cannot log in. (`tests/test_auth.py`, 16 tests)
- **Audit:** security events recorded incl. failed logins; audit details
  redacted; no raw passwords or `sk-` secrets in the log.
- **SSRF / transport:** origin-pinned, DNS-validated, redirect-refusing
  transport. (`tests/test_secure_transport.py`, 42 tests) — with the
  **unresolved** private-API dependency concern (see
  `SECURITY_REVIEW.md`).
- **Input validation:** pydantic schemas; strict base-URL validation
  rejects private/reserved IPs, credentials-in-URL, query/fragment.
- **Secret handling:** target API keys handled only as env-var names;
  never stored/returned/logged; redaction on evidence/errors/audit.
- **Path safety:** report downloads come from DB content; SPA file
  handler refuses traversal outside the dist directory.
- **Finding integrity:** findings are evidence-attributed and start
  `pending_review`; automation never self-confirms.

## Secret / config scan of the repository

- No credentials, tokens, or private keys committed. `.env.example`
  contains only placeholders; `.gitignore`/`.dockerignore` exclude
  `.env`, `data/`, and build output.
- Grep for `sk-`, `AKIA`, `password=` over `src/` and config: only the
  clearly-labeled **synthetic** markers used by fixtures (e.g.
  `SYNTHETIC-SECRET-…`) and detection patterns in `redaction.py`.

## Known unresolved security items (carried forward)

From `SECURITY_REVIEW.md`, required before non-local/enterprise use:
rate limiting, CSRF/XSS hardening + CSP, session binding/shorter TTL,
account lockout/MFA, PostgreSQL + load testing, dependency-vulnerability
scanning in CI, and an **independent external security review** (not yet
performed).

## Honest statement

No OWASP compliance, certification, or third-party audit is claimed.
"Audit" here means a structured internal self-review with regression
tests. External review is **pending** and is a release gate for the
Professional Engagement and Enterprise levels in `RELEASE_LEVELS.md`.
