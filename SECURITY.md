# Security Policy

NullTrace AI is a **defensive** security-assessment tool. This policy covers
the security of NullTrace AI itself.

## Project maturity

This is pre-1.0 software with **no production security SLA**. It is intended
for **local / trusted single-tenant** use. It has **not** had an independent
external security review, and no claim of external validation or
enterprise-readiness is made. See
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) for the internal review and
the list of unresolved concerns, and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model.

## Reporting a vulnerability

If you discover a security issue in NullTrace AI, please report it
**privately** to the maintainers rather than posting exploitable details in a
public issue. Include a clear description, affected version/commit, and
reproduction steps. We will acknowledge the report and work on a fix before
any public disclosure.

> Replace this with your project's real private security contact (e.g. a
> dedicated email or a GitHub private security advisory) before publishing.

Relevant issue classes include: unsafe execution, secret exposure,
authorization/scope bypass, SSRF in the outbound transport, and leakage of
assessment evidence or report data.

## Responsible use

Only assess systems you own or are explicitly authorized to test. NullTrace
AI operates offline by default; network assessments require an explicitly
authorized target and per-run consent, and are bounded by request budgets,
timeouts and response-size limits. The framework performs no destructive
actions and simulates all tool actions.

## Handling of secrets and data

- API keys for assessment targets are referenced only by **environment
  variable name** — never stored in the database, returned by any endpoint,
  or written to logs — and are redacted from evidence.
- The local SQLite database (`data/`), generated reports (`reports/`) and the
  academic report folder (`report/`) are **git-ignored** and must not be
  committed; they may contain assessment evidence or personal data.
- Before deploying beyond localhost, add the controls listed in
  [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) (rate limiting,
  CSRF/XSS hardening, session hardening) and obtain an independent review.
