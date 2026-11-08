# Security Review — internal, external pending

This document records an **internal** security review performed during
development and a reviewer-ready list of unresolved concerns. **No
independent third-party review has occurred.** Any statement of
"reviewed" in release materials refers only to this internal pass.

## Transport layer (`adapters/secure_transport.py`)

Reviewed internally; 42 regression tests in `tests/test_secure_transport.py`.

Controls verified by tests:
- Single DNS resolution; rejection of empty/invalid/mixed/non-global
  answers; loopback only for explicit localhost HTTP.
- Connection pinned to validated IPs **and** the validated host:port
  origin (`PinnedIPBackend` refuses other origins — regression tests
  `test_pinned_backend_refuses_unexpected_host/port`).
- IDNA hostname normalization; IPv4/IPv6 literal handling.
- TLS verification on; SNI/hostname uses the original hostname, not the
  pinned IP; redirects refused; proxies/retries/keepalive disabled.

**Unresolved / reviewer attention required:**
1. The transport imports **private HTTPCore interfaces**
   (`httpcore._backends`, `_pool`). This is pinned to httpx 0.28.x /
   httpcore 1.0.x. A dependency upgrade could silently break the pin —
   CI must re-run the transport suite on any bump. A maintainable
   alternative (a supported custom-resolver API, or a vetted SSRF-guard
   library) should be evaluated. **We do not claim SSRF-proof behavior.**
2. DNS is resolved once in-process; a resolver returning different
   answers between the validation call and OS connect is mitigated by IP
   pinning, but the OS resolver cache / TOCTOU at the socket layer has
   not been independently audited.
3. No IPv6 scoped-address / NAT64 edge-case fuzzing has been done.

## Web platform (`web/`)

Internal review; 38 tests across `test_web_api.py` + `test_auth.py`.

Controls:
- scrypt password hashing, constant-time verify, salted; session tokens
  stored only as SHA-256 hashes with expiry; logout invalidates.
- RBAC least-privilege gates on every write endpoint; setup mode closes
  on first user.
- Audit log on security events; audit details pass through redaction.
- Pydantic validation on all inputs; parameterized SQL throughout;
  strict base-URL validation (SSRF guard) shared with the CLI.
- API keys handled only as env-var names; never stored/returned/logged.
- SPA static handler resolves paths and refuses traversal outside dist.

**Unresolved / reviewer attention required:**
1. **No rate limiting** on login or the API — brute-force and
   resource-exhaustion are possible. A reverse proxy or app-level
   limiter is required before any non-local exposure.
2. **No CSRF protection**: the design avoids ambient cookies (session is
   a header token), which sidesteps classic CSRF, but a browser client
   storing the token in sessionStorage is exposed to XSS token theft.
   A strict CSP and/or httpOnly-cookie + CSRF-token scheme should be
   reviewed.
3. Sessions are not bound to client IP/user-agent; a stolen token is
   usable until expiry (12h). Consider shorter TTL + refresh.
4. No account lockout or MFA.
5. SQLite is single-node; concurrent writers rely on WAL + short
   transactions. Multi-user production load has not been stress-tested.
6. CORS allows localhost dev origins only; a production origin allowlist
   must be set explicitly.

## Secret handling

- Redaction (`core/redaction.py`) covers common credential shapes and
  known values; it is pattern-based and **cannot catch every secret
  shape**. Evidence should be reviewed before sharing reports.

## Dependencies

- **Python:** runtime deps are pinned ranges; `uv.lock` present. No
  automated dependency-vulnerability scan (e.g. `pip-audit`) is wired into
  CI yet — recommended before a professional release.
- **Frontend (`npm audit`, as of this review):** 4 advisories (3 moderate,
  1 high). Assessment:
  - **`vite` (high) and `esbuild` (moderate)** are **devDependencies** —
    build tooling and the local dev server (`npm run dev`). The deployed
    application serves the **production build** (`npm run build`) as static
    files via FastAPI, so these dev-server advisories (path traversal /
    `server.fs` bypass / cross-origin dev-server access, several
    Windows-specific) do **not** affect the served app. They are a
    developer-workstation concern.
  - **`react-router-dom` / `react-router` (moderate)** are **production**
    dependencies. The relevant issues are an open-redirect via a backslash
    in `<Link>`/`useNavigate` and a constructor-injection in SSR hydration.
    NullTrace AI is a **client-only SPA (no SSR)**, so the SSR vector does
    not apply, and routing targets are internal/static dashboard routes
    (not user-supplied URLs), so open-redirect exploitability is low.
  - **Remediation:** the published fixes are major, breaking upgrades
    (Vite 8, React Router 7). They are **not** applied here to avoid an
    untested breaking change; a planned, tested upgrade to React Router v7
    and Vite v8 is recommended, and `npm audit fix --force` should **not**
    be run blindly.

## Conclusion

The platform is suitable for **local / trusted single-tenant** use with
authentication enabled. Items 1–6 under "Web platform" and 1–3 under
"Transport" must be addressed, and an **independent external review**
performed, before internet-facing or multi-tenant enterprise
deployment. These gates are reflected in `RELEASE_LEVELS.md`.
